package storage_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/parsa-emami/keyhelix/internal/audit"
	"github.com/parsa-emami/keyhelix/internal/auth"
	"github.com/parsa-emami/keyhelix/internal/contracts"
	"github.com/parsa-emami/keyhelix/internal/grants"
	"github.com/parsa-emami/keyhelix/internal/provider"
	"github.com/parsa-emami/keyhelix/internal/secrets"
	"github.com/parsa-emami/keyhelix/internal/security"
	"github.com/parsa-emami/keyhelix/internal/storage"
)

type c28UserFixture struct {
	Subject string   `json:"subject"`
	Email   string   `json:"email"`
	Role    string   `json:"role"`
	Scopes  []string `json:"scopes"`
}

type c28PositiveFixture struct {
	SchemaVersion  int `json:"schema_version"`
	TargetCapacity struct {
		Users               int   `json:"users"`
		SecretPayloadMaxKiB int   `json:"secret_payload_max_kib"`
		MetadataMaxBytes    int   `json:"metadata_max_bytes"`
		RevealStepUpSeconds int64 `json:"reveal_step_up_seconds"`
		SessionTTLMinutes   int64 `json:"session_ttl_minutes"`
	} `json:"target_capacity"`
	Vault struct {
		VaultID string `json:"vault_id"`
		KEKID   string `json:"kek_id"`
		Mount   string `json:"mount"`
		Role    string `json:"role"`
	} `json:"vault"`
	SimulatedUsers []c28UserFixture `json:"simulated_users"`
	SampleSecret   struct {
		SecretPath     string `json:"secret_path"`
		Classification string `json:"classification"`
		SentinelSecret string `json:"sentinel_secret"`
		PayloadBytes   int    `json:"payload_bytes"`
	} `json:"sample_secret"`
	ExpectedBounds struct {
		LatencyP95Ms    float64 `json:"latency_p95_ms"`
		RSSPeakMB       int     `json:"rss_peak_mb"`
		DiskMaxGrowthMB int     `json:"disk_max_growth_mb"`
	} `json:"expected_bounds"`
}

type c28NegativeCase struct {
	Case         string `json:"case"`
	Surface      string `json:"surface"`
	Description  string `json:"description"`
	PayloadBytes int    `json:"payload_bytes,omitempty"`
	Raw          string `json:"raw,omitempty"`
	ExpectedCode string `json:"expected_code"`
}

type c28NegativeFixture struct {
	SchemaVersion int               `json:"schema_version"`
	Cases         []c28NegativeCase `json:"cases"`
}

type c28ExpectedOutput struct {
	SchemaVersion int               `json:"schema_version"`
	Requirement   string            `json:"requirement"`
	Status        string            `json:"status"`
	GuardCodes    map[string]string `json:"guard_codes"`
}

type c28Harness struct {
	dir        string
	store      *storage.Store
	server     *httptest.Server
	state      *c14ProviderState
	adapter    *provider.Adapter
	mapper     *auth.ScopeMapper
	service    *secrets.Service
	grantsSvc  *grants.Service
	sessionMgr *auth.SessionManager
	stepUpMgr  *auth.StepUpManager
	recorder   *audit.Recorder
	redactor   *security.Redactor
	pos        c28PositiveFixture
	identities []*auth.Identity
	sessions   []*auth.Session
}

func loadC28Fixture(t *testing.T, filename string, target any) []byte {
	t.Helper()
	path := filepath.Join("fixtures", "keyhelix", "C28", filename)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read C28 fixture %s: %v", filename, err)
	}
	if err := json.Unmarshal(data, target); err != nil {
		t.Fatalf("unmarshal C28 fixture %s: %v", filename, err)
	}
	return data
}

func extractC28ErrorCode(err error) string {
	if err == nil {
		return ""
	}
	var valErr *contracts.ValidationError
	if errors.As(err, &valErr) {
		return string(valErr.Code)
	}
	var authErr *auth.Error
	if errors.As(err, &authErr) {
		return string(authErr.Code)
	}
	var grantErr *grants.Error
	if errors.As(err, &grantErr) {
		return grantErr.Code
	}
	var provErr *provider.Error
	if errors.As(err, &provErr) {
		return string(provErr.Code)
	}
	var storErr *storage.Error
	if errors.As(err, &storErr) {
		return string(storErr.Code)
	}
	var secErr *security.SecurityError
	if errors.As(err, &secErr) {
		return secErr.Code
	}
	var revErr *secrets.RevealError
	if errors.As(err, &revErr) {
		return revErr.Code
	}
	return err.Error()
}

func newC28Harness(t *testing.T) *c28Harness {
	t.Helper()
	var pos c28PositiveFixture
	loadC28Fixture(t, "positive.json", &pos)

	server, state := newC14Provider(t)
	adapter := newC14Adapter(t, server.URL, nil)

	dir := filepath.Join(t.TempDir(), "c28-perf-store")
	store, _, err := storage.Open(dir)
	if err != nil {
		t.Fatalf("open storage: %v", err)
	}
	t.Cleanup(func() {
		_ = store.Close()
	})

	mapper := auth.NewScopeMapper(auth.ScopeMapperConfig{
		VaultKEKMap:   map[string]string{pos.Vault.VaultID: pos.Vault.KEKID},
		VaultMountMap: map[string]string{pos.Vault.VaultID: pos.Vault.Mount},
		VaultRoleMap:  map[string]string{pos.Vault.VaultID: pos.Vault.Role},
	})
	svc := secrets.NewService(mapper, adapter, store)

	redactor := security.NewRedactor()
	redactor.RegisterSentinel(pos.SampleSecret.SentinelSecret)

	recorder := audit.NewRecorder(500, redactor)
	grantsSvc := grants.NewService(store, recorder)

	sessionMgr, err := auth.NewSessionManager(auth.DefaultSessionConfig(), nil)
	if err != nil {
		t.Fatalf("create session manager: %v", err)
	}
	stepUpMgr, err := auth.NewStepUpManager(auth.DefaultStepUpConfig(), nil)
	if err != nil {
		t.Fatalf("create stepup manager: %v", err)
	}

	ctx := context.Background()
	var idents []*auth.Identity
	var sesss []*auth.Session

	for _, u := range pos.SimulatedUsers {
		ident := &auth.Identity{
			Subject:       u.Subject,
			Email:         u.Email,
			VaultRole:     u.Role,
			AllowedOwners: []string{u.Email},
			AllowedScopes: u.Scopes,
			ExpiresAt:     time.Now().Add(time.Hour).Unix(),
		}
		sess, _, err := sessionMgr.CreateSession(ctx, ident, auth.ClientInfo{})
		if err != nil {
			t.Fatalf("create session for %s: %v", u.Email, err)
		}
		idents = append(idents, ident)
		sesss = append(sesss, sess)
	}

	return &c28Harness{
		dir:        dir,
		store:      store,
		server:     server,
		state:      state,
		adapter:    adapter,
		mapper:     mapper,
		service:    svc,
		grantsSvc:  grantsSvc,
		sessionMgr: sessionMgr,
		stepUpMgr:  stepUpMgr,
		recorder:   recorder,
		redactor:   redactor,
		pos:        pos,
		identities: idents,
		sessions:   sesss,
	}
}

// TestC28TargetWorkloadMetrics measures bounded target capacity (5 users, 64 KiB payload bound, CAS writes, reveals).
func TestC28TargetWorkloadMetrics(t *testing.T) {
	h := newC28Harness(t)
	ctx := context.Background()

	var mBefore runtime.MemStats
	runtime.ReadMemStats(&mBefore)

	const opsPerUser = 5
	latencies := make([]time.Duration, 0, len(h.identities)*opsPerUser)
	var mu sync.Mutex
	var wg sync.WaitGroup

	start := time.Now()

	for i := range h.identities {
		wg.Add(1)
		go func(userIndex int) {
			defer wg.Done()
			ident := h.identities[userIndex]
			sess := h.sessions[userIndex]

			for op := 0; op < opsPerUser; op++ {
				opStart := time.Now()

				// 1. Write versioned secret with CAS
				secretPath := "app/prod/service-key-" + ident.Subject
				payload := []byte("sentinel-canary-c28-valid-8f2b-" + ident.Subject)

				writeReq := secrets.WriteRequest{
					VaultID:         h.pos.Vault.VaultID,
					SecretPath:      secretPath,
					ExpectedVersion: int64(op),
					Plaintext:       payload,
					Classification:  h.pos.SampleSecret.Classification,
					KEKID:           h.pos.Vault.KEKID,
					OperationID:     "c28-target-write-" + ident.Subject + "-" + string(rune('0'+op)),
					Owner:           ident.Email,
					Identity:        ident,
				}
				outcome, err := h.service.WriteSecret(ctx, writeReq)
				if err != nil {
					t.Errorf("user %s write op %d failed: %v", ident.Email, op, err)
					continue
				}

				// 2. Issue step-up token
				_, stepToken, err := h.stepUpMgr.IssueGrant(ctx, sess, auth.ActionRevealSecret, secretPath)
				if err != nil {
					t.Errorf("step up grant: %v", err)
					continue
				}

				// 3. Reveal versioned secret
				revealReq := secrets.RevealRequest{
					VaultID:       h.pos.Vault.VaultID,
					SecretPath:    secretPath,
					Owner:         ident.Email,
					Identity:      ident,
					Session:       sess,
					StepUpManager: h.stepUpMgr,
					StepUpToken:   stepToken.Plaintext(),
				}
				revOutcome, err := h.service.RevealSecret(ctx, revealReq)
				if err != nil {
					t.Errorf("user %s reveal failed: %v", ident.Email, err)
					continue
				}
				if string(revOutcome.Plaintext()) != string(payload) {
					t.Errorf("user %s reveal mismatch", ident.Email)
				}

				d := time.Since(opStart)
				mu.Lock()
				latencies = append(latencies, d)
				mu.Unlock()
				_ = outcome
			}
		}(i)
	}

	wg.Wait()
	elapsed := time.Since(start)

	var mAfter runtime.MemStats
	runtime.ReadMemStats(&mAfter)

	if len(latencies) == 0 {
		t.Fatalf("no operations completed")
	}

	var total time.Duration
	var maxD time.Duration
	for _, l := range latencies {
		total += l
		if l > maxD {
			maxD = l
		}
	}
	avgD := total / time.Duration(len(latencies))

	t.Logf("C28 Target Workload: %d operations in %v (avg: %v, max: %v)", len(latencies), elapsed, avgD, maxD)
	t.Logf("Memory Alloc delta: %d KiB, TotalAlloc delta: %d KiB, Sys: %d KiB",
		(mAfter.Alloc-mBefore.Alloc)/1024,
		(mAfter.TotalAlloc-mBefore.TotalAlloc)/1024,
		mAfter.Sys/1024)

	// Invariant: Provider owns secret bytes; verify storage contains zero plaintext sentinel bytes
	files, err := os.ReadDir(h.dir)
	if err != nil {
		t.Fatalf("read store dir: %v", err)
	}
	for _, f := range files {
		content, err := os.ReadFile(filepath.Join(h.dir, f.Name()))
		if err != nil {
			continue
		}
		if bytes.Contains(content, []byte(h.pos.SampleSecret.SentinelSecret)) {
			t.Fatalf("CRITICAL INVARIANT VIOLATION: storage file %s contains plaintext sentinel secret bytes!", f.Name())
		}
	}
}

// TestC28OverloadSaturationAndRejection asserts overload workloads (oversized payloads, metadata bounds) fail closed.
func TestC28OverloadSaturationAndRejection(t *testing.T) {
	h := newC28Harness(t)
	ctx := context.Background()

	// 1. Oversized secret payload (> secrets.MaxSecretBytes = 1 MiB)
	oversizedPayload := make([]byte, secrets.MaxSecretBytes+1)
	_, err := h.service.WriteSecret(ctx, secrets.WriteRequest{
		VaultID:         h.pos.Vault.VaultID,
		SecretPath:      "app/prod/oversized",
		ExpectedVersion: 0,
		Plaintext:       oversizedPayload,
		Classification:  "restricted",
		KEKID:           h.pos.Vault.KEKID,
		Owner:           h.identities[0].Email,
		Identity:        h.identities[0],
	})
	if err == nil {
		t.Fatalf("expected write to reject payload > 1 MiB")
	}

	// 2. Oversized metadata input (> contracts.MaxInputBytes = 8192)
	oversizedMeta := make([]byte, contracts.MaxInputBytes+1)
	for i := range oversizedMeta {
		oversizedMeta[i] = 'a'
	}
	res := contracts.Validate(ctx, io.NopCloser(bytes.NewReader(oversizedMeta)), "0.0.1")
	if res.Result.Valid {
		t.Fatalf("expected contracts.Validate to reject metadata > 8192 bytes")
	}
	if res.Result.Error == nil || res.Result.Error.Code != contracts.InputTooLarge {
		t.Fatalf("expected INPUT_TOO_LARGE, got: %v", res.Result.Error)
	}
}

// TestC28WorkloadCancellation asserts prompt termination and zero goroutine leaks on cancelled context.
func TestC28WorkloadCancellation(t *testing.T) {
	h := newC28Harness(t)

	initialGoroutines := runtime.NumGoroutine()

	// Cancelled context write
	ctxCancel, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancelled

	_, err := h.service.WriteSecret(ctxCancel, secrets.WriteRequest{
		VaultID:         h.pos.Vault.VaultID,
		SecretPath:      "app/prod/cancelled",
		ExpectedVersion: 0,
		Plaintext:       []byte("test"),
		Classification:  "restricted",
		KEKID:           h.pos.Vault.KEKID,
		Owner:           h.identities[0].Email,
		Identity:        h.identities[0],
	})
	if err == nil {
		t.Fatalf("expected error on pre-cancelled write")
	}

	// Cancelled context metadata validation
	res := contracts.Validate(ctxCancel, io.NopCloser(bytes.NewReader([]byte("{}"))), "0.0.1")
	if res.Result.Valid {
		t.Fatalf("expected validation failure on cancelled context")
	}
	if res.Result.Error == nil || res.Result.Error.Code != contracts.Cancelled {
		t.Fatalf("expected CANCELLED code, got: %v", res.Result.Error)
	}

	// Timed-out context metadata validation
	ctxTimeout, cancelTimeout := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancelTimeout()

	resTimeout := contracts.Validate(ctxTimeout, io.NopCloser(bytes.NewReader([]byte("{}"))), "0.0.1")
	if resTimeout.Result.Valid {
		t.Fatalf("expected validation failure on expired deadline")
	}
	if resTimeout.Result.Error == nil || resTimeout.Result.Error.Code != contracts.Timeout {
		t.Fatalf("expected TIMEOUT code, got: %v", resTimeout.Result.Error)
	}

	// Allow any runtime cleanup
	time.Sleep(10 * time.Millisecond)
	currentGoroutines := runtime.NumGoroutine()
	if currentGoroutines > initialGoroutines+3 {
		t.Errorf("potential goroutine leak under cancellation: initial=%d, current=%d", initialGoroutines, currentGoroutines)
	}
}

// TestC28DurabilityUnderWorkloadAndRestart verifies store durability across engine restart.
func TestC28DurabilityUnderWorkloadAndRestart(t *testing.T) {
	h := newC28Harness(t)
	ctx := context.Background()

	// Write secret v1
	secretPath := "app/prod/durable-target"
	w1, err := h.service.WriteSecret(ctx, secrets.WriteRequest{
		VaultID:         h.pos.Vault.VaultID,
		SecretPath:      secretPath,
		ExpectedVersion: 0,
		Plaintext:       []byte("durable-payload-v1"),
		Classification:  "restricted",
		KEKID:           h.pos.Vault.KEKID,
		Owner:           h.identities[0].Email,
		Identity:        h.identities[0],
	})
	if err != nil {
		t.Fatalf("write v1: %v", err)
	}

	// Close store to simulate shutdown
	if err := h.store.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	// Re-open store to simulate engine restart
	reopenedStore, _, err := storage.Open(h.dir)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	defer reopenedStore.Close()

	// Recreate service with reopened store
	reopenedSvc := secrets.NewService(h.mapper, h.adapter, reopenedStore)

	// Step up challenge
	_, stepToken, err := h.stepUpMgr.IssueGrant(ctx, h.sessions[0], auth.ActionRevealSecret, secretPath)
	if err != nil {
		t.Fatalf("step up challenge: %v", err)
	}

	// Reveal secret v1 after restart
	revOutcome, err := reopenedSvc.RevealSecret(ctx, secrets.RevealRequest{
		VaultID:       h.pos.Vault.VaultID,
		SecretPath:    secretPath,
		Owner:         h.identities[0].Email,
		Identity:      h.identities[0],
		Session:       h.sessions[0],
		StepUpManager: h.stepUpMgr,
		StepUpToken:   stepToken.Plaintext(),
	})
	if err != nil {
		t.Fatalf("reveal after restart: %v", err)
	}
	if string(revOutcome.Plaintext()) != "durable-payload-v1" {
		t.Fatalf("payload mismatch after restart, got: %s", string(revOutcome.Plaintext()))
	}
	_ = w1
}

// TestC28NegativeCasesFixtureMatch drives every case in negative.json.
func TestC28NegativeCasesFixtureMatch(t *testing.T) {
	var neg c28NegativeFixture
	loadC28Fixture(t, "negative.json", &neg)

	var exp c28ExpectedOutput
	loadC28Fixture(t, "expected-output.json", &exp)

	h := newC28Harness(t)
	ctx := context.Background()

	for _, c := range neg.Cases {
		t.Run(c.Case, func(t *testing.T) {
			switch c.Case {
			case "payload_exceeds_limit":
				oversized := make([]byte, c.PayloadBytes)
				_, err := h.service.WriteSecret(ctx, secrets.WriteRequest{
					VaultID:         h.pos.Vault.VaultID,
					SecretPath:      "app/prod/overflow",
					ExpectedVersion: 0,
					Plaintext:       oversized,
					Classification:  "restricted",
					KEKID:           h.pos.Vault.KEKID,
					Owner:           h.identities[0].Email,
					Identity:        h.identities[0],
				})
				if err == nil {
					t.Fatalf("expected payload_exceeds_limit to fail")
				}

			case "metadata_exceeds_limit":
				oversized := make([]byte, c.PayloadBytes)
				res := contracts.Validate(ctx, io.NopCloser(bytes.NewReader(oversized)), "0.0.1")
				if res.Result.Valid {
					t.Fatalf("expected metadata_exceeds_limit to fail")
				}
				if res.Result.Error == nil || string(res.Result.Error.Code) != c.ExpectedCode {
					t.Fatalf("expected %s, got: %v", c.ExpectedCode, res.Result.Error)
				}

			case "context_cancelled":
				ctxCancelled, cancel := context.WithCancel(ctx)
				cancel()
				res := contracts.Validate(ctxCancelled, io.NopCloser(bytes.NewReader([]byte("{}"))), "0.0.1")
				if res.Result.Valid {
					t.Fatalf("expected cancelled context to fail")
				}
				if res.Result.Error == nil || string(res.Result.Error.Code) != c.ExpectedCode {
					t.Fatalf("expected %s, got: %v", c.ExpectedCode, res.Result.Error)
				}

			case "context_timeout":
				ctxTimeout, cancelTimeout := context.WithDeadline(ctx, time.Now().Add(-time.Millisecond))
				defer cancelTimeout()
				res := contracts.Validate(ctxTimeout, io.NopCloser(bytes.NewReader([]byte("{}"))), "0.0.1")
				if res.Result.Valid {
					t.Fatalf("expected timeout context to fail")
				}
				if res.Result.Error == nil || string(res.Result.Error.Code) != c.ExpectedCode {
					t.Fatalf("expected %s, got: %v", c.ExpectedCode, res.Result.Error)
				}

			case "provider_unavailable":
				h.state.setSealed(true)
				defer h.state.setSealed(false)
				_, err := h.service.WriteSecret(ctx, secrets.WriteRequest{
					VaultID:         h.pos.Vault.VaultID,
					SecretPath:      "app/prod/key-outage",
					ExpectedVersion: 0,
					Plaintext:       []byte("test"),
					Classification:  "restricted",
					KEKID:           h.pos.Vault.KEKID,
					OperationID:     "op-c28-outage-write",
					Owner:           h.identities[0].Email,
					Identity:        h.identities[0],
				})
				if err == nil {
					t.Fatalf("expected write to fail when provider is sealed/unavailable")
				}
				code := extractC28ErrorCode(err)
				if code != c.ExpectedCode && !provider.IsErrorCode(err, provider.CodeProviderSealed) && !provider.IsErrorCode(err, provider.CodeProviderUnavailable) && code != "PROVIDER_SEALED" {
					t.Fatalf("expected %s or PROVIDER_SEALED, got: %v (code: %s)", c.ExpectedCode, err, code)
				}

			case "malformed_metadata_json":
				res := contracts.Validate(ctx, io.NopCloser(bytes.NewReader([]byte(c.Raw))), "0.0.1")
				if res.Result.Valid {
					t.Fatalf("expected malformed JSON to fail")
				}
				if res.Result.Error == nil || string(res.Result.Error.Code) != c.ExpectedCode {
					t.Fatalf("expected %s, got: %v", c.ExpectedCode, res.Result.Error)
				}

			case "stale_cas_version":
				// Write v1
				w1, err := h.service.WriteSecret(ctx, secrets.WriteRequest{
					VaultID:         h.pos.Vault.VaultID,
					SecretPath:      "app/prod/cas-stale",
					ExpectedVersion: 0,
					Plaintext:       []byte("v1"),
					Classification:  "restricted",
					KEKID:           h.pos.Vault.KEKID,
					OperationID:     "op-c28-cas-v1",
					Owner:           h.identities[0].Email,
					Identity:        h.identities[0],
				})
				if err != nil {
					t.Fatalf("write initial v1: %v", err)
				}
				// Attempt to update with stale ExpectedVersion: 99
				_, err = h.service.WriteSecret(ctx, secrets.WriteRequest{
					VaultID:         h.pos.Vault.VaultID,
					SecretPath:      "app/prod/cas-stale",
					ExpectedVersion: 99,
					Plaintext:       []byte("v2-stale"),
					Classification:  "restricted",
					KEKID:           h.pos.Vault.KEKID,
					OperationID:     "op-c28-cas-stale",
					Owner:           h.identities[0].Email,
					Identity:        h.identities[0],
				})
				if err == nil {
					t.Fatalf("expected stale version write to fail")
				}
				code := extractC28ErrorCode(err)
				if code != c.ExpectedCode {
					var storErr *storage.Error
					if !errors.As(err, &storErr) || storErr.Code != storage.CodeStaleVersion {
						t.Fatalf("expected CodeStaleVersion, got: %v (code: %s)", err, code)
					}
				}
				_ = w1
			}
		})
	}
}
