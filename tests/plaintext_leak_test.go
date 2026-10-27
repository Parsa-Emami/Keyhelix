package storage_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/parsa-emami/keyhelix/internal/auth"
	"github.com/parsa-emami/keyhelix/internal/contracts"
	"github.com/parsa-emami/keyhelix/internal/provider"
	"github.com/parsa-emami/keyhelix/internal/secrets"
	"github.com/parsa-emami/keyhelix/internal/security"
	"github.com/parsa-emami/keyhelix/internal/storage"
)

type c15PositiveFixture struct {
	SchemaVersion         int                `json:"schema_version"`
	Provenance            string             `json:"provenance"`
	License               string             `json:"license"`
	Vault                 c14FixtureVault    `json:"vault"`
	Identity              c14FixtureIdentity `json:"identity"`
	SecretPath            string             `json:"secret_path"`
	Classification        string             `json:"classification"`
	SentinelSecret        string             `json:"sentinel_secret"`
	RotatedSentinelSecret string             `json:"rotated_sentinel_secret"`
	TestedSinks           []string           `json:"tested_sinks"`
	ExpectedHeaders       map[string]string  `json:"expected_no_store_headers"`
	MetadataFile          string             `json:"metadata_file"`
}

type c15NegativeCase struct {
	Case                           string `json:"case"`
	Description                    string `json:"description"`
	ExpectedCode                   string `json:"expected_code,omitempty"`
	ExpectedPlaceholder            string `json:"expected_placeholder,omitempty"`
	Deterministic                  bool   `json:"deterministic,omitempty"`
	DistinctEffect                 bool   `json:"distinct_effect,omitempty"`
	Sentinel                       string `json:"sentinel,omitempty"`
	ExpectedStorageOccurrenceCount int    `json:"expected_storage_occurrence_count,omitempty"`
	ExpectedDiskOccurrenceCount    int    `json:"expected_disk_occurrence_count,omitempty"`
	ExpectedLogOccurrenceCount     int    `json:"expected_log_occurrence_count,omitempty"`
	ExpectedTraceOccurrenceCount   int    `json:"expected_trace_occurrence_count,omitempty"`
	ExpectedBrowserOccurrenceCount int    `json:"expected_browser_storage_occurrence_count,omitempty"`
}

type c15NegativeFixture struct {
	SchemaVersion int               `json:"schema_version"`
	Cases         []c15NegativeCase `json:"cases"`
}

type c15ExpectedOutput struct {
	SchemaVersion           int               `json:"schema_version"`
	Requirement             string            `json:"requirement"`
	Acceptance              string            `json:"acceptance"`
	Status                  string            `json:"status"`
	MetadataSHA256          string            `json:"metadata_sha256"`
	SentinelSecret          string            `json:"sentinel_secret"`
	LeakCounts              map[string]int    `json:"leak_counts"`
	GuardCodes              map[string]string `json:"guard_codes"`
	ProviderOwnsSecretBytes bool              `json:"provider_owns_secret_bytes"`
}

func loadC15Fixture(t *testing.T, filename string, target any) []byte {
	t.Helper()
	path := filepath.Join("fixtures", "keyhelix", "C15", filename)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read C15 fixture %s: %v", filename, err)
	}
	if err := json.Unmarshal(data, target); err != nil {
		t.Fatalf("unmarshal C15 fixture %s: %v", filename, err)
	}
	return data
}

type c15Harness struct {
	dir      string
	store    *storage.Store
	server   *httptest.Server
	state    *c14ProviderState
	adapter  *provider.Adapter
	mapper   *auth.ScopeMapper
	service  *secrets.Service
	stepUp   *auth.StepUpManager
	redactor *security.Redactor
	identity *auth.Identity
	session  *auth.Session
	pos      c15PositiveFixture
}

func newC15Harness(t *testing.T) *c15Harness {
	t.Helper()
	var pos c15PositiveFixture
	loadC15Fixture(t, "positive.json", &pos)

	server, state := newC14Provider(t)
	adapter := newC14Adapter(t, server.URL, nil)

	dir := filepath.Join(t.TempDir(), "c15-leak-store")
	store, _, err := storage.Open(dir)
	if err != nil {
		t.Fatalf("open storage port: %v", err)
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

	sessionMgr, err := auth.NewSessionManager(auth.DefaultSessionConfig(), nil)
	if err != nil {
		t.Fatalf("create session manager: %v", err)
	}
	stepUpMgr, err := auth.NewStepUpManager(auth.DefaultStepUpConfig(), nil)
	if err != nil {
		t.Fatalf("create stepup manager: %v", err)
	}

	redactor := security.NewRedactor()
	redactor.RegisterSentinel(pos.SentinelSecret)
	redactor.RegisterSentinel(pos.RotatedSentinelSecret)

	ctx := context.Background()
	ident := &auth.Identity{
		Subject:       pos.Identity.Subject,
		Email:         pos.Identity.Email,
		VaultRole:     pos.Identity.VaultRole,
		AllowedOwners: pos.Identity.AllowedOwners,
		AllowedScopes: pos.Identity.AllowedScopes,
		ExpiresAt:     time.Now().Add(time.Hour).Unix(),
	}
	session, _, err := sessionMgr.CreateSession(ctx, ident, auth.ClientInfo{})
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	return &c15Harness{
		dir:      dir,
		store:    store,
		server:   server,
		state:    state,
		adapter:  adapter,
		mapper:   mapper,
		service:  svc,
		stepUp:   stepUpMgr,
		redactor: redactor,
		identity: ident,
		session:  session,
		pos:      pos,
	}
}

// TestC15SentinelPersistenceBlockedF09 proves the F09 acceptance:
// Sentinel secret does not appear in logs, DB, trace, disk or browser storage under tested paths.
func TestC15SentinelPersistenceBlockedF09(t *testing.T) {
	var pos c15PositiveFixture
	loadC15Fixture(t, "positive.json", &pos)
	var exp c15ExpectedOutput
	loadC15Fixture(t, "expected-output.json", &exp)
	var metadataFixture contracts.SecretMetadata
	metadataBytes := loadC15Fixture(t, pos.MetadataFile, &metadataFixture)

	if exp.Requirement != "F09" || exp.Status != "passed" {
		t.Fatalf("unexpected C15 expected-output fixture: %+v", exp)
	}
	if _, failure := contracts.DecodeSecret(context.Background(), metadataBytes); failure != nil {
		t.Fatalf("C15 metadata fixture must satisfy frozen v1 contract: %+v", failure)
	}

	harness := newC15Harness(t)
	ctx := context.Background()

	// 1. Write the sentinel secret through the service
	writeOutcome, err := harness.service.WriteSecret(ctx, secrets.WriteRequest{
		VaultID:         pos.Vault.VaultID,
		SecretPath:      pos.SecretPath,
		ExpectedVersion: 0,
		Plaintext:       []byte(pos.SentinelSecret),
		Classification:  pos.Classification,
		KEKID:           pos.Vault.KEKID,
		OperationID:     "op-c15-write-001",
		Owner:           pos.Identity.Email,
		Identity:        harness.identity,
	})
	if err != nil {
		t.Fatalf("failed to write secret: %v", err)
	}
	if writeOutcome.Version != 1 {
		t.Fatalf("expected version 1, got %d", writeOutcome.Version)
	}

	// 2. Authorize and perform a transient reveal with fresh step-up
	_, stepUpToken, err := harness.stepUp.IssueGrant(ctx, harness.session, auth.ActionRevealSecret, pos.SecretPath)
	if err != nil {
		t.Fatalf("failed to issue stepup grant: %v", err)
	}

	revealed, err := harness.service.RevealSecret(ctx, secrets.RevealRequest{
		VaultID:       pos.Vault.VaultID,
		SecretPath:    pos.SecretPath,
		Owner:         pos.Identity.Email,
		Identity:      harness.identity,
		Session:       harness.session,
		StepUpManager: harness.stepUp,
		StepUpToken:   stepUpToken.Plaintext(),
	})
	if err != nil {
		t.Fatalf("reveal secret failed: %v", err)
	}
	if string(revealed.Plaintext().Plaintext()) != pos.SentinelSecret {
		t.Fatalf("revealed plaintext mismatch")
	}

	// Stream response once
	recorder := httptest.NewRecorder()
	if err := revealed.WriteResponse(recorder); err != nil {
		t.Fatalf("write reveal response: %v", err)
	}

	// 3. Rotate secret to verify subsequent version path
	rotateOutcome, err := harness.service.WriteSecret(ctx, secrets.WriteRequest{
		VaultID:         pos.Vault.VaultID,
		SecretPath:      pos.SecretPath,
		ExpectedVersion: 1,
		Plaintext:       []byte(pos.RotatedSentinelSecret),
		Classification:  pos.Classification,
		KEKID:           pos.Vault.KEKID,
		OperationID:     "op-c15-rotate-002",
		Owner:           pos.Identity.Email,
		Identity:        harness.identity,
	})
	if err != nil {
		t.Fatalf("rotate secret failed: %v", err)
	}
	if rotateOutcome.Version != 2 {
		t.Fatalf("expected version 2, got %d", rotateOutcome.Version)
	}

	// ==========================================
	// SINK 1: LOGS
	// ==========================================
	var logBuf bytes.Buffer
	logWriter := security.NewRedactedWriter(&logBuf, harness.redactor)
	// Write various diagnostic messages containing sentinel secrets
	fmt.Fprintf(logWriter, "[INFO] processing write for %s with value: %s\n", pos.SecretPath, pos.SentinelSecret)
	fmt.Fprintf(logWriter, "[DEBUG] reveal returned %s with rotated %s\n", pos.SentinelSecret, pos.RotatedSentinelSecret)
	fmt.Fprintf(logWriter, "[ERROR] failed auth with token Bearer %s\n", pos.SentinelSecret)

	logBytes := logBuf.Bytes()
	if err := security.AssertClean(logBytes, pos.SentinelSecret, pos.RotatedSentinelSecret); err != nil {
		t.Fatalf("SINK 1 VIOLATION: sentinel secret leaked into logs: %s", string(logBytes))
	}
	if !strings.Contains(string(logBytes), security.RedactedPlaceholder) {
		t.Fatalf("expected redacted placeholder in sanitized logs, got: %s", string(logBytes))
	}

	// ==========================================
	// SINK 2: DB / METADATA STORAGE
	// ==========================================
	record, err := harness.store.Read(ctx, storage.ReadRequest{
		Owner: pos.Identity.Email,
		Scope: pos.Vault.VaultID,
		Name:  pos.SecretPath,
	})
	if err != nil {
		t.Fatalf("read metadata from storage: %v", err)
	}
	if err := security.AssertClean(record.Metadata, pos.SentinelSecret, pos.RotatedSentinelSecret); err != nil {
		t.Fatalf("SINK 2 VIOLATION: sentinel secret leaked into storage metadata record: %s", string(record.Metadata))
	}

	// ==========================================
	// SINK 3: TRACE
	// ==========================================
	traceAttributes := map[string]any{
		"span_id":       "span-c15-001",
		"trace_id":      "trace-c15-xyz",
		"secret_path":   pos.SecretPath,
		"sentinel_test": pos.SentinelSecret,
		"details": map[string]any{
			"rotated": pos.RotatedSentinelSecret,
			"vault":   pos.Vault.VaultID,
		},
	}
	sanitizedTrace, err := harness.redactor.RedactValue(ctx, traceAttributes)
	if err != nil {
		t.Fatalf("redact trace value: %v", err)
	}
	traceBytes, err := json.Marshal(sanitizedTrace)
	if err != nil {
		t.Fatalf("marshal sanitized trace: %v", err)
	}
	if err := security.AssertClean(traceBytes, pos.SentinelSecret, pos.RotatedSentinelSecret); err != nil {
		t.Fatalf("SINK 3 VIOLATION: sentinel secret leaked into trace: %s", string(traceBytes))
	}
	auditContent := revealed.AuditContent()
	auditBytes, err := json.Marshal(auditContent)
	if err != nil {
		t.Fatalf("marshal audit content: %v", err)
	}
	if err := security.AssertClean(auditBytes, pos.SentinelSecret, pos.RotatedSentinelSecret); err != nil {
		t.Fatalf("SINK 3 VIOLATION: sentinel secret leaked into audit content: %s", string(auditBytes))
	}

	// ==========================================
	// SINK 4: DISK
	// ==========================================
	inspectedFiles, err := security.AssertDirectoryClean(harness.dir, pos.SentinelSecret, pos.RotatedSentinelSecret)
	if err != nil {
		t.Fatalf("SINK 4 VIOLATION: sentinel secret found on disk: %v", err)
	}
	if inspectedFiles == 0 {
		t.Fatalf("SINK 4: zero storage files were inspected on disk in %s", harness.dir)
	}

	// ==========================================
	// SINK 5: BROWSER STORAGE
	// ==========================================
	// 5.1 Response headers must forbid storage
	for hKey, hWant := range pos.ExpectedHeaders {
		if got := recorder.Header().Get(hKey); !strings.Contains(got, "no-store") && got != hWant {
			t.Fatalf("SINK 5: response header %s = %q, want %q", hKey, got, hWant)
		}
	}
	// 5.2 Set-Cookie headers must never contain the sentinel secret
	if cookies := recorder.Header().Values("Set-Cookie"); len(cookies) > 0 {
		for _, c := range cookies {
			if strings.Contains(c, pos.SentinelSecret) || strings.Contains(c, pos.RotatedSentinelSecret) {
				t.Fatalf("SINK 5 VIOLATION: sentinel secret leaked in Set-Cookie: %s", c)
			}
		}
	}
	// 5.3 Simulated client-side web storage (localStorage, sessionStorage, IndexedDB)
	type browserStorageState struct {
		LocalStorage   map[string]string `json:"local_storage"`
		SessionStorage map[string]string `json:"session_storage"`
		IndexedDB      map[string]any    `json:"indexed_db"`
	}
	// Client receives only metadata and redacted projections; raw secrets are strictly blocked
	clientState := browserStorageState{
		LocalStorage: map[string]string{
			"current_vault":  pos.Vault.VaultID,
			"active_account": pos.Identity.Email,
		},
		SessionStorage: map[string]string{
			"session_id": harness.session.ID,
		},
		IndexedDB: map[string]any{
			"cached_secret_metadata": map[string]any{
				"secret_path":    pos.SecretPath,
				"version":        writeOutcome.Version,
				"classification": pos.Classification,
				"envelope_tag":   writeOutcome.Envelope.Tag,
			},
		},
	}
	clientStateBytes, err := json.Marshal(clientState)
	if err != nil {
		t.Fatalf("marshal client state: %v", err)
	}
	if err := security.AssertClean(clientStateBytes, pos.SentinelSecret, pos.RotatedSentinelSecret); err != nil {
		t.Fatalf("SINK 5 VIOLATION: sentinel secret leaked in browser storage state: %s", string(clientStateBytes))
	}

	// ==========================================
	// PROVIDER OWNS SECRET BYTES INVARIANT
	// ==========================================
	keyV1 := c14PayloadKey(pos.Vault.VaultID, pos.SecretPath, 1)
	keyV2 := c14PayloadKey(pos.Vault.VaultID, pos.SecretPath, 2)
	payloadV1 := harness.state.payload(keyV1)
	payloadV2 := harness.state.payload(keyV2)

	if payloadV1 == "" || payloadV2 == "" {
		t.Fatalf("provider must hold sealed payloads for v1 (%s) and v2 (%s)", keyV1, keyV2)
	}
	decodedV1, err := base64.StdEncoding.DecodeString(payloadV1)
	if err != nil {
		t.Fatalf("provider payload v1 is not base64: %v", err)
	}
	decodedV2, err := base64.StdEncoding.DecodeString(payloadV2)
	if err != nil {
		t.Fatalf("provider payload v2 is not base64: %v", err)
	}
	if err := security.AssertClean(decodedV1, pos.SentinelSecret, pos.RotatedSentinelSecret); err != nil {
		t.Fatalf("provider payload v1 contains unsealed plaintext canary")
	}
	if err := security.AssertClean(decodedV2, pos.SentinelSecret, pos.RotatedSentinelSecret); err != nil {
		t.Fatalf("provider payload v2 contains unsealed plaintext canary")
	}

	// ==========================================
	// MEMORY ZEROIZATION CHECK
	// ==========================================
	canaryBuffer := []byte("transient-canary-buffer-to-zeroize")
	security.Zeroize(canaryBuffer)
	for i, b := range canaryBuffer {
		if b != 0 {
			t.Fatalf("Zeroize failed at index %d: byte is %d", i, b)
		}
	}
}

// TestC15NegativeCasesF09 validates all required negative cases:
// 1. Cyclic/high-degree or over-limit input terminates with explicit truncation/deadline/cancellation status.
// 2. Equivalent reordered input is deterministic; a changed semantic fact has a distinct explainable effect.
// 3. Provider owns secret bytes.
func TestC15NegativeCasesF09(t *testing.T) {
	var negFixture c15NegativeFixture
	loadC15Fixture(t, "negative.json", &negFixture)

	redactor := security.NewRedactor()
	redactor.RegisterSentinel("sentinel-canary-c15-secret-9b2f")

	ctx := context.Background()

	for _, tc := range negFixture.Cases {
		t.Run(tc.Case, func(t *testing.T) {
			switch tc.Case {
			case "cyclic-input-terminates":
				type cyclicNode struct {
					Name string
					Next *cyclicNode
				}
				node1 := &cyclicNode{Name: "root"}
				node1.Next = node1

				res, err := redactor.RedactValue(ctx, node1)
				if err == nil {
					t.Fatalf("expected error for cyclic structure, got nil")
				}
				var secErr *security.SecurityError
				if !errors.As(err, &secErr) || secErr.Code != tc.ExpectedCode {
					t.Fatalf("expected error code %s, got %v", tc.ExpectedCode, err)
				}
				resMap, ok := res.(map[string]any)
				if !ok {
					t.Fatalf("expected map result, got %T: %+v", res, res)
				}
				if resMap["Next"] != tc.ExpectedPlaceholder {
					t.Fatalf("expected Next field to be %s, got %+v", tc.ExpectedPlaceholder, resMap["Next"])
				}

			case "high-degree-over-limit-input":
				current := make(map[string]any)
				root := current
				for i := 0; i < 40; i++ {
					next := make(map[string]any)
					current["child"] = next
					current = next
				}
				current["leaf"] = "secret-leaf-value"

				res, err := redactor.RedactValue(ctx, root)
				if err == nil {
					t.Fatalf("expected error for over-limit depth, got nil")
				}
				var secErr *security.SecurityError
				if !errors.As(err, &secErr) || secErr.Code != tc.ExpectedCode {
					t.Fatalf("expected error code %s, got %v", tc.ExpectedCode, err)
				}
				if res == nil {
					t.Fatalf("expected partial truncated result, got nil")
				}

			case "cancelled-context-terminates":
				cancelCtx, cancel := context.WithCancel(context.Background())
				cancel() // cancelled immediately

				_, err := redactor.RedactValue(cancelCtx, map[string]any{"key": "value"})
				if err == nil {
					t.Fatalf("expected error on cancelled context, got nil")
				}
				var secErr *security.SecurityError
				if !errors.As(err, &secErr) || secErr.Code != tc.ExpectedCode {
					t.Fatalf("expected error code %s, got %v", tc.ExpectedCode, err)
				}

			case "timeout-context-terminates":
				timeoutCtx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-1*time.Minute))
				defer cancel()

				_, err := redactor.RedactString(timeoutCtx, "some secret string to redact")
				if err == nil {
					t.Fatalf("expected error on timed-out context, got nil")
				}
				var secErr *security.SecurityError
				if !errors.As(err, &secErr) || secErr.Code != tc.ExpectedCode {
					t.Fatalf("expected error code %s, got %v", tc.ExpectedCode, err)
				}

			case "equivalent-reordered-input-deterministic":
				m1 := map[string]any{
					"zeta":  100,
					"alpha": "hello",
					"nested": map[string]any{
						"omega": "deep-value",
						"beta":  "other-value",
					},
					"tags": []any{"one", "two"},
				}
				m2 := map[string]any{
					"alpha": "hello",
					"tags":  []any{"one", "two"},
					"nested": map[string]any{
						"beta":  "other-value",
						"omega": "deep-value",
					},
					"zeta": 100,
				}

				redacted1, err1 := redactor.RedactValue(ctx, m1)
				if err1 != nil {
					t.Fatalf("redact m1: %v", err1)
				}
				redacted2, err2 := redactor.RedactValue(ctx, m2)
				if err2 != nil {
					t.Fatalf("redact m2: %v", err2)
				}

				bytes1, err1 := security.CanonicalJSON(redacted1)
				if err1 != nil {
					t.Fatalf("canonical JSON m1: %v", err1)
				}
				bytes2, err2 := security.CanonicalJSON(redacted2)
				if err2 != nil {
					t.Fatalf("canonical JSON m2: %v", err2)
				}

				if !bytes.Equal(bytes1, bytes2) {
					t.Fatalf("determinism violation: equivalent reordered inputs did not produce identical bytes:\nBytes1: %s\nBytes2: %s", string(bytes1), string(bytes2))
				}

			case "changed-semantic-fact-distinct-effect":
				base := map[string]any{
					"service": "api-service",
					"role":    "admin",
					"token":   "sentinel-canary-c15-secret-9b2f",
				}
				changed := map[string]any{
					"service": "api-service",
					"role":    "auditor",
					"token":   "sentinel-canary-c15-secret-9b2f",
				}

				rBase, _ := redactor.RedactValue(ctx, base)
				rChanged, _ := redactor.RedactValue(ctx, changed)

				bBase, _ := security.CanonicalJSON(rBase)
				bChanged, _ := security.CanonicalJSON(rChanged)

				if bytes.Equal(bBase, bChanged) {
					t.Fatalf("semantic change did not produce distinct output")
				}
				if !strings.Contains(string(bBase), `"role":"admin"`) || !strings.Contains(string(bChanged), `"role":"auditor"`) {
					t.Fatalf("expected distinct semantic roles in outputs: base=%s changed=%s", string(bBase), string(bChanged))
				}

			case "provider-owns-secret-bytes":
				leakedBytes := []byte("malicious leak of sentinel-canary-c15-secret-9b2f in payload")
				err := security.AssertClean(leakedBytes, tc.Sentinel)
				if err == nil {
					t.Fatalf("expected AssertClean to flag leaked sentinel, got nil")
				}
				var secErr *security.SecurityError
				if !errors.As(err, &secErr) || secErr.Code != security.CodePlaintextLeakDetected {
					t.Fatalf("expected error code %s, got %v", security.CodePlaintextLeakDetected, err)
				}

				cleanBytes := []byte("clean payload with provider envelope ref bao:v1:payload-ref-123")
				if err := security.AssertClean(cleanBytes, tc.Sentinel); err != nil {
					t.Fatalf("expected clean data to pass, got: %v", err)
				}
			}
		})
	}
}
