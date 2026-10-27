package storage_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/parsa-emami/keyhelix/internal/auth"
	"github.com/parsa-emami/keyhelix/internal/contracts"
	"github.com/parsa-emami/keyhelix/internal/provider"
	"github.com/parsa-emami/keyhelix/internal/secrets"
	"github.com/parsa-emami/keyhelix/internal/storage"
)

type c14FixtureVault struct {
	VaultID string `json:"vault_id"`
	KEKID   string `json:"kek_id"`
	Mount   string `json:"mount"`
	Role    string `json:"role"`
}

type c14FixtureIdentity struct {
	Subject       string   `json:"subject"`
	Email         string   `json:"email"`
	VaultRole     string   `json:"vault_role"`
	AllowedOwners []string `json:"allowed_owners"`
	AllowedScopes []string `json:"allowed_scopes"`
}

type c14PositiveFixture struct {
	SchemaVersion   int                  `json:"schema_version"`
	Vault           c14FixtureVault      `json:"vault"`
	Identity        c14FixtureIdentity   `json:"identity"`
	SecretPath      string               `json:"secret_path"`
	Classification  string               `json:"classification"`
	PlaintextCanary string               `json:"plaintext_canary"`
	RotatedCanary   string               `json:"rotated_plaintext_canary"`
	ExpectedHeaders map[string]string    `json:"expected_no_store_headers"`
	ExpectedCalls   map[string]int       `json:"expected_provider_calls"`
	MetadataFile    string               `json:"metadata_file"`
}

type c14NegativeCase struct {
	Case                      string            `json:"case"`
	Kind                      string            `json:"kind"`
	Description               string            `json:"description"`
	ExpectedCode              string            `json:"expected_code"`
	TargetOwner               string            `json:"target_owner"`
	TargetVault               string            `json:"target_vault"`
	OtherResource             string            `json:"other_resource"`
	Headers                   map[string]string `json:"headers"`
	RawPath                   string            `json:"raw_path"`
	ProviderOffline           bool              `json:"provider_offline"`
	ProviderState             string            `json:"provider_state"`
	WorkloadScopes            []string          `json:"workload_scopes"`
	ForeignKEKID              string            `json:"foreign_kek_id"`
	Canary                    string            `json:"canary"`
	ExpectedStorageOccurrence int               `json:"expected_storage_occurrence_count"`
}

type c14NegativeFixture struct {
	SchemaVersion int               `json:"schema_version"`
	Cases         []c14NegativeCase `json:"cases"`
}

type c14ExpectedOutput struct {
	SchemaVersion   int    `json:"schema_version"`
	Requirement     string `json:"requirement"`
	Acceptance      string `json:"acceptance"`
	Status          string `json:"status"`
	MetadataSHA256  string `json:"metadata_sha256"`
	PlaintextCanary string `json:"plaintext_canary"`
	Response        struct {
		SchemaVersion                 string            `json:"schema_version"`
		NoStore                       bool              `json:"no_store"`
		Headers                       map[string]string `json:"headers"`
		PlaintextSerialization        string            `json:"plaintext_serialization"`
		AuditContentExcludesPlaintext bool              `json:"audit_content_excludes_plaintext"`
	} `json:"response"`
	GuardCodes                map[string]string `json:"guard_codes"`
	ProviderCallBudget        int               `json:"provider_call_budget_before_authorization"`
	StoragePlaintextLeakCount int               `json:"storage_plaintext_leak_count"`
}

func loadC14Fixture(t *testing.T, filename string, target any) []byte {
	t.Helper()
	path := filepath.Join("fixtures", "keyhelix", "C14", filename)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read C14 fixture %s: %v", filename, err)
	}
	if err := json.Unmarshal(data, target); err != nil {
		t.Fatalf("unmarshal C14 fixture %s: %v", filename, err)
	}
	return data
}

// c14ProviderState is an in-process OpenBao-compatible wire fixture: health,
// transit and KV v2. It owns the sealed payload bytes, exactly like the provider.
type c14ProviderState struct {
	mu                 sync.Mutex
	sealed             map[string]string
	versions           map[string]int
	transit            map[string]string
	callCounts         map[string]int
	casHistory         []int
	sealed503          bool
	denyTransitDecrypt bool
	kvReadDenied       bool
	kvWriteDenied      bool
	payloadMissing     bool
}

func newC14ProviderState() *c14ProviderState {
	return &c14ProviderState{
		sealed:     make(map[string]string),
		versions:   make(map[string]int),
		transit:    make(map[string]string),
		callCounts: make(map[string]int),
	}
}

func (s *c14ProviderState) record(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.callCounts[name]++
}

func (s *c14ProviderState) calls(name string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.callCounts[name]
}

func (s *c14ProviderState) payload(key string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sealed[key]
}

func (s *c14ProviderState) seedPayload(key, value string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sealed[key] = base64.StdEncoding.EncodeToString([]byte(value))
	s.versions[key] = 1
}

func (s *c14ProviderState) setSealed(sealed bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sealed503 = sealed
}

func (s *c14ProviderState) setPayloadMissing(missing bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.payloadMissing = missing
}

// tamper flips one byte of the stored sealed payload. When tag is true the
// committed tag itself is corrupted, otherwise the ciphertext body is.
func (s *c14ProviderState) tamper(key string, tag bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	raw, ok := s.sealed[key]
	if !ok {
		return
	}
	decoded, err := base64.StdEncoding.DecodeString(raw)
	if err != nil || len(decoded) == 0 {
		return
	}
	if tag {
		decoded[len(decoded)-1] ^= 0xff
	} else {
		decoded[0] ^= 0xff
	}
	s.sealed[key] = base64.StdEncoding.EncodeToString(decoded)
}

func c14PayloadKey(vaultID, path string, version int64) string {
	return vaultID + "/" + path + "/v" + strconv.FormatInt(version, 10)
}

func newC14Provider(t *testing.T) (*httptest.Server, *c14ProviderState) {
	t.Helper()
	state := newC14ProviderState()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		state.mu.Lock()
		sealedMode := state.sealed503
		state.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/v1/sys/health" {
			if sealedMode {
				w.WriteHeader(http.StatusServiceUnavailable)
				json.NewEncoder(w).Encode(map[string]any{"initialized": true, "sealed": true})
				return
			}
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]any{"initialized": true, "sealed": false, "version": "2.4.0"})
			return
		}
		token := r.Header.Get("X-Vault-Token")
		if token == "" || strings.EqualFold(token, "invalid") {
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]any{"errors": []string{"permission denied"}})
			return
		}
		if sealedMode {
			// Record the attempted operation before failing so call budgets stay observable.
			switch {
			case strings.HasPrefix(r.URL.Path, "/v1/transit/encrypt/") && r.Method == http.MethodPost:
				state.record("transit_encrypt")
			case strings.HasPrefix(r.URL.Path, "/v1/transit/decrypt/") && r.Method == http.MethodPost:
				state.record("transit_decrypt")
			case strings.HasPrefix(r.URL.Path, "/v1/kv/data/") && r.Method == http.MethodPost:
				state.record("kv_write")
			case strings.HasPrefix(r.URL.Path, "/v1/kv/data/"):
				state.record("kv_read")
			}
			w.WriteHeader(http.StatusServiceUnavailable)
			json.NewEncoder(w).Encode(map[string]any{"errors": []string{"Vault is sealed"}})
			return
		}

		switch {
		case strings.HasPrefix(r.URL.Path, "/v1/transit/encrypt/") && r.Method == http.MethodPost:
			state.record("transit_encrypt")
			var body struct {
				Plaintext string `json:"plaintext"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			ciphertext := "bao:v1:" + body.Plaintext
			state.mu.Lock()
			state.transit[ciphertext] = body.Plaintext
			state.mu.Unlock()
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{"ciphertext": ciphertext, "key_version": 1},
			})
			return

		case strings.HasPrefix(r.URL.Path, "/v1/transit/decrypt/") && r.Method == http.MethodPost:
			state.record("transit_decrypt")
			state.mu.Lock()
			denied := state.denyTransitDecrypt
			state.mu.Unlock()
			if denied {
				w.WriteHeader(http.StatusForbidden)
				json.NewEncoder(w).Encode(map[string]any{"errors": []string{"permission denied"}})
				return
			}
			var body struct {
				Ciphertext string `json:"ciphertext"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			state.mu.Lock()
			plaintext, ok := state.transit[body.Ciphertext]
			state.mu.Unlock()
			if !ok {
				plaintext = strings.TrimPrefix(body.Ciphertext, "bao:v1:")
			}
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"plaintext": plaintext}})
			return

		case strings.HasPrefix(r.URL.Path, "/v1/kv/data/"):
			path := strings.TrimPrefix(r.URL.Path, "/v1/kv/data/")
			if r.Method == http.MethodPost {
				state.record("kv_write")
				state.mu.Lock()
				denied := state.kvWriteDenied
				state.mu.Unlock()
				if denied {
					w.WriteHeader(http.StatusForbidden)
					json.NewEncoder(w).Encode(map[string]any{"errors": []string{"permission denied"}})
					return
				}
				var body struct {
					Data struct {
						Sealed string `json:"sealed"`
					} `json:"data"`
					Options struct {
						CAS int `json:"cas"`
					} `json:"options"`
				}
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				state.mu.Lock()
				current := state.versions[path]
				state.casHistory = append(state.casHistory, body.Options.CAS)
				if body.Options.CAS != current {
					state.mu.Unlock()
					w.WriteHeader(http.StatusBadRequest)
					json.NewEncoder(w).Encode(map[string]any{
						"errors": []string{"check-and-set parameter did not match the current version"},
					})
					return
				}
				state.versions[path] = current + 1
				state.sealed[path] = body.Data.Sealed
				version := state.versions[path]
				state.mu.Unlock()
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"version": version}})
				return
			}
			state.record("kv_read")
			state.mu.Lock()
			readDenied := state.kvReadDenied
			missing := state.payloadMissing
			value, exists := state.sealed[path]
			version := state.versions[path]
			state.mu.Unlock()
			if readDenied {
				w.WriteHeader(http.StatusForbidden)
				json.NewEncoder(w).Encode(map[string]any{"errors": []string{"permission denied"}})
				return
			}
			if missing || !exists || version == 0 {
				w.WriteHeader(http.StatusNotFound)
				json.NewEncoder(w).Encode(map[string]any{"errors": []string{}})
				return
			}
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{
					"data":     map[string]any{"sealed": value},
					"metadata": map[string]any{"version": version},
				},
			})
			return
		}

		w.WriteHeader(http.StatusNotFound)
	})

	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return server, state
}

func c14AllScopes() []string {
	return []string{"transit:encrypt", "transit:decrypt", "kv:read", "kv:write"}
}

func newC14Adapter(t *testing.T, address string, scopes []string) *provider.Adapter {
	t.Helper()
	if scopes == nil {
		scopes = c14AllScopes()
	}
	adapter, err := provider.NewOpenBaoAdapter(context.Background(), provider.Config{
		Address:      address,
		KEKMount:     "transit",
		PayloadMount: "kv",
		Environment:  "local",
		Timeout:      2 * time.Second,
	}, provider.WorkloadIdentity{
		Role:   "workload-c14",
		Token:  "s.c14-scoped-token",
		Scopes: scopes,
	})
	if err != nil {
		t.Fatalf("create C14 provider adapter: %v", err)
	}
	return adapter
}

func c14Mapper(vault c14FixtureVault) *auth.ScopeMapper {
	return auth.NewScopeMapper(auth.ScopeMapperConfig{
		VaultKEKMap:   map[string]string{vault.VaultID: vault.KEKID},
		VaultMountMap: map[string]string{vault.VaultID: vault.Mount},
		VaultRoleMap:  map[string]string{vault.VaultID: vault.Role},
	})
}

func c14Identity(pos c14PositiveFixture, expiresAt time.Time) *auth.Identity {
	return &auth.Identity{
		Subject:       pos.Identity.Subject,
		Email:         pos.Identity.Email,
		VaultRole:     pos.Identity.VaultRole,
		AllowedOwners: pos.Identity.AllowedOwners,
		AllowedScopes: pos.Identity.AllowedScopes,
		ExpiresAt:     expiresAt.Unix(),
	}
}

// c14Harness bundles the real storage, provider, auth and reveal collaborators
// used by the C14 acceptance and negative cases.
type c14Harness struct {
	server     *httptest.Server
	state      *c14ProviderState
	adapter    *provider.Adapter
	service    *secrets.Service
	mapper     *auth.ScopeMapper
	store      *storage.Store
	dir        string
	pos        c14PositiveFixture
	identity   *auth.Identity
	session    *auth.Session
	sessionMgr *auth.SessionManager
	stepUp     *auth.StepUpManager
}

func newC14Harness(t *testing.T) *c14Harness {
	t.Helper()
	var pos c14PositiveFixture
	loadC14Fixture(t, "positive.json", &pos)

	server, state := newC14Provider(t)
	adapter := newC14Adapter(t, server.URL, nil)
	dir := filepath.Join(t.TempDir(), "c14-reveal-store")
	store, _, err := storage.Open(dir)
	if err != nil {
		t.Fatalf("open C14 storage: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	ctx := context.Background()
	sessionMgr, err := auth.NewSessionManager(auth.DefaultSessionConfig(), nil)
	if err != nil {
		t.Fatalf("create session manager: %v", err)
	}
	stepUpMgr, err := auth.NewStepUpManager(auth.DefaultStepUpConfig(), nil)
	if err != nil {
		t.Fatalf("create step-up manager: %v", err)
	}
	mapper := c14Mapper(pos.Vault)
	identity := c14Identity(pos, time.Now().Add(time.Hour))
	session, _, err := sessionMgr.CreateSession(ctx, identity, auth.ClientInfo{})
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	return &c14Harness{
		server:     server,
		state:      state,
		adapter:    adapter,
		service:    secrets.NewService(mapper, adapter, store),
		mapper:     mapper,
		store:      store,
		dir:        dir,
		pos:        pos,
		identity:   identity,
		session:    session,
		sessionMgr: sessionMgr,
		stepUp:     stepUpMgr,
	}
}

func (h *c14Harness) writeSecret(t *testing.T, plaintext string, expectedVersion int64, operationID string) *secrets.WriteOutcome {
	t.Helper()
	outcome, err := h.service.WriteSecret(context.Background(), secrets.WriteRequest{
		VaultID:         h.pos.Vault.VaultID,
		SecretPath:      h.pos.SecretPath,
		ExpectedVersion: expectedVersion,
		Plaintext:       []byte(plaintext),
		Classification:  h.pos.Classification,
		KEKID:           h.pos.Vault.KEKID,
		Owner:           h.identity.Email,
		Identity:        h.identity,
		OperationID:     operationID,
	})
	if err != nil {
		t.Fatalf("C14 write failed: %v", err)
	}
	return outcome
}

func (h *c14Harness) grant(t *testing.T, session *auth.Session, resource string) string {
	t.Helper()
	_, token, err := h.stepUp.IssueGrant(context.Background(), session, auth.ActionRevealSecret, resource)
	if err != nil {
		t.Fatalf("issue step-up grant: %v", err)
	}
	return token.Plaintext()
}

func (h *c14Harness) request(session *auth.Session, token string) secrets.RevealRequest {
	if session == nil {
		session = h.session
	}
	return secrets.RevealRequest{
		VaultID:       h.pos.Vault.VaultID,
		SecretPath:    h.pos.SecretPath,
		Owner:         h.identity.Email,
		Identity:      h.identity,
		Session:       session,
		StepUpManager: h.stepUp,
		StepUpToken:   token,
	}
}

func (h *c14Harness) providerCalls() (int, int) {
	return h.state.calls("transit_decrypt"), h.state.calls("kv_read")
}

func (h *c14Harness) readCommittedMetadata(t *testing.T) storage.Record {
	t.Helper()
	record, err := h.store.Read(context.Background(), storage.ReadRequest{
		Owner: h.identity.Email,
		Scope: h.pos.Vault.VaultID,
		Name:  h.pos.SecretPath,
	})
	if err != nil {
		t.Fatalf("read committed metadata: %v", err)
	}
	return record
}

func c14AssertNoPlaintext(t *testing.T, what string, payload []byte, canary string) {
	t.Helper()
	if strings.Contains(string(payload), canary) {
		t.Fatalf("plaintext canary leaked into %s", what)
	}
}

func c14AssertCode(t *testing.T, err error, code string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected failure with code %s, got nil", code)
	}
	var revealErr *secrets.RevealError
	if errors.As(err, &revealErr) && revealErr.Code == code {
		return
	}
	var authErr *auth.Error
	if errors.As(err, &authErr) && string(authErr.Code) == code {
		return
	}
	var providerErr *provider.Error
	if errors.As(err, &providerErr) && string(providerErr.Code) == code {
		return
	}
	var storageErr *storage.Error
	if errors.As(err, &storageErr) && string(storageErr.Code) == code {
		return
	}
	t.Fatalf("expected code %s, got %T: %v", code, err, err)
}

func c14ScanDirectory(t *testing.T, root, canary string) int {
	t.Helper()
	checked := 0
	err := filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil || info.IsDir() {
			return walkErr
		}
		checked++
		content, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		if strings.Contains(string(content), canary) {
			t.Fatalf("plaintext canary found in %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("scan %s: %v", root, err)
	}
	return checked
}

// TestC14BoundedAuthorizedRevealF08 proves the F08 acceptance on the real
// storage/provider boundaries: provider-owned sealed bytes, mandatory fresh
// step-up, no-store response and no plaintext in metadata, errors or audit content.
func TestC14BoundedAuthorizedRevealF08(t *testing.T) {
	var pos c14PositiveFixture
	loadC14Fixture(t, "positive.json", &pos)
	var exp c14ExpectedOutput
	loadC14Fixture(t, "expected-output.json", &exp)
	var metadataFixture contracts.SecretMetadata
	metadataBytes := loadC14Fixture(t, pos.MetadataFile, &metadataFixture)

	if exp.Requirement != "F08" || exp.Status != "passed" {
		t.Fatalf("unexpected C14 expected-output fixture: %+v", exp)
	}
	if _, failure := contracts.DecodeSecret(context.Background(), metadataBytes); failure != nil {
		t.Fatalf("C14 metadata fixture must satisfy the frozen v1 contract: %+v", failure)
	}
	if metadataFixture.VaultID != pos.Vault.VaultID || metadataFixture.Envelope.KEKID != pos.Vault.KEKID {
		t.Fatalf("C14 metadata fixture must match the positive vault binding")
	}

	ctx := context.Background()
	harness := newC14Harness(t)

	// 1. Scoped write: the provider owns the sealed bytes, metadata storage does not.
	outcome := harness.writeSecret(t, pos.PlaintextCanary, 0, "op-c14-init-0001")
	if outcome.Version != 1 {
		t.Fatalf("expected initial version 1, got %d", outcome.Version)
	}
	record := harness.readCommittedMetadata(t)
	c14AssertNoPlaintext(t, "metadata storage", record.Metadata, pos.PlaintextCanary)
	key := c14PayloadKey(pos.Vault.VaultID, pos.SecretPath, 1)
	stored := harness.state.payload(key)
	if stored == "" {
		t.Fatalf("provider owns no sealed payload at %s", key)
	}
	sealedBytes, err := base64.StdEncoding.DecodeString(stored)
	if err != nil {
		t.Fatalf("provider payload is not base64: %v", err)
	}
	c14AssertNoPlaintext(t, "provider-owned sealed bytes", sealedBytes, pos.PlaintextCanary)
	if checked := c14ScanDirectory(t, harness.dir, pos.PlaintextCanary); checked == 0 {
		t.Fatalf("no storage files inspected in %s", harness.dir)
	}
	if harness.state.calls("kv_write") != 1 {
		t.Fatalf("expected exactly one provider payload write, got %d", harness.state.calls("kv_write"))
	}
	if decrypts, reads := harness.providerCalls(); decrypts != exp.ProviderCallBudget || reads != exp.ProviderCallBudget {
		t.Fatalf("no provider decrypt/read may happen before authorization: decrypt=%d read=%d", decrypts, reads)
	}

	// 2. Fresh step-up reveal returns the exact plaintext transiently.
	token := harness.grant(t, harness.session, pos.SecretPath)
	revealed, err := harness.service.RevealSecret(ctx, harness.request(harness.session, token))
	if err != nil {
		t.Fatalf("authorized reveal failed: %v", err)
	}
	if string(revealed.Plaintext().Plaintext()) != pos.PlaintextCanary {
		t.Fatalf("revealed plaintext mismatch")
	}
	if revealed.Version != outcome.Version {
		t.Fatalf("revealed version %d does not match committed version %d", revealed.Version, outcome.Version)
	}
	if revealed.Classification != pos.Classification || revealed.Algorithm != "AES-256-GCM" {
		t.Fatalf("unexpected reveal metadata: %s/%s", revealed.Classification, revealed.Algorithm)
	}
	if revealed.MetadataDigest != outcome.MetadataHash {
		t.Fatalf("revealed metadata digest %s does not match the committed digest %s", revealed.MetadataDigest, outcome.MetadataHash)
	}
	if decrypts, reads := harness.providerCalls(); decrypts != pos.ExpectedCalls["transit_decrypt"] || reads != pos.ExpectedCalls["payload_read"] {
		t.Fatalf("unexpected provider call budget: decrypt=%d read=%d", decrypts, reads)
	}

	// 3. No-store response contract, streamed once.
	recorder := httptest.NewRecorder()
	if err := revealed.WriteResponse(recorder); err != nil {
		t.Fatalf("write reveal response: %v", err)
	}
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200 reveal response, got %d", recorder.Code)
	}
	for name, want := range pos.ExpectedHeaders {
		if got := recorder.Header().Get(name); got != want {
			t.Fatalf("response header %s = %q, want %q", name, got, want)
		}
	}
	if recorder.Body.String() != pos.PlaintextCanary {
		t.Fatalf("response body did not carry the revealed plaintext once")
	}

	// 4. Traces, serialization and audit content stay secret-free.
	rendered := []string{
		fmt.Sprintf("%v", revealed),
		fmt.Sprintf("%#v", revealed),
		fmt.Sprintf("%s", revealed.Plaintext()),
		fmt.Sprintf("%x", revealed.Plaintext()),
		fmt.Sprintf("%q", revealed.Plaintext()),
	}
	for _, form := range rendered {
		if !strings.Contains(form, "[REDACTED]") {
			t.Fatalf("formatted reveal output must be redacted: %s", form)
		}
		c14AssertNoPlaintext(t, "formatted reveal output", []byte(form), pos.PlaintextCanary)
	}
	serialized, err := json.Marshal(revealed)
	if err != nil {
		t.Fatalf("marshal reveal response: %v", err)
	}
	c14AssertNoPlaintext(t, "serialized reveal response", serialized, pos.PlaintextCanary)
	if !strings.Contains(string(serialized), exp.Response.PlaintextSerialization) {
		t.Fatalf("serialized reveal response must redact plaintext: %s", serialized)
	}
	audit := revealed.AuditContent()
	if audit.Action != string(auth.ActionRevealSecret) || audit.VaultID != pos.Vault.VaultID || audit.Outcome != "revealed" {
		t.Fatalf("unexpected audit content projection: %+v", audit)
	}
	auditBytes, err := json.Marshal(audit)
	if err != nil {
		t.Fatalf("marshal audit content: %v", err)
	}
	c14AssertNoPlaintext(t, "audit content", auditBytes, pos.PlaintextCanary)
	if exp.Response.AuditContentExcludesPlaintext {
		if !strings.Contains(string(auditBytes), pos.SecretPath) || !strings.Contains(string(auditBytes), pos.Identity.Subject) {
			t.Fatalf("audit content must carry the attributable actor and path without plaintext: %s", auditBytes)
		}
	}

	// 5. The transient buffer is destroyed after the response is written.
	if revealed.Plaintext() != nil {
		t.Fatalf("reveal response must destroy its transient plaintext after writing")
	}

	// 6. Rotation keeps the versioned provider payload aligned with metadata.
	updated := harness.writeSecret(t, pos.RotatedCanary, 1, "op-c14-rotate-0002")
	if updated.Version != 2 {
		t.Fatalf("expected rotated version 2, got %d", updated.Version)
	}
	token = harness.grant(t, harness.session, pos.SecretPath)
	rotated, err := harness.service.RevealSecret(ctx, harness.request(harness.session, token))
	if err != nil {
		t.Fatalf("rotated reveal failed: %v", err)
	}
	if string(rotated.Plaintext().Plaintext()) != pos.RotatedCanary {
		t.Fatalf("rotated reveal returned stale plaintext")
	}
	rotated.Destroy()
	if harness.state.payload(c14PayloadKey(pos.Vault.VaultID, pos.SecretPath, 2)) == "" {
		t.Fatalf("rotated provider payload is missing")
	}
	record = harness.readCommittedMetadata(t)
	c14AssertNoPlaintext(t, "rotated metadata storage", record.Metadata, pos.RotatedCanary)

	// 7. Restart recovery: a committed version is still revealable.
	if err := harness.store.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}
	reopened, report, err := storage.Open(harness.dir)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	defer reopened.Close()
	if report.ManifestVersion == 0 {
		t.Fatalf("reopened store reported no committed manifest: %+v", report)
	}
	restarted := secrets.NewService(harness.mapper, harness.adapter, reopened)
	token = harness.grant(t, harness.session, pos.SecretPath)
	afterRestart, err := restarted.RevealSecret(ctx, harness.request(harness.session, token))
	if err != nil {
		t.Fatalf("reveal after restart failed: %v", err)
	}
	if string(afterRestart.Plaintext().Plaintext()) != pos.RotatedCanary {
		t.Fatalf("reveal after restart returned the wrong version")
	}
	afterRestart.Destroy()
}

// TestC14RevealNegativeCasesF08 drives every fixture negative case over the real
// boundaries and asserts authorizations fail before sensitive provider effects.
func TestC14RevealNegativeCasesF08(t *testing.T) {
	var pos c14PositiveFixture
	loadC14Fixture(t, "positive.json", &pos)
	var neg c14NegativeFixture
	loadC14Fixture(t, "negative.json", &neg)
	var exp c14ExpectedOutput
	loadC14Fixture(t, "expected-output.json", &exp)

	ctx := context.Background()
	preSideEffect := map[string]bool{
		"missing-identity-rejected":              true,
		"expired-identity-rejected":              true,
		"replayed-identity-rejected":             true,
		"unrelated-owner-denied":                 true,
		"foreign-vault-scope-denied":             true,
		"missing-stepup-rejected":                true,
		"expired-stepup-rejected":                true,
		"cross-session-stepup-replay-rejected":   true,
		"stepup-scope-mismatch-denied":           true,
		"revoked-session-cannot-reveal":          true,
		"forged-header-cannot-authorize-reveal":  true,
		"traversal-cannot-widen-reveal":          true,
		"prefix-collision-cannot-widen-reveal":   true,
		"identity-provider-unavailable-fails-closed": true,
		"foreign-kek-envelope-denied":            true,
	}
	seenCanaryCase := false

	for _, testCase := range neg.Cases {
		if testCase.Kind == "plaintext_canary" {
			seenCanaryCase = true
			continue
		}
		t.Run(testCase.Case, func(t *testing.T) {
			harness := newC14Harness(t)
			if testCase.Case != "orphaned-provider-payload-conflict-fails-closed" {
				harness.writeSecret(t, pos.PlaintextCanary, 0, "op-c14-negative-01")
			}
			key := c14PayloadKey(pos.Vault.VaultID, pos.SecretPath, 1)
			request := harness.request(harness.session, harness.grant(t, harness.session, pos.SecretPath))

			var err error
			switch testCase.Case {
			case "missing-identity-rejected":
				request.Identity = nil
				_, err = harness.service.RevealSecret(ctx, request)

			case "expired-identity-rejected":
				request.Identity = c14Identity(pos, time.Now().Add(-10*time.Minute))
				_, err = harness.service.RevealSecret(ctx, request)

			case "replayed-identity-rejected":
				oidc, createErr := auth.NewProvider(auth.Config{
					IssuerURL:   "https://auth.keyhelix.local",
					ClientID:    "keyhelix-client",
					RedirectURI: "http://localhost:8080/callback",
				})
				if createErr != nil {
					t.Fatalf("create OIDC provider: %v", createErr)
				}
				// A replayed identity token carries a stale nonce and never becomes a verified identity.
				_, err = oidc.ParseAndVerifyIDToken(makeSyntheticJWT(
					map[string]any{"alg": "RS256", "typ": "JWT"},
					map[string]any{
						"iss":   "https://auth.keyhelix.local",
						"sub":   pos.Identity.Subject,
						"aud":   "keyhelix-client",
						"exp":   time.Now().Add(time.Hour).Unix(),
						"iat":   time.Now().Add(-time.Hour).Unix(),
						"nonce": "replayed-nonce",
					},
				), "expected-fresh-nonce", time.Now().UTC())

			case "unrelated-owner-denied":
				request.Owner = testCase.TargetOwner
				_, err = harness.service.RevealSecret(ctx, request)

			case "foreign-vault-scope-denied":
				request.VaultID = testCase.TargetVault
				_, err = harness.service.RevealSecret(ctx, request)

			case "missing-stepup-rejected":
				_, err = harness.service.RevealSecret(ctx, harness.request(harness.session, ""))

			case "expired-stepup-rejected":
				expiredGrant, expiredToken, issueErr := harness.stepUp.IssueGrant(ctx, harness.session, auth.ActionRevealSecret, pos.SecretPath)
				if issueErr != nil {
					t.Fatalf("issue grant: %v", issueErr)
				}
				expiredGrant.ExpiresAt = time.Now().Add(-time.Minute)
				_, err = harness.service.RevealSecret(ctx, harness.request(harness.session, expiredToken.Plaintext()))

			case "cross-session-stepup-replay-rejected":
				otherSession, _, sessionErr := harness.sessionMgr.CreateSession(ctx, c14Identity(pos, time.Now().Add(time.Hour)), auth.ClientInfo{})
				if sessionErr != nil {
					t.Fatalf("create second session: %v", sessionErr)
				}
				_, err = harness.service.RevealSecret(ctx, harness.request(otherSession, request.StepUpToken))

			case "stepup-scope-mismatch-denied":
				_, err = harness.service.RevealSecret(ctx, harness.request(harness.session, harness.grant(t, harness.session, testCase.OtherResource)))

			case "revoked-session-cannot-reveal":
				if revokeErr := harness.sessionMgr.RevokeSession(ctx, harness.session.ID, "departing user"); revokeErr != nil {
					t.Fatalf("revoke session: %v", revokeErr)
				}
				_, err = harness.service.RevealSecret(ctx, request)

			case "forged-header-cannot-authorize-reveal":
				forged := request
				forged.Headers = http.Header{}
				for name, value := range testCase.Headers {
					forged.Headers.Set(name, value)
				}
				_, err = harness.service.RevealSecret(ctx, forged)

			case "traversal-cannot-widen-reveal":
				widened := request
				widened.SecretPath = testCase.RawPath
				_, err = harness.service.RevealSecret(ctx, widened)

			case "prefix-collision-cannot-widen-reveal":
				widened := request
				widened.SecretPath = testCase.RawPath
				widened.StepUpToken = harness.grant(t, harness.session, testCase.RawPath)
				_, err = harness.service.RevealSecret(ctx, widened)

			case "identity-provider-unavailable-fails-closed":
				harness.mapper.SetIDPOnline(false)
				_, err = harness.service.RevealSecret(ctx, request)

			case "provider-offline-reveal-fails-closed":
				harness.server.Close()
				_, err = harness.service.RevealSecret(ctx, request)

			case "provider-sealed-reveal-fails-closed":
				harness.state.setSealed(true)
				_, err = harness.service.RevealSecret(ctx, request)
				if decrypts, _ := harness.providerCalls(); decrypts == 0 {
					t.Fatalf("expected the sealed provider to be reached by the decrypt attempt")
				}

			case "workload-without-decrypt-scope-denied":
				restricted := newC14Adapter(t, harness.server.URL, testCase.WorkloadScopes)
				_, err = secrets.NewService(harness.mapper, restricted, harness.store).RevealSecret(ctx, request)
				if decrypts, reads := harness.providerCalls(); decrypts != 0 || reads != 0 {
					t.Fatalf("a workload without decrypt scope must not reach the provider: decrypt=%d read=%d", decrypts, reads)
				}

			case "workload-without-payload-read-scope-denied":
				restricted := newC14Adapter(t, harness.server.URL, testCase.WorkloadScopes)
				_, err = secrets.NewService(harness.mapper, restricted, harness.store).RevealSecret(ctx, request)
				if decrypts, reads := harness.providerCalls(); decrypts != 1 || reads != 0 {
					t.Fatalf("a workload without payload-read scope must fail before reading bytes: decrypt=%d read=%d", decrypts, reads)
				}

			case "tampered-ciphertext-denied":
				harness.state.tamper(key, false)
				_, err = harness.service.RevealSecret(ctx, request)
				c14AssertCode(t, err, testCase.ExpectedCode)
				harness.state.tamper(key, true)
				_, integrityErr := harness.service.RevealSecret(ctx, request)
				c14AssertCode(t, integrityErr, exp.GuardCodes["reveal_integrity_failure"])
				if decrypts, reads := harness.providerCalls(); decrypts != 2 || reads != 2 {
					t.Fatalf("tampered payload attempts must not be short-circuited: decrypt=%d read=%d", decrypts, reads)
				}
				return

			case "missing-provider-payload-fails-closed":
				harness.state.setPayloadMissing(true)
				_, err = harness.service.RevealSecret(ctx, request)

			case "foreign-kek-envelope-denied":
				var seeded contracts.SecretMetadata
				seededBytes := loadC14Fixture(t, pos.MetadataFile, &seeded)
				foreignOwner := "carol@keyhelix.local"
				foreignMetadata := strings.Replace(string(seededBytes), pos.Vault.KEKID, testCase.ForeignKEKID, 1)
				foreignIdentity := &auth.Identity{
					Subject:       "usr_carol_01",
					Email:         foreignOwner,
					VaultRole:     pos.Identity.VaultRole,
					AllowedOwners: []string{foreignOwner},
					AllowedScopes: []string{"secret:read", "app/prod/*"},
					ExpiresAt:     time.Now().Add(time.Hour).Unix(),
				}
				foreignSession, _, sessionErr := harness.sessionMgr.CreateSession(ctx, foreignIdentity, auth.ClientInfo{})
				if sessionErr != nil {
					t.Fatalf("create foreign session: %v", sessionErr)
				}
				if _, writeErr := harness.store.Write(ctx, storage.WriteRequest{
					OperationID:     "op-c14-foreign-kek-01",
					Owner:           foreignOwner,
					Scope:           pos.Vault.VaultID,
					Name:            pos.SecretPath,
					ExpectedVersion: 0,
					Metadata:        []byte(foreignMetadata),
				}); writeErr != nil {
					t.Fatalf("seed foreign envelope metadata: %v", writeErr)
				}
				foreignRequest := secrets.RevealRequest{
					VaultID:       pos.Vault.VaultID,
					SecretPath:    pos.SecretPath,
					Owner:         foreignOwner,
					Identity:      foreignIdentity,
					Session:       foreignSession,
					StepUpManager: harness.stepUp,
					StepUpToken:   harness.grant(t, foreignSession, pos.SecretPath),
				}
				_, err = harness.service.RevealSecret(ctx, foreignRequest)
				c14AssertCode(t, err, testCase.ExpectedCode)
				// Anti-oracle: a non-matching envelope and an absent record return one uniform denial.
				absent := foreignRequest
				absent.SecretPath = "app/prod/absent-oracle-check"
				absent.StepUpToken = harness.grant(t, foreignSession, absent.SecretPath)
				_, absentErr := harness.service.RevealSecret(ctx, absent)
				if absentErr == nil {
					t.Fatalf("expected a uniform denial for an absent record")
				}
				if absentErr.Error() != err.Error() {
					t.Fatalf("denial messages must be uniform: %q vs %q", err.Error(), absentErr.Error())
				}
				return

			case "stale-write-rejected-before-provider-call":
				_, err = harness.service.WriteSecret(ctx, secrets.WriteRequest{
					VaultID:         pos.Vault.VaultID,
					SecretPath:      pos.SecretPath,
					ExpectedVersion: 99,
					Plaintext:       []byte("stale-should-never-persist"),
					Classification:  pos.Classification,
					KEKID:           pos.Vault.KEKID,
					Owner:           harness.identity.Email,
					Identity:        harness.identity,
					OperationID:     "op-c14-stale-write-01",
				})
				if writes := harness.state.calls("kv_write"); writes != 1 {
					t.Fatalf("a stale write must not reach the provider payload store: writes=%d", writes)
				}
				_, duplicateErr := harness.service.WriteSecret(ctx, secrets.WriteRequest{
					VaultID:         pos.Vault.VaultID,
					SecretPath:      pos.SecretPath,
					ExpectedVersion: 0,
					Plaintext:       []byte(pos.RotatedCanary),
					Classification:  pos.Classification,
					KEKID:           pos.Vault.KEKID,
					Owner:           harness.identity.Email,
					Identity:        harness.identity,
					OperationID:     "op-c14-duplicate-create-01",
				})
				c14AssertCode(t, duplicateErr, exp.GuardCodes["already_exists"])
				if writes := harness.state.calls("kv_write"); writes != 1 {
					t.Fatalf("a duplicate create must not reach the provider payload store: writes=%d", writes)
				}

			case "orphaned-provider-payload-conflict-fails-closed":
				orphanKey := c14PayloadKey(pos.Vault.VaultID, pos.SecretPath, 1)
				harness.state.seedPayload(orphanKey, "orphan-sealed-bytes-without-metadata")
				_, err = harness.service.WriteSecret(ctx, secrets.WriteRequest{
					VaultID:         pos.Vault.VaultID,
					SecretPath:      pos.SecretPath,
					ExpectedVersion: 0,
					Plaintext:       []byte(pos.PlaintextCanary),
					Classification:  pos.Classification,
					KEKID:           pos.Vault.KEKID,
					Owner:           harness.identity.Email,
					Identity:        harness.identity,
					OperationID:     "op-c14-orphan-01",
				})
				c14AssertCode(t, err, testCase.ExpectedCode)
				if _, readErr := harness.store.Read(ctx, storage.ReadRequest{
					Owner: harness.identity.Email,
					Scope: pos.Vault.VaultID,
					Name:  pos.SecretPath,
				}); readErr == nil {
					t.Fatalf("a conflicted provider payload must not publish a metadata version")
				}

			default:
				t.Fatalf("unhandled C14 negative case %q", testCase.Case)
			}

			c14AssertCode(t, err, testCase.ExpectedCode)
			if err != nil {
				c14AssertNoPlaintext(t, "reveal failure message", []byte(err.Error()), pos.PlaintextCanary)
			}
			if preSideEffect[testCase.Case] {
				if decrypts, reads := harness.providerCalls(); decrypts != 0 || reads != 0 {
					t.Fatalf("case %s must fail before sensitive provider side effects: decrypt=%d read=%d", testCase.Case, decrypts, reads)
				}
			}
		})
	}

	if !seenCanaryCase {
		t.Fatalf("C14 negative fixture must include the provider-owns-secret-bytes canary case")
	}

	// The canary case: no tested path may persist or expose provider-owned plaintext.
	for _, testCase := range neg.Cases {
		if testCase.Kind != "plaintext_canary" {
			continue
		}
		harness := newC14Harness(t)
		harness.writeSecret(t, testCase.Canary, 0, "op-c14-canary-01")
		token := harness.grant(t, harness.session, pos.SecretPath)
		revealed, err := harness.service.RevealSecret(ctx, harness.request(harness.session, token))
		if err != nil {
			t.Fatalf("canary reveal failed: %v", err)
		}
		payload := revealed.Plaintext()
		revealed.Destroy()
		for _, b := range payload {
			if b != 0 {
				t.Fatalf("destroyed plaintext buffer must be zeroed")
			}
		}
		record := harness.readCommittedMetadata(t)
		c14AssertNoPlaintext(t, "metadata storage", record.Metadata, testCase.Canary)
		c14ScanDirectory(t, harness.dir, testCase.Canary)
		if testCase.ExpectedStorageOccurrence != exp.StoragePlaintextLeakCount {
			t.Fatalf("fixture canary expectation must stay at the verified leak count")
		}
	}
}
