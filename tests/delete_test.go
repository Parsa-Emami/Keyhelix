package storage_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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

type c19PositiveFixture struct {
	SchemaVersion    int                `json:"schema_version"`
	Provenance       string             `json:"provenance"`
	License          string             `json:"license"`
	Vault            c14FixtureVault    `json:"vault"`
	OperatorIdentity c14FixtureIdentity `json:"operator_identity"`
	UserIdentity     c14FixtureIdentity `json:"user_identity"`
	Secret           struct {
		SecretPath     string `json:"secret_path"`
		Classification string `json:"classification"`
		Sentinel       string `json:"sentinel"`
	} `json:"secret"`
	RetentionPolicy struct {
		RetentionDurationSeconds int64 `json:"retention_duration_seconds"`
	} `json:"retention_policy"`
	MetadataFile string `json:"metadata_file"`
}

type c19NegativeCase struct {
	Case                           string `json:"case"`
	Description                    string `json:"description"`
	ExpectedCode                   string `json:"expected_code,omitempty"`
	MalformedJSON                  string `json:"malformed_json,omitempty"`
	Sentinel                       string `json:"sentinel,omitempty"`
	ExpectedStorageOccurrenceCount int    `json:"expected_storage_occurrence_count,omitempty"`
}

type c19NegativeFixture struct {
	SchemaVersion int               `json:"schema_version"`
	Cases         []c19NegativeCase `json:"cases"`
}

type c19ExpectedOutput struct {
	SchemaVersion                         int               `json:"schema_version"`
	Requirement                           string            `json:"requirement"`
	Acceptance                            string            `json:"acceptance"`
	Status                                string            `json:"status"`
	DeleteAndDestroyAreDistinct           bool              `json:"delete_and_destroy_are_distinct"`
	RetentionAppliedOnDelete              bool              `json:"retention_applied_on_delete"`
	ExplicitOperatorActionEnforced        bool              `json:"explicit_operator_action_enforced"`
	DestructionIrreversibleAcrossRestart bool              `json:"destruction_irreversible_across_restart"`
	GuardCodes                            map[string]string `json:"guard_codes"`
	ProviderOwnsSecretBytes               bool              `json:"provider_owns_secret_bytes"`
}

func loadC19Fixture(t *testing.T, filename string, target any) []byte {
	t.Helper()
	path := filepath.Join("fixtures", "keyhelix", "C19", filename)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read C19 fixture %s: %v", filename, err)
	}
	if err := json.Unmarshal(data, target); err != nil {
		t.Fatalf("unmarshal C19 fixture %s: %v", filename, err)
	}
	return data
}

type c19ProviderState struct {
	mu         sync.Mutex
	sealed503  bool
	sealed     map[string]string
	versions   map[string]int
	transit    map[string]string
	callCounts map[string]int
}

func newC19Provider(t *testing.T) (*httptest.Server, *c19ProviderState) {
	t.Helper()
	state := &c19ProviderState{
		sealed:     make(map[string]string),
		versions:   make(map[string]int),
		transit:    make(map[string]string),
		callCounts: make(map[string]int),
	}
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
			w.WriteHeader(http.StatusServiceUnavailable)
			json.NewEncoder(w).Encode(map[string]any{"errors": []string{"Vault is sealed"}})
			return
		}

		switch {
		case strings.HasPrefix(r.URL.Path, "/v1/transit/encrypt/") && r.Method == http.MethodPost:
			state.mu.Lock()
			state.callCounts["transit_encrypt"]++
			state.mu.Unlock()

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
			state.mu.Lock()
			state.callCounts["transit_decrypt"]++
			state.mu.Unlock()

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
				state.mu.Lock()
				state.callCounts["kv_write"]++
				state.mu.Unlock()

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

			if r.Method == http.MethodDelete {
				state.mu.Lock()
				state.callCounts["kv_destroy"]++
				delete(state.sealed, path)
				state.versions[path] = 0
				state.mu.Unlock()
				w.WriteHeader(http.StatusNoContent)
				return
			}

			// GET (kv_read)
			state.mu.Lock()
			state.callCounts["kv_read"]++
			value, exists := state.sealed[path]
			version := state.versions[path]
			state.mu.Unlock()

			if !exists || version == 0 {
				w.WriteHeader(http.StatusNotFound)
				json.NewEncoder(w).Encode(map[string]any{"errors": []string{"not found"}})
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

type c19Harness struct {
	dir         string
	store       *storage.Store
	server      *httptest.Server
	state       *c19ProviderState
	adapter     *provider.Adapter
	mapper      *auth.ScopeMapper
	secretSvc   *secrets.Service
	sessionMgr  *auth.SessionManager
	stepUpMgr   *auth.StepUpManager
	operator    *auth.Identity
	user        *auth.Identity
	operatorSes *auth.Session
	userSes     *auth.Session
	pos         c19PositiveFixture
}

func newC19Harness(t *testing.T) *c19Harness {
	t.Helper()
	var pos c19PositiveFixture
	loadC19Fixture(t, "positive.json", &pos)

	server, state := newC19Provider(t)

	adapter, err := provider.NewOpenBaoAdapter(context.Background(), provider.Config{
		Address:      server.URL,
		KEKMount:     "transit",
		PayloadMount: "kv",
		Environment:  "test",
		AllowDevMode: true,
	}, provider.WorkloadIdentity{
		Role:   "vault-admin",
		Token:  "test-valid-root-token",
		Scopes: []string{"transit:encrypt", "transit:decrypt", "kv:read", "kv:write", "kv:destroy", "*"},
	})
	if err != nil {
		t.Fatalf("create provider adapter: %v", err)
	}

	dir := filepath.Join(t.TempDir(), "c19-deletion-store")
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
	secretSvc := secrets.NewService(mapper, adapter, store)

	sessionMgr, err := auth.NewSessionManager(auth.DefaultSessionConfig(), nil)
	if err != nil {
		t.Fatalf("create session manager: %v", err)
	}
	stepUpMgr, err := auth.NewStepUpManager(auth.DefaultStepUpConfig(), nil)
	if err != nil {
		t.Fatalf("create step-up manager: %v", err)
	}

	operator := &auth.Identity{
		Subject:       pos.OperatorIdentity.Subject,
		Email:         pos.OperatorIdentity.Email,
		VaultRole:     pos.OperatorIdentity.VaultRole,
		AllowedOwners: pos.OperatorIdentity.AllowedOwners,
		AllowedScopes: pos.OperatorIdentity.AllowedScopes,
		ExpiresAt:     time.Now().Add(time.Hour).Unix(),
	}
	operatorSes, _, err := sessionMgr.CreateSession(context.Background(), operator, auth.ClientInfo{})
	if err != nil {
		t.Fatalf("create operator session: %v", err)
	}

	user := &auth.Identity{
		Subject:       pos.UserIdentity.Subject,
		Email:         pos.UserIdentity.Email,
		VaultRole:     pos.UserIdentity.VaultRole,
		AllowedOwners: pos.UserIdentity.AllowedOwners,
		AllowedScopes: pos.UserIdentity.AllowedScopes,
		ExpiresAt:     time.Now().Add(time.Hour).Unix(),
	}
	userSes, _, err := sessionMgr.CreateSession(context.Background(), user, auth.ClientInfo{})
	if err != nil {
		t.Fatalf("create user session: %v", err)
	}

	return &c19Harness{
		dir:         dir,
		store:       store,
		server:      server,
		state:       state,
		adapter:     adapter,
		mapper:      mapper,
		secretSvc:   secretSvc,
		sessionMgr:  sessionMgr,
		stepUpMgr:   stepUpMgr,
		operator:    operator,
		user:        user,
		operatorSes: operatorSes,
		userSes:     userSes,
		pos:         pos,
	}
}

func (h *c19Harness) issueStepUpToken(t *testing.T, session *auth.Session) string {
	t.Helper()
	_, token, err := h.stepUpMgr.IssueGrant(context.Background(), session, auth.ActionRevealSecret, h.pos.Secret.SecretPath)
	if err != nil {
		t.Fatalf("issue step-up grant: %v", err)
	}
	return token.Plaintext()
}

// TestC19DeleteAndDestroyAreDistinctF13 tests that delete (soft-delete with provider retention)
// and destroy (irreversible version destruction requiring explicit operator action) are distinct.
func TestC19DeleteAndDestroyAreDistinctF13(t *testing.T) {
	h := newC19Harness(t)
	ctx := context.Background()

	var expected c19ExpectedOutput
	loadC19Fixture(t, "expected-output.json", &expected)

	// Step 1: Write secret (v1)
	writeOutcome, err := h.secretSvc.WriteSecret(ctx, secrets.WriteRequest{
		VaultID:         h.pos.Vault.VaultID,
		SecretPath:      h.pos.Secret.SecretPath,
		ExpectedVersion: 0,
		Plaintext:       []byte(h.pos.Secret.Sentinel),
		Classification:  h.pos.Secret.Classification,
		KEKID:           h.pos.Vault.KEKID,
		Identity:        h.operator,
	})
	if err != nil {
		t.Fatalf("WriteSecret failed: %v", err)
	}
	if writeOutcome.Version != 1 {
		t.Fatalf("expected version 1, got %d", writeOutcome.Version)
	}

	// Step 2: Confirm active reveal succeeds
	stepUpToken := h.issueStepUpToken(t, h.operatorSes)
	revealResp, err := h.secretSvc.RevealSecret(ctx, secrets.RevealRequest{
		VaultID:       h.pos.Vault.VaultID,
		SecretPath:    h.pos.Secret.SecretPath,
		Identity:      h.operator,
		Session:       h.operatorSes,
		StepUpManager: h.stepUpMgr,
		StepUpToken:   stepUpToken,
	})
	if err != nil {
		t.Fatalf("RevealSecret failed on active version: %v", err)
	}
	if string(revealResp.Plaintext()) != h.pos.Secret.Sentinel {
		t.Fatalf("revealed plaintext mismatch; expected %s, got %s", h.pos.Secret.Sentinel, string(revealResp.Plaintext()))
	}
	revealResp.Destroy()

	// Verify lifecycle query shows ACTIVE
	lc, err := h.secretSvc.GetVersionLifecycle(ctx, h.pos.Vault.VaultID, h.pos.Secret.SecretPath, 1, h.operator)
	if err != nil {
		t.Fatalf("GetVersionLifecycle failed: %v", err)
	}
	if lc.Status != secrets.VersionStatusActive {
		t.Fatalf("expected ACTIVE status, got %s", lc.Status)
	}

	// Step 3: Execute soft-deletion (DeleteSecret)
	retentionDuration := time.Duration(h.pos.RetentionPolicy.RetentionDurationSeconds) * time.Second
	delOutcome, err := h.secretSvc.DeleteSecret(ctx, secrets.DeleteRequest{
		VaultID:           h.pos.Vault.VaultID,
		SecretPath:        h.pos.Secret.SecretPath,
		Version:           1,
		RetentionDuration: retentionDuration,
		Identity:          h.operator,
	})
	if err != nil {
		t.Fatalf("DeleteSecret failed: %v", err)
	}
	if delOutcome.Status != secrets.VersionStatusDeleted {
		t.Fatalf("expected DELETED status, got %s", delOutcome.Status)
	}
	if delOutcome.DeletedAt == "" || delOutcome.RetainUntil == "" {
		t.Fatalf("expected non-empty DeletedAt and RetainUntil, got deleted_at=%s retain_until=%s", delOutcome.DeletedAt, delOutcome.RetainUntil)
	}

	// Provider retention check: sealed payload MUST still exist in provider storage!
	retainedPayload, err := h.adapter.ReadSealedPayload(ctx, provider.SealedRef{
		VaultID: h.pos.Vault.VaultID,
		Path:    h.pos.Secret.SecretPath,
		Version: 1,
	})
	if err != nil {
		t.Fatalf("provider ReadSealedPayload failed during retention; payload was prematurely purged: %v", err)
	}
	if len(retainedPayload) == 0 {
		t.Fatalf("retained payload is empty")
	}

	// RevealSecret MUST fail while soft-deleted
	stepUpToken2 := h.issueStepUpToken(t, h.operatorSes)
	_, err = h.secretSvc.RevealSecret(ctx, secrets.RevealRequest{
		VaultID:       h.pos.Vault.VaultID,
		SecretPath:    h.pos.Secret.SecretPath,
		Identity:      h.operator,
		Session:       h.operatorSes,
		StepUpManager: h.stepUpMgr,
		StepUpToken:   stepUpToken2,
	})
	if err == nil {
		t.Fatalf("expected RevealSecret to fail on deleted secret, but it succeeded")
	}

	// Step 4: Undelete / Restore the secret version
	undelOutcome, err := h.secretSvc.UndeleteSecret(ctx, secrets.UndeleteRequest{
		VaultID:    h.pos.Vault.VaultID,
		SecretPath: h.pos.Secret.SecretPath,
		Version:    1,
		Identity:   h.operator,
	})
	if err != nil {
		t.Fatalf("UndeleteSecret failed: %v", err)
	}
	if undelOutcome.Status != secrets.VersionStatusActive {
		t.Fatalf("expected restored status ACTIVE, got %s", undelOutcome.Status)
	}

	// RevealSecret MUST succeed again after undelete
	stepUpToken3 := h.issueStepUpToken(t, h.operatorSes)
	restoredReveal, err := h.secretSvc.RevealSecret(ctx, secrets.RevealRequest{
		VaultID:       h.pos.Vault.VaultID,
		SecretPath:    h.pos.Secret.SecretPath,
		Identity:      h.operator,
		Session:       h.operatorSes,
		StepUpManager: h.stepUpMgr,
		StepUpToken:   stepUpToken3,
	})
	if err != nil {
		t.Fatalf("RevealSecret failed after undelete: %v", err)
	}
	if string(restoredReveal.Plaintext()) != h.pos.Secret.Sentinel {
		t.Fatalf("restored plaintext mismatch")
	}
	restoredReveal.Destroy()

	// Step 5: Destruction guard - Missing explicit operator action flag MUST fail
	_, err = h.secretSvc.DestroySecretVersion(ctx, secrets.DestroyRequest{
		VaultID:                h.pos.Vault.VaultID,
		SecretPath:             h.pos.Secret.SecretPath,
		Version:                undelOutcome.Version,
		ExplicitOperatorAction: false,
		Confirmation:           "",
		Identity:               h.operator,
	})
	if err == nil {
		t.Fatalf("expected DestroySecretVersion without explicit operator action to fail, but it succeeded")
	}
	var delErr *secrets.DeletionError
	if !strings.Contains(err.Error(), expected.GuardCodes["explicit_operator_action_required"]) {
		t.Fatalf("expected error containing %s, got: %v", expected.GuardCodes["explicit_operator_action_required"], err)
	}

	// Step 6: Destruction guard - Non-operator identity MUST fail
	_, err = h.secretSvc.DestroySecretVersion(ctx, secrets.DestroyRequest{
		VaultID:                h.pos.Vault.VaultID,
		SecretPath:             h.pos.Secret.SecretPath,
		Version:                undelOutcome.Version,
		ExplicitOperatorAction: true,
		Confirmation:           "DESTROY",
		Identity:               h.user, // role developer
	})
	if err == nil {
		t.Fatalf("expected DestroySecretVersion with non-operator identity to fail, but it succeeded")
	}

	// Step 7: Explicit irreversible destruction by authorized operator
	dstOutcome, err := h.secretSvc.DestroySecretVersion(ctx, secrets.DestroyRequest{
		VaultID:                h.pos.Vault.VaultID,
		SecretPath:             h.pos.Secret.SecretPath,
		Version:                undelOutcome.Version,
		ExplicitOperatorAction: true,
		Confirmation:           "DESTROY",
		Identity:               h.operator,
	})
	if err != nil {
		t.Fatalf("DestroySecretVersion failed: %v", err)
	}
	if dstOutcome.Status != secrets.VersionStatusDestroyed {
		t.Fatalf("expected status DESTROYED, got %s", dstOutcome.Status)
	}
	if dstOutcome.DestroyedAt == "" || dstOutcome.DestroyedBy != h.operator.Subject {
		t.Fatalf("expected valid destroyed metadata; got at=%s by=%s", dstOutcome.DestroyedAt, dstOutcome.DestroyedBy)
	}

	// Assert provider sealed payload is permanently purged!
	_, err = h.adapter.ReadSealedPayload(ctx, provider.SealedRef{
		VaultID: h.pos.Vault.VaultID,
		Path:    h.pos.Secret.SecretPath,
		Version: 1,
	})
	if err == nil {
		t.Fatalf("expected provider ReadSealedPayload to fail after destruction, but payload still exists!")
	}

	// Assert RevealSecret fails closed
	stepUpToken4 := h.issueStepUpToken(t, h.operatorSes)
	_, err = h.secretSvc.RevealSecret(ctx, secrets.RevealRequest{
		VaultID:       h.pos.Vault.VaultID,
		SecretPath:    h.pos.Secret.SecretPath,
		Identity:      h.operator,
		Session:       h.operatorSes,
		StepUpManager: h.stepUpMgr,
		StepUpToken:   stepUpToken4,
	})
	if err == nil {
		t.Fatalf("expected RevealSecret to fail on destroyed secret, but it succeeded")
	}

	// Step 8: Irreversibility invariant - Undelete on destroyed version MUST be refused!
	_, err = h.secretSvc.UndeleteSecret(ctx, secrets.UndeleteRequest{
		VaultID:    h.pos.Vault.VaultID,
		SecretPath: h.pos.Secret.SecretPath,
		Version:    undelOutcome.Version,
		Identity:   h.operator,
	})
	if err == nil {
		t.Fatalf("expected UndeleteSecret on destroyed version to fail, but it succeeded")
	}
	if !strings.Contains(err.Error(), expected.GuardCodes["version_destroyed"]) {
		t.Fatalf("expected error containing %s, got: %v", expected.GuardCodes["version_destroyed"], err)
	}

	// Soft-delete on destroyed version MUST also be refused!
	_, err = h.secretSvc.DeleteSecret(ctx, secrets.DeleteRequest{
		VaultID:           h.pos.Vault.VaultID,
		SecretPath:        h.pos.Secret.SecretPath,
		Version:           undelOutcome.Version,
		RetentionDuration: retentionDuration,
		Identity:          h.operator,
	})
	if err == nil {
		t.Fatalf("expected DeleteSecret on destroyed version to fail, but it succeeded")
	}

	// Assert expected-output assertions
	if !expected.DeleteAndDestroyAreDistinct {
		t.Fatalf("expected DeleteAndDestroyAreDistinct to be true")
	}
	if !expected.RetentionAppliedOnDelete {
		t.Fatalf("expected RetentionAppliedOnDelete to be true")
	}
	if !expected.ExplicitOperatorActionEnforced {
		t.Fatalf("expected ExplicitOperatorActionEnforced to be true")
	}
	_ = delErr
}

// TestC19NegativeCasesF13 validates negative scenarios, provider outage, restart durability,
// and ensures plaintext secrets never enter metadata storage.
func TestC19NegativeCasesF13(t *testing.T) {
	h := newC19Harness(t)
	ctx := context.Background()

	var negFixture c19NegativeFixture
	loadC19Fixture(t, "negative.json", &negFixture)

	// Write baseline secret (v1)
	writeOutcome, err := h.secretSvc.WriteSecret(ctx, secrets.WriteRequest{
		VaultID:         h.pos.Vault.VaultID,
		SecretPath:      h.pos.Secret.SecretPath,
		ExpectedVersion: 0,
		Plaintext:       []byte(h.pos.Secret.Sentinel),
		Classification:  h.pos.Secret.Classification,
		KEKID:           h.pos.Vault.KEKID,
		Identity:        h.operator,
	})
	if err != nil {
		t.Fatalf("initial write failed: %v", err)
	}

	for _, tc := range negFixture.Cases {
		tc := tc
		t.Run(tc.Case, func(t *testing.T) {
			switch tc.Case {
			case "missing-prerequisites-rejected":
				// Empty vault ID
				_, err := h.secretSvc.DeleteSecret(ctx, secrets.DeleteRequest{
					VaultID:    "",
					SecretPath: h.pos.Secret.SecretPath,
					Version:    1,
					Identity:   h.operator,
				})
				if err == nil {
					t.Fatalf("expected error for empty vault ID")
				}

				// Empty secret path
				_, err = h.secretSvc.DeleteSecret(ctx, secrets.DeleteRequest{
					VaultID:    h.pos.Vault.VaultID,
					SecretPath: "",
					Version:    1,
					Identity:   h.operator,
				})
				if err == nil {
					t.Fatalf("expected error for empty secret path")
				}

				// Negative version
				_, err = h.secretSvc.DestroySecretVersion(ctx, secrets.DestroyRequest{
					VaultID:                h.pos.Vault.VaultID,
					SecretPath:             h.pos.Secret.SecretPath,
					Version:                -1,
					ExplicitOperatorAction: true,
					Confirmation:           "DESTROY",
					Identity:               h.operator,
				})
				if err == nil {
					t.Fatalf("expected error for negative version")
				}

			case "malformed-fixture-rejected":
				if tc.MalformedJSON == "" {
					t.Fatalf("missing malformed_json in negative fixture")
				}
				_, decodeErr := contracts.DecodeSecret(ctx, []byte(tc.MalformedJSON))
				if decodeErr == nil {
					t.Fatalf("expected contracts.DecodeSecret to reject malformed fixture, but it succeeded")
				}

			case "destroy-without-explicit-operator-action-blocked":
				_, err := h.secretSvc.DestroySecretVersion(ctx, secrets.DestroyRequest{
					VaultID:                h.pos.Vault.VaultID,
					SecretPath:             h.pos.Secret.SecretPath,
					Version:                writeOutcome.Version,
					ExplicitOperatorAction: false,
					Confirmation:           "",
					Identity:               h.operator,
				})
				if err == nil || !strings.Contains(err.Error(), tc.ExpectedCode) {
					t.Fatalf("expected error code %s, got: %v", tc.ExpectedCode, err)
				}

			case "destroy-by-non-operator-blocked":
				_, err := h.secretSvc.DestroySecretVersion(ctx, secrets.DestroyRequest{
					VaultID:                h.pos.Vault.VaultID,
					SecretPath:             h.pos.Secret.SecretPath,
					Version:                writeOutcome.Version,
					ExplicitOperatorAction: true,
					Confirmation:           "DESTROY",
					Identity:               h.user,
				})
				if err == nil || !strings.Contains(err.Error(), tc.ExpectedCode) {
					t.Fatalf("expected error code %s, got: %v", tc.ExpectedCode, err)
				}

			case "undelete-destroyed-version-blocked":
				// Create and destroy a dedicated secret to test undelete blocking
				dedicatedPath := "production/services/payment/destroy-target"
				wRes, err := h.secretSvc.WriteSecret(ctx, secrets.WriteRequest{
					VaultID:         h.pos.Vault.VaultID,
					SecretPath:      dedicatedPath,
					ExpectedVersion: 0,
					Plaintext:       []byte("temp-data"),
					Classification:  h.pos.Secret.Classification,
					KEKID:           h.pos.Vault.KEKID,
					Identity:        h.operator,
				})
				if err != nil {
					t.Fatalf("write dedicated secret failed: %v", err)
				}
				_, err = h.secretSvc.DestroySecretVersion(ctx, secrets.DestroyRequest{
					VaultID:                h.pos.Vault.VaultID,
					SecretPath:             dedicatedPath,
					Version:                wRes.Version,
					ExplicitOperatorAction: true,
					Confirmation:           "DESTROY",
					Identity:               h.operator,
				})
				if err != nil {
					t.Fatalf("destroy dedicated secret failed: %v", err)
				}
				// Undelete MUST fail
				_, err = h.secretSvc.UndeleteSecret(ctx, secrets.UndeleteRequest{
					VaultID:    h.pos.Vault.VaultID,
					SecretPath: dedicatedPath,
					Version:    wRes.Version,
					Identity:   h.operator,
				})
				if err == nil || !strings.Contains(err.Error(), tc.ExpectedCode) {
					t.Fatalf("expected error code %s, got: %v", tc.ExpectedCode, err)
				}

			case "provider-unavailable-fails-closed":
				// Seal the provider
				h.state.mu.Lock()
				h.state.sealed503 = true
				h.state.mu.Unlock()

				_, err := h.secretSvc.DeleteSecret(ctx, secrets.DeleteRequest{
					VaultID:    h.pos.Vault.VaultID,
					SecretPath: h.pos.Secret.SecretPath,
					Version:    writeOutcome.Version,
					Identity:   h.operator,
				})
				if err == nil {
					t.Fatalf("expected provider outage to fail delete")
				}

				_, err = h.secretSvc.DestroySecretVersion(ctx, secrets.DestroyRequest{
					VaultID:                h.pos.Vault.VaultID,
					SecretPath:             h.pos.Secret.SecretPath,
					Version:                writeOutcome.Version,
					ExplicitOperatorAction: true,
					Confirmation:           "DESTROY",
					Identity:               h.operator,
				})
				if err == nil {
					t.Fatalf("expected provider outage to fail destroy")
				}

				// Unseal provider
				h.state.mu.Lock()
				h.state.sealed503 = false
				h.state.mu.Unlock()

			case "restart-durability-and-irreversibility-verified":
				// Setup a soft-deleted secret and a destroyed secret
				pathDeleted := "production/services/payment/restart-deleted"
				pathDestroyed := "production/services/payment/restart-destroyed"

				w1, err := h.secretSvc.WriteSecret(ctx, secrets.WriteRequest{
					VaultID:         h.pos.Vault.VaultID,
					SecretPath:      pathDeleted,
					ExpectedVersion: 0,
					Plaintext:       []byte("data-1"),
					Classification:  h.pos.Secret.Classification,
					KEKID:           h.pos.Vault.KEKID,
					Identity:        h.operator,
				})
				if err != nil {
					t.Fatalf("write w1 failed: %v", err)
				}

				w2, err := h.secretSvc.WriteSecret(ctx, secrets.WriteRequest{
					VaultID:         h.pos.Vault.VaultID,
					SecretPath:      pathDestroyed,
					ExpectedVersion: 0,
					Plaintext:       []byte("data-2"),
					Classification:  h.pos.Secret.Classification,
					KEKID:           h.pos.Vault.KEKID,
					Identity:        h.operator,
				})
				if err != nil {
					t.Fatalf("write w2 failed: %v", err)
				}

				// Soft delete pathDeleted
				delRes, err := h.secretSvc.DeleteSecret(ctx, secrets.DeleteRequest{
					VaultID:           h.pos.Vault.VaultID,
					SecretPath:        pathDeleted,
					Version:           w1.Version,
					RetentionDuration: 24 * time.Hour,
					Identity:          h.operator,
				})
				if err != nil {
					t.Fatalf("delete w1 failed: %v", err)
				}

				// Destroy pathDestroyed
				dstRes, err := h.secretSvc.DestroySecretVersion(ctx, secrets.DestroyRequest{
					VaultID:                h.pos.Vault.VaultID,
					SecretPath:             pathDestroyed,
					Version:                w2.Version,
					ExplicitOperatorAction: true,
					Confirmation:           "DESTROY",
					Identity:               h.operator,
				})
				if err != nil {
					t.Fatalf("destroy w2 failed: %v", err)
				}

				// Restart storage: close and reopen
				if err := h.store.Close(); err != nil {
					t.Fatalf("close storage failed: %v", err)
				}
				reopenedStore, _, err := storage.Open(h.dir)
				if err != nil {
					t.Fatalf("reopen storage failed: %v", err)
				}
				t.Cleanup(func() { _ = reopenedStore.Close() })
				h.store = reopenedStore
				h.secretSvc = secrets.NewService(h.mapper, h.adapter, reopenedStore)

				// Verify soft-deleted secret state persisted across restart
				lcDel, err := h.secretSvc.GetVersionLifecycle(ctx, h.pos.Vault.VaultID, pathDeleted, w1.Version, h.operator)
				if err != nil {
					t.Fatalf("GetVersionLifecycle after restart failed: %v", err)
				}
				if lcDel.Status != secrets.VersionStatusDeleted || lcDel.RetainUntil != delRes.RetainUntil {
					t.Fatalf("expected preserved deleted status and retain_until; got status=%s retain_until=%s", lcDel.Status, lcDel.RetainUntil)
				}

				// Restore soft-deleted secret after restart
				undelRes, err := h.secretSvc.UndeleteSecret(ctx, secrets.UndeleteRequest{
					VaultID:    h.pos.Vault.VaultID,
					SecretPath: pathDeleted,
					Version:    w1.Version,
					Identity:   h.operator,
				})
				if err != nil {
					t.Fatalf("UndeleteSecret after restart failed: %v", err)
				}
				if undelRes.Status != secrets.VersionStatusActive {
					t.Fatalf("expected restored ACTIVE status after restart, got %s", undelRes.Status)
				}

				// Verify destroyed secret remains destroyed across restart
				lcDst, err := h.secretSvc.GetVersionLifecycle(ctx, h.pos.Vault.VaultID, pathDestroyed, w2.Version, h.operator)
				if err != nil {
					t.Fatalf("GetVersionLifecycle destroyed after restart failed: %v", err)
				}
				if lcDst.Status != secrets.VersionStatusDestroyed || lcDst.DestroyedAt != dstRes.DestroyedAt {
					t.Fatalf("expected preserved destroyed status; got status=%s destroyed_at=%s", lcDst.Status, lcDst.DestroyedAt)
				}

				// Attempting to undelete destroyed secret after restart MUST fail closed
				_, err = h.secretSvc.UndeleteSecret(ctx, secrets.UndeleteRequest{
					VaultID:    h.pos.Vault.VaultID,
					SecretPath: pathDestroyed,
					Version:    w2.Version,
					Identity:   h.operator,
				})
				if err == nil || !strings.Contains(err.Error(), tc.ExpectedCode) {
					t.Fatalf("expected error %s for undeleting destroyed version after restart, got: %v", tc.ExpectedCode, err)
				}

			case "provider-owns-secret-bytes":
				// Scan all files under h.dir for sentinel string
				sentinelBytes := []byte(tc.Sentinel)
				var matchCount int
				err := filepath.Walk(h.dir, func(p string, info os.FileInfo, walkErr error) error {
					if walkErr != nil || info.IsDir() {
						return walkErr
					}
					content, readErr := os.ReadFile(p)
					if readErr != nil {
						return readErr
					}
					if bytes.Contains(content, sentinelBytes) {
						matchCount++
					}
					return nil
				})
				if err != nil {
					t.Fatalf("failed walking storage directory: %v", err)
				}
				if matchCount != tc.ExpectedStorageOccurrenceCount {
					t.Fatalf("security violation: plaintext sentinel %q found in %d storage files (expected %d)", tc.Sentinel, matchCount, tc.ExpectedStorageOccurrenceCount)
				}
			}
		})
	}
}
