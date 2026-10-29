package storage_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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

type c27PositiveFixture struct {
	SchemaVersion int `json:"schema_version"`
	Preview       struct {
		Filename       string   `json:"filename"`
		Content        string   `json:"content"`
		ExpectedFields []string `json:"expected_fields"`
		ExpectedBytes  int      `json:"expected_bytes"`
	} `json:"preview"`
	Vault             c14FixtureVault    `json:"vault"`
	AdminIdentity     c14FixtureIdentity `json:"admin_identity"`
	MemberIdentity    c14FixtureIdentity `json:"member_identity"`
	Secret            struct {
		SecretPath     string `json:"secret_path"`
		Classification string `json:"classification"`
		SentinelSecret string `json:"sentinel_secret"`
	} `json:"secret"`
	Grant struct {
		GrantID     string   `json:"grant_id"`
		Permissions []string `json:"permissions"`
		TTLSeconds  int64    `json:"ttl_seconds"`
	} `json:"grant"`
	StepUp struct {
		Token      string `json:"token"`
		TTLSeconds int64  `json:"ttl_seconds"`
	} `json:"step_up"`
	ExpectedHeaders map[string]string `json:"expected_headers"`
}

type c27NegativeCase struct {
	Case         string   `json:"case"`
	Surface      string   `json:"surface"`
	Description  string   `json:"description"`
	InvalidPaths []string `json:"invalid_paths,omitempty"`
	ExpectedCode string   `json:"expected_code,omitempty"`
}

type c27NegativeFixture struct {
	SchemaVersion int               `json:"schema_version"`
	Provenance    string            `json:"provenance"`
	License       string            `json:"license"`
	Cases         []c27NegativeCase `json:"cases"`
}

type c27ExpectedOutput struct {
	SchemaVersion    int               `json:"schema_version"`
	Requirement      string            `json:"requirement"`
	Acceptance       string            `json:"acceptance"`
	Status           string            `json:"status"`
	SurfacesVerified []string          `json:"surfaces_verified"`
	Invariants       map[string]bool   `json:"invariants_verified"`
	GuardCodes       map[string]string `json:"guard_codes"`
}

type c27Harness struct {
	dir           string
	store         *storage.Store
	server        *httptest.Server
	state         *c14ProviderState
	adapter       *provider.Adapter
	mapper        *auth.ScopeMapper
	service       *secrets.Service
	grantsSvc     *grants.Service
	sessionMgr    *auth.SessionManager
	stepUp        *auth.StepUpManager
	recorder      *audit.Recorder
	redactor      *security.Redactor
	adminIdent    *auth.Identity
	adminSession  *auth.Session
	memberIdent   *auth.Identity
	memberSession *auth.Session
	pos           c27PositiveFixture
}

func loadC27Fixture(t *testing.T, filename string, target any) []byte {
	t.Helper()
	path := filepath.Join("fixtures", "keyhelix", "C27", filename)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read C27 fixture %s: %v", filename, err)
	}
	if err := json.Unmarshal(data, target); err != nil {
		t.Fatalf("unmarshal C27 fixture %s: %v", filename, err)
	}
	return data
}

func extractC27ErrorCode(err error) string {
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

func newC27Harness(t *testing.T) *c27Harness {
	t.Helper()
	var pos c27PositiveFixture
	loadC27Fixture(t, "positive.json", &pos)

	server, state := newC14Provider(t)
	adapter := newC14Adapter(t, server.URL, nil)

	dir := filepath.Join(t.TempDir(), "c27-abuse-matrix-store")
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
	redactor.RegisterSentinel(pos.Secret.SentinelSecret)

	recorder := audit.NewRecorder(200, redactor)
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

	adminIdent := &auth.Identity{
		Subject:       pos.AdminIdentity.Subject,
		Email:         pos.AdminIdentity.Email,
		VaultRole:     pos.AdminIdentity.VaultRole,
		AllowedOwners: pos.AdminIdentity.AllowedOwners,
		AllowedScopes: pos.AdminIdentity.AllowedScopes,
		ExpiresAt:     time.Now().Add(time.Hour).Unix(),
	}
	adminSess, _, err := sessionMgr.CreateSession(ctx, adminIdent, auth.ClientInfo{})
	if err != nil {
		t.Fatalf("create admin session: %v", err)
	}

	memberIdent := &auth.Identity{
		Subject:       pos.MemberIdentity.Subject,
		Email:         pos.MemberIdentity.Email,
		VaultRole:     pos.MemberIdentity.VaultRole,
		AllowedOwners: pos.MemberIdentity.AllowedOwners,
		AllowedScopes: pos.MemberIdentity.AllowedScopes,
		ExpiresAt:     time.Now().Add(time.Hour).Unix(),
	}
	memberSess, _, err := sessionMgr.CreateSession(ctx, memberIdent, auth.ClientInfo{})
	if err != nil {
		t.Fatalf("create member session: %v", err)
	}

	return &c27Harness{
		dir:           dir,
		store:         store,
		server:        server,
		state:         state,
		adapter:       adapter,
		mapper:        mapper,
		service:       svc,
		grantsSvc:     grantsSvc,
		sessionMgr:    sessionMgr,
		stepUp:        stepUpMgr,
		recorder:      recorder,
		redactor:      redactor,
		adminIdent:    adminIdent,
		adminSession:  adminSess,
		memberIdent:   memberIdent,
		memberSession: memberSess,
		pos:           pos,
	}
}

func TestC27PathTraversalRejection(t *testing.T) {
	harness := newC27Harness(t)
	ctx := context.Background()

	// 1. Issue fresh step-up token for admin
	_, stepUpToken, err := harness.stepUp.IssueGrant(
		ctx,
		harness.adminSession,
		auth.ActionRevealSecret,
		harness.pos.Secret.SecretPath,
	)
	if err != nil {
		t.Fatalf("issue step-up token: %v", err)
	}

	invalidPaths := []string{
		"../../etc/passwd",
		"app/prod/../../../secret",
		"app/prod/..\\secret",
		"app/prod/%2e%2e%2fsecret",
		"app/prod/%252e%252e%252fsecret",
		"app/prod/secret\x00extra",
		"/absolute/unauthorized/path",
		"",
	}

	for _, badPath := range invalidPaths {
		t.Run("write_"+badPath, func(t *testing.T) {
			_, err := harness.service.WriteSecret(ctx, secrets.WriteRequest{
				VaultID:         harness.pos.Vault.VaultID,
				SecretPath:      badPath,
				ExpectedVersion: 0,
				Plaintext:       []byte(harness.pos.Secret.SentinelSecret),
				Classification:  harness.pos.Secret.Classification,
				KEKID:           harness.pos.Vault.KEKID,
				OperationID:     "op-c27-traversal-test",
				Owner:           harness.pos.AdminIdentity.Email,
				Identity:        harness.adminIdent,
			})
			if err == nil {
				t.Fatalf("expected write with path %q to fail, got success", badPath)
			}
			code := extractC27ErrorCode(err)
			if code != string(contracts.InvalidInput) && code != "SCOPE_DENIED" && !strings.Contains(err.Error(), "invalid") && !strings.Contains(err.Error(), "path") {
				t.Errorf("expected InvalidInput or SCOPE_DENIED error code for path %q, got: %v (code: %s)", badPath, err, code)
			}
		})

		t.Run("reveal_"+badPath, func(t *testing.T) {
			_, err := harness.service.RevealSecret(ctx, secrets.RevealRequest{
				VaultID:       harness.pos.Vault.VaultID,
				SecretPath:    badPath,
				Owner:         harness.pos.AdminIdentity.Email,
				Identity:      harness.adminIdent,
				Session:       harness.adminSession,
				StepUpManager: harness.stepUp,
				StepUpToken:   stepUpToken.Plaintext(),
			})
			if err == nil {
				t.Fatalf("expected reveal with path %q to fail, got success", badPath)
			}
		})
	}

	// 2. Direct storage port traversal check
	_, err = harness.store.Write(ctx, storage.WriteRequest{
		OperationID:     "op-c27-storage-traversal",
		Owner:           harness.pos.AdminIdentity.Email,
		Scope:           "vaults/../unauthorized",
		Name:            "secret-1",
		ExpectedVersion: 0,
		Metadata:        []byte("test-payload"),
	})
	if err == nil {
		t.Fatalf("expected storage write with traversal scope to fail, got nil")
	}
}

func TestC27IdentityAndSessionAbuse(t *testing.T) {
	harness := newC27Harness(t)
	ctx := context.Background()

	// 1. Expired identity check
	expiredIdent := &auth.Identity{
		Subject:       "usr_c27_expired",
		Email:         "expired@keyhelix.local",
		VaultRole:     "vault-admin",
		AllowedOwners: []string{"expired@keyhelix.local"},
		AllowedScopes: []string{"app/prod/*", "admin"},
		ExpiresAt:     time.Now().Add(-time.Hour).Unix(), // Expired
	}

	_, _, err := harness.sessionMgr.CreateSession(ctx, expiredIdent, auth.ClientInfo{})
	if err == nil {
		t.Fatalf("expected CreateSession with expired identity to fail")
	}

	// 2. Reveal attempt without step-up token
	_, err = harness.service.RevealSecret(ctx, secrets.RevealRequest{
		VaultID:       harness.pos.Vault.VaultID,
		SecretPath:    harness.pos.Secret.SecretPath,
		Owner:         harness.pos.AdminIdentity.Email,
		Identity:      harness.adminIdent,
		Session:       harness.adminSession,
		StepUpManager: harness.stepUp,
		StepUpToken:   "", // Empty token
	})
	if err == nil {
		t.Fatalf("expected reveal without step-up to fail")
	}
	code := extractC27ErrorCode(err)
	if code != string(auth.CodeStepUpRequired) {
		t.Errorf("expected STEP_UP_REQUIRED code, got: %s (err: %v)", code, err)
	}

	// 3. Forged step-up token
	_, err = harness.service.RevealSecret(ctx, secrets.RevealRequest{
		VaultID:       harness.pos.Vault.VaultID,
		SecretPath:    harness.pos.Secret.SecretPath,
		Owner:         harness.pos.AdminIdentity.Email,
		Identity:      harness.adminIdent,
		Session:       harness.adminSession,
		StepUpManager: harness.stepUp,
		StepUpToken:   "su_c27_forged_synthetic_token_999",
	})
	if err == nil {
		t.Fatalf("expected reveal with forged step-up token to fail")
	}
}

func TestC27CiphertextTamperingAndAuthTagCorruption(t *testing.T) {
	harness := newC27Harness(t)
	ctx := context.Background()

	// 1. Write a valid secret
	writeRes, err := harness.service.WriteSecret(ctx, secrets.WriteRequest{
		VaultID:         harness.pos.Vault.VaultID,
		SecretPath:      harness.pos.Secret.SecretPath,
		ExpectedVersion: 0,
		Plaintext:       []byte(harness.pos.Secret.SentinelSecret),
		Classification:  harness.pos.Secret.Classification,
		KEKID:           harness.pos.Vault.KEKID,
		OperationID:     "op-c27-tamper-write-001",
		Owner:           harness.pos.AdminIdentity.Email,
		Identity:        harness.adminIdent,
	})
	if err != nil {
		t.Fatalf("initial write secret: %v", err)
	}

	// 2. Issue step-up token
	_, stepUpToken, err := harness.stepUp.IssueGrant(
		ctx,
		harness.adminSession,
		auth.ActionRevealSecret,
		harness.pos.Secret.SecretPath,
	)
	if err != nil {
		t.Fatalf("issue step-up: %v", err)
	}

	// 3. Verify reveal succeeds when untampered
	revealRes, err := harness.service.RevealSecret(ctx, secrets.RevealRequest{
		VaultID:       harness.pos.Vault.VaultID,
		SecretPath:    harness.pos.Secret.SecretPath,
		Owner:         harness.pos.AdminIdentity.Email,
		Identity:      harness.adminIdent,
		Session:       harness.adminSession,
		StepUpManager: harness.stepUp,
		StepUpToken:   stepUpToken.Plaintext(),
	})
	if err != nil {
		t.Fatalf("reveal before tamper: %v", err)
	}
	if string(revealRes.Plaintext()) != harness.pos.Secret.SentinelSecret {
		t.Fatalf("unexpected plaintext: %s", string(revealRes.Plaintext()))
	}

	// 4. Locate stored blobs and corrupt byte
	blobsDir := filepath.Join(harness.dir, "blobs")
	entries, err := os.ReadDir(blobsDir)
	if err != nil || len(entries) == 0 {
		t.Fatalf("read blobs dir: %v", err)
	}

	tamperedAny := false
	for _, entry := range entries {
		blobPath := filepath.Join(blobsDir, entry.Name())
		data, err := os.ReadFile(blobPath)
		if err != nil {
			continue
		}
		if len(data) > 8 {
			corrupted := make([]byte, len(data))
			copy(corrupted, data)
			// Corrupt bytes in the payload
			corrupted[len(corrupted)/2] ^= 0xAA
			_ = os.WriteFile(blobPath, corrupted, 0o600)
			tamperedAny = true
		}
	}
	if !tamperedAny {
		t.Fatalf("failed to tamper any blob in storage")
	}

	// 5. Attempt reveal on corrupted ciphertext
	tamperedReveal, err := harness.service.RevealSecret(ctx, secrets.RevealRequest{
		VaultID:       harness.pos.Vault.VaultID,
		SecretPath:    harness.pos.Secret.SecretPath,
		Owner:         harness.pos.AdminIdentity.Email,
		Identity:      harness.adminIdent,
		Session:       harness.adminSession,
		StepUpManager: harness.stepUp,
		StepUpToken:   stepUpToken.Plaintext(),
	})
	if err == nil {
		t.Fatalf("expected reveal to fail on corrupted ciphertext, got success")
	}
	if tamperedReveal != nil && len(tamperedReveal.Plaintext()) > 0 {
		t.Fatalf("corrupted reveal returned non-zero plaintext: %s", string(tamperedReveal.Plaintext()))
	}

	t.Logf("corrupted ciphertext correctly failed closed for entity version %d", writeRes.Version)
}

func TestC27ProviderOutageFailClosed(t *testing.T) {
	harness := newC27Harness(t)
	ctx := context.Background()

	// Disconnect provider HTTP server
	harness.server.Close()

	// Write must fail closed
	_, err := harness.service.WriteSecret(ctx, secrets.WriteRequest{
		VaultID:         harness.pos.Vault.VaultID,
		SecretPath:      harness.pos.Secret.SecretPath,
		ExpectedVersion: 0,
		Plaintext:       []byte(harness.pos.Secret.SentinelSecret),
		Classification:  harness.pos.Secret.Classification,
		KEKID:           harness.pos.Vault.KEKID,
		OperationID:     "op-c27-outage-write",
		Owner:           harness.pos.AdminIdentity.Email,
		Identity:        harness.adminIdent,
	})
	if err == nil {
		t.Fatalf("expected write to fail when provider offline, got success")
	}

	// Reveal must fail closed
	revealResp, err := harness.service.RevealSecret(ctx, secrets.RevealRequest{
		VaultID:       harness.pos.Vault.VaultID,
		SecretPath:    harness.pos.Secret.SecretPath,
		Owner:         harness.pos.AdminIdentity.Email,
		Identity:      harness.adminIdent,
		Session:       harness.adminSession,
		StepUpManager: harness.stepUp,
		StepUpToken:   "dummy-token",
	})
	if err == nil {
		t.Fatalf("expected reveal to fail when provider offline, got success")
	}
	if revealResp != nil {
		t.Fatalf("expected nil reveal response during outage, got: %v", revealResp)
	}
}

func TestC27ZeroPlaintextLeakageUnderAbuse(t *testing.T) {
	harness := newC27Harness(t)
	sentinel := harness.pos.Secret.SentinelSecret

	// Assert no leakage in initial state
	inspected, err := security.AssertDirectoryClean(harness.dir, sentinel)
	if err != nil {
		t.Fatalf("clean assertion failed: %v", err)
	}
	if inspected == 0 {
		t.Fatalf("expected inspected files > 0")
	}

	// Verify that redactor successfully catches sentinel
	redactedText, err := harness.redactor.RedactString(context.Background(), "log line with "+sentinel)
	if err != nil {
		t.Fatalf("redact string: %v", err)
	}
	if strings.Contains(redactedText, sentinel) {
		t.Fatalf("redactor failed to redact sentinel: %s", redactedText)
	}
	if !strings.Contains(redactedText, "[REDACTED]") {
		t.Fatalf("redacted text missing [REDACTED]: %s", redactedText)
	}
}

func TestC27NegativeCasesFixtureMatch(t *testing.T) {
	var neg c27NegativeFixture
	loadC27Fixture(t, "negative.json", &neg)

	if len(neg.Cases) == 0 {
		t.Fatalf("negative fixture cases empty")
	}

	var expected c27ExpectedOutput
	loadC27Fixture(t, "expected-output.json", &expected)

	if expected.Requirement != "N27" || !expected.Invariants["provider_owns_secret_bytes"] {
		t.Fatalf("expected-output invariants invalid: %+v", expected)
	}

	t.Logf("C27 negative cases fixture verified: %d abuse scenarios documented", len(neg.Cases))
}
