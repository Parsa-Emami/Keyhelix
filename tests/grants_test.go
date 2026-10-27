package storage_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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

type c17PositiveFixture struct {
	SchemaVersion     int                `json:"schema_version"`
	Provenance        string             `json:"provenance"`
	License           string             `json:"license"`
	Vault             c14FixtureVault    `json:"vault"`
	AdminIdentity     c14FixtureIdentity `json:"admin_identity"`
	MemberIdentity    c14FixtureIdentity `json:"member_identity"`
	SecretPath        string             `json:"secret_path"`
	Classification    string             `json:"classification"`
	SentinelSecret    string             `json:"sentinel_secret"`
	MemberPermissions []string           `json:"member_permissions"`
	ExpectedEvents    []string           `json:"expected_events"`
	MetadataFile      string             `json:"metadata_file"`
}

type c17NegativeCase struct {
	Case                           string `json:"case"`
	Description                    string `json:"description"`
	ExpectedCode                   string `json:"expected_code,omitempty"`
	ForgedHeader                   string `json:"forged_header,omitempty"`
	Sentinel                       string `json:"sentinel,omitempty"`
	ExpectedStorageOccurrenceCount int    `json:"expected_storage_occurrence_count,omitempty"`
}

type c17NegativeFixture struct {
	SchemaVersion int               `json:"schema_version"`
	Cases         []c17NegativeCase `json:"cases"`
}

type c17ExpectedOutput struct {
	SchemaVersion                       int               `json:"schema_version"`
	Requirement                         string            `json:"requirement"`
	Acceptance                          string            `json:"acceptance"`
	Status                              string            `json:"status"`
	MetadataSHA256                      string            `json:"metadata_sha256"`
	StepUpEnforcedOnMemberChanges       bool              `json:"step_up_enforced_on_member_changes"`
	ImmediatePrivilegeReductionVerified bool              `json:"immediate_privilege_reduction_verified"`
	GuardCodes                          map[string]string `json:"guard_codes"`
	ProviderOwnsSecretBytes             bool              `json:"provider_owns_secret_bytes"`
}

func loadC17Fixture(t *testing.T, filename string, target any) []byte {
	t.Helper()
	path := filepath.Join("fixtures", "keyhelix", "C17", filename)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read C17 fixture %s: %v", filename, err)
	}
	if err := json.Unmarshal(data, target); err != nil {
		t.Fatalf("unmarshal C17 fixture %s: %v", filename, err)
	}
	return data
}

type c17Harness struct {
	dir           string
	store         *storage.Store
	server        *httptest.Server
	state         *c14ProviderState
	adapter       *provider.Adapter
	mapper        *auth.ScopeMapper
	service       *secrets.Service
	grantsSvc     *grants.Service
	stepUp        *auth.StepUpManager
	recorder      *audit.Recorder
	adminIdent    *auth.Identity
	memberIdent   *auth.Identity
	adminSession  *auth.Session
	memberSession *auth.Session
	pos           c17PositiveFixture
}

func newC17Harness(t *testing.T) *c17Harness {
	t.Helper()
	var pos c17PositiveFixture
	loadC17Fixture(t, "positive.json", &pos)

	server, state := newC14Provider(t)
	adapter := newC14Adapter(t, server.URL, nil)

	dir := filepath.Join(t.TempDir(), "c17-grants-store")
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

	redactor := security.NewRedactor()
	redactor.RegisterSentinel(pos.SentinelSecret)
	recorder := audit.NewRecorder(100, redactor)
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

	return &c17Harness{
		dir:           dir,
		store:         store,
		server:        server,
		state:         state,
		adapter:       adapter,
		mapper:        mapper,
		service:       svc,
		grantsSvc:     grantsSvc,
		stepUp:        stepUpMgr,
		recorder:      recorder,
		adminIdent:    adminIdent,
		memberIdent:   memberIdent,
		adminSession:  adminSess,
		memberSession: memberSess,
		pos:           pos,
	}
}

// TestC17MemberChangesRequireStepUpAndImmediatePrivilegeReductionF11 proves Requirement F11:
// Member changes require step-up; privilege reduction takes effect on next sensitive request.
func TestC17MemberChangesRequireStepUpAndImmediatePrivilegeReductionF11(t *testing.T) {
	var pos c17PositiveFixture
	loadC17Fixture(t, "positive.json", &pos)
	var exp c17ExpectedOutput
	loadC17Fixture(t, "expected-output.json", &exp)
	var metadataFixture contracts.SecretMetadata
	metadataBytes := loadC17Fixture(t, pos.MetadataFile, &metadataFixture)

	if exp.Requirement != "F11" || exp.Status != "passed" {
		t.Fatalf("unexpected C17 expected-output fixture: %+v", exp)
	}
	if _, failure := contracts.DecodeSecret(context.Background(), metadataBytes); failure != nil {
		t.Fatalf("C17 metadata fixture must satisfy frozen v1 contract: %+v", failure)
	}

	harness := newC17Harness(t)
	ctx := context.Background()

	// 1. Initial write of the target secret by admin
	_, err := harness.service.WriteSecret(ctx, secrets.WriteRequest{
		VaultID:         pos.Vault.VaultID,
		SecretPath:      pos.SecretPath,
		ExpectedVersion: 0,
		Plaintext:       []byte(pos.SentinelSecret),
		Classification:  pos.Classification,
		KEKID:           pos.Vault.KEKID,
		OperationID:     "op-c17-write-001",
		Owner:           pos.AdminIdentity.Email,
		Identity:        harness.adminIdent,
	})
	if err != nil {
		t.Fatalf("failed to write initial secret: %v", err)
	}

	// 2. Invariant 1: Member changes REQUIRE step-up authentication (ActionPolicyChange)
	// Attempt to create member grant WITHOUT step-up must fail closed
	_, err = harness.grantsSvc.CreateGrant(ctx, grants.CreateGrantRequest{
		VaultID:       pos.Vault.VaultID,
		PrincipalID:   pos.MemberIdentity.Email,
		Permissions:   pos.MemberPermissions,
		OperatorIdent: harness.adminIdent,
		Session:       harness.adminSession,
		StepUpManager: harness.stepUp,
		StepUpToken:   "", // empty token
	})
	if err == nil {
		t.Fatalf("member change without step-up must fail closed, got nil")
	}

	// Now issue a legitimate fresh step-up grant for policy change
	_, stepUpPolicyToken, err := harness.stepUp.IssueGrant(
		ctx,
		harness.adminSession,
		auth.ActionPolicyChange,
		"vault/"+pos.Vault.VaultID+"/grants",
	)
	if err != nil {
		t.Fatalf("failed to issue policy step-up grant: %v", err)
	}

	// Grant creation with valid step-up succeeds
	createdGrant, err := harness.grantsSvc.CreateGrant(ctx, grants.CreateGrantRequest{
		VaultID:       pos.Vault.VaultID,
		PrincipalID:   pos.MemberIdentity.Email,
		Permissions:   pos.MemberPermissions,
		OperatorIdent: harness.adminIdent,
		Session:       harness.adminSession,
		StepUpManager: harness.stepUp,
		StepUpToken:   stepUpPolicyToken.Plaintext(),
	})
	if err != nil {
		t.Fatalf("create grant with step-up failed: %v", err)
	}

	// 3. Member reveals secret using their granted permission and a fresh reveal step-up
	_, memberStepUpToken, err := harness.stepUp.IssueGrant(
		ctx,
		harness.memberSession,
		auth.ActionRevealSecret,
		pos.SecretPath,
	)
	if err != nil {
		t.Fatalf("failed to issue member reveal step-up grant: %v", err)
	}

	revealed, err := harness.service.RevealSecret(ctx, secrets.RevealRequest{
		VaultID:       pos.Vault.VaultID,
		SecretPath:    pos.SecretPath,
		Owner:         pos.AdminIdentity.Email,
		Identity:      harness.memberIdent,
		Session:       harness.memberSession,
		StepUpManager: harness.stepUp,
		StepUpToken:   memberStepUpToken.Plaintext(),
	})
	if err != nil {
		t.Fatalf("authorized member reveal failed: %v", err)
	}
	if string(revealed.Plaintext().Plaintext()) != pos.SentinelSecret {
		t.Fatalf("revealed plaintext mismatch")
	}

	// 4. Invariant 2: Privilege reduction takes effect on NEXT sensitive request
	// Admin revokes member's grant (requires fresh step-up)
	_, revokePolicyToken, err := harness.stepUp.IssueGrant(
		ctx,
		harness.adminSession,
		auth.ActionPolicyChange,
		"vault/grants/"+createdGrant.ID,
	)
	if err != nil {
		t.Fatalf("failed to issue revoke policy step-up: %v", err)
	}

	err = harness.grantsSvc.RevokeGrant(ctx, grants.RevokeGrantRequest{
		GrantID:       createdGrant.ID,
		OperatorIdent: harness.adminIdent,
		Session:       harness.adminSession,
		MemberSession: harness.memberSession,
		StepUpManager: harness.stepUp,
		StepUpToken:   revokePolicyToken.Plaintext(),
	})
	if err != nil {
		t.Fatalf("revoke grant failed: %v", err)
	}

	// Now member attempts a sensitive reveal request on the NEXT call:
	// A) Reusing previous step-up token MUST fail closed (token was invalidated by RevokeGrant)
	_, err = harness.service.RevealSecret(ctx, secrets.RevealRequest{
		VaultID:       pos.Vault.VaultID,
		SecretPath:    pos.SecretPath,
		Owner:         pos.AdminIdentity.Email,
		Identity:      harness.memberIdent,
		Session:       harness.memberSession,
		StepUpManager: harness.stepUp,
		StepUpToken:   memberStepUpToken.Plaintext(),
	})
	if err == nil {
		t.Fatalf("CRITICAL SECURITY VIOLATION: revoked member could still reveal secret with previous step-up!")
	}

	// B) Checking authorization in grants service confirms member access is immediately denied
	if harness.grantsSvc.AuthorizeMemberAccess(pos.MemberIdentity.Email, pos.Vault.VaultID, "secret:read", pos.SecretPath) {
		t.Fatalf("CRITICAL: AuthorizeMemberAccess reported true after revocation!")
	}

	// 5. Invariant: CloudEvents emitted for grant operations
	events := harness.recorder.Events()
	var foundCreated, foundRevoked bool
	for _, e := range events {
		if e.Type == audit.EventGrantCreated {
			foundCreated = true
		}
		if e.Type == audit.EventGrantRevoked {
			foundRevoked = true
		}
	}
	if !foundCreated || !foundRevoked {
		t.Fatalf("expected audit events for grant creation and revocation, got events: %+v", events)
	}
}

// TestC17NegativeCasesF11 validates all required negative cases:
// 1. Missing/expired identity.
// 2. Unrelated owner / object scope fails before sensitive actions.
// 3. Forged header, widened path cannot authorize sensitive action.
// 4. Provider owns secret bytes.
func TestC17NegativeCasesF11(t *testing.T) {
	var negFixture c17NegativeFixture
	loadC17Fixture(t, "negative.json", &negFixture)

	harness := newC17Harness(t)
	ctx := context.Background()

	for _, tc := range negFixture.Cases {
		t.Run(tc.Case, func(t *testing.T) {
			switch tc.Case {
			case "member-change-without-step-up-rejected":
				_, err := harness.grantsSvc.CreateGrant(ctx, grants.CreateGrantRequest{
					VaultID:       "vault-prod",
					PrincipalID:   "bob@keyhelix.local",
					Permissions:   []string{"secret:read"},
					OperatorIdent: harness.adminIdent,
					Session:       harness.adminSession,
					StepUpManager: harness.stepUp,
					StepUpToken:   "invalid-step-up-token",
				})
				if err == nil {
					t.Fatalf("expected failure for grant change without valid step-up")
				}

			case "missing-expired-identity-rejected":
				expiredIdent := &auth.Identity{
					Subject:   "expired-user",
					Email:     "expired@keyhelix.local",
					ExpiresAt: time.Now().Add(-time.Hour).Unix(), // expired
				}
				sessMgr, _ := auth.NewSessionManager(auth.DefaultSessionConfig(), nil)
				sess, _, _ := sessMgr.CreateSession(ctx, expiredIdent, auth.ClientInfo{})

				_, err := harness.service.RevealSecret(ctx, secrets.RevealRequest{
					VaultID:       "vault-prod",
					SecretPath:    "production/services/payment/api-key",
					Owner:         "alice@keyhelix.local",
					Identity:      expiredIdent,
					Session:       sess,
					StepUpManager: harness.stepUp,
					StepUpToken:   "tok",
				})
				if err == nil {
					t.Fatalf("expected failure for expired identity")
				}

			case "unrelated-owner-scope-rejected":
				unrelatedIdent := &auth.Identity{
					Subject:       "unrelated-user",
					Email:         "unrelated@keyhelix.local",
					AllowedOwners: []string{"unrelated@keyhelix.local"},
					AllowedScopes: []string{"unrelated/*"},
					ExpiresAt:     time.Now().Add(time.Hour).Unix(),
				}
				sessMgr, _ := auth.NewSessionManager(auth.DefaultSessionConfig(), nil)
				sess, _, _ := sessMgr.CreateSession(ctx, unrelatedIdent, auth.ClientInfo{})

				_, err := harness.service.RevealSecret(ctx, secrets.RevealRequest{
					VaultID:       "vault-prod",
					SecretPath:    "production/services/payment/api-key",
					Owner:         "alice@keyhelix.local", // targeting alice
					Identity:      unrelatedIdent,
					Session:       sess,
					StepUpManager: harness.stepUp,
					StepUpToken:   "tok",
				})
				if err == nil {
					t.Fatalf("expected failure for unrelated owner scope")
				}

			case "forged-header-cannot-authorize":
				forgedHeader := http.Header{}
				forgedHeader.Set("X-Forwarded-User", "alice@keyhelix.local")
				forgedHeader.Set("X-Vault-Role", "vault-admin")

				attackerIdent := &auth.Identity{
					Subject:       "attacker-user",
					Email:         "attacker@keyhelix.local",
					AllowedOwners: []string{"attacker@keyhelix.local"},
					AllowedScopes: []string{"attacker/*"},
					ExpiresAt:     time.Now().Add(time.Hour).Unix(),
				}
				sessMgr, _ := auth.NewSessionManager(auth.DefaultSessionConfig(), nil)
				sess, _, _ := sessMgr.CreateSession(ctx, attackerIdent, auth.ClientInfo{})

				_, err := harness.service.RevealSecret(ctx, secrets.RevealRequest{
					VaultID:       "vault-prod",
					SecretPath:    "production/services/payment/api-key",
					Owner:         "alice@keyhelix.local",
					Identity:      attackerIdent,
					Session:       sess,
					StepUpManager: harness.stepUp,
					StepUpToken:   "tok",
					Headers:       forgedHeader,
				})
				if err == nil {
					t.Fatalf("expected failure when attacker attempts forged headers")
				}

			case "privilege-reduction-immediate-on-next-request":
				// Confirm revoked grant check fails closed
				g := &grants.Grant{
					ID:          "revoked-g",
					VaultID:     "vault-prod",
					PrincipalID: "bob@keyhelix.local",
					Permissions: []string{"secret:read"},
					CreatedAt:   time.Now().Add(-time.Hour),
					ExpiresAt:   time.Now().Add(time.Hour),
				}
				now := time.Now()
				g.RevokedAt = &now
				if g.IsActive(now) {
					t.Fatalf("revoked grant must not be active")
				}

			case "provider-owns-secret-bytes":
				// AssertClean confirms no secret leaks in grants storage files
				inspected, err := security.AssertDirectoryClean(harness.dir, tc.Sentinel)
				if err != nil {
					t.Fatalf("secret leaked into grants storage directory: %v", err)
				}
				if inspected == 0 {
					t.Fatalf("no storage files inspected in %s", harness.dir)
				}
			}
		})
	}
}
