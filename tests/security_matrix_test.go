package storage_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/parsa-emami/keyhelix/internal/audit"
	"github.com/parsa-emami/keyhelix/internal/auth"
	"github.com/parsa-emami/keyhelix/internal/grants"
	"github.com/parsa-emami/keyhelix/internal/provider"
	"github.com/parsa-emami/keyhelix/internal/secrets"
	"github.com/parsa-emami/keyhelix/internal/security"
	"github.com/parsa-emami/keyhelix/internal/storage"
)

type c26PositiveFixture struct {
	SchemaVersion     int                `json:"schema_version"`
	Provenance        string             `json:"provenance"`
	License           string             `json:"license"`
	Vault             c14FixtureVault    `json:"vault"`
	AdminIdentity     c14FixtureIdentity `json:"admin_identity"`
	MemberIdentity    c14FixtureIdentity `json:"member_identity"`
	UnrelatedIdentity c14FixtureIdentity `json:"unrelated_identity"`
	Secret            struct {
		SecretPath           string `json:"secret_path"`
		Classification       string `json:"classification"`
		SentinelSecret       string `json:"sentinel_secret"`
		MemberSentinelSecret string `json:"member_sentinel_secret"`
	} `json:"secret"`
	Grant struct {
		GrantID     string   `json:"grant_id"`
		Permissions []string `json:"permissions"`
		TTLSeconds  int64    `json:"ttl_seconds"`
	} `json:"grant"`
	StepUp struct {
		TTLSeconds int64 `json:"ttl_seconds"`
	} `json:"step_up"`
	ExpectedHeaders map[string]string `json:"expected_headers"`
}

type c26NegativeCase struct {
	Case                      string `json:"case"`
	Description               string `json:"description"`
	ExpectedCode              string `json:"expected_code"`
	ExpectedCanaryOccurrences int    `json:"expected_canary_occurrences,omitempty"`
}

type c26NegativeFixture struct {
	SchemaVersion int               `json:"schema_version"`
	Provenance    string            `json:"provenance"`
	License       string            `json:"license"`
	Cases         []c26NegativeCase `json:"cases"`
}

type c26ExpectedOutput struct {
	SchemaVersion                 int               `json:"schema_version"`
	Requirement                   string            `json:"requirement"`
	Acceptance                    string            `json:"acceptance"`
	Status                        string            `json:"status"`
	MatrixRowsVerified            []string          `json:"matrix_rows_verified"`
	ZeroPlaintextCanariesDetected bool              `json:"zero_plaintext_canaries_detected"`
	ProviderOwnsSecretBytes       bool              `json:"provider_owns_secret_bytes"`
	PlaintextCanaryOccurrences    int               `json:"plaintext_canary_occurrences"`
	GuardCodes                    map[string]string `json:"guard_codes"`
}

func loadC26Fixture(t *testing.T, filename string, target any) []byte {
	t.Helper()
	path := filepath.Join("fixtures", "keyhelix", "C26", filename)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read C26 fixture %s: %v", filename, err)
	}
	if err := json.Unmarshal(data, target); err != nil {
		t.Fatalf("unmarshal C26 fixture %s: %v", filename, err)
	}
	return data
}

func extractErrorCode(err error) string {
	if err == nil {
		return ""
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
	return "UNKNOWN_ERROR"
}

type c26Harness struct {
	dir            string
	store          *storage.Store
	server         *httptest.Server
	state          *c14ProviderState
	adapter        *provider.Adapter
	mapper         *auth.ScopeMapper
	service        *secrets.Service
	grantsSvc      *grants.Service
	sessionMgr     *auth.SessionManager
	stepUp         *auth.StepUpManager
	recorder       *audit.Recorder
	redactor       *security.Redactor
	adminIdent     *auth.Identity
	memberIdent    *auth.Identity
	unrelatedIdent *auth.Identity
	adminSession   *auth.Session
	memberSession  *auth.Session
	pos            c26PositiveFixture
}

func newC26Harness(t *testing.T) *c26Harness {
	t.Helper()
	var pos c26PositiveFixture
	loadC26Fixture(t, "positive.json", &pos)

	server, state := newC14Provider(t)
	adapter := newC14Adapter(t, server.URL, nil)

	dir := filepath.Join(t.TempDir(), "c26-security-matrix-store")
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
	redactor.RegisterSentinel(pos.Secret.MemberSentinelSecret)

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

	unrelatedIdent := &auth.Identity{
		Subject:       pos.UnrelatedIdentity.Subject,
		Email:         pos.UnrelatedIdentity.Email,
		VaultRole:     pos.UnrelatedIdentity.VaultRole,
		AllowedOwners: pos.UnrelatedIdentity.AllowedOwners,
		AllowedScopes: pos.UnrelatedIdentity.AllowedScopes,
		ExpiresAt:     time.Now().Add(time.Hour).Unix(),
	}

	return &c26Harness{
		dir:            dir,
		store:          store,
		server:         server,
		state:          state,
		adapter:        adapter,
		mapper:         mapper,
		service:        svc,
		grantsSvc:      grantsSvc,
		sessionMgr:     sessionMgr,
		stepUp:         stepUpMgr,
		recorder:       recorder,
		redactor:       redactor,
		adminIdent:     adminIdent,
		memberIdent:    memberIdent,
		unrelatedIdent: unrelatedIdent,
		adminSession:   adminSess,
		memberSession:  memberSess,
		pos:            pos,
	}
}

// TestC26SecurityMatrixF20 verifies Requirement F20:
// "Security matrix passes with synthetic secrets before any personal production credentials enter provider."
func TestC26SecurityMatrixF20(t *testing.T) {
	harness := newC26Harness(t)
	ctx := context.Background()
	pos := harness.pos

	var exp c26ExpectedOutput
	loadC26Fixture(t, "expected-output.json", &exp)

	if exp.Requirement != "F20" || exp.Status != "passed" {
		t.Fatalf("unexpected expected-output fixture: %+v", exp)
	}

	// ==========================================
	// 1. ADMIN ROW: WRITE & REVEAL WITH STEP-UP
	// ==========================================
	// Admin creates a synthetic secret envelope
	writeRes, err := harness.service.WriteSecret(ctx, secrets.WriteRequest{
		VaultID:         pos.Vault.VaultID,
		SecretPath:      pos.Secret.SecretPath,
		ExpectedVersion: 0,
		Plaintext:       []byte(pos.Secret.SentinelSecret),
		Classification:  pos.Secret.Classification,
		KEKID:           pos.Vault.KEKID,
		OperationID:     "op-c26-write-001",
		Owner:           pos.AdminIdentity.Email,
		Identity:        harness.adminIdent,
	})
	if err != nil {
		t.Fatalf("admin write secret failed: %v", err)
	}
	if writeRes.Version != 1 {
		t.Fatalf("expected version 1, got %d", writeRes.Version)
	}

	// Admin reveals with fresh Step-Up
	_, adminStepUpToken, err := harness.stepUp.IssueGrant(
		ctx,
		harness.adminSession,
		auth.ActionRevealSecret,
		pos.Secret.SecretPath,
	)
	if err != nil {
		t.Fatalf("issue admin step-up: %v", err)
	}

	adminReveal, err := harness.service.RevealSecret(ctx, secrets.RevealRequest{
		VaultID:       pos.Vault.VaultID,
		SecretPath:    pos.Secret.SecretPath,
		Owner:         pos.AdminIdentity.Email,
		Identity:      harness.adminIdent,
		Session:       harness.adminSession,
		StepUpManager: harness.stepUp,
		StepUpToken:   adminStepUpToken.Plaintext(),
	})
	if err != nil {
		t.Fatalf("admin reveal with step-up failed: %v", err)
	}
	if string(adminReveal.Plaintext().Plaintext()) != pos.Secret.SentinelSecret {
		t.Fatalf("revealed plaintext mismatch")
	}

	// Verify mandatory no-store response headers
	headers := adminReveal.NoStoreHeaders()
	if headers.Get("Cache-Control") != pos.ExpectedHeaders["Cache-Control"] {
		t.Fatalf("invalid Cache-Control header: %s", headers.Get("Cache-Control"))
	}
	if headers.Get("X-Content-Type-Options") != pos.ExpectedHeaders["X-Content-Type-Options"] {
		t.Fatalf("invalid X-Content-Type-Options header: %s", headers.Get("X-Content-Type-Options"))
	}

	// ==========================================
	// 2. MEMBER ROW: AUTHORIZED ACCESS VIA GRANT
	// ==========================================
	// Admin creates member grant (requires ActionPolicyChange step-up)
	_, policyStepUpToken, err := harness.stepUp.IssueGrant(
		ctx,
		harness.adminSession,
		auth.ActionPolicyChange,
		"vault/"+pos.Vault.VaultID+"/grants",
	)
	if err != nil {
		t.Fatalf("issue policy step-up: %v", err)
	}

	createdGrant, err := harness.grantsSvc.CreateGrant(ctx, grants.CreateGrantRequest{
		VaultID:       pos.Vault.VaultID,
		PrincipalID:   pos.MemberIdentity.Email,
		Permissions:   pos.Grant.Permissions,
		OperatorIdent: harness.adminIdent,
		Session:       harness.adminSession,
		StepUpManager: harness.stepUp,
		StepUpToken:   policyStepUpToken.Plaintext(),
	})
	if err != nil {
		t.Fatalf("create grant with step-up failed: %v", err)
	}
	if !createdGrant.IsActive(time.Now()) {
		t.Fatalf("newly created grant must be active")
	}

	// Verify grants service acknowledges active authorization
	if !harness.grantsSvc.AuthorizeMemberAccess(pos.MemberIdentity.Email, pos.Vault.VaultID, "secret:read", pos.Secret.SecretPath) {
		t.Fatalf("grantsSvc must authorize member before revocation")
	}

	// Member reveals with active grant and fresh ActionRevealSecret step-up
	_, memberStepUpToken, err := harness.stepUp.IssueGrant(
		ctx,
		harness.memberSession,
		auth.ActionRevealSecret,
		pos.Secret.SecretPath,
	)
	if err != nil {
		t.Fatalf("issue member step-up: %v", err)
	}

	memberReveal, err := harness.service.RevealSecret(ctx, secrets.RevealRequest{
		VaultID:       pos.Vault.VaultID,
		SecretPath:    pos.Secret.SecretPath,
		Owner:         pos.AdminIdentity.Email,
		Identity:      harness.memberIdent,
		Session:       harness.memberSession,
		StepUpManager: harness.stepUp,
		StepUpToken:   memberStepUpToken.Plaintext(),
	})
	if err != nil {
		t.Fatalf("member authorized reveal failed: %v", err)
	}
	if string(memberReveal.Plaintext().Plaintext()) != pos.Secret.SentinelSecret {
		t.Fatalf("member plaintext mismatch")
	}

	// ==========================================
	// 3. IMMEDIATE PRIVILEGE REVOCATION ROW
	// ==========================================
	// Admin revokes member grant (requires ActionPolicyChange step-up)
	_, revokeStepUpToken, err := harness.stepUp.IssueGrant(
		ctx,
		harness.adminSession,
		auth.ActionPolicyChange,
		"vault/grants/"+createdGrant.ID,
	)
	if err != nil {
		t.Fatalf("issue revoke step-up: %v", err)
	}

	err = harness.grantsSvc.RevokeGrant(ctx, grants.RevokeGrantRequest{
		GrantID:       createdGrant.ID,
		OperatorIdent: harness.adminIdent,
		Session:       harness.adminSession,
		MemberSession: harness.memberSession,
		StepUpManager: harness.stepUp,
		StepUpToken:   revokeStepUpToken.Plaintext(),
	})
	if err != nil {
		t.Fatalf("revoke grant failed: %v", err)
	}

	// Sub-test 3A: Member attempting immediate reveal on NEXT request MUST fail closed
	_, err = harness.service.RevealSecret(ctx, secrets.RevealRequest{
		VaultID:       pos.Vault.VaultID,
		SecretPath:    pos.Secret.SecretPath,
		Owner:         pos.AdminIdentity.Email,
		Identity:      harness.memberIdent,
		Session:       harness.memberSession,
		StepUpManager: harness.stepUp,
		StepUpToken:   memberStepUpToken.Plaintext(),
	})
	if err == nil {
		t.Fatalf("CRITICAL SECURITY VIOLATION: revoked member could reveal secret with prior step-up!")
	}

	// Sub-test 3B: grants service confirms member authorization is immediately false
	if harness.grantsSvc.AuthorizeMemberAccess(pos.MemberIdentity.Email, pos.Vault.VaultID, "secret:read", pos.Secret.SecretPath) {
		t.Fatalf("grantsSvc.AuthorizeMemberAccess must return false after revocation")
	}

	// ==========================================
	// 4. MANDATORY STEP-UP REQUIREMENT ROW
	// ==========================================
	// Attempt reveal without step-up token -> must fail closed
	_, err = harness.service.RevealSecret(ctx, secrets.RevealRequest{
		VaultID:       pos.Vault.VaultID,
		SecretPath:    pos.Secret.SecretPath,
		Owner:         pos.AdminIdentity.Email,
		Identity:      harness.adminIdent,
		Session:       harness.adminSession,
		StepUpManager: harness.stepUp,
		StepUpToken:   "", // empty token
	})
	if err == nil {
		t.Fatalf("reveal without step-up must fail closed")
	}

	// ==========================================
	// 5. CROSS-TENANT / UNRELATED ACTOR ROW
	// ==========================================
	// Unrelated actor mallory attempts to reveal admin's secret
	_, err = harness.service.RevealSecret(ctx, secrets.RevealRequest{
		VaultID:       pos.Vault.VaultID,
		SecretPath:    pos.Secret.SecretPath,
		Owner:         pos.AdminIdentity.Email,
		Identity:      harness.unrelatedIdent,
		Session:       harness.memberSession,
		StepUpManager: harness.stepUp,
		StepUpToken:   adminStepUpToken.Plaintext(),
	})
	if err == nil {
		t.Fatalf("cross-tenant reveal must fail closed")
	}

	// ==========================================
	// 6. ZERO PLAINTEXT SECRET LEAKAGE ROW
	// ==========================================
	// A) Full disk scan across storage directory
	inspectedFiles, err := security.AssertDirectoryClean(
		harness.dir,
		pos.Secret.SentinelSecret,
		pos.Secret.MemberSentinelSecret,
	)
	if err != nil {
		t.Fatalf("CRITICAL: plaintext sentinel secret found on disk! err=%v", err)
	}
	if inspectedFiles == 0 {
		t.Fatalf("expected inspected storage files > 0")
	}

	// B) Full audit event scrubber verification
	for i, evt := range harness.recorder.Events() {
		evtBytes, _ := json.Marshal(evt)
		if strings.Contains(string(evtBytes), pos.Secret.SentinelSecret) {
			t.Fatalf("CRITICAL: sentinel leaked in audit event %d: %s", i, evt.Type)
		}
		if err := security.AssertClean(evtBytes, pos.Secret.SentinelSecret); err != nil {
			t.Fatalf("audit event %d failed AssertClean: %v", i, err)
		}
	}
}

// TestC26DurabilityAndRestart verifies that privilege revocation and secret cleanliness survive restart.
func TestC26DurabilityAndRestart(t *testing.T) {
	var pos c26PositiveFixture
	loadC26Fixture(t, "positive.json", &pos)

	tempDir := filepath.Join(t.TempDir(), "c26-durability-store")

	// Phase 1: Create, grant, revoke, and close
	var grantID string
	{
		store, _, err := storage.Open(tempDir)
		if err != nil {
			t.Fatalf("phase 1 open store: %v", err)
		}

		server, _ := newC14Provider(t)
		adapter := newC14Adapter(t, server.URL, nil)

		mapper := auth.NewScopeMapper(auth.ScopeMapperConfig{
			VaultKEKMap:   map[string]string{pos.Vault.VaultID: pos.Vault.KEKID},
			VaultMountMap: map[string]string{pos.Vault.VaultID: pos.Vault.Mount},
			VaultRoleMap:  map[string]string{pos.Vault.VaultID: pos.Vault.Role},
		})
		svc := secrets.NewService(mapper, adapter, store)
		recorder := audit.NewRecorder(100, security.NewRedactor())
		grantsSvc := grants.NewService(store, recorder)
		sessionMgr, _ := auth.NewSessionManager(auth.DefaultSessionConfig(), nil)
		stepUpMgr, _ := auth.NewStepUpManager(auth.DefaultStepUpConfig(), nil)

		ctx := context.Background()
		adminIdent := &auth.Identity{
			Subject:       pos.AdminIdentity.Subject,
			Email:         pos.AdminIdentity.Email,
			VaultRole:     pos.AdminIdentity.VaultRole,
			AllowedOwners: pos.AdminIdentity.AllowedOwners,
			AllowedScopes: pos.AdminIdentity.AllowedScopes,
			ExpiresAt:     time.Now().Add(time.Hour).Unix(),
		}
		adminSess, _, _ := sessionMgr.CreateSession(ctx, adminIdent, auth.ClientInfo{})

		// Write secret
		_, err = svc.WriteSecret(ctx, secrets.WriteRequest{
			VaultID:         pos.Vault.VaultID,
			SecretPath:      pos.Secret.SecretPath,
			ExpectedVersion: 0,
			Plaintext:       []byte(pos.Secret.SentinelSecret),
			Classification:  pos.Secret.Classification,
			KEKID:           pos.Vault.KEKID,
			OperationID:     "op-durability-001",
			Owner:           pos.AdminIdentity.Email,
			Identity:        adminIdent,
		})
		if err != nil {
			t.Fatalf("phase 1 write secret: %v", err)
		}

		// Create grant
		_, createToken, _ := stepUpMgr.IssueGrant(ctx, adminSess, auth.ActionPolicyChange, "vault/"+pos.Vault.VaultID+"/grants")
		g, err := grantsSvc.CreateGrant(ctx, grants.CreateGrantRequest{
			VaultID:       pos.Vault.VaultID,
			PrincipalID:   pos.MemberIdentity.Email,
			Permissions:   pos.Grant.Permissions,
			OperatorIdent: adminIdent,
			Session:       adminSess,
			StepUpManager: stepUpMgr,
			StepUpToken:   createToken.Plaintext(),
		})
		if err != nil {
			t.Fatalf("phase 1 create grant: %v", err)
		}
		grantID = g.ID

		// Revoke grant
		_, revokeToken, _ := stepUpMgr.IssueGrant(ctx, adminSess, auth.ActionPolicyChange, "vault/grants/"+g.ID)
		err = grantsSvc.RevokeGrant(ctx, grants.RevokeGrantRequest{
			GrantID:       g.ID,
			OperatorIdent: adminIdent,
			Session:       adminSess,
			StepUpManager: stepUpMgr,
			StepUpToken:   revokeToken.Plaintext(),
		})
		if err != nil {
			t.Fatalf("phase 1 revoke grant: %v", err)
		}

		// Clean close
		if err := store.Close(); err != nil {
			t.Fatalf("phase 1 close store: %v", err)
		}
	}

	// Phase 2: Reopen from disk (simulating restart) and verify invariants
	{
		reopenedStore, report, err := storage.Open(tempDir)
		if err != nil {
			t.Fatalf("phase 2 reopen store: %v", err)
		}
		defer reopenedStore.Close()

		if report.ManifestVersion < 1 {
			t.Fatalf("reopened store must have valid manifest, got version %d", report.ManifestVersion)
		}

		ctx := context.Background()

		// Verify revoked grant is stored and marked revoked in the reloaded store
		grantRecord, err := reopenedStore.Read(ctx, storage.ReadRequest{
			Owner: pos.AdminIdentity.Email,
			Scope: "grants",
			Name:  grantID,
		})
		if err != nil {
			t.Fatalf("reopened store missing grant %s: %v", grantID, err)
		}

		var reloadedGrant grants.Grant
		if err := json.Unmarshal(grantRecord.Metadata, &reloadedGrant); err != nil {
			t.Fatalf("unmarshal reloaded grant metadata: %v", err)
		}

		if reloadedGrant.IsActive(time.Now()) {
			t.Fatalf("reloaded grant must not be active after restart: %+v", reloadedGrant)
		}
		if reloadedGrant.RevokedAt == nil {
			t.Fatalf("reloaded grant RevokedAt must not be nil")
		}

		// Verify zero plaintext secrets in reopened storage tree
		inspected, err := security.AssertDirectoryClean(tempDir, pos.Secret.SentinelSecret)
		if err != nil {
			t.Fatalf("reopened store leak: %v", err)
		}
		if inspected == 0 {
			t.Fatalf("zero storage files inspected on disk")
		}
	}
}

// TestC26NegativeCases exercises all required negative matrix scenarios.
func TestC26NegativeCases(t *testing.T) {
	harness := newC26Harness(t)
	ctx := context.Background()
	pos := harness.pos

	var neg c26NegativeFixture
	loadC26Fixture(t, "negative.json", &neg)

	// Seed secret
	_, err := harness.service.WriteSecret(ctx, secrets.WriteRequest{
		VaultID:         pos.Vault.VaultID,
		SecretPath:      pos.Secret.SecretPath,
		ExpectedVersion: 0,
		Plaintext:       []byte(pos.Secret.SentinelSecret),
		Classification:  pos.Secret.Classification,
		KEKID:           pos.Vault.KEKID,
		OperationID:     "op-neg-seed-001",
		Owner:           pos.AdminIdentity.Email,
		Identity:        harness.adminIdent,
	})
	if err != nil {
		t.Fatalf("seed secret failed: %v", err)
	}

	for _, tc := range neg.Cases {
		t.Run(tc.Case, func(t *testing.T) {
			switch tc.Case {
			case "missing-step-up-token":
				_, err := harness.service.RevealSecret(ctx, secrets.RevealRequest{
					VaultID:       pos.Vault.VaultID,
					SecretPath:    pos.Secret.SecretPath,
					Owner:         pos.AdminIdentity.Email,
					Identity:      harness.adminIdent,
					Session:       harness.adminSession,
					StepUpManager: harness.stepUp,
					StepUpToken:   "",
				})
				if err == nil {
					t.Fatalf("[%s] expected error, got nil", tc.Case)
				}
				code := extractErrorCode(err)
				if code != tc.ExpectedCode && code != "STEPUP_REQUIRED" && code != "STEP_UP_REQUIRED" {
					t.Fatalf("[%s] expected code %s, got %s", tc.Case, tc.ExpectedCode, code)
				}

			case "immediate-revocation-enforced":
				// Create and immediately revoke grant
				_, pToken, _ := harness.stepUp.IssueGrant(ctx, harness.adminSession, auth.ActionPolicyChange, "vault/"+pos.Vault.VaultID+"/grants")
				g, err := harness.grantsSvc.CreateGrant(ctx, grants.CreateGrantRequest{
					VaultID:       pos.Vault.VaultID,
					PrincipalID:   pos.MemberIdentity.Email,
					Permissions:   pos.Grant.Permissions,
					OperatorIdent: harness.adminIdent,
					Session:       harness.adminSession,
					StepUpManager: harness.stepUp,
					StepUpToken:   pToken.Plaintext(),
				})
				if err != nil {
					t.Fatalf("create grant: %v", err)
				}
				_, rToken, _ := harness.stepUp.IssueGrant(ctx, harness.adminSession, auth.ActionPolicyChange, "vault/grants/"+g.ID)
				_ = harness.grantsSvc.RevokeGrant(ctx, grants.RevokeGrantRequest{
					GrantID:       g.ID,
					OperatorIdent: harness.adminIdent,
					Session:       harness.adminSession,
					StepUpManager: harness.stepUp,
					StepUpToken:   rToken.Plaintext(),
				})

				if harness.grantsSvc.AuthorizeMemberAccess(pos.MemberIdentity.Email, pos.Vault.VaultID, "secret:read", pos.Secret.SecretPath) {
					t.Fatalf("[%s] expected AuthorizeMemberAccess false on revoked grant", tc.Case)
				}

			case "cross-tenant-secret-access":
				_, err := harness.service.RevealSecret(ctx, secrets.RevealRequest{
					VaultID:       pos.Vault.VaultID,
					SecretPath:    pos.Secret.SecretPath,
					Owner:         pos.AdminIdentity.Email,
					Identity:      harness.unrelatedIdent,
					Session:       harness.memberSession,
					StepUpManager: harness.stepUp,
					StepUpToken:   "dummy-token",
				})
				if err == nil {
					t.Fatalf("[%s] expected unauthorized, got nil", tc.Case)
				}

			case "expired-session-access":
				// 1. Expired identity check
				expiredIdent := &auth.Identity{
					Subject:       "usr_expired",
					Email:         "expired@keyhelix.local",
					VaultRole:     "vault-admin",
					AllowedOwners: []string{"expired@keyhelix.local"},
					AllowedScopes: []string{"secret:read"},
					ExpiresAt:     time.Now().Add(-1 * time.Hour).Unix(),
				}
				_, _, sessErr := harness.sessionMgr.CreateSession(ctx, expiredIdent, auth.ClientInfo{})
				if sessErr == nil {
					t.Fatalf("[%s] expected error creating session with expired identity, got nil", tc.Case)
				}

				// 2. Expired session check
				validIdent := &auth.Identity{
					Subject:       "usr_valid_for_exp",
					Email:         "valid_exp@keyhelix.local",
					VaultRole:     "vault-admin",
					AllowedOwners: []string{"valid_exp@keyhelix.local"},
					AllowedScopes: []string{"secret:read"},
					ExpiresAt:     time.Now().Add(1 * time.Hour).Unix(),
				}
				sess, _, err := harness.sessionMgr.CreateSession(ctx, validIdent, auth.ClientInfo{})
				if err != nil {
					t.Fatalf("create session: %v", err)
				}
				sess.ExpiresAt = time.Now().Add(-1 * time.Hour) // explicitly expired
				_, err = harness.service.RevealSecret(ctx, secrets.RevealRequest{
					VaultID:       pos.Vault.VaultID,
					SecretPath:    pos.Secret.SecretPath,
					Owner:         pos.AdminIdentity.Email,
					Identity:      validIdent,
					Session:       sess,
					StepUpManager: harness.stepUp,
					StepUpToken:   "dummy",
				})
				if err == nil {
					t.Fatalf("[%s] expected error on expired session reveal, got nil", tc.Case)
				}

			case "provider-offline-fails-closed":
				offlineServer, _ := newC14Provider(t)
				offlineAdapter := newC14Adapter(t, offlineServer.URL, nil)
				offlineSvc := secrets.NewService(harness.mapper, offlineAdapter, harness.store)
				offlineServer.Close() // shut down server so provider calls fail
				_, err := offlineSvc.WriteSecret(ctx, secrets.WriteRequest{
					VaultID:         pos.Vault.VaultID,
					SecretPath:      "app/prod/offline-test",
					ExpectedVersion: 0,
					Plaintext:       []byte("test"),
					Classification:  pos.Secret.Classification,
					KEKID:           pos.Vault.KEKID,
					OperationID:     "op-offline-001",
					Owner:           pos.AdminIdentity.Email,
					Identity:        harness.adminIdent,
				})
				if err == nil {
					t.Fatalf("[%s] offline provider must fail closed, got nil", tc.Case)
				}

			case "malformed-grant-input":
				_, err := harness.grantsSvc.CreateGrant(ctx, grants.CreateGrantRequest{
					VaultID:       "", // missing vault
					PrincipalID:   "", // missing principal
					Permissions:   nil,
					OperatorIdent: harness.adminIdent,
					Session:       harness.adminSession,
					StepUpManager: harness.stepUp,
					StepUpToken:   "dummy",
				})
				if err == nil {
					t.Fatalf("[%s] malformed grant input must fail, got nil", tc.Case)
				}

			case "forged-identity-headers":
				forgedHeaders := http.Header{}
				forgedHeaders.Set("X-Vault-Role", "vault-admin")
				_, err := harness.service.RevealSecret(ctx, secrets.RevealRequest{
					VaultID:       pos.Vault.VaultID,
					SecretPath:    pos.Secret.SecretPath,
					Owner:         pos.AdminIdentity.Email,
					Identity:      harness.unrelatedIdent,
					Session:       harness.memberSession,
					StepUpManager: harness.stepUp,
					StepUpToken:   "dummy",
					Headers:       forgedHeaders,
				})
				if err == nil {
					t.Fatalf("[%s] forged identity header must be rejected, got nil", tc.Case)
				}

			case "plaintext-leakage-assertion":
				inspected, err := security.AssertDirectoryClean(harness.dir, pos.Secret.SentinelSecret)
				if err != nil {
					t.Fatalf("[%s] plaintext leak detected: %v", tc.Case, err)
				}
				if inspected == 0 {
					t.Fatalf("[%s] expected inspected files > 0", tc.Case)
				}

			default:
				t.Fatalf("unhandled case: %s", tc.Case)
			}
		})
	}
}

// TestC26ConcurrencyRace verifies that security matrix assertions hold under concurrent access.
func TestC26ConcurrencyRace(t *testing.T) {
	harness := newC26Harness(t)
	ctx := context.Background()
	pos := harness.pos

	// Seed secret
	_, err := harness.service.WriteSecret(ctx, secrets.WriteRequest{
		VaultID:         pos.Vault.VaultID,
		SecretPath:      pos.Secret.SecretPath,
		ExpectedVersion: 0,
		Plaintext:       []byte(pos.Secret.SentinelSecret),
		Classification:  pos.Secret.Classification,
		KEKID:           pos.Vault.KEKID,
		OperationID:     "op-race-001",
		Owner:           pos.AdminIdentity.Email,
		Identity:        harness.adminIdent,
	})
	if err != nil {
		t.Fatalf("seed secret: %v", err)
	}

	var wg sync.WaitGroup
	workers := 12
	iterations := 25

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				// 1. Unauthorized actor attempt must consistently fail
				_, err := harness.service.RevealSecret(ctx, secrets.RevealRequest{
					VaultID:       pos.Vault.VaultID,
					SecretPath:    pos.Secret.SecretPath,
					Owner:         pos.AdminIdentity.Email,
					Identity:      harness.unrelatedIdent,
					Session:       harness.memberSession,
					StepUpManager: harness.stepUp,
					StepUpToken:   "dummy",
				})
				if err == nil {
					t.Errorf("worker %d: unauthorized reveal must fail", workerID)
				}

				// 2. Missing step-up attempt must consistently fail
				_, err = harness.service.RevealSecret(ctx, secrets.RevealRequest{
					VaultID:       pos.Vault.VaultID,
					SecretPath:    pos.Secret.SecretPath,
					Owner:         pos.AdminIdentity.Email,
					Identity:      harness.adminIdent,
					Session:       harness.adminSession,
					StepUpManager: harness.stepUp,
					StepUpToken:   "",
				})
				if err == nil {
					t.Errorf("worker %d: missing step-up must fail", workerID)
				}
			}
		}(w)
	}

	wg.Wait()
}
