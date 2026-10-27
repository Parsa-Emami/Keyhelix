package grants

import (
	"context"
	"testing"
	"time"

	"github.com/parsa-emami/keyhelix/internal/auth"
)

func TestGrantAllowsPath(t *testing.T) {
	grant := &Grant{
		ID:          "grnt-test-01",
		VaultID:     "vault-prod",
		PrincipalID: "bob@keyhelix.local",
		Permissions: []string{
			"secret:read",
			"production/services/payment/*",
		},
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}

	if !grant.IsActive(time.Now()) {
		t.Fatalf("expected grant to be active")
	}

	// 1. Matching action and allowed path
	if !grant.AllowsPath("secret:read", "production/services/payment/api-key") {
		t.Fatalf("expected path to be allowed")
	}

	// 2. Disallowed path
	if grant.AllowsPath("secret:read", "production/services/other/secret") {
		t.Fatalf("expected path to be disallowed")
	}

	// 3. Disallowed action
	if grant.AllowsPath("secret:write", "production/services/payment/api-key") {
		t.Fatalf("expected action to be disallowed")
	}

	// 4. Revoked grant
	now := time.Now()
	grant.RevokedAt = &now
	if grant.IsActive(now) {
		t.Fatalf("revoked grant must not be active")
	}
}

func TestGrantServiceStepUpRequired(t *testing.T) {
	svc := NewService(nil, nil)
	ctx := context.Background()

	// Creating grant without StepUpManager fails closed
	_, err := svc.CreateGrant(ctx, CreateGrantRequest{
		VaultID:     "vault-prod",
		PrincipalID: "bob@keyhelix.local",
		Permissions: []string{"secret:read"},
	})
	if err == nil {
		t.Fatalf("expected error without step-up")
	}
	var grantErr *Error
	if err != nil && grantErr == nil {
		// Verify error code
		if err.Error() != "STEP_UP_REQUIRED: step-up authentication required for policy changes" {
			t.Fatalf("unexpected error message: %v", err)
		}
	}
}

func TestGrantServiceLifecycle(t *testing.T) {
	svc := NewService(nil, nil)
	ctx := context.Background()

	stepUpMgr, err := auth.NewStepUpManager(auth.DefaultStepUpConfig(), nil)
	if err != nil {
		t.Fatalf("create step-up manager: %v", err)
	}
	ident := &auth.Identity{
		Subject: "admin-sub",
		Email:   "admin@keyhelix.local",
	}
	sessMgr, _ := auth.NewSessionManager(auth.DefaultSessionConfig(), nil)
	session, _, err := sessMgr.CreateSession(ctx, ident, auth.ClientInfo{})
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	// Issue step-up grant for policy change
	_, stepUpTok, err := stepUpMgr.IssueGrant(ctx, session, auth.ActionPolicyChange, "vault/vault-prod/grants")
	if err != nil {
		t.Fatalf("issue step-up grant: %v", err)
	}

	grant, err := svc.CreateGrant(ctx, CreateGrantRequest{
		VaultID:       "vault-prod",
		PrincipalID:   "bob@keyhelix.local",
		Permissions:   []string{"secret:read", "production/services/*"},
		OperatorIdent: ident,
		Session:       session,
		StepUpManager: stepUpMgr,
		StepUpToken:   stepUpTok.Plaintext(),
	})
	if err != nil {
		t.Fatalf("create grant: %v", err)
	}

	if !svc.AuthorizeMemberAccess("bob@keyhelix.local", "vault-prod", "secret:read", "production/services/api") {
		t.Fatalf("expected member access to be authorized")
	}

	// Step-up required to revoke
	_, revokeTok, err := stepUpMgr.IssueGrant(ctx, session, auth.ActionPolicyChange, "vault/grants/"+grant.ID)
	if err != nil {
		t.Fatalf("issue revoke step-up: %v", err)
	}

	err = svc.RevokeGrant(ctx, RevokeGrantRequest{
		GrantID:       grant.ID,
		OperatorIdent: ident,
		Session:       session,
		StepUpManager: stepUpMgr,
		StepUpToken:   revokeTok.Plaintext(),
	})
	if err != nil {
		t.Fatalf("revoke grant: %v", err)
	}

	// Immediate reduction: member is no longer authorized
	if svc.AuthorizeMemberAccess("bob@keyhelix.local", "vault-prod", "secret:read", "production/services/api") {
		t.Fatalf("member access must be revoked immediately")
	}
}
