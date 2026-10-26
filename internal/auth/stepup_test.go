package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestStepUpManager_IssueAndValidate(t *testing.T) {
	sm, _ := NewSessionManager(DefaultSessionConfig(), nil)
	stepUpMgr, err := NewStepUpManager(DefaultStepUpConfig(), nil)
	if err != nil {
		t.Fatalf("failed initializing step-up manager: %v", err)
	}

	identity := &Identity{
		Subject:       "usr_alice_01",
		Email:         "alice@keyhelix.local",
		VaultRole:     "vault-admin",
		AllowedOwners: []string{"alice@keyhelix.local"},
		AllowedScopes: []string{"secret:read", "policy:write"},
		ExpiresAt:     time.Now().Add(1 * time.Hour).Unix(),
	}

	ctx := context.Background()
	sess, _, err := sm.CreateSession(ctx, identity, ClientInfo{})
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	grant, token, err := stepUpMgr.IssueGrant(ctx, sess, ActionRevealSecret, "app/prod/database-url")
	if err != nil {
		t.Fatalf("failed issuing step-up grant: %v", err)
	}

	if grant.ID == "" {
		t.Fatalf("expected non-empty grant ID")
	}
	if grant.SessionID != sess.ID {
		t.Fatalf("expected grant SessionID %s, got %s", sess.ID, grant.SessionID)
	}
	if token.Plaintext() == "" {
		t.Fatalf("expected non-empty token plaintext")
	}

	// Validate matching step-up
	validated, err := stepUpMgr.ValidateStepUp(ctx, sess, token.Plaintext(), ActionRevealSecret, "app/prod/database-url")
	if err != nil {
		t.Fatalf("expected valid step-up, got err: %v", err)
	}
	if validated.ID != grant.ID {
		t.Fatalf("expected grant ID %s, got %s", grant.ID, validated.ID)
	}

	// Authorize sensitive action
	err = AuthorizeSensitiveAction(ctx, stepUpMgr, sess, token.Plaintext(), "alice@keyhelix.local", "secret:read", ActionRevealSecret, "app/prod/database-url")
	if err != nil {
		t.Fatalf("expected successful authorization, got err: %v", err)
	}
}

func TestStepUpManager_ExpiredCannotRevealOrChangePolicy(t *testing.T) {
	sm, _ := NewSessionManager(DefaultSessionConfig(), nil)
	shortCfg := DefaultStepUpConfig()
	shortCfg.DefaultTTL = 10 * time.Millisecond
	stepUpMgr, _ := NewStepUpManager(shortCfg, nil)

	identity := &Identity{
		Subject:       "usr_alice_01",
		Email:         "alice@keyhelix.local",
		AllowedOwners: []string{"alice@keyhelix.local"},
		AllowedScopes: []string{"secret:read", "policy:write"},
		ExpiresAt:     time.Now().Add(1 * time.Hour).Unix(),
	}

	ctx := context.Background()
	sess, _, _ := sm.CreateSession(ctx, identity, ClientInfo{})

	// 1. Reveal Secret: Expired cannot reveal
	_, tokenReveal, _ := stepUpMgr.IssueGrant(ctx, sess, ActionRevealSecret, "app/prod/database-url")
	time.Sleep(20 * time.Millisecond)

	_, err := stepUpMgr.ValidateStepUp(ctx, sess, tokenReveal.Plaintext(), ActionRevealSecret, "app/prod/database-url")
	if !IsErrorCode(err, CodeStepUpExpired) {
		t.Fatalf("expected CodeStepUpExpired for reveal, got: %v", err)
	}

	err = AuthorizeSensitiveAction(ctx, stepUpMgr, sess, tokenReveal.Plaintext(), "alice@keyhelix.local", "secret:read", ActionRevealSecret, "app/prod/database-url")
	if !IsErrorCode(err, CodeStepUpExpired) {
		t.Fatalf("expected CodeStepUpExpired in AuthorizeSensitiveAction, got: %v", err)
	}

	// 2. Policy Change: Expired cannot authorize policy changes
	_, tokenPolicy, _ := stepUpMgr.IssueGrant(ctx, sess, ActionPolicyChange, "vault/policy/admin")
	time.Sleep(20 * time.Millisecond)

	_, err = stepUpMgr.ValidateStepUp(ctx, sess, tokenPolicy.Plaintext(), ActionPolicyChange, "vault/policy/admin")
	if !IsErrorCode(err, CodeStepUpExpired) {
		t.Fatalf("expected CodeStepUpExpired for policy change, got: %v", err)
	}

	err = AuthorizeSensitiveAction(ctx, stepUpMgr, sess, tokenPolicy.Plaintext(), "alice@keyhelix.local", "policy:write", ActionPolicyChange, "vault/policy/admin")
	if !IsErrorCode(err, CodeStepUpExpired) {
		t.Fatalf("expected CodeStepUpExpired in AuthorizeSensitiveAction for policy change, got: %v", err)
	}
}

func TestStepUpManager_CannotBeReusedAcrossSessionBinding(t *testing.T) {
	sm, _ := NewSessionManager(DefaultSessionConfig(), nil)
	stepUpMgr, _ := NewStepUpManager(DefaultStepUpConfig(), nil)

	identity := &Identity{
		Subject:       "usr_alice_01",
		Email:         "alice@keyhelix.local",
		AllowedOwners: []string{"alice@keyhelix.local"},
		AllowedScopes: []string{"secret:read"},
		ExpiresAt:     time.Now().Add(1 * time.Hour).Unix(),
	}

	ctx := context.Background()
	sess1, _, _ := sm.CreateSession(ctx, identity, ClientInfo{})
	sess2, _, _ := sm.CreateSession(ctx, identity, ClientInfo{})

	// Issue step-up bound to sess1
	_, token1, err := stepUpMgr.IssueGrant(ctx, sess1, ActionRevealSecret, "app/prod/database-url")
	if err != nil {
		t.Fatalf("issue grant: %v", err)
	}

	// Validate against sess1 succeeds
	_, err = stepUpMgr.ValidateStepUp(ctx, sess1, token1.Plaintext(), ActionRevealSecret, "app/prod/database-url")
	if err != nil {
		t.Fatalf("expected success with sess1, got: %v", err)
	}

	// Attempt to reuse token1 with sess2 MUST fail closed with CodeStepUpSessionMismatch
	_, err = stepUpMgr.ValidateStepUp(ctx, sess2, token1.Plaintext(), ActionRevealSecret, "app/prod/database-url")
	if !IsErrorCode(err, CodeStepUpSessionMismatch) {
		t.Fatalf("expected CodeStepUpSessionMismatch when reusing across session binding, got: %v", err)
	}

	// AuthorizeSensitiveAction with sess2 MUST fail closed
	err = AuthorizeSensitiveAction(ctx, stepUpMgr, sess2, token1.Plaintext(), "alice@keyhelix.local", "secret:read", ActionRevealSecret, "app/prod/database-url")
	if !IsErrorCode(err, CodeStepUpSessionMismatch) {
		t.Fatalf("expected CodeStepUpSessionMismatch in AuthorizeSensitiveAction, got: %v", err)
	}
}

func TestStepUpManager_ScopeMismatches(t *testing.T) {
	sm, _ := NewSessionManager(DefaultSessionConfig(), nil)
	stepUpMgr, _ := NewStepUpManager(DefaultStepUpConfig(), nil)

	identity := &Identity{
		Subject:       "usr_alice_01",
		Email:         "alice@keyhelix.local",
		AllowedOwners: []string{"alice@keyhelix.local"},
		AllowedScopes: []string{"secret:read", "policy:write"},
		ExpiresAt:     time.Now().Add(1 * time.Hour).Unix(),
	}

	ctx := context.Background()
	sess, _, _ := sm.CreateSession(ctx, identity, ClientInfo{})

	_, token, _ := stepUpMgr.IssueGrant(ctx, sess, ActionRevealSecret, "app/prod/database-url")

	// Resource mismatch
	_, err := stepUpMgr.ValidateStepUp(ctx, sess, token.Plaintext(), ActionRevealSecret, "app/prod/other-secret")
	if !IsErrorCode(err, CodeStepUpScopeDenied) {
		t.Fatalf("expected CodeStepUpScopeDenied for resource mismatch, got: %v", err)
	}

	// Action mismatch
	_, err = stepUpMgr.ValidateStepUp(ctx, sess, token.Plaintext(), ActionPolicyChange, "app/prod/database-url")
	if !IsErrorCode(err, CodeStepUpScopeDenied) {
		t.Fatalf("expected CodeStepUpScopeDenied for action mismatch, got: %v", err)
	}
}

func TestStepUpToken_NeverLoggedOrSerialized(t *testing.T) {
	rawSecret := "stepup-secret-token-abcdef1234567890"
	tok := StepUpToken(rawSecret)

	// Stringer checks
	for _, s := range []string{fmt.Sprintf("%s", tok), fmt.Sprintf("%v", tok), fmt.Sprintf("%+v", tok), fmt.Sprintf("%#v", tok)} {
		if strings.Contains(s, rawSecret) {
			t.Fatalf("secret leaked in fmt: %s", s)
		}
		if !strings.Contains(s, "[REDACTED]") {
			t.Fatalf("expected [REDACTED] in fmt output, got: %s", s)
		}
	}

	// JSON check
	data, _ := json.Marshal(map[string]StepUpToken{"grant": tok})
	if strings.Contains(string(data), rawSecret) {
		t.Fatalf("secret leaked in json: %s", string(data))
	}
	if !strings.Contains(string(data), `"[REDACTED]"`) {
		t.Fatalf("expected [REDACTED] in json output, got: %s", string(data))
	}

	// Log Sanitization check
	rawLog := fmt.Sprintf("Failed with StepUp %s and param stepup_token=%s", rawSecret, rawSecret)
	sanitized := SanitizeStepUpLogMessage(rawLog)
	if strings.Contains(sanitized, rawSecret) {
		t.Fatalf("secret leaked in sanitized log: %s", sanitized)
	}
	if !strings.Contains(sanitized, "StepUp [REDACTED]") || !strings.Contains(sanitized, "stepup_token=[REDACTED]") {
		t.Fatalf("expected sanitized log to contain redacted markers, got: %s", sanitized)
	}
}
