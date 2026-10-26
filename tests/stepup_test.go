package storage_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/parsa-emami/keyhelix/internal/auth"
)

type c10PositiveFixture struct {
	SchemaVersion int    `json:"schema_version"`
	Provenance    string `json:"provenance"`
	License       string `json:"license"`
	StepUpPolicy  struct {
		DefaultTTLSeconds int `json:"default_ttl_seconds"`
		MaxAgeSeconds     int `json:"max_age_seconds"`
		ClockSkewSeconds  int `json:"clock_skew_seconds"`
	} `json:"stepup_policy"`
	Identity struct {
		Subject       string   `json:"subject"`
		Email         string   `json:"email"`
		VaultRole     string   `json:"vault_role"`
		AllowedOwners []string `json:"allowed_owners"`
		AllowedScopes []string `json:"allowed_scopes"`
	} `json:"identity"`
	TargetReveal struct {
		VaultID       string `json:"vault_id"`
		SecretPath    string `json:"secret_path"`
		Action        string `json:"action"`
		RequiredScope string `json:"required_scope"`
	} `json:"target_reveal"`
	TargetPolicy struct {
		VaultID       string `json:"vault_id"`
		PolicyPath    string `json:"policy_path"`
		Action        string `json:"action"`
		RequiredScope string `json:"required_scope"`
	} `json:"target_policy"`
	PlaintextCanary string `json:"plaintext_canary"`
	MetadataFile    string `json:"metadata_file"`
}

type c10NegativeCase struct {
	Case             string `json:"case"`
	Kind             string `json:"kind"`
	Description      string `json:"description"`
	Action           string `json:"action,omitempty"`
	Token            string `json:"token,omitempty"`
	GrantedResource  string `json:"granted_resource,omitempty"`
	TargetResource   string `json:"target_resource,omitempty"`
	GrantedAction    string `json:"granted_action,omitempty"`
	TargetAction     string `json:"target_action,omitempty"`
	Actor            string `json:"actor,omitempty"`
	TargetOwner      string `json:"target_owner,omitempty"`
	Canary           string `json:"canary,omitempty"`
	ExpectedCode     string `json:"expected_code,omitempty"`
	ExpectedRedacted *bool  `json:"expected_redacted,omitempty"`
	ExpectedPersisted *bool `json:"expected_persisted,omitempty"`
}

type c10NegativeFixture struct {
	SchemaVersion int               `json:"schema_version"`
	Provenance    string            `json:"provenance"`
	License       string            `json:"license"`
	Cases         []c10NegativeCase `json:"cases"`
}

type c10ExpectedOutput struct {
	SchemaVersion   int               `json:"schema_version"`
	Provenance      string            `json:"provenance"`
	License         string            `json:"license"`
	MetadataSHA256  string            `json:"metadata_sha256"`
	PlaintextCanary string            `json:"plaintext_canary"`
	StepUpPolicy    map[string]any    `json:"stepup_policy"`
	GuardCodes      map[string]string `json:"guard_codes"`
}

func loadC10Fixture(t *testing.T, filename string, target any) {
	t.Helper()
	path := filepath.Join("fixtures", "keyhelix", "C10", filename)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read C10 fixture %s: %v", filename, err)
	}
	if err := json.Unmarshal(data, target); err != nil {
		t.Fatalf("unmarshal C10 fixture %s: %v", filename, err)
	}
}

func assertStepUpCode(t *testing.T, err error, expected auth.ErrorCode) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error code %s, got nil", expected)
	}
	var authErr *auth.Error
	if errors.As(err, &authErr) {
		if authErr.Code != expected {
			t.Fatalf("expected error code %s, got %s (%v)", expected, authErr.Code, err)
		}
		return
	}
	t.Fatalf("expected *auth.Error with code %s, got %T: %v", expected, err, err)
}

func TestC10_MetadataIntegrity(t *testing.T) {
	var expected c10ExpectedOutput
	loadC10Fixture(t, "expected-output.json", &expected)

	metadataPath := filepath.Join("fixtures", "keyhelix", "C10", "metadata.json")
	data, err := os.ReadFile(metadataPath)
	if err != nil {
		t.Fatalf("read C10 metadata: %v", err)
	}
	hash := sha256.Sum256(data)
	actualSHA256 := hex.EncodeToString(hash[:])
	if actualSHA256 != expected.MetadataSHA256 {
		t.Fatalf("metadata sha256 mismatch: got %s, expected %s", actualSHA256, expected.MetadataSHA256)
	}
}

func TestC10_StepUp_PositiveFlow(t *testing.T) {
	var pos c10PositiveFixture
	loadC10Fixture(t, "positive.json", &pos)

	sessionMgr, err := auth.NewSessionManager(auth.DefaultSessionConfig(), nil)
	if err != nil {
		t.Fatalf("init session manager: %v", err)
	}

	stepUpCfg := auth.DefaultStepUpConfig()
	stepUpCfg.DefaultTTL = time.Duration(pos.StepUpPolicy.DefaultTTLSeconds) * time.Second
	stepUpMgr, err := auth.NewStepUpManager(stepUpCfg, nil)
	if err != nil {
		t.Fatalf("init stepup manager: %v", err)
	}

	aliceIdentity := &auth.Identity{
		Subject:       pos.Identity.Subject,
		Email:         pos.Identity.Email,
		VaultRole:     pos.Identity.VaultRole,
		AllowedOwners: pos.Identity.AllowedOwners,
		AllowedScopes: pos.Identity.AllowedScopes,
		ExpiresAt:     time.Now().Add(1 * time.Hour).Unix(),
	}

	ctx := context.Background()
	sess, _, err := sessionMgr.CreateSession(ctx, aliceIdentity, auth.ClientInfo{})
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	// 1. Authorize Secret Reveal within 120s
	grantReveal, tokenReveal, err := stepUpMgr.IssueGrant(ctx, sess, auth.ActionRevealSecret, pos.TargetReveal.SecretPath)
	if err != nil {
		t.Fatalf("issue reveal grant: %v", err)
	}
	if grantReveal.SessionID != sess.ID {
		t.Fatalf("expected grant bound to session %s, got %s", sess.ID, grantReveal.SessionID)
	}
	err = auth.AuthorizeSensitiveAction(
		ctx,
		stepUpMgr,
		sess,
		tokenReveal.Plaintext(),
		pos.Identity.Email,
		pos.TargetReveal.RequiredScope,
		auth.ActionRevealSecret,
		pos.TargetReveal.SecretPath,
	)
	if err != nil {
		t.Fatalf("expected successful reveal authorization, got: %v", err)
	}

	// 2. Authorize Policy Change within 120s
	grantPolicy, tokenPolicy, err := stepUpMgr.IssueGrant(ctx, sess, auth.ActionPolicyChange, pos.TargetPolicy.PolicyPath)
	if err != nil {
		t.Fatalf("issue policy grant: %v", err)
	}
	if grantPolicy.SessionID != sess.ID {
		t.Fatalf("expected grant bound to session %s, got %s", sess.ID, grantPolicy.SessionID)
	}
	err = auth.AuthorizeSensitiveAction(
		ctx,
		stepUpMgr,
		sess,
		tokenPolicy.Plaintext(),
		pos.Identity.Email,
		pos.TargetPolicy.RequiredScope,
		auth.ActionPolicyChange,
		pos.TargetPolicy.PolicyPath,
	)
	if err != nil {
		t.Fatalf("expected successful policy change authorization, got: %v", err)
	}
}

func TestC10_NegativeCases_FixtureDriven(t *testing.T) {
	var pos c10PositiveFixture
	loadC10Fixture(t, "positive.json", &pos)

	var neg c10NegativeFixture
	loadC10Fixture(t, "negative.json", &neg)

	sessionMgr, _ := auth.NewSessionManager(auth.DefaultSessionConfig(), nil)
	stepUpMgr, _ := auth.NewStepUpManager(auth.DefaultStepUpConfig(), nil)

	aliceIdentity := &auth.Identity{
		Subject:       pos.Identity.Subject,
		Email:         pos.Identity.Email,
		VaultRole:     pos.Identity.VaultRole,
		AllowedOwners: pos.Identity.AllowedOwners,
		AllowedScopes: pos.Identity.AllowedScopes,
		ExpiresAt:     time.Now().Add(1 * time.Hour).Unix(),
	}

	ctx := context.Background()
	sess, _, _ := sessionMgr.CreateSession(ctx, aliceIdentity, auth.ClientInfo{})

	for _, tc := range neg.Cases {
		tc := tc
		t.Run(tc.Case, func(t *testing.T) {
			switch tc.Case {
			case "expired-stepup-cannot-authorize-reveal":
				shortCfg := auth.DefaultStepUpConfig()
				shortCfg.DefaultTTL = 2 * time.Millisecond
				shortMgr, _ := auth.NewStepUpManager(shortCfg, nil)
				_, token, err := shortMgr.IssueGrant(ctx, sess, auth.ActionRevealSecret, pos.TargetReveal.SecretPath)
				if err != nil {
					t.Fatalf("issue grant: %v", err)
				}
				time.Sleep(5 * time.Millisecond)

				err = auth.AuthorizeSensitiveAction(
					ctx,
					shortMgr,
					sess,
					token.Plaintext(),
					pos.Identity.Email,
					pos.TargetReveal.RequiredScope,
					auth.ActionRevealSecret,
					pos.TargetReveal.SecretPath,
				)
				assertStepUpCode(t, err, auth.ErrorCode(tc.ExpectedCode))

			case "expired-stepup-cannot-authorize-policy-change":
				shortCfg := auth.DefaultStepUpConfig()
				shortCfg.DefaultTTL = 2 * time.Millisecond
				shortMgr, _ := auth.NewStepUpManager(shortCfg, nil)
				_, token, err := shortMgr.IssueGrant(ctx, sess, auth.ActionPolicyChange, pos.TargetPolicy.PolicyPath)
				if err != nil {
					t.Fatalf("issue grant: %v", err)
				}
				time.Sleep(5 * time.Millisecond)

				err = auth.AuthorizeSensitiveAction(
					ctx,
					shortMgr,
					sess,
					token.Plaintext(),
					pos.Identity.Email,
					pos.TargetPolicy.RequiredScope,
					auth.ActionPolicyChange,
					pos.TargetPolicy.PolicyPath,
				)
				assertStepUpCode(t, err, auth.ErrorCode(tc.ExpectedCode))

			case "stepup-reuse-across-session-binding-rejected":
				sess2, _, _ := sessionMgr.CreateSession(ctx, aliceIdentity, auth.ClientInfo{})
				_, token1, _ := stepUpMgr.IssueGrant(ctx, sess, auth.ActionRevealSecret, pos.TargetReveal.SecretPath)

				// Attempting token1 with sess2 must fail closed
				err := auth.AuthorizeSensitiveAction(
					ctx,
					stepUpMgr,
					sess2,
					token1.Plaintext(),
					pos.Identity.Email,
					pos.TargetReveal.RequiredScope,
					auth.ActionRevealSecret,
					pos.TargetReveal.SecretPath,
				)
				assertStepUpCode(t, err, auth.ErrorCode(tc.ExpectedCode))

			case "missing-stepup-token-rejected":
				err := auth.AuthorizeSensitiveAction(
					ctx,
					stepUpMgr,
					sess,
					"",
					pos.Identity.Email,
					pos.TargetReveal.RequiredScope,
					auth.ActionRevealSecret,
					pos.TargetReveal.SecretPath,
				)
				assertStepUpCode(t, err, auth.ErrorCode(tc.ExpectedCode))

			case "missing-stepup-for-policy-change-rejected":
				err := auth.AuthorizeSensitiveAction(
					ctx,
					stepUpMgr,
					sess,
					"",
					pos.Identity.Email,
					pos.TargetPolicy.RequiredScope,
					auth.ActionPolicyChange,
					pos.TargetPolicy.PolicyPath,
				)
				assertStepUpCode(t, err, auth.ErrorCode(tc.ExpectedCode))

			case "forged-stepup-token-rejected":
				err := auth.AuthorizeSensitiveAction(
					ctx,
					stepUpMgr,
					sess,
					tc.Token,
					pos.Identity.Email,
					pos.TargetReveal.RequiredScope,
					auth.ActionRevealSecret,
					pos.TargetReveal.SecretPath,
				)
				assertStepUpCode(t, err, auth.ErrorCode(tc.ExpectedCode))

			case "stepup-resource-scope-mismatch":
				_, token, _ := stepUpMgr.IssueGrant(ctx, sess, auth.ActionRevealSecret, tc.GrantedResource)
				err := auth.AuthorizeSensitiveAction(
					ctx,
					stepUpMgr,
					sess,
					token.Plaintext(),
					pos.Identity.Email,
					pos.TargetReveal.RequiredScope,
					auth.ActionRevealSecret,
					tc.TargetResource,
				)
				assertStepUpCode(t, err, auth.ErrorCode(tc.ExpectedCode))

			case "stepup-action-type-mismatch":
				_, token, _ := stepUpMgr.IssueGrant(ctx, sess, auth.SensitiveAction(tc.GrantedAction), pos.TargetReveal.SecretPath)
				err := auth.AuthorizeSensitiveAction(
					ctx,
					stepUpMgr,
					sess,
					token.Plaintext(),
					pos.Identity.Email,
					pos.TargetPolicy.RequiredScope,
					auth.SensitiveAction(tc.TargetAction),
					pos.TargetReveal.SecretPath,
				)
				assertStepUpCode(t, err, auth.ErrorCode(tc.ExpectedCode))

			case "unrelated-owner-denied":
				_, token, _ := stepUpMgr.IssueGrant(ctx, sess, auth.ActionRevealSecret, pos.TargetReveal.SecretPath)
				err := auth.AuthorizeSensitiveAction(
					ctx,
					stepUpMgr,
					sess,
					token.Plaintext(),
					tc.TargetOwner,
					pos.TargetReveal.RequiredScope,
					auth.ActionRevealSecret,
					pos.TargetReveal.SecretPath,
				)
				assertStepUpCode(t, err, auth.ErrorCode(tc.ExpectedCode))

			case "widened-path-permission-denied":
				_, token, _ := stepUpMgr.IssueGrant(ctx, sess, auth.ActionRevealSecret, pos.TargetReveal.SecretPath)
				err := auth.AuthorizeSensitiveAction(
					ctx,
					stepUpMgr,
					sess,
					token.Plaintext(),
					tc.TargetOwner,
					tc.Action,
					auth.ActionRevealSecret,
					pos.TargetReveal.SecretPath,
				)
				assertStepUpCode(t, err, auth.ErrorCode(tc.ExpectedCode))

			case "token-leak-in-logs-prevented":
				secretToken := "stepup-token-to-verify-redaction-98765432"
				tok := auth.StepUpToken(secretToken)
				output := fmt.Sprintf("%v %+v %#v", tok, tok, tok)
				if strings.Contains(output, secretToken) {
					t.Fatalf("stepup token secret leaked in string format: %s", output)
				}
				sanitized := auth.SanitizeStepUpLogMessage(fmt.Sprintf("StepUp %s; stepup_token=%s", secretToken, secretToken))
				if strings.Contains(sanitized, secretToken) {
					t.Fatalf("stepup token secret leaked in sanitized log: %s", sanitized)
				}

			case "provider-owns-secret-bytes":
				canary := tc.Canary
				grant, _, _ := stepUpMgr.IssueGrant(ctx, sess, auth.ActionRevealSecret, pos.TargetReveal.SecretPath)
				grantJSON, _ := json.Marshal(grant)
				if strings.Contains(string(grantJSON), canary) {
					t.Fatalf("plaintext canary persisted in step-up grant json: %s", string(grantJSON))
				}
				grantStr := grant.String()
				if strings.Contains(grantStr, canary) {
					t.Fatalf("plaintext canary leaked in grant string: %s", grantStr)
				}
			}
		})
	}
}

func TestC10_ConcurrentStepUpAccess(t *testing.T) {
	sessionMgr, _ := auth.NewSessionManager(auth.DefaultSessionConfig(), nil)
	stepUpMgr, _ := auth.NewStepUpManager(auth.DefaultStepUpConfig(), nil)

	identity := &auth.Identity{
		Subject:       "usr_concurrent_stepup",
		Email:         "concurrent@keyhelix.local",
		AllowedOwners: []string{"concurrent@keyhelix.local"},
		AllowedScopes: []string{"secret:read"},
		ExpiresAt:     time.Now().Add(1 * time.Hour).Unix(),
	}

	ctx := context.Background()
	sess, _, _ := sessionMgr.CreateSession(ctx, identity, auth.ClientInfo{})
	grant, token, err := stepUpMgr.IssueGrant(ctx, sess, auth.ActionRevealSecret, "app/prod/database-url")
	if err != nil {
		t.Fatalf("issue grant: %v", err)
	}

	var wg sync.WaitGroup
	workers := 20
	iterations := 50

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				_, _ = stepUpMgr.ValidateStepUp(ctx, sess, token.Plaintext(), auth.ActionRevealSecret, "app/prod/database-url")
				_ = auth.AuthorizeSensitiveAction(
					ctx,
					stepUpMgr,
					sess,
					token.Plaintext(),
					"concurrent@keyhelix.local",
					"secret:read",
					auth.ActionRevealSecret,
					"app/prod/database-url",
				)
			}
		}()
	}

	// Concurrently revoke grant while readers are validating
	wg.Add(1)
	go func() {
		defer wg.Done()
		time.Sleep(2 * time.Millisecond)
		_ = stepUpMgr.Store().Revoke(ctx, grant.ID)
	}()

	wg.Wait()
}
