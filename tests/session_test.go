package storage_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/parsa-emami/keyhelix/internal/auth"
)

type c09PositiveFixture struct {
	SchemaVersion int    `json:"schema_version"`
	Provenance    string `json:"provenance"`
	License       string `json:"license"`
	Session       struct {
		TTLMinutes int    `json:"ttl_minutes"`
		CookieName string `json:"cookie_name"`
		CookiePath string `json:"cookie_path"`
		HTTPOnly   bool   `json:"http_only"`
		Secure     bool   `json:"secure"`
		SameSite   string `json:"same_site"`
	} `json:"session"`
	Identity struct {
		Subject       string   `json:"subject"`
		Email         string   `json:"email"`
		VaultRole     string   `json:"vault_role"`
		AllowedOwners []string `json:"allowed_owners"`
		AllowedScopes []string `json:"allowed_scopes"`
	} `json:"identity"`
	DepartingUser struct {
		Subject       string   `json:"subject"`
		Email         string   `json:"email"`
		VaultRole     string   `json:"vault_role"`
		AllowedOwners []string `json:"allowed_owners"`
		AllowedScopes []string `json:"allowed_scopes"`
	} `json:"departing_user"`
	TargetSecret struct {
		VaultID       string `json:"vault_id"`
		SecretPath    string `json:"secret_path"`
		RequiredScope string `json:"required_scope"`
	} `json:"target_secret"`
	PlaintextCanary string `json:"plaintext_canary"`
	MetadataFile    string `json:"metadata_file"`
}

type c09NegativeCase struct {
	Case             string `json:"case"`
	Kind             string `json:"kind"`
	Description      string `json:"description"`
	Token            string `json:"token,omitempty"`
	Actor            string `json:"actor,omitempty"`
	TargetOwner      string `json:"target_owner,omitempty"`
	Action           string `json:"action,omitempty"`
	Subject          string `json:"subject,omitempty"`
	Canary           string `json:"canary,omitempty"`
	ExpectedCode     string `json:"expected_code,omitempty"`
	ExpectedRedacted *bool  `json:"expected_redacted,omitempty"`
	ExpectedPersisted *bool `json:"expected_persisted,omitempty"`
}

type c09NegativeFixture struct {
	SchemaVersion int               `json:"schema_version"`
	Provenance    string            `json:"provenance"`
	License       string            `json:"license"`
	Cases         []c09NegativeCase `json:"cases"`
}

type c09ExpectedOutput struct {
	SchemaVersion   int               `json:"schema_version"`
	Provenance      string            `json:"provenance"`
	License         string            `json:"license"`
	MetadataSHA256  string            `json:"metadata_sha256"`
	PlaintextCanary string            `json:"plaintext_canary"`
	SessionPolicy   map[string]any    `json:"session_policy"`
	GuardCodes      map[string]string `json:"guard_codes"`
}

func loadC09Fixture(t *testing.T, filename string, target any) {
	t.Helper()
	path := filepath.Join("fixtures", "keyhelix", "C09", filename)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read C09 fixture %s: %v", filename, err)
	}
	if err := json.Unmarshal(data, target); err != nil {
		t.Fatalf("unmarshal C09 fixture %s: %v", filename, err)
	}
}

func assertSessionCode(t *testing.T, err error, expected auth.ErrorCode) {
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

func TestC09_MetadataIntegrity(t *testing.T) {
	var expected c09ExpectedOutput
	loadC09Fixture(t, "expected-output.json", &expected)

	metadataPath := filepath.Join("fixtures", "keyhelix", "C09", "metadata.json")
	data, err := os.ReadFile(metadataPath)
	if err != nil {
		t.Fatalf("read C09 metadata: %v", err)
	}
	hash := sha256.Sum256(data)
	actualSHA256 := hex.EncodeToString(hash[:])
	if actualSHA256 != expected.MetadataSHA256 {
		t.Fatalf("metadata sha256 mismatch: got %s, expected %s", actualSHA256, expected.MetadataSHA256)
	}
}

func TestC09_Session_PositiveFlow(t *testing.T) {
	var pos c09PositiveFixture
	loadC09Fixture(t, "positive.json", &pos)

	var expected c09ExpectedOutput
	loadC09Fixture(t, "expected-output.json", &expected)

	cfg := auth.DefaultSessionConfig()
	cfg.DefaultTTL = time.Duration(pos.Session.TTLMinutes) * time.Minute
	cfg.CookieName = pos.Session.CookieName
	cfg.CookiePath = pos.Session.CookiePath
	cfg.SecureCookie = pos.Session.Secure
	cfg.SameSite = http.SameSiteStrictMode

	sm, err := auth.NewSessionManager(cfg, nil)
	if err != nil {
		t.Fatalf("failed initializing session manager: %v", err)
	}

	aliceIdentity := &auth.Identity{
		Subject:       pos.Identity.Subject,
		Email:         pos.Identity.Email,
		VaultRole:     pos.Identity.VaultRole,
		AllowedOwners: pos.Identity.AllowedOwners,
		AllowedScopes: pos.Identity.AllowedScopes,
		ExpiresAt:     time.Now().Add(1 * time.Hour).Unix(),
	}

	client := auth.ClientInfo{
		UserAgent: "KeyHelix-Browser-Test/1.0",
		IPAddress: "127.0.0.1",
	}

	ctx := context.Background()
	sess, token, err := sm.CreateSession(ctx, aliceIdentity, client)
	if err != nil {
		t.Fatalf("failed creating session: %v", err)
	}

	// 1. Verify Session Invariants
	if sess.ID == "" {
		t.Fatalf("expected non-empty session ID")
	}
	expectedHash := sha256.Sum256([]byte(token.Plaintext()))
	if sess.TokenHash != hex.EncodeToString(expectedHash[:]) {
		t.Fatalf("expected token hash to match sha256(token)")
	}
	if sess.IsRevoked() {
		t.Fatalf("newly created session must not be revoked")
	}
	if sess.IsExpired(time.Now().UTC()) {
		t.Fatalf("newly created session must not be expired")
	}

	// 2. Verify Secure Cookie Generation
	cookie, err := sm.BuildSessionCookie(token, sess.ExpiresAt)
	if err != nil {
		t.Fatalf("failed building session cookie: %v", err)
	}
	if !cookie.HttpOnly {
		t.Fatalf("cookie must be HttpOnly")
	}
	if !cookie.Secure {
		t.Fatalf("cookie must be Secure")
	}
	if cookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("cookie must be SameSite=Strict")
	}
	if cookie.Value != token.Plaintext() {
		t.Fatalf("cookie value must contain token secret")
	}

	// 3. Verify Token Validation
	validated, err := sm.ValidateSessionToken(ctx, token.Plaintext(), client)
	if err != nil {
		t.Fatalf("failed validating active session token: %v", err)
	}
	if validated.ID != sess.ID {
		t.Fatalf("session ID mismatch: got %s, expected %s", validated.ID, sess.ID)
	}

	// 4. Verify Authorization for Target Secret Reveal Prior to Revocation
	err = auth.AuthorizeSessionAction(sess, pos.Identity.Email, pos.TargetSecret.RequiredScope)
	if err != nil {
		t.Fatalf("expected successful authorization before revocation, got: %v", err)
	}

	// 5. Revoke Session and verify Acceptance: "Revoked session cannot reveal"
	err = sm.RevokeSession(ctx, sess.ID, "user logout")
	if err != nil {
		t.Fatalf("failed revoking session: %v", err)
	}

	// Validation fails closed immediately
	_, err = sm.ValidateSessionToken(ctx, token.Plaintext(), client)
	assertSessionCode(t, err, auth.CodeSessionRevoked)

	// Reveal authorization fails closed immediately
	err = auth.AuthorizeSessionAction(sess, pos.Identity.Email, pos.TargetSecret.RequiredScope)
	assertSessionCode(t, err, auth.CodeSessionRevoked)
}

func TestC09_NegativeCases_FixtureDriven(t *testing.T) {
	var pos c09PositiveFixture
	loadC09Fixture(t, "positive.json", &pos)

	var neg c09NegativeFixture
	loadC09Fixture(t, "negative.json", &neg)

	sm, err := auth.NewSessionManager(auth.DefaultSessionConfig(), nil)
	if err != nil {
		t.Fatalf("failed initializing session manager: %v", err)
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

	for _, tc := range neg.Cases {
		tc := tc
		t.Run(tc.Case, func(t *testing.T) {
			switch tc.Case {
			case "revoked-session-cannot-reveal":
				sess, _, err := sm.CreateSession(ctx, aliceIdentity, auth.ClientInfo{})
				if err != nil {
					t.Fatalf("create session: %v", err)
				}
				_ = sm.RevokeSession(ctx, sess.ID, "administrative revocation")
				err = auth.AuthorizeSessionAction(sess, pos.Identity.Email, "secret:read")
				assertSessionCode(t, err, auth.ErrorCode(tc.ExpectedCode))

			case "expired-session-rejected":
				expiredCfg := auth.DefaultSessionConfig()
				expiredCfg.DefaultTTL = 1 * time.Millisecond
				shortSM, _ := auth.NewSessionManager(expiredCfg, nil)
				sess, token, _ := shortSM.CreateSession(ctx, aliceIdentity, auth.ClientInfo{})
				time.Sleep(5 * time.Millisecond)

				_, err := shortSM.ValidateSessionToken(ctx, token.Plaintext(), auth.ClientInfo{})
				assertSessionCode(t, err, auth.ErrorCode(tc.ExpectedCode))

				err = auth.AuthorizeSessionAction(sess, pos.Identity.Email, "secret:read")
				assertSessionCode(t, err, auth.ErrorCode(tc.ExpectedCode))

			case "forged-session-token-rejected":
				_, err := sm.ValidateSessionToken(ctx, tc.Token, auth.ClientInfo{})
				assertSessionCode(t, err, auth.ErrorCode(tc.ExpectedCode))

			case "missing-session-token-rejected":
				_, err := sm.ValidateSessionToken(ctx, "", auth.ClientInfo{})
				assertSessionCode(t, err, auth.ErrorCode(tc.ExpectedCode))

				req := httptest.NewRequest(http.MethodGet, "/vault", nil)
				_, err = sm.ExtractSessionToken(req)
				assertSessionCode(t, err, auth.ErrorCode(tc.ExpectedCode))

			case "unrelated-owner-denied":
				sess, _, _ := sm.CreateSession(ctx, aliceIdentity, auth.ClientInfo{})
				err := auth.AuthorizeSessionAction(sess, tc.TargetOwner, tc.Action)
				assertSessionCode(t, err, auth.ErrorCode(tc.ExpectedCode))

			case "widened-path-permission-denied":
				sess, _, _ := sm.CreateSession(ctx, aliceIdentity, auth.ClientInfo{})
				err := auth.AuthorizeSessionAction(sess, tc.TargetOwner, tc.Action)
				assertSessionCode(t, err, auth.ErrorCode(tc.ExpectedCode))

			case "insecure-cookie-rejected":
				insecureCfg := auth.DefaultSessionConfig()
				insecureCfg.SecureCookie = false
				insecureSM, _ := auth.NewSessionManager(insecureCfg, nil)
				_, err := insecureSM.BuildSessionCookie(auth.SessionToken("dummy"), time.Now().Add(15*time.Minute))
				assertSessionCode(t, err, auth.ErrorCode(tc.ExpectedCode))

				cookie := &http.Cookie{
					Name:     "insecure",
					Value:    "dummy",
					HttpOnly: false,
					Secure:   true,
					SameSite: http.SameSiteStrictMode,
				}
				err = auth.ValidateCookieSecurity(cookie)
				assertSessionCode(t, err, auth.ErrorCode(tc.ExpectedCode))

			case "token-leak-in-logs-prevented":
				secretToken := "secret-token-to-verify-redaction-12345678"
				tok := auth.SessionToken(secretToken)
				output := fmt.Sprintf("%v %+v %#v", tok, tok, tok)
				if strings.Contains(output, secretToken) {
					t.Fatalf("raw token secret leaked in string format: %s", output)
				}
				sanitized := auth.SanitizeLogMessage(fmt.Sprintf("Bearer %s; keyhelix_session=%s", secretToken, secretToken))
				if strings.Contains(sanitized, secretToken) {
					t.Fatalf("raw token secret leaked in sanitized log: %s", sanitized)
				}

			case "departing-user-revocation-immediate":
				bobIdentity := &auth.Identity{
					Subject:       pos.DepartingUser.Subject,
					Email:         pos.DepartingUser.Email,
					VaultRole:     pos.DepartingUser.VaultRole,
					AllowedOwners: pos.DepartingUser.AllowedOwners,
					AllowedScopes: pos.DepartingUser.AllowedScopes,
					ExpiresAt:     time.Now().Add(1 * time.Hour).Unix(),
				}
				sess, token, _ := sm.CreateSession(ctx, bobIdentity, auth.ClientInfo{})
				count, err := sm.RevokeAllForSubject(ctx, pos.DepartingUser.Subject, "departing user offboarding")
				if err != nil || count == 0 {
					t.Fatalf("failed revoking departing user: %v (count=%d)", err, count)
				}
				_, err = sm.ValidateSessionToken(ctx, token.Plaintext(), auth.ClientInfo{})
				assertSessionCode(t, err, auth.ErrorCode(tc.ExpectedCode))
				err = auth.AuthorizeSessionAction(sess, pos.DepartingUser.Email, "secret:read")
				assertSessionCode(t, err, auth.ErrorCode(tc.ExpectedCode))

			case "provider-owns-secret-bytes":
				canary := tc.Canary
				sess, _, _ := sm.CreateSession(ctx, aliceIdentity, auth.ClientInfo{})
				sessJSON, _ := json.Marshal(sess)
				if strings.Contains(string(sessJSON), canary) {
					t.Fatalf("plaintext canary persisted in session json: %s", string(sessJSON))
				}
				sessStr := sess.String()
				if strings.Contains(sessStr, canary) {
					t.Fatalf("plaintext canary leaked in session string: %s", sessStr)
				}
			}
		})
	}
}

func TestC09_ConcurrentSessionAccess(t *testing.T) {
	sm, err := auth.NewSessionManager(auth.DefaultSessionConfig(), nil)
	if err != nil {
		t.Fatalf("failed initializing session manager: %v", err)
	}

	identity := &auth.Identity{
		Subject:       "usr_concurrent",
		Email:         "concurrent@keyhelix.local",
		AllowedOwners: []string{"concurrent@keyhelix.local"},
		AllowedScopes: []string{"secret:read"},
		ExpiresAt:     time.Now().Add(1 * time.Hour).Unix(),
	}

	ctx := context.Background()
	sess, token, err := sm.CreateSession(ctx, identity, auth.ClientInfo{})
	if err != nil {
		t.Fatalf("failed creating session: %v", err)
	}

	var wg sync.WaitGroup
	workers := 20
	iterations := 100

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				_, _ = sm.ValidateSessionToken(ctx, token.Plaintext(), auth.ClientInfo{})
				_ = auth.AuthorizeSessionAction(sess, "concurrent@keyhelix.local", "secret:read")
			}
		}()
	}

	// Concurrently revoke session while readers are validating
	wg.Add(1)
	go func() {
		defer wg.Done()
		time.Sleep(2 * time.Millisecond)
		_ = sm.RevokeSession(ctx, sess.ID, "concurrent test revocation")
	}()

	wg.Wait()

	// Final check: session must be revoked
	if !sess.IsRevoked() {
		t.Fatalf("expected session to be marked revoked")
	}
	_, err = sm.ValidateSessionToken(ctx, token.Plaintext(), auth.ClientInfo{})
	assertSessionCode(t, err, auth.CodeSessionRevoked)
}
