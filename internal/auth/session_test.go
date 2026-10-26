package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSessionManager_CreateAndValidate(t *testing.T) {
	sm, err := NewSessionManager(DefaultSessionConfig(), nil)
	if err != nil {
		t.Fatalf("failed initializing session manager: %v", err)
	}

	identity := &Identity{
		Subject:       "usr_alice_01",
		Email:         "alice@keyhelix.local",
		VaultRole:     "vault-admin",
		AllowedOwners: []string{"alice@keyhelix.local", "org:platform"},
		AllowedScopes: []string{"vault:read", "vault:write", "secret:read", "secret:write"},
		ExpiresAt:     time.Now().Add(1 * time.Hour).Unix(),
	}

	client := ClientInfo{
		UserAgent: "Mozilla/5.0 KeyHelixTest",
		IPAddress: "127.0.0.1",
	}

	ctx := context.Background()
	sess, token, err := sm.CreateSession(ctx, identity, client)
	if err != nil {
		t.Fatalf("failed creating session: %v", err)
	}

	if sess.ID == "" {
		t.Fatalf("expected non-empty session ID")
	}
	if sess.TokenHash == "" {
		t.Fatalf("expected non-empty token hash")
	}
	if token.Plaintext() == "" {
		t.Fatalf("expected non-empty token plaintext")
	}

	// Validate valid session token
	validated, err := sm.ValidateSessionToken(ctx, token.Plaintext(), client)
	if err != nil {
		t.Fatalf("expected valid session, got err: %v", err)
	}
	if validated.ID != sess.ID {
		t.Fatalf("expected session ID %s, got %s", sess.ID, validated.ID)
	}

	// Client fingerprint mismatch
	differentClient := ClientInfo{
		UserAgent: "DifferentAgent/1.0",
		IPAddress: "192.168.1.100",
	}
	_, err = sm.ValidateSessionToken(ctx, token.Plaintext(), differentClient)
	if !IsErrorCode(err, CodeInvalidSession) {
		t.Fatalf("expected CodeInvalidSession for fingerprint mismatch, got: %v", err)
	}
}

func TestSessionManager_ExpiredIdentityRejected(t *testing.T) {
	sm, _ := NewSessionManager(DefaultSessionConfig(), nil)
	expiredIdentity := &Identity{
		Subject:   "usr_expired",
		ExpiresAt: time.Now().Add(-10 * time.Minute).Unix(),
	}

	_, _, err := sm.CreateSession(context.Background(), expiredIdentity, ClientInfo{})
	if !IsErrorCode(err, CodeExpiredToken) {
		t.Fatalf("expected CodeExpiredToken for expired identity, got: %v", err)
	}
}

func TestSessionManager_RevocationCannotReveal(t *testing.T) {
	sm, _ := NewSessionManager(DefaultSessionConfig(), nil)
	identity := &Identity{
		Subject:       "usr_alice_01",
		Email:         "alice@keyhelix.local",
		VaultRole:     "vault-admin",
		AllowedOwners: []string{"alice@keyhelix.local"},
		AllowedScopes: []string{"secret:read"},
		ExpiresAt:     time.Now().Add(1 * time.Hour).Unix(),
	}

	ctx := context.Background()
	sess, token, err := sm.CreateSession(ctx, identity, ClientInfo{})
	if err != nil {
		t.Fatalf("failed creating session: %v", err)
	}

	// Authorize prior to revocation succeeds
	err = AuthorizeSessionAction(sess, "alice@keyhelix.local", "secret:read")
	if err != nil {
		t.Fatalf("expected successful authorization before revocation, got: %v", err)
	}

	// Revoke the session
	err = sm.RevokeSession(ctx, sess.ID, "user logged out")
	if err != nil {
		t.Fatalf("failed revoking session: %v", err)
	}

	// 1. Validation of revoked session token fails closed
	_, err = sm.ValidateSessionToken(ctx, token.Plaintext(), ClientInfo{})
	if !IsErrorCode(err, CodeSessionRevoked) {
		t.Fatalf("expected CodeSessionRevoked from token validation, got: %v", err)
	}

	// 2. AuthorizeSessionAction on revoked session fails closed (Revoked session cannot reveal)
	err = AuthorizeSessionAction(sess, "alice@keyhelix.local", "secret:read")
	if !IsErrorCode(err, CodeSessionRevoked) {
		t.Fatalf("expected CodeSessionRevoked from AuthorizeSessionAction, got: %v", err)
	}
}

func TestSessionManager_DepartingUserRevocation(t *testing.T) {
	sm, _ := NewSessionManager(DefaultSessionConfig(), nil)
	bobIdentity := &Identity{
		Subject:       "usr_bob_02",
		Email:         "bob@keyhelix.local",
		VaultRole:     "vault-reader",
		AllowedOwners: []string{"bob@keyhelix.local"},
		AllowedScopes: []string{"secret:read"},
		ExpiresAt:     time.Now().Add(1 * time.Hour).Unix(),
	}

	ctx := context.Background()
	sess1, token1, _ := sm.CreateSession(ctx, bobIdentity, ClientInfo{})
	sess2, token2, _ := sm.CreateSession(ctx, bobIdentity, ClientInfo{})

	// Revoke all sessions for bob
	revokedCount, err := sm.RevokeAllForSubject(ctx, "usr_bob_02", "departing user offboarding")
	if err != nil {
		t.Fatalf("failed revoking all for subject: %v", err)
	}
	if revokedCount != 2 {
		t.Fatalf("expected 2 revoked sessions, got %d", revokedCount)
	}

	// Both sessions must now fail closed
	if _, err := sm.ValidateSessionToken(ctx, token1.Plaintext(), ClientInfo{}); !IsErrorCode(err, CodeSessionRevoked) {
		t.Fatalf("expected token1 to be revoked, got: %v", err)
	}
	if _, err := sm.ValidateSessionToken(ctx, token2.Plaintext(), ClientInfo{}); !IsErrorCode(err, CodeSessionRevoked) {
		t.Fatalf("expected token2 to be revoked, got: %v", err)
	}

	if err := AuthorizeSessionAction(sess1, "bob@keyhelix.local", "secret:read"); !IsErrorCode(err, CodeSessionRevoked) {
		t.Fatalf("expected sess1 to fail reveal authorization, got: %v", err)
	}
	if err := AuthorizeSessionAction(sess2, "bob@keyhelix.local", "secret:read"); !IsErrorCode(err, CodeSessionRevoked) {
		t.Fatalf("expected sess2 to fail reveal authorization, got: %v", err)
	}
}

func TestSessionManager_SessionExpiry(t *testing.T) {
	cfg := DefaultSessionConfig()
	cfg.DefaultTTL = 10 * time.Millisecond
	sm, _ := NewSessionManager(cfg, nil)

	identity := &Identity{
		Subject:       "usr_alice_01",
		Email:         "alice@keyhelix.local",
		AllowedOwners: []string{"alice@keyhelix.local"},
		AllowedScopes: []string{"secret:read"},
		ExpiresAt:     time.Now().Add(1 * time.Hour).Unix(),
	}

	ctx := context.Background()
	sess, token, _ := sm.CreateSession(ctx, identity, ClientInfo{})

	time.Sleep(20 * time.Millisecond)

	_, err := sm.ValidateSessionToken(ctx, token.Plaintext(), ClientInfo{})
	if !IsErrorCode(err, CodeSessionExpired) {
		t.Fatalf("expected CodeSessionExpired, got: %v", err)
	}

	err = AuthorizeSessionAction(sess, "alice@keyhelix.local", "secret:read")
	if !IsErrorCode(err, CodeSessionExpired) {
		t.Fatalf("expected CodeSessionExpired from AuthorizeSessionAction, got: %v", err)
	}
}

func TestSessionManager_SecureCookiePolicies(t *testing.T) {
	sm, _ := NewSessionManager(DefaultSessionConfig(), nil)
	rawToken := SessionToken("test-session-token-secret")
	expires := time.Now().Add(15 * time.Minute)

	cookie, err := sm.BuildSessionCookie(rawToken, expires)
	if err != nil {
		t.Fatalf("failed building session cookie: %v", err)
	}

	if !cookie.HttpOnly {
		t.Fatalf("expected HttpOnly=true")
	}
	if !cookie.Secure {
		t.Fatalf("expected Secure=true")
	}
	if cookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("expected SameSite=Strict")
	}
	if cookie.Value != rawToken.Plaintext() {
		t.Fatalf("expected cookie value to match raw token")
	}

	// Revocation cookie
	revCookie := sm.BuildRevocationCookie()
	if revCookie.MaxAge != -1 {
		t.Fatalf("expected MaxAge=-1 for revocation cookie")
	}
	if revCookie.Value != "" {
		t.Fatalf("expected empty value for revocation cookie")
	}

	// Insecure cookie rejection
	insecureCookie := &http.Cookie{
		Name:     "insecure",
		Value:    "val",
		HttpOnly: false,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	}
	if err := ValidateCookieSecurity(insecureCookie); !IsErrorCode(err, CodeCookieInsecure) {
		t.Fatalf("expected CodeCookieInsecure for missing HttpOnly, got: %v", err)
	}

	insecureCookie2 := &http.Cookie{
		Name:     "insecure",
		Value:    "val",
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteStrictMode,
	}
	if err := ValidateCookieSecurity(insecureCookie2); !IsErrorCode(err, CodeCookieInsecure) {
		t.Fatalf("expected CodeCookieInsecure for missing Secure, got: %v", err)
	}
}

func TestSessionManager_ExtractSessionToken(t *testing.T) {
	sm, _ := NewSessionManager(DefaultSessionConfig(), nil)

	// 1. From Authorization Header
	reqHeader := httptest.NewRequest(http.MethodGet, "/vault", nil)
	reqHeader.Header.Set("Authorization", "Bearer header-token-1234")
	tok, err := sm.ExtractSessionToken(reqHeader)
	if err != nil || tok != "header-token-1234" {
		t.Fatalf("failed extracting token from header: %v", err)
	}

	// 2. From Cookie
	reqCookie := httptest.NewRequest(http.MethodGet, "/vault", nil)
	reqCookie.AddCookie(&http.Cookie{
		Name:  "keyhelix_session",
		Value: "cookie-token-5678",
	})
	tok, err = sm.ExtractSessionToken(reqCookie)
	if err != nil || tok != "cookie-token-5678" {
		t.Fatalf("failed extracting token from cookie: %v", err)
	}

	// 3. Missing both
	reqEmpty := httptest.NewRequest(http.MethodGet, "/vault", nil)
	_, err = sm.ExtractSessionToken(reqEmpty)
	if !IsErrorCode(err, CodeSessionNotFound) {
		t.Fatalf("expected CodeSessionNotFound for missing token, got: %v", err)
	}
}

func TestSessionToken_NeverLoggedOrSerialized(t *testing.T) {
	secret := "super-sensitive-session-secret-abcdef123456"
	tok := SessionToken(secret)

	// 1. String formatting (%s, %v, %+v, %#v)
	formattedS := fmt.Sprintf("%s", tok)
	formattedV := fmt.Sprintf("%v", tok)
	formattedPlusV := fmt.Sprintf("%+v", tok)
	formattedHashV := fmt.Sprintf("%#v", tok)

	for _, str := range []string{formattedS, formattedV, formattedPlusV, formattedHashV} {
		if strings.Contains(str, secret) {
			t.Fatalf("session token secret leaked in fmt: %s", str)
		}
		if !strings.Contains(str, "[REDACTED]") {
			t.Fatalf("expected [REDACTED] in fmt output, got: %s", str)
		}
	}

	// 2. JSON Serialization
	type container struct {
		Token SessionToken `json:"token"`
	}
	c := container{Token: tok}
	data, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("failed marshaling container: %v", err)
	}
	if strings.Contains(string(data), secret) {
		t.Fatalf("session token secret leaked in JSON: %s", string(data))
	}
	if !strings.Contains(string(data), `"[REDACTED]"`) {
		t.Fatalf("expected [REDACTED] in json output, got: %s", string(data))
	}

	// 3. Log sanitization
	rawLog := fmt.Sprintf("Request failed with Bearer %s and cookie keyhelix_session=%s", secret, secret)
	sanitized := SanitizeLogMessage(rawLog)
	if strings.Contains(sanitized, secret) {
		t.Fatalf("secret leaked in sanitized log: %s", sanitized)
	}
	if !strings.Contains(sanitized, "Bearer [REDACTED]") || !strings.Contains(sanitized, "keyhelix_session=[REDACTED]") {
		t.Fatalf("expected sanitized log to contain redacted markers, got: %s", sanitized)
	}
}
