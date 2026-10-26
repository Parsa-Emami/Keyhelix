package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func makeTestJWT(header map[string]any, payload map[string]any) string {
	hBytes, _ := json.Marshal(header)
	pBytes, _ := json.Marshal(payload)
	hB64 := base64.RawURLEncoding.EncodeToString(hBytes)
	pB64 := base64.RawURLEncoding.EncodeToString(pBytes)
	sigB64 := base64.RawURLEncoding.EncodeToString([]byte("synthetic-signature-bytes"))
	return fmt.Sprintf("%s.%s.%s", hB64, pB64, sigB64)
}

func TestNewProvider_Validation(t *testing.T) {
	_, err := NewProvider(Config{IssuerURL: "", ClientID: "cid", RedirectURI: "http://cb"})
	if !IsErrorCode(err, CodeInvalidConfig) {
		t.Fatalf("expected CodeInvalidConfig for empty issuer, got %v", err)
	}

	_, err = NewProvider(Config{IssuerURL: "https://auth.local", ClientID: "", RedirectURI: "http://cb"})
	if !IsErrorCode(err, CodeInvalidConfig) {
		t.Fatalf("expected CodeInvalidConfig for empty client_id, got %v", err)
	}

	_, err = NewProvider(Config{IssuerURL: "https://auth.local", ClientID: "cid", RedirectURI: ""})
	if !IsErrorCode(err, CodeInvalidConfig) {
		t.Fatalf("expected CodeInvalidConfig for empty redirect_uri, got %v", err)
	}

	p, err := NewProvider(Config{
		IssuerURL:   "https://auth.local/",
		ClientID:    "cid",
		RedirectURI: "http://cb",
	})
	if err != nil {
		t.Fatalf("unexpected error creating provider: %v", err)
	}
	if p.Config().IssuerURL != "https://auth.local" {
		t.Fatalf("expected trimmed issuer URL, got %q", p.Config().IssuerURL)
	}
}

func TestPKCE_GenerateAndVerify(t *testing.T) {
	verifier, challenge, err := GeneratePKCE()
	if err != nil {
		t.Fatalf("GeneratePKCE failed: %v", err)
	}
	if len(verifier) == 0 || len(challenge) == 0 {
		t.Fatalf("empty verifier or challenge")
	}

	if !VerifyPKCE(verifier, challenge) {
		t.Fatalf("expected valid PKCE verification to succeed")
	}

	if VerifyPKCE("wrong-verifier", challenge) {
		t.Fatalf("expected PKCE verification to fail with mismatched verifier")
	}
}

func TestBeginAuthFlow(t *testing.T) {
	p, err := NewProvider(Config{
		IssuerURL:   "https://auth.example.com",
		ClientID:    "client-123",
		RedirectURI: "https://app.example.com/callback",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req, authURL, err := p.BeginAuthFlow()
	if err != nil {
		t.Fatalf("BeginAuthFlow failed: %v", err)
	}
	if req.State == "" || req.Nonce == "" || req.CodeVerifier == "" || req.CodeChallenge == "" {
		t.Fatalf("incomplete AuthRequest: %+v", req)
	}
	if !VerifyPKCE(req.CodeVerifier, req.CodeChallenge) {
		t.Fatalf("generated PKCE pair does not verify")
	}
	if authURL == "" {
		t.Fatalf("empty authURL")
	}
}

func TestValidateCallbackState(t *testing.T) {
	p, _ := NewProvider(Config{IssuerURL: "https://auth.local", ClientID: "cid", RedirectURI: "http://cb"})

	if err := p.ValidateCallbackState("state-123", "state-123"); err != nil {
		t.Fatalf("expected state match, got %v", err)
	}

	if err := p.ValidateCallbackState("state-123", "state-tampered"); !IsErrorCode(err, CodeStateMismatch) {
		t.Fatalf("expected CodeStateMismatch for tampered state, got %v", err)
	}

	if err := p.ValidateCallbackState("", "state-123"); !IsErrorCode(err, CodeStateMismatch) {
		t.Fatalf("expected CodeStateMismatch for empty expected state, got %v", err)
	}
}

func TestParseAndVerifyIDToken(t *testing.T) {
	p, _ := NewProvider(Config{
		IssuerURL:   "https://auth.example.com",
		ClientID:    "client-123",
		RedirectURI: "https://app.example.com/callback",
		ClockSkew:   30 * time.Second,
	})

	now := time.Now().UTC()
	validHeader := map[string]any{"alg": "RS256", "typ": "JWT"}

	// Valid token
	validPayload := map[string]any{
		"iss":            "https://auth.example.com",
		"sub":            "usr-1",
		"aud":            "client-123",
		"exp":            now.Add(10 * time.Minute).Unix(),
		"iat":            now.Unix(),
		"nonce":          "nonce-abc",
		"email":          "alice@example.com",
		"vault_role":     "vault-admin",
		"allowed_owners": []string{"alice@example.com", "team-sec"},
		"allowed_scopes": []string{"vault:read", "vault:write"},
	}
	token := makeTestJWT(validHeader, validPayload)

	id, err := p.ParseAndVerifyIDToken(token, "nonce-abc", now)
	if err != nil {
		t.Fatalf("unexpected error on valid token: %v", err)
	}
	if id.Subject != "usr-1" || id.Email != "alice@example.com" {
		t.Fatalf("unexpected identity parsed: %+v", id)
	}

	// Invalid Issuer
	badIssPayload := map[string]any{
		"iss":   "https://attacker.com",
		"sub":   "usr-1",
		"aud":   "client-123",
		"exp":   now.Add(10 * time.Minute).Unix(),
		"nonce": "nonce-abc",
	}
	_, err = p.ParseAndVerifyIDToken(makeTestJWT(validHeader, badIssPayload), "nonce-abc", now)
	if !IsErrorCode(err, CodeInvalidIssuer) {
		t.Fatalf("expected CodeInvalidIssuer, got %v", err)
	}

	// Invalid Audience
	badAudPayload := map[string]any{
		"iss":   "https://auth.example.com",
		"sub":   "usr-1",
		"aud":   "other-client",
		"exp":   now.Add(10 * time.Minute).Unix(),
		"nonce": "nonce-abc",
	}
	_, err = p.ParseAndVerifyIDToken(makeTestJWT(validHeader, badAudPayload), "nonce-abc", now)
	if !IsErrorCode(err, CodeInvalidAudience) {
		t.Fatalf("expected CodeInvalidAudience, got %v", err)
	}

	// Expired Token
	expiredPayload := map[string]any{
		"iss":   "https://auth.example.com",
		"sub":   "usr-1",
		"aud":   "client-123",
		"exp":   now.Add(-2 * time.Minute).Unix(),
		"nonce": "nonce-abc",
	}
	_, err = p.ParseAndVerifyIDToken(makeTestJWT(validHeader, expiredPayload), "nonce-abc", now)
	if !IsErrorCode(err, CodeExpiredToken) {
		t.Fatalf("expected CodeExpiredToken, got %v", err)
	}

	// Nonce Mismatch (Replay)
	_, err = p.ParseAndVerifyIDToken(token, "other-nonce", now)
	if !IsErrorCode(err, CodeNonceMismatch) {
		t.Fatalf("expected CodeNonceMismatch, got %v", err)
	}

	// Forged Header ("none" algorithm)
	noneHeader := map[string]any{"alg": "none", "typ": "JWT"}
	_, err = p.ParseAndVerifyIDToken(makeTestJWT(noneHeader, validPayload), "nonce-abc", now)
	if !IsErrorCode(err, CodeInvalidToken) {
		t.Fatalf("expected CodeInvalidToken for alg 'none', got %v", err)
	}
}

func TestAuthorizeAction(t *testing.T) {
	id := &Identity{
		Subject:       "usr-1",
		Email:         "alice@example.com",
		AllowedOwners: []string{"alice@example.com", "org:platform"},
		AllowedScopes: []string{"vault:read", "vault:write", "secret:*"},
	}

	// Self-owner and permitted scope
	if err := AuthorizeAction(id, "alice@example.com", "vault:read"); err != nil {
		t.Fatalf("expected authorized, got %v", err)
	}

	// Allowed org owner and prefix-matched scope
	if err := AuthorizeAction(id, "org:platform", "secret:read"); err != nil {
		t.Fatalf("expected authorized, got %v", err)
	}

	// Unrelated owner
	if err := AuthorizeAction(id, "bob@example.com", "vault:read"); !IsErrorCode(err, CodeScopeDenied) {
		t.Fatalf("expected CodeScopeDenied for unrelated owner, got %v", err)
	}

	// Unauthorized scope / widened permission
	if err := AuthorizeAction(id, "alice@example.com", "admin:override"); !IsErrorCode(err, CodeScopeDenied) {
		t.Fatalf("expected CodeScopeDenied for widened permission, got %v", err)
	}

	// Nil identity
	if err := AuthorizeAction(nil, "alice@example.com", "vault:read"); !IsErrorCode(err, CodeInvalidToken) {
		t.Fatalf("expected CodeInvalidToken for nil identity, got %v", err)
	}
}

func TestExchangeAndValidate(t *testing.T) {
	var tokenHandler http.HandlerFunc

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if tokenHandler != nil {
			tokenHandler(w, r)
		}
	}))
	defer server.Close()

	p, err := NewProvider(Config{
		IssuerURL:   server.URL,
		ClientID:    "client-123",
		RedirectURI: "http://localhost/callback",
		HTTPClient:  server.Client(),
	})
	if err != nil {
		t.Fatalf("NewProvider failed: %v", err)
	}

	authReq, _, err := p.BeginAuthFlow()
	if err != nil {
		t.Fatalf("BeginAuthFlow failed: %v", err)
	}

	// 1. Success case
	validPayload := map[string]any{
		"iss":   server.URL,
		"sub":   "usr-1",
		"aud":   "client-123",
		"exp":   time.Now().Add(5 * time.Minute).Unix(),
		"nonce": authReq.Nonce,
		"email": "alice@keyhelix.local",
	}
	validIDToken := makeTestJWT(map[string]any{"alg": "RS256"}, validPayload)

	tokenHandler = func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/token" {
			http.NotFound(w, r)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		verifier := r.Form.Get("code_verifier")
		if !VerifyPKCE(verifier, authReq.CodeChallenge) {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error":             "invalid_grant",
				"error_description": "PKCE verification failed",
			})
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(TokenResponse{
			AccessToken: "synthetic-access-token",
			TokenType:   "Bearer",
			IDToken:     validIDToken,
		})
	}

	id, err := p.ExchangeAndValidate(context.Background(), "auth-code-123", authReq.State, authReq)
	if err != nil {
		t.Fatalf("ExchangeAndValidate failed: %v", err)
	}
	if id.Email != "alice@keyhelix.local" {
		t.Fatalf("unexpected email %q", id.Email)
	}

	// 2. PKCE failure case
	tamperedReq := *authReq
	tamperedReq.CodeVerifier = "tampered-verifier-which-does-not-match-challenge"
	_, err = p.ExchangeAndValidate(context.Background(), "auth-code-123", tamperedReq.State, &tamperedReq)
	if !IsErrorCode(err, CodeInvalidPKCE) {
		t.Fatalf("expected CodeInvalidPKCE, got %v", err)
	}

	// 3. Callback State mismatch
	_, err = p.ExchangeAndValidate(context.Background(), "auth-code-123", "tampered-state", authReq)
	if !IsErrorCode(err, CodeStateMismatch) {
		t.Fatalf("expected CodeStateMismatch, got %v", err)
	}

	// 4. Server 500 error
	tokenHandler = func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("server error"))
	}
	_, err = p.ExchangeAndValidate(context.Background(), "auth-code-123", authReq.State, authReq)
	if !IsErrorCode(err, CodeIDPUnavailable) {
		t.Fatalf("expected CodeIDPUnavailable, got %v", err)
	}
}
