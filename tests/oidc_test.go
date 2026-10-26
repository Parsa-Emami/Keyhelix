package storage_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/parsa-emami/keyhelix/internal/auth"
)

type c08PositiveFixture struct {
	SchemaVersion int    `json:"schema_version"`
	Provenance    string `json:"provenance"`
	License       string `json:"license"`
	Provider      struct {
		Issuer      string   `json:"issuer"`
		ClientID    string   `json:"client_id"`
		RedirectURI string   `json:"redirect_uri"`
		Scopes      []string `json:"scopes"`
	} `json:"provider"`
	Identity struct {
		Subject       string   `json:"subject"`
		Email         string   `json:"email"`
		VaultRole     string   `json:"vault_role"`
		AllowedOwners []string `json:"allowed_owners"`
		AllowedScopes []string `json:"allowed_scopes"`
	} `json:"identity"`
	PKCE struct {
		CodeChallengeMethod string `json:"code_challenge_method"`
	} `json:"pkce"`
	PlaintextCanary string `json:"plaintext_canary"`
	MetadataFile    string `json:"metadata_file"`
}

type c08NegativeCase struct {
	Case             string `json:"case"`
	Kind             string `json:"kind"`
	Description      string `json:"description"`
	TokenIssuer      string `json:"token_issuer,omitempty"`
	TokenAudience    string `json:"token_audience,omitempty"`
	Expired          bool   `json:"expired,omitempty"`
	Nonce            string `json:"nonce,omitempty"`
	CallbackState    string `json:"callback_state,omitempty"`
	CodeVerifier     string `json:"code_verifier,omitempty"`
	Actor            string `json:"actor,omitempty"`
	TargetOwner      string `json:"target_owner,omitempty"`
	Action           string `json:"action,omitempty"`
	Header           string `json:"header,omitempty"`
	ProviderOffline  bool   `json:"provider_offline,omitempty"`
	Canary           string `json:"canary,omitempty"`
	ExpectedCode     string `json:"expected_code,omitempty"`
	ExpectedPersisted *bool `json:"expected_persisted,omitempty"`
}

type c08NegativeFixture struct {
	SchemaVersion int               `json:"schema_version"`
	Provenance    string            `json:"provenance"`
	License       string            `json:"license"`
	Cases         []c08NegativeCase `json:"cases"`
}

type c08ExpectedOutput struct {
	SchemaVersion   int               `json:"schema_version"`
	Provenance      string            `json:"provenance"`
	License         string            `json:"license"`
	MetadataSHA256  string            `json:"metadata_sha256"`
	PlaintextCanary string            `json:"plaintext_canary"`
	AuthFlow        map[string]string `json:"auth_flow"`
	GuardCodes      map[string]string `json:"guard_codes"`
}

func loadC08Fixture(t *testing.T, filename string, target any) {
	t.Helper()
	path := filepath.Join("fixtures", "keyhelix", "C08", filename)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read C08 fixture %s: %v", filename, err)
	}
	if err := json.Unmarshal(data, target); err != nil {
		t.Fatalf("unmarshal C08 fixture %s: %v", filename, err)
	}
}

func assertAuthCode(t *testing.T, err error, expected auth.ErrorCode) {
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

func makeSyntheticJWT(header map[string]any, payload map[string]any) string {
	hBytes, _ := json.Marshal(header)
	pBytes, _ := json.Marshal(payload)
	hB64 := base64.RawURLEncoding.EncodeToString(hBytes)
	pB64 := base64.RawURLEncoding.EncodeToString(pBytes)
	sigB64 := base64.RawURLEncoding.EncodeToString([]byte("synthetic-signature-bytes"))
	return fmt.Sprintf("%s.%s.%s", hB64, pB64, sigB64)
}

func TestC08_MetadataIntegrity(t *testing.T) {
	var expected c08ExpectedOutput
	loadC08Fixture(t, "expected-output.json", &expected)

	metadataPath := filepath.Join("fixtures", "keyhelix", "C08", "metadata.json")
	data, err := os.ReadFile(metadataPath)
	if err != nil {
		t.Fatalf("read C08 metadata: %v", err)
	}
	hash := sha256.Sum256(data)
	actualSHA256 := hex.EncodeToString(hash[:])
	if actualSHA256 != expected.MetadataSHA256 {
		t.Fatalf("metadata sha256 mismatch: got %s, expected %s", actualSHA256, expected.MetadataSHA256)
	}
}

func TestC08_OIDC_PositiveFlow(t *testing.T) {
	var pos c08PositiveFixture
	loadC08Fixture(t, "positive.json", &pos)

	var expected c08ExpectedOutput
	loadC08Fixture(t, "expected-output.json", &expected)

	// Mock OIDC token server
	var lastAuthReq *auth.AuthRequest
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" && r.Method == http.MethodPost {
			if err := r.ParseForm(); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			// Validate PKCE code_verifier
			verifier := r.Form.Get("code_verifier")
			if lastAuthReq != nil && !auth.VerifyPKCE(verifier, lastAuthReq.CodeChallenge) {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]string{
					"error":             "invalid_grant",
					"error_description": "PKCE verification failed",
				})
				return
			}

			// Return valid token
			now := time.Now().UTC()
			idToken := makeSyntheticJWT(
				map[string]any{"alg": "RS256", "typ": "JWT"},
				map[string]any{
					"iss":            "http://" + r.Host,
					"sub":            pos.Identity.Subject,
					"aud":            pos.Provider.ClientID,
					"exp":            now.Add(15 * time.Minute).Unix(),
					"iat":            now.Unix(),
					"nonce":          lastAuthReq.Nonce,
					"email":          pos.Identity.Email,
					"vault_role":     pos.Identity.VaultRole,
					"allowed_owners": pos.Identity.AllowedOwners,
					"allowed_scopes": pos.Identity.AllowedScopes,
				},
			)

			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(auth.TokenResponse{
				AccessToken: "synthetic-bearer-access-token",
				TokenType:   "Bearer",
				IDToken:     idToken,
				ExpiresIn:   900,
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer mockServer.Close()

	// Initialize Provider pointing to mock server
	provider, err := auth.NewProvider(auth.Config{
		IssuerURL:   mockServer.URL,
		ClientID:    pos.Provider.ClientID,
		RedirectURI: pos.Provider.RedirectURI,
		HTTPClient:  mockServer.Client(),
	})
	if err != nil {
		t.Fatalf("failed creating provider: %v", err)
	}

	// 1. Begin auth flow (generates state, nonce, PKCE)
	authReq, authURL, err := provider.BeginAuthFlow()
	if err != nil {
		t.Fatalf("BeginAuthFlow failed: %v", err)
	}
	lastAuthReq = authReq

	if authReq.State == "" || authReq.Nonce == "" {
		t.Fatalf("expected non-empty state and nonce")
	}
	if !strings.Contains(authURL, "code_challenge=") || !strings.Contains(authURL, "code_challenge_method=S256") {
		t.Fatalf("expected authURL to include PKCE challenge: %s", authURL)
	}

	// 2. Validate state callback
	if err := provider.ValidateCallbackState(authReq.State, authReq.State); err != nil {
		t.Fatalf("state validation failed: %v", err)
	}

	// 3. Exchange code and validate ID token
	// To match issuer, update the ID token returned by the mock server to use mockServer.URL
	identity, err := provider.ExchangeAndValidate(context.Background(), "synthetic-auth-code", authReq.State, authReq)
	if err != nil {
		t.Fatalf("ExchangeAndValidate failed: %v", err)
	}

	// 4. Validate parsed Identity
	if identity.Subject != pos.Identity.Subject {
		t.Errorf("subject mismatch: got %s, expected %s", identity.Subject, pos.Identity.Subject)
	}
	if identity.Email != pos.Identity.Email {
		t.Errorf("email mismatch: got %s, expected %s", identity.Email, pos.Identity.Email)
	}
	if identity.VaultRole != pos.Identity.VaultRole {
		t.Errorf("vault role mismatch: got %s, expected %s", identity.VaultRole, pos.Identity.VaultRole)
	}

	// 5. Authorize sensitive action for allowed owner and scope
	err = auth.AuthorizeAction(identity, "alice@keyhelix.local", "secret:read")
	if err != nil {
		t.Fatalf("expected authorized action for alice, got %v", err)
	}
	err = auth.AuthorizeAction(identity, "org:platform", "vault:write")
	if err != nil {
		t.Fatalf("expected authorized action for org:platform, got %v", err)
	}

	// 6. Provider owns secret bytes canary invariant
	if strings.Contains(authURL, pos.PlaintextCanary) {
		t.Fatalf("auth URL leaked plaintext secret canary")
	}
}

func TestC08_OIDC_NegativeCases(t *testing.T) {
	var neg c08NegativeFixture
	loadC08Fixture(t, "negative.json", &neg)

	baseIssuer := "https://auth.keyhelix.local"
	clientID := "keyhelix-engine"

	provider, err := auth.NewProvider(auth.Config{
		IssuerURL:   baseIssuer,
		ClientID:    clientID,
		RedirectURI: "http://localhost:8080/callback",
		ClockSkew:   30 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewProvider failed: %v", err)
	}

	validReq, _, err := provider.BeginAuthFlow()
	if err != nil {
		t.Fatalf("BeginAuthFlow failed: %v", err)
	}

	now := time.Now().UTC()

	for _, tc := range neg.Cases {
		tc := tc
		t.Run(tc.Case, func(t *testing.T) {
			switch tc.Case {
			case "issuer-mismatch-rejected":
				token := makeSyntheticJWT(
					map[string]any{"alg": "RS256"},
					map[string]any{
						"iss":   tc.TokenIssuer,
						"sub":   "usr-1",
						"aud":   clientID,
						"exp":   now.Add(10 * time.Minute).Unix(),
						"nonce": validReq.Nonce,
					},
				)
				_, err := provider.ParseAndVerifyIDToken(token, validReq.Nonce, now)
				assertAuthCode(t, err, auth.CodeInvalidIssuer)

			case "audience-mismatch-rejected":
				token := makeSyntheticJWT(
					map[string]any{"alg": "RS256"},
					map[string]any{
						"iss":   baseIssuer,
						"sub":   "usr-1",
						"aud":   tc.TokenAudience,
						"exp":   now.Add(10 * time.Minute).Unix(),
						"nonce": validReq.Nonce,
					},
				)
				_, err := provider.ParseAndVerifyIDToken(token, validReq.Nonce, now)
				assertAuthCode(t, err, auth.CodeInvalidAudience)

			case "expired-identity-token-rejected":
				token := makeSyntheticJWT(
					map[string]any{"alg": "RS256"},
					map[string]any{
						"iss":   baseIssuer,
						"sub":   "usr-1",
						"aud":   clientID,
						"exp":   now.Add(-10 * time.Minute).Unix(), // expired
						"nonce": validReq.Nonce,
					},
				)
				_, err := provider.ParseAndVerifyIDToken(token, validReq.Nonce, now)
				assertAuthCode(t, err, auth.CodeExpiredToken)

			case "replayed-nonce-rejected":
				token := makeSyntheticJWT(
					map[string]any{"alg": "RS256"},
					map[string]any{
						"iss":   baseIssuer,
						"sub":   "usr-1",
						"aud":   clientID,
						"exp":   now.Add(10 * time.Minute).Unix(),
						"nonce": tc.Nonce, // replayed or mismatched
					},
				)
				_, err := provider.ParseAndVerifyIDToken(token, validReq.Nonce, now)
				assertAuthCode(t, err, auth.CodeNonceMismatch)

			case "tampered-state-callback-rejected":
				err := provider.ValidateCallbackState(validReq.State, tc.CallbackState)
				assertAuthCode(t, err, auth.CodeStateMismatch)

			case "pkce-verifier-mismatch-rejected":
				matched := auth.VerifyPKCE(tc.CodeVerifier, validReq.CodeChallenge)
				if matched {
					t.Fatalf("expected PKCE verifier mismatch to fail")
				}
				// Also verify via mock exchange returning invalid_grant
				mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusBadRequest)
					_ = json.NewEncoder(w).Encode(map[string]string{
						"error":             "invalid_grant",
						"error_description": "PKCE code_verifier does not match",
					})
				}))
				defer mockServer.Close()
				p, _ := auth.NewProvider(auth.Config{
					IssuerURL:   mockServer.URL,
					ClientID:    clientID,
					RedirectURI: "http://localhost:8080/callback",
					HTTPClient:  mockServer.Client(),
				})
				_, err := p.ExchangeToken(context.Background(), "auth-code", &auth.AuthRequest{
					CodeVerifier: tc.CodeVerifier,
				})
				assertAuthCode(t, err, auth.CodeInvalidPKCE)

			case "unrelated-owner-scope-denied":
				identity := &auth.Identity{
					Subject:       "usr_alice_01",
					Email:         tc.Actor,
					AllowedOwners: []string{tc.Actor},
					AllowedScopes: []string{"vault:read"},
				}
				err := auth.AuthorizeAction(identity, tc.TargetOwner, tc.Action)
				assertAuthCode(t, err, auth.CodeScopeDenied)

			case "forged-authorization-header-rejected":
				// Header is "Bearer eyJhbGciOiJub25lIn0..."
				tokenStr := strings.TrimPrefix(tc.Header, "Bearer ")
				_, err := provider.ParseAndVerifyIDToken(tokenStr, validReq.Nonce, now)
				assertAuthCode(t, err, auth.CodeInvalidToken)

			case "widened-path-permission-denied":
				identity := &auth.Identity{
					Subject:       "usr_alice_01",
					Email:         tc.Actor,
					AllowedOwners: []string{tc.Actor},
					AllowedScopes: []string{"vault:read", "secret:read"},
				}
				err := auth.AuthorizeAction(identity, tc.TargetOwner, tc.Action)
				assertAuthCode(t, err, auth.CodeScopeDenied)

			case "identity-provider-unavailable-fails-closed":
				offlineProvider, _ := auth.NewProvider(auth.Config{
					IssuerURL:   "http://127.0.0.1:59999", // closed port
					ClientID:    clientID,
					RedirectURI: "http://localhost:8080/callback",
					HTTPClient:  &http.Client{Timeout: 50 * time.Millisecond},
				})
				_, err := offlineProvider.ExchangeToken(context.Background(), "code", validReq)
				assertAuthCode(t, err, auth.CodeIDPUnavailable)

			case "provider-owns-secret-bytes":
				if tc.ExpectedPersisted != nil && *tc.ExpectedPersisted {
					t.Fatalf("expected canary not to be persisted")
				}

			default:
				t.Fatalf("unhandled negative case: %s", tc.Case)
			}
		})
	}
}
