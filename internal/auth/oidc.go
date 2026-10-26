// Package auth provides OpenID Connect (OIDC) identity provider integration and claim verification.
// It implements requirement F02: validating issuer, audience, nonce, PKCE, callback state, and resource scopes.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ErrorCode identifies a typed auth failure.
type ErrorCode string

const (
	CodeInvalidIssuer   ErrorCode = "INVALID_ISSUER"
	CodeInvalidAudience ErrorCode = "INVALID_AUDIENCE"
	CodeExpiredToken    ErrorCode = "EXPIRED_TOKEN"
	CodeNonceMismatch   ErrorCode = "NONCE_MISMATCH"
	CodeStateMismatch   ErrorCode = "STATE_MISMATCH"
	CodeInvalidPKCE     ErrorCode = "INVALID_PKCE"
	CodeScopeDenied     ErrorCode = "SCOPE_DENIED"
	CodeInvalidToken    ErrorCode = "INVALID_TOKEN"
	CodeIDPUnavailable  ErrorCode = "IDP_UNAVAILABLE"
	CodeInvalidConfig   ErrorCode = "INVALID_CONFIG"
)

// Error represents a typed failure from OIDC verification or provider communication.
type Error struct {
	Code    ErrorCode `json:"code"`
	Message string    `json:"message"`
	Err     error     `json:"-"`
}

func (e *Error) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("%s: %s", e.Code, e.Message)
	}
	return string(e.Code)
}

func (e *Error) Unwrap() error {
	return e.Err
}

// IsErrorCode checks whether err is or wraps an auth Error with the given code.
func IsErrorCode(err error, code ErrorCode) bool {
	var authErr *Error
	if errors.As(err, &authErr) {
		return authErr.Code == code
	}
	return false
}

// Config configures the OIDC client provider.
type Config struct {
	IssuerURL    string        `json:"issuer_url"`
	ClientID     string        `json:"client_id"`
	ClientSecret string        `json:"client_secret,omitempty"`
	RedirectURI  string        `json:"redirect_uri"`
	HTTPClient   *http.Client  `json:"-"`
	ClockSkew    time.Duration `json:"clock_skew,omitempty"`
}

// AuthRequest tracks ephemeral state for an in-flight authorization request.
type AuthRequest struct {
	State        string    `json:"state"`
	Nonce        string    `json:"nonce"`
	CodeVerifier string    `json:"code_verifier"`
	CodeChallenge string   `json:"code_challenge"`
	CreatedAt    time.Time `json:"created_at"`
}

// Identity represents an authenticated, verified OIDC principal.
type Identity struct {
	Subject       string   `json:"sub"`
	Email         string   `json:"email"`
	VaultRole     string   `json:"vault_role"`
	AllowedOwners []string `json:"allowed_owners"`
	AllowedScopes []string `json:"allowed_scopes"`
	Issuer        string   `json:"iss"`
	Audience      []string `json:"aud"`
	ExpiresAt     int64    `json:"exp"`
	IssuedAt      int64    `json:"iat"`
	Nonce         string   `json:"nonce"`
}

// IDTokenClaims defines the structure of claims embedded in an OIDC ID Token.
type IDTokenClaims struct {
	Issuer        string   `json:"iss"`
	Subject       string   `json:"sub"`
	Audience      any      `json:"aud"` // string or []string
	Nonce         string   `json:"nonce"`
	ExpiresAt     int64    `json:"exp"`
	IssuedAt      int64    `json:"iat"`
	Email         string   `json:"email,omitempty"`
	VaultRole     string   `json:"vault_role,omitempty"`
	AllowedOwners []string `json:"allowed_owners,omitempty"`
	AllowedScopes []string `json:"allowed_scopes,omitempty"`
}

// Audiences returns a normalized slice of audience strings.
func (c *IDTokenClaims) Audiences() []string {
	switch v := c.Audience.(type) {
	case string:
		if v != "" {
			return []string{v}
		}
		return nil
	case []any:
		var list []string
		for _, item := range v {
			if s, ok := item.(string); ok && s != "" {
				list = append(list, s)
			}
		}
		return list
	case []string:
		return v
	default:
		return nil
	}
}

// TokenResponse represents the JSON returned by the OIDC token endpoint.
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	IDToken     string `json:"id_token"`
	ExpiresIn   int    `json:"expires_in,omitempty"`
}

// Provider manages OIDC authentication flow and token validation.
type Provider struct {
	cfg Config
}

// NewProvider creates a new OIDC Provider adapter with configuration validation.
func NewProvider(cfg Config) (*Provider, error) {
	issuer := strings.TrimRight(strings.TrimSpace(cfg.IssuerURL), "/")
	if issuer == "" {
		return nil, &Error{Code: CodeInvalidConfig, Message: "issuer URL must not be empty"}
	}
	u, err := url.Parse(issuer)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, &Error{Code: CodeInvalidConfig, Message: fmt.Sprintf("invalid issuer URL %q: %v", issuer, err)}
	}

	clientID := strings.TrimSpace(cfg.ClientID)
	if clientID == "" {
		return nil, &Error{Code: CodeInvalidConfig, Message: "client ID must not be empty"}
	}

	redirectURI := strings.TrimSpace(cfg.RedirectURI)
	if redirectURI == "" {
		return nil, &Error{Code: CodeInvalidConfig, Message: "redirect URI must not be empty"}
	}

	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}

	clockSkew := cfg.ClockSkew
	if clockSkew <= 0 {
		clockSkew = 1 * time.Minute
	}

	return &Provider{
		cfg: Config{
			IssuerURL:    issuer,
			ClientID:     clientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURI:  redirectURI,
			HTTPClient:   client,
			ClockSkew:    clockSkew,
		},
	}, nil
}

// Config returns the active configuration.
func (p *Provider) Config() Config {
	return p.cfg
}

// GeneratePKCE creates a high-entropy code_verifier and the derived S256 code_challenge.
func GeneratePKCE() (verifier, challenge string, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", fmt.Errorf("failed generating random bytes: %w", err)
	}
	verifier = base64.RawURLEncoding.EncodeToString(b)
	hash := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(hash[:])
	return verifier, challenge, nil
}

// VerifyPKCE validates that the code_verifier produces the expected S256 challenge.
func VerifyPKCE(verifier, challenge string) bool {
	if verifier == "" || challenge == "" {
		return false
	}
	hash := sha256.Sum256([]byte(verifier))
	calculated := base64.RawURLEncoding.EncodeToString(hash[:])
	return subtle.ConstantTimeCompare([]byte(calculated), []byte(challenge)) == 1
}

// BeginAuthFlow initializes an authorization code flow with state, nonce, and PKCE.
// It returns the tracking AuthRequest struct and the authorization redirect URL.
func (p *Provider) BeginAuthFlow() (*AuthRequest, string, error) {
	stateBytes := make([]byte, 24)
	if _, err := rand.Read(stateBytes); err != nil {
		return nil, "", fmt.Errorf("failed generating state: %w", err)
	}
	state := hex.EncodeToString(stateBytes)

	nonceBytes := make([]byte, 24)
	if _, err := rand.Read(nonceBytes); err != nil {
		return nil, "", fmt.Errorf("failed generating nonce: %w", err)
	}
	nonce := hex.EncodeToString(nonceBytes)

	verifier, challenge, err := GeneratePKCE()
	if err != nil {
		return nil, "", err
	}

	authReq := &AuthRequest{
		State:         state,
		Nonce:         nonce,
		CodeVerifier:  verifier,
		CodeChallenge: challenge,
		CreatedAt:     time.Now().UTC(),
	}

	authURL := fmt.Sprintf("%s/authorize?response_type=code&client_id=%s&redirect_uri=%s&scope=openid+profile+email&state=%s&nonce=%s&code_challenge=%s&code_challenge_method=S256",
		p.cfg.IssuerURL,
		url.QueryEscape(p.cfg.ClientID),
		url.QueryEscape(p.cfg.RedirectURI),
		url.QueryEscape(state),
		url.QueryEscape(nonce),
		url.QueryEscape(challenge),
	)

	return authReq, authURL, nil
}

// ValidateCallbackState verifies the callback state against the expected authorization state in constant time.
func (p *Provider) ValidateCallbackState(expectedState, callbackState string) error {
	if expectedState == "" || callbackState == "" {
		return &Error{Code: CodeStateMismatch, Message: "callback state is missing"}
	}
	if subtle.ConstantTimeCompare([]byte(expectedState), []byte(callbackState)) != 1 {
		return &Error{Code: CodeStateMismatch, Message: "callback state mismatch or tampered"}
	}
	return nil
}

// ExchangeToken performs authorization code exchange with the OIDC token endpoint.
func (p *Provider) ExchangeToken(ctx context.Context, code string, authReq *AuthRequest) (*TokenResponse, error) {
	if authReq == nil {
		return nil, &Error{Code: CodeInvalidConfig, Message: "nil auth request provided"}
	}
	if code == "" {
		return nil, &Error{Code: CodeInvalidToken, Message: "empty authorization code"}
	}

	tokenURL := fmt.Sprintf("%s/token", p.cfg.IssuerURL)
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", p.cfg.RedirectURI)
	form.Set("client_id", p.cfg.ClientID)
	form.Set("code_verifier", authReq.CodeVerifier)
	if p.cfg.ClientSecret != "" {
		form.Set("client_secret", p.cfg.ClientSecret)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, &Error{Code: CodeIDPUnavailable, Message: fmt.Sprintf("failed constructing token request: %v", err), Err: err}
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := p.cfg.HTTPClient.Do(req)
	if err != nil {
		return nil, &Error{Code: CodeIDPUnavailable, Message: fmt.Sprintf("identity provider connection failed: %v", err), Err: err}
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, &Error{Code: CodeIDPUnavailable, Message: fmt.Sprintf("failed reading response from identity provider: %v", err), Err: err}
	}

	if resp.StatusCode >= 500 {
		return nil, &Error{Code: CodeIDPUnavailable, Message: fmt.Sprintf("identity provider returned status %d: %s", resp.StatusCode, string(bodyBytes))}
	}

	if resp.StatusCode != http.StatusOK {
		var errResp struct {
			Error            string `json:"error"`
			ErrorDescription string `json:"error_description"`
		}
		_ = json.Unmarshal(bodyBytes, &errResp)
		if strings.Contains(strings.ToLower(errResp.Error), "pkce") || strings.Contains(strings.ToLower(errResp.ErrorDescription), "pkce") {
			return nil, &Error{Code: CodeInvalidPKCE, Message: fmt.Sprintf("pkce verification failed at idp: %s (%s)", errResp.Error, errResp.ErrorDescription)}
		}
		return nil, &Error{Code: CodeInvalidToken, Message: fmt.Sprintf("token exchange failed (%d): %s", resp.StatusCode, string(bodyBytes))}
	}

	var tokenResp TokenResponse
	if err := json.Unmarshal(bodyBytes, &tokenResp); err != nil {
		return nil, &Error{Code: CodeIDPUnavailable, Message: fmt.Sprintf("invalid JSON from token endpoint: %v", err), Err: err}
	}

	if tokenResp.IDToken == "" {
		return nil, &Error{Code: CodeInvalidToken, Message: "identity provider response did not contain an id_token"}
	}

	return &tokenResp, nil
}

// ParseAndVerifyIDToken parses and validates a signed/encoded OIDC ID Token against expected issuer, audience, nonce, and expiration.
func (p *Provider) ParseAndVerifyIDToken(rawToken string, expectedNonce string, now time.Time) (*Identity, error) {
	if rawToken == "" {
		return nil, &Error{Code: CodeInvalidToken, Message: "empty ID token"}
	}

	parts := strings.Split(rawToken, ".")
	if len(parts) != 3 {
		return nil, &Error{Code: CodeInvalidToken, Message: "malformed ID token: must contain 3 segments"}
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, &Error{Code: CodeInvalidToken, Message: fmt.Sprintf("invalid header encoding: %v", err), Err: err}
	}

	var header struct {
		Algorithm string `json:"alg"`
		Type      string `json:"typ"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, &Error{Code: CodeInvalidToken, Message: fmt.Sprintf("malformed header json: %v", err), Err: err}
	}

	// Forged tokens using alg: "none" or empty are rejected
	if strings.ToLower(header.Algorithm) == "none" || header.Algorithm == "" {
		return nil, &Error{Code: CodeInvalidToken, Message: "unsecured algorithm 'none' or missing algorithm rejected"}
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, &Error{Code: CodeInvalidToken, Message: fmt.Sprintf("invalid payload encoding: %v", err), Err: err}
	}

	var claims IDTokenClaims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, &Error{Code: CodeInvalidToken, Message: fmt.Sprintf("malformed payload json: %v", err), Err: err}
	}

	// 1. Verify Issuer
	tokenIssuer := strings.TrimRight(strings.TrimSpace(claims.Issuer), "/")
	if tokenIssuer != p.cfg.IssuerURL {
		return nil, &Error{
			Code:    CodeInvalidIssuer,
			Message: fmt.Sprintf("token issuer %q does not match configured issuer %q", tokenIssuer, p.cfg.IssuerURL),
		}
	}

	// 2. Verify Audience
	audiences := claims.Audiences()
	audFound := false
	for _, aud := range audiences {
		if aud == p.cfg.ClientID {
			audFound = true
			break
		}
	}
	if !audFound {
		return nil, &Error{
			Code:    CodeInvalidAudience,
			Message: fmt.Sprintf("token audience %v does not contain client ID %q", audiences, p.cfg.ClientID),
		}
	}

	// 3. Verify Expiration with Clock Skew
	skew := p.cfg.ClockSkew
	if now.Unix() > claims.ExpiresAt+int64(skew.Seconds()) {
		return nil, &Error{
			Code:    CodeExpiredToken,
			Message: fmt.Sprintf("token expired at %d (current time: %d, skew allowed: %s)", claims.ExpiresAt, now.Unix(), skew),
		}
	}

	// 4. Verify Nonce (timing-safe)
	if expectedNonce != "" {
		if claims.Nonce == "" {
			return nil, &Error{Code: CodeNonceMismatch, Message: "missing nonce in token claims"}
		}
		if subtle.ConstantTimeCompare([]byte(claims.Nonce), []byte(expectedNonce)) != 1 {
			return nil, &Error{Code: CodeNonceMismatch, Message: "token nonce does not match expected nonce"}
		}
	}

	// 5. Verify Subject
	if strings.TrimSpace(claims.Subject) == "" {
		return nil, &Error{Code: CodeInvalidToken, Message: "token subject must not be empty"}
	}

	return &Identity{
		Subject:       claims.Subject,
		Email:         claims.Email,
		VaultRole:     claims.VaultRole,
		AllowedOwners: claims.AllowedOwners,
		AllowedScopes: claims.AllowedScopes,
		Issuer:        tokenIssuer,
		Audience:      audiences,
		ExpiresAt:     claims.ExpiresAt,
		IssuedAt:      claims.IssuedAt,
		Nonce:         claims.Nonce,
	}, nil
}

// ExchangeAndValidate executes the complete authorization code exchange and token verification lifecycle.
func (p *Provider) ExchangeAndValidate(ctx context.Context, code, state string, req *AuthRequest) (*Identity, error) {
	if req == nil {
		return nil, &Error{Code: CodeInvalidConfig, Message: "nil auth request provided"}
	}

	if err := p.ValidateCallbackState(req.State, state); err != nil {
		return nil, err
	}

	tokens, err := p.ExchangeToken(ctx, code, req)
	if err != nil {
		return nil, err
	}

	return p.ParseAndVerifyIDToken(tokens.IDToken, req.Nonce, time.Now().UTC())
}

// AuthorizeAction checks whether an identity is authorized to perform an action on a target resource owner and scope.
// It fails closed before any sensitive action can be executed.
func AuthorizeAction(identity *Identity, targetOwner string, targetScope string) error {
	if identity == nil {
		return &Error{Code: CodeInvalidToken, Message: "cannot authorize action with nil identity"}
	}

	// Verify Target Owner
	if targetOwner != "" {
		ownerMatch := false
		if identity.Email != "" && subtle.ConstantTimeCompare([]byte(identity.Email), []byte(targetOwner)) == 1 {
			ownerMatch = true
		} else if identity.Subject != "" && subtle.ConstantTimeCompare([]byte(identity.Subject), []byte(targetOwner)) == 1 {
			ownerMatch = true
		} else {
			for _, allowed := range identity.AllowedOwners {
				if subtle.ConstantTimeCompare([]byte(allowed), []byte(targetOwner)) == 1 {
					ownerMatch = true
					break
				}
			}
		}

		if !ownerMatch {
			return &Error{
				Code:    CodeScopeDenied,
				Message: fmt.Sprintf("identity %q is not authorized to access resources belonging to owner %q", identity.Subject, targetOwner),
			}
		}
	}

	// Verify Target Scope / Permission
	if targetScope != "" {
		scopeMatch := false
		for _, s := range identity.AllowedScopes {
			if s == "*" || s == targetScope {
				scopeMatch = true
				break
			}
			// Prefix matching for scoped permissions like "vault:*"
			if strings.HasSuffix(s, ":*") {
				prefix := strings.TrimSuffix(s, "*")
				if strings.HasPrefix(targetScope, prefix) {
					scopeMatch = true
					break
				}
			}
		}

		if !scopeMatch {
			return &Error{
				Code:    CodeScopeDenied,
				Message: fmt.Sprintf("identity %q lacks required scope %q", identity.Subject, targetScope),
			}
		}
	}

	return nil
}
