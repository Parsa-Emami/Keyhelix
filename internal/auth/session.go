// Package auth provides session binding, short-lived session token management,
// secure cookie enforcement, and immediate revocation for verified OIDC principals.
// It implements requirement F03: Revoked session cannot reveal; session cookies are secure
// and tokens are never logged.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Additional typed error codes for session and cookie enforcement.
const (
	CodeSessionNotFound ErrorCode = "SESSION_NOT_FOUND"
	CodeSessionExpired  ErrorCode = "SESSION_EXPIRED"
	CodeSessionRevoked  ErrorCode = "SESSION_REVOKED"
	CodeInvalidSession  ErrorCode = "INVALID_SESSION"
	CodeCookieInsecure  ErrorCode = "COOKIE_INSECURE"
	CodeTokenLogged     ErrorCode = "TOKEN_LOG_REJECTED"
	CodeInvalidInput    ErrorCode = "INVALID_INPUT"
)

var (
	bearerTokenRegex = regexp.MustCompile(`(?i)Bearer\s+([a-zA-Z0-9_\-\.=]+)`)
	cookieTokenRegex = regexp.MustCompile(`(keyhelix_session=)([a-zA-Z0-9_\-\.=]+)`)
)

// SessionToken represents a sensitive bearer or cookie token.
// It implements fmt.Stringer, fmt.GoStringer, and json.Marshaler
// to ensure the raw token secret is NEVER printed, formatted, or serialized into logs.
type SessionToken string

// String ensures fmt.Printf("%s") or %v outputs [REDACTED].
func (t SessionToken) String() string {
	return "[REDACTED]"
}

// GoString ensures %#v outputs [REDACTED].
func (t SessionToken) GoString() string {
	return "[REDACTED]"
}

// MarshalJSON ensures json.Marshal outputs "[REDACTED]".
func (t SessionToken) MarshalJSON() ([]byte, error) {
	return []byte(`"[REDACTED]"`), nil
}

// Plaintext returns the raw token string exclusively for authorized header/cookie delivery.
func (t SessionToken) Plaintext() string {
	return string(t)
}

// Session represents an authenticated user session cryptographically bound to a verified OIDC Identity.
type Session struct {
	mu                sync.RWMutex
	ID                string     `json:"id"`
	TokenHash         string     `json:"token_hash"` // SHA-256 hex digest of the secret session token; raw token is never stored
	Identity          *Identity  `json:"identity"`
	CreatedAt         time.Time  `json:"created_at"`
	ExpiresAt         time.Time  `json:"expires_at"`
	LastActivityAt    time.Time  `json:"last_activity_at"`
	RevokedAt         *time.Time `json:"revoked_at,omitempty"`
	RevocationReason  string     `json:"revocation_reason,omitempty"`
	ClientFingerprint string     `json:"client_fingerprint,omitempty"`
	IPAddress         string     `json:"ip_address,omitempty"`
}

// IsRevoked reports whether the session has been revoked.
func (s *Session) IsRevoked() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.RevokedAt != nil
}

// IsExpired reports whether the session has passed its expiration deadline.
func (s *Session) IsExpired(now time.Time) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return now.After(s.ExpiresAt)
}

// Revoke marks the session as revoked in a thread-safe manner.
func (s *Session) Revoke(reason string, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.RevokedAt == nil {
		s.RevokedAt = &now
		s.RevocationReason = reason
	}
}

// Touch updates the last activity timestamp in a thread-safe manner.
func (s *Session) Touch(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.LastActivityAt = now
}

// RevocationReasonString returns the revocation reason in a thread-safe manner.
func (s *Session) RevocationReasonString() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.RevocationReason
}

// Expiration returns the session expiration time in a thread-safe manner.
func (s *Session) Expiration() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.ExpiresAt
}

// String provides safe structured printing of session metadata without exposing token hashes or secrets.
func (s *Session) String() string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	status := "active"
	if s.RevokedAt != nil {
		status = "revoked"
	}
	subject := "unknown"
	if s.Identity != nil {
		subject = s.Identity.Subject
	}
	return fmt.Sprintf("Session(id=%s, subject=%s, status=%s, expires_at=%s)",
		s.ID, subject, status, s.ExpiresAt.Format(time.RFC3339))
}

// SessionConfig defines timing, cookie security, and client binding policies.
type SessionConfig struct {
	DefaultTTL   time.Duration `json:"default_ttl"`
	MaxLifetime  time.Duration `json:"max_lifetime"`
	CookieName   string        `json:"cookie_name"`
	CookiePath   string        `json:"cookie_path"`
	CookieDomain string        `json:"cookie_domain"`
	SecureCookie bool          `json:"secure_cookie"`
	SameSite     http.SameSite `json:"same_site"`
	ClockSkew    time.Duration `json:"clock_skew"`
}

// DefaultSessionConfig returns secure defaults per ADR-0001 (15-minute TTL, strict cookies).
func DefaultSessionConfig() SessionConfig {
	return SessionConfig{
		DefaultTTL:   15 * time.Minute,
		MaxLifetime:  60 * time.Minute,
		CookieName:   "keyhelix_session",
		CookiePath:   "/",
		SecureCookie: true,
		SameSite:     http.SameSiteStrictMode,
		ClockSkew:    1 * time.Minute,
	}
}

// ClientInfo captures client context used for session binding.
type ClientInfo struct {
	UserAgent string `json:"user_agent"`
	IPAddress string `json:"ip_address"`
}

// Fingerprint derives a binding digest from client context.
func (c ClientInfo) Fingerprint() string {
	if c.UserAgent == "" && c.IPAddress == "" {
		return ""
	}
	h := sha256.Sum256([]byte(fmt.Sprintf("%s|%s", c.UserAgent, c.IPAddress)))
	return hex.EncodeToString(h[:])
}

// SessionStore defines the interface for session storage and lookup.
type SessionStore interface {
	Save(ctx context.Context, session *Session) error
	GetByTokenHash(ctx context.Context, tokenHash string) (*Session, error)
	GetByID(ctx context.Context, id string) (*Session, error)
	Revoke(ctx context.Context, id string, reason string, now time.Time) error
	RevokeAllForSubject(ctx context.Context, subject string, reason string, now time.Time) (int, error)
	DeleteExpired(ctx context.Context, now time.Time) (int, error)
	ListForSubject(ctx context.Context, subject string) ([]*Session, error)
}

// MemorySessionStore provides a thread-safe in-memory session registry.
type MemorySessionStore struct {
	mu        sync.RWMutex
	byID      map[string]*Session
	byHash    map[string]*Session
	bySubject map[string]map[string]struct{}
}

// NewMemorySessionStore initializes an empty memory session store.
func NewMemorySessionStore() *MemorySessionStore {
	return &MemorySessionStore{
		byID:      make(map[string]*Session),
		byHash:    make(map[string]*Session),
		bySubject: make(map[string]map[string]struct{}),
	}
}

// Save stores a new session record indexed by ID, TokenHash, and Subject.
func (m *MemorySessionStore) Save(ctx context.Context, session *Session) error {
	if session == nil {
		return &Error{Code: CodeInvalidSession, Message: "cannot save nil session"}
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	m.byID[session.ID] = session
	m.byHash[session.TokenHash] = session

	if session.Identity != nil && session.Identity.Subject != "" {
		sub := session.Identity.Subject
		if m.bySubject[sub] == nil {
			m.bySubject[sub] = make(map[string]struct{})
		}
		m.bySubject[sub][session.ID] = struct{}{}
	}
	return nil
}

// GetByTokenHash looks up a session by the SHA-256 digest of its token.
func (m *MemorySessionStore) GetByTokenHash(ctx context.Context, tokenHash string) (*Session, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	sess, ok := m.byHash[tokenHash]
	if !ok || sess == nil {
		return nil, nil
	}
	return sess, nil
}

// GetByID looks up a session by its unique ID.
func (m *MemorySessionStore) GetByID(ctx context.Context, id string) (*Session, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	sess, ok := m.byID[id]
	if !ok || sess == nil {
		return nil, nil
	}
	return sess, nil
}

// Revoke marks a specific session as revoked immediately.
func (m *MemorySessionStore) Revoke(ctx context.Context, id string, reason string, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	sess, ok := m.byID[id]
	if !ok || sess == nil {
		return &Error{Code: CodeSessionNotFound, Message: fmt.Sprintf("session %q not found", id)}
	}

	sess.Revoke(reason, now)
	return nil
}

// RevokeAllForSubject immediately revokes every active session for a subject.
func (m *MemorySessionStore) RevokeAllForSubject(ctx context.Context, subject string, reason string, now time.Time) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	sessionIDs, ok := m.bySubject[subject]
	if !ok || len(sessionIDs) == 0 {
		return 0, nil
	}

	count := 0
	for id := range sessionIDs {
		if sess, exists := m.byID[id]; exists && sess != nil {
			if !sess.IsRevoked() {
				sess.Revoke(reason, now)
				count++
			}
		}
	}
	return count, nil
}

// DeleteExpired removes sessions whose expiration time has passed.
func (m *MemorySessionStore) DeleteExpired(ctx context.Context, now time.Time) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	count := 0
	for id, sess := range m.byID {
		if sess.IsExpired(now) {
			delete(m.byID, id)
			delete(m.byHash, sess.TokenHash)
			if sess.Identity != nil && sess.Identity.Subject != "" {
				sub := sess.Identity.Subject
				delete(m.bySubject[sub], id)
				if len(m.bySubject[sub]) == 0 {
					delete(m.bySubject, sub)
				}
			}
			count++
		}
	}
	return count, nil
}

// ListForSubject returns all sessions registered for a subject or email principal.
func (m *MemorySessionStore) ListForSubject(ctx context.Context, subject string) ([]*Session, error) {
	target := strings.TrimSpace(subject)
	if target == "" {
		return nil, nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()

	seen := make(map[string]struct{})
	var list []*Session
	if sessionIDs, ok := m.bySubject[target]; ok {
		for id := range sessionIDs {
			if sess, exists := m.byID[id]; exists && sess != nil {
				seen[id] = struct{}{}
				list = append(list, sess)
			}
		}
	}
	for id, sess := range m.byID {
		if sess == nil || sess.Identity == nil {
			continue
		}
		if _, already := seen[id]; already {
			continue
		}
		if sess.Identity.Email == target || sess.Identity.Subject == target {
			seen[id] = struct{}{}
			list = append(list, sess)
		}
	}
	return list, nil
}

// SessionManager manages session issuance, verification, cookie production, and revocation.
type SessionManager struct {
	cfg   SessionConfig
	store SessionStore
}


// NewSessionManager initializes a SessionManager with verified configuration.
func NewSessionManager(cfg SessionConfig, store SessionStore) (*SessionManager, error) {
	if cfg.DefaultTTL <= 0 {
		cfg.DefaultTTL = 15 * time.Minute
	}
	if cfg.CookieName == "" {
		cfg.CookieName = "keyhelix_session"
	}
	if cfg.CookiePath == "" {
		cfg.CookiePath = "/"
	}
	if cfg.SameSite == 0 {
		cfg.SameSite = http.SameSiteStrictMode
	}
	if store == nil {
		store = NewMemorySessionStore()
	}
	return &SessionManager{
		cfg:   cfg,
		store: store,
	}, nil
}

// Config returns the active session configuration.
func (sm *SessionManager) Config() SessionConfig {
	return sm.cfg
}

// Store returns the underlying session store.
func (sm *SessionManager) Store() SessionStore {
	return sm.store
}

// CreateSession establishes a short-lived bound session for a verified OIDC Identity.
// It returns the newly created Session and the high-entropy SessionToken secret.
func (sm *SessionManager) CreateSession(ctx context.Context, identity *Identity, client ClientInfo) (*Session, SessionToken, error) {
	if identity == nil {
		return nil, "", &Error{Code: CodeInvalidToken, Message: "cannot create session with nil identity"}
	}

	now := time.Now().UTC()
	skew := sm.cfg.ClockSkew
	if skew <= 0 {
		skew = 1 * time.Minute
	}

	// Verify that the identity token itself is not expired
	if identity.ExpiresAt > 0 && now.Unix() > identity.ExpiresAt+int64(skew.Seconds()) {
		return nil, "", &Error{
			Code:    CodeExpiredToken,
			Message: fmt.Sprintf("cannot bind session to expired identity (expired at %d)", identity.ExpiresAt),
		}
	}

	if strings.TrimSpace(identity.Subject) == "" {
		return nil, "", &Error{Code: CodeInvalidToken, Message: "identity subject must not be empty"}
	}

	// Generate high-entropy session ID
	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return nil, "", fmt.Errorf("failed generating session ID: %w", err)
	}
	sessionID := hex.EncodeToString(idBytes)

	// Generate high-entropy token secret (32 cryptographically secure random bytes)
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, "", fmt.Errorf("failed generating session token: %w", err)
	}
	rawToken := base64.RawURLEncoding.EncodeToString(tokenBytes)

	// Hash the token secret using SHA-256 before storage; the raw secret is never retained in store
	tokenHashBytes := sha256.Sum256([]byte(rawToken))
	tokenHash := hex.EncodeToString(tokenHashBytes[:])

	sess := &Session{
		ID:                sessionID,
		TokenHash:         tokenHash,
		Identity:          identity,
		CreatedAt:         now,
		ExpiresAt:         now.Add(sm.cfg.DefaultTTL),
		LastActivityAt:    now,
		ClientFingerprint: client.Fingerprint(),
		IPAddress:         client.IPAddress,
	}

	if err := sm.store.Save(ctx, sess); err != nil {
		return nil, "", err
	}

	return sess, SessionToken(rawToken), nil
}

// ValidateSessionToken looks up a session by token secret, timing-safely checks revocation and expiration,
// and enforces client fingerprint invariants.
func (sm *SessionManager) ValidateSessionToken(ctx context.Context, rawToken string, client ClientInfo) (*Session, error) {
	trimmed := strings.TrimSpace(rawToken)
	if trimmed == "" {
		return nil, &Error{Code: CodeSessionNotFound, Message: "missing or empty session token"}
	}

	tokenHashBytes := sha256.Sum256([]byte(trimmed))
	tokenHash := hex.EncodeToString(tokenHashBytes[:])

	sess, err := sm.store.GetByTokenHash(ctx, tokenHash)
	if err != nil {
		return nil, err
	}
	if sess == nil {
		return nil, &Error{Code: CodeSessionNotFound, Message: "session not found or invalid token"}
	}

	// 1. Immediate revocation check: Revoked session fails closed immediately
	if sess.IsRevoked() {
		return nil, &Error{
			Code:    CodeSessionRevoked,
			Message: fmt.Sprintf("session %s was revoked (%s)", sess.ID, sess.RevocationReasonString()),
		}
	}

	// 2. Expiration check: Expired session fails closed
	now := time.Now().UTC()
	if sess.IsExpired(now) {
		return nil, &Error{
			Code:    CodeSessionExpired,
			Message: fmt.Sprintf("session %s expired at %s", sess.ID, sess.Expiration().Format(time.RFC3339)),
		}
	}

	// 3. Client binding check: Fingerprint mismatch fails closed
	if sess.ClientFingerprint != "" && client.Fingerprint() != "" {
		if subtle.ConstantTimeCompare([]byte(sess.ClientFingerprint), []byte(client.Fingerprint())) != 1 {
			return nil, &Error{Code: CodeInvalidSession, Message: "client fingerprint mismatch"}
		}
	}

	sess.Touch(now)
	return sess, nil
}

// RevokeSession revokes a specific session by its ID.
func (sm *SessionManager) RevokeSession(ctx context.Context, sessionID, reason string) error {
	if strings.TrimSpace(sessionID) == "" {
		return &Error{Code: CodeInvalidInput, Message: "session ID must not be empty"}
	}
	return sm.store.Revoke(ctx, sessionID, reason, time.Now().UTC())
}

// RevokeAllForSubject revokes all active sessions for a subject (e.g., departing user).
func (sm *SessionManager) RevokeAllForSubject(ctx context.Context, subject, reason string) (int, error) {
	if strings.TrimSpace(subject) == "" {
		return 0, &Error{Code: CodeInvalidInput, Message: "subject must not be empty"}
	}
	return sm.store.RevokeAllForSubject(ctx, subject, reason, time.Now().UTC())
}

// BuildSessionCookie creates a secure http.Cookie with mandatory HttpOnly, Secure, and SameSite flags.
func (sm *SessionManager) BuildSessionCookie(token SessionToken, expiresAt time.Time) (*http.Cookie, error) {
	if !sm.cfg.SecureCookie {
		return nil, &Error{
			Code:    CodeCookieInsecure,
			Message: "refusing to build insecure cookie: SecureCookie configuration must be enabled",
		}
	}

	maxAge := int(time.Until(expiresAt).Seconds())
	if maxAge < 0 {
		maxAge = 0
	}

	cookie := &http.Cookie{
		Name:     sm.cfg.CookieName,
		Value:    token.Plaintext(),
		Path:     sm.cfg.CookiePath,
		Domain:   sm.cfg.CookieDomain,
		Expires:  expiresAt,
		MaxAge:   maxAge,
		Secure:   true,
		HttpOnly: true,
		SameSite: sm.cfg.SameSite,
	}

	if err := ValidateCookieSecurity(cookie); err != nil {
		return nil, err
	}

	return cookie, nil
}

// BuildRevocationCookie returns an expired cookie configured to clear the client's session cookie.
func (sm *SessionManager) BuildRevocationCookie() *http.Cookie {
	return &http.Cookie{
		Name:     sm.cfg.CookieName,
		Value:    "",
		Path:     sm.cfg.CookiePath,
		Domain:   sm.cfg.CookieDomain,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		Secure:   sm.cfg.SecureCookie,
		HttpOnly: true,
		SameSite: sm.cfg.SameSite,
	}
}

// ValidateCookieSecurity validates that an http.Cookie satisfies essential security invariants.
func ValidateCookieSecurity(cookie *http.Cookie) error {
	if cookie == nil {
		return &Error{Code: CodeCookieInsecure, Message: "cookie must not be nil"}
	}
	if !cookie.HttpOnly {
		return &Error{Code: CodeCookieInsecure, Message: "cookie must have HttpOnly=true"}
	}
	if !cookie.Secure {
		return &Error{Code: CodeCookieInsecure, Message: "cookie must have Secure=true"}
	}
	if cookie.SameSite != http.SameSiteStrictMode && cookie.SameSite != http.SameSiteLaxMode {
		return &Error{Code: CodeCookieInsecure, Message: "cookie must have SameSite=Strict or SameSite=Lax"}
	}
	return nil
}

// ExtractSessionToken extracts the session token from an http.Request.
// It checks the Authorization: Bearer header first, falling back to the session cookie.
func (sm *SessionManager) ExtractSessionToken(r *http.Request) (string, error) {
	if r == nil {
		return "", &Error{Code: CodeSessionNotFound, Message: "nil request"}
	}

	// 1. Check Authorization: Bearer <token>
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" {
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
			token := strings.TrimSpace(parts[1])
			if token != "" {
				return token, nil
			}
		}
	}

	// 2. Fall back to Cookie
	cookie, err := r.Cookie(sm.cfg.CookieName)
	if err == nil && cookie != nil && strings.TrimSpace(cookie.Value) != "" {
		return strings.TrimSpace(cookie.Value), nil
	}

	return "", &Error{Code: CodeSessionNotFound, Message: "no session token found in Authorization header or cookie"}
}

// AuthorizeSessionAction enforces that the session is active, unrevoked, unexpired, and authorized
// for the target resource owner and scope.
// It strictly implements: "Revoked session cannot reveal".
func AuthorizeSessionAction(session *Session, targetOwner, targetScope string) error {
	if session == nil {
		return &Error{Code: CodeInvalidSession, Message: "cannot authorize action with nil session"}
	}

	// Revoked session check: MUST fail closed immediately
	if session.IsRevoked() {
		return &Error{
			Code:    CodeSessionRevoked,
			Message: fmt.Sprintf("revoked session %s cannot reveal or authorize actions (%s)", session.ID, session.RevocationReasonString()),
		}
	}

	// Expiry check: MUST fail closed
	if session.IsExpired(time.Now().UTC()) {
		return &Error{
			Code:    CodeSessionExpired,
			Message: fmt.Sprintf("expired session %s cannot authorize actions", session.ID),
		}
	}

	if session.Identity == nil {
		return &Error{Code: CodeInvalidToken, Message: "session carries nil identity"}
	}

	return AuthorizeAction(session.Identity, targetOwner, targetScope)
}

// SanitizeLogMessage scrubs sensitive tokens from log messages or error traces.
func SanitizeLogMessage(msg string) string {
	sanitized := bearerTokenRegex.ReplaceAllString(msg, "Bearer [REDACTED]")
	sanitized = cookieTokenRegex.ReplaceAllString(sanitized, "${1}[REDACTED]")
	return sanitized
}
