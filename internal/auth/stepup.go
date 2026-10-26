// Package auth provides step-up reauthentication, short-lived privilege elevation,
// cryptographic session binding, and sensitive action authorization.
// It implements requirement F04: Expired step-up cannot authorize reveal or policy changes
// and cannot be reused across session binding.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Typed error codes for step-up reauthentication.
const (
	CodeStepUpRequired        ErrorCode = "STEPUP_REQUIRED"
	CodeStepUpExpired         ErrorCode = "STEPUP_EXPIRED"
	CodeStepUpSessionMismatch ErrorCode = "STEPUP_SESSION_MISMATCH"
	CodeStepUpInvalid         ErrorCode = "INVALID_STEPUP"
	CodeStepUpScopeDenied     ErrorCode = "STEPUP_SCOPE_DENIED"
)

var (
	stepUpHeaderRegex = regexp.MustCompile(`(?i)StepUp\s+([a-zA-Z0-9_\-\.=]+)`)
	stepUpParamRegex  = regexp.MustCompile(`(?i)(stepup[_-]?token[=:\s]+)([a-zA-Z0-9_\-\.=]+)`)
)

// SensitiveAction identifies high-risk operations requiring fresh step-up authentication.
type SensitiveAction string

const (
	ActionRevealSecret SensitiveAction = "reveal_secret"
	ActionPolicyChange SensitiveAction = "policy_change"
	ActionVaultWrite   SensitiveAction = "vault_write"
)

// StepUpToken represents a sensitive temporary privilege elevation token secret.
// It implements fmt.Stringer, fmt.GoStringer, and json.Marshaler
// to ensure the raw secret is NEVER printed, formatted, or serialized into logs.
type StepUpToken string

// String ensures fmt.Printf("%s") or %v outputs [REDACTED].
func (t StepUpToken) String() string {
	return "[REDACTED]"
}

// GoString ensures %#v outputs [REDACTED].
func (t StepUpToken) GoString() string {
	return "[REDACTED]"
}

// MarshalJSON ensures json.Marshal outputs "[REDACTED]".
func (t StepUpToken) MarshalJSON() ([]byte, error) {
	return []byte(`"[REDACTED]"`), nil
}

// Plaintext returns the raw token string exclusively for authorized transmission.
func (t StepUpToken) Plaintext() string {
	return string(t)
}

// StepUpGrant represents a verified privilege elevation grant strictly bound to a session.
type StepUpGrant struct {
	mu         sync.RWMutex
	ID         string          `json:"id"`
	TokenHash  string          `json:"token_hash"` // SHA-256 hex digest of the raw step-up token
	SessionID  string          `json:"session_id"` // Cryptographically bound to session.ID
	Subject    string          `json:"subject"`    // Bound to identity.Subject
	Action     SensitiveAction `json:"action"`     // Authorized sensitive action
	Resource   string          `json:"resource"`   // Target secret or policy path (* for broad scope)
	CreatedAt  time.Time       `json:"created_at"`
	ExpiresAt  time.Time       `json:"expires_at"` // Maximum 120s TTL
	Consumed   bool            `json:"consumed"`
	ConsumedAt *time.Time      `json:"consumed_at,omitempty"`
}

// IsExpired reports whether the grant has passed its expiration deadline.
func (g *StepUpGrant) IsExpired(now time.Time) bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return now.After(g.ExpiresAt)
}

// MatchesSession checks whether the grant is bound to the given session and subject in constant time.
func (g *StepUpGrant) MatchesSession(sessionID, subject string) bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	if subtle.ConstantTimeCompare([]byte(g.SessionID), []byte(sessionID)) != 1 {
		return false
	}
	if subtle.ConstantTimeCompare([]byte(g.Subject), []byte(subject)) != 1 {
		return false
	}
	return true
}

// MatchesScope checks whether the grant authorizes the requested action and resource.
func (g *StepUpGrant) MatchesScope(action SensitiveAction, resource string) bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	if g.Action != "" && g.Action != action {
		return false
	}
	if g.Resource == "*" || g.Resource == "" || resource == "" {
		return true
	}
	return subtle.ConstantTimeCompare([]byte(g.Resource), []byte(resource)) == 1
}

// Consume marks a single-use grant as consumed.
func (g *StepUpGrant) Consume(now time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.Consumed = true
	g.ConsumedAt = &now
}

// IsConsumed reports whether the grant has already been used.
func (g *StepUpGrant) IsConsumed() bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.Consumed
}

// Expiration returns the expiration time under read lock.
func (g *StepUpGrant) Expiration() time.Time {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.ExpiresAt
}

// String provides safe structured printing of step-up metadata without exposing token hashes or secrets.
func (g *StepUpGrant) String() string {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return fmt.Sprintf("StepUpGrant(id=%s, session_id=%s, subject=%s, action=%s, expires_at=%s)",
		g.ID, g.SessionID, g.Subject, g.Action, g.ExpiresAt.Format(time.RFC3339))
}

// StepUpConfig defines timing and lifetime policies for step-up reauthentication.
type StepUpConfig struct {
	DefaultTTL time.Duration `json:"default_ttl"` // 120 seconds per ADR-0001
	SingleUse  bool          `json:"single_use"`
	ClockSkew  time.Duration `json:"clock_skew"`
}

// DefaultStepUpConfig returns standard production defaults (120-second TTL).
func DefaultStepUpConfig() StepUpConfig {
	return StepUpConfig{
		DefaultTTL: 120 * time.Second,
		SingleUse:  false,
		ClockSkew:  10 * time.Second,
	}
}

// StepUpStore defines the interface for persisting and looking up step-up grants.
type StepUpStore interface {
	Save(ctx context.Context, grant *StepUpGrant) error
	GetByTokenHash(ctx context.Context, tokenHash string) (*StepUpGrant, error)
	GetByID(ctx context.Context, id string) (*StepUpGrant, error)
	Revoke(ctx context.Context, id string) error
	RevokeAllForSession(ctx context.Context, sessionID string) (int, error)
	DeleteExpired(ctx context.Context, now time.Time) (int, error)
}

// MemoryStepUpStore provides a thread-safe in-memory step-up grant registry.
type MemoryStepUpStore struct {
	mu        sync.RWMutex
	byID      map[string]*StepUpGrant
	byHash    map[string]*StepUpGrant
	bySession map[string]map[string]struct{}
}

// NewMemoryStepUpStore initializes an empty memory step-up store.
func NewMemoryStepUpStore() *MemoryStepUpStore {
	return &MemoryStepUpStore{
		byID:      make(map[string]*StepUpGrant),
		byHash:    make(map[string]*StepUpGrant),
		bySession: make(map[string]map[string]struct{}),
	}
}

// Save stores a new step-up grant indexed by ID, TokenHash, and SessionID.
func (m *MemoryStepUpStore) Save(ctx context.Context, grant *StepUpGrant) error {
	if grant == nil {
		return &Error{Code: CodeStepUpInvalid, Message: "cannot save nil step-up grant"}
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	m.byID[grant.ID] = grant
	m.byHash[grant.TokenHash] = grant

	if grant.SessionID != "" {
		if m.bySession[grant.SessionID] == nil {
			m.bySession[grant.SessionID] = make(map[string]struct{})
		}
		m.bySession[grant.SessionID][grant.ID] = struct{}{}
	}
	return nil
}

// GetByTokenHash looks up a grant by the SHA-256 digest of its token secret.
func (m *MemoryStepUpStore) GetByTokenHash(ctx context.Context, tokenHash string) (*StepUpGrant, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	grant, ok := m.byHash[tokenHash]
	if !ok || grant == nil {
		return nil, nil
	}
	return grant, nil
}

// GetByID looks up a grant by its unique ID.
func (m *MemoryStepUpStore) GetByID(ctx context.Context, id string) (*StepUpGrant, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	grant, ok := m.byID[id]
	if !ok || grant == nil {
		return nil, nil
	}
	return grant, nil
}

// Revoke removes a specific grant immediately.
func (m *MemoryStepUpStore) Revoke(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	grant, ok := m.byID[id]
	if !ok || grant == nil {
		return &Error{Code: CodeStepUpInvalid, Message: fmt.Sprintf("step-up grant %q not found", id)}
	}

	delete(m.byID, id)
	delete(m.byHash, grant.TokenHash)
	if grant.SessionID != "" && m.bySession[grant.SessionID] != nil {
		delete(m.bySession[grant.SessionID], id)
	}
	return nil
}

// RevokeAllForSession invalidates all step-up grants associated with a session ID.
func (m *MemoryStepUpStore) RevokeAllForSession(ctx context.Context, sessionID string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	grantIDs, ok := m.bySession[sessionID]
	if !ok || len(grantIDs) == 0 {
		return 0, nil
	}

	count := 0
	for id := range grantIDs {
		if grant, exists := m.byID[id]; exists && grant != nil {
			delete(m.byID, id)
			delete(m.byHash, grant.TokenHash)
			count++
		}
	}
	delete(m.bySession, sessionID)
	return count, nil
}

// DeleteExpired removes grants whose expiration time has passed.
func (m *MemoryStepUpStore) DeleteExpired(ctx context.Context, now time.Time) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	count := 0
	for id, grant := range m.byID {
		if grant.IsExpired(now) {
			delete(m.byID, id)
			delete(m.byHash, grant.TokenHash)
			if grant.SessionID != "" && m.bySession[grant.SessionID] != nil {
				delete(m.bySession[grant.SessionID], id)
				if len(m.bySession[grant.SessionID]) == 0 {
					delete(m.bySession, grant.SessionID)
				}
			}
			count++
		}
	}
	return count, nil
}

// StepUpManager orchestrates step-up grant issuance, expiration, session binding, and validation.
type StepUpManager struct {
	cfg   StepUpConfig
	store StepUpStore
}

// NewStepUpManager initializes a StepUpManager with verified configuration.
func NewStepUpManager(cfg StepUpConfig, store StepUpStore) (*StepUpManager, error) {
	if cfg.DefaultTTL <= 0 {
		cfg.DefaultTTL = 120 * time.Second
	}
	if store == nil {
		store = NewMemoryStepUpStore()
	}
	return &StepUpManager{
		cfg:   cfg,
		store: store,
	}, nil
}

// Config returns the active step-up configuration.
func (sm *StepUpManager) Config() StepUpConfig {
	return sm.cfg
}

// Store returns the underlying store.
func (sm *StepUpManager) Store() StepUpStore {
	return sm.store
}

// IssueGrant issues a short-lived (120s) step-up grant strictly bound to the provided session.
// It returns the newly created StepUpGrant and the high-entropy StepUpToken secret.
func (sm *StepUpManager) IssueGrant(ctx context.Context, session *Session, action SensitiveAction, resource string) (*StepUpGrant, StepUpToken, error) {
	if session == nil {
		return nil, "", &Error{Code: CodeInvalidSession, Message: "cannot issue step-up grant for nil session"}
	}
	if session.IsRevoked() {
		return nil, "", &Error{Code: CodeSessionRevoked, Message: "cannot issue step-up grant for revoked session"}
	}
	now := time.Now().UTC()
	if session.IsExpired(now) {
		return nil, "", &Error{Code: CodeSessionExpired, Message: "cannot issue step-up grant for expired session"}
	}
	if session.Identity == nil || strings.TrimSpace(session.Identity.Subject) == "" {
		return nil, "", &Error{Code: CodeInvalidToken, Message: "session carries invalid identity subject"}
	}

	// Generate high-entropy grant ID
	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return nil, "", fmt.Errorf("failed generating grant ID: %w", err)
	}
	grantID := hex.EncodeToString(idBytes)

	// Generate high-entropy step-up token secret (32 random bytes url-safe base64)
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, "", fmt.Errorf("failed generating step-up token: %w", err)
	}
	rawToken := base64.RawURLEncoding.EncodeToString(tokenBytes)

	// Hash the token secret with SHA-256 before storage; the raw secret is never retained in store
	tokenHashBytes := sha256.Sum256([]byte(rawToken))
	tokenHash := hex.EncodeToString(tokenHashBytes[:])

	grant := &StepUpGrant{
		ID:        grantID,
		TokenHash: tokenHash,
		SessionID: session.ID,
		Subject:   session.Identity.Subject,
		Action:    action,
		Resource:  resource,
		CreatedAt: now,
		ExpiresAt: now.Add(sm.cfg.DefaultTTL),
	}

	if err := sm.store.Save(ctx, grant); err != nil {
		return nil, "", err
	}

	return grant, StepUpToken(rawToken), nil
}

// ValidateStepUp validates that a step-up token is valid, unexpired, bound to the specified session,
// and authorizes the requested action and resource scope.
// It strictly implements: "Expired step-up cannot authorize reveal or policy changes and cannot be reused across session binding."
func (sm *StepUpManager) ValidateStepUp(ctx context.Context, session *Session, rawToken string, action SensitiveAction, resource string) (*StepUpGrant, error) {
	if session == nil {
		return nil, &Error{Code: CodeInvalidSession, Message: "cannot validate step-up with nil session"}
	}
	if session.IsRevoked() {
		return nil, &Error{Code: CodeSessionRevoked, Message: "session is revoked; step-up authorization refused"}
	}
	now := time.Now().UTC()
	if session.IsExpired(now) {
		return nil, &Error{Code: CodeSessionExpired, Message: "session is expired; step-up authorization refused"}
	}

	trimmed := strings.TrimSpace(rawToken)
	if trimmed == "" {
		return nil, &Error{
			Code:    CodeStepUpRequired,
			Message: fmt.Sprintf("action %q requires fresh step-up reauthentication", action),
		}
	}

	tokenHashBytes := sha256.Sum256([]byte(trimmed))
	tokenHash := hex.EncodeToString(tokenHashBytes[:])

	grant, err := sm.store.GetByTokenHash(ctx, tokenHash)
	if err != nil {
		return nil, err
	}
	if grant == nil {
		return nil, &Error{Code: CodeStepUpInvalid, Message: "invalid or forged step-up token"}
	}

	// 1. Session Binding Invariant: Step-up CANNOT be reused across session binding
	subject := ""
	if session.Identity != nil {
		subject = session.Identity.Subject
	}
	if !grant.MatchesSession(session.ID, subject) {
		return nil, &Error{
			Code: CodeStepUpSessionMismatch,
			Message: fmt.Sprintf("step-up grant %s was issued for session %s (subject %s); cannot be reused in session %s (subject %s)",
				grant.ID, grant.SessionID, grant.Subject, session.ID, subject),
		}
	}

	// 2. Expiration Invariant: Expired step-up CANNOT authorize reveal or policy changes
	if grant.IsExpired(now) {
		return nil, &Error{
			Code:    CodeStepUpExpired,
			Message: fmt.Sprintf("step-up grant %s expired at %s; fresh reauthentication required", grant.ID, grant.Expiration().Format(time.RFC3339)),
		}
	}

	// 3. Single-use check if enabled
	if sm.cfg.SingleUse && grant.IsConsumed() {
		return nil, &Error{
			Code:    CodeStepUpExpired,
			Message: fmt.Sprintf("single-use step-up grant %s has already been consumed", grant.ID),
		}
	}

	// 4. Action and Resource Scope Invariant
	if !grant.MatchesScope(action, resource) {
		return nil, &Error{
			Code: CodeStepUpScopeDenied,
			Message: fmt.Sprintf("step-up grant %s (action=%s, resource=%s) does not authorize action %q on resource %q",
				grant.ID, grant.Action, grant.Resource, action, resource),
		}
	}

	if sm.cfg.SingleUse {
		grant.Consume(now)
	}

	return grant, nil
}

// RevokeAllForSession invalidates all step-up grants associated with a session.
func (sm *StepUpManager) RevokeAllForSession(ctx context.Context, sessionID string) (int, error) {
	if strings.TrimSpace(sessionID) == "" {
		return 0, &Error{Code: CodeInvalidInput, Message: "session ID must not be empty"}
	}
	return sm.store.RevokeAllForSession(ctx, sessionID)
}

// AuthorizeSensitiveAction enforces combined session and step-up authorization for high-risk operations.
// It verifies:
// 1. Session is active, unrevoked, unexpired, and authorized for owner and targetScope.
// 2. Fresh, unexpired step-up grant matching the session binding and target resource is presented.
func AuthorizeSensitiveAction(
	ctx context.Context,
	stepUpMgr *StepUpManager,
	session *Session,
	stepUpToken string,
	targetOwner string,
	targetScope string,
	action SensitiveAction,
	targetResource string,
) error {
	// First enforce session authorization (owner, scope, not revoked, not expired)
	if err := AuthorizeSessionAction(session, targetOwner, targetScope); err != nil {
		return err
	}

	// Step-up manager must be configured for sensitive actions
	if stepUpMgr == nil {
		return &Error{Code: CodeInvalidConfig, Message: "step-up manager is required for sensitive actions"}
	}

	// Enforce fresh step-up authorization
	_, err := stepUpMgr.ValidateStepUp(ctx, session, stepUpToken, action, targetResource)
	return err
}

// SanitizeStepUpLogMessage scrubs step-up tokens in addition to bearer and cookie tokens.
func SanitizeStepUpLogMessage(msg string) string {
	sanitized := SanitizeLogMessage(msg)
	sanitized = stepUpHeaderRegex.ReplaceAllString(sanitized, "StepUp [REDACTED]")
	sanitized = stepUpParamRegex.ReplaceAllString(sanitized, "${1}[REDACTED]")
	return sanitized
}
