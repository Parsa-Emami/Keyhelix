// Package auth provides identity-to-provider scope mapping and anti-path-manipulation defenses.
// It implements requirement F05: Server-side path manipulation cannot widen effective provider permissions.
package auth

import (
	"context"
	"crypto/subtle"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// Additional typed error codes for path validation and anti-manipulation.
const (
	CodeInvalidPath   ErrorCode = "INVALID_PATH"
	CodePathTraversal ErrorCode = "PATH_TRAVERSAL"
)

// Suspicious request headers commonly used in proxy/server-side path override attacks.
var suspiciousHeaders = []string{
	"X-Original-URL",
	"X-Rewrite-URL",
	"X-Forwarded-Prefix",
	"X-Vault-Path",
	"X-Provider-Scope",
	"X-User-Role",
	"X-Remote-User",
	"X-Effective-Scope",
}

// PathScope defines an authorized resource path pattern bound to a vault.
type PathScope struct {
	VaultID string   `json:"vault_id"`
	Path    string   `json:"path"`
	Actions []string `json:"actions"`
}

// EffectiveProviderScope represents the verified, bounded provider capability
// granted to interact with key and secret provider backends.
// Plaintext secret bytes are owned exclusively by the provider and are never held here (Requirement F05).
type EffectiveProviderScope struct {
	VaultID        string   `json:"vault_id"`
	CanonicalPath  string   `json:"canonical_path"`
	KEKID          string   `json:"kek_id"`
	ProviderMount  string   `json:"provider_mount"`
	ProviderRole   string   `json:"provider_role"`
	ProviderScopes []string `json:"provider_scopes"` // e.g. ["transit:decrypt"] or ["transit:encrypt"]
	Owner          string   `json:"owner"`
	Subject        string   `json:"subject"`
	Action         string   `json:"action"`
}

// NormalizePath validates and canonicalizes a resource secret path.
// It strictly refuses directory traversal, null bytes, backslashes,
// and double-encoded evasion sequences, returning a clean relative path (Requirement F05).
func NormalizePath(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", &Error{Code: CodeInvalidPath, Message: "secret path must not be empty"}
	}
	if utf8.RuneCountInString(trimmed) > 1024 {
		return "", &Error{Code: CodeInvalidPath, Message: "secret path exceeds 1024 runes"}
	}

	// Reject raw null byte injection
	if strings.Contains(trimmed, "\x00") || strings.Contains(trimmed, "%00") {
		return "", &Error{Code: CodeInvalidPath, Message: "path contains null bytes"}
	}

	// Reject raw backslashes to prevent cross-platform separator evasion
	if strings.Contains(trimmed, "\\") {
		return "", &Error{Code: CodeInvalidPath, Message: "backslashes in secret path are forbidden"}
	}

	// URL-decode if encoded
	candidate := trimmed
	if strings.Contains(trimmed, "%") {
		unescaped, err := url.PathUnescape(trimmed)
		if err != nil {
			return "", &Error{Code: CodeInvalidPath, Message: "malformed url-encoded path", Err: err}
		}
		if strings.Contains(unescaped, "\x00") {
			return "", &Error{Code: CodeInvalidPath, Message: "path contains unescaped null byte"}
		}
		if strings.Contains(unescaped, "\\") {
			return "", &Error{Code: CodeInvalidPath, Message: "unescaped backslash in secret path"}
		}

		// Double-encoding inspection
		if strings.Contains(unescaped, "%") {
			second, err := url.PathUnescape(unescaped)
			if err == nil && second != unescaped {
				if strings.Contains(second, "..") || strings.Contains(second, "\x00") || strings.Contains(second, "/") {
					return "", &Error{Code: CodePathTraversal, Message: "double-encoded path traversal attempt detected"}
				}
			}
		}

		candidate = unescaped
	}

	// Split by '/' and validate individual path segments
	rawSegments := strings.Split(candidate, "/")
	var cleanSegments []string

	for _, seg := range rawSegments {
		s := strings.TrimSpace(seg)
		if s == "" {
			// Collapse redundant slashes
			continue
		}
		if strings.Trim(s, ".") == "" {
			return "", &Error{
				Code:    CodePathTraversal,
				Message: "directory traversal or dot segment forbidden in secret path",
			}
		}

		// Segment level checks: check for control characters
		for _, r := range s {
			if r < 32 || r == 127 {
				return "", &Error{Code: CodeInvalidPath, Message: "control characters in path segment forbidden"}
			}
		}

		cleanSegments = append(cleanSegments, s)
	}

	if len(cleanSegments) == 0 {
		return "", &Error{Code: CodeInvalidPath, Message: "path resolves to empty target"}
	}

	canonical := strings.Join(cleanSegments, "/")
	if utf8.RuneCountInString(canonical) > 1024 {
		return "", &Error{Code: CodeInvalidPath, Message: "canonical path exceeds 1024 runes"}
	}

	return canonical, nil
}

// MatchPathScope checks whether a canonical target path matches a pattern.
// It strictly respects segment boundaries:
// "app/prod" or "app/prod/*" will NOT match "app/prod-secret" or "app/production" (Requirement F05).
func MatchPathScope(pattern, targetPath string) bool {
	p := strings.Trim(strings.TrimSpace(pattern), "/")
	t := strings.Trim(strings.TrimSpace(targetPath), "/")

	if p == "*" || p == "**" {
		return true
	}
	if p == "" || t == "" {
		return p == t
	}
	if subtle.ConstantTimeCompare([]byte(p), []byte(t)) == 1 {
		return true
	}

	pSegs := strings.Split(p, "/")
	tSegs := strings.Split(t, "/")

	// Check wildcard suffix: e.g., "app/prod/*" or "app/prod/**"
	if len(pSegs) > 0 && (pSegs[len(pSegs)-1] == "*" || pSegs[len(pSegs)-1] == "**") {
		prefixSegs := pSegs[:len(pSegs)-1]
		if len(tSegs) < len(prefixSegs) {
			return false
		}
		for i, prefix := range prefixSegs {
			if prefix == "*" {
				continue
			}
			if subtle.ConstantTimeCompare([]byte(prefix), []byte(tSegs[i])) != 1 {
				return false
			}
		}
		return true
	}

	// Exact segment count with segment-level wildcards
	if len(pSegs) == len(tSegs) {
		for i := range pSegs {
			if pSegs[i] == "*" {
				continue
			}
			if subtle.ConstantTimeCompare([]byte(pSegs[i]), []byte(tSegs[i])) != 1 {
				return false
			}
		}
		return true
	}

	return false
}

// ValidateRequestHeaders inspects HTTP headers for forged override headers
// such as X-Original-URL, X-Rewrite-URL, X-Vault-Path, X-Provider-Scope, etc.
// It fails closed before authorization if any forged override header is present.
func ValidateRequestHeaders(headers http.Header) error {
	if headers == nil {
		return nil
	}
	for _, h := range suspiciousHeaders {
		if val := headers.Get(h); strings.TrimSpace(val) != "" {
			return &Error{
				Code:    CodeScopeDenied,
				Message: fmt.Sprintf("forged or override header %q is forbidden", h),
			}
		}
	}
	return nil
}

// ScopeMapperConfig defines vault bindings and provider settings.
type ScopeMapperConfig struct {
	VaultKEKMap   map[string]string `json:"vault_kek_map"`
	VaultMountMap map[string]string `json:"vault_mount_map"`
	VaultRoleMap  map[string]string `json:"vault_role_map"`
}

// DefaultScopeMapperConfig returns the standard vault and provider mappings.
func DefaultScopeMapperConfig() ScopeMapperConfig {
	return ScopeMapperConfig{
		VaultKEKMap: map[string]string{
			"vault-prod": "kek-v1-openbao",
			"vault-dev":  "kek-v1-dev",
		},
		VaultMountMap: map[string]string{
			"vault-prod": "transit",
			"vault-dev":  "transit",
		},
		VaultRoleMap: map[string]string{
			"vault-prod": "vault-admin",
			"vault-dev":  "vault-developer",
		},
	}
}

// ScopeMapper maps authenticated user identities and step-up privileges
// to strictly bounded provider scopes, ensuring that server-side path manipulation
// cannot widen effective provider permissions.
type ScopeMapper struct {
	mu           sync.RWMutex
	vaultKEKMap  map[string]string
	vaultMount   map[string]string
	vaultRoleMap map[string]string
	idpOnline    bool
}

// NewScopeMapper creates and initializes a ScopeMapper.
func NewScopeMapper(cfg ScopeMapperConfig) *ScopeMapper {
	kekMap := make(map[string]string)
	mountMap := make(map[string]string)
	roleMap := make(map[string]string)

	for k, v := range cfg.VaultKEKMap {
		kekMap[k] = v
	}
	for k, v := range cfg.VaultMountMap {
		mountMap[k] = v
	}
	for k, v := range cfg.VaultRoleMap {
		roleMap[k] = v
	}

	return &ScopeMapper{
		vaultKEKMap:  kekMap,
		vaultMount:   mountMap,
		vaultRoleMap: roleMap,
		idpOnline:    true,
	}
}

// SetIDPOnline controls the simulated availability state of the identity provider.
func (m *ScopeMapper) SetIDPOnline(online bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.idpOnline = online
}

// IsIDPOnline reports whether the identity provider is reachable.
func (m *ScopeMapper) IsIDPOnline() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.idpOnline
}

// MapUserToProviderScope validates user identity, session, step-up privilege,
// canonicalizes target secret path, and maps to strictly bounded provider scopes.
// Server-side path manipulation cannot widen effective provider permissions (Requirement F05).
func (m *ScopeMapper) MapUserToProviderScope(
	ctx context.Context,
	identity *Identity,
	session *Session,
	stepUpGrant *StepUpGrant,
	vaultID string,
	rawSecretPath string,
	targetOwner string,
	action string,
	headers http.Header,
) (*EffectiveProviderScope, error) {
	// 1. Guard: Check Identity Provider Availability
	if !m.IsIDPOnline() {
		return nil, &Error{
			Code:    CodeIDPUnavailable,
			Message: "identity provider is offline or unreachable",
		}
	}

	// 2. Guard: Forged or Override Headers
	if err := ValidateRequestHeaders(headers); err != nil {
		return nil, err
	}

	// 3. Guard: Validate Identity presence and expiration
	if identity == nil {
		return nil, &Error{
			Code:    CodeInvalidToken,
			Message: "cannot map provider scope for nil identity",
		}
	}
	now := time.Now().UTC()
	if identity.ExpiresAt > 0 && now.Unix() > identity.ExpiresAt {
		return nil, &Error{
			Code:    CodeExpiredToken,
			Message: "identity token has expired",
		}
	}

	// 4. Guard: Validate Session freshness and binding (if provided)
	if session != nil {
		if session.IsRevoked() {
			return nil, &Error{
				Code:    CodeInvalidToken,
				Message: "session has been revoked",
			}
		}
		if session.IsExpired(now) {
			return nil, &Error{
				Code:    CodeExpiredToken,
				Message: "session has expired",
			}
		}
		if subtle.ConstantTimeCompare([]byte(session.Identity.Subject), []byte(identity.Subject)) != 1 {
			return nil, &Error{
				Code:    CodeInvalidToken,
				Message: "session subject does not match identity subject",
			}
		}
	}

	// 5. Guard: Normalize path and enforce anti-manipulation defenses
	canonicalPath, err := NormalizePath(rawSecretPath)
	if err != nil {
		return nil, err
	}

	// 6. Guard: Owner Authorization
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
			return nil, &Error{
				Code:    CodeScopeDenied,
				Message: fmt.Sprintf("identity %q is not authorized to access resources belonging to owner %q", identity.Subject, targetOwner),
			}
		}
	}

	// 7. Guard: Action Scope Authorization
	requiredScope := actionToRequiredScope(action)
	if !hasAllowedScope(identity.AllowedScopes, requiredScope) {
		return nil, &Error{
			Code:    CodeScopeDenied,
			Message: fmt.Sprintf("identity %q lacks required scope %q for action %q", identity.Subject, requiredScope, action),
		}
	}

	// 8. Guard: Path-level scope restrictions
	// If identity defines path-specific scopes, verify segment-boundary match
	hasPathRestrictions := false
	pathMatched := false
	for _, s := range identity.AllowedScopes {
		if strings.Contains(s, "/") {
			hasPathRestrictions = true
			if MatchPathScope(s, canonicalPath) {
				pathMatched = true
				break
			}
		}
	}
	if hasPathRestrictions && !pathMatched {
		return nil, &Error{
			Code:    CodeScopeDenied,
			Message: fmt.Sprintf("path %q does not match identity allowed path scopes", canonicalPath),
		}
	}

	// 9. Guard: Vault binding check
	m.mu.RLock()
	kekID, vaultExists := m.vaultKEKMap[vaultID]
	mount := m.vaultMount[vaultID]
	role := m.vaultRoleMap[vaultID]
	m.mu.RUnlock()

	if !vaultExists {
		return nil, &Error{
			Code:    CodeScopeDenied,
			Message: fmt.Sprintf("target vault %q is not authorized or bound to provider", vaultID),
		}
	}
	if mount == "" {
		mount = "transit"
	}
	if role == "" {
		role = identity.VaultRole
	}

	// 10. Guard: Step-up reauthentication for sensitive actions
	isSensitive := action == "reveal_secret" || action == string(ActionRevealSecret) ||
		action == "policy_change" || action == string(ActionPolicyChange)

	if isSensitive {
		if stepUpGrant == nil {
			return nil, &Error{
				Code:    CodeStepUpRequired,
				Message: "fresh step-up authentication required for sensitive action",
			}
		}
		if stepUpGrant.IsExpired(now) {
			return nil, &Error{
				Code:    CodeStepUpExpired,
				Message: "step-up authentication grant has expired",
			}
		}
		if session != nil && !stepUpGrant.MatchesSession(session.ID, identity.Subject) {
			return nil, &Error{
				Code:    CodeStepUpSessionMismatch,
				Message: "step-up grant is not bound to current session",
			}
		}
		if !stepUpGrant.MatchesScope(SensitiveAction(action), canonicalPath) {
			return nil, &Error{
				Code:    CodeStepUpScopeDenied,
				Message: fmt.Sprintf("step-up grant does not authorize action %q on path %q", action, canonicalPath),
			}
		}
	}

	// 11. Derive Bounded Provider Scopes
	var providerScopes []string
	switch action {
	case string(ActionRevealSecret), "secret:read":
		providerScopes = []string{"transit:decrypt"}
	case "secret:write", string(ActionVaultWrite):
		providerScopes = []string{"transit:encrypt"}
	case string(ActionPolicyChange), "policy:write":
		providerScopes = []string{"transit:write"}
	default:
		providerScopes = []string{"transit:read"}
	}

	return &EffectiveProviderScope{
		VaultID:        vaultID,
		CanonicalPath:  canonicalPath,
		KEKID:          kekID,
		ProviderMount:  mount,
		ProviderRole:   role,
		ProviderScopes: providerScopes,
		Owner:          targetOwner,
		Subject:        identity.Subject,
		Action:         action,
	}, nil
}

// AuthorizeProviderAction combines session, step-up manager, path normalization,
// and scope mapping to authorize an end-to-end operation and produce effective provider scope.
func AuthorizeProviderAction(
	ctx context.Context,
	mapper *ScopeMapper,
	identity *Identity,
	session *Session,
	stepUpMgr *StepUpManager,
	stepUpToken string,
	vaultID string,
	rawSecretPath string,
	targetOwner string,
	action string,
	headers http.Header,
) (*EffectiveProviderScope, error) {
	if mapper == nil {
		return nil, &Error{Code: CodeInvalidConfig, Message: "scope mapper must not be nil"}
	}

	// Normalize path early for step-up validation
	canonicalPath, err := NormalizePath(rawSecretPath)
	if err != nil {
		return nil, err
	}

	var grant *StepUpGrant
	isSensitive := action == "reveal_secret" || action == string(ActionRevealSecret) ||
		action == "policy_change" || action == string(ActionPolicyChange)

	if isSensitive && stepUpMgr != nil && session != nil {
		validatedGrant, err := stepUpMgr.ValidateStepUp(
			ctx,
			session,
			stepUpToken,
			SensitiveAction(action),
			canonicalPath,
		)
		if err != nil {
			return nil, err
		}
		grant = validatedGrant
	}

	return mapper.MapUserToProviderScope(
		ctx,
		identity,
		session,
		grant,
		vaultID,
		canonicalPath,
		targetOwner,
		action,
		headers,
	)
}

func actionToRequiredScope(action string) string {
	switch action {
	case string(ActionRevealSecret), "secret:read":
		return "secret:read"
	case "secret:write", string(ActionVaultWrite):
		return "secret:write"
	case string(ActionPolicyChange), "policy:write":
		return "policy:write"
	default:
		return action
	}
}

func hasAllowedScope(allowedScopes []string, required string) bool {
	if required == "" {
		return true
	}
	for _, s := range allowedScopes {
		if s == "*" || s == required {
			return true
		}
		if strings.HasSuffix(s, ":*") {
			prefix := strings.TrimSuffix(s, "*")
			if strings.HasPrefix(required, prefix) {
				return true
			}
		}
	}
	return false
}
