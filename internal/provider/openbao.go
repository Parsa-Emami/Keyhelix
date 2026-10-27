// Package provider defines local and remote key provider capability adapters.
// It implements requirement F01: refusing production dev-mode providers and enforcing scoped workload identity.
package provider

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ErrorCode identifies a typed provider failure.
type ErrorCode string

const (
	CodeDevModeRefused      ErrorCode = "DEV_MODE_REFUSED"
	CodeUnscopedIdentity    ErrorCode = "UNSCOPED_IDENTITY"
	CodeInvalidConfig       ErrorCode = "INVALID_CONFIG"
	CodeProviderUnavailable ErrorCode = "PROVIDER_UNAVAILABLE"
	CodeProviderSealed      ErrorCode = "PROVIDER_SEALED"
	CodeMalformedResponse   ErrorCode = "MALFORMED_RESPONSE"
	CodeUnauthorized        ErrorCode = "UNAUTHORIZED"
	CodeInvalidInput        ErrorCode = "INVALID_INPUT"
	CodePayloadConflict     ErrorCode = "PROVIDER_CONFLICT"
	CodePayloadNotFound     ErrorCode = "PAYLOAD_NOT_FOUND"
)

// MaxSealedPayloadBytes bounds one provider-owned sealed payload.
const MaxSealedPayloadBytes = 1 << 20

// checkAndSetError is the OpenBao/Vault wire message for a failed KV v2
// check-and-set write. It is the only provider-conflict signal we accept.
const checkAndSetError = "check-and-set parameter did not match the current version"

// IsErrorCode reports whether err is or wraps an Error with the given code.
func IsErrorCode(err error, code ErrorCode) bool {
	var providerErr *Error
	if errors.As(err, &providerErr) {
		return providerErr.Code == code
	}
	return false
}

// Error represents a typed failure from the key provider capability adapter.
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

// WorkloadIdentity represents a scoped machine identity authorized to interact with the provider.
type WorkloadIdentity struct {
	Role      string   `json:"role"`
	Token     string   `json:"token"`
	Scopes    []string `json:"scopes"`
	Namespace string   `json:"namespace,omitempty"`
}

// HasScope reports whether the identity carries the requested scope or a wildcard.
func (w WorkloadIdentity) HasScope(required string) bool {
	for _, s := range w.Scopes {
		if s == "*" || s == required || (strings.HasSuffix(s, ":*") && strings.HasPrefix(required, strings.TrimSuffix(s, "*"))) {
			return true
		}
	}
	return false
}

// Config defines connection and environment parameters for the OpenBao adapter.
type Config struct {
	Address      string        `json:"address"`
	KEKMount     string        `json:"kek_mount"`
	PayloadMount string        `json:"payload_mount"` // KV v2 mount that owns sealed secret bytes
	Environment  string        `json:"environment"`   // "production", "staging", "local", "test"
	AllowDevMode bool          `json:"allow_dev_mode"`
	HTTPClient   *http.Client  `json:"-"`
	Timeout      time.Duration `json:"timeout"`
}

// SealedRef addresses one provider-owned sealed payload version. The provider
// owns these encrypted bytes; metadata storage never accepts them.
type SealedRef struct {
	VaultID string `json:"vault_id"`
	Path    string `json:"path"`
	Version int64  `json:"version"`
}

// Health represents OpenBao server health status.
type Health struct {
	Status      string `json:"status"`
	Version     string `json:"version"`
	Initialized bool   `json:"initialized"`
	Sealed      bool   `json:"sealed"`
	DevMode     bool   `json:"dev_mode"`
}

// WrapResult contains the result of a KEK wrapping operation.
type WrapResult struct {
	Ciphertext string `json:"ciphertext"`
	KEKVersion int    `json:"kek_version"`
}

// PayloadDestroyer defines the optional provider capability for permanent
// destruction of provider-owned sealed bytes (Requirement F13).
type PayloadDestroyer interface {
	DestroySealedPayload(ctx context.Context, ref SealedRef) error
}

// Port defines the capabilities provided by an OpenBao provider adapter.
type Port interface {
	WrapDEK(ctx context.Context, kekID string, plaintextDEK []byte) (*WrapResult, error)
	UnwrapDEK(ctx context.Context, kekID string, ciphertext string) ([]byte, error)
	PutSealedPayload(ctx context.Context, ref SealedRef, sealed []byte) error
	ReadSealedPayload(ctx context.Context, ref SealedRef) ([]byte, error)
	Health(ctx context.Context) (*Health, error)
	WorkloadIdentity() WorkloadIdentity
}

// Adapter implements the OpenBao capability adapter.
type Adapter struct {
	config   Config
	identity WorkloadIdentity
	client   *http.Client
	baseURL  *url.URL
}

var _ Port = (*Adapter)(nil)

// NewOpenBaoAdapter creates and verifies an OpenBao capability adapter.
// It strictly refuses dev-mode OpenBao under production/staging environments (Requirement F01)
// and validates scoped workload identity.
func NewOpenBaoAdapter(ctx context.Context, cfg Config, identity WorkloadIdentity) (*Adapter, error) {
	if strings.TrimSpace(cfg.Address) == "" {
		return nil, &Error{Code: CodeInvalidConfig, Message: "provider address is required"}
	}
	parsedURL, err := url.Parse(cfg.Address)
	if err != nil || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") {
		return nil, &Error{Code: CodeInvalidConfig, Message: "provider address must be a valid http or https URL"}
	}
	if parsedURL.Host == "" {
		return nil, &Error{Code: CodeInvalidConfig, Message: "provider address must include a valid host"}
	}

	env := strings.ToLower(strings.TrimSpace(cfg.Environment))
	if env == "" {
		env = "local"
	}

	isProduction := env == "production" || env == "staging"

	// Guard: Configuration refusing dev mode in production
	if isProduction && cfg.AllowDevMode {
		return nil, &Error{
			Code:    CodeDevModeRefused,
			Message: "production and staging environments strictly refuse dev-mode provider configuration",
		}
	}

	// Guard: Scoped Workload Identity validation
	token := strings.TrimSpace(identity.Token)
	if token == "" {
		return nil, &Error{Code: CodeUnscopedIdentity, Message: "workload token must not be empty"}
	}
	if strings.EqualFold(token, "root") || strings.HasPrefix(strings.ToLower(token), "s.root") {
		return nil, &Error{
			Code:    CodeUnscopedIdentity,
			Message: "omnipotent root tokens are refused; scoped workload identity required",
		}
	}
	if len(identity.Scopes) == 0 {
		return nil, &Error{
			Code:    CodeUnscopedIdentity,
			Message: "workload identity must specify explicit authorized scopes",
		}
	}

	kekMount := strings.Trim(cfg.KEKMount, "/")
	if kekMount == "" {
		kekMount = "transit"
	}
	cfg.KEKMount = kekMount

	payloadMount := strings.Trim(cfg.PayloadMount, "/")
	if payloadMount == "" {
		payloadMount = "kv"
	}
	cfg.PayloadMount = payloadMount

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: timeout}
	}

	adapter := &Adapter{
		config:   cfg,
		identity: identity,
		client:   client,
		baseURL:  parsedURL,
	}

	// Perform health check to verify availability and dev-mode state
	health, err := adapter.Health(ctx)
	if err != nil {
		return nil, err
	}

	if isProduction && health.DevMode {
		return nil, &Error{
			Code:    CodeDevModeRefused,
			Message: "production environment refuses dev-mode OpenBao instance",
		}
	}

	return adapter, nil
}

// WorkloadIdentity returns the configured workload identity.
func (a *Adapter) WorkloadIdentity() WorkloadIdentity {
	return a.identity
}

// Health checks the status of the OpenBao instance via /v1/sys/health.
func (a *Adapter) Health(ctx context.Context) (*Health, error) {
	endpoint := a.baseURL.ResolveReference(&url.URL{Path: "/v1/sys/health"})
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, &Error{Code: CodeInvalidInput, Message: "failed to construct health request", Err: err}
	}
	req.Header.Set("User-Agent", "KeyHelix-Engine/0.0.1")

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, &Error{Code: CodeProviderUnavailable, Message: "openbao health check unreachable", Err: err}
	}
	defer resp.Body.Close()

	// In OpenBao/Vault /v1/sys/health:
	// 200 = initialized, unsealed, active
	// 429 = unsealed, standby
	// 472 = disaster recovery mode
	// 473 = performance standby
	// 501 = not initialized
	// 503 = sealed
	if resp.StatusCode == http.StatusServiceUnavailable {
		return nil, &Error{Code: CodeProviderSealed, Message: "openbao is sealed"}
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != 429 && resp.StatusCode != 473 {
		return nil, &Error{Code: CodeProviderUnavailable, Message: fmt.Sprintf("openbao health reported status %d", resp.StatusCode)}
	}

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, &Error{Code: CodeProviderUnavailable, Message: "failed to read health response", Err: err}
	}

	var raw map[string]any
	if err := json.Unmarshal(bodyBytes, &raw); err != nil {
		return nil, &Error{Code: CodeMalformedResponse, Message: "invalid json in health response", Err: err}
	}

	h := &Health{
		Status:      "ok",
		Version:     "unknown",
		Initialized: true,
		Sealed:      false,
		DevMode:     false,
	}

	if v, ok := raw["version"].(string); ok {
		h.Version = v
	}
	if s, ok := raw["sealed"].(bool); ok {
		h.Sealed = s
	}
	if i, ok := raw["initialized"].(bool); ok {
		h.Initialized = i
	}
	// Dev mode detection: explicit boolean or header
	if d, ok := raw["dev_mode"].(bool); ok {
		h.DevMode = d
	} else if strings.EqualFold(resp.Header.Get("X-Vault-Dev"), "true") || strings.EqualFold(resp.Header.Get("X-OpenBao-Dev"), "true") {
		h.DevMode = true
	}

	return h, nil
}

// WrapDEK wraps a data encryption key (DEK) using the specified transit KEK ID.
func (a *Adapter) WrapDEK(ctx context.Context, kekID string, plaintextDEK []byte) (*WrapResult, error) {
	if strings.TrimSpace(kekID) == "" {
		return nil, &Error{Code: CodeInvalidInput, Message: "kek_id is required"}
	}
	if len(plaintextDEK) == 0 {
		return nil, &Error{Code: CodeInvalidInput, Message: "plaintext_dek must not be empty"}
	}

	// Enforce scoped workload identity policy
	if !a.identity.HasScope("transit:encrypt") {
		return nil, &Error{
			Code:    CodeUnscopedIdentity,
			Message: "workload identity lacks 'transit:encrypt' scope for key wrapping",
		}
	}

	b64Plaintext := base64.StdEncoding.EncodeToString(plaintextDEK)
	payload := map[string]string{
		"plaintext": b64Plaintext,
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, &Error{Code: CodeInvalidInput, Message: "failed to marshal encrypt payload", Err: err}
	}

	path := fmt.Sprintf("/v1/%s/encrypt/%s", a.config.KEKMount, url.PathEscape(kekID))
	endpoint := a.baseURL.ResolveReference(&url.URL{Path: path})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(payloadBytes))
	if err != nil {
		return nil, &Error{Code: CodeInvalidInput, Message: "failed to create encrypt request", Err: err}
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Vault-Token", a.identity.Token)
	if a.identity.Namespace != "" {
		req.Header.Set("X-Vault-Namespace", a.identity.Namespace)
	}

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, &Error{Code: CodeProviderUnavailable, Message: "openbao transit encrypt unreachable", Err: err}
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized {
		return nil, &Error{Code: CodeUnauthorized, Message: "openbao refused token authorization"}
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, &Error{Code: CodeInvalidInput, Message: fmt.Sprintf("kek_id '%s' not found on mount '%s'", kekID, a.config.KEKMount)}
	}
	if resp.StatusCode == http.StatusServiceUnavailable {
		return nil, &Error{Code: CodeProviderSealed, Message: "openbao provider is sealed"}
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &Error{Code: CodeProviderUnavailable, Message: fmt.Sprintf("openbao returned unexpected status %d", resp.StatusCode)}
	}

	var parsed struct {
		Data struct {
			Ciphertext string `json:"ciphertext"`
			KeyVersion int    `json:"key_version"`
		} `json:"data"`
		Errors []string `json:"errors"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64*1024)).Decode(&parsed); err != nil {
		return nil, &Error{Code: CodeMalformedResponse, Message: "failed to decode encrypt response", Err: err}
	}
	if parsed.Data.Ciphertext == "" {
		return nil, &Error{Code: CodeMalformedResponse, Message: "missing ciphertext in transit response"}
	}

	return &WrapResult{
		Ciphertext: parsed.Data.Ciphertext,
		KEKVersion: parsed.Data.KeyVersion,
	}, nil
}

// UnwrapDEK unwraps a data encryption key (DEK) using the specified transit KEK ID.
func (a *Adapter) UnwrapDEK(ctx context.Context, kekID string, ciphertext string) ([]byte, error) {
	if strings.TrimSpace(kekID) == "" {
		return nil, &Error{Code: CodeInvalidInput, Message: "kek_id is required"}
	}
	if strings.TrimSpace(ciphertext) == "" {
		return nil, &Error{Code: CodeInvalidInput, Message: "ciphertext is required"}
	}

	// Enforce scoped workload identity policy
	if !a.identity.HasScope("transit:decrypt") {
		return nil, &Error{
			Code:    CodeUnscopedIdentity,
			Message: "workload identity lacks 'transit:decrypt' scope for key unwrapping",
		}
	}

	payload := map[string]string{
		"ciphertext": ciphertext,
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, &Error{Code: CodeInvalidInput, Message: "failed to marshal decrypt payload", Err: err}
	}

	path := fmt.Sprintf("/v1/%s/decrypt/%s", a.config.KEKMount, url.PathEscape(kekID))
	endpoint := a.baseURL.ResolveReference(&url.URL{Path: path})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(payloadBytes))
	if err != nil {
		return nil, &Error{Code: CodeInvalidInput, Message: "failed to create decrypt request", Err: err}
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Vault-Token", a.identity.Token)
	if a.identity.Namespace != "" {
		req.Header.Set("X-Vault-Namespace", a.identity.Namespace)
	}

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, &Error{Code: CodeProviderUnavailable, Message: "openbao transit decrypt unreachable", Err: err}
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized {
		return nil, &Error{Code: CodeUnauthorized, Message: "openbao refused token authorization"}
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, &Error{Code: CodeInvalidInput, Message: fmt.Sprintf("kek_id '%s' or ciphertext not found", kekID)}
	}
	if resp.StatusCode == http.StatusServiceUnavailable {
		return nil, &Error{Code: CodeProviderSealed, Message: "openbao provider is sealed"}
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &Error{Code: CodeProviderUnavailable, Message: fmt.Sprintf("openbao returned unexpected status %d", resp.StatusCode)}
	}

	var parsed struct {
		Data struct {
			Plaintext string `json:"plaintext"`
		} `json:"data"`
		Errors []string `json:"errors"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64*1024)).Decode(&parsed); err != nil {
		return nil, &Error{Code: CodeMalformedResponse, Message: "failed to decode decrypt response", Err: err}
	}
	if parsed.Data.Plaintext == "" {
		return nil, &Error{Code: CodeMalformedResponse, Message: "missing plaintext in transit response"}
	}

	decoded, err := base64.StdEncoding.DecodeString(parsed.Data.Plaintext)
	if err != nil {
		return nil, &Error{Code: CodeMalformedResponse, Message: "invalid base64 plaintext in response", Err: err}
	}

	return decoded, nil
}

// PutSealedPayload stores provider-owned sealed bytes for one secret version in
// the version-scoped KV v2 path <payload mount>/data/<vault>/<path>/v<version>.
// The write is create-only (cas=0) so a retry cannot replace bytes that an
// already published envelope references; the provider owns these bytes and
// metadata storage never accepts them.
func (a *Adapter) PutSealedPayload(ctx context.Context, ref SealedRef, sealed []byte) error {
	if err := validateSealedRef(ref); err != nil {
		return err
	}
	if len(sealed) == 0 {
		return &Error{Code: CodeInvalidInput, Message: "sealed payload must not be empty"}
	}
	if len(sealed) > MaxSealedPayloadBytes {
		return &Error{Code: CodeInvalidInput, Message: "sealed payload exceeds the bounded maximum"}
	}
	if !a.identity.HasScope("kv:write") {
		return &Error{
			Code:    CodeUnscopedIdentity,
			Message: "workload identity lacks 'kv:write' scope for provider-owned payload storage",
		}
	}

	payload, err := json.Marshal(map[string]any{
		"data":    map[string]string{"sealed": base64.StdEncoding.EncodeToString(sealed)},
		"options": map[string]int{"cas": 0},
	})
	if err != nil {
		return &Error{Code: CodeInvalidInput, Message: "failed to marshal payload write", Err: err}
	}

	endpoint := a.kvEndpoint(ref)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(payload))
	if err != nil {
		return &Error{Code: CodeInvalidInput, Message: "failed to create payload write request", Err: err}
	}
	a.authorize(req)

	resp, err := a.client.Do(req)
	if err != nil {
		return &Error{Code: CodeProviderUnavailable, Message: "openbao payload store unreachable", Err: err}
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized {
		return &Error{Code: CodeUnauthorized, Message: "openbao refused token authorization for payload write"}
	}
	if resp.StatusCode == http.StatusServiceUnavailable {
		return &Error{Code: CodeProviderSealed, Message: "openbao provider is sealed"}
	}
	if resp.StatusCode == http.StatusNotFound {
		return &Error{Code: CodeInvalidConfig, Message: "openbao payload mount is not available"}
	}
	if resp.StatusCode == http.StatusBadRequest {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		if strings.Contains(string(body), checkAndSetError) {
			return &Error{Code: CodePayloadConflict, Message: "provider already owns a payload for this secret version"}
		}
		return &Error{Code: CodeMalformedResponse, Message: "openbao rejected the payload write"}
	}
	if resp.StatusCode != http.StatusOK {
		return &Error{Code: CodeProviderUnavailable, Message: fmt.Sprintf("openbao returned unexpected status %d for payload write", resp.StatusCode)}
	}
	if _, err := io.Copy(io.Discard, io.LimitReader(resp.Body, 64*1024)); err != nil {
		return &Error{Code: CodeMalformedResponse, Message: "failed to read payload write response", Err: err}
	}
	return nil
}

// ReadSealedPayload returns the provider-owned sealed bytes for the addressed
// secret version. Only the latest payload of that version path is ever returned.
func (a *Adapter) ReadSealedPayload(ctx context.Context, ref SealedRef) ([]byte, error) {
	if err := validateSealedRef(ref); err != nil {
		return nil, err
	}
	if !a.identity.HasScope("kv:read") {
		return nil, &Error{
			Code:    CodeUnscopedIdentity,
			Message: "workload identity lacks 'kv:read' scope for provider-owned payload access",
		}
	}

	endpoint := a.kvEndpoint(ref)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, &Error{Code: CodeInvalidInput, Message: "failed to create payload read request", Err: err}
	}
	a.authorize(req)

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, &Error{Code: CodeProviderUnavailable, Message: "openbao payload store unreachable", Err: err}
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized {
		return nil, &Error{Code: CodeUnauthorized, Message: "openbao refused token authorization for payload read"}
	}
	if resp.StatusCode == http.StatusServiceUnavailable {
		return nil, &Error{Code: CodeProviderSealed, Message: "openbao provider is sealed"}
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, &Error{Code: CodePayloadNotFound, Message: "provider owns no payload for this secret version"}
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &Error{Code: CodeProviderUnavailable, Message: fmt.Sprintf("openbao returned unexpected status %d for payload read", resp.StatusCode)}
	}

	var parsed struct {
		Data struct {
			Data     map[string]string `json:"data"`
			Metadata struct {
				Version int64 `json:"version"`
			} `json:"metadata"`
		} `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64*1024)).Decode(&parsed); err != nil {
		return nil, &Error{Code: CodeMalformedResponse, Message: "failed to decode payload response", Err: err}
	}
	if parsed.Data.Metadata.Version < 1 || parsed.Data.Data["sealed"] == "" {
		return nil, &Error{Code: CodeMalformedResponse, Message: "missing sealed payload in provider response"}
	}

	decoded, err := base64.StdEncoding.DecodeString(parsed.Data.Data["sealed"])
	if err != nil {
		return nil, &Error{Code: CodeMalformedResponse, Message: "invalid base64 sealed payload in response", Err: err}
	}
	if len(decoded) == 0 || len(decoded) > MaxSealedPayloadBytes {
		return nil, &Error{Code: CodeMalformedResponse, Message: "sealed payload length is outside the bounded range"}
	}
	return decoded, nil
}

// DestroySealedPayload permanently purges provider-owned sealed bytes for one
// secret version (Requirement F13). This operation is irreversible and requires
// operator-level KV scope ("kv:destroy", "kv:write" or "*").
func (a *Adapter) DestroySealedPayload(ctx context.Context, ref SealedRef) error {
	if err := validateSealedRef(ref); err != nil {
		return err
	}
	if !a.identity.HasScope("kv:destroy") && !a.identity.HasScope("kv:write") && !a.identity.HasScope("*") {
		return &Error{
			Code:    CodeUnscopedIdentity,
			Message: "workload identity lacks scope for provider-owned payload destruction",
		}
	}

	endpoint := a.kvEndpoint(ref)
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, endpoint.String(), nil)
	if err != nil {
		return &Error{Code: CodeInvalidInput, Message: "failed to create payload destroy request", Err: err}
	}
	a.authorize(req)

	resp, err := a.client.Do(req)
	if err != nil {
		return &Error{Code: CodeProviderUnavailable, Message: "openbao payload store unreachable", Err: err}
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized {
		return &Error{Code: CodeUnauthorized, Message: "openbao refused token authorization for payload destruction"}
	}
	if resp.StatusCode == http.StatusServiceUnavailable {
		return &Error{Code: CodeProviderSealed, Message: "openbao provider is sealed"}
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusNotFound {
		return &Error{Code: CodeProviderUnavailable, Message: fmt.Sprintf("openbao returned unexpected status %d for payload destruction", resp.StatusCode)}
	}
	return nil
}

func (a *Adapter) authorize(req *http.Request) {
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Vault-Token", a.identity.Token)
	if a.identity.Namespace != "" {
		req.Header.Set("X-Vault-Namespace", a.identity.Namespace)
	}
}

// kvEndpoint builds the KV v2 data endpoint for one version-scoped payload path.
func (a *Adapter) kvEndpoint(ref SealedRef) *url.URL {
	path := fmt.Sprintf("/v1/%s/data/%s/%s/v%d", a.config.PayloadMount, ref.VaultID, ref.Path, ref.Version)
	return a.baseURL.ResolveReference(&url.URL{Path: path})
}

// validateSealedRef bounds the provider path so a caller cannot address bytes
// outside the vault-scoped payload tree.
func validateSealedRef(ref SealedRef) error {
	if ref.Version < 1 {
		return &Error{Code: CodeInvalidInput, Message: "sealed payload version must be positive"}
	}
	for _, field := range []struct{ name, value string }{
		{"vault_id", ref.VaultID},
		{"path", ref.Path},
	} {
		trimmed := strings.TrimSpace(field.value)
		if trimmed == "" {
			return &Error{Code: CodeInvalidInput, Message: field.name + " is required for sealed payload access"}
		}
		if strings.Contains(trimmed, "\\") {
			return &Error{Code: CodeInvalidInput, Message: field.name + " contains a forbidden separator"}
		}
		for _, segment := range strings.Split(trimmed, "/") {
			if segment == "" || segment == "." || segment == ".." {
				return &Error{Code: CodeInvalidInput, Message: field.name + " must be a bounded provider path"}
			}
		}
		for _, r := range trimmed {
			if r < 32 || r == 127 || r == '?' || r == '#' {
				return &Error{Code: CodeInvalidInput, Message: field.name + " contains forbidden characters"}
			}
		}
	}
	return nil
}
