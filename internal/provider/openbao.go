// Package provider defines local and remote key provider capability adapters.
// It implements requirement F01: refusing production dev-mode providers and enforcing scoped workload identity.
package provider

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
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
)

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
	Environment  string        `json:"environment"` // "production", "staging", "local", "test"
	AllowDevMode bool          `json:"allow_dev_mode"`
	HTTPClient   *http.Client  `json:"-"`
	Timeout      time.Duration `json:"timeout"`
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

// Port defines the capabilities provided by an OpenBao provider adapter.
type Port interface {
	WrapDEK(ctx context.Context, kekID string, plaintextDEK []byte) (*WrapResult, error)
	UnwrapDEK(ctx context.Context, kekID string, ciphertext string) ([]byte, error)
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
