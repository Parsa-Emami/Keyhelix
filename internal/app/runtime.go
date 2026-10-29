package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/parsa-emami/keyhelix/internal/audit"
	"github.com/parsa-emami/keyhelix/internal/auth"
	"github.com/parsa-emami/keyhelix/internal/grants"
	"github.com/parsa-emami/keyhelix/internal/provider"
	"github.com/parsa-emami/keyhelix/internal/secrets"
	"github.com/parsa-emami/keyhelix/internal/security"
	"github.com/parsa-emami/keyhelix/internal/storage"
	"github.com/parsa-emami/keyhelix/internal/vaults"
)

// Version is the engine runtime version reported by health and readiness.
const Version = "0.0.1"

// ProviderHealth is the provider partition of engine readiness.
type ProviderHealth struct {
	State      string `json:"state"`
	ProviderID string `json:"provider_id"`
	Sealed     bool   `json:"sealed"`
	AuditReady bool   `json:"audit_ready"`
	Version    string `json:"version,omitempty"`
	Error      string `json:"error,omitempty"`
}

// IdentityHealth is the identity provider partition of engine readiness.
type IdentityHealth struct {
	State  string `json:"state"`
	Issuer string `json:"issuer"`
	Error  string `json:"error,omitempty"`
}

// HealthReport is the composed engine readiness document.
type HealthReport struct {
	Status           string         `json:"status"`
	Scope            string         `json:"scope"`
	Version          string         `json:"version"`
	Toolchain        string         `json:"toolchain"`
	CoreReady        bool           `json:"coreReady"`
	Storage          string         `json:"storage"`
	Provider         ProviderHealth `json:"provider"`
	IdentityProvider IdentityHealth `json:"identity_provider"`
}

type elevation struct {
	token     auth.StepUpToken
	action    auth.SensitiveAction
	resource  string
	expiresAt time.Time
}

type pendingFlow struct {
	request   *auth.AuthRequest
	flow      string
	returnTo  string
	action    auth.SensitiveAction
	resource  string
	sessionID string
	subject   string
	expiresAt time.Time
}

type discoveryDocument struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

// Runtime is the composed local engine: durable metadata storage, the scoped
// OpenBao adapter, the OIDC identity provider and the domain services.
type Runtime struct {
	config    Config
	store     *storage.Store
	provider  *provider.Adapter
	mapper    *auth.ScopeMapper
	oidc      *auth.Provider
	discovery discoveryDocument
	sessions  *auth.SessionManager
	stepUp    *auth.StepUpManager
	secrets   *secrets.Service
	vaults    *vaults.Service
	grants    *grants.Service
	audit     *audit.Recorder
	client    *http.Client

	mu        sync.Mutex
	pending   map[string]*pendingFlow
	elevated  map[string]elevation
	idpCheck  time.Time
	idpState  IdentityHealth
	startedAt time.Time
}

// New opens the durable store, verifies the scoped provider and discovers the
// identity provider before serving any request.
func New(ctx context.Context, config Config) (*Runtime, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	dataDir, err := ResolvePath(config.Engine.DataDir)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("engine data directory is not writable: %w", err)
	}
	store, _, err := storage.Open(dataDir)
	if err != nil {
		return nil, fmt.Errorf("durable metadata storage is unavailable: %w", err)
	}

	client := &http.Client{Timeout: 5 * time.Second}
	adapter, err := provider.NewOpenBaoAdapter(ctx, provider.Config{
		Address:      config.OpenBao.Address,
		KEKMount:     config.OpenBao.KEKMount,
		PayloadMount: config.OpenBao.PayloadMount,
		Environment:  "local",
		AllowDevMode: false,
		HTTPClient:   client,
		Timeout:      5 * time.Second,
	}, provider.WorkloadIdentity{
		Role:   "keyhelix-engine",
		Token:  config.OpenBao.Token,
		Scopes: config.OpenBao.Scopes,
	})
	if err != nil {
		store.Close()
		return nil, fmt.Errorf("key provider is not ready: %w", err)
	}

	discovery, err := discover(ctx, client, config.OIDC.Issuer)
	if err != nil {
		store.Close()
		return nil, fmt.Errorf("identity provider is not ready: %w", err)
	}
	oidcProvider, err := auth.NewProvider(auth.Config{
		IssuerURL:             config.OIDC.Issuer,
		ClientID:              config.OIDC.ClientID,
		RedirectURI:           config.OIDC.RedirectURI,
		AuthorizationEndpoint: discovery.AuthorizationEndpoint,
		TokenEndpoint:         discovery.TokenEndpoint,
		JWKSURL:               discovery.JWKSURI,
		HTTPClient:            client,
	})
	if err != nil {
		store.Close()
		return nil, err
	}

	sessionConfig := auth.DefaultSessionConfig()
	sessionConfig.SecureCookie = true
	sessionConfig.SameSite = http.SameSiteLaxMode // required for the OIDC redirect back to the app
	sessions, err := auth.NewSessionManager(sessionConfig, auth.NewMemorySessionStore())
	if err != nil {
		store.Close()
		return nil, err
	}
	stepUpConfig := auth.DefaultStepUpConfig()
	stepUpConfig.SingleUse = true
	stepUp, err := auth.NewStepUpManager(stepUpConfig, auth.NewMemoryStepUpStore())
	if err != nil {
		store.Close()
		return nil, err
	}

	scopeConfig := auth.DefaultScopeMapperConfig()
	scopeConfig.VaultKEKMap = map[string]string{}
	scopeConfig.VaultMountMap = map[string]string{}
	scopeConfig.VaultRoleMap = map[string]string{}
	for _, vault := range config.Engine.Vaults {
		scopeConfig.VaultKEKMap[vault] = config.OpenBao.KEKID
		scopeConfig.VaultMountMap[vault] = config.OpenBao.KEKMount
		scopeConfig.VaultRoleMap[vault] = "keyhelix-engine"
	}
	mapper := auth.NewScopeMapper(scopeConfig)

	recorder := audit.NewRecorder(2048, security.NewRedactor())
	grantService := grants.NewService(store, recorder)
	if _, err := grantService.Restore(ctx); err != nil {
		store.Close()
		return nil, fmt.Errorf("grant index is not readable: %w", err)
	}

	runtime := &Runtime{
		config:    config,
		store:     store,
		provider:  adapter,
		mapper:    mapper,
		oidc:      oidcProvider,
		discovery: discovery,
		sessions:  sessions,
		stepUp:    stepUp,
		secrets:   secrets.NewService(mapper, adapter, store),
		vaults:    vaults.NewService(store, mapper),
		grants:    grantService,
		audit:     recorder,
		client:    client,
		pending:   map[string]*pendingFlow{},
		elevated:  map[string]elevation{},
		idpState:  IdentityHealth{State: "ready", Issuer: config.OIDC.Issuer},
		idpCheck:  time.Now(),
		startedAt: time.Now().UTC(),
	}
	return runtime, nil
}

func discover(ctx context.Context, client *http.Client, issuer string) (discoveryDocument, error) {
	var document discoveryDocument
	endpoint := strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return document, err
	}
	response, err := client.Do(request)
	if err != nil {
		return document, fmt.Errorf("discovery request failed: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return document, fmt.Errorf("discovery returned status %d", response.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&document); err != nil {
		return document, fmt.Errorf("discovery document is malformed: %w", err)
	}
	if strings.TrimRight(document.Issuer, "/") != strings.TrimRight(issuer, "/") {
		return document, fmt.Errorf("discovery issuer %q does not match the configured issuer", document.Issuer)
	}
	for _, endpoint := range []struct{ value, field string }{
		{document.AuthorizationEndpoint, "authorization endpoint"},
		{document.TokenEndpoint, "token endpoint"},
		{document.JWKSURI, "JWKS URI"},
	} {
		parsed, err := url.Parse(endpoint.value)
		if err != nil || parsed.Scheme != "http" && parsed.Scheme != "https" || parsed.Host == "" {
			return document, fmt.Errorf("discovery document has no absolute %s", endpoint.field)
		}
	}
	return document, nil
}

// Close releases the durable store writer lock.
func (r *Runtime) Close() error { return r.store.Close() }

// CheckReadiness probes storage, the key provider and the identity provider.
func (r *Runtime) CheckReadiness(ctx context.Context) HealthReport {
	report := HealthReport{
		Status:    "not_ready",
		Scope:     "engine-runtime",
		Version:   Version,
		Toolchain: runtime.Version(),
		CoreReady: true,
		Storage:   "ready",
		Provider:  ProviderHealth{State: "unavailable", ProviderID: "openbao", AuditReady: r.audit != nil},
	}
	if _, err := r.store.List(ctx, storage.ListRequest{Scope: "grants"}); err != nil {
		report.Storage = "failed"
	}
	health, err := r.provider.Health(ctx)
	switch {
	case err != nil:
		report.Provider.State = "unavailable"
		report.Provider.Error = "key provider is unreachable"
	case health != nil && health.Sealed:
		report.Provider.Sealed = true
		report.Provider.State = "sealed"
		report.Provider.Error = "key provider is sealed"
	default:
		report.Provider.State = "ready"
		if health != nil {
			report.Provider.Version = health.Version
		}
	}
	idp := r.identityReadiness(ctx)
	if idp.State != "ready" {
		report.IdentityProvider = idp
	}
	report.IdentityProvider = idp
	if report.Storage == "ready" && report.Provider.State == "ready" && idp.State == "ready" {
		report.Status = "ready"
	}
	return report
}

// identityReadiness caches the identity provider probe for a short interval so
// readiness polling cannot amplify load on Keycloak.
func (r *Runtime) identityReadiness(ctx context.Context) IdentityHealth {
	r.mu.Lock()
	cached := r.idpState
	checkedAt := r.idpCheck
	r.mu.Unlock()
	if time.Since(checkedAt) < 5*time.Second {
		return cached
	}
	probe, err := discover(ctx, r.client, r.config.OIDC.Issuer)
	state := IdentityHealth{State: "ready", Issuer: r.config.OIDC.Issuer}
	if err != nil || probe.JWKSURI == "" {
		state = IdentityHealth{State: "unavailable", Issuer: r.config.OIDC.Issuer, Error: "identity provider is unreachable"}
		r.mapper.SetIDPOnline(false)
	} else {
		r.mapper.SetIDPOnline(true)
	}
	r.mu.Lock()
	r.idpState = state
	r.idpCheck = time.Now()
	r.mu.Unlock()
	return state
}

func (r *Runtime) rememberFlow(flow *pendingFlow) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	for state, pending := range r.pending {
		if now.After(pending.expiresAt) {
			delete(r.pending, state)
		}
	}
	r.pending[flow.request.State] = flow
}

func (r *Runtime) takeFlow(state string) *pendingFlow {
	r.mu.Lock()
	defer r.mu.Unlock()
	flow := r.pending[state]
	delete(r.pending, state)
	if flow == nil || time.Now().After(flow.expiresAt) {
		return nil
	}
	return flow
}

func (r *Runtime) setElevation(sessionID string, grant *auth.StepUpGrant, token auth.StepUpToken) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.elevated[sessionID] = elevation{token: token, action: grant.Action, resource: grant.Resource, expiresAt: grant.Expiration()}
}

func (r *Runtime) elevationFor(sessionID string, action auth.SensitiveAction, resource string) (auth.StepUpToken, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	value, ok := r.elevated[sessionID]
	if !ok || time.Now().After(value.expiresAt) || value.action != action || value.resource != resource {
		return "", false
	}
	return value.token, true
}

func (r *Runtime) clearElevation(sessionID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.elevated, sessionID)
}

func (r *Runtime) record(eventType, subject string, data audit.AuditData) {
	if r.audit == nil {
		return
	}
	event, err := audit.NewEvent(eventType, subject, data)
	if err != nil {
		return
	}
	_ = r.audit.Record(context.Background(), event)
}

func randomState() (string, error) {
	buffer := make([]byte, 16)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return hex.EncodeToString(buffer), nil
}
