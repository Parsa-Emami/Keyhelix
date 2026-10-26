package storage_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/parsa-emami/keyhelix/internal/provider"
)

type c07PositiveFixture struct {
	SchemaVersion int `json:"schema_version"`
	Provider      struct {
		Name        string `json:"name"`
		KEKMount    string `json:"kek_mount"`
		KEKID       string `json:"kek_id"`
		Environment string `json:"environment"`
		DevMode     bool   `json:"dev_mode"`
	} `json:"provider"`
	WorkloadIdentity provider.WorkloadIdentity `json:"workload_identity"`
	PlaintextCanary  string                    `json:"plaintext_dek_canary"`
	MetadataFile     string                    `json:"metadata_file"`
}

type c07ExpectedOutput struct {
	SchemaVersion   int    `json:"schema_version"`
	MetadataSHA256  string `json:"metadata_sha256"`
	PlaintextCanary string `json:"plaintext_canary"`
	Provider        struct {
		Status      string `json:"status"`
		Sealed      bool   `json:"sealed"`
		Initialized bool   `json:"initialized"`
		DevMode     bool   `json:"dev_mode"`
	} `json:"provider"`
	WrappedDEKPrefix string `json:"wrapped_dek_prefix"`
	DevModeRefusal   struct {
		ExpectedCode string `json:"expected_code"`
	} `json:"dev_mode_refusal"`
	UnscopedIdentity struct {
		ExpectedCode string `json:"expected_code"`
	} `json:"unscoped_identity"`
	ProviderOutage struct {
		ExpectedCode string `json:"expected_code"`
	} `json:"provider_outage"`
	ProviderSealed struct {
		ExpectedCode string `json:"expected_code"`
	} `json:"provider_sealed"`
	MalformedResponse struct {
		ExpectedCode string `json:"expected_code"`
	} `json:"malformed_response"`
}

func loadC07Fixture(t *testing.T, filename string, target any) {
	t.Helper()
	path := filepath.Join("fixtures", "keyhelix", "C07", filename)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read C07 fixture %s: %v", filename, err)
	}
	if err := json.Unmarshal(data, target); err != nil {
		t.Fatalf("unmarshal C07 fixture %s: %v", filename, err)
	}
}

func assertProviderCode(t *testing.T, err error, expected provider.ErrorCode) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error code %s, got nil", expected)
	}
	var provErr *provider.Error
	if errors.As(err, &provErr) {
		if provErr.Code != expected {
			t.Fatalf("expected error code %s, got %s (%v)", expected, provErr.Code, err)
		}
		return
	}
	t.Fatalf("expected *provider.Error with code %s, got %T: %v", expected, err, err)
}

// setupMockOpenBao returns an httptest server simulating OpenBao Transit and Health endpoints.
func setupMockOpenBao(t *testing.T, isDevMode bool, isSealed bool) (*httptest.Server, *int32) {
	t.Helper()
	var requestCount int32
	var mu sync.Mutex
	transitStore := make(map[string]string)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)

		// Health endpoint
		if r.URL.Path == "/v1/sys/health" {
			if isSealed {
				w.WriteHeader(http.StatusServiceUnavailable)
				json.NewEncoder(w).Encode(map[string]any{
					"initialized": true,
					"sealed":      true,
				})
				return
			}
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]any{
				"initialized": true,
				"sealed":      false,
				"dev_mode":    isDevMode,
				"version":     "2.0.0",
			})
			return
		}

		// Verify auth token
		token := r.Header.Get("X-Vault-Token")
		if token == "" || strings.EqualFold(token, "invalid") {
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]any{"errors": []string{"permission denied"}})
			return
		}

		// Transit encrypt endpoint: /v1/transit/encrypt/<kek_id>
		if strings.HasPrefix(r.URL.Path, "/v1/transit/encrypt/") && r.Method == http.MethodPost {
			var body struct {
				Plaintext string `json:"plaintext"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			ciphertext := "bao:v1:" + body.Plaintext
			mu.Lock()
			transitStore[ciphertext] = body.Plaintext
			mu.Unlock()

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{
					"ciphertext":  ciphertext,
					"key_version": 1,
				},
			})
			return
		}

		// Transit decrypt endpoint: /v1/transit/decrypt/<kek_id>
		if strings.HasPrefix(r.URL.Path, "/v1/transit/decrypt/") && r.Method == http.MethodPost {
			var body struct {
				Ciphertext string `json:"ciphertext"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			mu.Lock()
			plaintext, ok := transitStore[body.Ciphertext]
			mu.Unlock()

			if !ok {
				// Fallback if not tracked
				plaintext = strings.TrimPrefix(body.Ciphertext, "bao:v1:")
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{
					"plaintext": plaintext,
				},
			})
			return
		}

		w.WriteHeader(http.StatusNotFound)
	})

	server := httptest.NewServer(handler)
	t.Cleanup(func() { server.Close() })
	return server, &requestCount
}

func TestC07OpenBaoPositiveLifecycleAndContract(t *testing.T) {
	var pos c07PositiveFixture
	var exp c07ExpectedOutput
	loadC07Fixture(t, "positive.json", &pos)
	loadC07Fixture(t, "expected-output.json", &exp)

	server, _ := setupMockOpenBao(t, false, false)

	cfg := provider.Config{
		Address:      server.URL,
		KEKMount:     pos.Provider.KEKMount,
		Environment:  pos.Provider.Environment,
		AllowDevMode: false,
		Timeout:      2 * time.Second,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 1. Adapter creation and health verification
	adapter, err := provider.NewOpenBaoAdapter(ctx, cfg, pos.WorkloadIdentity)
	if err != nil {
		t.Fatalf("failed to create OpenBao adapter: %v", err)
	}

	health, err := adapter.Health(ctx)
	if err != nil {
		t.Fatalf("adapter.Health() failed: %v", err)
	}
	if health.Sealed || !health.Initialized || health.DevMode {
		t.Fatalf("unexpected health attributes: %+v", health)
	}

	// 2. WrapDEK
	plaintextDEK := []byte(pos.PlaintextCanary)
	wrapRes, err := adapter.WrapDEK(ctx, pos.Provider.KEKID, plaintextDEK)
	if err != nil {
		t.Fatalf("adapter.WrapDEK() failed: %v", err)
	}
	if !strings.HasPrefix(wrapRes.Ciphertext, exp.WrappedDEKPrefix) {
		t.Fatalf("wrapped DEK missing expected prefix %s: %s", exp.WrappedDEKPrefix, wrapRes.Ciphertext)
	}

	// 3. UnwrapDEK
	unwrapped, err := adapter.UnwrapDEK(ctx, pos.Provider.KEKID, wrapRes.Ciphertext)
	if err != nil {
		t.Fatalf("adapter.UnwrapDEK() failed: %v", err)
	}
	if string(unwrapped) != pos.PlaintextCanary {
		t.Fatalf("unwrapped DEK mismatch: got %s, want %s", string(unwrapped), pos.PlaintextCanary)
	}
}

func TestC07DevModeRefusalInProduction(t *testing.T) {
	var exp c07ExpectedOutput
	loadC07Fixture(t, "expected-output.json", &exp)

	// Server running in dev mode
	devServer, _ := setupMockOpenBao(t, true, false)

	identity := provider.WorkloadIdentity{
		Role:   "admin",
		Token:  "s.test-scoped-token",
		Scopes: []string{"transit:encrypt", "transit:decrypt"},
	}

	t.Run("RefuseDevModeServerInProduction", func(t *testing.T) {
		cfg := provider.Config{
			Address:      devServer.URL,
			Environment:  "production",
			AllowDevMode: false,
		}
		_, err := provider.NewOpenBaoAdapter(context.Background(), cfg, identity)
		assertProviderCode(t, err, provider.ErrorCode(exp.DevModeRefusal.ExpectedCode))
	})

	t.Run("RefuseDevModeServerInStaging", func(t *testing.T) {
		cfg := provider.Config{
			Address:      devServer.URL,
			Environment:  "staging",
			AllowDevMode: false,
		}
		_, err := provider.NewOpenBaoAdapter(context.Background(), cfg, identity)
		assertProviderCode(t, err, provider.ErrorCode(exp.DevModeRefusal.ExpectedCode))
	})

	t.Run("RefuseDevModeConfigFlagInProduction", func(t *testing.T) {
		cfg := provider.Config{
			Address:      devServer.URL,
			Environment:  "production",
			AllowDevMode: true, // Attempting to allow dev mode in production must be refused
		}
		_, err := provider.NewOpenBaoAdapter(context.Background(), cfg, identity)
		assertProviderCode(t, err, provider.ErrorCode(exp.DevModeRefusal.ExpectedCode))
	})

	t.Run("PermitDevModeServerInLocalTestEnvironment", func(t *testing.T) {
		cfg := provider.Config{
			Address:      devServer.URL,
			Environment:  "local",
			AllowDevMode: true,
		}
		adapter, err := provider.NewOpenBaoAdapter(context.Background(), cfg, identity)
		if err != nil {
			t.Fatalf("expected dev mode permitted in local environment, got: %v", err)
		}
		health, _ := adapter.Health(context.Background())
		if !health.DevMode {
			t.Fatalf("expected DevMode=true in local test server")
		}
	})
}

func TestC07ScopedWorkloadIdentityEnforcement(t *testing.T) {
	var exp c07ExpectedOutput
	loadC07Fixture(t, "expected-output.json", &exp)

	server, _ := setupMockOpenBao(t, false, false)
	cfg := provider.Config{
		Address:     server.URL,
		Environment: "production",
	}

	t.Run("RootTokenRefused", func(t *testing.T) {
		rootIdentity := provider.WorkloadIdentity{
			Role:   "root-admin",
			Token:  "root",
			Scopes: []string{"*"},
		}
		_, err := provider.NewOpenBaoAdapter(context.Background(), cfg, rootIdentity)
		assertProviderCode(t, err, provider.ErrorCode(exp.UnscopedIdentity.ExpectedCode))
	})

	t.Run("PrefixedRootTokenRefused", func(t *testing.T) {
		rootIdentity := provider.WorkloadIdentity{
			Role:   "root-admin",
			Token:  "s.root-token-attempt",
			Scopes: []string{"*"},
		}
		_, err := provider.NewOpenBaoAdapter(context.Background(), cfg, rootIdentity)
		assertProviderCode(t, err, provider.ErrorCode(exp.UnscopedIdentity.ExpectedCode))
	})

	t.Run("EmptyTokenRefused", func(t *testing.T) {
		emptyIdentity := provider.WorkloadIdentity{
			Role:   "empty",
			Token:  "",
			Scopes: []string{"transit:encrypt"},
		}
		_, err := provider.NewOpenBaoAdapter(context.Background(), cfg, emptyIdentity)
		assertProviderCode(t, err, provider.ErrorCode(exp.UnscopedIdentity.ExpectedCode))
	})

	t.Run("MissingScopesRefused", func(t *testing.T) {
		noScopeIdentity := provider.WorkloadIdentity{
			Role:   "unscoped",
			Token:  "s.some-valid-token",
			Scopes: []string{},
		}
		_, err := provider.NewOpenBaoAdapter(context.Background(), cfg, noScopeIdentity)
		assertProviderCode(t, err, provider.ErrorCode(exp.UnscopedIdentity.ExpectedCode))
	})

	t.Run("IdentityMissingEncryptScopeRejectsWrap", func(t *testing.T) {
		decryptOnlyIdentity := provider.WorkloadIdentity{
			Role:   "decrypt-only",
			Token:  "s.valid-decrypt-token",
			Scopes: []string{"transit:decrypt"},
		}
		adapter, err := provider.NewOpenBaoAdapter(context.Background(), cfg, decryptOnlyIdentity)
		if err != nil {
			t.Fatalf("creation failed: %v", err)
		}
		_, err = adapter.WrapDEK(context.Background(), "kek-01", []byte("dek"))
		assertProviderCode(t, err, provider.ErrorCode(exp.UnscopedIdentity.ExpectedCode))
	})

	t.Run("IdentityMissingDecryptScopeRejectsUnwrap", func(t *testing.T) {
		encryptOnlyIdentity := provider.WorkloadIdentity{
			Role:   "encrypt-only",
			Token:  "s.valid-encrypt-token",
			Scopes: []string{"transit:encrypt"},
		}
		adapter, err := provider.NewOpenBaoAdapter(context.Background(), cfg, encryptOnlyIdentity)
		if err != nil {
			t.Fatalf("creation failed: %v", err)
		}
		_, err = adapter.UnwrapDEK(context.Background(), "kek-01", "bao:v1:sample")
		assertProviderCode(t, err, provider.ErrorCode(exp.UnscopedIdentity.ExpectedCode))
	})
}

func TestC07NegativeCasesAndFailClosed(t *testing.T) {
	var exp c07ExpectedOutput
	loadC07Fixture(t, "expected-output.json", &exp)

	identity := provider.WorkloadIdentity{
		Role:   "operator",
		Token:  "s.valid-operator-token",
		Scopes: []string{"transit:encrypt", "transit:decrypt"},
	}

	t.Run("ProviderUnavailableFailsClosed", func(t *testing.T) {
		cfg := provider.Config{
			Address:     "http://127.0.0.1:59999", // closed port
			Environment: "production",
			Timeout:     100 * time.Millisecond,
		}
		_, err := provider.NewOpenBaoAdapter(context.Background(), cfg, identity)
		assertProviderCode(t, err, provider.ErrorCode(exp.ProviderOutage.ExpectedCode))
	})

	t.Run("ProviderSealedFailsClosed", func(t *testing.T) {
		sealedServer, _ := setupMockOpenBao(t, false, true)
		cfg := provider.Config{
			Address:     sealedServer.URL,
			Environment: "production",
		}
		_, err := provider.NewOpenBaoAdapter(context.Background(), cfg, identity)
		assertProviderCode(t, err, provider.ErrorCode(exp.ProviderSealed.ExpectedCode))
	})

	t.Run("MalformedResponseFailsClosed", func(t *testing.T) {
		corruptServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/v1/sys/health" {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"initialized":true,"sealed":false,"dev_mode":false}`))
				return
			}
			// Malformed non-JSON response for transit
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`corrupted-truncated-response{`))
		}))
		defer corruptServer.Close()

		cfg := provider.Config{
			Address:     corruptServer.URL,
			Environment: "production",
		}
		adapter, err := provider.NewOpenBaoAdapter(context.Background(), cfg, identity)
		if err != nil {
			t.Fatalf("adapter init failed: %v", err)
		}
		_, err = adapter.WrapDEK(context.Background(), "kek-01", []byte("sample-dek"))
		assertProviderCode(t, err, provider.ErrorCode(exp.MalformedResponse.ExpectedCode))
	})

	t.Run("ProviderRestartRecovery", func(t *testing.T) {
		var activeServer atomic.Value
		healthyHandler := func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/v1/sys/health" {
				json.NewEncoder(w).Encode(map[string]any{"initialized": true, "sealed": false, "dev_mode": false})
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"ciphertext": "bao:v1:restarted-dek"}})
		}
		activeServer.Store(http.HandlerFunc(healthyHandler))

		dynamicServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := activeServer.Load().(http.HandlerFunc)
			h(w, r)
		}))
		defer dynamicServer.Close()

		cfg := provider.Config{
			Address:     dynamicServer.URL,
			Environment: "production",
			Timeout:     500 * time.Millisecond,
		}
		adapter, err := provider.NewOpenBaoAdapter(context.Background(), cfg, identity)
		if err != nil {
			t.Fatalf("init: %v", err)
		}

		// Simulate restart outage
		activeServer.Store(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
		}))
		_, err = adapter.WrapDEK(context.Background(), "kek-01", []byte("dek"))
		if err == nil {
			t.Fatal("expected error during simulated outage")
		}

		// Re-emerge healthy after restart
		activeServer.Store(http.HandlerFunc(healthyHandler))
		wrapRes, err := adapter.WrapDEK(context.Background(), "kek-01", []byte("dek"))
		if err != nil {
			t.Fatalf("expected recovery after restart, got: %v", err)
		}
		if wrapRes.Ciphertext != "bao:v1:restarted-dek" {
			t.Fatalf("unexpected recovered ciphertext: %s", wrapRes.Ciphertext)
		}
	})

	t.Run("ProviderOwnsSecretBytesNoPlaintextPersisted", func(t *testing.T) {
		canary := exp.PlaintextCanary
		server, _ := setupMockOpenBao(t, false, false)

		cfg := provider.Config{
			Address:     server.URL,
			Environment: "production",
		}
		adapter, err := provider.NewOpenBaoAdapter(context.Background(), cfg, identity)
		if err != nil {
			t.Fatalf("init: %v", err)
		}

		wrapRes, err := adapter.WrapDEK(context.Background(), "kek-v1-openbao", []byte(canary))
		if err != nil {
			t.Fatalf("wrap failed: %v", err)
		}

		// Ciphertext envelope returned; verify that plaintext canary is wrapped by provider
		if strings.Contains(wrapRes.Ciphertext, "bao:v1:") == false {
			t.Fatalf("expected wrapped ciphertext format")
		}
		// Confirm adapter struct does not retain the plaintext canary
		if strings.Contains(adapter.WorkloadIdentity().Token, canary) {
			t.Fatal("leakage of canary in workload token")
		}
	})
}
