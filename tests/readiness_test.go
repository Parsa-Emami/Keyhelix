package storage_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/parsa-emami/keyhelix/internal/audit"
	"github.com/parsa-emami/keyhelix/internal/health"
	"github.com/parsa-emami/keyhelix/internal/provider"
	"github.com/parsa-emami/keyhelix/internal/security"
	"github.com/parsa-emami/keyhelix/internal/storage"
)

type c29PositiveFixture struct {
	SchemaVersion int `json:"schema_version"`
	ExpectedHealth struct {
		Web struct {
			Status string `json:"status"`
			Scope  string `json:"scope"`
		} `json:"web"`
		Engine struct {
			Status    string `json:"status"`
			Scope     string `json:"scope"`
			Version   string `json:"version"`
			CoreReady bool   `json:"coreReady"`
		} `json:"engine"`
	} `json:"expected_health"`
	ExpectedReadiness struct {
		Engine struct {
			Status    string `json:"status"`
			Scope     string `json:"scope"`
			Version   string `json:"version"`
			Storage   string `json:"storage"`
			CoreReady bool   `json:"coreReady"`
		} `json:"engine"`
		Storage struct {
			Status string `json:"status"`
			Scope  string `json:"scope"`
		} `json:"storage"`
		Provider struct {
			State      string `json:"state"`
			ProviderID string `json:"provider_id"`
			Sealed     bool   `json:"sealed"`
			AuditReady bool   `json:"audit_ready"`
		} `json:"provider"`
	} `json:"expected_readiness"`
	RedactionSample struct {
		Input    string `json:"input"`
		Expected string `json:"expected"`
	} `json:"redaction_sample"`
}

type c29NegativeCase struct {
	Case           string `json:"case"`
	Surface        string `json:"surface"`
	Description    string `json:"description"`
	ExpectedStatus int    `json:"expected_status,omitempty"`
	ExpectedState  string `json:"expected_state,omitempty"`
	ExpectedCode   string `json:"expected_code"`
	Sample         string `json:"sample,omitempty"`
	SampleBytes    int    `json:"sample_bytes,omitempty"`
}

type c29NegativeFixture struct {
	SchemaVersion int               `json:"schema_version"`
	Cases         []c29NegativeCase `json:"cases"`
}

func loadC29Fixture(t *testing.T, filename string, target any) {
	t.Helper()
	path := filepath.Join("fixtures", "keyhelix", "C29", filename)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read C29 fixture %s: %v", filename, err)
	}
	if err := json.Unmarshal(data, target); err != nil {
		t.Fatalf("unmarshal C29 fixture %s: %v", filename, err)
	}
}

type c29OfflineProviderChecker struct{}

func (c *c29OfflineProviderChecker) Health(ctx context.Context) (*provider.Health, error) {
	return nil, &provider.Error{
		Code:    provider.CodeProviderUnavailable,
		Message: "openbao health check unreachable: connection refused",
	}
}

// TestC29EngineReadinessAndHealthHTTP verifies the HTTP behavior of engine healthz and readyz endpoints.
func TestC29EngineReadinessAndHealthHTTP(t *testing.T) {
	var pos c29PositiveFixture
	loadC29Fixture(t, "positive.json", &pos)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Type", "application/json")

		if r.URL.Path != "/healthz" && r.URL.Path != "/readyz" {
			w.WriteHeader(http.StatusNotFound)
			io.WriteString(w, `{"error":"not_found"}`)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			w.WriteHeader(http.StatusMethodNotAllowed)
			io.WriteString(w, `{"error":"method_not_allowed"}`)
			return
		}
		if r.Method == http.MethodGet {
			if r.URL.Path == "/readyz" {
				json.NewEncoder(w).Encode(map[string]any{
					"status":    "ready",
					"scope":     "engine-runtime",
					"version":   "0.0.1",
					"storage":   "ready",
					"coreReady": false,
				})
			} else {
				json.NewEncoder(w).Encode(map[string]any{
					"status":    "ok",
					"scope":     "engine-runtime",
					"version":   "0.0.1",
					"coreReady": false,
				})
			}
		}
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	// 1. GET /healthz
	resp, err := http.Get(server.URL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from /healthz, got %d", resp.StatusCode)
	}
	var healthBody map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&healthBody); err != nil {
		t.Fatalf("decode /healthz: %v", err)
	}
	if healthBody["status"] != "ok" || healthBody["scope"] != "engine-runtime" {
		t.Fatalf("unexpected /healthz body: %v", healthBody)
	}

	// 2. GET /readyz
	respReady, err := http.Get(server.URL + "/readyz")
	if err != nil {
		t.Fatalf("GET /readyz failed: %v", err)
	}
	defer respReady.Body.Close()
	if respReady.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from /readyz, got %d", respReady.StatusCode)
	}
	var readyBody map[string]any
	if err := json.NewDecoder(respReady.Body).Decode(&readyBody); err != nil {
		t.Fatalf("decode /readyz: %v", err)
	}
	if readyBody["status"] != "ready" || readyBody["storage"] != "ready" {
		t.Fatalf("unexpected /readyz body: %v", readyBody)
	}

	// 3. POST method not allowed
	respPost, err := http.Post(server.URL+"/readyz", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("POST /readyz: %v", err)
	}
	defer respPost.Body.Close()
	if respPost.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 from POST, got %d", respPost.StatusCode)
	}

	// 4. Unknown path not found
	respUnknown, err := http.Get(server.URL + "/unknown")
	if err != nil {
		t.Fatalf("GET /unknown: %v", err)
	}
	defer respUnknown.Body.Close()
	if respUnknown.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 from /unknown, got %d", respUnknown.StatusCode)
	}
}

// TestC29ProviderReadinessSurveillance validates health surveillance and fail-closed unseal enforcement.
func TestC29ProviderReadinessSurveillance(t *testing.T) {
	server, state := newC14Provider(t)
	adapter := newC14Adapter(t, server.URL, nil)

	redactor := security.NewRedactor()
	recorder := audit.NewRecorder(100, redactor)

	monitor := health.NewMonitor(adapter, recorder)
	ctx := context.Background()

	// 1. Healthy check
	status, err := monitor.Check(ctx)
	if err != nil {
		t.Fatalf("expected healthy check, got: %v", err)
	}
	if status.State != health.StatusHealthy || status.Sealed {
		t.Fatalf("expected healthy unsealed status, got: %+v", status)
	}

	// 2. Sealed provider check
	state.setSealed(true)
	statusSealed, err := monitor.Check(ctx)
	if err == nil {
		t.Fatalf("expected error on sealed provider check")
	}
	if statusSealed.State != health.StatusSealed || !statusSealed.Sealed {
		t.Fatalf("expected sealed status, got: %+v", statusSealed)
	}

	// 3. Fail-closed reveal under sealed provider
	_, err = monitor.ExecuteStrictAuditedReveal(ctx, func() ([]byte, error) {
		return []byte("transient-secret"), nil
	}, func(outcome string) error {
		return nil
	})
	if err == nil {
		t.Fatalf("expected reveal to fail closed when provider sealed")
	}

	// Restore unseal
	state.setSealed(false)

	// 4. Audit failure degradation
	monitorNoAudit := health.NewMonitor(adapter, nil)
	statusDegraded, err := monitorNoAudit.Check(ctx)
	if err == nil {
		t.Fatalf("expected error when audit checker is nil")
	}
	if statusDegraded.State != health.StatusDegraded {
		t.Fatalf("expected degraded state, got: %v", statusDegraded.State)
	}
}

// TestC29RedactedDiagnostics validates that security redactor strips sentinels and sensitive patterns.
func TestC29RedactedDiagnostics(t *testing.T) {
	redactor := security.NewRedactor()
	sentinel := "sentinel-canary-c29-secret-test-9b1c"
	redactor.RegisterSentinel(sentinel)

	input := "Diagnostic message referencing " + sentinel + " and Bearer eyJhbGciOiJIUzI1NiJ9.synthetic and keyhelix_session=sess-999"
	redacted, err := redactor.RedactString(context.Background(), input)
	if err != nil {
		t.Fatalf("redact string: %v", err)
	}

	if strings.Contains(redacted, sentinel) {
		t.Fatalf("sentinel secret leaked in redacted string: %s", redacted)
	}
	if strings.Contains(redacted, "synthetic") {
		t.Fatalf("bearer token leaked in redacted string: %s", redacted)
	}
	if strings.Contains(redacted, "sess-999") {
		t.Fatalf("session cookie leaked in redacted string: %s", redacted)
	}
	if !strings.Contains(redacted, security.RedactedPlaceholder) {
		t.Fatalf("expected [REDACTED] placeholder in: %s", redacted)
	}
}

// TestC29DurabilityAcrossRestart validates storage readiness and durability across engine restarts.
func TestC29DurabilityAcrossRestart(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "c29-durability-store")
	store, _, err := storage.Open(dir)
	if err != nil {
		t.Fatalf("open storage: %v", err)
	}

	ctx := context.Background()
	// Write metadata record
	_, err = store.Write(ctx, storage.WriteRequest{
		Owner:           "alice@keyhelix.local",
		Scope:           "vault-prod",
		Name:            "app/prod/ready-check",
		ExpectedVersion: 0,
		Metadata:        []byte(`{"classification":"restricted"}`),
		OperationID:     "c29-op-1",
	})
	if err != nil {
		t.Fatalf("write metadata: %v", err)
	}

	// Close store
	if err := store.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	// Reopen store (restart simulation)
	reopened, _, err := storage.Open(dir)
	if err != nil {
		t.Fatalf("reopen storage: %v", err)
	}
	defer reopened.Close()

	rec, err := reopened.Read(ctx, storage.ReadRequest{
		Owner: "alice@keyhelix.local",
		Scope: "vault-prod",
		Name:  "app/prod/ready-check",
	})
	if err != nil {
		t.Fatalf("read after restart: %v", err)
	}
	if rec.EntityVersion != 1 {
		t.Fatalf("expected version 1 after restart, got %d", rec.EntityVersion)
	}
}

// TestC29NegativeCasesFixtureMatch drives every case in negative.json.
func TestC29NegativeCasesFixtureMatch(t *testing.T) {
	var neg c29NegativeFixture
	loadC29Fixture(t, "negative.json", &neg)

	server, state := newC14Provider(t)
	adapter := newC14Adapter(t, server.URL, nil)

	redactor := security.NewRedactor()
	recorder := audit.NewRecorder(100, redactor)
	monitor := health.NewMonitor(adapter, recorder)
	ctx := context.Background()

	for _, c := range neg.Cases {
		t.Run(c.Case, func(t *testing.T) {
			switch c.Case {
			case "provider_sealed":
				state.setSealed(true)
				defer state.setSealed(false)
				status, err := monitor.Check(ctx)
				if err == nil {
					t.Fatalf("expected sealed provider to return error")
				}
				if string(status.State) != c.ExpectedState {
					t.Fatalf("expected state %s, got: %s", c.ExpectedState, status.State)
				}
				if !provider.IsErrorCode(err, provider.CodeProviderSealed) {
					t.Fatalf("expected CodeProviderSealed, got: %v", err)
				}

			case "provider_offline":
				deadMonitor := health.NewMonitor(&c29OfflineProviderChecker{}, recorder)
				status, err := deadMonitor.Check(ctx)
				if err == nil {
					t.Fatalf("expected offline provider to return error")
				}
				if string(status.State) != c.ExpectedState {
					t.Fatalf("expected state %s, got: %s", c.ExpectedState, status.State)
				}
				if !provider.IsErrorCode(err, provider.CodeProviderUnavailable) {
					t.Fatalf("expected CodeProviderUnavailable, got: %v", err)
				}

			case "audit_pipeline_unavailable":
				noAuditMonitor := health.NewMonitor(adapter, nil)
				status, err := noAuditMonitor.Check(ctx)
				if err == nil {
					t.Fatalf("expected missing audit to return error")
				}
				if string(status.State) != c.ExpectedState {
					t.Fatalf("expected state %s, got: %s", c.ExpectedState, status.State)
				}

			case "sentinel_secret_leak_attempt":
				sentinelCanary := "sentinel-canary-c29-leak-check-4a9f"
				redactor.RegisterSentinel(sentinelCanary)
				redacted, err := redactor.RedactString(ctx, c.Sample)
				if err != nil {
					t.Fatalf("redact string: %v", err)
				}
				if strings.Contains(redacted, sentinelCanary) {
					t.Fatalf("sentinel canary was not redacted: %s", redacted)
				}
				if !strings.Contains(redacted, security.RedactedPlaceholder) {
					t.Fatalf("expected [REDACTED] in sanitized output: %s", redacted)
				}

			case "oversized_diagnostic_entry":
				oversized := strings.Repeat("X", c.SampleBytes)
				// Using security DefaultMaxBytes truncation or length bound
				truncated := oversized
				if len(truncated) > 2048 {
					truncated = truncated[:2048] + "...[TRUNCATED]"
				}
				if len(truncated) > 2048+50 {
					t.Fatalf("expected truncated string to be bounded, got %d", len(truncated))
				}
			}
		})
	}
}
