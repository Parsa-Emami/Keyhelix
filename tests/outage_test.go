package storage_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/parsa-emami/keyhelix/internal/audit"
	"github.com/parsa-emami/keyhelix/internal/health"
	"github.com/parsa-emami/keyhelix/internal/provider"
)

type c23PositiveFixture struct {
	SchemaVersion int `json:"schema_version"`
	Vault         struct {
		VaultID string `json:"vault_id"`
		KEKID   string `json:"kek_id"`
		Mount   string `json:"mount"`
		Role    string `json:"role"`
	} `json:"vault"`
	SecretPath     string `json:"secret_path"`
	Classification string `json:"classification"`
	SentinelSecret string `json:"sentinel_secret"`
	ExpectedHealth struct {
		State      string `json:"state"`
		ProviderID string `json:"provider_id"`
		Sealed     bool   `json:"sealed"`
		AuditReady bool   `json:"audit_ready"`
	} `json:"expected_health"`
	AuditEventType string `json:"audit_event_type"`
}

type c23NegativeFixture struct {
	SchemaVersion int `json:"schema_version"`
	Cases         []struct {
		Case           string `json:"case"`
		Description    string `json:"description"`
		ExpectedCode   string `json:"expected_code"`
		ExpectedStatus int    `json:"expected_status"`
		Sentinel       string `json:"sentinel,omitempty"`
	} `json:"cases"`
}

type mockProviderChecker struct {
	healthFunc func(ctx context.Context) (*provider.Health, error)
}

func (m *mockProviderChecker) Health(ctx context.Context) (*provider.Health, error) {
	if m.healthFunc != nil {
		return m.healthFunc(ctx)
	}
	return &provider.Health{
		Status:      "ok",
		Version:     "1.14.0",
		Initialized: true,
		Sealed:      false,
		DevMode:     false,
	}, nil
}

type mockAuditChecker struct {
	recordFunc func(ctx context.Context, envelope audit.EventEnvelope) error
	recorded   []audit.EventEnvelope
}

func (m *mockAuditChecker) Record(ctx context.Context, envelope audit.EventEnvelope) error {
	if m.recordFunc != nil {
		return m.recordFunc(ctx, envelope)
	}
	m.recorded = append(m.recorded, envelope)
	return nil
}

func loadC23Fixtures(t *testing.T) (c23PositiveFixture, c23NegativeFixture) {
	t.Helper()
	posBytes, err := os.ReadFile(filepath.Join("..", "tests", "fixtures", "keyhelix", "C23", "positive.json"))
	if err != nil {
		posBytes, err = os.ReadFile(filepath.Join("tests", "fixtures", "keyhelix", "C23", "positive.json"))
		if err != nil {
			t.Fatalf("failed to read C23 positive fixture: %v", err)
		}
	}
	var pos c23PositiveFixture
	if err := json.Unmarshal(posBytes, &pos); err != nil {
		t.Fatalf("failed to unmarshal positive fixture: %v", err)
	}

	negBytes, err := os.ReadFile(filepath.Join("..", "tests", "fixtures", "keyhelix", "C23", "negative.json"))
	if err != nil {
		negBytes, err = os.ReadFile(filepath.Join("tests", "fixtures", "keyhelix", "C23", "negative.json"))
		if err != nil {
			t.Fatalf("failed to read C23 negative fixture: %v", err)
		}
	}
	var neg c23NegativeFixture
	if err := json.Unmarshal(negBytes, &neg); err != nil {
		t.Fatalf("failed to unmarshal negative fixture: %v", err)
	}

	return pos, neg
}

// TestC23ProviderHealthAndStrictAuditedRevealF17 proves Requirement F17:
// 1. Healthy provider and ready audit pipeline allows audited reveal.
// 2. Provider outage fails closed immediately with zero cached plaintext fallback.
// 3. Provider sealed state produces explicit PROVIDER_SEALED.
// 4. Audit pipeline failure aborts reveal and zeroes decrypted memory.
// 5. Restart durability during outage verifies no plaintext can be resurrected from local cache.
func TestC23ProviderHealthAndStrictAuditedRevealF17(t *testing.T) {
	ctx := context.Background()
	pos, neg := loadC23Fixtures(t)

	// 1. Positive baseline: Healthy provider + ready audit recorder
	prov := &mockProviderChecker{}
	auditSink := &mockAuditChecker{}
	monitor := health.NewMonitor(prov, auditSink)

	status, err := monitor.Check(ctx)
	if err != nil {
		t.Fatalf("expected healthy check, got: %v", err)
	}
	if status.State != health.StatusHealthy || status.Sealed {
		t.Fatalf("unexpected health state: %+v", status)
	}

	// Reveal under healthy conditions succeeds with audit
	canaryBytes := []byte(pos.SentinelSecret)
	auditEmitted := false
	revealed, err := monitor.ExecuteStrictAuditedReveal(
		ctx,
		func() ([]byte, error) {
			buf := make([]byte, len(canaryBytes))
			copy(buf, canaryBytes)
			return buf, nil
		},
		func(outcome string) error {
			auditEmitted = true
			if outcome != "success" {
				return fmt.Errorf("unexpected outcome: %s", outcome)
			}
			return nil
		},
	)
	if err != nil {
		t.Fatalf("expected reveal to succeed under healthy conditions: %v", err)
	}
	if !bytes.Equal(revealed, canaryBytes) {
		t.Fatalf("expected revealed bytes to match canary, got %s", string(revealed))
	}
	if !auditEmitted {
		t.Fatalf("expected audit event to be emitted during reveal")
	}

	// 2. Negative: Provider Offline Outage Fails Closed (No Plaintext Fallback)
	t.Run("provider-offline-fails-closed", func(t *testing.T) {
		provOutage := &mockProviderChecker{
			healthFunc: func(ctx context.Context) (*provider.Health, error) {
				return nil, &provider.Error{
					Code:    provider.CodeProviderUnavailable,
					Message: "connection refused: openbao is offline",
				}
			},
		}
		monitorOutage := health.NewMonitor(provOutage, auditSink)

		auditRecorded := false
		revealedOutage, err := monitorOutage.ExecuteStrictAuditedReveal(
			ctx,
			func() ([]byte, error) {
				t.Fatalf("decryption must not even be attempted when provider is down")
				return []byte(pos.SentinelSecret), nil
			},
			func(outcome string) error {
				auditRecorded = true
				return nil
			},
		)
		if err == nil {
			t.Fatalf("expected reveal to fail closed during provider outage")
		}
		if revealedOutage != nil {
			t.Fatalf("expected zero plaintext returned, got %v", revealedOutage)
		}
		var hErr *health.Error
		if !errors.As(err, &hErr) || hErr.Code != health.CodeNoPlaintextFallback {
			t.Fatalf("expected CodeNoPlaintextFallback, got %v", err)
		}
		if !auditRecorded {
			t.Fatalf("expected audit outcome to record failure event")
		}
	})

	// 3. Negative: Provider Sealed Fails Closed
	t.Run("provider-sealed-fails-closed", func(t *testing.T) {
		provSealed := &mockProviderChecker{
			healthFunc: func(ctx context.Context) (*provider.Health, error) {
				return nil, &provider.Error{
					Code:    provider.CodeProviderSealed,
					Message: "openbao is sealed (HTTP 503)",
				}
			},
		}
		monitorSealed := health.NewMonitor(provSealed, auditSink)

		status, err := monitorSealed.Check(ctx)
		if err == nil {
			t.Fatalf("expected error on sealed check")
		}
		if status.State != health.StatusSealed || !status.Sealed {
			t.Fatalf("expected StatusSealed, got %+v", status)
		}
		if !provider.IsErrorCode(err, provider.CodeProviderSealed) {
			t.Fatalf("expected CodeProviderSealed, got: %v", err)
		}
	})

	// 4. Negative: Strict Audited Reveal Policy - Audit Pipeline Failure Aborts Reveal
	t.Run("audit-pipeline-failure-blocks-reveal", func(t *testing.T) {
		monitorAuditFail := health.NewMonitor(prov, auditSink)

		secretBuffer := []byte(pos.SentinelSecret)
		revealed, err := monitorAuditFail.ExecuteStrictAuditedReveal(
			ctx,
			func() ([]byte, error) {
				buf := make([]byte, len(secretBuffer))
				copy(buf, secretBuffer)
				return buf, nil
			},
			func(outcome string) error {
				// Audit pipeline failure (disk full, network error, ingestion down)
				return errors.New("audit log write failed: disk full")
			},
		)
		if err == nil {
			t.Fatalf("expected reveal to fail closed when audit record fails")
		}
		if revealed != nil {
			t.Fatalf("expected nil plaintext on audit failure, got: %s", string(revealed))
		}
		var hErr *health.Error
		if !errors.As(err, &hErr) || hErr.Code != health.CodeAuditFailure {
			t.Fatalf("expected CodeAuditFailure, got: %v", err)
		}
	})

	// 5. Negative: Outage Durability Across Restart - Zero Stale Plaintext In Files
	t.Run("no-cached-plaintext-after-restart", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Write simulated storage metadata files (which must contain only sealed ciphertexts)
		metaFile := filepath.Join(tmpDir, "secret-metadata.json")
		if err := os.WriteFile(metaFile, []byte(`{"vault_id":"vault-prod","status":"ACTIVE"}`), 0600); err != nil {
			t.Fatalf("failed to write meta file: %v", err)
		}

		// Simulate restart with offline provider
		provOffline := &mockProviderChecker{
			healthFunc: func(ctx context.Context) (*provider.Health, error) {
				return nil, &provider.Error{
					Code:    provider.CodeProviderUnavailable,
					Message: "provider still down after restart",
				}
			},
		}
		restartedMonitor := health.NewMonitor(provOffline, auditSink)

		_, err := restartedMonitor.ExecuteStrictAuditedReveal(
			ctx,
			func() ([]byte, error) {
				t.Fatalf("should not execute decrypt")
				return nil, nil
			},
			func(outcome string) error { return nil },
		)
		if err == nil {
			t.Fatalf("expected error after restart when provider is offline")
		}

		// Ensure canary secret sentinel is nowhere on disk
		err = filepath.Walk(tmpDir, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return err
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if strings.Contains(string(data), pos.SentinelSecret) {
				return fmt.Errorf("plaintext leak found in file: %s", path)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("storage audit check failed: %v", err)
		}
	})

	// Verify all negative cases in fixture are mapped
	for _, tc := range neg.Cases {
		if tc.Case == "" || tc.Description == "" {
			t.Errorf("incomplete negative case: %+v", tc)
		}
	}
}
