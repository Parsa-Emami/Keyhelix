package health

import (
	"context"
	"errors"
	"testing"

	"github.com/parsa-emami/keyhelix/internal/audit"
	"github.com/parsa-emami/keyhelix/internal/provider"
)

type stubProvider struct {
	health *provider.Health
	err    error
}

func (s *stubProvider) Health(ctx context.Context) (*provider.Health, error) {
	return s.health, s.err
}

type stubAuditor struct {
	err error
}

func (s *stubAuditor) Record(ctx context.Context, envelope audit.EventEnvelope) error {
	return s.err
}

func TestMonitorCheckAndStrictAuditedReveal(t *testing.T) {
	ctx := context.Background()

	// 1. Healthy provider and audit pipeline
	mon := NewMonitor(&stubProvider{health: &provider.Health{Version: "2.2.2", Sealed: false}}, &stubAuditor{})
	status, err := mon.Check(ctx)
	if err != nil {
		t.Fatalf("expected healthy check, got err: %v", err)
	}
	if status.State != StatusHealthy || !status.AuditReady {
		t.Fatalf("unexpected status: %+v", status)
	}

	out, err := mon.ExecuteStrictAuditedReveal(ctx, func() ([]byte, error) {
		return []byte("secret-value"), nil
	}, func(outcome string) error {
		if outcome != "success" {
			t.Fatalf("expected outcome=success, got %s", outcome)
		}
		return nil
	})
	if err != nil || string(out) != "secret-value" {
		t.Fatalf("expected successful reveal, got out=%q err=%v", string(out), err)
	}

	// 2. Audit failure must zero plaintext and fail closed
	buf := []byte("sensitive-plaintext")
	_, err = mon.ExecuteStrictAuditedReveal(ctx, func() ([]byte, error) {
		return buf, nil
	}, func(outcome string) error {
		return errors.New("audit sink down")
	})
	if err == nil {
		t.Fatal("expected error when audit recording fails")
	}
	for i, b := range buf {
		if b != 0 {
			t.Fatalf("expected plaintext buffer to be zeroed at index %d", i)
		}
	}

	// 3. Sealed provider fails closed
	sealedMon := NewMonitor(&stubProvider{health: &provider.Health{Version: "2.2.2", Sealed: true}}, &stubAuditor{})
	if _, err := sealedMon.Check(ctx); err == nil {
		t.Fatal("expected error for sealed provider")
	}
}
