package rotation_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/parsa-emami/keyhelix/internal/auth"
	"github.com/parsa-emami/keyhelix/internal/rotation"
	"github.com/parsa-emami/keyhelix/internal/storage"
)

func TestStateTransitions(t *testing.T) {
	validTransitions := [][2]rotation.State{
		{"", rotation.StatePlanned},
		{rotation.StatePlanned, rotation.StateRewrapping},
		{rotation.StateRewrapping, rotation.StateRewrapping},
		{rotation.StateRewrapping, rotation.StateVerifying},
		{rotation.StateVerifying, rotation.StateComplete},
		{rotation.StateRewrapping, rotation.StateFailedRollback},
		{rotation.StateFailedRollback, rotation.StateRewrapping},
	}
	for _, pair := range validTransitions {
		if err := rotation.ValidateTransition(pair[0], pair[1]); err != nil {
			t.Fatalf("expected valid transition %s -> %s, got: %v", pair[0], pair[1], err)
		}
	}

	illegalTransitions := [][2]rotation.State{
		{rotation.StatePlanned, rotation.StateComplete},
		{rotation.StateComplete, rotation.StateRewrapping},
		{rotation.StatePlanned, rotation.StateVerifying},
	}
	for _, pair := range illegalTransitions {
		if err := rotation.ValidateTransition(pair[0], pair[1]); err == nil {
			t.Fatalf("expected illegal transition %s -> %s to fail", pair[0], pair[1])
		}
	}
}

func TestStartOrResumeRequiresPrerequisitesAndStepUp(t *testing.T) {
	ctx := context.Background()
	store, _, err := storage.Open(filepath.Join(t.TempDir(), "rot-unit"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	// Missing provider fails closed
	svcNoProvider := rotation.NewService(nil, nil, store, nil)
	_, err = svcNoProvider.StartOrResumeRotation(ctx, rotation.StartOrResumeRequest{
		JobID:            "job-001",
		VaultID:          "vault-prod",
		TargetKEKVersion: "v2",
		SecretPaths:      []string{"production/services/payment/api-key"},
		OperatorIdent: &auth.Identity{
			Subject:   "usr_alice",
			Email:     "alice@keyhelix.local",
			ExpiresAt: time.Now().Add(time.Hour).Unix(),
		},
	})
	if err == nil {
		t.Fatalf("expected failure when provider is nil")
	}
}
