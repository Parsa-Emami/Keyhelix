package secrets

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/parsa-emami/keyhelix/internal/auth"
	"github.com/parsa-emami/keyhelix/internal/provider"
	"github.com/parsa-emami/keyhelix/internal/storage"
)

type mockKeyProvider struct {
	fail bool
}

func (m *mockKeyProvider) WrapDEK(ctx context.Context, kekID string, plaintextDEK []byte) (*provider.WrapResult, error) {
	if m.fail {
		return nil, &provider.Error{Code: provider.CodeProviderUnavailable, Message: "OpenBao offline"}
	}
	return &provider.WrapResult{
		Ciphertext: "bao:v1:wrapped-test-dek",
		KEKVersion: 1,
	}, nil
}

func (m *mockKeyProvider) UnwrapDEK(ctx context.Context, kekID string, ciphertext string) ([]byte, error) {
	return []byte("01234567890123456789012345678901"), nil
}

func (m *mockKeyProvider) PutSealedPayload(ctx context.Context, ref provider.SealedRef, sealed []byte) error {
	if m.fail {
		return &provider.Error{Code: provider.CodeProviderUnavailable, Message: "OpenBao offline"}
	}
	return nil
}

func (m *mockKeyProvider) ReadSealedPayload(ctx context.Context, ref provider.SealedRef) ([]byte, error) {
	if m.fail {
		return nil, &provider.Error{Code: provider.CodeProviderUnavailable, Message: "OpenBao offline"}
	}
	return nil, &provider.Error{Code: provider.CodePayloadNotFound, Message: "mock provider stores no payload"}
}

func (m *mockKeyProvider) Health(ctx context.Context) (*provider.Health, error) {
	if m.fail {
		return nil, errors.New("unhealthy")
	}
	return &provider.Health{Status: "ok"}, nil
}

func (m *mockKeyProvider) WorkloadIdentity() provider.WorkloadIdentity {
	return provider.WorkloadIdentity{}
}

func TestWriteSecretCASAndBytesNeverStored(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "secrets-store")
	store, _, err := storage.Open(dir)
	if err != nil {
		t.Fatalf("failed to open storage: %v", err)
	}
	defer store.Close()

	prov := &mockKeyProvider{fail: false}
	svc := NewService(nil, prov, store)

	canary := "VERY_SECRET_PLAINTEXT_CANARY_VALUE_12345"

	// 1. Initial write with ExpectedVersion = 0 (Create)
	outcome1, err := svc.WriteSecret(context.Background(), WriteRequest{
		VaultID:         "vlt-1",
		SecretPath:      "prod/db/pass",
		ExpectedVersion: 0,
		Plaintext:       []byte(canary),
		KEKID:           "kek-1",
		Owner:           "team-data",
		OperationID:     "op-init-secret-01",
	})
	if err != nil {
		t.Fatalf("initial write failed: %v", err)
	}
	if outcome1.Version != 1 {
		t.Fatalf("expected version 1, got %d", outcome1.Version)
	}

	// 2. Duplicate create with ExpectedVersion = 0 must fail with CodeAlreadyExists
	_, err = svc.WriteSecret(context.Background(), WriteRequest{
		VaultID:         "vlt-1",
		SecretPath:      "prod/db/pass",
		ExpectedVersion: 0,
		Plaintext:       []byte("another-secret"),
		KEKID:           "kek-1",
		Owner:           "team-data",
		OperationID:     "op-dup-create-02",
	})
	if err == nil {
		t.Fatalf("expected duplicate create error, got nil")
	}
	var sErr *storage.Error
	if !errors.As(err, &sErr) || sErr.Code != storage.CodeAlreadyExists {
		t.Fatalf("expected CodeAlreadyExists, got %v", err)
	}

	// 3. Update with stale version (ExpectedVersion = 99) must fail with CodeStaleVersion
	_, err = svc.WriteSecret(context.Background(), WriteRequest{
		VaultID:         "vlt-1",
		SecretPath:      "prod/db/pass",
		ExpectedVersion: 99,
		Plaintext:       []byte("stale-secret"),
		KEKID:           "kek-1",
		Owner:           "team-data",
		OperationID:     "op-stale-ver-03",
	})
	if err == nil {
		t.Fatalf("expected stale version error, got nil")
	}
	if !errors.As(err, &sErr) || sErr.Code != storage.CodeStaleVersion {
		t.Fatalf("expected CodeStaleVersion, got %v", err)
	}

	// 4. Update with correct ExpectedVersion = 1 must succeed and increment to 2
	outcome2, err := svc.WriteSecret(context.Background(), WriteRequest{
		VaultID:         "vlt-1",
		SecretPath:      "prod/db/pass",
		ExpectedVersion: 1,
		Plaintext:       []byte("rotated-secret-canary-999"),
		KEKID:           "kek-1",
		Owner:           "team-data",
		OperationID:     "op-update-secret-04",
	})
	if err != nil {
		t.Fatalf("update failed: %v", err)
	}
	if outcome2.Version != 2 {
		t.Fatalf("expected version 2, got %d", outcome2.Version)
	}

	// 5. Invariant check: Plaintext canary bytes NEVER enter metadata storage
	rec, err := store.Read(context.Background(), storage.ReadRequest{
		Owner: "team-data",
		Scope: "vlt-1",
		Name:  "prod/db/pass",
	})
	if err != nil {
		t.Fatalf("failed to read store record: %v", err)
	}
	payloadStr := string(rec.Metadata)
	if strings.Contains(payloadStr, canary) {
		t.Fatalf("CRITICAL SECURITY INVARIANT VIOLATION: plaintext canary '%s' found in storage record payload!", canary)
	}
	if strings.Contains(payloadStr, "rotated-secret-canary-999") {
		t.Fatalf("CRITICAL SECURITY INVARIANT VIOLATION: rotated plaintext canary found in storage record payload!")
	}

	// Also check raw directory files on disk to guarantee zero plaintext leak
	entries, err := filepath.Glob(filepath.Join(dir, "**", "*"))
	if err == nil {
		for _, entry := range entries {
			content, err := os.ReadFile(entry)
			if err == nil {
				if strings.Contains(string(content), canary) {
					t.Fatalf("CRITICAL SECURITY INVARIANT VIOLATION: canary found in raw disk file %s", entry)
				}
			}
		}
	}
}

func TestWriteSecretProviderUnavailable(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "secrets-store-prov-fail")
	store, _, err := storage.Open(dir)
	if err != nil {
		t.Fatalf("failed to open storage: %v", err)
	}
	defer store.Close()

	prov := &mockKeyProvider{fail: true}
	svc := NewService(nil, prov, store)

	_, err = svc.WriteSecret(context.Background(), WriteRequest{
		VaultID:         "vlt-1",
		SecretPath:      "prod/db/pass",
		ExpectedVersion: 0,
		Plaintext:       []byte("any-secret"),
		KEKID:           "kek-1",
		Owner:           "team-data",
		OperationID:     "op-prov-fail-01",
	})
	if err == nil {
		t.Fatalf("expected provider error, got nil")
	}
	var pErr *provider.Error
	if !errors.As(err, &pErr) || pErr.Code != provider.CodeProviderUnavailable {
		t.Fatalf("expected CodeProviderUnavailable, got %v", err)
	}
}

func TestWriteSecretUnauthorized(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "secrets-store-auth-test")
	store, _, err := storage.Open(dir)
	if err != nil {
		t.Fatalf("failed to open storage: %v", err)
	}
	defer store.Close()

	prov := &mockKeyProvider{fail: false}
	svc := NewService(nil, prov, store)

	// User not authorized for path
	identity := &auth.Identity{
		Subject:       "user-restricted",
		Email:         "user@example.com",
		AllowedOwners: []string{"user@example.com"},
		AllowedScopes: []string{"dev/*"},
	}

	_, err = svc.WriteSecret(context.Background(), WriteRequest{
		VaultID:         "vlt-1",
		SecretPath:      "prod/db/pass",
		ExpectedVersion: 0,
		Plaintext:       []byte("any-secret"),
		KEKID:           "kek-1",
		Owner:           "user@example.com",
		Identity:        identity,
		OperationID:     "op-auth-fail-01",
	})
	if err == nil {
		t.Fatalf("expected unauthorized error, got nil")
	}
	var aErr *auth.Error
	if !errors.As(err, &aErr) || aErr.Code != auth.CodeScopeDenied {
		t.Fatalf("expected CodeScopeDenied, got %v", err)
	}
}
