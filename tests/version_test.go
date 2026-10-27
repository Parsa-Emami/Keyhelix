package storage_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/parsa-emami/keyhelix/internal/auth"
	"github.com/parsa-emami/keyhelix/internal/contracts"
	"github.com/parsa-emami/keyhelix/internal/provider"
	"github.com/parsa-emami/keyhelix/internal/secrets"
	"github.com/parsa-emami/keyhelix/internal/storage"
)

type c13MockKeyProvider struct {
	mu          sync.Mutex
	fail        bool
	wrapCount   int64
	unwrapCount int64
}

func (m *c13MockKeyProvider) WrapDEK(ctx context.Context, kekID string, plaintextDEK []byte) (*provider.WrapResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail {
		return nil, &provider.Error{Code: provider.CodeProviderUnavailable, Message: "key provider unavailable"}
	}
	atomic.AddInt64(&m.wrapCount, 1)
	return &provider.WrapResult{
		Ciphertext: "bao:v1:wrapped-dek-for-" + kekID,
		KEKVersion: 1,
	}, nil
}

func (m *c13MockKeyProvider) UnwrapDEK(ctx context.Context, kekID string, ciphertext string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail {
		return nil, &provider.Error{Code: provider.CodeProviderUnavailable, Message: "key provider unavailable"}
	}
	atomic.AddInt64(&m.unwrapCount, 1)
	return make([]byte, 32), nil
}

func (m *c13MockKeyProvider) Health(ctx context.Context) (*provider.Health, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail {
		return nil, &provider.Error{Code: provider.CodeProviderUnavailable, Message: "provider offline"}
	}
	return &provider.Health{Status: "ok", Initialized: true, Sealed: false}, nil
}

func (m *c13MockKeyProvider) WorkloadIdentity() provider.WorkloadIdentity {
	return provider.WorkloadIdentity{
		Role:   "workload-test",
		Scopes: []string{"transit:encrypt", "transit:decrypt"},
	}
}

// TestVersionedSecretWriteF07 validates requirement F07:
// CAS version prevents lost update; bytes never enter metadata storage.
func TestVersionedSecretWriteF07(t *testing.T) {
	ctx := context.Background()
	storeDir := filepath.Join(t.TempDir(), "c13-version-store")

	store, _, err := storage.Open(storeDir)
	if err != nil {
		t.Fatalf("failed to open storage: %v", err)
	}
	defer store.Close()

	keyProv := &c13MockKeyProvider{fail: false}
	svc := secrets.NewService(nil, keyProv, store)

	alice := &auth.Identity{
		Subject:       "alice-123",
		Email:         "alice@example.com",
		VaultRole:     "engineer",
		AllowedOwners: []string{"alice@example.com", "shared-team"},
		AllowedScopes: []string{"production/*", "staging/*"},
	}

	canaryPayloadV1 := "SUPER_CONFIDENTIAL_PAYLOAD_CANARY_V1_xyz890"
	canaryPayloadV2 := "SUPER_CONFIDENTIAL_PAYLOAD_CANARY_V2_abc123"

	// Step 1: Initial secret write (ExpectedVersion = 0)
	outcome1, err := svc.WriteSecret(ctx, secrets.WriteRequest{
		VaultID:         "vlt-prod-primary",
		SecretPath:      "production/databases/postgres/credentials",
		ExpectedVersion: 0,
		Plaintext:       []byte(canaryPayloadV1),
		Classification:  "CONFIDENTIAL",
		KEKID:           "kek-database-prod",
		Owner:           "shared-team",
		Identity:        alice,
		OperationID:     "op-init-secret-v1",
	})
	if err != nil {
		t.Fatalf("initial secret write failed: %v", err)
	}

	if outcome1.Version != 1 {
		t.Fatalf("expected initial version 1, got %d", outcome1.Version)
	}
	if outcome1.SecretID == "" || outcome1.MetadataHash == "" {
		t.Fatalf("missing secret_id or metadata_hash in outcome: %+v", outcome1)
	}

	// Step 2: Attempt duplicate create (ExpectedVersion = 0) must be rejected with CodeAlreadyExists
	_, err = svc.WriteSecret(ctx, secrets.WriteRequest{
		VaultID:         "vlt-prod-primary",
		SecretPath:      "production/databases/postgres/credentials",
		ExpectedVersion: 0,
		Plaintext:       []byte("overwrite-attempt"),
		Classification:  "CONFIDENTIAL",
		KEKID:           "kek-database-prod",
		Owner:           "shared-team",
		Identity:        alice,
		OperationID:     "op-dup-create-reject",
	})
	if err == nil {
		t.Fatalf("expected duplicate create error, got nil")
	}
	var storageErr *storage.Error
	if !errors.As(err, &storageErr) || storageErr.Code != storage.CodeAlreadyExists {
		t.Fatalf("expected CodeAlreadyExists, got %v", err)
	}

	// Step 3: Concurrent CAS update simulation — CAS prevents lost update
	// Two clients read version 1 and both try to update to version 2 concurrently.
	// Only ONE write must succeed; the second must fail with CodeStaleVersion.
	var wg sync.WaitGroup
	var successCount int64
	var staleCount int64

	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			opID := "op-cas-concurrent-0" + string(rune('1'+idx))
			_, wErr := svc.WriteSecret(ctx, secrets.WriteRequest{
				VaultID:         "vlt-prod-primary",
				SecretPath:      "production/databases/postgres/credentials",
				ExpectedVersion: 1, // Both expect version 1
				Plaintext:       []byte(canaryPayloadV2),
				Classification:  "CONFIDENTIAL",
				KEKID:           "kek-database-prod",
				Owner:           "shared-team",
				Identity:        alice,
				OperationID:     opID,
			})
			if wErr == nil {
				atomic.AddInt64(&successCount, 1)
			} else {
				var sErr *storage.Error
				if errors.As(wErr, &sErr) && sErr.Code == storage.CodeStaleVersion {
					atomic.AddInt64(&staleCount, 1)
				}
			}
		}(i)
	}
	wg.Wait()

	if successCount != 1 {
		t.Fatalf("expected exactly 1 successful CAS write, got %d", successCount)
	}
	if staleCount != 1 {
		t.Fatalf("expected exactly 1 stale CAS conflict rejection, got %d", staleCount)
	}

	// Step 4: Stale update rejected with CodeStaleVersion when giving an outdated version (e.g. 1 after version is 2)
	_, err = svc.WriteSecret(ctx, secrets.WriteRequest{
		VaultID:         "vlt-prod-primary",
		SecretPath:      "production/databases/postgres/credentials",
		ExpectedVersion: 1,
		Plaintext:       []byte("outdated-write"),
		Classification:  "CONFIDENTIAL",
		KEKID:           "kek-database-prod",
		Owner:           "shared-team",
		Identity:        alice,
		OperationID:     "op-stale-after-increment",
	})
	if err == nil {
		t.Fatalf("expected stale version error, got nil")
	}
	if !errors.As(err, &storageErr) || storageErr.Code != storage.CodeStaleVersion {
		t.Fatalf("expected CodeStaleVersion, got %v", err)
	}

	// Step 5: Provider offline fails closed
	keyProv.mu.Lock()
	keyProv.fail = true
	keyProv.mu.Unlock()

	_, err = svc.WriteSecret(ctx, secrets.WriteRequest{
		VaultID:         "vlt-prod-primary",
		SecretPath:      "production/databases/postgres/offline-target",
		ExpectedVersion: 0,
		Plaintext:       []byte("should-fail-offline"),
		Classification:  "CONFIDENTIAL",
		KEKID:           "kek-database-prod",
		Owner:           "shared-team",
		Identity:        alice,
		OperationID:     "op-provider-offline",
	})
	if err == nil {
		t.Fatalf("expected provider unavailable error, got nil")
	}
	var provErr *provider.Error
	if !errors.As(err, &provErr) || provErr.Code != provider.CodeProviderUnavailable {
		t.Fatalf("expected CodeProviderUnavailable, got %v", err)
	}

	keyProv.mu.Lock()
	keyProv.fail = false
	keyProv.mu.Unlock()

	// Step 6: Verify Requirement F07 Invariant — Plaintext bytes NEVER enter metadata storage
	record, err := store.Read(ctx, storage.ReadRequest{
		Owner: "shared-team",
		Scope: "vlt-prod-primary",
		Name:  "production/databases/postgres/credentials",
	})
	if err != nil {
		t.Fatalf("failed to read stored record: %v", err)
	}

	if record.EntityVersion != 2 {
		t.Fatalf("expected storage entity version 2, got %d", record.EntityVersion)
	}

	// Ensure record payload parses into contracts.SecretMetadata
	var meta contracts.SecretMetadata
	if err := json.Unmarshal(record.Metadata, &meta); err != nil {
		t.Fatalf("metadata payload failed unmarshaling: %v", err)
	}
	if meta.Version != 2 {
		t.Fatalf("expected metadata version 2, got %d", meta.Version)
	}
	if meta.Envelope.WrappedDEK == "" || meta.Envelope.Nonce == "" || meta.Envelope.Tag == "" {
		t.Fatalf("missing envelope fields: %+v", meta.Envelope)
	}

	// Verify plaintext canary V1 and V2 NEVER appear in stored metadata
	metadataStr := string(record.Metadata)
	if strings.Contains(metadataStr, canaryPayloadV1) {
		t.Fatalf("CRITICAL SECURITY VIOLATION: canaryPayloadV1 leaked into storage metadata!")
	}
	if strings.Contains(metadataStr, canaryPayloadV2) {
		t.Fatalf("CRITICAL SECURITY VIOLATION: canaryPayloadV2 leaked into storage metadata!")
	}

	// Verify plaintext canary bytes NEVER appear anywhere on disk in the storage directory
	var filesChecked int
	err = filepath.Walk(storeDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		filesChecked++
		content, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		if strings.Contains(string(content), canaryPayloadV1) {
			t.Fatalf("CRITICAL SECURITY VIOLATION: canaryPayloadV1 found in storage file %s", path)
		}
		if strings.Contains(string(content), canaryPayloadV2) {
			t.Fatalf("CRITICAL SECURITY VIOLATION: canaryPayloadV2 found in storage file %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("failed inspecting storage directory files: %v", err)
	}
	if filesChecked == 0 {
		t.Fatalf("no storage files inspected in %s", storeDir)
	}

	// Step 7: Restart recovery preserves version
	if err := store.Close(); err != nil {
		t.Fatalf("failed closing store: %v", err)
	}

	reopenedStore, report, err := storage.Open(storeDir)
	if err != nil {
		t.Fatalf("failed reopening store: %v", err)
	}
	defer reopenedStore.Close()

	if report.ManifestVersion == 0 {
		t.Fatalf("reopened store reported zero manifest version: %+v", report)
	}

	reopenedSvc := secrets.NewService(nil, keyProv, reopenedStore)

	// CAS write expecting version 1 after restart must fail with CodeStaleVersion
	_, err = reopenedSvc.WriteSecret(ctx, secrets.WriteRequest{
		VaultID:         "vlt-prod-primary",
		SecretPath:      "production/databases/postgres/credentials",
		ExpectedVersion: 1,
		Plaintext:       []byte("stale-after-restart"),
		Classification:  "CONFIDENTIAL",
		KEKID:           "kek-database-prod",
		Owner:           "shared-team",
		Identity:        alice,
		OperationID:     "op-stale-after-restart",
	})
	if err == nil {
		t.Fatalf("expected stale version error after restart, got nil")
	}
	if !errors.As(err, &storageErr) || storageErr.Code != storage.CodeStaleVersion {
		t.Fatalf("expected CodeStaleVersion after restart, got %v", err)
	}

	// CAS write expecting version 2 after restart must succeed and increment to 3
	outcome3, err := reopenedSvc.WriteSecret(ctx, secrets.WriteRequest{
		VaultID:         "vlt-prod-primary",
		SecretPath:      "production/databases/postgres/credentials",
		ExpectedVersion: 2,
		Plaintext:       []byte("valid-after-restart-v3"),
		Classification:  "CONFIDENTIAL",
		KEKID:           "kek-database-prod",
		Owner:           "shared-team",
		Identity:        alice,
		OperationID:     "op-valid-after-restart",
	})
	if err != nil {
		t.Fatalf("valid CAS write after restart failed: %v", err)
	}
	if outcome3.Version != 3 {
		t.Fatalf("expected version 3 after restart, got %d", outcome3.Version)
	}
}
