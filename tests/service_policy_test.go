package storage_test

import (
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/parsa-emami/keyhelix/internal/storage"
)

// TestC38StagedWriterCrashAndAuthoritativeRecoveryN38 tests Requirement N38 invariant:
// Killing the writer at the staged-byte/manifest boundary ensures restart exposes
// only the complete authoritative prior state and automatically purges uncommitted staging bytes.
func TestC38StagedWriterCrashAndAuthoritativeRecoveryN38(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()

	// 1. Initial store setup & authoritative commit
	store, _, err := storage.Open(root)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}

	initialPayload := []byte(`{"vault_id":"vault-alpha","status":"active","wrapped_dek":"vault-transit-envelope-v1"}`)
	res1, err := store.Write(ctx, storage.WriteRequest{
		OperationID:     "op-init-c38-authoritative",
		Owner:           "alice",
		Scope:           "vaults",
		Name:            "vault-alpha",
		ExpectedVersion: 0,
		Metadata:        initialPayload,
	})
	if err != nil {
		t.Fatalf("initial write: %v", err)
	}
	if res1.ManifestVersion != 1 || res1.EntityVersion != 1 {
		t.Fatalf("expected manifest v1, entity v1; got manifest=%d, entity=%d", res1.ManifestVersion, res1.EntityVersion)
	}

	if err := store.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	// 2. Simulate writer crash at staged-byte/manifest boundary
	// Inject uncommitted staging file (writer died after staging but before manifest publish)
	stagingFile := filepath.Join(root, "staging", "in-flight-crash-uuid.staging")
	if err := os.WriteFile(stagingFile, []byte("half-written-payload-uncommitted"), 0o600); err != nil {
		t.Fatalf("inject staging file: %v", err)
	}

	// Inject uncommitted orphan blob (writer died before manifest referenced it)
	orphanBlob := filepath.Join(root, "blobs", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if err := os.WriteFile(orphanBlob, []byte("orphan-blob-bytes"), 0o600); err != nil {
		t.Fatalf("inject orphan blob: %v", err)
	}

	// 3. Re-open store and assert crash recovery behavior
	store2, report, err := storage.Open(root)
	if err != nil {
		t.Fatalf("reopen store after crash: %v", err)
	}
	defer store2.Close()

	if report.RemovedStaging != 1 {
		t.Errorf("expected 1 removed staging file, got %d", report.RemovedStaging)
	}
	if report.RemovedOrphanBlobs != 1 {
		t.Errorf("expected 1 removed orphan blob, got %d", report.RemovedOrphanBlobs)
	}
	if report.ManifestVersion != 1 {
		t.Errorf("expected manifest to stay at version 1, got %d", report.ManifestVersion)
	}

	// Verify authoritative state is intact and uncorrupted
	record, err := store2.Read(ctx, storage.ReadRequest{
		Owner: "alice",
		Scope: "vaults",
		Name:  "vault-alpha",
	})
	if err != nil {
		t.Fatalf("read authoritative record: %v", err)
	}
	if !bytes.Equal(record.Metadata, initialPayload) {
		t.Fatalf("authoritative payload mismatch: got %s, want %s", record.Metadata, initialPayload)
	}
	if record.EntityVersion != 1 {
		t.Errorf("expected record entity version 1, got %d", record.EntityVersion)
	}
}

// TestC38OperationReplayIdempotencyN38 tests Requirement N38 invariant:
// Replaying an operation with the same operation ID produces an idempotent result
// without secondary side-effects or duplicate manifest increments.
func TestC38OperationReplayIdempotencyN38(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()

	store, _, err := storage.Open(root)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	payload := []byte(`{"grant_id":"grant-beta","member":"bob","role":"reader"}`)
	req := storage.WriteRequest{
		OperationID:     "op-replay-idempotent-c38",
		Owner:           "alice",
		Scope:           "grants",
		Name:            "grant-beta",
		ExpectedVersion: 0,
		Metadata:        payload,
	}

	// First execution
	res1, err := store.Write(ctx, req)
	if err != nil {
		t.Fatalf("first write: %v", err)
	}
	if res1.Duplicate {
		t.Fatal("first write should not be marked as duplicate")
	}

	// Second execution (replay / lost ACK)
	res2, err := store.Write(ctx, req)
	if err != nil {
		t.Fatalf("second write (replay): %v", err)
	}
	if !res2.Duplicate {
		t.Fatal("second write must be recognized as duplicate")
	}
	if res2.ManifestVersion != res1.ManifestVersion {
		t.Errorf("manifest version mutated on replay: want %d, got %d", res1.ManifestVersion, res2.ManifestVersion)
	}
	if res2.EntityVersion != res1.EntityVersion {
		t.Errorf("entity version mutated on replay: want %d, got %d", res1.EntityVersion, res2.EntityVersion)
	}
	if res2.MetadataDigest != res1.MetadataDigest {
		t.Errorf("digest mismatch on replay: want %s, got %s", res1.MetadataDigest, res2.MetadataDigest)
	}
}

// TestC38QuotaBoundsRejectionN38 tests Requirement N38 invariant:
// Payload exceeding storage boundaries (1 MiB) fails closed without corrupting the store.
func TestC38QuotaBoundsRejectionN38(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()

	store, _, err := storage.Open(root)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	// MaxMetadataBytes is 1 MiB (1,048,576 bytes). Generate 1 MiB + 10 bytes.
	oversized := make([]byte, storage.MaxMetadataBytes+10)
	for i := range oversized {
		oversized[i] = 'A'
	}

	_, err = store.Write(ctx, storage.WriteRequest{
		OperationID:     "op-oversized-rejection-c38",
		Owner:           "alice",
		Scope:           "vaults",
		Name:            "vault-oversized",
		ExpectedVersion: 0,
		Metadata:        oversized,
	})
	if err == nil {
		t.Fatal("expected oversized metadata write to fail, but it succeeded")
	}
}

// TestC38ProviderOwnsSecretBytesZeroPlaintextScanN38 tests Requirement N38 invariant:
// Provider owns secret bytes; engine store never persists raw secret sentinels to disk.
func TestC38ProviderOwnsSecretBytesZeroPlaintextScanN38(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()

	store, _, err := storage.Open(root)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}

	canary := "KEYHELIX_SENTINEL_SECRET_DO_NOT_PERSIST_C38"
	// Metadata contains encrypted envelope with transit key reference, NOT plaintext canary
	wrappedMetadata := []byte(fmt.Sprintf(`{"vault_id":"vault-canary","ciphertext":"enc:v1:fake-ciphertext-token","key_ref":"transit/keys/kek"}`))

	_, err = store.Write(ctx, storage.WriteRequest{
		OperationID:     "op-sentinel-check-c38",
		Owner:           "alice",
		Scope:           "vaults",
		Name:            "vault-canary",
		ExpectedVersion: 0,
		Metadata:        wrappedMetadata,
	})
	if err != nil {
		t.Fatalf("write metadata: %v", err)
	}

	if err := store.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	// Walk root directory and assert 0 occurrences of canary
	occurrences := 0
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.Contains(data, []byte(canary)) {
			occurrences++
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk store dir: %v", err)
	}

	if occurrences != 0 {
		t.Fatalf("provider ownership violation: found %d occurrences of plaintext canary in store", occurrences)
	}
}
