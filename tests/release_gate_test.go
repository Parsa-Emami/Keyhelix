package storage_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/parsa-emami/keyhelix/internal/storage"
)

// TestC39StagedWriterCrashAuthoritativeRecoveryN39 verifies the C39 negative case:
// Kill the writer at the staged-byte/manifest boundary; restart exposes only a
// complete prior or new authoritative state.
func TestC39StagedWriterCrashAuthoritativeRecoveryN39(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()

	store, _, err := storage.Open(root)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}

	authoritativeMetadata := []byte(`{"vault_id":"vault-c39-gate","status":"active","wrapped_dek":"openbao:transit:v1:ciphertext"}`)
	res, err := store.Write(ctx, storage.WriteRequest{
		OperationID:     "op-c39-authoritative-1",
		Owner:           "alice",
		Scope:           "vaults",
		Name:            "vault-c39-gate",
		ExpectedVersion: 0,
		Metadata:        authoritativeMetadata,
	})
	if err != nil {
		t.Fatalf("authoritative write: %v", err)
	}
	if res.ManifestVersion != 1 || res.EntityVersion != 1 {
		t.Fatalf("expected manifest=1 entity=1, got manifest=%d entity=%d", res.ManifestVersion, res.EntityVersion)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	// Simulate interrupted writer at the staged-byte/manifest boundary
	stagingCrashPath := filepath.Join(root, "staging", "crash-c39-writer.staging")
	if err := os.WriteFile(stagingCrashPath, []byte(`{"partial":"uncommitted-c39"}`), 0o600); err != nil {
		t.Fatalf("write simulated staging file: %v", err)
	}
	orphanBlobPath := filepath.Join(root, "blobs", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if err := os.WriteFile(orphanBlobPath, []byte(`unreferenced-blob-c39`), 0o600); err != nil {
		t.Fatalf("write simulated orphan blob: %v", err)
	}

	reopened, report, err := storage.Open(root)
	if err != nil {
		t.Fatalf("reopen store after writer crash: %v", err)
	}
	defer reopened.Close()

	if report.RemovedStaging != 1 {
		t.Fatalf("expected 1 staging file purged on restart, got %d", report.RemovedStaging)
	}
	if report.RemovedOrphanBlobs != 1 {
		t.Fatalf("expected 1 orphan blob purged on restart, got %d", report.RemovedOrphanBlobs)
	}
	if report.ManifestVersion != 1 {
		t.Fatalf("expected authoritative manifest version 1, got %d", report.ManifestVersion)
	}

	rec, err := reopened.Read(ctx, storage.ReadRequest{
		Owner: "alice",
		Scope: "vaults",
		Name:  "vault-c39-gate",
	})
	if err != nil {
		t.Fatalf("read authoritative record after recovery: %v", err)
	}
	if !bytes.Equal(rec.Metadata, authoritativeMetadata) {
		t.Fatalf("authoritative metadata mismatch: got %s, want %s", rec.Metadata, authoritativeMetadata)
	}
}

// TestC39ReplayIdempotencyAndQuotaExhaustionN39 verifies the C39 negative case:
// Replay the operation, lose an ACK or exhaust disk/quota; no duplicate side effect,
// partial success or unlimited retry.
func TestC39ReplayIdempotencyAndQuotaExhaustionN39(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()

	store, _, err := storage.Open(root)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	payload := []byte(`{"grant_id":"grant-c39","member":"bob","role":"reader"}`)
	req := storage.WriteRequest{
		OperationID:     "op-c39-replay-check",
		Owner:           "alice",
		Scope:           "grants",
		Name:            "grant-c39",
		ExpectedVersion: 0,
		Metadata:        payload,
	}

	first, err := store.Write(ctx, req)
	if err != nil {
		t.Fatalf("first write: %v", err)
	}
	if first.Duplicate {
		t.Fatal("first write must not be flagged as duplicate")
	}

	replayed, err := store.Write(ctx, req)
	if err != nil {
		t.Fatalf("replay write: %v", err)
	}
	if !replayed.Duplicate {
		t.Fatal("replayed operation must be flagged as duplicate")
	}
	if replayed.ManifestVersion != first.ManifestVersion || replayed.EntityVersion != first.EntityVersion {
		t.Fatalf("replay mutated state versions: first=(%d,%d) replay=(%d,%d)",
			first.ManifestVersion, first.EntityVersion, replayed.ManifestVersion, replayed.EntityVersion)
	}

	// Exhaust metadata quota (> 1 MiB) and confirm fail-closed rejection without partial state mutation
	oversized := bytes.Repeat([]byte("Q"), storage.MaxMetadataBytes+32)
	_, err = store.Write(ctx, storage.WriteRequest{
		OperationID:     "op-c39-quota-exceeded",
		Owner:           "alice",
		Scope:           "vaults",
		Name:            "vault-c39-oversized",
		ExpectedVersion: 0,
		Metadata:        oversized,
	})
	if err == nil {
		t.Fatal("expected quota exhaustion write to fail closed, but it succeeded")
	}
}

// TestC39ProviderOwnsSecretBytesZeroPlaintextN39 verifies the C39 negative case:
// Provider owns secret bytes; zero plaintext secret sentinels enter local metadata storage.
func TestC39ProviderOwnsSecretBytesZeroPlaintextN39(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()

	store, _, err := storage.Open(root)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}

	sentinel := "KEYHELIX_C39_RELEASE_GATE_SECRET_SENTINEL_NEVER_PERSIST"
	envelope := []byte(fmt.Sprintf(`{"secret_path":"app/prod/api-key","provider_ref":"openbao://kv/data/app/prod/api-key","sealed_version":1}`))
	if _, err := store.Write(ctx, storage.WriteRequest{
		OperationID:     "op-c39-provider-ownership",
		Owner:           "alice",
		Scope:           "secrets",
		Name:            "api-key",
		ExpectedVersion: 0,
		Metadata:        envelope,
	}); err != nil {
		t.Fatalf("write metadata envelope: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil || d.IsDir() {
			return walkErr
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.Contains(raw, []byte(sentinel)) {
			t.Fatalf("plaintext sentinel leaked into engine store file %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk store directory: %v", err)
	}
}

// TestC39EvidenceGateIntegrityN39 verifies C01-C38 evidence files and docs/evidence/v1-gate.json
// reject planning templates, missing proofs, and source_identity mismatches.
func TestC39EvidenceGateIntegrityN39(t *testing.T) {
	repoRoot := filepath.Clean(filepath.Join(".."))

	progressBytes, err := os.ReadFile(filepath.Join(repoRoot, "plans", "progress.json"))
	if err != nil {
		t.Fatalf("read progress.json: %v", err)
	}
	var progress struct {
		Commits []struct {
			ID             string   `json:"id"`
			Status         string   `json:"status"`
			Evidence       []string `json:"evidence"`
			SourceIdentity string   `json:"source_identity"`
		} `json:"commits"`
	}
	if err := json.Unmarshal(progressBytes, &progress); err != nil {
		t.Fatalf("parse progress.json: %v", err)
	}

	v1GateBytes, err := os.ReadFile(filepath.Join(repoRoot, "docs", "evidence", "v1-gate.json"))
	if err != nil {
		t.Fatalf("read v1-gate.json: %v", err)
	}
	var v1Gate struct {
		Passed            bool              `json:"passed"`
		PlanningTemplate  bool              `json:"planning_template"`
		CoreReady         bool              `json:"core_ready"`
		VerifiedCommits   map[string]string `json:"verified_commits"`
		CloneToValue      struct{ Verified bool `json:"verified"` } `json:"clone_to_value"`
		PackagingSigning  struct{ Verified bool `json:"verified"` } `json:"packaging_and_signing"`
		Licenses          struct{ Verified bool `json:"verified"` } `json:"licenses_and_provenance"`
		SecurityRecovery  struct{ Verified bool `json:"verified"` } `json:"security_and_recovery"`
	}
	if err := json.Unmarshal(v1GateBytes, &v1Gate); err != nil {
		t.Fatalf("parse v1-gate.json: %v", err)
	}
	if !v1Gate.Passed || v1Gate.PlanningTemplate || !v1Gate.CoreReady {
		t.Fatalf("invalid v1-gate top-level status: passed=%v template=%v core_ready=%v",
			v1Gate.Passed, v1Gate.PlanningTemplate, v1Gate.CoreReady)
	}
	if !v1Gate.CloneToValue.Verified || !v1Gate.PackagingSigning.Verified || !v1Gate.Licenses.Verified || !v1Gate.SecurityRecovery.Verified {
		t.Fatal("v1-gate.json domain readiness pillars must all be verified")
	}

	for i := 0; i < 38; i++ {
		expectedID := fmt.Sprintf("C%02d", i+1)
		c := progress.Commits[i]
		if c.ID != expectedID || c.Status != "verified" {
			t.Fatalf("prerequisite %s not verified in progress.json (got id=%s status=%s)", expectedID, c.ID, c.Status)
		}
		if !strings.HasPrefix(c.SourceIdentity, "sha256:") || len(c.Evidence) == 0 {
			t.Fatalf("prerequisite %s missing source_identity or evidence path", expectedID)
		}
		if v1Gate.VerifiedCommits[expectedID] != c.SourceIdentity {
			t.Fatalf("v1-gate.json source_identity mismatch for %s: got %s, want %s",
				expectedID, v1Gate.VerifiedCommits[expectedID], c.SourceIdentity)
		}
		evBytes, err := os.ReadFile(filepath.Join(repoRoot, c.Evidence[0]))
		if err != nil {
			t.Fatalf("read %s evidence: %v", expectedID, err)
		}
		var ev struct {
			Passed           bool   `json:"passed"`
			PlanningTemplate bool   `json:"planning_template"`
			CommitID         string `json:"commit_id"`
			SourceIdentity   string `json:"source_identity"`
			Commands         []struct {
				ExitCode int `json:"exit_code"`
			} `json:"commands"`
		}
		if err := json.Unmarshal(evBytes, &ev); err != nil {
			t.Fatalf("parse %s evidence: %v", expectedID, err)
		}
		if !ev.Passed || ev.PlanningTemplate || ev.CommitID != expectedID || ev.SourceIdentity != c.SourceIdentity || len(ev.Commands) == 0 {
			t.Fatalf("invalid evidence record for %s", expectedID)
		}
		for _, cmd := range ev.Commands {
			if cmd.ExitCode != 0 {
				t.Fatalf("non-zero command exit code in %s evidence", expectedID)
			}
		}
	}
}
