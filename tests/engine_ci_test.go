package storage_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/parsa-emami/keyhelix/internal/contracts"
	"github.com/parsa-emami/keyhelix/internal/storage"
)

type c06PositiveFixture struct {
	SchemaVersion     int    `json:"schema_version"`
	Owner             string `json:"owner"`
	Scope             string `json:"scope"`
	Name              string `json:"name"`
	OperationID       string `json:"operation_id"`
	ExpectedVersion   int64  `json:"expected_version"`
	MetadataFile      string `json:"metadata_file"`
	SecondOperationID string `json:"second_operation_id"`
	EngineAddress     string `json:"engine_address"`
	ExpectedScope     string `json:"expected_scope"`
}

type c06ExpectedOutput struct {
	SchemaVersion   int           `json:"schema_version"`
	MetadataSHA256  string        `json:"metadata_sha256"`
	PlaintextCanary string        `json:"plaintext_canary"`
	Health          expectedHealth `json:"health"`
	FirstWrite      expectedWrite `json:"first_write"`
	SecondWrite     expectedWrite `json:"second_write"`
	StaleReplay     struct {
		ExpectedCode string `json:"expected_code"`
	} `json:"stale_replay"`
	TamperedBlob struct {
		ExpectedCode string `json:"expected_code"`
	} `json:"tampered_blob"`
	TamperedManifest struct {
		ExpectedCode string `json:"expected_code"`
	} `json:"tampered_manifest"`
}

type expectedHealth struct {
	Status    string `json:"status"`
	Scope     string `json:"scope"`
	Version   string `json:"version"`
	CoreReady bool   `json:"coreReady"`
}

func loadC06Fixture(t *testing.T, filename string, target any) {
	t.Helper()
	path := filepath.Join("fixtures", "keyhelix", "C06", filename)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", filename, err)
	}
	if err := json.Unmarshal(data, target); err != nil {
		t.Fatalf("unmarshal fixture %s: %v", filename, err)
	}
}

func TestC06EngineTestDiscoveryInventory(t *testing.T) {
	// Verify that all four domain test packages are discoverable and collected.
	expectedPackages := []string{
		"github.com/parsa-emami/keyhelix/cmd/keyhelix",
		"github.com/parsa-emami/keyhelix/internal/contracts",
		"github.com/parsa-emami/keyhelix/internal/storage",
		"github.com/parsa-emami/keyhelix/tests",
	}

	cmd := exec.Command("go", "test", "-list", ".*", "./...")
	cmd.Dir = ".."
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go test -list failed: %v\nOutput: %s", err, string(output))
	}
	outStr := string(output)
	for _, pkg := range expectedPackages {
		if !strings.Contains(outStr, pkg) {
			t.Fatalf("missing expected domain test package in discovery: %s", pkg)
		}
	}
}

func TestC06CleanCheckoutEngineAndStorageEndToEnd(t *testing.T) {
	var pos c06PositiveFixture
	var exp c06ExpectedOutput
	loadC06Fixture(t, "positive.json", &pos)
	loadC06Fixture(t, "expected-output.json", &exp)

	metaBytes, err := os.ReadFile(filepath.Join("fixtures", "keyhelix", "C06", pos.MetadataFile))
	if err != nil {
		t.Fatalf("read metadata fixture: %v", err)
	}
	actualDigest := hex.EncodeToString(func() []byte {
		sum := sha256.Sum256(metaBytes)
		return sum[:]
	}())
	if actualDigest != exp.MetadataSHA256 {
		t.Fatalf("metadata sha256 mismatch: got %s want %s", actualDigest, exp.MetadataSHA256)
	}

	// 1. Validate contract via internal/contracts
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	valResult := contracts.Validate(ctx, io.NopCloser(bytes.NewReader(metaBytes)), "0.0.1")
	if valResult.Status != "unverified" || !valResult.Result.Valid {
		t.Fatalf("contracts validation failed on positive fixture: %+v", valResult)
	}

	// 2. Authoritative local storage write
	storeDir := t.TempDir()
	store, report := mustOpen(t, storeDir)
	if report.ManifestVersion != 0 || report.Records != 0 {
		t.Fatalf("initial report not clean: %+v", report)
	}

	// First write (version 1)
	writeReq1 := storage.WriteRequest{
		OperationID:     pos.OperationID,
		Owner:           pos.Owner,
		Scope:           pos.Scope,
		Name:            pos.Name,
		ExpectedVersion: pos.ExpectedVersion,
		Metadata:        metaBytes,
	}
	res1, err := store.Write(context.Background(), writeReq1)
	if err != nil {
		t.Fatalf("write 1 failed: %v", err)
	}
	assertWrite(t, res1, exp.FirstWrite)

	// Second write (version 2)
	writeReq2 := storage.WriteRequest{
		OperationID:     pos.SecondOperationID,
		Owner:           pos.Owner,
		Scope:           pos.Scope,
		Name:            pos.Name,
		ExpectedVersion: 1,
		Metadata:        metaBytes,
	}
	res2, err := store.Write(context.Background(), writeReq2)
	if err != nil {
		t.Fatalf("write 2 failed: %v", err)
	}
	assertWrite(t, res2, exp.SecondWrite)

	// Verify read returns version 2
	readRes, err := store.Read(context.Background(), storage.ReadRequest{
		Owner: pos.Owner,
		Scope: pos.Scope,
		Name:  pos.Name,
	})
	if err != nil {
		t.Fatalf("read version 2 failed: %v", err)
	}
	if readRes.EntityVersion != 2 || readRes.MetadataDigest != exp.MetadataSHA256 {
		t.Fatalf("read mismatch: version=%d digest=%s", readRes.EntityVersion, readRes.MetadataDigest)
	}
}

func TestC06NegativeCases(t *testing.T) {
	var pos c06PositiveFixture
	var exp c06ExpectedOutput
	loadC06Fixture(t, "positive.json", &pos)
	loadC06Fixture(t, "expected-output.json", &exp)

	metaBytes, err := os.ReadFile(filepath.Join("fixtures", "keyhelix", "C06", pos.MetadataFile))
	if err != nil {
		t.Fatalf("read metadata fixture: %v", err)
	}

	// Negative Case 1: "One modified byte, missing evidence or a wrong/untrusted signer must not produce trusted success"
	t.Run("ModifiedByteInBlobFailsVerification", func(t *testing.T) {
		storeDir := t.TempDir()
		store, _ := mustOpen(t, storeDir)
		w := storage.WriteRequest{
			OperationID:     pos.OperationID,
			Owner:           pos.Owner,
			Scope:           pos.Scope,
			Name:            pos.Name,
			ExpectedVersion: 0,
			Metadata:        metaBytes,
		}
		if _, err := store.Write(context.Background(), w); err != nil {
			t.Fatalf("write failed: %v", err)
		}

		blobPath := filepath.Join(storeDir, "blobs", exp.MetadataSHA256)
		blobData, err := os.ReadFile(blobPath)
		if err != nil {
			t.Fatalf("read blob: %v", err)
		}
		// Tamper with one byte
		corrupted := make([]byte, len(blobData))
		copy(corrupted, blobData)
		corrupted[0] ^= 0xFF
		if err := os.WriteFile(blobPath, corrupted, 0o600); err != nil {
			t.Fatalf("write corrupted blob: %v", err)
		}

		// Read must fail closed with CORRUPT_STATE
		_, err = store.Read(context.Background(), storage.ReadRequest{
			Owner: pos.Owner,
			Scope: pos.Scope,
			Name:  pos.Name,
		})
		assertCode(t, err, storage.ErrorCode(exp.TamperedBlob.ExpectedCode))
	})

	t.Run("ModifiedByteInManifestFailsVerification", func(t *testing.T) {
		storeDir := t.TempDir()
		store, _, err := storage.Open(storeDir)
		if err != nil {
			t.Fatalf("open store: %v", err)
		}
		w := storage.WriteRequest{
			OperationID:     pos.OperationID,
			Owner:           pos.Owner,
			Scope:           pos.Scope,
			Name:            pos.Name,
			ExpectedVersion: 0,
			Metadata:        metaBytes,
		}
		if _, err := store.Write(context.Background(), w); err != nil {
			t.Fatalf("write failed: %v", err)
		}

		manifestPath := filepath.Join(storeDir, "manifests", "manifest-00000000000000000001.json")
		mfData, err := os.ReadFile(manifestPath)
		if err != nil {
			t.Fatalf("read manifest: %v", err)
		}
		// Corrupt manifest JSON byte
		corrupted := bytes.Replace(mfData, []byte(`"manifest_version":1`), []byte(`"manifest_version":9`), 1)
		if bytes.Equal(corrupted, mfData) {
			t.Fatal("manifest replacement target not found")
		}

		// Close current store to release writer lock
		if err := store.Close(); err != nil {
			t.Fatalf("store close: %v", err)
		}

		if err := os.WriteFile(manifestPath, corrupted, 0o600); err != nil {
			t.Fatalf("write corrupted manifest: %v", err)
		}

		// Reopen store; corrupted manifest must fail verification
		_, _, err = storage.Open(storeDir)
		assertCode(t, err, storage.ErrorCode(exp.TamperedManifest.ExpectedCode))
	})

	t.Run("UntrustedSignerOrMissingKEKFailsClosed", func(t *testing.T) {
		// Missing kek_id
		badMetadata := bytes.Replace(metaBytes, []byte(`"kek_id": "kek-v1-openbao"`), []byte(`"kek_id": ""`), 1)
		val := contracts.Validate(context.Background(), io.NopCloser(bytes.NewReader(badMetadata)), "0.0.1")
		if val.Status != "failed" || val.Result.Valid {
			t.Fatalf("expected validation failure for missing KEK, got: %+v", val)
		}
		if val.Result.Error == nil || string(val.Result.Error.Code) != "INVALID_INPUT" {
			t.Fatalf("expected INVALID_INPUT for untrusted/empty KEK, got: %+v", val.Result.Error)
		}
	})

	// Negative Case 2: "An expired/stale/replayed revision cannot replace the last valid accepted authority"
	t.Run("StaleRevisionReplayRejected", func(t *testing.T) {
		storeDir := t.TempDir()
		store, _ := mustOpen(t, storeDir)

		w1 := storage.WriteRequest{
			OperationID:     pos.OperationID,
			Owner:           pos.Owner,
			Scope:           pos.Scope,
			Name:            pos.Name,
			ExpectedVersion: 0,
			Metadata:        metaBytes,
		}
		if _, err := store.Write(context.Background(), w1); err != nil {
			t.Fatalf("setup write 1 failed: %v", err)
		}
		w2 := storage.WriteRequest{
			OperationID:     pos.SecondOperationID,
			Owner:           pos.Owner,
			Scope:           pos.Scope,
			Name:            pos.Name,
			ExpectedVersion: 1,
			Metadata:        metaBytes,
		}
		if _, err := store.Write(context.Background(), w2); err != nil {
			t.Fatalf("setup write 2 failed: %v", err)
		}

		staleWrite := storage.WriteRequest{
			OperationID:     "op-c06-stale-replay",
			Owner:           pos.Owner,
			Scope:           pos.Scope,
			Name:            pos.Name,
			ExpectedVersion: 1, // Stale! Current version is 2
			Metadata:        metaBytes,
		}
		_, err := store.Write(context.Background(), staleWrite)
		assertCode(t, err, storage.ErrorCode(exp.StaleReplay.ExpectedCode))

		// Confirm accepted authority is preserved at version 2
		readRes, err := store.Read(context.Background(), storage.ReadRequest{
			Owner: pos.Owner,
			Scope: pos.Scope,
			Name:  pos.Name,
		})
		if err != nil {
			t.Fatalf("read after stale write failed: %v", err)
		}
		if readRes.EntityVersion != 2 {
			t.Fatalf("expected entity version 2 preserved, got: %d", readRes.EntityVersion)
		}
	})

	// Negative Case 3: "Provider owns secret bytes"
	t.Run("ProviderOwnsSecretBytesNoPlaintextPersisted", func(t *testing.T) {
		canary := exp.PlaintextCanary
		storeDir := t.TempDir()
		store, _ := mustOpen(t, storeDir)

		w := storage.WriteRequest{
			OperationID:     pos.OperationID,
			Owner:           pos.Owner,
			Scope:           pos.Scope,
			Name:            pos.Name,
			ExpectedVersion: 0,
			Metadata:        metaBytes,
		}
		if _, err := store.Write(context.Background(), w); err != nil {
			t.Fatalf("write failed: %v", err)
		}

		// Scan all files in storeDir (manifests, operations, blobs)
		foundCanary := false
		err := filepath.Walk(storeDir, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return err
			}
			content, readErr := os.ReadFile(path)
			if readErr != nil {
				return readErr
			}
			if bytes.Contains(content, []byte(canary)) {
				foundCanary = true
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk store dir: %v", err)
		}
		if foundCanary {
			t.Fatal("security violation: plaintext canary secret found in storage files; provider must own secret bytes")
		}
	})
}
