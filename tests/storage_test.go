package storage_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/parsa-emami/keyhelix/internal/storage"
)

type positiveFixture struct {
	SchemaVersion     int    `json:"schema_version"`
	Owner             string `json:"owner"`
	Scope             string `json:"scope"`
	Name              string `json:"name"`
	OperationID       string `json:"operation_id"`
	ExpectedVersion   int64  `json:"expected_version"`
	MetadataFile      string `json:"metadata_file"`
	SecondOperationID string `json:"second_operation_id"`
}

type expectedWrite struct {
	OperationID     string `json:"operation_id"`
	EntityVersion   int64  `json:"entity_version"`
	ManifestVersion int64  `json:"manifest_version"`
	Duplicate       bool   `json:"duplicate"`
}

type expectedRecovery struct {
	ManifestVersion    int64 `json:"manifest_version"`
	Records            int   `json:"records"`
	RemovedStaging     int   `json:"removed_staging"`
	RemovedOrphanBlobs int   `json:"removed_orphan_blobs"`
}

type expectedFixture struct {
	MetadataSHA256  string           `json:"metadata_sha256"`
	PlaintextCanary string           `json:"plaintext_canary"`
	FirstWrite      expectedWrite    `json:"first_write"`
	SecondWrite     expectedWrite    `json:"second_write"`
	Replay          expectedWrite    `json:"replay"`
	OrphanRecovery  expectedRecovery `json:"orphan_recovery"`
}

type negativeCase struct {
	CaseName        string  `json:"case"`
	Kind            string  `json:"kind"`
	OperationID     string  `json:"operation_id"`
	Owner           string  `json:"owner"`
	Scope           string  `json:"scope"`
	Name            string  `json:"name"`
	ExpectedVersion int64   `json:"expected_version"`
	Metadata        *string `json:"metadata"`
	MetadataRepeat  int     `json:"metadata_repeat"`
	ExpectedCode    string  `json:"expected_code"`
}

type negativeFixture struct {
	Cases []negativeCase `json:"cases"`
}

type recoveryExpectation struct {
	OpenOK             bool   `json:"open_ok"`
	RemovedStaging     int    `json:"removed_staging"`
	RemovedOrphanBlobs int    `json:"removed_orphan_blobs"`
	ExpectedCode       string `json:"expected_code"`
}

type recoveryCase struct {
	Name     string              `json:"name"`
	Setup    string              `json:"setup"`
	Expected recoveryExpectation `json:"expected"`
}

type recoveryFixture struct {
	Cases []recoveryCase `json:"cases"`
}

func loadFixture(t *testing.T, name string, target any) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("fixtures", "keyhelix", "C05", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	if err := json.Unmarshal(data, target); err != nil {
		t.Fatalf("parse fixture %s: %v", name, err)
	}
}

func fixtureMetadata(t *testing.T, positive positiveFixture) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("fixtures", "keyhelix", "C05", positive.MetadataFile))
	if err != nil {
		t.Fatalf("read metadata fixture: %v", err)
	}
	return data
}

func mustOpen(t *testing.T, root string) (*storage.Store, storage.RecoveryReport) {
	t.Helper()
	store, report, err := storage.Open(root)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store, report
}

func codeOf(err error) storage.ErrorCode {
	var typed *storage.Error
	if errors.As(err, &typed) {
		return typed.Code
	}
	return ""
}

func assertCode(t *testing.T, err error, expected storage.ErrorCode) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected %s, got nil", expected)
	}
	if actual := codeOf(err); actual != expected {
		t.Fatalf("expected %s, got %s (%v)", expected, actual, err)
	}
}

func assertWrite(t *testing.T, actual storage.WriteResult, expected expectedWrite) {
	t.Helper()
	if actual.OperationID != expected.OperationID ||
		actual.EntityVersion != expected.EntityVersion ||
		actual.ManifestVersion != expected.ManifestVersion ||
		actual.Duplicate != expected.Duplicate {
		t.Fatalf("write result mismatch: got %+v want %+v", actual, expected)
	}
}

func request(positive positiveFixture, operationID string, expectedVersion int64, metadata []byte) storage.WriteRequest {
	return storage.WriteRequest{
		OperationID:     operationID,
		Owner:           positive.Owner,
		Scope:           positive.Scope,
		Name:            positive.Name,
		ExpectedVersion: expectedVersion,
		Metadata:        metadata,
	}
}

func readRequest(positive positiveFixture) storage.ReadRequest {
	return storage.ReadRequest{Owner: positive.Owner, Scope: positive.Scope, Name: positive.Name}
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func manifestFiles(t *testing.T, root string) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(root, "manifests"))
	if err != nil {
		t.Fatalf("read manifests: %v", err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	return names
}

func TestFixtureWriteReadReplayAndRestart(t *testing.T) {
	var positive positiveFixture
	var expected expectedFixture
	loadFixture(t, "positive.json", &positive)
	loadFixture(t, "expected-output.json", &expected)
	metadata := fixtureMetadata(t, positive)
	if actual := sha256Hex(metadata); actual != expected.MetadataSHA256 {
		t.Fatalf("fixture digest mismatch: %s", actual)
	}

	root := t.TempDir()
	store, report := mustOpen(t, root)
	if report.ManifestVersion != 0 || report.Records != 0 {
		t.Fatalf("unexpected initial recovery report: %+v", report)
	}

	first := request(positive, positive.OperationID, positive.ExpectedVersion, metadata)
	firstResult, err := store.Write(context.Background(), first)
	if err != nil {
		t.Fatalf("first write: %v", err)
	}
	assertWrite(t, firstResult, expected.FirstWrite)
	if firstResult.MetadataDigest != expected.MetadataSHA256 {
		t.Fatalf("unexpected digest: %s", firstResult.MetadataDigest)
	}

	record, err := store.Read(context.Background(), readRequest(positive))
	if err != nil {
		t.Fatalf("read first record: %v", err)
	}
	if !bytes.Equal(record.Metadata, metadata) || record.EntityVersion != 1 || record.ManifestVersion != 1 {
		t.Fatalf("unexpected record: %+v", record)
	}

	second := request(positive, positive.SecondOperationID, 1, metadata)
	secondResult, err := store.Write(context.Background(), second)
	if err != nil {
		t.Fatalf("second write: %v", err)
	}
	assertWrite(t, secondResult, expected.SecondWrite)

	replayResult, err := store.Write(context.Background(), first)
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	assertWrite(t, replayResult, expected.Replay)

	record, err = store.Read(context.Background(), readRequest(positive))
	if err != nil {
		t.Fatalf("read updated record: %v", err)
	}
	if record.EntityVersion != expected.SecondWrite.EntityVersion || record.ManifestVersion != expected.SecondWrite.ManifestVersion {
		t.Fatalf("replay changed visible state: %+v", record)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	reopened, report := mustOpen(t, root)
	if report.ManifestVersion != expected.SecondWrite.ManifestVersion || report.Records != 1 {
		t.Fatalf("unexpected restart report: %+v", report)
	}
	replayAfterRestart, err := reopened.Write(context.Background(), first)
	if err != nil {
		t.Fatalf("replay after restart: %v", err)
	}
	assertWrite(t, replayAfterRestart, expected.Replay)

	blobPath := filepath.Join(root, "blobs", expected.MetadataSHA256)
	blob, err := os.ReadFile(blobPath)
	if err != nil {
		t.Fatalf("read blob: %v", err)
	}
	if !bytes.Equal(blob, metadata) {
		t.Fatal("blob bytes differ from the fixture")
	}
	for _, name := range manifestFiles(t, root) {
		manifest, err := os.ReadFile(filepath.Join(root, "manifests", name))
		if err != nil {
			t.Fatalf("read manifest: %v", err)
		}
		if strings.Contains(string(manifest), "wrapped_dek") || strings.Contains(string(manifest), "synthetic-c05") {
			t.Fatalf("manifest duplicates metadata bytes: %s", name)
		}
	}
}

func TestFixtureScopePathReplayAndBounds(t *testing.T) {
	var positive positiveFixture
	var negative negativeFixture
	loadFixture(t, "positive.json", &positive)
	loadFixture(t, "negative.json", &negative)
	metadata := fixtureMetadata(t, positive)

	root := t.TempDir()
	store, _ := mustOpen(t, root)
	if _, err := store.Write(context.Background(), request(positive, positive.OperationID, positive.ExpectedVersion, metadata)); err != nil {
		t.Fatalf("seed write: %v", err)
	}

	for _, testCase := range negative.Cases {
		t.Run(testCase.CaseName, func(t *testing.T) {
			switch testCase.Kind {
			case "read":
				_, err := store.Read(context.Background(), storage.ReadRequest{Owner: testCase.Owner, Scope: testCase.Scope, Name: testCase.Name})
				assertCode(t, err, storage.ErrorCode(testCase.ExpectedCode))
			case "write", "replay-conflict":
				var payload []byte
				if testCase.Metadata != nil {
					payload = []byte(*testCase.Metadata)
				}
				if testCase.MetadataRepeat > 0 {
					payload = bytes.Repeat([]byte("a"), testCase.MetadataRepeat)
				}
				_, err := store.Write(context.Background(), storage.WriteRequest{
					OperationID:     testCase.OperationID,
					Owner:           testCase.Owner,
					Scope:           testCase.Scope,
					Name:            testCase.Name,
					ExpectedVersion: testCase.ExpectedVersion,
					Metadata:        payload,
				})
				assertCode(t, err, storage.ErrorCode(testCase.ExpectedCode))
			default:
				t.Fatalf("unknown fixture kind %q", testCase.Kind)
			}
		})
	}

	record, err := store.Read(context.Background(), readRequest(positive))
	if err != nil {
		t.Fatalf("read after rejected writes: %v", err)
	}
	if record.EntityVersion != 1 || !bytes.Equal(record.Metadata, metadata) {
		t.Fatalf("rejected writes changed state: %+v", record)
	}
	if names := manifestFiles(t, root); len(names) != 1 {
		t.Fatalf("rejected writes published manifests: %v", names)
	}
}

func TestSingleWriterLockAndRelease(t *testing.T) {
	root := t.TempDir()
	first, _ := mustOpen(t, root)
	second, _, err := storage.Open(root)
	if err == nil {
		_ = second.Close()
		t.Fatal("second writer acquired the lock")
	}
	assertCode(t, err, storage.CodeLocked)
	if err := first.Close(); err != nil {
		t.Fatalf("close first writer: %v", err)
	}
	third, _, err := storage.Open(root)
	if err != nil {
		t.Fatalf("lock not released: %v", err)
	}
	_ = third.Close()
}

func TestRecoveryMatrix(t *testing.T) {
	var positive positiveFixture
	var expected expectedFixture
	var recovery recoveryFixture
	loadFixture(t, "positive.json", &positive)
	loadFixture(t, "expected-output.json", &expected)
	loadFixture(t, "recovery.json", &recovery)
	metadata := fixtureMetadata(t, positive)

	for _, testCase := range recovery.Cases {
		t.Run(testCase.Name, func(t *testing.T) {
			root := t.TempDir()
			store, report := mustOpen(t, root)
			if report.ManifestVersion != 0 {
				t.Fatalf("unexpected initial manifest: %+v", report)
			}
			if _, err := store.Write(context.Background(), request(positive, positive.OperationID, 0, metadata)); err != nil {
				t.Fatalf("seed first write: %v", err)
			}
			if _, err := store.Write(context.Background(), request(positive, positive.SecondOperationID, 1, metadata)); err != nil {
				t.Fatalf("seed second write: %v", err)
			}
			if err := store.Close(); err != nil {
				t.Fatalf("close seeded store: %v", err)
			}

			applyRecoverySetup(t, root, testCase.Setup, expected.MetadataSHA256)

			reopened, report, err := storage.Open(root)
			if testCase.Expected.OpenOK {
				if err != nil {
					t.Fatalf("open after %s: %v", testCase.Setup, err)
				}
				defer reopened.Close()
				if report.ManifestVersion != expected.OrphanRecovery.ManifestVersion ||
					report.Records != expected.OrphanRecovery.Records {
					t.Fatalf("unexpected recovery report: %+v", report)
				}
				if report.RemovedStaging != testCase.Expected.RemovedStaging ||
					report.RemovedOrphanBlobs != testCase.Expected.RemovedOrphanBlobs {
					t.Fatalf("unexpected cleanup counts: %+v", report)
				}
				record, err := reopened.Read(context.Background(), readRequest(positive))
				if err != nil {
					t.Fatalf("read recovered record: %v", err)
				}
				if !bytes.Equal(record.Metadata, metadata) {
					t.Fatal("recovered metadata differs")
				}
				return
			}

			if err == nil {
				_ = reopened.Close()
				t.Fatalf("open succeeded for %s", testCase.Setup)
			}
			assertCode(t, err, storage.ErrorCode(testCase.Expected.ExpectedCode))
			if _, _, secondErr := storage.Open(root); codeOf(secondErr) == storage.CodeLocked {
				t.Fatal("failed open retained the writer lock")
			}
		})
	}
}

func applyRecoverySetup(t *testing.T, root, setup, digest string) {
	t.Helper()
	switch setup {
	case "orphan_staging":
		if err := os.WriteFile(filepath.Join(root, "staging", "orphan.tmp"), []byte("uncommitted"), 0o600); err != nil {
			t.Fatalf("create orphan staging: %v", err)
		}
	case "orphan_blob":
		if err := os.WriteFile(filepath.Join(root, "blobs", strings.Repeat("ab", 32)), []byte("orphan"), 0o600); err != nil {
			t.Fatalf("create orphan blob: %v", err)
		}
	case "missing_blob":
		if err := os.Remove(filepath.Join(root, "blobs", digest)); err != nil {
			t.Fatalf("remove referenced blob: %v", err)
		}
	case "corrupt_blob":
		if err := os.WriteFile(filepath.Join(root, "blobs", digest), []byte("corrupt"), 0o600); err != nil {
			t.Fatalf("corrupt blob: %v", err)
		}
	case "corrupt_manifest":
		names := manifestFiles(t, root)
		if len(names) == 0 {
			t.Fatal("no manifest to corrupt")
		}
		if err := os.WriteFile(filepath.Join(root, "manifests", names[len(names)-1]), []byte("{"), 0o600); err != nil {
			t.Fatalf("corrupt manifest: %v", err)
		}
	default:
		t.Fatalf("unknown recovery setup %q", setup)
	}
}

func TestBoundedStateAndOperationWindow(t *testing.T) {
	var positive positiveFixture
	loadFixture(t, "positive.json", &positive)
	metadata := fixtureMetadata(t, positive)

	root := t.TempDir()
	store, _ := mustOpen(t, root)

	var latest storage.WriteResult
	for index := 0; index < 7; index++ {
		result, err := store.Write(context.Background(), request(positive, fmt.Sprintf("op-bounds-%03d", index), int64(index), metadata))
		if err != nil {
			t.Fatalf("bounded write %d: %v", index, err)
		}
		latest = result
	}
	if names := manifestFiles(t, root); len(names) > storage.MaxManifestVersions {
		t.Fatalf("manifest history is unbounded: %d files", len(names))
	}
	replay, err := store.Write(context.Background(), request(positive, fmt.Sprintf("op-bounds-%03d", 6), 6, metadata))
	if err != nil {
		t.Fatalf("replay latest operation: %v", err)
	}
	if !replay.Duplicate || replay.ManifestVersion != latest.ManifestVersion {
		t.Fatalf("latest operation did not replay: %+v", replay)
	}

	for index := 0; index < 260; index++ {
		expectedVersion := int64(7 + index)
		if _, err := store.Write(context.Background(), request(positive, fmt.Sprintf("op-window-%03d", index), expectedVersion, metadata)); err != nil {
			t.Fatalf("window write %d: %v", index, err)
		}
	}
	latestManifest := readLatestManifest(t, root)
	if len(latestManifest.Operations) > storage.MaxOperations {
		t.Fatalf("operation window is unbounded: %d", len(latestManifest.Operations))
	}
	if record, err := store.Read(context.Background(), readRequest(positive)); err != nil || record.EntityVersion != 267 {
		t.Fatalf("unexpected record after window writes: %+v (%v)", record, err)
	}

	for index := 0; index < storage.MaxRecords-1; index++ {
		request := storage.WriteRequest{
			OperationID:     fmt.Sprintf("op-record-%03d", index),
			Owner:           positive.Owner,
			Scope:           positive.Scope,
			Name:            fmt.Sprintf("app/prod/item-%03d", index),
			ExpectedVersion: 0,
			Metadata:        metadata,
		}
		if _, err := store.Write(context.Background(), request); err != nil {
			t.Fatalf("record quota seed %d: %v", index, err)
		}
	}
	_, err = store.Write(context.Background(), storage.WriteRequest{
		OperationID:     "op-record-overflow",
		Owner:           positive.Owner,
		Scope:           positive.Scope,
		Name:            "app/prod/overflow",
		ExpectedVersion: 0,
		Metadata:        metadata,
	})
	assertCode(t, err, storage.CodeQuotaExceeded)
}

type manifestFixture struct {
	Operations []json.RawMessage `json:"operations"`
}

func readLatestManifest(t *testing.T, root string) manifestFixture {
	t.Helper()
	names := manifestFiles(t, root)
	if len(names) == 0 {
		t.Fatal("no manifest found")
	}
	data, err := os.ReadFile(filepath.Join(root, "manifests", names[len(names)-1]))
	if err != nil {
		t.Fatalf("read latest manifest: %v", err)
	}
	var value manifestFixture
	if err := json.Unmarshal(data, &value); err != nil {
		t.Fatalf("parse latest manifest: %v", err)
	}
	return value
}

func TestConcurrentWritesAreSerialized(t *testing.T) {
	var positive positiveFixture
	loadFixture(t, "positive.json", &positive)
	metadata := fixtureMetadata(t, positive)

	root := t.TempDir()
	store, _ := mustOpen(t, root)
	const writers = 24
	results := make([]storage.WriteResult, writers)
	errs := make([]error, writers)
	var wait sync.WaitGroup
	for index := 0; index < writers; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			results[index], errs[index] = store.Write(context.Background(), storage.WriteRequest{
				OperationID:     fmt.Sprintf("op-concurrent-%03d", index),
				Owner:           positive.Owner,
				Scope:           positive.Scope,
				Name:            fmt.Sprintf("app/prod/concurrent-%03d", index),
				ExpectedVersion: 0,
				Metadata:        metadata,
			})
		}(index)
	}
	wait.Wait()
	for index, err := range errs {
		if err != nil {
			t.Fatalf("concurrent writer %d: %v", index, err)
		}
	}
	versions := make([]int64, 0, writers)
	for _, result := range results {
		versions = append(versions, result.ManifestVersion)
	}
	sort.Slice(versions, func(i, j int) bool { return versions[i] < versions[j] })
	for index, version := range versions {
		if version != int64(index+1) {
			t.Fatalf("manifest versions are not sequential: %v", versions)
		}
	}
	for index := 0; index < writers; index++ {
		record, err := store.Read(context.Background(), storage.ReadRequest{
			Owner: positive.Owner,
			Scope: positive.Scope,
			Name:  fmt.Sprintf("app/prod/concurrent-%03d", index),
		})
		if err != nil || record.EntityVersion != 1 {
			t.Fatalf("read concurrent record %d: %+v (%v)", index, record, err)
		}
	}
}

func TestReadVerifiesStoredBytes(t *testing.T) {
	var positive positiveFixture
	loadFixture(t, "positive.json", &positive)
	metadata := fixtureMetadata(t, positive)

	for _, setup := range []string{"missing", "corrupt"} {
		t.Run(setup, func(t *testing.T) {
			root := t.TempDir()
			store, _ := mustOpen(t, root)
			if _, err := store.Write(context.Background(), request(positive, positive.OperationID, 0, metadata)); err != nil {
				t.Fatalf("seed write: %v", err)
			}
			blobPath := filepath.Join(root, "blobs", sha256Hex(metadata))
			if setup == "missing" {
				if err := os.Remove(blobPath); err != nil {
					t.Fatalf("remove blob: %v", err)
				}
			} else if err := os.WriteFile(blobPath, []byte("corrupt"), 0o600); err != nil {
				t.Fatalf("corrupt blob: %v", err)
			}
			record, err := store.Read(context.Background(), readRequest(positive))
			assertCode(t, err, storage.CodeCorruptState)
			if len(record.Metadata) != 0 {
				t.Fatal("corrupt read returned bytes")
			}
		})
	}
}

func TestNoPlaintextOrDuplicateMetadataPersisted(t *testing.T) {
	var positive positiveFixture
	var expected expectedFixture
	loadFixture(t, "positive.json", &positive)
	loadFixture(t, "expected-output.json", &expected)
	metadata := fixtureMetadata(t, positive)

	root := t.TempDir()
	store, _ := mustOpen(t, root)
	if _, err := store.Write(context.Background(), request(positive, positive.OperationID, 0, metadata)); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	err := filepath.WalkDir(root, func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		data, err := os.ReadFile(name)
		if err != nil {
			return err
		}
		if strings.Contains(string(data), expected.PlaintextCanary) {
			t.Fatalf("plaintext canary persisted in %s", name)
		}
		if strings.Contains(filepath.ToSlash(name), "manifests") && strings.Contains(string(data), "wrapped_dek") {
			t.Fatalf("manifest duplicates metadata body: %s", name)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk store: %v", err)
	}
}

func TestContextCancellationDoesNotWrite(t *testing.T) {
	var positive positiveFixture
	loadFixture(t, "positive.json", &positive)
	metadata := fixtureMetadata(t, positive)

	root := t.TempDir()
	store, _ := mustOpen(t, root)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := store.Write(ctx, request(positive, positive.OperationID, 0, metadata))
	assertCode(t, err, storage.CodeCancelled)
	_, err = store.Read(ctx, readRequest(positive))
	assertCode(t, err, storage.CodeCancelled)
	if names := manifestFiles(t, root); len(names) != 0 {
		t.Fatalf("cancelled write published a manifest: %v", names)
	}
	if _, err := store.Write(context.Background(), request(positive, positive.OperationID, 0, metadata)); err != nil {
		t.Fatalf("write after cancellation: %v", err)
	}
}
