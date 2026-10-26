package storage

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

type faultCase struct {
	Stage        string `json:"stage"`
	ExpectedCode string `json:"expected_code"`
}

type recoveryFixture struct {
	FaultCases []faultCase `json:"fault_cases"`
}

var faultStages = map[string]stage{
	string(stageMetadataWrite):   stageMetadataWrite,
	string(stageMetadataSync):    stageMetadataSync,
	string(stageMetadataRename):  stageMetadataRename,
	string(stageMetadataDirSync): stageMetadataDirSync,
	string(stageManifestWrite):   stageManifestWrite,
	string(stageManifestSync):    stageManifestSync,
	string(stageManifestRename):  stageManifestRename,
	string(stageManifestDirSync): stageManifestDirSync,
}

func loadFaultCases(t *testing.T) []faultCase {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "tests", "fixtures", "keyhelix", "C05", "recovery.json"))
	if err != nil {
		t.Fatalf("read recovery fixture: %v", err)
	}
	var fixture recoveryFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatalf("parse recovery fixture: %v", err)
	}
	if len(fixture.FaultCases) == 0 {
		t.Fatal("no fault cases")
	}
	return fixture.FaultCases
}

func faultCode(err error) ErrorCode {
	var typed *Error
	if errors.As(err, &typed) {
		return typed.Code
	}
	return ""
}

func TestInjectedDeviceFailuresDoNotCommit(t *testing.T) {
	metadata := []byte(`{"synthetic":"c05-fault-metadata"}`)
	seedRequest := WriteRequest{
		OperationID:     "op-fault-seed",
		Owner:           "alice@keyhelix.local",
		Scope:           "vault-prod",
		Name:            "app/prod/database-url",
		ExpectedVersion: 0,
		Metadata:        metadata,
	}

	for _, testCase := range loadFaultCases(t) {
		t.Run(testCase.Stage, func(t *testing.T) {
			stageValue, ok := faultStages[testCase.Stage]
			if !ok {
				t.Fatalf("unknown fault stage %q", testCase.Stage)
			}
			root := t.TempDir()
			store, _, err := Open(root)
			if err != nil {
				t.Fatalf("open: %v", err)
			}
			defer store.Close()
			if _, err := store.Write(context.Background(), seedRequest); err != nil {
				t.Fatalf("seed write: %v", err)
			}

			store.faults = func(value stage) error {
				if value == stageValue {
					return syscall.ENOSPC
				}
				return nil
			}
			failing := WriteRequest{
				OperationID:     "op-fault-" + strings.ReplaceAll(testCase.Stage, "_", "-"),
				Owner:           "alice@keyhelix.local",
				Scope:           "vault-prod",
				Name:            "app/prod/fault-target",
				ExpectedVersion: 0,
				Metadata:        []byte(`{"synthetic":"c05-fault-target"}`),
			}
			if _, err := store.Write(context.Background(), failing); err == nil {
				t.Fatal("injected failure was acknowledged")
			} else if actual := faultCode(err); actual != ErrorCode(testCase.ExpectedCode) {
				t.Fatalf("expected %s, got %s (%v)", testCase.ExpectedCode, actual, err)
			}
			store.faults = nil
			if entries, err := os.ReadDir(filepath.Join(root, "blobs")); err != nil {
				t.Fatalf("read blobs: %v", err)
			} else {
				expectedBlobs := 1
				if testCase.Stage == string(stageManifestDirSync) {
					// The manifest rename already happened; its blob is referenced
					// by the durable manifest and must survive for replay recovery.
					expectedBlobs = 2
				}
				if len(entries) != expectedBlobs {
					t.Fatalf("failed write left %d blobs, want %d", len(entries), expectedBlobs)
				}
			}

			seed, err := store.Read(context.Background(), ReadRequest{Owner: seedRequest.Owner, Scope: seedRequest.Scope, Name: seedRequest.Name})
			if err != nil {
				t.Fatalf("seed state was damaged: %v", err)
			}
			if !bytes.Equal(seed.Metadata, metadata) {
				t.Fatal("seed metadata changed")
			}
			if _, err := store.Read(context.Background(), ReadRequest{Owner: failing.Owner, Scope: failing.Scope, Name: failing.Name}); faultCode(err) != CodeNotFound {
				t.Fatalf("failed write became visible: %v", err)
			}
			if store.manifestVersion != 1 {
				t.Fatalf("failed write advanced manifest version to %d", store.manifestVersion)
			}

			retried, err := store.Write(context.Background(), failing)
			if err != nil {
				t.Fatalf("retry after failure: %v", err)
			}
			if retried.Duplicate || retried.ManifestVersion != 2 || retried.EntityVersion != 1 {
				t.Fatalf("unexpected retry result: %+v", retried)
			}
			if err := store.Close(); err != nil {
				t.Fatalf("close: %v", err)
			}

			reopened, report, err := Open(root)
			if err != nil {
				t.Fatalf("reopen: %v", err)
			}
			defer reopened.Close()
			if report.ManifestVersion != 2 || report.Records != 2 {
				t.Fatalf("unexpected recovery report: %+v", report)
			}
			replay, err := reopened.Write(context.Background(), failing)
			if err != nil {
				t.Fatalf("replay after restart: %v", err)
			}
			if !replay.Duplicate || replay.ManifestVersion != 2 || replay.EntityVersion != 1 {
				t.Fatalf("unexpected replay: %+v", replay)
			}
			target, err := reopened.Read(context.Background(), ReadRequest{Owner: failing.Owner, Scope: failing.Scope, Name: failing.Name})
			if err != nil {
				t.Fatalf("read retried record: %v", err)
			}
			if !bytes.Equal(target.Metadata, failing.Metadata) {
				t.Fatal("retried metadata differs")
			}
		})
	}
}

func TestFailedWriteAfterAmbiguousManifestDoesNotAccumulateOrphans(t *testing.T) {
	root := t.TempDir()
	store, _, err := Open(root)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer store.Close()
	metadataA := []byte(`{"synthetic":"c05-ambiguous-a"}`)
	metadataB := []byte(`{"synthetic":"c05-ambiguous-b"}`)
	if _, err := store.Write(context.Background(), WriteRequest{
		OperationID: "op-ambiguous-seed-01", Owner: "alice@keyhelix.local", Scope: "vault-prod", Name: "app/prod/ambiguous-seed", Metadata: []byte(`{"synthetic":"c05-seed"}`),
	}); err != nil {
		t.Fatalf("seed write: %v", err)
	}
	store.faults = func(value stage) error {
		if value == stageManifestDirSync {
			return syscall.ENOSPC
		}
		return nil
	}
	if _, err := store.Write(context.Background(), WriteRequest{
		OperationID: "op-ambiguous-a-01", Owner: "alice@keyhelix.local", Scope: "vault-prod", Name: "app/prod/ambiguous-a", Metadata: metadataA,
	}); err == nil {
		t.Fatal("ambiguous manifest commit was acknowledged")
	}
	store.faults = nil

	store.faults = func(value stage) error {
		if value == stageMetadataDirSync {
			return syscall.ENOSPC
		}
		return nil
	}
	if _, err := store.Write(context.Background(), WriteRequest{
		OperationID: "op-ambiguous-b-01", Owner: "alice@keyhelix.local", Scope: "vault-prod", Name: "app/prod/ambiguous-b", Metadata: metadataB,
	}); err == nil {
		t.Fatal("failed metadata directory sync was acknowledged")
	}
	store.faults = nil

	entries, err := os.ReadDir(filepath.Join(root, "blobs"))
	if err != nil {
		t.Fatalf("read blobs: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("orphan blob was not cleaned: %d blobs remain", len(entries))
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	reopened, report, err := Open(root)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()
	if report.ManifestVersion != 2 || report.Records != 2 {
		t.Fatalf("unexpected recovery report: %+v", report)
	}
}

func TestAmbiguousManifestCommitReplaysAfterRestart(t *testing.T) {
	root := t.TempDir()
	store, _, err := Open(root)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	metadata := []byte(`{"synthetic":"c05-ambiguous-commit"}`)
	request := WriteRequest{
		OperationID:     "op-ambiguous-0001",
		Owner:           "alice@keyhelix.local",
		Scope:           "vault-prod",
		Name:            "app/prod/ambiguous",
		ExpectedVersion: 0,
		Metadata:        metadata,
	}
	store.faults = func(value stage) error {
		if value == stageManifestDirSync {
			return syscall.ENOSPC
		}
		return nil
	}
	if _, err := store.Write(context.Background(), request); err == nil {
		t.Fatal("ambiguous commit was acknowledged")
	}
	store.faults = nil
	if store.manifestVersion != 0 {
		t.Fatalf("in-memory state advanced after failed directory sync: %d", store.manifestVersion)
	}
	if _, err := store.Read(context.Background(), ReadRequest{Owner: request.Owner, Scope: request.Scope, Name: request.Name}); faultCode(err) != CodeNotFound {
		t.Fatalf("ambiguous commit became visible in memory: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	reopened, report, err := Open(root)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()
	if report.ManifestVersion != 1 || report.Records != 1 {
		t.Fatalf("durable ambiguous commit was not recovered: %+v", report)
	}
	replay, err := reopened.Write(context.Background(), request)
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if !replay.Duplicate || replay.ManifestVersion != 1 || replay.EntityVersion != 1 {
		t.Fatalf("unexpected replay: %+v", replay)
	}
	record, err := reopened.Read(context.Background(), ReadRequest{Owner: request.Owner, Scope: request.Scope, Name: request.Name})
	if err != nil {
		t.Fatalf("read recovered record: %v", err)
	}
	if !bytes.Equal(record.Metadata, metadata) {
		t.Fatal("recovered metadata differs")
	}
	if names := storedManifestNames(t, root); len(names) != 1 {
		t.Fatalf("replay published another manifest: %v", names)
	}
}

func TestFailedOpenReleasesLock(t *testing.T) {
	root := t.TempDir()
	store, _, err := Open(root)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	metadata := []byte(`{"synthetic":"c05-lock-release"}`)
	if _, err := store.Write(context.Background(), WriteRequest{
		OperationID:     "op-lock-release-01",
		Owner:           "alice@keyhelix.local",
		Scope:           "vault-prod",
		Name:            "app/prod/lock-release",
		ExpectedVersion: 0,
		Metadata:        metadata,
	}); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	names := storedManifestNames(t, root)
	if len(names) != 1 {
		t.Fatalf("unexpected manifests: %v", names)
	}
	if err := os.WriteFile(filepath.Join(root, "manifests", names[0]), []byte("{"), 0o600); err != nil {
		t.Fatalf("corrupt manifest: %v", err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		_, _, err := Open(root)
		if err == nil {
			t.Fatal("corrupt manifest was accepted")
		}
		if actual := faultCode(err); actual != CodeCorruptState {
			t.Fatalf("expected %s, got %s (%v)", CodeCorruptState, actual, err)
		}
	}
}

func storedManifestNames(t *testing.T, root string) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(root, "manifests"))
	if err != nil {
		t.Fatalf("read manifests: %v", err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names
}
