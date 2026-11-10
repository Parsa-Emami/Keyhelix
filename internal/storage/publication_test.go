package storage

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

var c40Write = WriteRequest{
	OperationID: "c40-release-update", Owner: "alice", Scope: "vault-prod", Name: "app/prod/c40",
	ExpectedVersion: 1, Metadata: []byte(`{"provider_ref":"openbao://synthetic/v2"}`),
}

func TestC40KilledWriter(t *testing.T) {
	root := os.Getenv("KEYHELIX_C40_CRASH_STORE")
	if root == "" {
		return
	}
	crashStage := stage(os.Getenv("KEYHELIX_C40_CRASH_STAGE"))
	store, _, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	store.faults = func(current stage) error {
		if current == crashStage {
			return syscall.Kill(os.Getpid(), syscall.SIGKILL)
		}
		return nil
	}
	_, err = store.Write(context.Background(), c40Write)
	t.Fatalf("writer returned before being killed at %s: %v", crashStage, err)
}

func TestC40RecoveryAtPublicationBoundary(t *testing.T) {
	for _, scenario := range []struct {
		boundary  stage
		committed bool
	}{
		{stageManifestRename, false},
		{stageManifestDirSync, true},
	} {
		t.Run(string(scenario.boundary), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			root := t.TempDir()
			store, _, err := Open(root)
			if err != nil {
				t.Fatal(err)
			}
			initial := c40Write
			initial.OperationID, initial.ExpectedVersion = "c40-release-seed", 0
			initial.Metadata = []byte(`{"provider_ref":"openbao://synthetic/v1"}`)
			if _, err := store.Write(ctx, initial); err != nil {
				t.Fatal(err)
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}

			child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestC40KilledWriter$")
			child.Env = append(os.Environ(), "KEYHELIX_C40_CRASH_STORE="+root, "KEYHELIX_C40_CRASH_STAGE="+string(scenario.boundary))
			output, err := child.CombinedOutput()
			var killed *exec.ExitError
			if ctx.Err() != nil || !errors.As(err, &killed) || killed.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
				t.Fatalf("expected SIGKILL at %s: %v %s", scenario.boundary, err, output)
			}

			reopened, recovery, err := Open(root)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			expectedBytes, expectedVersion := initial.Metadata, int64(1)
			if scenario.committed {
				expectedBytes, expectedVersion = c40Write.Metadata, 2
			}
			record, err := reopened.Read(ctx, ReadRequest{Owner: c40Write.Owner, Scope: c40Write.Scope, Name: c40Write.Name})
			if err != nil || record.EntityVersion != expectedVersion || !bytes.Equal(record.Metadata, expectedBytes) || recovery.ManifestVersion != expectedVersion || recovery.Records != 1 {
				t.Fatalf("incorrect recovery: record=%+v recovery=%+v error=%v", record, recovery, err)
			}
			replayed, err := reopened.Write(ctx, c40Write)
			if err != nil || replayed.Duplicate != scenario.committed || replayed.EntityVersion != 2 || replayed.ManifestVersion != 2 {
				t.Fatalf("incorrect retry after lost acknowledgment: %+v %v", replayed, err)
			}
			oversized := c40Write
			oversized.OperationID, oversized.ExpectedVersion = "c40-release-oversized", 2
			oversized.Metadata = bytes.Repeat([]byte("x"), MaxMetadataBytes+1)
			if _, err := reopened.Write(ctx, oversized); faultCode(err) != CodeQuotaExceeded {
				t.Fatalf("incorrect quota outcome: %v", err)
			}
			record, err = reopened.Read(ctx, ReadRequest{Owner: c40Write.Owner, Scope: c40Write.Scope, Name: c40Write.Name})
			if err != nil || record.EntityVersion != 2 || !bytes.Equal(record.Metadata, c40Write.Metadata) {
				t.Fatalf("quota rejection altered committed state: %+v %v", record, err)
			}
		})
	}
}
