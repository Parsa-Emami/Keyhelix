package storage_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/parsa-emami/keyhelix/internal/auth"
	"github.com/parsa-emami/keyhelix/internal/grants"
	"github.com/parsa-emami/keyhelix/internal/provider"
	"github.com/parsa-emami/keyhelix/internal/secrets"
	"github.com/parsa-emami/keyhelix/internal/storage"
)

// C24 is an operator recovery drill. It uses the real local metadata store and
// the real OpenBao capability adapter against the existing in-process
// OpenBao-compatible wire fixture in this package. The operator material gate
// below models the offline unseal material that the provider requires; it is a
// drill harness, not an engine restore command or a substitute for a live
// OpenBao restore.

const (
	c24CodeMaterialRequired = "RECOVERY_MATERIAL_REQUIRED"
	c24CodeMaterialInvalid  = "RECOVERY_MATERIAL_INVALID"
	c24CodeBackupCorrupt    = "BACKUP_CORRUPT"
	c24CodeTargetNotEmpty   = "TARGET_NOT_EMPTY"
	c24CodeIOFailure        = "IO_FAILURE"

	c24CrashChildEnv = "KEYHELIX_C24_CRASH_CHILD"
	c24CrashRootEnv  = "KEYHELIX_C24_CRASH_ROOT"
	c24CrashReadyEnv = "KEYHELIX_C24_CRASH_READY"
	c24CrashOpEnv    = "KEYHELIX_C24_CRASH_OP"

	c24CrashOperationID = "op-c24-crash-001"
)

type c24Error struct {
	Code  string
	Stage string
	Err   error
}

func (e *c24Error) Error() string {
	if e.Stage != "" {
		return e.Code + ":" + e.Stage
	}
	return e.Code
}

func (e *c24Error) Unwrap() error { return e.Err }

func c24Failure(code, stage string, err error) error {
	return &c24Error{Code: code, Stage: stage, Err: err}
}

func c24CodeOf(err error) string {
	var typed *c24Error
	if errors.As(err, &typed) {
		return typed.Code
	}
	var storageErr *storage.Error
	if errors.As(err, &storageErr) {
		return string(storageErr.Code)
	}
	var providerErr *provider.Error
	if errors.As(err, &providerErr) {
		return string(providerErr.Code)
	}
	return ""
}

func c24AssertCode(t *testing.T, err error, expected string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected %s, got nil", expected)
	}
	if actual := c24CodeOf(err); actual != expected {
		t.Fatalf("expected %s, got %s (%v)", expected, actual, err)
	}
}

func c24RequireCase(t *testing.T, cases map[string]c24NegativeCase, kind string) c24NegativeCase {
	t.Helper()
	testCase, ok := cases[kind]
	if !ok {
		t.Fatalf("missing C24 fixture case %q", kind)
	}
	return testCase
}

type c24Vault struct {
	VaultID string `json:"vault_id"`
	KEKID   string `json:"kek_id"`
	Mount   string `json:"mount"`
	Role    string `json:"role"`
}

type c24Identity struct {
	Subject       string   `json:"subject"`
	Email         string   `json:"email"`
	VaultRole     string   `json:"vault_role"`
	AllowedOwners []string `json:"allowed_owners"`
	AllowedScopes []string `json:"allowed_scopes"`
}

type c24Secret struct {
	SecretPath       string `json:"secret_path"`
	Classification   string `json:"classification"`
	PlaintextCanary  string `json:"plaintext_canary"`
	WriteOperationID string `json:"write_operation_id"`
	ExpectedVersion  int64  `json:"expected_version"`
}

type c24RevokedGrant struct {
	GrantID     string `json:"grant_id"`
	OperationID string `json:"operation_id"`
	File        string `json:"file"`
}

type c24OperatorMaterialFixture struct {
	Custody          string `json:"custody"`
	Threshold        int    `json:"threshold"`
	Shares           int    `json:"shares"`
	IncludedInBackup bool   `json:"included_in_backup"`
	File             string `json:"file"`
}

type c24ExpectedRestore struct {
	ManifestVersion           int64 `json:"manifest_version"`
	Records                   int   `json:"records"`
	RevokedGrantPreserved     bool  `json:"revoked_grant_preserved"`
	ProviderSealedUntilUnseal bool  `json:"provider_sealed_until_unseal"`
	TargetMustBeEmpty         bool  `json:"target_must_be_empty"`
}

type c24PositiveFixture struct {
	SchemaVersion    int                        `json:"schema_version"`
	Provenance       string                     `json:"provenance"`
	License          string                     `json:"license"`
	Vault            c24Vault                   `json:"vault"`
	Identity         c24Identity                `json:"identity"`
	Secret           c24Secret                  `json:"secret"`
	RevokedGrant     c24RevokedGrant            `json:"revoked_grant"`
	OperatorMaterial c24OperatorMaterialFixture `json:"operator_material"`
	ExpectedRestore  c24ExpectedRestore         `json:"expected_restore"`
}

type c24NegativeCase struct {
	Case         string `json:"case"`
	Kind         string `json:"kind"`
	Description  string `json:"description"`
	ExpectedCode string `json:"expected_code"`
}

type c24NegativeFixture struct {
	SchemaVersion      int               `json:"schema_version"`
	Provenance         string            `json:"provenance"`
	License            string            `json:"license"`
	UnsealAttemptLimit int               `json:"unseal_attempt_limit"`
	Cases              []c24NegativeCase `json:"cases"`
}

type c24ExpectedOutput struct {
	SchemaVersion                     int               `json:"schema_version"`
	Requirement                       string            `json:"requirement"`
	Acceptance                        string            `json:"acceptance"`
	Status                            string            `json:"status"`
	RecoveryMaterialRequired          bool              `json:"recovery_material_required"`
	RestoreTestedOnIsolatedInstance   bool              `json:"restore_tested_on_isolated_instance"`
	ProviderSealedUntilUnseal         bool              `json:"provider_sealed_until_unseal"`
	RevokedGrantPreserved             bool              `json:"revoked_grant_preserved"`
	NewerTargetNotOverwritten         bool              `json:"newer_target_not_overwritten"`
	CrashBoundaryCompletePriorOrNew   bool              `json:"crash_boundary_complete_prior_or_new"`
	ReplayHasNoDuplicateSideEffect    bool              `json:"replay_has_no_duplicate_side_effect"`
	QuotaBoundedWithoutPartialSuccess bool              `json:"quota_bounded_without_partial_success"`
	ProviderOwnsSecretBytes           bool              `json:"provider_owns_secret_bytes"`
	GuardCodes                        map[string]string `json:"guard_codes"`
	RevokedGrantSHA256                string            `json:"revoked_grant_sha256"`
	ManifestVersion                   int64             `json:"manifest_version"`
	Records                           int               `json:"records"`
	PlaintextCanaryOccurrences        int               `json:"plaintext_canary_occurrences"`
}

func c24LoadFixture(t *testing.T, name string, target any) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("fixtures", "keyhelix", "C24", name))
	if err != nil {
		t.Fatalf("read C24 fixture %s: %v", name, err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		t.Fatalf("parse C24 fixture %s: %v", name, err)
	}
	return data
}

func c24FixtureBytes(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("fixtures", "keyhelix", "C24", name))
	if err != nil {
		t.Fatalf("read C24 fixture %s: %v", name, err)
	}
	return data
}

type c24Material struct {
	Path   string
	Bytes  []byte
	SHA256 string
}

func c24WriteOperatorMaterial(t *testing.T, directory string) c24Material {
	t.Helper()
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatalf("create operator material directory: %v", err)
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("generate operator material: %v", err)
	}
	path := filepath.Join(directory, "recovery.key")
	if err := os.WriteFile(path, key, 0o600); err != nil {
		t.Fatalf("write operator material: %v", err)
	}
	return c24Material{Path: path, Bytes: key, SHA256: c24SHA256Hex(key)}
}

func (m c24Material) verify(path string) error {
	if strings.TrimSpace(path) == "" {
		return c24Failure(c24CodeMaterialRequired, "material", nil)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return c24Failure(c24CodeMaterialRequired, "material", err)
		}
		return c24Failure(c24CodeIOFailure, "material", err)
	}
	if len(data) == 0 {
		return c24Failure(c24CodeMaterialRequired, "material", nil)
	}
	if len(data) > 128 {
		return c24Failure(c24CodeMaterialInvalid, "material", nil)
	}
	actual := c24SHA256Hex(data)
	if subtle.ConstantTimeCompare([]byte(actual), []byte(m.SHA256)) != 1 {
		return c24Failure(c24CodeMaterialInvalid, "material", nil)
	}
	return nil
}

type c24BackupFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}

type c24BackupManifest struct {
	SchemaVersion          int             `json:"schema_version"`
	SourceManifestVersion  int64           `json:"source_manifest_version"`
	CreatedAt              string          `json:"created_at"`
	ProviderSnapshot       string          `json:"provider_snapshot"`
	ProviderSnapshotSHA256 string          `json:"provider_snapshot_sha256"`
	Files                  []c24BackupFile `json:"files"`
}

type c24ProviderSnapshot struct {
	SchemaVersion int               `json:"schema_version"`
	Sealed        map[string]string `json:"sealed"`
	Versions      map[string]int    `json:"versions"`
}

type c24Backup struct {
	Dir      string
	Manifest c24BackupManifest
	Provider c24ProviderSnapshot
}

type c24RestoreReport struct {
	ManifestVersion int64
	Records         int
	Files           int
	Provider        c24ProviderSnapshot
}

type c24RestoreOptions struct {
	FailAfterFiles int
}

func c24SHA256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func c24ManifestVersion(name string) (int64, bool) {
	if !strings.HasPrefix(name, "manifest-") || !strings.HasSuffix(name, ".json") {
		return 0, false
	}
	body := strings.TrimSuffix(strings.TrimPrefix(name, "manifest-"), ".json")
	if len(body) != 20 {
		return 0, false
	}
	version, err := strconv.ParseInt(body, 10, 64)
	if err != nil || version < 1 || version > storage.MaxSequence {
		return 0, false
	}
	return version, true
}

func c24ValidBlobName(name string) bool {
	if len(name) != 64 {
		return false
	}
	_, err := hex.DecodeString(name)
	return err == nil
}

func c24ReadBounded(t *testing.T, name string, maximum int64) []byte {
	t.Helper()
	info, err := os.Lstat(name)
	if err != nil {
		t.Fatalf("stat %s: %v", name, err)
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maximum {
		t.Fatalf("unexpected file shape for %s", name)
	}
	data, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return data
}

func c24WriteFile(t *testing.T, name string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(name), 0o700); err != nil {
		t.Fatalf("create directory for %s: %v", name, err)
	}
	file, err := os.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("create %s: %v", name, err)
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		t.Fatalf("write %s: %v", name, err)
	}
	if err := file.Sync(); err != nil {
		file.Close()
		t.Fatalf("sync %s: %v", name, err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close %s: %v", name, err)
	}
}

func c24CopyFile(t *testing.T, source, target string, maximum int64) []byte {
	t.Helper()
	data := c24ReadBounded(t, source, maximum)
	c24WriteFile(t, target, data)
	return data
}

func c24SyncDir(directory string) error {
	handle, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer handle.Close()
	return handle.Sync()
}

func c24CopyStoreDirectories(t *testing.T, sourceRoot, targetRoot string) {
	t.Helper()
	for _, name := range []string{"manifests", "blobs"} {
		entries, err := os.ReadDir(filepath.Join(sourceRoot, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		for _, entry := range entries {
			if !entry.Type().IsRegular() {
				t.Fatalf("unexpected %s entry %s", name, entry.Name())
			}
			target := filepath.Join(targetRoot, name, entry.Name())
			maximum := int64(storage.MaxMetadataBytes)
			if name == "manifests" {
				maximum = storage.MaxManifestBytes
			}
			c24CopyFile(t, filepath.Join(sourceRoot, name, entry.Name()), target, maximum)
		}
		if err := c24SyncDir(filepath.Join(targetRoot, name)); err != nil {
			t.Fatalf("sync copied %s: %v", name, err)
		}
	}
}

func c24BackupStore(t *testing.T, sourceRoot, backupDir string, state *c14ProviderState) c24Backup {
	t.Helper()
	if state == nil {
		t.Fatal("provider state is required for the recovery drill")
	}
	if err := os.MkdirAll(backupDir, 0o700); err != nil {
		t.Fatalf("create backup directory: %v", err)
	}

	manifest := c24BackupManifest{
		SchemaVersion:         1,
		CreatedAt:             time.Now().UTC().Format(time.RFC3339Nano),
		ProviderSnapshot:      "provider-snapshot.json",
		SourceManifestVersion: 0,
	}

	manifestEntries, err := os.ReadDir(filepath.Join(sourceRoot, "manifests"))
	if err != nil {
		t.Fatalf("read source manifests: %v", err)
	}
	names := make([]string, 0, len(manifestEntries))
	for _, entry := range manifestEntries {
		if !entry.Type().IsRegular() {
			t.Fatalf("unexpected manifest entry %s", entry.Name())
		}
		version, ok := c24ManifestVersion(entry.Name())
		if !ok {
			t.Fatalf("unexpected manifest name %s", entry.Name())
		}
		if version > manifest.SourceManifestVersion {
			manifest.SourceManifestVersion = version
		}
		names = append(names, entry.Name())
	}
	if len(names) == 0 {
		t.Fatal("source store has no committed manifest")
	}
	sort.Strings(names)

	blobEntries, err := os.ReadDir(filepath.Join(sourceRoot, "blobs"))
	if err != nil {
		t.Fatalf("read source blobs: %v", err)
	}
	blobNames := make([]string, 0, len(blobEntries))
	for _, entry := range blobEntries {
		if !entry.Type().IsRegular() || !c24ValidBlobName(entry.Name()) {
			t.Fatalf("unexpected blob entry %s", entry.Name())
		}
		blobNames = append(blobNames, entry.Name())
	}
	sort.Strings(blobNames)

	for _, name := range names {
		data := c24ReadBounded(t, filepath.Join(sourceRoot, "manifests", name), storage.MaxManifestBytes)
		relative := filepath.ToSlash(filepath.Join("manifests", name))
		c24WriteFile(t, filepath.Join(backupDir, "manifests", name), data)
		manifest.Files = append(manifest.Files, c24BackupFile{Path: relative, SHA256: c24SHA256Hex(data), Bytes: int64(len(data))})
	}
	for _, name := range blobNames {
		data := c24ReadBounded(t, filepath.Join(sourceRoot, "blobs", name), storage.MaxMetadataBytes)
		if c24SHA256Hex(data) != name {
			t.Fatalf("source blob %s does not match its digest", name)
		}
		relative := filepath.ToSlash(filepath.Join("blobs", name))
		c24WriteFile(t, filepath.Join(backupDir, "blobs", name), data)
		manifest.Files = append(manifest.Files, c24BackupFile{Path: relative, SHA256: c24SHA256Hex(data), Bytes: int64(len(data))})
	}

	snapshot := c24SnapshotProvider(t, state)
	snapshotBytes, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatalf("marshal provider snapshot: %v", err)
	}
	c24WriteFile(t, filepath.Join(backupDir, manifest.ProviderSnapshot), snapshotBytes)
	manifest.ProviderSnapshotSHA256 = c24SHA256Hex(snapshotBytes)

	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatalf("marshal backup manifest: %v", err)
	}
	manifestBytes = append(manifestBytes, '\n')
	c24WriteFile(t, filepath.Join(backupDir, "backup-manifest.json"), manifestBytes)
	if err := c24SyncDir(backupDir); err != nil {
		t.Fatalf("sync backup directory: %v", err)
	}
	return c24Backup{Dir: backupDir, Manifest: manifest, Provider: snapshot}
}

func c24SnapshotProvider(t *testing.T, state *c14ProviderState) c24ProviderSnapshot {
	t.Helper()
	state.mu.Lock()
	defer state.mu.Unlock()
	snapshot := c24ProviderSnapshot{
		SchemaVersion: 1,
		Sealed:        make(map[string]string, len(state.sealed)),
		Versions:      make(map[string]int, len(state.versions)),
	}
	for key, value := range state.sealed {
		snapshot.Sealed[key] = value
	}
	for key, value := range state.versions {
		snapshot.Versions[key] = value
	}
	return snapshot
}

func c24ReadBackupManifest(directory string) (c24BackupManifest, error) {
	name := filepath.Join(directory, "backup-manifest.json")
	info, err := os.Lstat(name)
	if err != nil {
		return c24BackupManifest{}, c24Failure(c24CodeBackupCorrupt, "backup_manifest", err)
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > storage.MaxManifestBytes {
		return c24BackupManifest{}, c24Failure(c24CodeBackupCorrupt, "backup_manifest", nil)
	}
	data, err := os.ReadFile(name)
	if err != nil {
		return c24BackupManifest{}, c24Failure(c24CodeIOFailure, "backup_manifest", err)
	}
	value := c24BackupManifest{}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return value, c24Failure(c24CodeBackupCorrupt, "backup_manifest", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return value, c24Failure(c24CodeBackupCorrupt, "backup_manifest", err)
	}
	return value, nil
}

func c24VerifyBackup(directory string, manifest c24BackupManifest) (c24ProviderSnapshot, error) {
	failure := func(stage string, err error) (c24ProviderSnapshot, error) {
		return c24ProviderSnapshot{}, c24Failure(c24CodeBackupCorrupt, stage, err)
	}
	if manifest.SchemaVersion != 1 || manifest.SourceManifestVersion < 1 {
		return failure("backup_manifest", nil)
	}
	if manifest.ProviderSnapshot != "provider-snapshot.json" || len(manifest.Files) == 0 {
		return failure("backup_manifest", nil)
	}

	seen := make(map[string]bool, len(manifest.Files)+2)
	allowed := map[string]bool{
		"backup-manifest.json":   true,
		"provider-snapshot.json": true,
	}
	manifestCount := 0
	blobCount := 0
	for _, entry := range manifest.Files {
		if entry.Path == "" || strings.Contains(entry.Path, "\\") || filepath.IsAbs(entry.Path) {
			return failure("backup_entry", nil)
		}
		clean := filepath.ToSlash(filepath.Clean(entry.Path))
		if clean != entry.Path || strings.Contains(clean, "..") {
			return failure("backup_entry", nil)
		}
		parts := strings.Split(clean, "/")
		if len(parts) != 2 {
			return failure("backup_entry", nil)
		}
		switch parts[0] {
		case "manifests":
			if _, ok := c24ManifestVersion(parts[1]); !ok || entry.Bytes <= 0 || entry.Bytes > storage.MaxManifestBytes {
				return failure("backup_entry", nil)
			}
			manifestCount++
		case "blobs":
			if !c24ValidBlobName(parts[1]) || entry.Bytes <= 0 || entry.Bytes > storage.MaxMetadataBytes {
				return failure("backup_entry", nil)
			}
			blobCount++
		default:
			return failure("backup_entry", nil)
		}
		if seen[clean] {
			return failure("backup_entry", nil)
		}
		seen[clean] = true
		allowed[clean] = true
	}
	if manifestCount == 0 || manifestCount > storage.MaxManifestVersions || blobCount > storage.MaxRecords {
		return failure("backup_entry", nil)
	}

	for _, entry := range manifest.Files {
		name := filepath.Join(directory, filepath.FromSlash(entry.Path))
		info, err := os.Lstat(name)
		if err != nil {
			return failure("backup_file", err)
		}
		if !info.Mode().IsRegular() || info.Size() != entry.Bytes {
			return failure("backup_file", nil)
		}
		data, err := os.ReadFile(name)
		if err != nil {
			return failure("backup_file", err)
		}
		if c24SHA256Hex(data) != entry.SHA256 {
			return failure("backup_file", nil)
		}
	}

	providerBytes, err := os.ReadFile(filepath.Join(directory, manifest.ProviderSnapshot))
	if err != nil {
		return failure("provider_snapshot", err)
	}
	if int64(len(providerBytes)) <= 0 || int64(len(providerBytes)) > storage.MaxManifestBytes {
		return failure("provider_snapshot", nil)
	}
	if c24SHA256Hex(providerBytes) != manifest.ProviderSnapshotSHA256 {
		return failure("provider_snapshot", nil)
	}
	snapshot := c24ProviderSnapshot{}
	decoder := json.NewDecoder(bytes.NewReader(providerBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&snapshot); err != nil {
		return failure("provider_snapshot", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return failure("provider_snapshot", err)
	}
	if snapshot.SchemaVersion != 1 || len(snapshot.Sealed) == 0 || len(snapshot.Sealed) > storage.MaxRecords || len(snapshot.Versions) != len(snapshot.Sealed) {
		return failure("provider_snapshot", nil)
	}
	for key, value := range snapshot.Sealed {
		if strings.TrimSpace(key) == "" || value == "" || snapshot.Versions[key] < 1 {
			return failure("provider_snapshot", nil)
		}
		decoded, err := base64.StdEncoding.DecodeString(value)
		if err != nil || len(decoded) == 0 || len(decoded) > provider.MaxSealedPayloadBytes {
			return failure("provider_snapshot", nil)
		}
	}

	err = filepath.WalkDir(directory, func(name string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("unexpected backup entry")
		}
		relative, err := filepath.Rel(directory, name)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		if !allowed[relative] {
			return fmt.Errorf("unlisted backup entry")
		}
		return nil
	})
	if err != nil {
		return failure("backup_tree", err)
	}
	return snapshot, nil
}

func c24CopyBackupFiles(t *testing.T, backupDir, targetRoot string, manifest c24BackupManifest, options c24RestoreOptions) error {
	t.Helper()
	copied := 0
	for _, entry := range manifest.Files {
		if options.FailAfterFiles > 0 && copied >= options.FailAfterFiles {
			return c24Failure(c24CodeIOFailure, "copy", nil)
		}
		source := filepath.Join(backupDir, filepath.FromSlash(entry.Path))
		target := filepath.Join(targetRoot, filepath.FromSlash(entry.Path))
		data := c24ReadBounded(t, source, storage.MaxManifestBytes)
		if int64(len(data)) != entry.Bytes || c24SHA256Hex(data) != entry.SHA256 {
			return c24Failure(c24CodeBackupCorrupt, "copy", nil)
		}
		c24WriteFile(t, target, data)
		copied++
	}
	for _, name := range []string{"manifests", "blobs"} {
		if err := c24SyncDir(filepath.Join(targetRoot, name)); err != nil {
			return c24Failure(c24CodeIOFailure, "sync", err)
		}
	}
	return nil
}

func c24Restore(t *testing.T, backupDir, targetRoot, materialPath string, material c24Material, options c24RestoreOptions) (c24RestoreReport, error) {
	t.Helper()
	if err := material.verify(materialPath); err != nil {
		return c24RestoreReport{}, err
	}
	manifest, err := c24ReadBackupManifest(backupDir)
	if err != nil {
		return c24RestoreReport{}, err
	}
	snapshot, err := c24VerifyBackup(backupDir, manifest)
	if err != nil {
		return c24RestoreReport{}, err
	}

	if info, err := os.Lstat(targetRoot); err == nil {
		if !info.IsDir() {
			return c24RestoreReport{}, c24Failure(c24CodeIOFailure, "target", nil)
		}
		entries, err := os.ReadDir(targetRoot)
		if err != nil {
			return c24RestoreReport{}, c24Failure(c24CodeIOFailure, "target", err)
		}
		if len(entries) != 0 {
			return c24RestoreReport{}, c24Failure(c24CodeTargetNotEmpty, "target", nil)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return c24RestoreReport{}, c24Failure(c24CodeIOFailure, "target", err)
	}

	temporary := targetRoot + ".restore-tmp-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	if err := os.MkdirAll(temporary, 0o700); err != nil {
		return c24RestoreReport{}, c24Failure(c24CodeIOFailure, "target_temp", err)
	}
	removeTemporary := true
	defer func() {
		if removeTemporary {
			_ = os.RemoveAll(temporary)
		}
	}()

	if err := c24CopyBackupFiles(t, backupDir, temporary, manifest, options); err != nil {
		return c24RestoreReport{}, err
	}

	store, recovery, err := storage.Open(temporary)
	if err != nil {
		return c24RestoreReport{}, c24Failure(c24CodeBackupCorrupt, "target_validate", err)
	}
	if err := store.Close(); err != nil {
		return c24RestoreReport{}, c24Failure(c24CodeIOFailure, "target_validate", err)
	}
	if recovery.ManifestVersion != manifest.SourceManifestVersion || recovery.Records <= 0 {
		return c24RestoreReport{}, c24Failure(c24CodeBackupCorrupt, "target_validate", nil)
	}

	if info, err := os.Lstat(targetRoot); err == nil && info.IsDir() {
		if err := os.Remove(targetRoot); err != nil {
			return c24RestoreReport{}, c24Failure(c24CodeIOFailure, "target", err)
		}
	}
	if err := os.Rename(temporary, targetRoot); err != nil {
		return c24RestoreReport{}, c24Failure(c24CodeIOFailure, "target_publish", err)
	}
	removeTemporary = false
	if err := c24SyncDir(filepath.Dir(targetRoot)); err != nil {
		return c24RestoreReport{}, c24Failure(c24CodeIOFailure, "target_publish", err)
	}
	return c24RestoreReport{
		ManifestVersion: recovery.ManifestVersion,
		Records:         recovery.Records,
		Files:           len(manifest.Files),
		Provider:        snapshot,
	}, nil
}

func c24StartProvider(t *testing.T, snapshot c24ProviderSnapshot) (*httptest.Server, *c14ProviderState) {
	t.Helper()
	server, state := newC14Provider(t)
	state.mu.Lock()
	state.sealed = make(map[string]string, len(snapshot.Sealed))
	state.versions = make(map[string]int, len(snapshot.Versions))
	for key, value := range snapshot.Sealed {
		state.sealed[key] = value
	}
	for key, value := range snapshot.Versions {
		state.versions[key] = value
	}
	state.sealed503 = true
	state.mu.Unlock()
	return server, state
}

func c24UnsealProvider(state *c14ProviderState, material c24Material, materialPath string) error {
	if state == nil {
		return c24Failure(c24CodeIOFailure, "provider_state", nil)
	}
	if err := material.verify(materialPath); err != nil {
		return err
	}
	state.mu.Lock()
	state.sealed503 = false
	state.mu.Unlock()
	return nil
}

func c24NewAdapter(address string) (*provider.Adapter, error) {
	return provider.NewOpenBaoAdapter(context.Background(), provider.Config{
		Address:      address,
		KEKMount:     "transit",
		PayloadMount: "kv",
		Environment:  "local",
		Timeout:      2 * time.Second,
	}, provider.WorkloadIdentity{
		Role:   "workload-c24",
		Token:  "s.c24-scoped-token",
		Scopes: []string{"transit:encrypt", "transit:decrypt", "kv:read", "kv:write"},
	})
}

func c24Mapper(vault c24Vault) *auth.ScopeMapper {
	return auth.NewScopeMapper(auth.ScopeMapperConfig{
		VaultKEKMap:   map[string]string{vault.VaultID: vault.KEKID},
		VaultMountMap: map[string]string{vault.VaultID: vault.Mount},
		VaultRoleMap:  map[string]string{vault.VaultID: vault.Role},
	})
}

func c24AuthIdentity(identity c24Identity) *auth.Identity {
	return &auth.Identity{
		Subject:       identity.Subject,
		Email:         identity.Email,
		VaultRole:     identity.VaultRole,
		AllowedOwners: identity.AllowedOwners,
		AllowedScopes: identity.AllowedScopes,
		ExpiresAt:     time.Now().Add(time.Hour).Unix(),
	}
}

func c24HashTree(t *testing.T, root string) string {
	t.Helper()
	type entry struct {
		name string
		hash string
	}
	entries := make([]entry, 0)
	err := filepath.WalkDir(root, func(name string, item os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if item.IsDir() {
			return nil
		}
		if !item.Type().IsRegular() {
			return fmt.Errorf("unexpected entry")
		}
		data, err := os.ReadFile(name)
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(root, name)
		if err != nil {
			return err
		}
		entries = append(entries, entry{name: filepath.ToSlash(relative), hash: c24SHA256Hex(data)})
		return nil
	})
	if err != nil {
		t.Fatalf("hash tree %s: %v", root, err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].name < entries[j].name })
	hasher := sha256.New()
	for _, item := range entries {
		hasher.Write([]byte(item.name))
		hasher.Write([]byte{0})
		hasher.Write([]byte(item.hash))
		hasher.Write([]byte{0})
	}
	return hex.EncodeToString(hasher.Sum(nil))
}

func c24ScanBytes(t *testing.T, root string, needles ...[]byte) int {
	t.Helper()
	count := 0
	err := filepath.WalkDir(root, func(name string, item os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if item.IsDir() {
			return nil
		}
		data, err := os.ReadFile(name)
		if err != nil {
			return err
		}
		for _, needle := range needles {
			if len(needle) > 0 && bytes.Contains(data, needle) {
				count++
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("scan %s: %v", root, err)
	}
	return count
}

func c24AssertNoBytes(t *testing.T, label, root string, needles ...[]byte) {
	t.Helper()
	if count := c24ScanBytes(t, root, needles...); count != 0 {
		t.Fatalf("%s contains a forbidden sentinel (%d occurrences)", label, count)
	}
}

func c24CopyBackup(t *testing.T, source, target string) {
	t.Helper()
	if err := filepath.WalkDir(source, func(name string, item os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(source, name)
		if err != nil {
			return err
		}
		destination := filepath.Join(target, relative)
		if item.IsDir() {
			return os.MkdirAll(destination, 0o700)
		}
		data, err := os.ReadFile(name)
		if err != nil {
			return err
		}
		return os.WriteFile(destination, data, 0o600)
	}); err != nil {
		t.Fatalf("copy backup: %v", err)
	}
}

type c24Drill struct {
	Material   c24Material
	Backup     c24Backup
	SourceRoot string
	Secret     []byte
	Grant      []byte
	Payload    []byte
	Base       string
}

func c24PrepareDrill(t *testing.T, positive c24PositiveFixture) c24Drill {
	t.Helper()
	base := t.TempDir()
	sourceRoot := filepath.Join(base, "source-store")
	materialDir := filepath.Join(base, "operator-material")

	store, _, err := storage.Open(sourceRoot)
	if err != nil {
		t.Fatalf("open source store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	server, state := newC14Provider(t)
	adapter, err := c24NewAdapter(server.URL)
	if err != nil {
		t.Fatalf("create source provider adapter: %v", err)
	}
	identity := c24AuthIdentity(positive.Identity)
	service := secrets.NewService(c24Mapper(positive.Vault), adapter, store)
	ctx := context.Background()
	outcome, err := service.WriteSecret(ctx, secrets.WriteRequest{
		VaultID:         positive.Vault.VaultID,
		SecretPath:      positive.Secret.SecretPath,
		ExpectedVersion: positive.Secret.ExpectedVersion,
		Plaintext:       []byte(positive.Secret.PlaintextCanary),
		Classification:  positive.Secret.Classification,
		KEKID:           positive.Vault.KEKID,
		OperationID:     positive.Secret.WriteOperationID,
		Owner:           identity.Email,
		Identity:        identity,
	})
	if err != nil {
		t.Fatalf("write source secret: %v", err)
	}
	if outcome.Version != 1 {
		t.Fatalf("source secret version: %d", outcome.Version)
	}
	secretRecord, err := store.Read(ctx, storage.ReadRequest{Owner: identity.Email, Scope: positive.Vault.VaultID, Name: positive.Secret.SecretPath})
	if err != nil {
		t.Fatalf("read source secret metadata: %v", err)
	}
	secretBytes := append([]byte(nil), secretRecord.Metadata...)

	grantBytes := c24FixtureBytes(t, positive.RevokedGrant.File)
	if _, err := store.Write(ctx, storage.WriteRequest{
		OperationID:     positive.RevokedGrant.OperationID,
		Owner:           identity.Email,
		Scope:           "grants",
		Name:            positive.RevokedGrant.GrantID,
		ExpectedVersion: 0,
		Metadata:        grantBytes,
	}); err != nil {
		t.Fatalf("write revoked grant: %v", err)
	}

	payload, err := adapter.ReadSealedPayload(ctx, provider.SealedRef{
		VaultID: positive.Vault.VaultID,
		Path:    positive.Secret.SecretPath,
		Version: 1,
	})
	if err != nil {
		t.Fatalf("read source provider payload: %v", err)
	}
	payloadBytes := append([]byte(nil), payload...)

	if err := store.Close(); err != nil {
		t.Fatalf("close source store: %v", err)
	}

	material := c24WriteOperatorMaterial(t, materialDir)
	backup := c24BackupStore(t, sourceRoot, filepath.Join(base, "backup"), state)

	canary := []byte(positive.Secret.PlaintextCanary)
	c24AssertNoBytes(t, "source store", sourceRoot, canary)
	c24AssertNoBytes(t, "backup", backup.Dir, canary)
	c24AssertNoBytes(t, "provider snapshot", backup.Dir, canary)
	keyForms := [][]byte{
		material.Bytes,
		[]byte(base64.StdEncoding.EncodeToString(material.Bytes)),
		[]byte(hex.EncodeToString(material.Bytes)),
	}
	c24AssertNoBytes(t, "backup operator material", backup.Dir, keyForms...)
	if _, err := os.Lstat(filepath.Join(backup.Dir, "recovery.key")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("operator material must not be included in the backup")
	}

	return c24Drill{
		Material:   material,
		Backup:     backup,
		SourceRoot: sourceRoot,
		Secret:     secretBytes,
		Grant:      grantBytes,
		Payload:    payloadBytes,
		Base:       base,
	}
}

func TestC24RestoreRequiresOperatorRecoveryMaterialF18(t *testing.T) {
	var positive c24PositiveFixture
	var negative c24NegativeFixture
	var expected c24ExpectedOutput
	c24LoadFixture(t, "positive.json", &positive)
	c24LoadFixture(t, "negative.json", &negative)
	c24LoadFixture(t, "expected-output.json", &expected)

	if expected.Requirement != "F18" || expected.Status != "passed" {
		t.Fatalf("unexpected expected-output metadata: %+v", expected)
	}
	if positive.OperatorMaterial.IncludedInBackup {
		t.Fatal("operator material must never be part of the backup fixture policy")
	}
	if positive.OperatorMaterial.Threshold < 1 || positive.OperatorMaterial.Shares < positive.OperatorMaterial.Threshold {
		t.Fatalf("invalid operator threshold: %+v", positive.OperatorMaterial)
	}
	if negative.UnsealAttemptLimit < 1 {
		t.Fatal("fixture must bound unseal attempts")
	}
	guardCodes := make(map[string]bool, len(expected.GuardCodes))
	for _, code := range expected.GuardCodes {
		guardCodes[code] = true
	}
	for _, code := range []string{c24CodeMaterialRequired, c24CodeMaterialInvalid, c24CodeBackupCorrupt, c24CodeTargetNotEmpty, c24CodeIOFailure, string(provider.CodeProviderSealed), "QUOTA_EXCEEDED", "DUPLICATE", "COMPLETE_PRIOR_OR_NEW", "NO_CANARY"} {
		if !guardCodes[code] {
			t.Fatalf("expected-output guard_codes is missing %s", code)
		}
	}
	if expected.RevokedGrantSHA256 != c24SHA256Hex(c24FixtureBytes(t, positive.RevokedGrant.File)) {
		t.Fatal("revoked grant fixture digest does not match expected-output.json")
	}
	drill := c24PrepareDrill(t, positive)
	base := drill.Base
	targetRoot := filepath.Join(base, "restored-store")

	sourceHash := c24HashTree(t, drill.SourceRoot)

	_, err := c24Restore(t, drill.Backup.Dir, targetRoot, "", drill.Material, c24RestoreOptions{})
	c24AssertCode(t, err, c24CodeMaterialRequired)
	if _, statErr := os.Lstat(targetRoot); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatal("restore without material created a target")
	}

	wrongDirectory := filepath.Join(base, "wrong-material")
	wrongMaterial := c24WriteOperatorMaterial(t, wrongDirectory)
	_, err = c24Restore(t, drill.Backup.Dir, targetRoot, wrongMaterial.Path, drill.Material, c24RestoreOptions{})
	c24AssertCode(t, err, c24CodeMaterialInvalid)
	if _, statErr := os.Lstat(targetRoot); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatal("restore with wrong material created a target")
	}

	report, err := c24Restore(t, drill.Backup.Dir, targetRoot, drill.Material.Path, drill.Material, c24RestoreOptions{})
	if err != nil {
		t.Fatalf("restore with operator material: %v", err)
	}
	if report.ManifestVersion != positive.ExpectedRestore.ManifestVersion || report.Records != positive.ExpectedRestore.Records {
		t.Fatalf("unexpected restore report: %+v", report)
	}
	if report.Files == 0 || len(report.Provider.Sealed) == 0 {
		t.Fatalf("restore omitted files or provider state: %+v", report)
	}

	targetStore, recovery := mustOpen(t, targetRoot)
	if recovery.ManifestVersion != positive.ExpectedRestore.ManifestVersion || recovery.Records != positive.ExpectedRestore.Records {
		t.Fatalf("unexpected restored store report: %+v", recovery)
	}
	ctx := context.Background()
	secretRecord, err := targetStore.Read(ctx, storage.ReadRequest{Owner: positive.Identity.Email, Scope: positive.Vault.VaultID, Name: positive.Secret.SecretPath})
	if err != nil {
		t.Fatalf("read restored secret metadata: %v", err)
	}
	if !bytes.Equal(secretRecord.Metadata, drill.Secret) || secretRecord.EntityVersion != 1 {
		t.Fatal("restored secret metadata differs from the source")
	}
	grantRecord, err := targetStore.Read(ctx, storage.ReadRequest{Owner: positive.Identity.Email, Scope: "grants", Name: positive.RevokedGrant.GrantID})
	if err != nil {
		t.Fatalf("read restored grant: %v", err)
	}
	if !bytes.Equal(grantRecord.Metadata, drill.Grant) {
		t.Fatal("restored grant bytes differ from the source")
	}
	var grant grants.Grant
	if err := json.Unmarshal(grantRecord.Metadata, &grant); err != nil {
		t.Fatalf("parse restored grant: %v", err)
	}
	if grant.RevokedAt == nil || grant.RevokedBy == "" {
		t.Fatal("restored grant lost its revocation state")
	}

	restoredServer, restoredState := c24StartProvider(t, report.Provider)
	if _, err := c24NewAdapter(restoredServer.URL); !provider.IsErrorCode(err, provider.CodeProviderSealed) {
		t.Fatalf("restored provider must start sealed, got %v", err)
	}

	wrongAttempts := 0
	for index := 0; index < negative.UnsealAttemptLimit; index++ {
		if err := c24UnsealProvider(restoredState, drill.Material, wrongMaterial.Path); c24CodeOf(err) != c24CodeMaterialInvalid {
			t.Fatalf("wrong unseal material must be refused, got %v", err)
		}
		wrongAttempts++
		if _, err := c24NewAdapter(restoredServer.URL); !provider.IsErrorCode(err, provider.CodeProviderSealed) {
			t.Fatal("wrong material changed provider seal state")
		}
	}
	if wrongAttempts != negative.UnsealAttemptLimit {
		t.Fatalf("unbounded unseal attempts: %d", wrongAttempts)
	}
	if err := c24UnsealProvider(restoredState, drill.Material, drill.Material.Path); err != nil {
		t.Fatalf("unseal restored provider: %v", err)
	}
	restoredAdapter, err := c24NewAdapter(restoredServer.URL)
	if err != nil {
		t.Fatalf("create restored provider adapter: %v", err)
	}
	payload, err := restoredAdapter.ReadSealedPayload(ctx, provider.SealedRef{
		VaultID: positive.Vault.VaultID,
		Path:    positive.Secret.SecretPath,
		Version: 1,
	})
	if err != nil {
		t.Fatalf("read restored provider payload: %v", err)
	}
	if !bytes.Equal(payload, drill.Payload) {
		t.Fatal("restored provider payload differs from the source")
	}

	canary := []byte(positive.Secret.PlaintextCanary)
	c24AssertNoBytes(t, "restored store", targetRoot, canary)
	c24AssertNoBytes(t, "restored provider payload", base, canary)
	c24AssertNoBytes(t, "restored provider snapshot", drill.Backup.Dir, canary)
	if bytes.Contains(payload, canary) {
		t.Fatal("plaintext canary appeared in provider-owned sealed bytes")
	}
	if c24HashTree(t, drill.SourceRoot) != sourceHash {
		t.Fatal("source instance changed during restore")
	}

	if !expected.RecoveryMaterialRequired || !expected.RestoreTestedOnIsolatedInstance ||
		!expected.ProviderSealedUntilUnseal || !expected.RevokedGrantPreserved ||
		!expected.ProviderOwnsSecretBytes {
		t.Fatalf("unexpected expected-output flags: %+v", expected)
	}
	if expected.ManifestVersion != report.ManifestVersion || expected.Records != report.Records {
		t.Fatalf("expected-output report mismatch: %+v vs %+v", expected, report)
	}
	if expected.PlaintextCanaryOccurrences != 0 {
		t.Fatalf("unexpected plaintext occurrence expectation: %d", expected.PlaintextCanaryOccurrences)
	}
}

func c24TamperJSONFile(t *testing.T, name string, mutate func(map[string]any)) {
	t.Helper()
	data, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("read tamper target: %v", err)
	}
	value := map[string]any{}
	if err := json.Unmarshal(data, &value); err != nil {
		t.Fatalf("parse tamper target: %v", err)
	}
	mutate(value)
	updated, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal tamper target: %v", err)
	}
	if err := os.WriteFile(name, updated, 0o600); err != nil {
		t.Fatalf("write tamper target: %v", err)
	}
}

func TestC24RestoreNegativeCasesF18(t *testing.T) {
	var positive c24PositiveFixture
	var negative c24NegativeFixture
	c24LoadFixture(t, "positive.json", &positive)
	c24LoadFixture(t, "negative.json", &negative)
	drill := c24PrepareDrill(t, positive)

	cases := map[string]c24NegativeCase{}
	for _, testCase := range negative.Cases {
		cases[testCase.Kind] = testCase
	}

	t.Run("missing-operator-material", func(t *testing.T) {
		testCase := c24RequireCase(t, cases, "restore_material_missing")
		target := filepath.Join(t.TempDir(), "target")
		_, err := c24Restore(t, drill.Backup.Dir, target, "", drill.Material, c24RestoreOptions{})
		c24AssertCode(t, err, testCase.ExpectedCode)
		if _, statErr := os.Lstat(target); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatal("material rejection created a target")
		}
	})

	t.Run("wrong-operator-material", func(t *testing.T) {
		testCase := c24RequireCase(t, cases, "restore_material_invalid")
		wrong := c24WriteOperatorMaterial(t, t.TempDir())
		target := filepath.Join(t.TempDir(), "target")
		_, err := c24Restore(t, drill.Backup.Dir, target, wrong.Path, drill.Material, c24RestoreOptions{})
		c24AssertCode(t, err, testCase.ExpectedCode)
		if _, statErr := os.Lstat(target); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatal("wrong material created a target")
		}
	})

	t.Run("corrupt-backup-manifest", func(t *testing.T) {
		testCase := c24RequireCase(t, cases, "backup_corrupt_manifest")
		backupDir := filepath.Join(t.TempDir(), "backup")
		c24CopyBackup(t, drill.Backup.Dir, backupDir)
		c24TamperJSONFile(t, filepath.Join(backupDir, "backup-manifest.json"), func(value map[string]any) {
			files, _ := value["files"].([]any)
			if len(files) == 0 {
				t.Fatal("backup manifest has no files")
			}
			first, _ := files[0].(map[string]any)
			first["sha256"] = strings.Repeat("0", 64)
		})
		target := filepath.Join(t.TempDir(), "target")
		_, err := c24Restore(t, backupDir, target, drill.Material.Path, drill.Material, c24RestoreOptions{})
		c24AssertCode(t, err, testCase.ExpectedCode)
		if _, statErr := os.Lstat(target); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatal("corrupt manifest created a target")
		}
	})

	t.Run("corrupt-backup-blob", func(t *testing.T) {
		testCase := c24RequireCase(t, cases, "backup_corrupt_blob")
		backupDir := filepath.Join(t.TempDir(), "backup")
		c24CopyBackup(t, drill.Backup.Dir, backupDir)
		entries, err := os.ReadDir(filepath.Join(backupDir, "blobs"))
		if err != nil || len(entries) == 0 {
			t.Fatalf("read backup blobs: %v", err)
		}
		name := filepath.Join(backupDir, "blobs", entries[0].Name())
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read backup blob: %v", err)
		}
		data[0] ^= 0xff
		if err := os.WriteFile(name, data, 0o600); err != nil {
			t.Fatalf("tamper backup blob: %v", err)
		}
		target := filepath.Join(t.TempDir(), "target")
		_, err = c24Restore(t, backupDir, target, drill.Material.Path, drill.Material, c24RestoreOptions{})
		c24AssertCode(t, err, testCase.ExpectedCode)
		if _, statErr := os.Lstat(target); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatal("corrupt blob created a target")
		}
	})

	t.Run("missing-backup-blob", func(t *testing.T) {
		testCase := c24RequireCase(t, cases, "backup_missing_blob")
		backupDir := filepath.Join(t.TempDir(), "backup")
		c24CopyBackup(t, drill.Backup.Dir, backupDir)
		entries, err := os.ReadDir(filepath.Join(backupDir, "blobs"))
		if err != nil || len(entries) == 0 {
			t.Fatalf("read backup blobs: %v", err)
		}
		if err := os.Remove(filepath.Join(backupDir, "blobs", entries[0].Name())); err != nil {
			t.Fatalf("remove backup blob: %v", err)
		}
		target := filepath.Join(t.TempDir(), "target")
		_, err = c24Restore(t, backupDir, target, drill.Material.Path, drill.Material, c24RestoreOptions{})
		c24AssertCode(t, err, testCase.ExpectedCode)
		if _, statErr := os.Lstat(target); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatal("incomplete backup created a target")
		}
	})

	t.Run("corrupt-provider-snapshot", func(t *testing.T) {
		testCase := c24RequireCase(t, cases, "backup_corrupt_provider")
		backupDir := filepath.Join(t.TempDir(), "backup")
		c24CopyBackup(t, drill.Backup.Dir, backupDir)
		name := filepath.Join(backupDir, "provider-snapshot.json")
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read provider snapshot: %v", err)
		}
		data[0] ^= 0xff
		if err := os.WriteFile(name, data, 0o600); err != nil {
			t.Fatalf("tamper provider snapshot: %v", err)
		}
		target := filepath.Join(t.TempDir(), "target")
		_, err = c24Restore(t, backupDir, target, drill.Material.Path, drill.Material, c24RestoreOptions{})
		c24AssertCode(t, err, testCase.ExpectedCode)
		if _, statErr := os.Lstat(target); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatal("corrupt provider snapshot created a target")
		}
	})

	t.Run("restore-over-newer-target", func(t *testing.T) {
		testCase := c24RequireCase(t, cases, "target_not_empty")
		parent := t.TempDir()
		target := filepath.Join(parent, "target")
		newer, _, err := storage.Open(target)
		if err != nil {
			t.Fatalf("open newer target: %v", err)
		}
		if _, err := newer.Write(context.Background(), storage.WriteRequest{
			OperationID: "op-c24-newer-target-001",
			Owner:       positive.Identity.Email,
			Scope:       positive.Vault.VaultID,
			Name:        "app/prod/newer-target",
			Metadata:    []byte(`{"synthetic":"c24-newer-target"}`),
		}); err != nil {
			t.Fatalf("write newer target: %v", err)
		}
		if err := newer.Close(); err != nil {
			t.Fatalf("close newer target: %v", err)
		}
		before := c24HashTree(t, target)
		_, err = c24Restore(t, drill.Backup.Dir, target, drill.Material.Path, drill.Material, c24RestoreOptions{})
		c24AssertCode(t, err, testCase.ExpectedCode)
		if c24HashTree(t, target) != before {
			t.Fatal("refused restore changed newer target state")
		}
	})

	t.Run("interrupted-restore-no-partial-target", func(t *testing.T) {
		testCase := c24RequireCase(t, cases, "restore_interrupted")
		parent := t.TempDir()
		target := filepath.Join(parent, "target")
		_, err := c24Restore(t, drill.Backup.Dir, target, drill.Material.Path, drill.Material, c24RestoreOptions{FailAfterFiles: 1})
		c24AssertCode(t, err, testCase.ExpectedCode)
		if _, statErr := os.Lstat(target); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatal("interrupted restore published a target")
		}
		entries, err := os.ReadDir(parent)
		if err != nil {
			t.Fatalf("read restore parent: %v", err)
		}
		for _, entry := range entries {
			if strings.Contains(entry.Name(), ".restore-tmp-") {
				t.Fatalf("interrupted restore left staging behind: %s", entry.Name())
			}
		}
	})

	known := map[string]bool{
		"restore_material_missing": true,
		"restore_material_invalid": true,
		"backup_corrupt_manifest":  true,
		"backup_corrupt_blob":      true,
		"backup_missing_blob":      true,
		"backup_corrupt_provider":  true,
		"target_not_empty":         true,
		"restore_interrupted":      true,
		"lost_ack_replay":          true,
		"quota_exhausted":          true,
		"crash_boundaries":         true,
		"provider_owns_bytes":      true,
	}
	for _, testCase := range negative.Cases {
		if !known[testCase.Kind] {
			t.Fatalf("unmapped C24 negative case %q", testCase.Kind)
		}
	}
}

func c24SeedCrashStore(t *testing.T, root string) []byte {
	t.Helper()
	metadata := []byte(`{"synthetic":"c24-crash-seed"}`)
	store, _, err := storage.Open(root)
	if err != nil {
		t.Fatalf("open crash source: %v", err)
	}
	if _, err := store.Write(context.Background(), storage.WriteRequest{
		OperationID: "op-c24-crash-seed-001",
		Owner:       "alice@keyhelix.local",
		Scope:       "vault-prod",
		Name:        "app/prod/crash-record",
		Metadata:    metadata,
	}); err != nil {
		t.Fatalf("seed crash source: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close crash source: %v", err)
	}
	return metadata
}

func c24CrashMetadata() []byte {
	prefix := []byte(`{"synthetic":"c24-crash-target","payload":"`)
	suffix := []byte(`"}`)
	body := bytes.Repeat([]byte("c"), 60*1024)
	result := make([]byte, 0, len(prefix)+len(body)+len(suffix))
	result = append(result, prefix...)
	result = append(result, body...)
	result = append(result, suffix...)
	if len(result) > storage.MaxMetadataBytes {
		panic("crash metadata exceeds the storage bound")
	}
	return result
}

func c24WaitForFile(t *testing.T, name string, command *exec.Cmd, output *bytes.Buffer) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(name); err == nil {
			return
		}
		if time.Now().After(deadline) {
			if command.Process != nil {
				_ = command.Process.Kill()
				_ = command.Wait()
			}
			t.Fatalf("crash child did not become ready: %s", output.String())
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func c24RunCrashChild(t *testing.T, root string, delay time.Duration) {
	t.Helper()
	ready := filepath.Join(t.TempDir(), "ready")
	command := exec.Command(os.Args[0], "-test.run=^TestC24CrashWriterChild$", "-test.v")
	command.Env = append(os.Environ(),
		c24CrashChildEnv+"=1",
		c24CrashRootEnv+"="+root,
		c24CrashReadyEnv+"="+ready,
		c24CrashOpEnv+"="+c24CrashOperationID,
	)
	output := &bytes.Buffer{}
	command.Stdout = output
	command.Stderr = output
	if err := command.Start(); err != nil {
		t.Fatalf("start crash child: %v", err)
	}
	c24WaitForFile(t, ready, command, output)
	time.Sleep(delay)
	if command.Process != nil {
		_ = command.Process.Kill()
	}
	_ = command.Wait()
}

func TestC24CrashReplayAndQuotaBoundsF18(t *testing.T) {
	var positive c24PositiveFixture
	var negative c24NegativeFixture
	c24LoadFixture(t, "positive.json", &positive)
	c24LoadFixture(t, "negative.json", &negative)
	cases := map[string]c24NegativeCase{}
	for _, testCase := range negative.Cases {
		cases[testCase.Kind] = testCase
	}

	t.Run("crash-writer-boundary", func(t *testing.T) {
		testCase := c24RequireCase(t, cases, "crash_boundaries")
		for index, delay := range []time.Duration{0, time.Millisecond, 3 * time.Millisecond, 8 * time.Millisecond} {
			root := filepath.Join(t.TempDir(), fmt.Sprintf("crash-%d", index))
			seed := c24SeedCrashStore(t, root)
			c24RunCrashChild(t, root, delay)
			store, report, err := storage.Open(root)
			if err != nil {
				t.Fatalf("reopen after kill %d: %v", index, err)
			}
			if report.ManifestVersion != 1 && report.ManifestVersion != 2 {
				_ = store.Close()
				t.Fatalf("kill %d exposed unexpected manifest version %d", index, report.ManifestVersion)
			}
			if report.Records != 1 {
				_ = store.Close()
				t.Fatalf("kill %d exposed %d records", index, report.Records)
			}
			record, err := store.Read(context.Background(), storage.ReadRequest{
				Owner: "alice@keyhelix.local",
				Scope: "vault-prod",
				Name:  "app/prod/crash-record",
			})
			if err != nil {
				_ = store.Close()
				t.Fatalf("read after kill %d: %v", index, err)
			}
			crashMetadata := c24CrashMetadata()
			if report.ManifestVersion == 1 {
				if !bytes.Equal(record.Metadata, seed) {
					_ = store.Close()
					t.Fatalf("kill %d exposed a partial prior state", index)
				}
				result, err := store.Write(context.Background(), storage.WriteRequest{
					OperationID:     c24CrashOperationID,
					Owner:           "alice@keyhelix.local",
					Scope:           "vault-prod",
					Name:            "app/prod/crash-record",
					ExpectedVersion: 1,
					Metadata:        crashMetadata,
				})
				if err != nil {
					_ = store.Close()
					t.Fatalf("replay after prior state %d: %v", index, err)
				}
				if result.Duplicate || result.ManifestVersion != 2 || result.EntityVersion != 2 {
					_ = store.Close()
					t.Fatalf("unexpected replay result after prior state %d: %+v", index, result)
				}
			} else {
				if !bytes.Equal(record.Metadata, crashMetadata) {
					_ = store.Close()
					t.Fatalf("kill %d exposed a partial new state", index)
				}
				result, err := store.Write(context.Background(), storage.WriteRequest{
					OperationID:     c24CrashOperationID,
					Owner:           "alice@keyhelix.local",
					Scope:           "vault-prod",
					Name:            "app/prod/crash-record",
					ExpectedVersion: 1,
					Metadata:        crashMetadata,
				})
				if err != nil {
					_ = store.Close()
					t.Fatalf("replay after new state %d: %v", index, err)
				}
				if !result.Duplicate || result.ManifestVersion != 2 || result.EntityVersion != 2 {
					_ = store.Close()
					t.Fatalf("unexpected replay result after new state %d: %+v", index, result)
				}
			}
			if err := store.Close(); err != nil {
				t.Fatalf("close recovered crash store %d: %v", index, err)
			}
			t.Logf("crash kill %d with %v delay: %s", index, delay, testCase.ExpectedCode)
		}
	})

	t.Run("staged-byte-boundary", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "staged")
		c24SeedCrashStore(t, root)
		if err := os.WriteFile(filepath.Join(root, "staging", "blob-killed.tmp"), []byte("uncommitted"), 0o600); err != nil {
			t.Fatalf("write staged bytes: %v", err)
		}
		store, report, err := storage.Open(root)
		if err != nil {
			t.Fatalf("open staged boundary: %v", err)
		}
		defer store.Close()
		if report.ManifestVersion != 1 || report.RemovedStaging != 1 {
			t.Fatalf("staged boundary exposed %+v", report)
		}
	})

	t.Run("orphan-blob-boundary", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "orphan")
		c24SeedCrashStore(t, root)
		twin := filepath.Join(t.TempDir(), "twin")
		c24CopyStoreDirectories(t, root, twin)
		twinStore, _, err := storage.Open(twin)
		if err != nil {
			t.Fatalf("open twin: %v", err)
		}
		crashMetadata := c24CrashMetadata()
		if _, err := twinStore.Write(context.Background(), storage.WriteRequest{
			OperationID:     c24CrashOperationID,
			Owner:           "alice@keyhelix.local",
			Scope:           "vault-prod",
			Name:            "app/prod/crash-record",
			ExpectedVersion: 1,
			Metadata:        crashMetadata,
		}); err != nil {
			t.Fatalf("write twin: %v", err)
		}
		if err := twinStore.Close(); err != nil {
			t.Fatalf("close twin: %v", err)
		}
		digest := c24SHA256Hex(crashMetadata)
		c24CopyFile(t, filepath.Join(twin, "blobs", digest), filepath.Join(root, "blobs", digest), storage.MaxMetadataBytes)
		store, report, err := storage.Open(root)
		if err != nil {
			t.Fatalf("open orphan boundary: %v", err)
		}
		defer store.Close()
		if report.ManifestVersion != 1 || report.RemovedOrphanBlobs != 1 {
			t.Fatalf("orphan boundary exposed %+v", report)
		}
	})

	t.Run("lost-ack-complete-manifest", func(t *testing.T) {
		testCase := c24RequireCase(t, cases, "lost_ack_replay")
		root := filepath.Join(t.TempDir(), "ack")
		c24SeedCrashStore(t, root)
		twin := filepath.Join(t.TempDir(), "twin")
		c24CopyStoreDirectories(t, root, twin)
		twinStore, _, err := storage.Open(twin)
		if err != nil {
			t.Fatalf("open twin: %v", err)
		}
		crashMetadata := c24CrashMetadata()
		if _, err := twinStore.Write(context.Background(), storage.WriteRequest{
			OperationID:     c24CrashOperationID,
			Owner:           "alice@keyhelix.local",
			Scope:           "vault-prod",
			Name:            "app/prod/crash-record",
			ExpectedVersion: 1,
			Metadata:        crashMetadata,
		}); err != nil {
			t.Fatalf("write twin: %v", err)
		}
		if err := twinStore.Close(); err != nil {
			t.Fatalf("close twin: %v", err)
		}
		digest := c24SHA256Hex(crashMetadata)
		c24CopyFile(t, filepath.Join(twin, "blobs", digest), filepath.Join(root, "blobs", digest), storage.MaxMetadataBytes)
		manifestName := "manifest-" + fmt.Sprintf("%020d", 2) + ".json"
		c24CopyFile(t, filepath.Join(twin, "manifests", manifestName), filepath.Join(root, "manifests", manifestName), storage.MaxManifestBytes)

		store, report, err := storage.Open(root)
		if err != nil {
			t.Fatalf("open lost-ack boundary: %v", err)
		}
		defer store.Close()
		if report.ManifestVersion != 2 || report.Records != 1 {
			t.Fatalf("lost-ack boundary exposed %+v", report)
		}
		record, err := store.Read(context.Background(), storage.ReadRequest{Owner: "alice@keyhelix.local", Scope: "vault-prod", Name: "app/prod/crash-record"})
		if err != nil || !bytes.Equal(record.Metadata, crashMetadata) {
			t.Fatalf("lost-ack record mismatch: %+v (%v)", record, err)
		}
		result, err := store.Write(context.Background(), storage.WriteRequest{
			OperationID:     c24CrashOperationID,
			Owner:           "alice@keyhelix.local",
			Scope:           "vault-prod",
			Name:            "app/prod/crash-record",
			ExpectedVersion: 1,
			Metadata:        crashMetadata,
		})
		if err != nil {
			t.Fatalf("replay lost-ack operation: %v", err)
		}
		if !result.Duplicate || result.ManifestVersion != 2 || result.EntityVersion != 2 {
			t.Fatalf("lost-ack replay was not idempotent: %+v", result)
		}
		if testCase.ExpectedCode != "DUPLICATE" {
			t.Fatalf("unexpected fixture expectation: %s", testCase.ExpectedCode)
		}
		if names, err := os.ReadDir(filepath.Join(root, "manifests")); err != nil || len(names) != 2 {
			t.Fatalf("lost-ack replay published another manifest: %v (%v)", names, err)
		}
	})

	t.Run("quota-bounded", func(t *testing.T) {
		testCase := c24RequireCase(t, cases, "quota_exhausted")
		store, _ := mustOpen(t, filepath.Join(t.TempDir(), "quota"))
		oversized := bytes.Repeat([]byte("q"), storage.MaxMetadataBytes+1)
		request := storage.WriteRequest{
			OperationID:     "op-c24-quota-oversized",
			Owner:           "alice@keyhelix.local",
			Scope:           "vault-prod",
			Name:            "app/prod/quota-oversized",
			ExpectedVersion: 0,
			Metadata:        oversized,
		}
		for attempt := 0; attempt < 3; attempt++ {
			_, err := store.Write(context.Background(), request)
			c24AssertCode(t, err, testCase.ExpectedCode)
		}

		small := []byte(`{"synthetic":"c24-quota"}`)
		for index := 0; index < storage.MaxRecords; index++ {
			if _, err := store.Write(context.Background(), storage.WriteRequest{
				OperationID:     fmt.Sprintf("op-c24-quota-%03d", index),
				Owner:           "alice@keyhelix.local",
				Scope:           "vault-prod",
				Name:            fmt.Sprintf("app/prod/quota-%03d", index),
				ExpectedVersion: 0,
				Metadata:        small,
			}); err != nil {
				t.Fatalf("seed record quota %d: %v", index, err)
			}
		}
		overflow := storage.WriteRequest{
			OperationID:     "op-c24-quota-overflow",
			Owner:           "alice@keyhelix.local",
			Scope:           "vault-prod",
			Name:            "app/prod/quota-overflow",
			ExpectedVersion: 0,
			Metadata:        small,
		}
		for attempt := 0; attempt < 3; attempt++ {
			_, err := store.Write(context.Background(), overflow)
			c24AssertCode(t, err, testCase.ExpectedCode)
		}
	})
}

func TestC24CrashWriterChild(t *testing.T) {
	if os.Getenv(c24CrashChildEnv) != "1" {
		t.Skip("crash-drill helper process")
	}
	root := os.Getenv(c24CrashRootEnv)
	ready := os.Getenv(c24CrashReadyEnv)
	operationID := os.Getenv(c24CrashOpEnv)
	if root == "" || ready == "" || operationID == "" {
		t.Fatal("crash child environment is incomplete")
	}
	store, _, err := storage.Open(root)
	if err != nil {
		t.Fatalf("open crash child store: %v", err)
	}
	defer store.Close()
	if err := os.WriteFile(ready, []byte("ready"), 0o600); err != nil {
		t.Fatalf("write crash readiness: %v", err)
	}
	if _, err := store.Write(context.Background(), storage.WriteRequest{
		OperationID:     operationID,
		Owner:           "alice@keyhelix.local",
		Scope:           "vault-prod",
		Name:            "app/prod/crash-record",
		ExpectedVersion: 1,
		Metadata:        c24CrashMetadata(),
	}); err != nil {
		t.Fatalf("crash child write: %v", err)
	}
}
