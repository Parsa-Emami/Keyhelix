// Package storage implements the bounded, single-writer local metadata port
// described by ADR-0003.
//
// The adapter stores immutable, caller-supplied metadata documents and a
// versioned manifest. It never accepts, derives, encrypts or decrypts secret
// values; provider-owned secret bytes remain outside this package.
package storage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	// SchemaVersion is the on-disk manifest schema this adapter writes.
	SchemaVersion = 1
	// MaxMetadataBytes bounds one caller-supplied metadata document.
	MaxMetadataBytes = 64 * 1024
	// MaxRecords bounds the number of logical metadata records.
	MaxRecords = 256
	// MaxOperations bounds the retained idempotency window.
	MaxOperations = 256
	// MaxManifestBytes bounds one serialized manifest.
	MaxManifestBytes = 1 << 20
	// MaxManifestVersions bounds retained manifest history.
	MaxManifestVersions = 4
	// MaxNameLength bounds a logical metadata name.
	MaxNameLength = 1024
	// MaxScopeLength bounds an owner or scope identifier.
	MaxScopeLength = 128
	// MaxSequence bounds entity, operation and manifest versions.
	MaxSequence int64 = 9007199254740991

	lockName      = "LOCK"
	blobsName     = "blobs"
	stagingName   = "staging"
	manifestsName = "manifests"

	manifestPrefix = "manifest-"
	manifestSuffix = ".json"
)

// ErrorCode identifies a typed storage failure.
type ErrorCode string

const (
	CodeInvalidInput      ErrorCode = "INVALID_INPUT"
	CodeLocked            ErrorCode = "LOCKED"
	CodeDiskFull          ErrorCode = "DISK_FULL"
	CodeIOFailure         ErrorCode = "IO_FAILURE"
	CodeCorruptState      ErrorCode = "CORRUPT_STATE"
	CodeOperationConflict ErrorCode = "OPERATION_CONFLICT"
	CodeAlreadyExists     ErrorCode = "ALREADY_EXISTS"
	CodeStaleVersion      ErrorCode = "STALE_VERSION"
	CodeQuotaExceeded     ErrorCode = "QUOTA_EXCEEDED"
	CodeNotFound          ErrorCode = "NOT_FOUND"
	CodeCancelled         ErrorCode = "CANCELLED"
	CodeTimeout           ErrorCode = "TIMEOUT"
	CodeClosed            ErrorCode = "CLOSED"
)

// Error is a typed storage failure. Paths and stored bytes are deliberately
// excluded from its message.
type Error struct {
	Code  ErrorCode `json:"code"`
	Field string    `json:"field,omitempty"`
	Stage string    `json:"stage,omitempty"`
	Err   error     `json:"-"`
}

func (e *Error) Error() string {
	if e.Field != "" {
		return string(e.Code) + ":" + e.Field
	}
	if e.Stage != "" {
		return string(e.Code) + ":" + e.Stage
	}
	return string(e.Code)
}

// Unwrap exposes the underlying device error without adding it to messages.
func (e *Error) Unwrap() error { return e.Err }

// WriteRequest is one idempotent metadata write.
type WriteRequest struct {
	OperationID     string
	Owner           string
	Scope           string
	Name            string
	ExpectedVersion int64
	Metadata        []byte
}

// WriteResult is the typed outcome of an accepted or replayed write.
type WriteResult struct {
	OperationID     string `json:"operation_id"`
	EntityVersion   int64  `json:"entity_version"`
	ManifestVersion int64  `json:"manifest_version"`
	MetadataDigest  string `json:"metadata_digest"`
	Duplicate       bool   `json:"duplicate"`
}

// ReadRequest selects one metadata record by owner, scope and name.
type ReadRequest struct {
	Owner string
	Scope string
	Name  string
}

// ListRequest selects committed metadata records by scope and optional owner.
// An empty Owner lists every owner in the scope; Scope is always required.
type ListRequest struct {
	Owner string
	Scope string
}

// Lister is the optional enumeration capability used by the engine to rebuild
// owner-scoped indexes (vault summaries and grants) after restart.
type Lister interface {
	List(ctx context.Context, request ListRequest) ([]Record, error)
}

// Record is a committed metadata record with hash-checked bytes.
type Record struct {
	Owner           string    `json:"owner"`
	Scope           string    `json:"scope"`
	Name            string    `json:"name"`
	EntityVersion   int64     `json:"entity_version"`
	ManifestVersion int64     `json:"manifest_version"`
	MetadataDigest  string    `json:"metadata_digest"`
	Metadata        []byte    `json:"-"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// RecoveryReport records what the last Open reconciled.
type RecoveryReport struct {
	ManifestVersion     int64 `json:"manifest_version"`
	Records             int   `json:"records"`
	RemovedStaging      int   `json:"removed_staging"`
	RemovedOrphanBlobs  int   `json:"removed_orphan_blobs"`
	RemovedOldManifests int   `json:"removed_old_manifests"`
}

// Port is the storage boundary consumed by domain services.
type Port interface {
	Write(ctx context.Context, request WriteRequest) (WriteResult, error)
	Read(ctx context.Context, request ReadRequest) (Record, error)
	Close() error
}

type manifest struct {
	SchemaVersion   int                 `json:"schema_version"`
	ManifestVersion int64               `json:"manifest_version"`
	PublishedAt     time.Time           `json:"published_at"`
	Records         []manifestRecord    `json:"records"`
	Operations      []manifestOperation `json:"operations"`
}

type manifestRecord struct {
	Owner          string    `json:"owner"`
	Scope          string    `json:"scope"`
	Name           string    `json:"name"`
	EntityVersion  int64     `json:"entity_version"`
	MetadataDigest string    `json:"metadata_digest"`
	MetadataBytes  int       `json:"metadata_bytes"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

type manifestOperation struct {
	OperationID     string    `json:"operation_id"`
	Owner           string    `json:"owner"`
	Scope           string    `json:"scope"`
	Name            string    `json:"name"`
	ExpectedVersion int64     `json:"expected_version"`
	EntityVersion   int64     `json:"entity_version"`
	ManifestVersion int64     `json:"manifest_version"`
	MetadataDigest  string    `json:"metadata_digest"`
	MetadataBytes   int       `json:"metadata_bytes"`
	RecordedAt      time.Time `json:"recorded_at"`
}

// Store is a single-host metadata store. Writes are serialized in-process and
// the exclusive LOCK file prevents a second process from owning the directory.
type Store struct {
	root   string
	lock   *os.File
	mu     sync.RWMutex
	closed bool

	records         map[string]manifestRecord
	operations      map[string]manifestOperation
	operationOrder  []string
	manifestVersion int64
	faults          func(stage) error
}

// stage identifies a durable write step for deterministic failure testing.
type stage string

const (
	stageMetadataWrite   stage = "metadata_write"
	stageMetadataSync    stage = "metadata_sync"
	stageMetadataRename  stage = "metadata_rename"
	stageMetadataDirSync stage = "metadata_dir_sync"
	stageManifestWrite   stage = "manifest_write"
	stageManifestSync    stage = "manifest_sync"
	stageManifestRename  stage = "manifest_rename"
	stageManifestDirSync stage = "manifest_dir_sync"
)

var (
	ownerPattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@-]{0,127}$`)
	scopePattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	namePattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]*$`)
	opPattern     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$`)
	digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

var (
	_ Port   = (*Store)(nil)
	_ Lister = (*Store)(nil)
)

// Open creates or recovers the store at root, acquires the exclusive writer
// lock and reconciles uncommitted staging bytes and orphan blobs.
func Open(root string) (*Store, RecoveryReport, error) {
	report := RecoveryReport{}
	if strings.TrimSpace(root) == "" {
		return nil, report, invalid("root")
	}
	root = filepath.Clean(root)
	for _, directory := range []string{root, filepath.Join(root, blobsName), filepath.Join(root, stagingName), filepath.Join(root, manifestsName)} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			return nil, report, ioFailure("mkdir", err)
		}
	}
	if err := syncDir(root); err != nil {
		return nil, report, ioFailure("root_sync", err)
	}
	lock, err := acquireLock(filepath.Join(root, lockName))
	if err != nil {
		return nil, report, err
	}
	store, report, err := loadLocked(root)
	if err != nil {
		releaseLock(lock)
		return nil, report, err
	}
	store.lock = lock
	return store, report, nil
}

func acquireLock(name string) (*os.File, error) {
	file, err := os.OpenFile(name, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, ioFailure("lock_open", err)
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		file.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, &Error{Code: CodeLocked, Stage: "lock"}
		}
		return nil, ioFailure("lock_acquire", err)
	}
	payload := []byte(fmt.Sprintf("pid=%d\nopened_at=%s\n", os.Getpid(), time.Now().UTC().Format(time.RFC3339Nano)))
	if file.Truncate(0) == nil {
		_, _ = file.WriteAt(payload, 0)
		_ = file.Sync()
	}
	return file, nil
}

func releaseLock(file *os.File) {
	if file == nil {
		return
	}
	_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	_ = file.Close()
}

func loadLocked(root string) (*Store, RecoveryReport, error) {
	report := RecoveryReport{}
	store := &Store{
		root:       root,
		records:    make(map[string]manifestRecord),
		operations: make(map[string]manifestOperation),
	}
	removedStaging, err := cleanupStagingLocked(root)
	if err != nil {
		return nil, report, err
	}
	report.RemovedStaging = removedStaging

	versions, err := listManifestVersionsLocked(root)
	if err != nil {
		return nil, report, err
	}
	if len(versions) == 0 {
		removedBlobs, err := cleanupOrphanBlobsLocked(root, map[string]bool{})
		if err != nil {
			return nil, report, err
		}
		report.RemovedOrphanBlobs = removedBlobs
		return store, report, nil
	}

	latest := versions[len(versions)-1]
	data, err := readRegularFile(manifestPath(root, latest), MaxManifestBytes)
	if err != nil {
		return nil, report, err
	}
	value, err := decodeManifest(data, latest)
	if err != nil {
		return nil, report, err
	}
	if err := verifyManifestBlobs(root, value); err != nil {
		return nil, report, err
	}
	store.apply(value)
	report.ManifestVersion = value.ManifestVersion
	report.Records = len(store.records)

	removedManifests, err := pruneManifestsLocked(root, value.ManifestVersion)
	if err != nil {
		return nil, report, err
	}
	report.RemovedOldManifests = removedManifests
	removedBlobs, err := cleanupOrphanBlobsLocked(root, store.referencedDigests())
	if err != nil {
		return nil, report, err
	}
	report.RemovedOrphanBlobs = removedBlobs
	return store, report, nil
}

func cleanupStagingLocked(root string) (int, error) {
	directory := filepath.Join(root, stagingName)
	entries, err := os.ReadDir(directory)
	if err != nil {
		return 0, ioFailure("staging_read", err)
	}
	removed := 0
	for _, entry := range entries {
		if !entry.Type().IsRegular() {
			return removed, corrupt("staging")
		}
		if err := os.Remove(filepath.Join(directory, entry.Name())); err != nil {
			return removed, ioFailure("staging_remove", err)
		}
		removed++
	}
	if removed > 0 {
		if err := syncDir(directory); err != nil {
			return removed, ioFailure("staging_sync", err)
		}
	}
	return removed, nil
}

func listManifestVersionsLocked(root string) ([]int64, error) {
	directory := filepath.Join(root, manifestsName)
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, ioFailure("manifests_read", err)
	}
	versions := make([]int64, 0, len(entries))
	for _, entry := range entries {
		if !entry.Type().IsRegular() {
			return nil, corrupt("manifests")
		}
		version, ok := parseManifestName(entry.Name())
		if !ok {
			return nil, corrupt("manifests")
		}
		versions = append(versions, version)
	}
	sort.Slice(versions, func(i, j int) bool { return versions[i] < versions[j] })
	return versions, nil
}

func pruneManifestsLocked(root string, current int64) (int, error) {
	versions, err := listManifestVersionsLocked(root)
	if err != nil {
		return 0, err
	}
	keepFrom := current - MaxManifestVersions + 1
	if keepFrom < 1 {
		keepFrom = 1
	}
	removed := 0
	for _, version := range versions {
		if version >= keepFrom {
			continue
		}
		if err := os.Remove(manifestPath(root, version)); err != nil {
			return removed, ioFailure("manifest_remove", err)
		}
		removed++
	}
	if removed > 0 {
		if err := syncDir(filepath.Join(root, manifestsName)); err != nil {
			return removed, ioFailure("manifests_sync", err)
		}
	}
	return removed, nil
}

func cleanupOrphanBlobsLocked(root string, referenced map[string]bool) (int, error) {
	directory := filepath.Join(root, blobsName)
	entries, err := os.ReadDir(directory)
	if err != nil {
		return 0, ioFailure("blobs_read", err)
	}
	removed := 0
	for _, entry := range entries {
		if !entry.Type().IsRegular() || !digestPattern.MatchString(entry.Name()) {
			return removed, corrupt("blobs")
		}
		if referenced[entry.Name()] {
			continue
		}
		if err := os.Remove(filepath.Join(directory, entry.Name())); err != nil {
			return removed, ioFailure("blob_remove", err)
		}
		removed++
	}
	if removed > 0 {
		if err := syncDir(directory); err != nil {
			return removed, ioFailure("blobs_sync", err)
		}
	}
	return removed, nil
}

func readRegularFile(name string, maximum int64) ([]byte, error) {
	info, err := os.Lstat(name)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, corrupt("manifest")
		}
		return nil, ioFailure("read", err)
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maximum {
		return nil, corrupt("manifest")
	}
	data, err := os.ReadFile(name)
	if err != nil {
		return nil, ioFailure("read", err)
	}
	return data, nil
}

func decodeManifest(data []byte, expected int64) (manifest, error) {
	value := manifest{}
	if len(data) == 0 || len(data) > MaxManifestBytes {
		return value, corrupt("manifest")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return value, corrupt("manifest")
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return value, corrupt("manifest")
	}
	if value.SchemaVersion != SchemaVersion || value.ManifestVersion != expected || value.PublishedAt.IsZero() {
		return value, corrupt("manifest")
	}
	if len(value.Operations) > MaxOperations {
		return value, corrupt("manifest")
	}
	seen := make(map[string]bool, len(value.Records))
	scopeCounts := make(map[string]int)
	for index, record := range value.Records {
		if err := validateRecordMeta(record); err != nil {
			return manifest{}, corrupt("manifest")
		}
		scopeCounts[record.Scope]++
		if scopeCounts[record.Scope] > MaxRecords {
			return manifest{}, corrupt("manifest")
		}
		key := recordKey(record.Owner, record.Scope, record.Name)
		if seen[key] {
			return manifest{}, corrupt("manifest")
		}
		if index > 0 && recordKey(value.Records[index-1].Owner, value.Records[index-1].Scope, value.Records[index-1].Name) >= key {
			return manifest{}, corrupt("manifest")
		}
		seen[key] = true
	}
	seenOperations := make(map[string]bool, len(value.Operations))
	var previousManifestVersion int64
	for _, operation := range value.Operations {
		if err := validateOperationMeta(operation, value.ManifestVersion); err != nil {
			return manifest{}, corrupt("manifest")
		}
		if seenOperations[operation.OperationID] {
			return manifest{}, corrupt("manifest")
		}
		if previousManifestVersion > operation.ManifestVersion {
			return manifest{}, corrupt("manifest")
		}
		previousManifestVersion = operation.ManifestVersion
		seenOperations[operation.OperationID] = true
	}
	return value, nil
}

func validateRecordMeta(record manifestRecord) *Error {
	if failure := validateKey(record.Owner, record.Scope, record.Name); failure != nil {
		return failure
	}
	if record.EntityVersion < 1 || record.EntityVersion > MaxSequence {
		return invalid("entity_version")
	}
	if !digestPattern.MatchString(record.MetadataDigest) {
		return invalid("metadata_digest")
	}
	if record.MetadataBytes < 1 || record.MetadataBytes > MaxMetadataBytes {
		return invalid("metadata_bytes")
	}
	if record.CreatedAt.IsZero() || record.UpdatedAt.IsZero() || record.CreatedAt.After(record.UpdatedAt) {
		return invalid("timestamps")
	}
	return nil
}

func validateOperationMeta(operation manifestOperation, current int64) *Error {
	if !opPattern.MatchString(operation.OperationID) {
		return invalid("operation_id")
	}
	if failure := validateKey(operation.Owner, operation.Scope, operation.Name); failure != nil {
		return failure
	}
	if operation.ExpectedVersion < 0 || operation.ExpectedVersion > MaxSequence {
		return invalid("expected_version")
	}
	if operation.EntityVersion < 1 || operation.EntityVersion > MaxSequence {
		return invalid("entity_version")
	}
	if operation.ManifestVersion < 1 || operation.ManifestVersion > current {
		return invalid("manifest_version")
	}
	if !digestPattern.MatchString(operation.MetadataDigest) {
		return invalid("metadata_digest")
	}
	if operation.MetadataBytes < 1 || operation.MetadataBytes > MaxMetadataBytes {
		return invalid("metadata_bytes")
	}
	if operation.RecordedAt.IsZero() {
		return invalid("recorded_at")
	}
	return nil
}

func verifyManifestBlobs(root string, value manifest) error {
	checked := make(map[string]int, len(value.Records))
	for _, record := range value.Records {
		if size, ok := checked[record.MetadataDigest]; ok {
			if size != record.MetadataBytes {
				return corrupt("metadata_blob")
			}
			continue
		}
		if err := verifyBlob(root, record.MetadataDigest, record.MetadataBytes); err != nil {
			return err
		}
		checked[record.MetadataDigest] = record.MetadataBytes
	}
	return nil
}

func verifyBlob(root, digest string, size int) error {
	name := filepath.Join(root, blobsName, digest)
	info, err := os.Lstat(name)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return corrupt("metadata_blob")
		}
		return ioFailure("blob_read", err)
	}
	if !info.Mode().IsRegular() || info.Size() != int64(size) {
		return corrupt("metadata_blob")
	}
	data, err := os.ReadFile(name)
	if err != nil {
		return ioFailure("blob_read", err)
	}
	if sha256Hex(data) != digest {
		return corrupt("metadata_blob")
	}
	return nil
}

func (s *Store) apply(value manifest) {
	records := make(map[string]manifestRecord, len(value.Records))
	for _, record := range value.Records {
		records[recordKey(record.Owner, record.Scope, record.Name)] = record
	}
	operations := make(map[string]manifestOperation, len(value.Operations))
	order := make([]string, 0, len(value.Operations))
	for _, operation := range value.Operations {
		operations[operation.OperationID] = operation
		order = append(order, operation.OperationID)
	}
	s.records = records
	s.operations = operations
	s.operationOrder = order
	s.manifestVersion = value.ManifestVersion
}

// Write validates and commits one idempotent metadata record.
func (s *Store) Write(ctx context.Context, request WriteRequest) (WriteResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := contextFailure(ctx); err != nil {
		return WriteResult{}, err
	}
	if failure := validateWriteRequest(request); failure != nil {
		return WriteResult{}, failure
	}
	digest := sha256Hex(request.Metadata)

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return WriteResult{}, &Error{Code: CodeClosed}
	}
	if failure := contextFailure(ctx); failure != nil {
		return WriteResult{}, failure
	}
	if operation, ok := s.operations[request.OperationID]; ok {
		if sameOperation(operation, request, digest) {
			return resultFromOperation(operation, true), nil
		}
		return WriteResult{}, &Error{Code: CodeOperationConflict, Field: "operation_id"}
	}

	key := recordKey(request.Owner, request.Scope, request.Name)
	existing, exists := s.records[key]
	if exists {
		switch {
		case request.ExpectedVersion == 0:
			return WriteResult{}, &Error{Code: CodeAlreadyExists, Field: "name"}
		case request.ExpectedVersion != existing.EntityVersion:
			return WriteResult{}, &Error{Code: CodeStaleVersion, Field: "expected_version"}
		}
	} else if request.ExpectedVersion != 0 {
		return WriteResult{}, &Error{Code: CodeStaleVersion, Field: "expected_version"}
	}
	if !exists {
		scopeRecords := 0
		for _, rec := range s.records {
			if rec.Scope == request.Scope {
				scopeRecords++
			}
		}
		if scopeRecords >= MaxRecords {
			return WriteResult{}, &Error{Code: CodeQuotaExceeded, Field: "records"}
		}
	}

	nextManifestVersion := s.manifestVersion + 1
	if nextManifestVersion > MaxSequence {
		return WriteResult{}, &Error{Code: CodeQuotaExceeded, Field: "manifest_version"}
	}
	now := time.Now().UTC()
	record := manifestRecord{
		Owner:          request.Owner,
		Scope:          request.Scope,
		Name:           request.Name,
		EntityVersion:  1,
		MetadataDigest: digest,
		MetadataBytes:  len(request.Metadata),
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	if exists {
		record.CreatedAt = existing.CreatedAt
		record.EntityVersion = existing.EntityVersion + 1
	}
	operation := manifestOperation{
		OperationID:     request.OperationID,
		Owner:           request.Owner,
		Scope:           request.Scope,
		Name:            request.Name,
		ExpectedVersion: request.ExpectedVersion,
		EntityVersion:   record.EntityVersion,
		ManifestVersion: nextManifestVersion,
		MetadataDigest:  digest,
		MetadataBytes:   len(request.Metadata),
		RecordedAt:      now,
	}

	records := cloneRecords(s.records)
	records[key] = record
	operations := cloneOperations(s.operations)
	order := append([]string(nil), s.operationOrder...)
	if len(order) >= MaxOperations {
		drop := len(order) - MaxOperations + 1
		for _, identifier := range order[:drop] {
			delete(operations, identifier)
		}
		order = order[drop:]
	}
	order = append(order, operation.OperationID)
	operations[operation.OperationID] = operation

	candidate := manifest{
		SchemaVersion:   SchemaVersion,
		ManifestVersion: nextManifestVersion,
		PublishedAt:     now,
		Records:         sortedRecords(records),
		Operations:      orderedOperations(order, operations),
	}
	serialized, err := json.Marshal(candidate)
	if err != nil {
		return WriteResult{}, ioFailure("manifest_encode", err)
	}
	if len(serialized) > MaxManifestBytes {
		return WriteResult{}, &Error{Code: CodeQuotaExceeded, Field: "manifest"}
	}

	created, err := s.ensureBlob(digest, request.Metadata)
	if err != nil {
		if created {
			s.discardUncommittedBlob(digest, nextManifestVersion, true)
		}
		return WriteResult{}, err
	}
	if failure := contextFailure(ctx); failure != nil {
		s.discardUncommittedBlob(digest, nextManifestVersion, created)
		return WriteResult{}, failure
	}
	if err := s.publishManifest(nextManifestVersion, serialized); err != nil {
		s.discardUncommittedBlob(digest, nextManifestVersion, created)
		return WriteResult{}, err
	}

	s.records = records
	s.operations = operations
	s.operationOrder = order
	s.manifestVersion = nextManifestVersion
	s.cleanupLocked()

	return WriteResult{
		OperationID:     request.OperationID,
		EntityVersion:   record.EntityVersion,
		ManifestVersion: nextManifestVersion,
		MetadataDigest:  digest,
	}, nil
}

// Read returns one committed record after checking the stored bytes.
func (s *Store) Read(ctx context.Context, request ReadRequest) (Record, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := contextFailure(ctx); err != nil {
		return Record{}, err
	}
	if failure := validateKey(request.Owner, request.Scope, request.Name); failure != nil {
		return Record{}, failure
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return Record{}, &Error{Code: CodeClosed}
	}
	record, ok := s.records[recordKey(request.Owner, request.Scope, request.Name)]
	if !ok {
		// Owner/scope is part of the lookup key. A miss is indistinguishable
		// from absence, so unauthorized scopes do not learn that a name exists.
		return Record{}, &Error{Code: CodeNotFound, Field: "name"}
	}
	data, err := readVerifiedBlob(s.root, record.MetadataDigest, record.MetadataBytes)
	if err != nil {
		return Record{}, err
	}
	return Record{
		Owner:           record.Owner,
		Scope:           record.Scope,
		Name:            record.Name,
		EntityVersion:   record.EntityVersion,
		ManifestVersion: s.manifestVersion,
		MetadataDigest:  record.MetadataDigest,
		Metadata:        data,
		CreatedAt:       record.CreatedAt,
		UpdatedAt:       record.UpdatedAt,
	}, nil
}

// List returns committed records in one scope after checking their stored bytes.
// Callers must still enforce owner authorization; this port only enumerates.
func (s *Store) List(ctx context.Context, request ListRequest) ([]Record, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := contextFailure(ctx); err != nil {
		return nil, err
	}
	if !scopePattern.MatchString(request.Scope) {
		return nil, invalid("scope")
	}
	if request.Owner != "" && !ownerPattern.MatchString(request.Owner) {
		return nil, invalid("owner")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return nil, &Error{Code: CodeClosed}
	}
	names := make([]string, 0, len(s.records))
	for key, record := range s.records {
		if record.Scope != request.Scope {
			continue
		}
		if request.Owner != "" && record.Owner != request.Owner {
			continue
		}
		names = append(names, key)
	}
	sort.Strings(names)
	records := make([]Record, 0, len(names))
	for _, key := range names {
		if err := contextFailure(ctx); err != nil {
			return nil, err
		}
		record := s.records[key]
		data, err := readVerifiedBlob(s.root, record.MetadataDigest, record.MetadataBytes)
		if err != nil {
			return nil, err
		}
		records = append(records, Record{
			Owner:           record.Owner,
			Scope:           record.Scope,
			Name:            record.Name,
			EntityVersion:   record.EntityVersion,
			ManifestVersion: s.manifestVersion,
			MetadataDigest:  record.MetadataDigest,
			Metadata:        data,
			CreatedAt:       record.CreatedAt,
			UpdatedAt:       record.UpdatedAt,
		})
	}
	return records, nil
}

// Close releases the exclusive writer lock. It is safe to call repeatedly.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if s.lock == nil {
		return nil
	}
	unlockErr := syscall.Flock(int(s.lock.Fd()), syscall.LOCK_UN)
	closeErr := s.lock.Close()
	s.lock = nil
	if unlockErr != nil {
		return ioFailure("lock_unlock", unlockErr)
	}
	return ioFailure("lock_close", closeErr)
}

func (s *Store) ensureBlob(digest string, metadata []byte) (bool, error) {
	name := filepath.Join(s.root, blobsName, digest)
	if info, err := os.Lstat(name); err == nil {
		if !info.Mode().IsRegular() || info.Size() != int64(len(metadata)) {
			return false, corrupt("metadata_blob")
		}
		existing, err := os.ReadFile(name)
		if err != nil {
			return false, ioFailure("blob_read", err)
		}
		if sha256Hex(existing) != digest {
			return false, corrupt("metadata_blob")
		}
		return false, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, ioFailure("blob_stat", err)
	}

	if err := s.fault(stageMetadataWrite); err != nil {
		return false, err
	}
	temporary, err := os.CreateTemp(filepath.Join(s.root, stagingName), "blob-*.tmp")
	if err != nil {
		return false, ioFailure(stageMetadataWrite, err)
	}
	temporaryName := temporary.Name()
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(temporaryName)
		}
	}()
	if _, err := temporary.Write(metadata); err != nil {
		temporary.Close()
		return false, ioFailure(stageMetadataWrite, err)
	}
	if err := s.fault(stageMetadataSync); err != nil {
		temporary.Close()
		return false, err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return false, ioFailure(stageMetadataSync, err)
	}
	if err := temporary.Close(); err != nil {
		return false, ioFailure(stageMetadataSync, err)
	}
	staged, err := os.ReadFile(temporaryName)
	if err != nil {
		return false, ioFailure("staged_read", err)
	}
	if sha256Hex(staged) != digest {
		return false, corrupt("metadata_blob")
	}
	if err := s.fault(stageMetadataRename); err != nil {
		return false, err
	}
	if err := os.Rename(temporaryName, name); err != nil {
		return false, ioFailure(stageMetadataRename, err)
	}
	committed = true
	if err := s.fault(stageMetadataDirSync); err != nil {
		return true, err
	}
	if err := syncDir(filepath.Join(s.root, blobsName)); err != nil {
		return true, ioFailure(stageMetadataDirSync, err)
	}
	return true, nil
}

func (s *Store) publishManifest(version int64, data []byte) error {
	if err := s.fault(stageManifestWrite); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Join(s.root, stagingName), "manifest-*.tmp")
	if err != nil {
		return ioFailure(stageManifestWrite, err)
	}
	temporaryName := temporary.Name()
	defer func() { _ = os.Remove(temporaryName) }()
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return ioFailure(stageManifestWrite, err)
	}
	if err := s.fault(stageManifestSync); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return ioFailure(stageManifestSync, err)
	}
	if err := temporary.Close(); err != nil {
		return ioFailure(stageManifestSync, err)
	}
	if err := s.fault(stageManifestRename); err != nil {
		return err
	}
	if err := os.Rename(temporaryName, manifestPath(s.root, version)); err != nil {
		return ioFailure(stageManifestRename, err)
	}
	if err := s.fault(stageManifestDirSync); err != nil {
		return err
	}
	if err := syncDir(filepath.Join(s.root, manifestsName)); err != nil {
		return ioFailure(stageManifestDirSync, err)
	}
	return nil
}

func (s *Store) discardUncommittedBlob(digest string, version int64, created bool) {
	if !created {
		return
	}
	if s.referencedByState(digest) || manifestReferences(s.root, version, digest) {
		return
	}
	_ = os.Remove(filepath.Join(s.root, blobsName, digest))
}

// manifestReferences reports whether a manifest already present at version
// references digest. A missing manifest is safe to treat as unreferenced; an
// unreadable or invalid manifest is treated as referenced so cleanup cannot
// discard bytes that recovery may still need.
func manifestReferences(root string, version int64, digest string) bool {
	name := manifestPath(root, version)
	info, err := os.Lstat(name)
	if err != nil {
		return !errors.Is(err, os.ErrNotExist)
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > MaxManifestBytes {
		return true
	}
	data, err := os.ReadFile(name)
	if err != nil {
		return true
	}
	value, err := decodeManifest(data, version)
	if err != nil {
		return true
	}
	for _, record := range value.Records {
		if record.MetadataDigest == digest {
			return true
		}
	}
	return false
}

func (s *Store) referencedByState(digest string) bool {
	for _, record := range s.records {
		if record.MetadataDigest == digest {
			return true
		}
	}
	return false
}

func (s *Store) referencedDigests() map[string]bool {
	referenced := make(map[string]bool, len(s.records))
	for _, record := range s.records {
		referenced[record.MetadataDigest] = true
	}
	return referenced
}

func (s *Store) cleanupLocked() {
	_, _ = cleanupStagingLocked(s.root)
	_, _ = pruneManifestsLocked(s.root, s.manifestVersion)
	_, _ = cleanupOrphanBlobsLocked(s.root, s.referencedDigests())
}

func (s *Store) fault(value stage) error {
	if s.faults == nil {
		return nil
	}
	if err := s.faults(value); err != nil {
		return ioFailure(value, err)
	}
	return nil
}

func readVerifiedBlob(root, digest string, size int) ([]byte, error) {
	name := filepath.Join(root, blobsName, digest)
	info, err := os.Lstat(name)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, corrupt("metadata_blob")
		}
		return nil, ioFailure("blob_read", err)
	}
	if !info.Mode().IsRegular() || info.Size() != int64(size) {
		return nil, corrupt("metadata_blob")
	}
	data, err := os.ReadFile(name)
	if err != nil {
		return nil, ioFailure("blob_read", err)
	}
	if sha256Hex(data) != digest {
		return nil, corrupt("metadata_blob")
	}
	return data, nil
}

func validateWriteRequest(request WriteRequest) *Error {
	if !opPattern.MatchString(request.OperationID) {
		return invalid("operation_id")
	}
	if failure := validateKey(request.Owner, request.Scope, request.Name); failure != nil {
		return failure
	}
	if request.ExpectedVersion < 0 || request.ExpectedVersion > MaxSequence {
		return invalid("expected_version")
	}
	if len(request.Metadata) == 0 {
		return invalid("metadata")
	}
	if len(request.Metadata) > MaxMetadataBytes {
		return &Error{Code: CodeQuotaExceeded, Field: "metadata"}
	}
	return nil
}

func validateKey(owner, scope, name string) *Error {
	if len(owner) > MaxScopeLength || !ownerPattern.MatchString(owner) {
		return invalid("owner")
	}
	if len(scope) > MaxScopeLength || !scopePattern.MatchString(scope) {
		return invalid("scope")
	}
	if len(name) < 1 || len(name) > MaxNameLength || !namePattern.MatchString(name) {
		return invalid("name")
	}
	if path.Clean(name) != name || strings.Contains(name, "//") {
		return invalid("name")
	}
	for _, segment := range strings.Split(name, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return invalid("name")
		}
	}
	return nil
}

func sameOperation(operation manifestOperation, request WriteRequest, digest string) bool {
	return operation.Owner == request.Owner &&
		operation.Scope == request.Scope &&
		operation.Name == request.Name &&
		operation.ExpectedVersion == request.ExpectedVersion &&
		operation.MetadataDigest == digest &&
		operation.MetadataBytes == len(request.Metadata)
}

func resultFromOperation(operation manifestOperation, duplicate bool) WriteResult {
	return WriteResult{
		OperationID:     operation.OperationID,
		EntityVersion:   operation.EntityVersion,
		ManifestVersion: operation.ManifestVersion,
		MetadataDigest:  operation.MetadataDigest,
		Duplicate:       duplicate,
	}
}

func cloneRecords(records map[string]manifestRecord) map[string]manifestRecord {
	cloned := make(map[string]manifestRecord, len(records)+1)
	for key, record := range records {
		cloned[key] = record
	}
	return cloned
}

func cloneOperations(operations map[string]manifestOperation) map[string]manifestOperation {
	cloned := make(map[string]manifestOperation, len(operations)+1)
	for key, operation := range operations {
		cloned[key] = operation
	}
	return cloned
}

func sortedRecords(records map[string]manifestRecord) []manifestRecord {
	keys := make([]string, 0, len(records))
	for key := range records {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]manifestRecord, 0, len(keys))
	for _, key := range keys {
		result = append(result, records[key])
	}
	return result
}

func orderedOperations(order []string, operations map[string]manifestOperation) []manifestOperation {
	result := make([]manifestOperation, 0, len(order))
	for _, identifier := range order {
		result = append(result, operations[identifier])
	}
	return result
}

func recordKey(owner, scope, name string) string {
	return owner + "\x00" + scope + "\x00" + name
}

func manifestName(version int64) string {
	return fmt.Sprintf("%s%020d%s", manifestPrefix, version, manifestSuffix)
}

func parseManifestName(name string) (int64, bool) {
	if !strings.HasPrefix(name, manifestPrefix) || !strings.HasSuffix(name, manifestSuffix) {
		return 0, false
	}
	body := strings.TrimSuffix(strings.TrimPrefix(name, manifestPrefix), manifestSuffix)
	if len(body) != 20 {
		return 0, false
	}
	for _, character := range body {
		if character < '0' || character > '9' {
			return 0, false
		}
	}
	version, err := strconv.ParseInt(body, 10, 64)
	if err != nil || version < 1 || version > MaxSequence {
		return 0, false
	}
	return version, true
}

func manifestPath(root string, version int64) string {
	return filepath.Join(root, manifestsName, manifestName(version))
}

func syncDir(directory string) error {
	handle, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer handle.Close()
	return handle.Sync()
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func contextFailure(ctx context.Context) error {
	switch ctx.Err() {
	case nil:
		return nil
	case context.DeadlineExceeded:
		return &Error{Code: CodeTimeout}
	default:
		return &Error{Code: CodeCancelled}
	}
}

func invalid(field string) *Error {
	return &Error{Code: CodeInvalidInput, Field: field}
}

func corrupt(field string) *Error {
	return &Error{Code: CodeCorruptState, Field: field}
}

func ioFailure(stageValue stage, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, syscall.ENOSPC) || errors.Is(err, syscall.EDQUOT) {
		return &Error{Code: CodeDiskFull, Stage: string(stageValue), Err: err}
	}
	return &Error{Code: CodeIOFailure, Stage: string(stageValue), Err: err}
}
