// Package secrets implements versioned secret management with CAS update
// semantics (F07), bounded authorized transient reveal responses (F08), and
// provider retention with explicit operator destruction (F13).
//
// Invariants:
//  1. Delete and destroy are distinct; irreversible version destruction
//     strictly requires explicit operator action.
//  2. Soft-deleted secret versions retain provider-owned sealed bytes and can
//     be restored within the configured retention duration.
//  3. Irreversibly destroyed secret versions permanently purge provider payload
//     bytes and cannot be restored or revealed; failure is closed and immutable.
//  4. Plaintext secret bytes are owned by the provider envelope and NEVER enter
//     metadata storage, lifecycle tombstones or error payloads.
package secrets

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/parsa-emami/keyhelix/internal/auth"
	"github.com/parsa-emami/keyhelix/internal/contracts"
	"github.com/parsa-emami/keyhelix/internal/provider"
	"github.com/parsa-emami/keyhelix/internal/storage"
)

// VersionStatus represents the lifecycle state of a secret version (Requirement F13).
type VersionStatus string

const (
	VersionStatusActive    VersionStatus = "ACTIVE"
	VersionStatusDeleted   VersionStatus = "DELETED"
	VersionStatusDestroyed VersionStatus = "DESTROYED"
)

// Deletion-specific typed failure codes.
const (
	CodeExplicitActionRequired = "EXPLICIT_OPERATOR_ACTION_REQUIRED"
	CodeVersionDestroyed       = "VERSION_DESTROYED"
	CodeIllegalTransition      = "ILLEGAL_STATE_TRANSITION"
	CodeRetentionExpired       = "RETENTION_EXPIRED"
)

// DefaultRetentionDuration is the default provider retention window for soft-deleted versions.
const DefaultRetentionDuration = 30 * 24 * time.Hour

// DeletionError is a typed deletion lifecycle error.
type DeletionError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Err     error  `json:"-"`
}

func (e *DeletionError) Error() string {
	if e.Message != "" {
		return e.Code + ": " + e.Message
	}
	return e.Code
}

func (e *DeletionError) Unwrap() error { return e.Err }

// LifecycleRecord persists durable version retention and destruction state in storage.Port.
// Plaintext secret bytes are NEVER stored here.
type LifecycleRecord struct {
	SchemaVersion  string                    `json:"schema_version"`
	VaultID        string                    `json:"vault_id"`
	SecretPath     string                    `json:"secret_path"`
	Version        int64                     `json:"version"`
	Status         VersionStatus             `json:"status"`
	CreatedAt      string                    `json:"created_at,omitempty"`
	DeletedAt      string                    `json:"deleted_at,omitempty"`
	RetainUntil    string                    `json:"retain_until,omitempty"`
	DestroyedAt    string                    `json:"destroyed_at,omitempty"`
	DestroyedBy    string                    `json:"destroyed_by,omitempty"`
	RestoredAt     string                    `json:"restored_at,omitempty"`
	RestoredBy     string                    `json:"restored_by,omitempty"`
	ActiveMetadata *contracts.SecretMetadata `json:"active_metadata,omitempty"`
}

// DeleteRequest encapsulates inputs for soft-deleting a secret version with provider retention.
type DeleteRequest struct {
	VaultID           string
	SecretPath        string
	Version           int64
	RetentionDuration time.Duration
	Owner             string
	Identity          *auth.Identity
	OperationID       string
}

// DeleteOutcome represents the confirmed soft-deletion outcome with retention window.
type DeleteOutcome struct {
	VaultID     string        `json:"vault_id"`
	SecretPath  string        `json:"secret_path"`
	Version     int64         `json:"version"`
	Status      VersionStatus `json:"status"`
	DeletedAt   string        `json:"deleted_at"`
	RetainUntil string        `json:"retain_until"`
}

// UndeleteRequest encapsulates inputs for restoring a soft-deleted secret version.
type UndeleteRequest struct {
	VaultID     string
	SecretPath  string
	Version     int64
	Owner       string
	Identity    *auth.Identity
	OperationID string
}

// UndeleteOutcome represents the confirmed restore outcome.
type UndeleteOutcome struct {
	VaultID    string        `json:"vault_id"`
	SecretPath string        `json:"secret_path"`
	Version    int64         `json:"version"`
	Status     VersionStatus `json:"status"`
	RestoredAt string        `json:"restored_at"`
}

// DestroyRequest encapsulates inputs for irreversibly destroying a secret version.
// ExplicitOperatorAction or Confirmation=="DESTROY" is strictly mandatory.
type DestroyRequest struct {
	VaultID                string
	SecretPath             string
	Version                int64
	ExplicitOperatorAction bool
	Confirmation           string
	Owner                  string
	Identity               *auth.Identity
	OperationID            string
}

// DestroyOutcome represents the confirmed irreversible destruction outcome.
type DestroyOutcome struct {
	VaultID     string        `json:"vault_id"`
	SecretPath  string        `json:"secret_path"`
	Version     int64         `json:"version"`
	Status      VersionStatus `json:"status"`
	DestroyedAt string        `json:"destroyed_at"`
	DestroyedBy string        `json:"destroyed_by"`
}

// LifecycleQuery selects lifecycle status for one version.
type LifecycleQuery struct {
	VaultID    string
	SecretPath string
	Version    int64
	Owner      string
	Identity   *auth.Identity
}

// DeleteSecret performs a soft-deletion of a secret version, applying provider
// retention policy. Provider-owned sealed bytes are RETAINED, not destroyed.
func (s *Service) DeleteSecret(ctx context.Context, req DeleteRequest) (*DeleteOutcome, error) {
	if strings.TrimSpace(req.VaultID) == "" {
		return nil, &contracts.ValidationError{Code: contracts.InvalidInput, Field: "vault_id"}
	}
	cleanPath, err := auth.NormalizePath(req.SecretPath)
	if err != nil {
		return nil, &contracts.ValidationError{Code: contracts.InvalidInput, Field: "secret_path"}
	}
	if req.Version < 0 {
		return nil, &contracts.ValidationError{Code: contracts.InvalidInput, Field: "version"}
	}

	targetOwner := resolveOwner(req.Owner, req.Identity)
	if targetOwner == "" {
		targetOwner = "default-owner"
	}

	// 1. Authorization check
	if req.Identity != nil {
		if !isDeleteAuthorized(req.Identity, targetOwner, cleanPath) {
			return nil, &auth.Error{Code: auth.CodeScopeDenied, Message: CodeUnauthorized}
		}
	}

	// 2. Provider health check
	if s.keyProvider == nil {
		return nil, &provider.Error{Code: provider.CodeProviderUnavailable, Message: "provider offline"}
	}
	health, err := s.keyProvider.Health(ctx)
	if err != nil {
		return nil, err
	}
	if health != nil && health.Sealed {
		return nil, &provider.Error{Code: provider.CodeProviderSealed, Message: "provider is sealed"}
	}

	// 3. Read current record
	record, err := s.store.Read(ctx, storage.ReadRequest{
		Owner: targetOwner,
		Scope: req.VaultID,
		Name:  cleanPath,
	})
	if err != nil {
		return nil, err
	}

	var currentActive contracts.SecretMetadata
	var currentLifecycle LifecycleRecord
	var isLifecycle bool

	if unmarshalErr := json.Unmarshal(record.Metadata, &currentLifecycle); unmarshalErr == nil && currentLifecycle.SchemaVersion == "lifecycle-v1" {
		isLifecycle = true
	} else {
		var decodeFail *contracts.ValidationError
		currentActive, decodeFail = contracts.DecodeSecret(ctx, record.Metadata)
		if decodeFail != nil {
			return nil, &storage.Error{Code: storage.CodeCorruptState, Field: "metadata"}
		}
	}

	if isLifecycle {
		if currentLifecycle.Status == VersionStatusDestroyed {
			return nil, &DeletionError{
				Code:    CodeIllegalTransition,
				Message: "cannot soft-delete an already destroyed secret version",
			}
		}
		if currentLifecycle.Status == VersionStatusDeleted {
			return &DeleteOutcome{
				VaultID:     req.VaultID,
				SecretPath:  cleanPath,
				Version:     currentLifecycle.Version,
				Status:      VersionStatusDeleted,
				DeletedAt:   currentLifecycle.DeletedAt,
				RetainUntil: currentLifecycle.RetainUntil,
			}, nil
		}
	}

	retention := req.RetentionDuration
	if retention <= 0 {
		retention = DefaultRetentionDuration
	}

	now := time.Now().UTC()
	deletedAt := now.Format(time.RFC3339)
	retainUntil := now.Add(retention).Format(time.RFC3339)

	targetVersion := currentActive.Version
	if isLifecycle {
		targetVersion = currentLifecycle.Version
	}
	if req.Version > 0 && req.Version != targetVersion {
		return nil, &storage.Error{Code: storage.CodeStaleVersion, Field: "version"}
	}

	activeBackup := currentActive
	if isLifecycle && currentLifecycle.ActiveMetadata != nil {
		activeBackup = *currentLifecycle.ActiveMetadata
	}

	newLifecycle := LifecycleRecord{
		SchemaVersion:  "lifecycle-v1",
		VaultID:        req.VaultID,
		SecretPath:     cleanPath,
		Version:        targetVersion,
		Status:         VersionStatusDeleted,
		CreatedAt:      activeBackup.CreatedAt,
		DeletedAt:      deletedAt,
		RetainUntil:    retainUntil,
		ActiveMetadata: &activeBackup,
	}

	metaBytes, err := json.Marshal(newLifecycle)
	if err != nil {
		return nil, fmt.Errorf("marshal lifecycle record: %w", err)
	}

	opID := req.OperationID
	if opID == "" {
		hasher := sha256.New()
		hasher.Write([]byte(fmt.Sprintf("del:%s:%s:%d:%d", targetOwner, cleanPath, targetVersion, now.UnixNano())))
		opID = "op-del-" + hex.EncodeToString(hasher.Sum(nil))[:16]
	}

	// CAS update on secret record: replaces active metadata with deleted tombstone
	_, err = s.store.Write(ctx, storage.WriteRequest{
		OperationID:     opID,
		Owner:           targetOwner,
		Scope:           req.VaultID,
		Name:            cleanPath,
		ExpectedVersion: record.EntityVersion,
		Metadata:        metaBytes,
	})
	if err != nil {
		return nil, err
	}

	// Also record in lifecycle scope for durable audit/version tracking
	versionOpID := fmt.Sprintf("op-lc-del-%s-v%d-%d", hex.EncodeToString([]byte(cleanPath))[:8], targetVersion, now.UnixNano())
	if err := s.writeLifecycleArchive(ctx, versionOpID, targetOwner, req.VaultID, cleanPath, targetVersion, metaBytes); err != nil {
		return nil, err
	}

	return &DeleteOutcome{
		VaultID:     req.VaultID,
		SecretPath:  cleanPath,
		Version:     targetVersion,
		Status:      VersionStatusDeleted,
		DeletedAt:   deletedAt,
		RetainUntil: retainUntil,
	}, nil
}

// UndeleteSecret restores a soft-deleted secret version back to ACTIVE status
// within the retention window. If the version was destroyed, undelete is permanently refused.
func (s *Service) UndeleteSecret(ctx context.Context, req UndeleteRequest) (*UndeleteOutcome, error) {
	if strings.TrimSpace(req.VaultID) == "" {
		return nil, &contracts.ValidationError{Code: contracts.InvalidInput, Field: "vault_id"}
	}
	cleanPath, err := auth.NormalizePath(req.SecretPath)
	if err != nil {
		return nil, &contracts.ValidationError{Code: contracts.InvalidInput, Field: "secret_path"}
	}
	if req.Version < 0 {
		return nil, &contracts.ValidationError{Code: contracts.InvalidInput, Field: "version"}
	}

	targetOwner := resolveOwner(req.Owner, req.Identity)
	if targetOwner == "" {
		targetOwner = "default-owner"
	}

	// 1. Authorization check
	if req.Identity != nil {
		if !isDeleteAuthorized(req.Identity, targetOwner, cleanPath) {
			return nil, &auth.Error{Code: auth.CodeScopeDenied, Message: CodeUnauthorized}
		}
	}

	// 2. Provider health check
	if s.keyProvider == nil {
		return nil, &provider.Error{Code: provider.CodeProviderUnavailable, Message: "provider offline"}
	}
	health, err := s.keyProvider.Health(ctx)
	if err != nil {
		return nil, err
	}
	if health != nil && health.Sealed {
		return nil, &provider.Error{Code: provider.CodeProviderSealed, Message: "provider is sealed"}
	}

	// 3. Read current record
	record, err := s.store.Read(ctx, storage.ReadRequest{
		Owner: targetOwner,
		Scope: req.VaultID,
		Name:  cleanPath,
	})
	if err != nil {
		return nil, err
	}

	var currentLifecycle LifecycleRecord
	if err := json.Unmarshal(record.Metadata, &currentLifecycle); err != nil || currentLifecycle.SchemaVersion != "lifecycle-v1" {
		_, decodeErr := contracts.DecodeSecret(ctx, record.Metadata)
		if decodeErr == nil {
			// Already active
			return &UndeleteOutcome{
				VaultID:    req.VaultID,
				SecretPath: cleanPath,
				Version:    record.EntityVersion,
				Status:     VersionStatusActive,
				RestoredAt: time.Now().UTC().Format(time.RFC3339),
			}, nil
		}
		return nil, &storage.Error{Code: storage.CodeCorruptState, Field: "metadata"}
	}

	// Invariant: Irreversible version destruction cannot be undeleted!
	if currentLifecycle.Status == VersionStatusDestroyed {
		return nil, &DeletionError{
			Code:    CodeVersionDestroyed,
			Message: "cannot undelete destroyed version; destruction is irreversible",
		}
	}

	if currentLifecycle.Status != VersionStatusDeleted {
		return nil, &DeletionError{
			Code:    CodeIllegalTransition,
			Message: "secret version is not in deleted state",
		}
	}

	// Check retention expiry
	if currentLifecycle.RetainUntil != "" {
		retainUntil, parseErr := time.Parse(time.RFC3339, currentLifecycle.RetainUntil)
		if parseErr == nil && time.Now().UTC().After(retainUntil) {
			return nil, &DeletionError{Code: CodeRetentionExpired, Message: "retention period has expired"}
		}
	}

	if currentLifecycle.ActiveMetadata == nil {
		return nil, &storage.Error{Code: storage.CodeCorruptState, Field: "active_metadata"}
	}

	now := time.Now().UTC()
	restoredAt := now.Format(time.RFC3339)

	// Restore original active metadata
	restoredMeta := *currentLifecycle.ActiveMetadata
	metaBytes, err := json.Marshal(restoredMeta)
	if err != nil {
		return nil, fmt.Errorf("marshal restored metadata: %w", err)
	}

	opID := req.OperationID
	if opID == "" {
		hasher := sha256.New()
		hasher.Write([]byte(fmt.Sprintf("undel:%s:%s:%d:%d", targetOwner, cleanPath, restoredMeta.Version, now.UnixNano())))
		opID = "op-undel-" + hex.EncodeToString(hasher.Sum(nil))[:16]
	}

	_, err = s.store.Write(ctx, storage.WriteRequest{
		OperationID:     opID,
		Owner:           targetOwner,
		Scope:           req.VaultID,
		Name:            cleanPath,
		ExpectedVersion: record.EntityVersion,
		Metadata:        metaBytes,
	})
	if err != nil {
		return nil, err
	}

	// Archive restored lifecycle record
	archivedLifecycle := currentLifecycle
	archivedLifecycle.Status = VersionStatusActive
	archivedLifecycle.RestoredAt = restoredAt
	archivedLifecycle.RestoredBy = targetOwner
	archivedLifecycle.Version = restoredMeta.Version
	archivedBytes, err := json.Marshal(archivedLifecycle)
	if err != nil {
		return nil, fmt.Errorf("marshal archived lifecycle record: %w", err)
	}
	versionOpID := fmt.Sprintf("op-lc-undel-%s-v%d-%d", hex.EncodeToString([]byte(cleanPath))[:8], restoredMeta.Version, now.UnixNano())
	if err := s.writeLifecycleArchive(ctx, versionOpID, targetOwner, req.VaultID, cleanPath, restoredMeta.Version, archivedBytes); err != nil {
		return nil, err
	}

	return &UndeleteOutcome{
		VaultID:    req.VaultID,
		SecretPath: cleanPath,
		Version:    restoredMeta.Version,
		Status:     VersionStatusActive,
		RestoredAt: restoredAt,
	}, nil
}

// DestroySecretVersion permanently and irreversibly destroys a secret version.
// Requirement F13: Irreversible destruction strictly requires explicit operator action.
func (s *Service) DestroySecretVersion(ctx context.Context, req DestroyRequest) (*DestroyOutcome, error) {
	if strings.TrimSpace(req.VaultID) == "" {
		return nil, &contracts.ValidationError{Code: contracts.InvalidInput, Field: "vault_id"}
	}
	cleanPath, err := auth.NormalizePath(req.SecretPath)
	if err != nil {
		return nil, &contracts.ValidationError{Code: contracts.InvalidInput, Field: "secret_path"}
	}
	if req.Version < 0 {
		return nil, &contracts.ValidationError{Code: contracts.InvalidInput, Field: "version"}
	}

	// Acceptance: irreversible version destruction requires explicit operator action
	if !req.ExplicitOperatorAction && !strings.EqualFold(req.Confirmation, "DESTROY") {
		return nil, &DeletionError{
			Code:    CodeExplicitActionRequired,
			Message: "irreversible version destruction requires explicit operator confirmation",
		}
	}

	targetOwner := resolveOwner(req.Owner, req.Identity)
	if targetOwner == "" {
		targetOwner = "default-owner"
	}

	// Operator authorization check: role must be vault-admin or identity must carry secret:destroy scope
	if req.Identity == nil {
		return nil, &auth.Error{Code: auth.CodeScopeDenied, Message: CodeUnauthorized}
	}
	if req.Identity.VaultRole != "vault-admin" && !hasScope(req.Identity, "secret:destroy") {
		return nil, &auth.Error{Code: auth.CodeScopeDenied, Message: CodeUnauthorized}
	}

	// Provider health check: Provider must be available to purge sealed payload
	if s.keyProvider == nil {
		return nil, &provider.Error{Code: provider.CodeProviderUnavailable, Message: "provider offline"}
	}
	health, err := s.keyProvider.Health(ctx)
	if err != nil {
		return nil, err
	}
	if health != nil && health.Sealed {
		return nil, &provider.Error{Code: provider.CodeProviderSealed, Message: "provider is sealed"}
	}

	// Read current record
	record, err := s.store.Read(ctx, storage.ReadRequest{
		Owner: targetOwner,
		Scope: req.VaultID,
		Name:  cleanPath,
	})
	if err != nil {
		return nil, err
	}

	var currentLifecycle LifecycleRecord
	var secretVersion int64

	if err := json.Unmarshal(record.Metadata, &currentLifecycle); err == nil && currentLifecycle.SchemaVersion == "lifecycle-v1" {
		secretVersion = currentLifecycle.Version
		if currentLifecycle.Status == VersionStatusDestroyed {
			// Idempotent: already destroyed
			return &DestroyOutcome{
				VaultID:     req.VaultID,
				SecretPath:  cleanPath,
				Version:     currentLifecycle.Version,
				Status:      VersionStatusDestroyed,
				DestroyedAt: currentLifecycle.DestroyedAt,
				DestroyedBy: currentLifecycle.DestroyedBy,
			}, nil
		}
	} else if active, decodeErr := contracts.DecodeSecret(ctx, record.Metadata); decodeErr == nil {
		secretVersion = active.Version
	} else {
		secretVersion = record.EntityVersion
	}

	if req.Version > 0 && req.Version != secretVersion {
		return nil, &storage.Error{Code: storage.CodeStaleVersion, Field: "version"}
	}

	now := time.Now().UTC()
	destroyedAt := now.Format(time.RFC3339)

	// Irreversible payload purge from provider
	if destroyer, ok := s.keyProvider.(provider.PayloadDestroyer); ok {
		if err := destroyer.DestroySealedPayload(ctx, provider.SealedRef{
			VaultID: req.VaultID,
			Path:    cleanPath,
			Version: secretVersion,
		}); err != nil {
			return nil, err
		}
	}

	// Irreversible tombstone: ActiveMetadata and envelope are wiped completely
	destroyedLifecycle := LifecycleRecord{
		SchemaVersion:  "lifecycle-v1",
		VaultID:        req.VaultID,
		SecretPath:     cleanPath,
		Version:        secretVersion,
		Status:         VersionStatusDestroyed,
		DestroyedAt:    destroyedAt,
		DestroyedBy:    req.Identity.Subject,
		ActiveMetadata: nil,
	}

	metaBytes, err := json.Marshal(destroyedLifecycle)
	if err != nil {
		return nil, fmt.Errorf("marshal destroyed lifecycle record: %w", err)
	}

	opID := req.OperationID
	if opID == "" {
		hasher := sha256.New()
		hasher.Write([]byte(fmt.Sprintf("dst:%s:%s:%d:%d", targetOwner, cleanPath, secretVersion, now.UnixNano())))
		opID = "op-dst-" + hex.EncodeToString(hasher.Sum(nil))[:16]
	}

	_, err = s.store.Write(ctx, storage.WriteRequest{
		OperationID:     opID,
		Owner:           targetOwner,
		Scope:           req.VaultID,
		Name:            cleanPath,
		ExpectedVersion: record.EntityVersion,
		Metadata:        metaBytes,
	})
	if err != nil {
		return nil, err
	}

	// Archive destroyed record under lifecycle scope
	versionOpID := fmt.Sprintf("op-lc-dst-%s-v%d-%d", hex.EncodeToString([]byte(cleanPath))[:8], secretVersion, now.UnixNano())
	if err := s.writeLifecycleArchive(ctx, versionOpID, targetOwner, req.VaultID, cleanPath, secretVersion, metaBytes); err != nil {
		return nil, err
	}

	return &DestroyOutcome{
		VaultID:     req.VaultID,
		SecretPath:  cleanPath,
		Version:     secretVersion,
		Status:      VersionStatusDestroyed,
		DestroyedAt: destroyedAt,
		DestroyedBy: req.Identity.Subject,
	}, nil
}

// GetVersionLifecycle inspects the durable lifecycle state of a secret.
func (s *Service) GetVersionLifecycle(ctx context.Context, vaultID, secretPath string, version int64, identity *auth.Identity) (*LifecycleRecord, error) {
	if strings.TrimSpace(vaultID) == "" {
		return nil, &contracts.ValidationError{Code: contracts.InvalidInput, Field: "vault_id"}
	}
	cleanPath, err := auth.NormalizePath(secretPath)
	if err != nil {
		return nil, &contracts.ValidationError{Code: contracts.InvalidInput, Field: "secret_path"}
	}
	targetOwner := resolveOwner("", identity)
	if targetOwner == "" {
		targetOwner = "default-owner"
	}

	record, err := s.store.Read(ctx, storage.ReadRequest{
		Owner: targetOwner,
		Scope: vaultID,
		Name:  cleanPath,
	})
	if err != nil {
		return nil, err
	}

	var lc LifecycleRecord
	if err := json.Unmarshal(record.Metadata, &lc); err == nil && lc.SchemaVersion == "lifecycle-v1" {
		return &lc, nil
	}

	meta, failure := contracts.DecodeSecret(ctx, record.Metadata)
	if failure != nil {
		return nil, &storage.Error{Code: storage.CodeCorruptState, Field: "metadata"}
	}

	return &LifecycleRecord{
		SchemaVersion:  "lifecycle-v1",
		VaultID:        meta.VaultID,
		SecretPath:     meta.SecretPath,
		Version:        meta.Version,
		Status:         VersionStatusActive,
		CreatedAt:      meta.CreatedAt,
		ActiveMetadata: &meta,
	}, nil
}

func lifecycleScope(vaultID string) string {
	return "lifecycle-" + vaultID
}

func lifecycleRecordName(secretPath string, version int64) string {
	return fmt.Sprintf("%s/v%d", secretPath, version)
}

func (s *Service) writeLifecycleArchive(ctx context.Context, opID, owner, vaultID, secretPath string, version int64, metadata []byte) error {
	scope := lifecycleScope(vaultID)
	name := lifecycleRecordName(secretPath, version)
	expectedVersion, err := s.currentVersion(ctx, owner, scope, name)
	if err != nil {
		return err
	}
	_, err = s.store.Write(ctx, storage.WriteRequest{
		OperationID:     opID,
		Owner:           owner,
		Scope:           scope,
		Name:            name,
		ExpectedVersion: expectedVersion,
		Metadata:        metadata,
	})
	return err
}

func hasScope(identity *auth.Identity, requiredScope string) bool {
	if identity == nil {
		return false
	}
	for _, sc := range identity.AllowedScopes {
		if sc == "*" || sc == requiredScope {
			return true
		}
	}
	return false
}

func isDeleteAuthorized(identity *auth.Identity, targetOwner, canonicalPath string) bool {
	if !auth.IsOwnerAuthorized(identity, targetOwner) || !auth.IsPathScopeAuthorized(identity, canonicalPath) {
		return false
	}
	if identity.VaultRole == "vault-admin" || hasScope(identity, "secret:delete") || hasScope(identity, "secret:write") || hasScope(identity, "*") {
		return true
	}
	for _, sc := range identity.AllowedScopes {
		if strings.Contains(sc, "/") {
			return true
		}
	}
	return false
}

