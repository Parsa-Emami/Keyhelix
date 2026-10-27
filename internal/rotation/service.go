// Package rotation implements resumable provider version and KEK rotations (Requirement F12).
//
// Invariants:
//  1. Partial rotation resumes from the last durable checkpoint without deleting
//     any valid prior secret version in metadata storage or provider payload storage.
//  2. State transitions follow PLANNED -> REWRAPPING -> VERIFYING -> COMPLETE | FAILED_ROLLBACK.
//  3. Retiring a prior KEK is forbidden until all target envelopes in the job are
//     rewrapped and verified.
//  4. Plaintext secret bytes are owned by the provider envelope and never enter
//     rotation metadata storage or audit events.
package rotation

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/parsa-emami/keyhelix/internal/audit"
	"github.com/parsa-emami/keyhelix/internal/auth"
	"github.com/parsa-emami/keyhelix/internal/contracts"
	"github.com/parsa-emami/keyhelix/internal/provider"
	"github.com/parsa-emami/keyhelix/internal/storage"
)

// State represents the lifecycle state of a rotation job.
type State string

const (
	StatePlanned        State = "PLANNED"
	StateRewrapping     State = "REWRAPPING"
	StateVerifying      State = "VERIFYING"
	StateComplete       State = "COMPLETE"
	StateFailedRollback State = "FAILED_ROLLBACK"
)

// Error codes for rotation operations.
const (
	CodeInvalidInput        = "INVALID_INPUT"
	CodeStepUpRequired      = "STEP_UP_REQUIRED"
	CodeUnauthorized        = "UNAUTHORIZED"
	CodeScopeDenied         = "SCOPE_DENIED"
	CodeProviderUnavailable = string(provider.CodeProviderUnavailable)
	CodeRotationNotFound    = "ROTATION_NOT_FOUND"
	CodeRotationIncomplete  = "ROTATION_INCOMPLETE"
	CodeIllegalTransition   = "ILLEGAL_STATE_TRANSITION"
	CodeIntegrityFailure    = "ROTATION_INTEGRITY_FAILURE"
)

const rotationStorageScope = "rotations"

// Error is a typed rotation error that never contains secret material.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Err     error  `json:"-"`
}

func (e *Error) Error() string {
	if e.Message != "" {
		return e.Code + ": " + e.Message
	}
	return e.Code
}

func (e *Error) Unwrap() error { return e.Err }

// SecretRotationItem tracks the durable rotation checkpoint of a single secret path.
type SecretRotationItem struct {
	SecretID            string              `json:"secret_id"`
	SecretPath          string              `json:"secret_path"`
	Classification      string              `json:"classification"`
	PriorVersion        int64               `json:"prior_version"`
	PriorMetadataDigest string              `json:"prior_metadata_digest"`
	PriorEnvelope       contracts.Envelope  `json:"prior_envelope"`
	TargetVersion       int64               `json:"target_version"`
	PendingEnvelope     *contracts.Envelope `json:"pending_envelope,omitempty"`
	PendingCreatedAt    string              `json:"pending_created_at,omitempty"`
	PendingCiphertext   string              `json:"pending_ciphertext,omitempty"`
	ActiveVersion       int64               `json:"active_version"`
	Rewrapped           bool                `json:"rewrapped"`
	Verified            bool                `json:"verified"`
}

// RotationJob is the durable aggregate tracking a resumable multi-secret rotation.
type RotationJob struct {
	SchemaVersion         int                  `json:"schema_version"`
	ID                    string               `json:"id"`
	VaultID               string               `json:"vault_id"`
	Owner                 string               `json:"owner"`
	SourceKEKID           string               `json:"source_kek_id"`
	TargetKEKID           string               `json:"target_kek_id"`
	TargetKEKVersion      string               `json:"target_kek_version"`
	State                 State                `json:"state"`
	Items                 []SecretRotationItem `json:"items"`
	RetirePriorKEKAllowed bool                 `json:"retire_prior_kek_allowed"`
	LastFailureCode       string               `json:"last_failure_code,omitempty"`
	CreatedAt             string               `json:"created_at"`
	UpdatedAt             string               `json:"updated_at"`
}

// StartOrResumeRequest defines inputs to start a new rotation job or resume a partial one.
type StartOrResumeRequest struct {
	JobID            string
	VaultID          string
	Owner            string
	SourceKEKID      string
	TargetKEKID      string
	TargetKEKVersion string
	SecretPaths      []string
	OperatorIdent    *auth.Identity
	Session          *auth.Session
	StepUpManager    *auth.StepUpManager
	StepUpToken      string
	// MaxItemsThisRun optionally bounds how many unrotated secrets are processed
	// in a single invocation to test deterministic mid-rotation interruption and resume.
	MaxItemsThisRun int
}

// Service coordinates resumable secret version and KEK rotations.
type Service struct {
	mu          sync.Mutex
	mapper      *auth.ScopeMapper
	keyProvider provider.Port
	store       storage.Port
	recorder    *audit.Recorder
}

// NewService constructs a new rotation Service.
func NewService(mapper *auth.ScopeMapper, keyProvider provider.Port, store storage.Port, recorder *audit.Recorder) *Service {
	return &Service{
		mapper:      mapper,
		keyProvider: keyProvider,
		store:       store,
		recorder:    recorder,
	}
}

// ValidateTransition verifies whether moving from current to next is a legal KeyRotation transition.
func ValidateTransition(current, next State) error {
	switch current {
	case "":
		if next == StatePlanned {
			return nil
		}
	case StatePlanned:
		if next == StateRewrapping || next == StateFailedRollback {
			return nil
		}
	case StateRewrapping:
		if next == StateRewrapping || next == StateVerifying || next == StateFailedRollback {
			return nil
		}
	case StateVerifying:
		if next == StateComplete || next == StateRewrapping || next == StateFailedRollback {
			return nil
		}
	case StateFailedRollback:
		if next == StateRewrapping {
			return nil
		}
	case StateComplete:
		if next == StateComplete {
			return nil
		}
	}
	return &Error{
		Code:    CodeIllegalTransition,
		Message: fmt.Sprintf("illegal rotation state transition from %s to %s", current, next),
	}
}

// StartOrResumeRotation initiates a new rotation job or resumes an existing partial job
// from its durable checkpoint in storage without deleting valid prior secret versions.
func (s *Service) StartOrResumeRotation(ctx context.Context, req StartOrResumeRequest) (*RotationJob, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if s.store == nil {
		return nil, &Error{Code: CodeInvalidInput, Message: "storage port is required"}
	}
	if s.keyProvider == nil {
		return nil, &provider.Error{Code: provider.CodeProviderUnavailable, Message: "provider offline"}
	}
	if strings.TrimSpace(req.JobID) == "" {
		return nil, &contracts.ValidationError{Code: contracts.InvalidInput, Field: "job_id"}
	}
	if strings.TrimSpace(req.VaultID) == "" {
		return nil, &contracts.ValidationError{Code: contracts.InvalidInput, Field: "vault_id"}
	}
	if strings.TrimSpace(req.TargetKEKVersion) == "" {
		return nil, &contracts.ValidationError{Code: contracts.InvalidInput, Field: "target_kek_version"}
	}
	if req.OperatorIdent == nil {
		return nil, &Error{Code: CodeUnauthorized, Message: "operator identity is required"}
	}
	if req.OperatorIdent.ExpiresAt > 0 && time.Now().Unix() > req.OperatorIdent.ExpiresAt {
		return nil, &Error{Code: CodeUnauthorized, Message: "operator identity is expired"}
	}

	targetOwner := strings.TrimSpace(req.Owner)
	if targetOwner == "" {
		if req.OperatorIdent.Email != "" {
			targetOwner = req.OperatorIdent.Email
		} else {
			targetOwner = req.OperatorIdent.Subject
		}
	}
	if !isOwnerAuthorized(req.OperatorIdent, targetOwner) {
		return nil, &Error{Code: CodeScopeDenied, Message: "operator is not authorized for target owner"}
	}

	// Mandatory fresh step-up authentication for rotation policy/key changes
	if req.StepUpManager == nil || req.Session == nil || strings.TrimSpace(req.StepUpToken) == "" {
		return nil, &Error{Code: CodeStepUpRequired, Message: "fresh step-up authentication required for rotation"}
	}
	if _, err := req.StepUpManager.ValidateStepUp(
		ctx,
		req.Session,
		req.StepUpToken,
		auth.ActionPolicyChange,
		"vault/"+req.VaultID+"/rotations",
	); err != nil {
		return nil, &Error{Code: CodeStepUpRequired, Message: "step-up validation failed for rotation", Err: err}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	job, jobEntityVersion, err := s.loadJobLocked(ctx, targetOwner, req.JobID)
	if err != nil {
		return nil, err
	}

	isNewJob := false
	if job == nil {
		if len(req.SecretPaths) == 0 {
			return nil, &contracts.ValidationError{Code: contracts.InvalidInput, Field: "secret_paths"}
		}
		createdJob, initErr := s.initializePlannedJob(ctx, req, targetOwner)
		if initErr != nil {
			return nil, initErr
		}
		job = createdJob
		isNewJob = true

		savedVer, saveErr := s.saveJobLocked(ctx, targetOwner, job, 0)
		if saveErr != nil {
			return nil, saveErr
		}
		jobEntityVersion = savedVer

		s.emitAudit(ctx, audit.EventKeyRotationStarted, req.VaultID+"/"+job.ID, AuditDetails(req.OperatorIdent, req.VaultID, "rotation:start", "started", map[string]any{
			"job_id":             job.ID,
			"target_kek_id":      job.TargetKEKID,
			"target_kek_version": job.TargetKEKVersion,
			"secret_count":       len(job.Items),
		}))
	} else {
		if job.VaultID != req.VaultID {
			return nil, &Error{Code: CodeInvalidInput, Message: "job vault_id mismatch"}
		}
		if job.State == StateComplete {
			return job, nil
		}
	}

	// Transition to REWRAPPING
	if err := ValidateTransition(job.State, StateRewrapping); err != nil {
		return nil, err
	}
	job.State = StateRewrapping
	job.LastFailureCode = ""
	job.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	savedVer, err := s.saveJobLocked(ctx, targetOwner, job, jobEntityVersion)
	if err != nil {
		return nil, err
	}
	jobEntityVersion = savedVer
	_ = isNewJob

	processedThisRun := 0
	for i := range job.Items {
		item := &job.Items[i]
		if item.Rewrapped && item.Verified {
			continue
		}

		if req.MaxItemsThisRun > 0 && processedThisRun >= req.MaxItemsThisRun {
			job.LastFailureCode = CodeRotationIncomplete
			job.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
			_, _ = s.saveJobLocked(ctx, targetOwner, job, jobEntityVersion)
			return job, &Error{
				Code:    CodeRotationIncomplete,
				Message: fmt.Sprintf("rotation paused after %d item(s); prior versions preserved and resumable", processedThisRun),
			}
		}

		if err := s.rewrapSingleItem(ctx, targetOwner, job, item, &jobEntityVersion); err != nil {
			job.LastFailureCode = extractErrorCode(err)
			job.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
			_, _ = s.saveJobLocked(ctx, targetOwner, job, jobEntityVersion)
			return job, err
		}
		processedThisRun++

		s.emitAudit(ctx, audit.EventKeyEnvelopeRewrapped, job.VaultID+"/"+item.SecretPath, audit.AuditData{
			Actor:          actorID(req.OperatorIdent),
			VaultID:        job.VaultID,
			SecretPath:     item.SecretPath,
			Version:        item.TargetVersion,
			Classification: item.Classification,
			Action:         "rotation:rewrap",
			Outcome:        "success",
			Details: map[string]any{
				"job_id":             job.ID,
				"prior_version":      item.PriorVersion,
				"target_version":     item.TargetVersion,
				"target_kek_id":      job.TargetKEKID,
				"target_kek_version": job.TargetKEKVersion,
			},
		})
	}

	// Transition REWRAPPING -> VERIFYING
	if err := ValidateTransition(job.State, StateVerifying); err != nil {
		return nil, err
	}
	job.State = StateVerifying
	job.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	savedVer, err = s.saveJobLocked(ctx, targetOwner, job, jobEntityVersion)
	if err != nil {
		return nil, err
	}
	jobEntityVersion = savedVer

	// Verify every item's new version AND confirm prior version payload still exists in provider
	for i := range job.Items {
		item := &job.Items[i]
		if err := s.verifyItemAndPriorPreserved(ctx, targetOwner, job.VaultID, job.TargetKEKID, item); err != nil {
			job.LastFailureCode = extractErrorCode(err)
			job.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
			_, _ = s.saveJobLocked(ctx, targetOwner, job, jobEntityVersion)
			return job, err
		}
		item.Verified = true
	}

	// Transition VERIFYING -> COMPLETE
	if err := ValidateTransition(job.State, StateComplete); err != nil {
		return nil, err
	}
	job.State = StateComplete
	job.RetirePriorKEKAllowed = true
	job.LastFailureCode = ""
	job.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := s.saveJobLocked(ctx, targetOwner, job, jobEntityVersion); err != nil {
		return nil, err
	}

	s.emitAudit(ctx, audit.EventKeyRotationCompleted, job.VaultID+"/"+job.ID, AuditDetails(req.OperatorIdent, job.VaultID, "rotation:complete", "success", map[string]any{
		"job_id":                   job.ID,
		"target_kek_id":            job.TargetKEKID,
		"target_kek_version":       job.TargetKEKVersion,
		"rewrapped_count":          len(job.Items),
		"retire_prior_kek_allowed": job.RetirePriorKEKAllowed,
	}))

	return job, nil
}

// initializePlannedJob inspects all target secret paths and records their current valid prior versions.
func (s *Service) initializePlannedJob(ctx context.Context, req StartOrResumeRequest, owner string) (*RotationJob, error) {
	items := make([]SecretRotationItem, 0, len(req.SecretPaths))
	seen := make(map[string]bool, len(req.SecretPaths))
	sourceKEK := strings.TrimSpace(req.SourceKEKID)

	for _, rawPath := range req.SecretPaths {
		cleanPath, err := auth.NormalizePath(rawPath)
		if err != nil {
			return nil, &contracts.ValidationError{Code: contracts.InvalidInput, Field: "secret_path"}
		}
		if seen[cleanPath] {
			continue
		}
		seen[cleanPath] = true

		if !isPathAuthorized(req.OperatorIdent, cleanPath) {
			return nil, &Error{Code: CodeScopeDenied, Message: "operator scope does not cover secret path"}
		}

		rec, err := s.store.Read(ctx, storage.ReadRequest{
			Owner: owner,
			Scope: req.VaultID,
			Name:  cleanPath,
		})
		if err != nil {
			return nil, err
		}
		meta, valErr := contracts.DecodeSecret(ctx, rec.Metadata)
		if valErr != nil {
			return nil, valErr
		}
		if sourceKEK == "" {
			sourceKEK = meta.Envelope.KEKID
		}

		items = append(items, SecretRotationItem{
			SecretID:            meta.SecretID,
			SecretPath:          cleanPath,
			Classification:      meta.Classification,
			PriorVersion:        meta.Version,
			PriorMetadataDigest: rec.MetadataDigest,
			PriorEnvelope:       meta.Envelope,
			TargetVersion:       meta.Version + 1,
			ActiveVersion:       meta.Version,
			Rewrapped:           false,
			Verified:            false,
		})
	}

	targetKEK := strings.TrimSpace(req.TargetKEKID)
	if targetKEK == "" {
		targetKEK = sourceKEK
	}
	if targetKEK == "" {
		return nil, &contracts.ValidationError{Code: contracts.InvalidInput, Field: "target_kek_id"}
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)
	return &RotationJob{
		SchemaVersion:         1,
		ID:                    strings.TrimSpace(req.JobID),
		VaultID:               strings.TrimSpace(req.VaultID),
		Owner:                 owner,
		SourceKEKID:           sourceKEK,
		TargetKEKID:           targetKEK,
		TargetKEKVersion:      strings.TrimSpace(req.TargetKEKVersion),
		State:                 StatePlanned,
		Items:                 items,
		RetirePriorKEKAllowed: false,
		CreatedAt:             now,
		UpdatedAt:             now,
	}, nil
}

// rewrapSingleItem rotates one secret from PriorVersion to TargetVersion without deleting PriorVersion.
func (s *Service) rewrapSingleItem(
	ctx context.Context,
	owner string,
	job *RotationJob,
	item *SecretRotationItem,
	jobEntityVersion *int64,
) error {
	// Check current committed metadata record in storage
	rec, err := s.store.Read(ctx, storage.ReadRequest{
		Owner: owner,
		Scope: job.VaultID,
		Name:  item.SecretPath,
	})
	if err != nil {
		return err
	}
	currentMeta, valErr := contracts.DecodeSecret(ctx, rec.Metadata)
	if valErr != nil {
		return valErr
	}

	// If storage already has TargetVersion committed from an earlier run before interruption,
	// recover idempotently without re-creating or overwriting versions.
	if currentMeta.Version == item.TargetVersion {
		item.ActiveVersion = item.TargetVersion
		item.Rewrapped = true
		item.PendingEnvelope = nil
		item.PendingCiphertext = ""
		item.PendingCreatedAt = ""
		savedVer, saveErr := s.saveJobLocked(ctx, owner, job, *jobEntityVersion)
		if saveErr != nil {
			return saveErr
		}
		*jobEntityVersion = savedVer
		return nil
	}

	if currentMeta.Version != item.PriorVersion {
		return &Error{
			Code:    CodeIntegrityFailure,
			Message: fmt.Sprintf("unexpected secret version %d during rotation (expected %d)", currentMeta.Version, item.PriorVersion),
		}
	}

	// Step 1: Prepare or reuse pending target envelope and ciphertext so an interruption
	// between provider PutSealedPayload and metadata store.Write can resume cleanly.
	var targetEnvelope contracts.Envelope
	var targetSealed []byte
	var targetCreatedAt string

	if item.PendingEnvelope != nil && item.PendingCiphertext != "" && item.PendingCreatedAt != "" {
		decodedSealed, decErr := hex.DecodeString(item.PendingCiphertext)
		if decErr != nil {
			return &Error{Code: CodeIntegrityFailure, Message: "corrupt pending ciphertext in checkpoint", Err: decErr}
		}
		targetEnvelope = *item.PendingEnvelope
		targetSealed = decodedSealed
		targetCreatedAt = item.PendingCreatedAt
	} else {
		// Read and authenticate the prior version from the provider; prior version stays untouched.
		priorDEK, unwrapErr := s.keyProvider.UnwrapDEK(ctx, item.PriorEnvelope.KEKID, item.PriorEnvelope.WrappedDEK)
		if unwrapErr != nil {
			return unwrapErr
		}
		defer wipeBytes(priorDEK)

		priorSealed, readErr := s.keyProvider.ReadSealedPayload(ctx, provider.SealedRef{
			VaultID: job.VaultID,
			Path:    item.SecretPath,
			Version: item.PriorVersion,
		})
		if readErr != nil {
			return readErr
		}

		plaintext, decErr := openAuthenticatedPayload(priorDEK, item.PriorEnvelope, priorSealed, item.SecretPath)
		if decErr != nil {
			return decErr
		}
		defer wipeBytes(plaintext)

		// Generate a fresh 256-bit DEK and wrap under TargetKEKID
		newDEK := make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, newDEK); err != nil {
			return fmt.Errorf("generate rotated DEK: %w", err)
		}
		defer wipeBytes(newDEK)

		wrapRes, wrapErr := s.keyProvider.WrapDEK(ctx, job.TargetKEKID, newDEK)
		if wrapErr != nil {
			return wrapErr
		}
		if wrapRes == nil || wrapRes.Ciphertext == "" {
			return &provider.Error{Code: provider.CodeProviderUnavailable, Message: "empty wrap response during rotation"}
		}

		newSealed, nonceHex, tagHex, sealErr := sealPayload(newDEK, plaintext, item.SecretPath)
		if sealErr != nil {
			return sealErr
		}

		targetEnvelope = contracts.Envelope{
			Algorithm:  "AES-256-GCM",
			WrappedDEK: wrapRes.Ciphertext,
			Nonce:      nonceHex,
			Tag:        tagHex,
			KEKID:      job.TargetKEKID,
		}
		targetSealed = newSealed
		targetCreatedAt = time.Now().UTC().Format(time.RFC3339)

		// Checkpoint pending envelope before writing to provider so resume is idempotent
		envCopy := targetEnvelope
		item.PendingEnvelope = &envCopy
		item.PendingCreatedAt = targetCreatedAt
		item.PendingCiphertext = hex.EncodeToString(targetSealed)
		job.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
		savedVer, saveErr := s.saveJobLocked(ctx, owner, job, *jobEntityVersion)
		if saveErr != nil {
			return saveErr
		}
		*jobEntityVersion = savedVer
	}

	// Step 2: Store target version sealed payload in provider (v<TargetVersion>).
	// Note: v<PriorVersion> in provider KV v2 is never deleted or overwritten!
	putErr := s.keyProvider.PutSealedPayload(ctx, provider.SealedRef{
		VaultID: job.VaultID,
		Path:    item.SecretPath,
		Version: item.TargetVersion,
	}, targetSealed)
	if putErr != nil && !provider.IsErrorCode(putErr, provider.CodePayloadConflict) {
		return putErr
	}

	// Step 3: Commit new SecretMetadata (Version = TargetVersion) to storage with CAS on PriorVersion.
	newMetadata := contracts.SecretMetadata{
		SchemaVersion:  contracts.SchemaVersion,
		VaultID:        job.VaultID,
		SecretID:       item.SecretID,
		SecretPath:     item.SecretPath,
		Version:        item.TargetVersion,
		Classification: item.Classification,
		CreatedAt:      targetCreatedAt,
		Envelope:       targetEnvelope,
	}
	metaBytes, err := json.Marshal(newMetadata)
	if err != nil {
		return fmt.Errorf("marshal rotated metadata: %w", err)
	}

	opID := deterministicOpID("rot-meta", job.ID, item.SecretPath, item.TargetVersion)
	_, err = s.store.Write(ctx, storage.WriteRequest{
		OperationID:     opID,
		Owner:           owner,
		Scope:           job.VaultID,
		Name:            item.SecretPath,
		ExpectedVersion: item.PriorVersion,
		Metadata:        metaBytes,
	})
	if err != nil {
		return err
	}

	// Step 4: Mark item rewrapped & verified and clear transient pending ciphertext
	item.ActiveVersion = item.TargetVersion
	item.Rewrapped = true
	item.Verified = true
	item.PendingEnvelope = nil
	item.PendingCiphertext = ""
	item.PendingCreatedAt = ""
	job.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)

	savedVer, err := s.saveJobLocked(ctx, owner, job, *jobEntityVersion)
	if err != nil {
		return err
	}
	*jobEntityVersion = savedVer
	return nil
}

// verifyItemAndPriorPreserved confirms that:
// 1. The prior secret version sealed bytes still exist intact in the provider (Requirement F12).
// 2. The new target secret version metadata and provider sealed bytes are valid and bound to TargetKEKID.
func (s *Service) verifyItemAndPriorPreserved(
	ctx context.Context,
	owner, vaultID, targetKEKID string,
	item *SecretRotationItem,
) error {
	// 1. Prior version sealed payload MUST still exist in provider (not deleted!)
	priorSealed, err := s.keyProvider.ReadSealedPayload(ctx, provider.SealedRef{
		VaultID: vaultID,
		Path:    item.SecretPath,
		Version: item.PriorVersion,
	})
	if err != nil || len(priorSealed) == 0 {
		return &Error{
			Code:    CodeIntegrityFailure,
			Message: fmt.Sprintf("prior secret version %d missing in provider for %s", item.PriorVersion, item.SecretPath),
			Err:     err,
		}
	}

	// 2. Target version sealed payload must exist in provider
	targetSealed, err := s.keyProvider.ReadSealedPayload(ctx, provider.SealedRef{
		VaultID: vaultID,
		Path:    item.SecretPath,
		Version: item.TargetVersion,
	})
	if err != nil || len(targetSealed) == 0 {
		return &Error{
			Code:    CodeIntegrityFailure,
			Message: fmt.Sprintf("target secret version %d missing in provider for %s", item.TargetVersion, item.SecretPath),
			Err:     err,
		}
	}

	// 3. Committed metadata in storage must be at TargetVersion and bound to TargetKEKID
	rec, err := s.store.Read(ctx, storage.ReadRequest{
		Owner: owner,
		Scope: vaultID,
		Name:  item.SecretPath,
	})
	if err != nil {
		return err
	}
	meta, valErr := contracts.DecodeSecret(ctx, rec.Metadata)
	if valErr != nil {
		return valErr
	}
	if meta.Version != item.TargetVersion || meta.Envelope.KEKID != targetKEKID {
		return &Error{
			Code:    CodeIntegrityFailure,
			Message: fmt.Sprintf("committed metadata for %s does not match target rotation state", item.SecretPath),
		}
	}
	return nil
}

// GetJob loads a durable rotation job from storage.
func (s *Service) GetJob(ctx context.Context, owner, vaultID, jobID string) (*RotationJob, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if s.store == nil {
		return nil, &Error{Code: CodeInvalidInput, Message: "storage port is required"}
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	job, _, err := s.loadJobLocked(ctx, owner, jobID)
	if err != nil {
		return nil, err
	}
	if job == nil || job.VaultID != vaultID {
		return nil, &Error{Code: CodeRotationNotFound, Message: "rotation job not found"}
	}
	return job, nil
}

// CanRetirePriorKEK enforces frozen v1 invariant 4:
// Retiring a KEK is forbidden until all live envelopes in the rotation job are verified rewrapped.
func (s *Service) CanRetirePriorKEK(ctx context.Context, owner, vaultID, jobID string) (bool, error) {
	job, err := s.GetJob(ctx, owner, vaultID, jobID)
	if err != nil {
		return false, err
	}
	if job.State != StateComplete || !job.RetirePriorKEKAllowed {
		return false, &Error{
			Code:    CodeRotationIncomplete,
			Message: "cannot retire prior KEK while rotation job is incomplete",
		}
	}
	for _, item := range job.Items {
		if !item.Rewrapped || !item.Verified {
			return false, &Error{
				Code:    CodeRotationIncomplete,
				Message: fmt.Sprintf("secret %s has not completed envelope rewrap verification", item.SecretPath),
			}
		}
	}
	return true, nil
}

func (s *Service) loadJobLocked(ctx context.Context, owner, jobID string) (*RotationJob, int64, error) {
	rec, err := s.store.Read(ctx, storage.ReadRequest{
		Owner: owner,
		Scope: rotationStorageScope,
		Name:  jobID,
	})
	if err != nil {
		var stErr *storage.Error
		if errors.As(err, &stErr) && stErr.Code == storage.CodeNotFound {
			return nil, 0, nil
		}
		return nil, 0, err
	}
	var job RotationJob
	if err := json.Unmarshal(rec.Metadata, &job); err != nil {
		return nil, 0, &Error{Code: CodeIntegrityFailure, Message: "corrupt rotation job record", Err: err}
	}
	return &job, rec.EntityVersion, nil
}

func (s *Service) saveJobLocked(ctx context.Context, owner string, job *RotationJob, expectedVersion int64) (int64, error) {
	data, err := json.Marshal(job)
	if err != nil {
		return 0, fmt.Errorf("marshal rotation job: %w", err)
	}
	opID := deterministicOpID("rot-job", job.ID, string(job.State), expectedVersion+1, time.Now().UnixNano())
	res, err := s.store.Write(ctx, storage.WriteRequest{
		OperationID:     opID,
		Owner:           owner,
		Scope:           rotationStorageScope,
		Name:            job.ID,
		ExpectedVersion: expectedVersion,
		Metadata:        data,
	})
	if err != nil {
		return 0, err
	}
	return res.EntityVersion, nil
}

func (s *Service) emitAudit(ctx context.Context, eventType, subject string, data audit.AuditData) {
	if s.recorder == nil {
		return
	}
	evt, err := audit.NewEvent(eventType, subject, data)
	if err == nil {
		_ = s.recorder.Record(ctx, evt)
	}
}

// AuditDetails builds secret-free AuditData for rotation lifecycle events.
func AuditDetails(ident *auth.Identity, vaultID, action, outcome string, details map[string]any) audit.AuditData {
	return audit.AuditData{
		Actor:   actorID(ident),
		VaultID: vaultID,
		Action:  action,
		Outcome: outcome,
		Details: details,
	}
}

func actorID(ident *auth.Identity) string {
	if ident == nil {
		return "unknown"
	}
	if ident.Email != "" {
		return ident.Email
	}
	if ident.Subject != "" {
		return ident.Subject
	}
	return "unknown"
}

func openAuthenticatedPayload(dek []byte, env contracts.Envelope, sealed []byte, canonicalPath string) ([]byte, error) {
	nonce, err := hex.DecodeString(env.Nonce)
	if err != nil {
		return nil, &Error{Code: CodeIntegrityFailure, Message: "invalid prior envelope nonce"}
	}
	tag, err := hex.DecodeString(env.Tag)
	if err != nil {
		return nil, &Error{Code: CodeIntegrityFailure, Message: "invalid prior envelope tag"}
	}
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, &Error{Code: CodeIntegrityFailure, Message: "invalid DEK length", Err: err}
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, &Error{Code: CodeIntegrityFailure, Message: "failed to initialize GCM", Err: err}
	}
	if len(nonce) != gcm.NonceSize() || len(sealed) < gcm.Overhead() {
		return nil, &Error{Code: CodeIntegrityFailure, Message: "sealed payload does not match prior envelope"}
	}
	storedTag := sealed[len(sealed)-gcm.Overhead():]
	if subtle.ConstantTimeCompare(storedTag, tag) != 1 {
		return nil, &Error{Code: CodeIntegrityFailure, Message: "prior payload authentication tag mismatch"}
	}
	plaintext, err := gcm.Open(nil, nonce, sealed, []byte(canonicalPath))
	if err != nil {
		return nil, &Error{Code: CodeIntegrityFailure, Message: "prior payload decryption failed", Err: err}
	}
	return plaintext, nil
}

func sealPayload(dek, plaintext []byte, canonicalPath string) ([]byte, string, string, error) {
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, "", "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, "", "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, "", "", err
	}
	sealed := gcm.Seal(nil, nonce, plaintext, []byte(canonicalPath))
	tag := sealed[len(sealed)-gcm.Overhead():]
	return sealed, hex.EncodeToString(nonce), hex.EncodeToString(tag), nil
}

func deterministicOpID(prefix, id, part string, seq ...int64) string {
	h := sha256.New()
	h.Write([]byte(prefix + ":" + id + ":" + part))
	for _, n := range seq {
		h.Write([]byte(fmt.Sprintf(":%d", n)))
	}
	return prefix + "-" + hex.EncodeToString(h.Sum(nil))[:16]
}

func extractErrorCode(err error) string {
	var rotErr *Error
	if errors.As(err, &rotErr) {
		return rotErr.Code
	}
	var provErr *provider.Error
	if errors.As(err, &provErr) {
		return string(provErr.Code)
	}
	var stErr *storage.Error
	if errors.As(err, &stErr) {
		return string(stErr.Code)
	}
	var valErr *contracts.ValidationError
	if errors.As(err, &valErr) {
		return string(valErr.Code)
	}
	return "ROTATION_ERROR"
}

func isOwnerAuthorized(identity *auth.Identity, targetOwner string) bool {
	if identity == nil {
		return false
	}
	if identity.Email != "" && subtle.ConstantTimeCompare([]byte(identity.Email), []byte(targetOwner)) == 1 {
		return true
	}
	if identity.Subject != "" && subtle.ConstantTimeCompare([]byte(identity.Subject), []byte(targetOwner)) == 1 {
		return true
	}
	for _, allowed := range identity.AllowedOwners {
		if subtle.ConstantTimeCompare([]byte(allowed), []byte(targetOwner)) == 1 {
			return true
		}
	}
	return false
}

func isPathAuthorized(identity *auth.Identity, canonicalPath string) bool {
	if identity == nil {
		return false
	}
	hasPathRestrictions := false
	pathMatched := false
	for _, sc := range identity.AllowedScopes {
		if strings.Contains(sc, "/") {
			hasPathRestrictions = true
			if auth.MatchPathScope(sc, canonicalPath) {
				pathMatched = true
				break
			}
		}
	}
	if hasPathRestrictions && !pathMatched {
		return false
	}
	return true
}

func wipeBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
