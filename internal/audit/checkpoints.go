// Package audit provides attributable metadata audit event emission, recording,
// and separately stored audit checkpoint verification (Requirement F19).
//
// Invariants:
//  1. Signature trust policy and unavailable checkpoint status are explicit.
//  2. A local hash chain alone is not immutable without an anchored, signed checkpoint.
//  3. An expired, stale or replayed revision cannot replace the last valid accepted authority.
//  4. Checkpoints, events, and verification results contain zero plaintext secrets or bearer tokens.
package audit

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/parsa-emami/keyhelix/internal/security"
)

// VerificationStatus represents the explicit, typed outcome of an audit checkpoint verification.
type VerificationStatus string

const (
	// StatusTrusted indicates the checkpoint signature is valid, signer is trusted,
	// sequence advances monotonically, and log root matches the event chain.
	StatusTrusted VerificationStatus = "TRUSTED"

	// StatusUnavailable indicates the separately stored checkpoint was not found
	// or the checkpoint store/sink was unreachable.
	StatusUnavailable VerificationStatus = "UNAVAILABLE"

	// StatusUntrustedSigner indicates the checkpoint was signed by a key not in the trust policy.
	StatusUntrustedSigner VerificationStatus = "UNTRUSTED_SIGNER"

	// StatusInvalidSignature indicates the cryptographic signature failed verification.
	StatusInvalidSignature VerificationStatus = "INVALID_SIGNATURE"

	// StatusTamperedLog indicates the audit events do not match the checkpoint's log root.
	StatusTamperedLog VerificationStatus = "TAMPERED_LOG"

	// StatusStaleRevision indicates the checkpoint sequence is older than the current accepted authority.
	StatusStaleRevision VerificationStatus = "STALE_REVISION"

	// StatusReplayRejected indicates a replayed checkpoint sequence or a divergent history fork.
	StatusReplayRejected VerificationStatus = "REPLAY_REJECTED"

	// StatusExpired indicates the checkpoint timestamp exceeds the policy maximum age.
	StatusExpired VerificationStatus = "EXPIRED"

	// StatusMalformed indicates required checkpoint fields are missing, invalid, or corrupt.
	StatusMalformed VerificationStatus = "MALFORMED"

	// StatusUnanchoredChain indicates a local hash chain without an authorized external checkpoint.
	// Requirement F19: hash chain alone is not immutable.
	StatusUnanchoredChain VerificationStatus = "UNANCHORED_CHAIN"
)

// Standard algorithm names.
const (
	AlgorithmEd25519 = "ed25519"
)

// Sentinel root seed for the very first checkpoint.
const InitialSeedZero = "0000000000000000000000000000000000000000000000000000000000000000"

// AuditCheckpoint represents a cryptographically signed statement over a slice of audit events
// stored independently from the primary engine metadata (Requirement F19).
type AuditCheckpoint struct {
	ID                     string `json:"id"`
	Sequence               int64  `json:"sequence"`
	EventCount             int64  `json:"event_count"`
	FirstEventID           string `json:"first_event_id"`
	LastEventID            string `json:"last_event_id"`
	LogRootHash            string `json:"log_root_hash"`
	PreviousCheckpointID   string `json:"previous_checkpoint_id,omitempty"`
	PreviousCheckpointHash string `json:"previous_checkpoint_hash,omitempty"`
	Timestamp              string `json:"timestamp"`
	SignerID               string `json:"signer_id"`
	Algorithm              string `json:"algorithm"`
	Signature              string `json:"signature"`
}

// CanonicalSigningBytes produces a deterministic, canonical byte slice over the authoritative fields
// of an AuditCheckpoint. Any change to any field alters the signed payload.
func CanonicalSigningBytes(cp *AuditCheckpoint) []byte {
	canonical := fmt.Sprintf(
		"keyhelix-checkpoint-v1:%s:%d:%d:%s:%s:%s:%s:%s:%s:%s:%s",
		cp.ID,
		cp.Sequence,
		cp.EventCount,
		cp.FirstEventID,
		cp.LastEventID,
		cp.LogRootHash,
		cp.PreviousCheckpointID,
		cp.PreviousCheckpointHash,
		cp.Timestamp,
		cp.SignerID,
		cp.Algorithm,
	)
	return []byte(canonical)
}

// Digest computes the SHA-256 hex digest of the canonical checkpoint payload.
func (cp *AuditCheckpoint) Digest() string {
	sum := sha256.Sum256(CanonicalSigningBytes(cp))
	return hex.EncodeToString(sum[:])
}

// ComputeEventDigest computes a deterministic SHA-256 digest of an audit EventEnvelope.
func ComputeEventDigest(evt EventEnvelope) string {
	dataBytes, _ := json.Marshal(evt.Data)
	canonical := fmt.Sprintf(
		"id=%s;spec=%s;type=%s;src=%s;sub=%s;time=%s;data=%s",
		evt.ID,
		evt.SpecVersion,
		evt.Type,
		evt.Source,
		evt.Subject,
		evt.Time,
		string(dataBytes),
	)
	h := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(h[:])
}

// ComputeLogRoot calculates the cumulative chained hash over an ordered sequence of events.
// Cumulative rule: H_i = SHA256(H_{i-1} || ":" || index || ":" || digest(event_i))
func ComputeLogRoot(events []EventEnvelope, initialSeed string) (string, error) {
	if len(events) == 0 {
		return "", errors.New("cannot compute log root for empty event sequence")
	}
	if initialSeed == "" {
		initialSeed = InitialSeedZero
	}
	current := initialSeed
	for i, evt := range events {
		digest := ComputeEventDigest(evt)
		combined := fmt.Sprintf("%s:%d:%s", current, i, digest)
		h := sha256.Sum256([]byte(combined))
		current = hex.EncodeToString(h[:])
	}
	return current, nil
}

// Signer signs canonical checkpoint payloads.
type Signer interface {
	SignerID() string
	Algorithm() string
	Sign(payload []byte) (string, error)
	PublicKey() ed25519.PublicKey
}

// Ed25519Signer implements Signer using an ed25519 private key.
type Ed25519Signer struct {
	signerID string
	privKey  ed25519.PrivateKey
}

// NewEd25519Signer constructs a new Ed25519Signer.
func NewEd25519Signer(signerID string, privKey ed25519.PrivateKey) (*Ed25519Signer, error) {
	if strings.TrimSpace(signerID) == "" {
		return nil, errors.New("signer ID is required")
	}
	if len(privKey) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid ed25519 private key size")
	}
	return &Ed25519Signer{
		signerID: signerID,
		privKey:  privKey,
	}, nil
}

func (s *Ed25519Signer) SignerID() string { return s.signerID }
func (s *Ed25519Signer) Algorithm() string { return AlgorithmEd25519 }

func (s *Ed25519Signer) Sign(payload []byte) (string, error) {
	sig := ed25519.Sign(s.privKey, payload)
	return base64.StdEncoding.EncodeToString(sig), nil
}

func (s *Ed25519Signer) PublicKey() ed25519.PublicKey {
	return s.privKey.Public().(ed25519.PublicKey)
}

// NewCheckpoint constructs and signs a new AuditCheckpoint over a slice of events.
func NewCheckpoint(
	id string,
	sequence int64,
	events []EventEnvelope,
	prev *AuditCheckpoint,
	signer Signer,
) (*AuditCheckpoint, error) {
	if strings.TrimSpace(id) == "" {
		return nil, errors.New("checkpoint ID is required")
	}
	if sequence <= 0 {
		return nil, errors.New("checkpoint sequence must be >= 1")
	}
	if len(events) == 0 {
		return nil, errors.New("events cannot be empty")
	}
	if signer == nil {
		return nil, errors.New("signer is required")
	}

	var prevID, prevHash, initialSeed string
	var totalCount int64

	if prev != nil {
		if sequence <= prev.Sequence {
			return nil, fmt.Errorf("new sequence (%d) must exceed previous sequence (%d)", sequence, prev.Sequence)
		}
		prevID = prev.ID
		prevHash = prev.Digest()
		initialSeed = prev.LogRootHash
		totalCount = prev.EventCount + int64(len(events))
	} else {
		prevID = ""
		prevHash = ""
		initialSeed = InitialSeedZero
		totalCount = int64(len(events))
	}

	rootHash, err := ComputeLogRoot(events, initialSeed)
	if err != nil {
		return nil, fmt.Errorf("failed to compute log root: %w", err)
	}

	cp := &AuditCheckpoint{
		ID:                     id,
		Sequence:               sequence,
		EventCount:             totalCount,
		FirstEventID:           events[0].ID,
		LastEventID:            events[len(events)-1].ID,
		LogRootHash:            rootHash,
		PreviousCheckpointID:   prevID,
		PreviousCheckpointHash: prevHash,
		Timestamp:              time.Now().UTC().Format(time.RFC3339Nano),
		SignerID:               signer.SignerID(),
		Algorithm:              signer.Algorithm(),
	}

	sig, err := signer.Sign(CanonicalSigningBytes(cp))
	if err != nil {
		return nil, fmt.Errorf("signing checkpoint failed: %w", err)
	}
	cp.Signature = sig

	return cp, nil
}

// TrustPolicy defines explicit cryptographic validation parameters for audit checkpoints (Requirement F19).
type TrustPolicy struct {
	// TrustedSigners maps SignerID -> ed25519.PublicKey
	TrustedSigners map[string]ed25519.PublicKey `json:"trusted_signers"`

	// AllowedAlgorithms specifies allowed algorithms (e.g. ["ed25519"])
	AllowedAlgorithms []string `json:"allowed_algorithms"`

	// MaxAge specifies maximum permissible age before a checkpoint is considered expired (0 disables check)
	MaxAge time.Duration `json:"max_age"`

	// ClockTolerance allows bounded skew for future timestamps (default 5m)
	ClockTolerance time.Duration `json:"clock_tolerance"`

	// MinSequence sets the floor for accepted sequences
	MinSequence int64 `json:"min_sequence"`
}

// Validate ensures the TrustPolicy itself is well-formed.
func (p TrustPolicy) Validate() error {
	if len(p.TrustedSigners) == 0 {
		return errors.New("trust policy must specify at least one trusted signer")
	}
	if len(p.AllowedAlgorithms) == 0 {
		return errors.New("trust policy must specify allowed algorithms")
	}
	for id, pub := range p.TrustedSigners {
		if strings.TrimSpace(id) == "" {
			return errors.New("trusted signer ID cannot be empty")
		}
		if len(pub) != ed25519.PublicKeySize {
			return fmt.Errorf("invalid ed25519 public key size for signer %s", id)
		}
	}
	return nil
}

// AuthorityRecord tracks the highest accepted valid checkpoint state.
type AuthorityRecord struct {
	CheckpointID string `json:"checkpoint_id"`
	Sequence     int64  `json:"sequence"`
	LogRootHash  string `json:"log_root_hash"`
	AcceptedAt   string `json:"accepted_at"`
	SignerID     string `json:"signer_id"`
}

// VerificationResult carries the explicit typed result of verifying an audit log against a checkpoint.
type VerificationResult struct {
	Status            VerificationStatus `json:"status"`
	Trusted           bool               `json:"trusted"`
	Message           string             `json:"message"`
	CheckpointID      string             `json:"checkpoint_id,omitempty"`
	Sequence          int64              `json:"sequence,omitempty"`
	EventCount        int64              `json:"event_count,omitempty"`
	SignerID          string             `json:"signer_id,omitempty"`
	ComputedLogRoot   string             `json:"computed_log_root,omitempty"`
	CheckpointLogRoot string             `json:"checkpoint_log_root,omitempty"`
	VerifiedAt        string             `json:"verified_at"`
	AcceptedAuthority *AuthorityRecord   `json:"accepted_authority,omitempty"`
}

// CheckpointStore errors.
var (
	ErrCheckpointNotFound = errors.New("checkpoint not found")
	ErrStoreUnavailable   = errors.New("checkpoint store is unavailable")
)

// CheckpointStore provides access to separately stored audit checkpoints.
type CheckpointStore interface {
	GetCheckpoint(ctx context.Context, id string) (*AuditCheckpoint, error)
	GetLatestCheckpoint(ctx context.Context) (*AuditCheckpoint, error)
	SaveCheckpoint(ctx context.Context, cp *AuditCheckpoint) error
}

// InMemoryCheckpointStore is a thread-safe in-memory implementation of CheckpointStore.
type InMemoryCheckpointStore struct {
	mu          sync.RWMutex
	checkpoints map[string]*AuditCheckpoint
	latestID    string
	highestSeq  int64
}

// NewInMemoryCheckpointStore creates a new in-memory store.
func NewInMemoryCheckpointStore() *InMemoryCheckpointStore {
	return &InMemoryCheckpointStore{
		checkpoints: make(map[string]*AuditCheckpoint),
	}
}

func (s *InMemoryCheckpointStore) SaveCheckpoint(_ context.Context, cp *AuditCheckpoint) error {
	if cp == nil || cp.ID == "" {
		return errors.New("invalid checkpoint")
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	cpCopy := *cp
	s.checkpoints[cp.ID] = &cpCopy
	if cp.Sequence > s.highestSeq {
		s.highestSeq = cp.Sequence
		s.latestID = cp.ID
	}
	return nil
}

func (s *InMemoryCheckpointStore) GetCheckpoint(_ context.Context, id string) (*AuditCheckpoint, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cp, ok := s.checkpoints[id]
	if !ok {
		return nil, ErrCheckpointNotFound
	}
	cpCopy := *cp
	return &cpCopy, nil
}

func (s *InMemoryCheckpointStore) GetLatestCheckpoint(_ context.Context) (*AuditCheckpoint, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.latestID == "" {
		return nil, ErrCheckpointNotFound
	}
	cp := s.checkpoints[s.latestID]
	cpCopy := *cp
	return &cpCopy, nil
}

// DirectoryCheckpointStore is a file-backed separately stored checkpoint sink.
type DirectoryCheckpointStore struct {
	mu  sync.RWMutex
	dir string
}

// NewDirectoryCheckpointStore creates a file-backed store at the given directory.
func NewDirectoryCheckpointStore(dir string) (*DirectoryCheckpointStore, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create checkpoint directory: %w", err)
	}
	return &DirectoryCheckpointStore{dir: dir}, nil
}

func (s *DirectoryCheckpointStore) SaveCheckpoint(_ context.Context, cp *AuditCheckpoint) error {
	if cp == nil || cp.ID == "" {
		return errors.New("invalid checkpoint")
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := json.MarshalIndent(cp, "", "  ")
	if err != nil {
		return err
	}
	filePath := filepath.Join(s.dir, fmt.Sprintf("%s.json", cp.ID))
	tmpPath := filePath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, filePath); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	latestPointer := filepath.Join(s.dir, "latest.id")
	_ = os.WriteFile(latestPointer, []byte(cp.ID), 0600)
	return nil
}

func (s *DirectoryCheckpointStore) GetCheckpoint(_ context.Context, id string) (*AuditCheckpoint, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	filePath := filepath.Join(s.dir, fmt.Sprintf("%s.json", id))
	data, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrCheckpointNotFound
		}
		return nil, fmt.Errorf("%w: %v", ErrStoreUnavailable, err)
	}
	var cp AuditCheckpoint
	if err := json.Unmarshal(data, &cp); err != nil {
		return nil, fmt.Errorf("corrupt checkpoint file: %w", err)
	}
	return &cp, nil
}

func (s *DirectoryCheckpointStore) GetLatestCheckpoint(ctx context.Context) (*AuditCheckpoint, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	latestPointer := filepath.Join(s.dir, "latest.id")
	idBytes, err := os.ReadFile(latestPointer)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrCheckpointNotFound
		}
		return nil, fmt.Errorf("%w: %v", ErrStoreUnavailable, err)
	}
	id := strings.TrimSpace(string(idBytes))
	return s.GetCheckpoint(ctx, id)
}

// FailingCheckpointStore is a mock/drill store used to simulate unavailable checkpoint sinks.
type FailingCheckpointStore struct {
	Err error
}

func (f *FailingCheckpointStore) GetCheckpoint(_ context.Context, _ string) (*AuditCheckpoint, error) {
	if f.Err != nil {
		return nil, f.Err
	}
	return nil, ErrStoreUnavailable
}

func (f *FailingCheckpointStore) GetLatestCheckpoint(_ context.Context) (*AuditCheckpoint, error) {
	if f.Err != nil {
		return nil, f.Err
	}
	return nil, ErrStoreUnavailable
}

func (f *FailingCheckpointStore) SaveCheckpoint(_ context.Context, _ *AuditCheckpoint) error {
	if f.Err != nil {
		return f.Err
	}
	return ErrStoreUnavailable
}

// Verifier executes signature trust policy evaluation and log integrity verification.
type Verifier struct {
	policy            TrustPolicy
	store             CheckpointStore
	acceptedAuthority *AuthorityRecord
	mu                sync.RWMutex
}

// NewVerifier creates a new Verifier with the specified policy and store.
func NewVerifier(policy TrustPolicy, store CheckpointStore) (*Verifier, error) {
	if err := policy.Validate(); err != nil {
		return nil, fmt.Errorf("invalid trust policy: %w", err)
	}
	if store == nil {
		return nil, errors.New("checkpoint store is required")
	}
	if policy.ClockTolerance <= 0 {
		policy.ClockTolerance = 5 * time.Minute
	}
	return &Verifier{
		policy: policy,
		store:  store,
	}, nil
}

// CurrentAuthority returns a copy of the current accepted authority record.
func (v *Verifier) CurrentAuthority() *AuthorityRecord {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.acceptedAuthority == nil {
		return nil
	}
	cp := *v.acceptedAuthority
	return &cp
}

// AcceptAuthority updates the accepted authority state upon a verified result.
func (v *Verifier) AcceptAuthority(res VerificationResult) error {
	if !res.Trusted || res.Status != StatusTrusted {
		return fmt.Errorf("cannot accept untrusted verification result: status %s", res.Status)
	}
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.acceptedAuthority != nil && res.Sequence <= v.acceptedAuthority.Sequence {
		return fmt.Errorf("cannot accept stale or replayed sequence %d (current: %d)", res.Sequence, v.acceptedAuthority.Sequence)
	}

	v.acceptedAuthority = &AuthorityRecord{
		CheckpointID: res.CheckpointID,
		Sequence:     res.Sequence,
		LogRootHash:  res.CheckpointLogRoot,
		AcceptedAt:   time.Now().UTC().Format(time.RFC3339Nano),
		SignerID:     res.SignerID,
	}
	return nil
}

// VerifyLogAgainstCheckpoint fetches the specified checkpoint from the separate store
// and validates it against the trust policy, authority monotonicity, and the provided events.
func (v *Verifier) VerifyLogAgainstCheckpoint(
	ctx context.Context,
	checkpointID string,
	events []EventEnvelope,
	initialSeed string,
) VerificationResult {
	now := time.Now().UTC()
	result := VerificationResult{
		CheckpointID: checkpointID,
		VerifiedAt:   now.Format(time.RFC3339Nano),
	}

	if strings.TrimSpace(checkpointID) == "" {
		result.Status = StatusMalformed
		result.Message = "checkpoint id is empty"
		return result
	}

	// 1. Fetch from separate sink
	cp, err := v.store.GetCheckpoint(ctx, checkpointID)
	if err != nil {
		result.Status = StatusUnavailable
		result.Message = fmt.Sprintf("checkpoint %s is unavailable: %v", checkpointID, err)
		return result
	}

	return v.verifyCheckpointPayload(cp, events, initialSeed, now)
}

// VerifyLatest verifies against the latest checkpoint published to the separate sink.
func (v *Verifier) VerifyLatest(
	ctx context.Context,
	events []EventEnvelope,
	initialSeed string,
) VerificationResult {
	now := time.Now().UTC()
	result := VerificationResult{
		VerifiedAt: now.Format(time.RFC3339Nano),
	}

	cp, err := v.store.GetLatestCheckpoint(ctx)
	if err != nil {
		result.Status = StatusUnavailable
		result.Message = fmt.Sprintf("latest checkpoint is unavailable: %v", err)
		return result
	}

	result.CheckpointID = cp.ID
	return v.verifyCheckpointPayload(cp, events, initialSeed, now)
}

// VerifyUnanchored evaluates an audit log without a checkpoint.
// Requirement F19: "hash chain alone is not immutable".
// Unanchored verification explicitly refuses to grant TRUSTED status.
func (v *Verifier) VerifyUnanchored(events []EventEnvelope) VerificationResult {
	now := time.Now().UTC()
	result := VerificationResult{
		Status:     StatusUnanchoredChain,
		Trusted:    false,
		VerifiedAt: now.Format(time.RFC3339Nano),
		EventCount: int64(len(events)),
		Message:    "hash chain alone is not immutable: verification requires an authorized signed checkpoint stored in a separate sink",
	}

	if len(events) > 0 {
		root, err := ComputeLogRoot(events, InitialSeedZero)
		if err == nil {
			result.ComputedLogRoot = root
		}
	}
	return result
}

// verifyCheckpointPayload evaluates trust policy, signatures, and log hashes against a loaded checkpoint.
func (v *Verifier) verifyCheckpointPayload(
	cp *AuditCheckpoint,
	events []EventEnvelope,
	initialSeed string,
	now time.Time,
) VerificationResult {
	result := VerificationResult{
		CheckpointID:      cp.ID,
		Sequence:          cp.Sequence,
		EventCount:        cp.EventCount,
		SignerID:          cp.SignerID,
		CheckpointLogRoot: cp.LogRootHash,
		VerifiedAt:        now.Format(time.RFC3339Nano),
	}

	// A. Validate structural integrity
	if cp.ID == "" || cp.Sequence <= 0 || cp.LogRootHash == "" || cp.SignerID == "" || cp.Signature == "" {
		result.Status = StatusMalformed
		result.Message = "checkpoint contains missing or empty required fields"
		return result
	}

	// B. Validate algorithm against policy
	algoAllowed := false
	for _, allowed := range v.policy.AllowedAlgorithms {
		if cp.Algorithm == allowed {
			algoAllowed = true
			break
		}
	}
	if !algoAllowed {
		result.Status = StatusUntrustedSigner
		result.Message = fmt.Sprintf("algorithm %s not allowed by trust policy", cp.Algorithm)
		return result
	}

	// C. Validate signer identity against trust policy
	pubKey, ok := v.policy.TrustedSigners[cp.SignerID]
	if !ok || len(pubKey) != ed25519.PublicKeySize {
		result.Status = StatusUntrustedSigner
		result.Message = fmt.Sprintf("signer %s is not recognized by trust policy", cp.SignerID)
		return result
	}

	// D. Verify cryptographic signature over canonical payload
	sigBytes, err := base64.StdEncoding.DecodeString(cp.Signature)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		result.Status = StatusInvalidSignature
		result.Message = "signature byte decoding failed or invalid signature size"
		return result
	}

	canonicalBytes := CanonicalSigningBytes(cp)
	if !ed25519.Verify(pubKey, canonicalBytes, sigBytes) {
		result.Status = StatusInvalidSignature
		result.Message = "cryptographic signature verification failed (payload altered or wrong key)"
		return result
	}

	// E. Check timestamp bounds (expiration & clock skew)
	ts, err := time.Parse(time.RFC3339Nano, cp.Timestamp)
	if err != nil {
		ts, err = time.Parse(time.RFC3339, cp.Timestamp)
	}
	if err != nil {
		result.Status = StatusMalformed
		result.Message = fmt.Sprintf("invalid timestamp format: %v", err)
		return result
	}

	if ts.After(now.Add(v.policy.ClockTolerance)) {
		result.Status = StatusInvalidSignature
		result.Message = "checkpoint timestamp is in the future beyond allowed clock tolerance"
		return result
	}

	if v.policy.MaxAge > 0 && now.Sub(ts) > v.policy.MaxAge {
		result.Status = StatusExpired
		result.Message = fmt.Sprintf("checkpoint expired (age %v exceeds max_age %v)", now.Sub(ts), v.policy.MaxAge)
		return result
	}

	// F. Verify audit events log root against checkpoint LogRootHash
	computedRoot, err := ComputeLogRoot(events, initialSeed)
	if err != nil {
		result.Status = StatusTamperedLog
		result.Message = fmt.Sprintf("log root calculation failed: %v", err)
		return result
	}
	result.ComputedLogRoot = computedRoot

	if computedRoot != cp.LogRootHash {
		result.Status = StatusTamperedLog
		result.Message = fmt.Sprintf("computed log root (%s) does not match checkpoint log root (%s)", computedRoot, cp.LogRootHash)
		return result
	}

	if len(events) > 0 {
		if cp.FirstEventID != "" && events[0].ID != cp.FirstEventID {
			result.Status = StatusTamperedLog
			result.Message = fmt.Sprintf("first event id mismatch: expected %s, got %s", cp.FirstEventID, events[0].ID)
			return result
		}
		if cp.LastEventID != "" && events[len(events)-1].ID != cp.LastEventID {
			result.Status = StatusTamperedLog
			result.Message = fmt.Sprintf("last event id mismatch: expected %s, got %s", cp.LastEventID, events[len(events)-1].ID)
			return result
		}
	}

	// G. Sequence bounds & Authority tracking
	v.mu.RLock()
	currentAuth := v.acceptedAuthority
	v.mu.RUnlock()

	if v.policy.MinSequence > 0 && cp.Sequence < v.policy.MinSequence {
		result.Status = StatusStaleRevision
		result.Message = fmt.Sprintf("sequence %d is below policy min_sequence %d", cp.Sequence, v.policy.MinSequence)
		return result
	}

	if currentAuth != nil {
		result.AcceptedAuthority = currentAuth
		if cp.Sequence < currentAuth.Sequence {
			result.Status = StatusStaleRevision
			result.Message = fmt.Sprintf("sequence %d is stale; lower than accepted authority sequence %d", cp.Sequence, currentAuth.Sequence)
			return result
		}
		if cp.Sequence == currentAuth.Sequence && (cp.ID != currentAuth.CheckpointID || cp.LogRootHash != currentAuth.LogRootHash) {
			result.Status = StatusReplayRejected
			result.Message = fmt.Sprintf("replayed/forked sequence %d: conflicts with accepted authority (id=%s)", cp.Sequence, currentAuth.CheckpointID)
			return result
		}
	}

	// All checks pass!
	result.Status = StatusTrusted
	result.Trusted = true
	result.Message = "checkpoint signature verified, signer trusted, sequence advances monotonically, log root matches"
	return result
}

// NewCheckpointSignedEvent creates a CloudEvents 1.0 envelope for EventAuditCheckpointSigned ("audit.checkpoint_signed.v1").
func NewCheckpointSignedEvent(actor string, cp *AuditCheckpoint) (EventEnvelope, error) {
	if cp == nil {
		return EventEnvelope{}, errors.New("checkpoint cannot be nil")
	}
	details := map[string]any{
		"checkpoint_id":  cp.ID,
		"sequence":       cp.Sequence,
		"event_count":    cp.EventCount,
		"first_event_id": cp.FirstEventID,
		"last_event_id":  cp.LastEventID,
		"log_root_hash":  cp.LogRootHash,
		"signer_id":      cp.SignerID,
		"algorithm":      cp.Algorithm,
		"timestamp":      cp.Timestamp,
	}

	auditData := AuditData{
		Actor:   actor,
		Action:  "audit:checkpoint:sign",
		Outcome: "success",
		Details: details,
	}

	evt, err := NewEvent(EventAuditCheckpointSigned, "audit/checkpoint/"+cp.ID, auditData)
	if err != nil {
		return EventEnvelope{}, err
	}

	// Invariant: zero plaintext secret leakage
	marshaled, err := json.Marshal(evt)
	if err != nil {
		return EventEnvelope{}, err
	}
	if err := security.AssertClean(marshaled); err != nil {
		return EventEnvelope{}, fmt.Errorf("checkpoint audit event contains prohibited secret material: %w", err)
	}

	return evt, nil
}
