// Package secrets implements versioned secret management with CAS update semantics
// and provider-owned secret encryption envelopes (F07).
// Plaintext secret bytes are owned by the provider / client envelope;
// they never enter metadata storage.
package secrets

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
	"time"

	"github.com/parsa-emami/keyhelix/internal/auth"
	"github.com/parsa-emami/keyhelix/internal/contracts"
	"github.com/parsa-emami/keyhelix/internal/provider"
	"github.com/parsa-emami/keyhelix/internal/storage"
)

// Error codes for secret operations.
const (
	CodeStaleVersion        = storage.CodeStaleVersion
	CodeAlreadyExists       = storage.CodeAlreadyExists
	CodeNotFound            = storage.CodeNotFound
	CodeProviderUnavailable = string(provider.CodeProviderUnavailable)
	CodeInvalidInput        = "INVALID_INPUT"
	CodeUnauthorized        = "UNAUTHORIZED"
)

// MaxSecretBytes bounds one secret payload handled by the engine.
const MaxSecretBytes = 1 << 20

// Provider capabilities required by the reveal path.
const (
	transitDecryptScope = "transit:decrypt"
	kvReadScope         = "kv:read"
)

// WriteRequest encapsulates inputs to write a versioned secret.
type WriteRequest struct {
	VaultID         string
	SecretPath      string
	ExpectedVersion int64
	Plaintext       []byte
	Classification  string
	KEKID           string
	OperationID     string
	Owner           string
	Identity        *auth.Identity
}

// WriteOutcome represents the confirmed versioned write metadata.
type WriteOutcome struct {
	VaultID      string             `json:"vault_id"`
	SecretID     string             `json:"secret_id"`
	SecretPath   string             `json:"secret_path"`
	Version      int64              `json:"version"`
	MetadataHash string             `json:"metadata_hash"`
	CreatedAt    string             `json:"created_at"`
	Envelope     contracts.Envelope `json:"envelope"`
}

// Service provides versioned secret operations.
type Service struct {
	mapper      *auth.ScopeMapper
	keyProvider provider.Port
	store       storage.Port
}

// NewService constructs a new secrets Service.
func NewService(mapper *auth.ScopeMapper, keyProvider provider.Port, store storage.Port) *Service {
	return &Service{
		mapper:      mapper,
		keyProvider: keyProvider,
		store:       store,
	}
}

// WriteSecret writes or updates a secret using Compare-And-Swap (CAS) on ExpectedVersion.
// Requirement F07:
// 1. CAS version prevents lost update.
// 2. Secret bytes are owned by the provider envelope; plaintext bytes NEVER enter metadata storage.
func (s *Service) WriteSecret(ctx context.Context, req WriteRequest) (*WriteOutcome, error) {
	if strings.TrimSpace(req.VaultID) == "" {
		return nil, &contracts.ValidationError{Code: contracts.InvalidInput, Field: "vault_id"}
	}
	cleanPath, err := auth.NormalizePath(req.SecretPath)
	if err != nil {
		return nil, &contracts.ValidationError{Code: contracts.InvalidInput, Field: "secret_path"}
	}
	if len(req.Plaintext) == 0 {
		return nil, &contracts.ValidationError{Code: contracts.InvalidInput, Field: "plaintext"}
	}
	if len(req.Plaintext) > MaxSecretBytes {
		return nil, &contracts.ValidationError{Code: contracts.InputTooLarge, Field: "plaintext"}
	}
	if strings.TrimSpace(req.KEKID) == "" {
		return nil, &contracts.ValidationError{Code: contracts.InvalidInput, Field: "kek_id"}
	}
	if req.ExpectedVersion < 0 {
		return nil, &contracts.ValidationError{Code: contracts.InvalidInput, Field: "expected_version"}
	}

	targetOwner := resolveOwner(req.Owner, req.Identity)
	if targetOwner == "" {
		targetOwner = "default-owner"
	}

	// 1. Authorization check
	if req.Identity != nil {
		if !s.isAuthorized(req.Identity, targetOwner, cleanPath) {
			return nil, &auth.Error{Code: auth.CodeScopeDenied, Message: CodeUnauthorized}
		}
	}

	// 2. Provider-independent CAS pre-check: refuse stale or duplicate writes
	// before any provider side effect runs.
	currentVersion, err := s.currentVersion(ctx, targetOwner, req.VaultID, cleanPath)
	if err != nil {
		return nil, err
	}
	switch {
	case currentVersion == 0 && req.ExpectedVersion != 0:
		return nil, &storage.Error{Code: storage.CodeStaleVersion, Field: "expected_version"}
	case currentVersion > 0 && req.ExpectedVersion == 0:
		return nil, &storage.Error{Code: storage.CodeAlreadyExists, Field: "name"}
	case currentVersion > 0 && currentVersion != req.ExpectedVersion:
		return nil, &storage.Error{Code: storage.CodeStaleVersion, Field: "expected_version"}
	}

	// 3. Provider health check & DEK Wrapping (Provider-owned encryption envelope)
	if s.keyProvider == nil {
		return nil, &provider.Error{Code: provider.CodeProviderUnavailable, Message: "provider offline"}
	}

	// Generate ephemeral Data Encryption Key (DEK) - 256-bit AES
	plaintextDEK := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, plaintextDEK); err != nil {
		return nil, fmt.Errorf("failed to generate random DEK: %w", err)
	}
	defer func() {
		// Zero out plaintext DEK from memory
		for i := range plaintextDEK {
			plaintextDEK[i] = 0
		}
	}()

	// Ask Key Provider to wrap the DEK
	wrapRes, err := s.keyProvider.WrapDEK(ctx, req.KEKID, plaintextDEK)
	if err != nil {
		return nil, err
	}
	if wrapRes == nil || wrapRes.Ciphertext == "" {
		return nil, &provider.Error{Code: provider.CodeProviderUnavailable, Message: "empty provider wrap response"}
	}

	// Encrypt plaintext with DEK using AES-GCM
	block, err := aes.NewCipher(plaintextDEK)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt and authenticate
	sealed := gcm.Seal(nil, nonce, req.Plaintext, []byte(cleanPath))
	// GCM appends tag of length gcm.Overhead() to ciphertext
	tagLen := gcm.Overhead()
	if len(sealed) < tagLen {
		return nil, errors.New("invalid ciphertext generated")
	}
	tag := sealed[len(sealed)-tagLen:]

	envelope := contracts.Envelope{
		Algorithm:  "AES-256-GCM",
		WrappedDEK: wrapRes.Ciphertext,
		Nonce:      hex.EncodeToString(nonce),
		Tag:        hex.EncodeToString(tag),
		KEKID:      req.KEKID,
	}

	// Generate deterministic SecretID from vaultID and cleanPath
	secretIDHasher := sha256.New()
	secretIDHasher.Write([]byte(req.VaultID + ":" + cleanPath))
	secretID := fmt.Sprintf("sec-%s", hex.EncodeToString(secretIDHasher.Sum(nil))[:16])

	classification := strings.ToLower(strings.TrimSpace(req.Classification))
	if classification == "" {
		classification = "confidential"
	}
	switch classification {
	case "restricted", "confidential", "internal":
	default:
		return nil, &contracts.ValidationError{Code: contracts.InvalidInput, Field: "classification"}
	}

	nextVersion := req.ExpectedVersion + 1
	createdAt := time.Now().UTC().Format(time.RFC3339)

	// 4. Provider owns the sealed bytes: write them before publishing metadata so a
	// failed provider write can never produce a metadata version without bytes.
	if err := s.keyProvider.PutSealedPayload(ctx, provider.SealedRef{
		VaultID: req.VaultID,
		Path:    cleanPath,
		Version: nextVersion,
	}, sealed); err != nil {
		return nil, s.reconcilePayloadWrite(ctx, err, targetOwner, req.VaultID, cleanPath, req.ExpectedVersion)
	}

	metadata := contracts.SecretMetadata{
		SchemaVersion:  contracts.SchemaVersion,
		VaultID:        req.VaultID,
		SecretID:       secretID,
		SecretPath:     cleanPath,
		Version:        nextVersion,
		Classification: classification,
		CreatedAt:      createdAt,
		Envelope:       envelope,
	}

	// Marshal ONLY metadata to JSON; notice req.Plaintext is NEVER added here!
	metadataBytes, err := json.Marshal(metadata)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal metadata: %w", err)
	}

	// 3. Storage Write with CAS Version verification
	opID := req.OperationID
	if opID == "" {
		opHasher := sha256.New()
		opHasher.Write([]byte(fmt.Sprintf("%s:%s:%s:%d:%d", targetOwner, req.VaultID, cleanPath, req.ExpectedVersion, time.Now().UnixNano())))
		opID = "op-" + hex.EncodeToString(opHasher.Sum(nil))[:16]
	}

	writeReq := storage.WriteRequest{
		OperationID:     opID,
		Owner:           targetOwner,
		Scope:           req.VaultID,
		Name:            cleanPath,
		ExpectedVersion: req.ExpectedVersion,
		Metadata:        metadataBytes,
	}

	writeRes, err := s.store.Write(ctx, writeReq)
	if err != nil {
		return nil, err
	}

	metadataHash := sha256.Sum256(metadataBytes)

	return &WriteOutcome{
		VaultID:      req.VaultID,
		SecretID:     secretID,
		SecretPath:   cleanPath,
		Version:      writeRes.EntityVersion,
		MetadataHash: hex.EncodeToString(metadataHash[:]),
		CreatedAt:    createdAt,
		Envelope:     envelope,
	}, nil
}

// resolveOwner derives the authoritative owner for one operation from the
// explicit request owner or the verified identity.
func resolveOwner(owner string, identity *auth.Identity) string {
	if strings.TrimSpace(owner) != "" {
		return owner
	}
	if identity == nil {
		return ""
	}
	if identity.Email != "" {
		return identity.Email
	}
	return identity.Subject
}

// currentVersion returns the committed version for one record, or 0 when the
// record does not exist yet.
func (s *Service) currentVersion(ctx context.Context, owner, vaultID, name string) (int64, error) {
	record, err := s.store.Read(ctx, storage.ReadRequest{Owner: owner, Scope: vaultID, Name: name})
	if err != nil {
		var storageErr *storage.Error
		if errors.As(err, &storageErr) && storageErr.Code == storage.CodeNotFound {
			return 0, nil
		}
		return 0, err
	}
	return record.EntityVersion, nil
}

// reconcilePayloadWrite keeps a provider conflict from publishing a metadata
// version whose bytes another writer already owns: if the authoritative record
// has advanced, the caller lost a CAS race; otherwise the conflict is surfaced.
func (s *Service) reconcilePayloadWrite(ctx context.Context, cause error, owner, vaultID, name string, expectedVersion int64) error {
	if !provider.IsErrorCode(cause, provider.CodePayloadConflict) {
		return cause
	}
	current, err := s.currentVersion(ctx, owner, vaultID, name)
	if err != nil {
		return cause
	}
	if current > expectedVersion {
		return &storage.Error{Code: storage.CodeStaleVersion, Field: "expected_version"}
	}
	return cause
}

func (s *Service) isAuthorized(identity *auth.Identity, targetOwner string, canonicalPath string) bool {
	if identity.ExpiresAt > 0 && time.Now().Unix() > identity.ExpiresAt {
		return false
	}
	// Check owner authorization
	ownerAuthorized := false
	if identity.Email != "" && subtle.ConstantTimeCompare([]byte(identity.Email), []byte(targetOwner)) == 1 {
		ownerAuthorized = true
	} else if identity.Subject != "" && subtle.ConstantTimeCompare([]byte(identity.Subject), []byte(targetOwner)) == 1 {
		ownerAuthorized = true
	} else {
		for _, allowed := range identity.AllowedOwners {
			if subtle.ConstantTimeCompare([]byte(allowed), []byte(targetOwner)) == 1 {
				ownerAuthorized = true
				break
			}
		}
	}
	if !ownerAuthorized {
		return false
	}

	// Check path-level scopes
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
