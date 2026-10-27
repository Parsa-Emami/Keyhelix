// Package secrets implements versioned secret management with CAS update
// semantics (F07) and bounded authorized transient reveal responses (F08).
//
// Reveal invariants:
//  1. A fresh step-up grant bound to the caller session is mandatory, and
//     owner/path/provider-scope authorization runs before any provider or
//     payload side effect.
//  2. The provider owns the sealed bytes; the engine decrypts them transiently
//     and never persists plaintext.
//  3. The response is no-store, and plaintext never reaches errors, traces or
//     audit content.
package secrets

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/parsa-emami/keyhelix/internal/auth"
	"github.com/parsa-emami/keyhelix/internal/contracts"
	"github.com/parsa-emami/keyhelix/internal/provider"
	"github.com/parsa-emami/keyhelix/internal/storage"
)

// Reveal-specific typed failure codes. They never carry secret material.
const (
	CodeRevealInvalidInput       = "INVALID_INPUT"
	CodeRevealIntegrityFailure   = "REVEAL_INTEGRITY_FAILURE"
	CodeRevealCiphertextTampered = "CIPHERTEXT_TAMPERED"
	CodeRevealContentTooLarge    = "REVEAL_CONTENT_TOO_LARGE"
	CodeRevealCancelled          = "CANCELLED"
	CodeRevealTimeout            = "TIMEOUT"
)

// revealDeniedMessage is the single uniform denial text so an unauthorized
// caller cannot distinguish absence from denial (Requirements F06/F08).
const revealDeniedMessage = "secret not found or access denied"

// redactedPlaceholder is the only text a formatting or serialization path may
// emit in place of transient secret bytes.
const redactedPlaceholder = "[REDACTED]"

// RevealError is a typed reveal failure whose message never contains secret bytes.
type RevealError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Err     error  `json:"-"`
}

func (e *RevealError) Error() string {
	if e.Message != "" {
		return e.Code + ": " + e.Message
	}
	return e.Code
}

func (e *RevealError) Unwrap() error { return e.Err }

// RevealedPlaintext carries transient secret bytes for one authorized response.
// Every formatting and serialization path is redacted, so plaintext cannot reach
// errors, traces or audit content by accident; Plaintext() is the only accessor
// permitted for authorized transmission.
type RevealedPlaintext []byte

func (p RevealedPlaintext) String() string   { return redactedPlaceholder }
func (p RevealedPlaintext) GoString() string { return redactedPlaceholder }

func (p RevealedPlaintext) MarshalJSON() ([]byte, error) {
	return json.Marshal(redactedPlaceholder)
}

// Format redacts every fmt verb, including %x/%q forms that would otherwise
// print the underlying bytes.
func (p RevealedPlaintext) Format(state fmt.State, verb rune) {
	io.WriteString(state, redactedPlaceholder)
}

// Plaintext exposes the transient bytes for authorized transmission only.
func (p RevealedPlaintext) Plaintext() []byte { return []byte(p) }

// RevealRequest carries the verified caller context for one reveal.
type RevealRequest struct {
	VaultID       string
	SecretPath    string
	Owner         string
	Identity      *auth.Identity
	Session       *auth.Session
	StepUpManager *auth.StepUpManager
	StepUpToken   string
	Headers       http.Header
}

// RevealAuditContent is the secret-free projection an audit record may carry
// (Requirement F10 consumes this projection; it holds no plaintext or tokens).
type RevealAuditContent struct {
	Action         string `json:"action"`
	Actor          string `json:"actor"`
	VaultID        string `json:"vault_id"`
	SecretPath     string `json:"secret_path"`
	Version        int64  `json:"version"`
	Classification string `json:"classification"`
	Outcome        string `json:"outcome"`
}

// RevealResponse is one bounded, authorized, no-store secret response. It never
// serializes plaintext; authorized transmission uses WriteTo/WriteResponse.
type RevealResponse struct {
	VaultID        string
	SecretPath     string
	Version        int64
	Classification string
	CreatedAt      string
	MetadataDigest string
	Algorithm      string

	actor     string
	plaintext RevealedPlaintext
}

type revealMetadata struct {
	VaultID        string `json:"vault_id"`
	SecretPath     string `json:"secret_path"`
	Version        int64  `json:"version"`
	Classification string `json:"classification"`
	CreatedAt      string `json:"created_at"`
	MetadataDigest string `json:"metadata_digest"`
	Algorithm      string `json:"algorithm"`
	NoStore        bool   `json:"no_store"`
	Plaintext      string `json:"plaintext"`
}

func (r *RevealResponse) metadata() revealMetadata {
	return revealMetadata{
		VaultID:        r.VaultID,
		SecretPath:     r.SecretPath,
		Version:        r.Version,
		Classification: r.Classification,
		CreatedAt:      r.CreatedAt,
		MetadataDigest: r.MetadataDigest,
		Algorithm:      r.Algorithm,
		NoStore:        true,
		Plaintext:      redactedPlaceholder,
	}
}

// String provides a redacted printable form for traces and diagnostics.
func (r *RevealResponse) String() string {
	return fmt.Sprintf("RevealResponse(vault_id=%s, secret_path=%s, version=%d, classification=%s, plaintext=%s)",
		r.VaultID, r.SecretPath, r.Version, r.Classification, redactedPlaceholder)
}

// GoString provides a redacted %#v form for traces and diagnostics.
func (r *RevealResponse) GoString() string { return r.String() }

// MarshalJSON serializes the secret-free response metadata only.
func (r *RevealResponse) MarshalJSON() ([]byte, error) { return json.Marshal(r.metadata()) }

// Plaintext returns the transient bytes for authorized transmission only.
func (r *RevealResponse) Plaintext() RevealedPlaintext { return r.plaintext }

// NoStoreHeaders returns the mandatory no-store response headers.
func (r *RevealResponse) NoStoreHeaders() http.Header {
	headers := http.Header{}
	headers.Set("Cache-Control", "no-store")
	headers.Set("Pragma", "no-cache")
	headers.Set("Expires", "0")
	headers.Set("X-Content-Type-Options", "nosniff")
	return headers
}

// StreamTo writes the transient plaintext once; callers must not buffer it.
func (r *RevealResponse) StreamTo(w io.Writer) (int, error) {
	if w == nil {
		return 0, &RevealError{Code: CodeRevealInvalidInput, Message: "response writer must not be nil"}
	}
	return w.Write(r.plaintext)
}

// WriteResponse writes the bounded no-store response and then destroys the
// transient plaintext buffer.
func (r *RevealResponse) WriteResponse(w http.ResponseWriter) error {
	if w == nil {
		return &RevealError{Code: CodeRevealInvalidInput, Message: "response writer must not be nil"}
	}
	for name, values := range r.NoStoreHeaders() {
		for _, value := range values {
			w.Header().Add(name, value)
		}
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.Itoa(len(r.plaintext)))
	w.WriteHeader(http.StatusOK)
	_, err := r.StreamTo(w)
	r.Destroy()
	return err
}

// Destroy zeroes the transient plaintext buffer.
func (r *RevealResponse) Destroy() {
	for i := range r.plaintext {
		r.plaintext[i] = 0
	}
	r.plaintext = nil
}

// AuditContent projects the secret-free audit fields for this reveal.
func (r *RevealResponse) AuditContent() RevealAuditContent {
	return RevealAuditContent{
		Action:         string(auth.ActionRevealSecret),
		Actor:          r.actor,
		VaultID:        r.VaultID,
		SecretPath:     r.SecretPath,
		Version:        r.Version,
		Classification: r.Classification,
		Outcome:        "revealed",
	}
}

// RevealSecret returns one bounded, authorized, no-store secret response.
//
// Requirement F08: mandatory fresh step-up; no secret in errors, traces or
// audit content. Authorization (session, fresh step-up, owner, path, vault and
// mapped provider permission) is completed before any provider side effect.
func (s *Service) RevealSecret(ctx context.Context, req RevealRequest) (*RevealResponse, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		code := CodeRevealCancelled
		if err == context.DeadlineExceeded {
			code = CodeRevealTimeout
		}
		return nil, &RevealError{Code: code, Message: "reveal context is no longer active", Err: err}
	}
	if strings.TrimSpace(req.VaultID) == "" {
		return nil, &contracts.ValidationError{Code: contracts.InvalidInput, Field: "vault_id"}
	}
	if strings.TrimSpace(req.SecretPath) == "" {
		return nil, &contracts.ValidationError{Code: contracts.InvalidInput, Field: "secret_path"}
	}
	if s.mapper == nil {
		return nil, &auth.Error{Code: auth.CodeInvalidConfig, Message: "scope mapper is required for reveal"}
	}
	if s.keyProvider == nil {
		return nil, &provider.Error{Code: provider.CodeProviderUnavailable, Message: "provider offline"}
	}
	targetOwner := resolveOwner(req.Owner, req.Identity)
	if targetOwner == "" {
		return nil, &contracts.ValidationError{Code: contracts.InvalidInput, Field: "owner"}
	}

	// 1. Mandatory fresh step-up plus session, owner, path, vault and mapped
	// provider permission checks run before any provider or payload side effect.
	scope, err := auth.AuthorizeProviderAction(
		ctx,
		s.mapper,
		req.Identity,
		req.Session,
		req.StepUpManager,
		req.StepUpToken,
		req.VaultID,
		req.SecretPath,
		targetOwner,
		string(auth.ActionRevealSecret),
		req.Headers,
	)
	if err != nil {
		return nil, err
	}
	if !hasProviderScope(scope.ProviderScopes, transitDecryptScope) {
		return nil, &auth.Error{
			Code:    auth.CodeScopeDenied,
			Message: "mapped provider scope does not authorize transit:decrypt for reveal",
		}
	}

	// 2. Read the committed metadata; absence and authorization failures stay
	// indistinguishable so reveal is not an existence oracle.
	record, err := s.store.Read(ctx, storage.ReadRequest{
		Owner: targetOwner,
		Scope: req.VaultID,
		Name:  scope.CanonicalPath,
	})
	if err != nil {
		return nil, &auth.Error{Code: auth.CodeScopeDenied, Message: revealDeniedMessage}
	}
	metadata, failure := contracts.DecodeSecret(ctx, record.Metadata)
	if failure != nil ||
		metadata.VaultID != req.VaultID ||
		metadata.SecretPath != scope.CanonicalPath ||
		metadata.Envelope.KEKID != scope.KEKID {
		return nil, &auth.Error{Code: auth.CodeScopeDenied, Message: revealDeniedMessage}
	}
	if metadata.Envelope.Algorithm != "AES-256-GCM" {
		return nil, &RevealError{Code: CodeRevealIntegrityFailure, Message: "unsupported envelope algorithm"}
	}

	// 3. Provider-owned bytes: unwrap the DEK, then read the sealed payload of
	// the committed version and decrypt it transiently.
	dek, err := s.keyProvider.UnwrapDEK(ctx, metadata.Envelope.KEKID, metadata.Envelope.WrappedDEK)
	if err != nil {
		return nil, err
	}
	defer wipeBytes(dek)

	sealed, err := s.keyProvider.ReadSealedPayload(ctx, provider.SealedRef{
		VaultID: req.VaultID,
		Path:    scope.CanonicalPath,
		Version: metadata.Version,
	})
	if err != nil {
		return nil, err
	}

	plaintext, err := decryptSealedPayload(dek, metadata.Envelope, sealed, scope.CanonicalPath)
	if err != nil {
		return nil, err
	}

	actor := ""
	if req.Identity != nil {
		actor = req.Identity.Subject
	}
	return &RevealResponse{
		VaultID:        metadata.VaultID,
		SecretPath:     metadata.SecretPath,
		Version:        metadata.Version,
		Classification: metadata.Classification,
		CreatedAt:      metadata.CreatedAt,
		MetadataDigest: record.MetadataDigest,
		Algorithm:      metadata.Envelope.Algorithm,
		actor:          actor,
		plaintext:      RevealedPlaintext(plaintext),
	}, nil
}

// decryptSealedPayload authenticates and decrypts one provider-owned payload.
// It returns no partial plaintext when authentication fails.
func decryptSealedPayload(dek []byte, envelope contracts.Envelope, sealed []byte, canonicalPath string) ([]byte, error) {
	nonce, err := hex.DecodeString(envelope.Nonce)
	if err != nil {
		return nil, &RevealError{Code: CodeRevealIntegrityFailure, Message: "envelope nonce is not valid hex"}
	}
	tag, err := hex.DecodeString(envelope.Tag)
	if err != nil {
		return nil, &RevealError{Code: CodeRevealIntegrityFailure, Message: "envelope tag is not valid hex"}
	}
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, &RevealError{Code: CodeRevealIntegrityFailure, Message: "provider returned an unusable data key", Err: err}
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, &RevealError{Code: CodeRevealIntegrityFailure, Message: "failed to initialize the envelope cipher", Err: err}
	}
	if len(nonce) != gcm.NonceSize() || len(sealed) < gcm.Overhead() {
		return nil, &RevealError{Code: CodeRevealIntegrityFailure, Message: "sealed payload does not match the committed envelope"}
	}
	storedTag := sealed[len(sealed)-gcm.Overhead():]
	if subtle.ConstantTimeCompare(storedTag, tag) != 1 {
		return nil, &RevealError{Code: CodeRevealIntegrityFailure, Message: "sealed payload does not match the committed envelope tag"}
	}
	plaintext, err := gcm.Open(nil, nonce, sealed, []byte(canonicalPath))
	if err != nil {
		return nil, &RevealError{
			Code:    CodeRevealCiphertextTampered,
			Message: "ciphertext authentication failed; no partial plaintext returned",
			Err:     err,
		}
	}
	if len(plaintext) > MaxSecretBytes {
		wipeBytes(plaintext)
		return nil, &RevealError{Code: CodeRevealContentTooLarge, Message: "revealed payload exceeds the bounded response maximum"}
	}
	return plaintext, nil
}

// hasProviderScope checks the mapped provider capability list.
func hasProviderScope(scopes []string, required string) bool {
	for _, scope := range scopes {
		if scope == required || scope == "*" {
			return true
		}
	}
	return false
}

// wipeBytes zeroes a transient key or plaintext buffer.
func wipeBytes(data []byte) {
	for i := range data {
		data[i] = 0
	}
}
