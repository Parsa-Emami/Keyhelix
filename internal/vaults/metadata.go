// Package vaults provides vault-level metadata inspection and listing services.
// It implements requirement F06: User sees no unauthorized secret names or existence via errors.
package vaults

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/parsa-emami/keyhelix/internal/auth"
	"github.com/parsa-emami/keyhelix/internal/contracts"
	"github.com/parsa-emami/keyhelix/internal/storage"
)

// SecretSummary represents public/safe metadata of an encrypted secret.
// Plaintext secret bytes are owned exclusively by provider and are never held here (Requirement F06).
type SecretSummary struct {
	VaultID        string `json:"vault_id"`
	SecretPath     string `json:"secret_path"`
	Version        int64  `json:"version"`
	Classification string `json:"classification"`
	CreatedAt      string `json:"created_at"`
	MetadataDigest string `json:"metadata_digest"`
	Status         string `json:"status,omitempty"`
	DeletedAt      string `json:"deleted_at,omitempty"`
	RetainUntil    string `json:"retain_until,omitempty"`
	DestroyedAt    string `json:"destroyed_at,omitempty"`
}

type lifecycleEnvelope struct {
	SchemaVersion  string                    `json:"schema_version"`
	VaultID        string                    `json:"vault_id"`
	SecretPath     string                    `json:"secret_path"`
	Version        int64                     `json:"version"`
	Status         string                    `json:"status"`
	CreatedAt      string                    `json:"created_at,omitempty"`
	DeletedAt      string                    `json:"deleted_at,omitempty"`
	RetainUntil    string                    `json:"retain_until,omitempty"`
	DestroyedAt    string                    `json:"destroyed_at,omitempty"`
	ActiveMetadata *contracts.SecretMetadata `json:"active_metadata,omitempty"`
}

func summarizeRecord(ctx context.Context, vaultID, canonicalPath string, rec storage.Record) SecretSummary {
	decoded, vErr := contracts.DecodeSecret(ctx, rec.Metadata)
	if vErr == nil {
		return SecretSummary{
			VaultID:        decoded.VaultID,
			SecretPath:     decoded.SecretPath,
			Version:        decoded.Version,
			Classification: decoded.Classification,
			CreatedAt:      decoded.CreatedAt,
			MetadataDigest: rec.MetadataDigest,
			Status:         "ACTIVE",
		}
	}

	var lc lifecycleEnvelope
	if err := json.Unmarshal(rec.Metadata, &lc); err == nil && lc.SchemaVersion == "lifecycle-v1" {
		classification := "restricted"
		createdAt := rec.CreatedAt.Format(time.RFC3339)
		if lc.ActiveMetadata != nil {
			if lc.ActiveMetadata.Classification != "" {
				classification = lc.ActiveMetadata.Classification
			}
			if lc.ActiveMetadata.CreatedAt != "" {
				createdAt = lc.ActiveMetadata.CreatedAt
			}
		} else if lc.CreatedAt != "" {
			createdAt = lc.CreatedAt
		}
		version := lc.Version
		if version <= 0 {
			version = rec.EntityVersion
		}
		status := lc.Status
		if status == "" {
			status = "ACTIVE"
		}
		return SecretSummary{
			VaultID:        vaultID,
			SecretPath:     canonicalPath,
			Version:        version,
			Classification: classification,
			CreatedAt:      createdAt,
			MetadataDigest: rec.MetadataDigest,
			Status:         status,
			DeletedAt:      lc.DeletedAt,
			RetainUntil:    lc.RetainUntil,
			DestroyedAt:    lc.DestroyedAt,
		}
	}

	return SecretSummary{
		VaultID:        vaultID,
		SecretPath:     canonicalPath,
		Version:        rec.EntityVersion,
		Classification: "restricted",
		CreatedAt:      rec.CreatedAt.Format(time.RFC3339),
		MetadataDigest: rec.MetadataDigest,
		Status:         "ACTIVE",
	}
}

// VaultSummary represents the metadata listing of a vault filtered strictly to caller's authorization.
type VaultSummary struct {
	VaultID         string          `json:"vault_id"`
	TotalSecrets    int             `json:"total_secrets"`
	AuthorizedCount int             `json:"authorized_count"`
	Secrets         []SecretSummary `json:"secrets"`
}

// Service manages vault metadata querying and access enforcement.
type Service struct {
	mu     sync.RWMutex
	store  storage.Port
	mapper *auth.ScopeMapper
}

// NewService creates a vault metadata management service.
func NewService(store storage.Port, mapper *auth.ScopeMapper) *Service {
	return &Service{
		store:  store,
		mapper: mapper,
	}
}

// ListAuthorizedMetadata queries vault records and returns only the metadata
// items that the caller identity is explicitly authorized to view.
// Unauthorized secret names are strictly omitted to prevent information leakage (Requirement F06).
func (s *Service) ListAuthorizedMetadata(
	ctx context.Context,
	identity *auth.Identity,
	session *auth.Session,
	vaultID string,
	targetOwner string,
	headers http.Header,
	knownSecretPaths []string,
) (*VaultSummary, error) {
	if s.mapper != nil && !s.mapper.IsIDPOnline() {
		return nil, &auth.Error{
			Code:    auth.CodeIDPUnavailable,
			Message: "identity provider is offline or unreachable",
		}
	}

	if err := auth.ValidateRequestHeaders(headers); err != nil {
		return nil, err
	}

	if identity == nil {
		return nil, &auth.Error{
			Code:    auth.CodeInvalidToken,
			Message: "cannot list vault metadata for nil identity",
		}
	}

	now := time.Now().UTC()
	if identity.ExpiresAt > 0 && now.Unix() > identity.ExpiresAt {
		return nil, &auth.Error{
			Code:    auth.CodeExpiredToken,
			Message: "identity token has expired",
		}
	}

	if session != nil {
		if session.IsRevoked() {
			return nil, &auth.Error{
				Code:    auth.CodeInvalidToken,
				Message: "session has been revoked",
			}
		}
		if session.IsExpired(now) {
			return nil, &auth.Error{
				Code:    auth.CodeExpiredToken,
				Message: "session has expired",
			}
		}
		if subtle.ConstantTimeCompare([]byte(session.Identity.Subject), []byte(identity.Subject)) != 1 {
			return nil, &auth.Error{
				Code:    auth.CodeInvalidToken,
				Message: "session subject does not match identity subject",
			}
		}
	}

	// Owner check: if targetOwner is supplied, verify caller authorization
	if targetOwner != "" && !auth.IsOwnerAuthorized(identity, targetOwner) {
		return nil, &auth.Error{
			Code:    auth.CodeScopeDenied,
			Message: fmt.Sprintf("identity %q not authorized for owner %q", identity.Subject, targetOwner),
		}
	}

	// Verify target vault permission
	hasVaultRead := false
	for _, sc := range identity.AllowedScopes {
		if sc == "*" || sc == "vault:read" || sc == "vault:*" || sc == "vault-admin" {
			hasVaultRead = true
			break
		}
	}
	if !hasVaultRead {
		return nil, &auth.Error{
			Code:    auth.CodeScopeDenied,
			Message: fmt.Sprintf("identity %q lacks vault:read scope", identity.Subject),
		}
	}

	summary := &VaultSummary{
		VaultID:         vaultID,
		TotalSecrets:    len(knownSecretPaths),
		AuthorizedCount: 0,
		Secrets:         make([]SecretSummary, 0),
	}

	// Filter known secrets strictly against identity permissions
	for _, path := range knownSecretPaths {
		canonical, err := auth.NormalizePath(path)
		if err != nil {
			// Skip or reject invalid path representations
			continue
		}

		if !s.isPathAuthorized(identity, canonical) {
			// Do NOT include in summary: unauthorized secret names are omitted
			continue
		}

		// Read metadata from store
		reqOwner := targetOwner
		if reqOwner == "" {
			reqOwner = identity.Email
		}

		rec, err := s.store.Read(ctx, storage.ReadRequest{
			Owner: reqOwner,
			Scope: vaultID,
			Name:  canonical,
		})
		if err != nil {
			// If not found in storage under this owner/vault, do not reveal
			continue
		}

		summary.Secrets = append(summary.Secrets, summarizeRecord(ctx, vaultID, canonical, rec))
		summary.AuthorizedCount++
	}

	return summary, nil
}

// GetSecretMetadata queries a single secret's metadata.
// If the caller lacks authorization, the error response is identical to a non-existent secret,
// preventing existence enumeration / oracle attacks (Requirement F06).
func (s *Service) GetSecretMetadata(
	ctx context.Context,
	identity *auth.Identity,
	session *auth.Session,
	vaultID string,
	rawSecretPath string,
	targetOwner string,
	headers http.Header,
) (*SecretSummary, error) {
	if s.mapper != nil && !s.mapper.IsIDPOnline() {
		return nil, &auth.Error{
			Code:    auth.CodeIDPUnavailable,
			Message: "identity provider is offline or unreachable",
		}
	}

	if err := auth.ValidateRequestHeaders(headers); err != nil {
		return nil, err
	}

	if identity == nil {
		return nil, &auth.Error{
			Code:    auth.CodeInvalidToken,
			Message: "cannot read metadata for nil identity",
		}
	}

	now := time.Now().UTC()
	if identity.ExpiresAt > 0 && now.Unix() > identity.ExpiresAt {
		return nil, &auth.Error{
			Code:    auth.CodeExpiredToken,
			Message: "identity token has expired",
		}
	}

	canonicalPath, err := auth.NormalizePath(rawSecretPath)
	if err != nil {
		return nil, err
	}

	// Owner check
	reqOwner := targetOwner
	if reqOwner == "" {
		reqOwner = identity.Email
	}

	ownerAuthorized := auth.IsOwnerAuthorized(identity, reqOwner)
	pathAuthorized := s.isPathAuthorized(identity, canonicalPath)

	if !ownerAuthorized || !pathAuthorized {
		// Anti-Oracle Invariant: Return CodeScopeDenied with uniform message
		// so an attacker cannot differentiate between an absent secret and an unauthorized one.
		return nil, &auth.Error{
			Code:    auth.CodeScopeDenied,
			Message: "secret not found or access denied",
		}
	}

	rec, err := s.store.Read(ctx, storage.ReadRequest{
		Owner: reqOwner,
		Scope: vaultID,
		Name:  canonicalPath,
	})
	if err != nil {
		return nil, &auth.Error{
			Code:    auth.CodeScopeDenied,
			Message: "secret not found or access denied",
		}
	}

	item := summarizeRecord(ctx, vaultID, canonicalPath, rec)
	return &item, nil
}

func (s *Service) isPathAuthorized(identity *auth.Identity, canonicalPath string) bool {
	return auth.IsPathScopeAuthorized(identity, canonicalPath, "secret:read", "vault:read")
}

