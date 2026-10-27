// Package vaults provides vault-level metadata inspection and listing services.
// It implements requirement F06: User sees no unauthorized secret names or existence via errors.
package vaults

import (
	"context"
	"crypto/subtle"
	"fmt"
	"net/http"
	"strings"
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
	if targetOwner != "" {
		ownerMatch := false
		if identity.Email != "" && subtle.ConstantTimeCompare([]byte(identity.Email), []byte(targetOwner)) == 1 {
			ownerMatch = true
		} else if identity.Subject != "" && subtle.ConstantTimeCompare([]byte(identity.Subject), []byte(targetOwner)) == 1 {
			ownerMatch = true
		} else {
			for _, allowed := range identity.AllowedOwners {
				if subtle.ConstantTimeCompare([]byte(allowed), []byte(targetOwner)) == 1 {
					ownerMatch = true
					break
				}
			}
		}
		if !ownerMatch {
			return nil, &auth.Error{
				Code:    auth.CodeScopeDenied,
				Message: fmt.Sprintf("identity %q not authorized for owner %q", identity.Subject, targetOwner),
			}
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

		// Decode contract envelope
		decoded, vErr := contracts.DecodeSecret(ctx, rec.Metadata)
		if vErr != nil {
			// Fallback summary from storage record if contract parse fails
			summary.Secrets = append(summary.Secrets, SecretSummary{
				VaultID:        vaultID,
				SecretPath:     canonical,
				Version:        rec.EntityVersion,
				Classification: "restricted",
				CreatedAt:      rec.CreatedAt.Format(time.RFC3339),
				MetadataDigest: rec.MetadataDigest,
			})
			summary.AuthorizedCount++
			continue
		}

		summary.Secrets = append(summary.Secrets, SecretSummary{
			VaultID:        decoded.VaultID,
			SecretPath:     decoded.SecretPath,
			Version:        decoded.Version,
			Classification: decoded.Classification,
			CreatedAt:      decoded.CreatedAt,
			MetadataDigest: rec.MetadataDigest,
		})
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

	ownerAuthorized := false
	if identity.Email != "" && subtle.ConstantTimeCompare([]byte(identity.Email), []byte(reqOwner)) == 1 {
		ownerAuthorized = true
	} else if identity.Subject != "" && subtle.ConstantTimeCompare([]byte(identity.Subject), []byte(reqOwner)) == 1 {
		ownerAuthorized = true
	} else {
		for _, allowed := range identity.AllowedOwners {
			if subtle.ConstantTimeCompare([]byte(allowed), []byte(reqOwner)) == 1 {
				ownerAuthorized = true
				break
			}
		}
	}

	// Check path authorization
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

	decoded, vErr := contracts.DecodeSecret(ctx, rec.Metadata)
	if vErr != nil {
		return &SecretSummary{
			VaultID:        vaultID,
			SecretPath:     canonicalPath,
			Version:        rec.EntityVersion,
			Classification: "restricted",
			CreatedAt:      rec.CreatedAt.Format(time.RFC3339),
			MetadataDigest: rec.MetadataDigest,
		}, nil
	}

	return &SecretSummary{
		VaultID:        decoded.VaultID,
		SecretPath:     decoded.SecretPath,
		Version:        decoded.Version,
		Classification: decoded.Classification,
		CreatedAt:      decoded.CreatedAt,
		MetadataDigest: rec.MetadataDigest,
	}, nil
}

func (s *Service) isPathAuthorized(identity *auth.Identity, canonicalPath string) bool {
	hasPathRestrictions := false
	pathMatched := false

	for _, sc := range identity.AllowedScopes {
		if strings.Contains(sc, "/") {
			hasPathRestrictions = true
			if auth.MatchPathScope(sc, canonicalPath) {
				pathMatched = true
				break
			}
		} else if sc == "*" || sc == "secret:*" {
			return true
		}
	}

	if hasPathRestrictions {
		return pathMatched
	}

	// If no path patterns are configured, check generic secret:read / vault:read
	for _, sc := range identity.AllowedScopes {
		if sc == "secret:read" || sc == "vault:read" {
			return true
		}
	}
	return false
}
