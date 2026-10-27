package vaults

import (
	"context"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/parsa-emami/keyhelix/internal/auth"
	"github.com/parsa-emami/keyhelix/internal/storage"
)

func TestVaultService_ListAuthorizedMetadata(t *testing.T) {
	dir := t.TempDir()
	store, _, err := storage.Open(dir)
	if err != nil {
		t.Fatalf("open storage: %v", err)
	}
	defer store.Close()

	ctx := context.Background()

	// Seed secrets in storage
	secretPayload := []byte(`{
		"schema_version": "1",
		"vault_id": "vault-prod",
		"secret_id": "sec-01",
		"secret_path": "app/prod/database-url",
		"version": 1,
		"classification": "restricted",
		"created_at": "2026-01-01T00:00:00Z",
		"envelope": {
			"algorithm": "AES-256-GCM",
			"wrapped_dek": "dek",
			"nonce": "nonce",
			"tag": "tag",
			"kek_id": "kek-1"
		}
	}`)

	_, err = store.Write(ctx, storage.WriteRequest{
		OperationID:     "operation-001",
		Owner:           "alice@keyhelix.local",
		Scope:           "vault-prod",
		Name:            "app/prod/database-url",
		ExpectedVersion: 0,
		Metadata:        secretPayload,
	})
	if err != nil {
		t.Fatalf("seed secret: %v", err)
	}

	devSecretPayload := []byte(`{
		"schema_version": "1",
		"vault_id": "vault-prod",
		"secret_id": "sec-02",
		"secret_path": "app/dev/db-credentials",
		"version": 1,
		"classification": "internal",
		"created_at": "2026-01-01T00:00:00Z",
		"envelope": {
			"algorithm": "AES-256-GCM",
			"wrapped_dek": "dek",
			"nonce": "nonce",
			"tag": "tag",
			"kek_id": "kek-1"
		}
	}`)
	_, err = store.Write(ctx, storage.WriteRequest{
		OperationID:     "operation-002",
		Owner:           "alice@keyhelix.local",
		Scope:           "vault-prod",
		Name:            "app/dev/db-credentials",
		ExpectedVersion: 0,
		Metadata:        devSecretPayload,
	})
	if err != nil {
		t.Fatalf("seed secret: %v", err)
	}

	mapper := auth.NewScopeMapper(auth.DefaultScopeMapperConfig())
	svc := NewService(store, mapper)

	alice := &auth.Identity{
		Subject:       "usr_alice",
		Email:         "alice@keyhelix.local",
		AllowedOwners: []string{"alice@keyhelix.local"},
		AllowedScopes: []string{"vault:read", "app/prod/*"},
		ExpiresAt:     time.Now().Add(1 * time.Hour).Unix(),
	}

	knownPaths := []string{
		"app/prod/database-url",
		"app/dev/db-credentials",
	}

	summary, err := svc.ListAuthorizedMetadata(ctx, alice, nil, "vault-prod", "alice@keyhelix.local", nil, knownPaths)
	if err != nil {
		t.Fatalf("ListAuthorizedMetadata failed: %v", err)
	}

	if summary.AuthorizedCount != 1 {
		t.Fatalf("expected 1 authorized secret, got %d", summary.AuthorizedCount)
	}
	if summary.Secrets[0].SecretPath != "app/prod/database-url" {
		t.Fatalf("expected app/prod/database-url, got %s", summary.Secrets[0].SecretPath)
	}
}

func TestVaultService_GetSecretMetadata_AntiOracle(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "store")
	store, _, err := storage.Open(dir)
	if err != nil {
		t.Fatalf("open storage: %v", err)
	}
	defer store.Close()

	ctx := context.Background()

	// Seed finance secret
	secretPayload := []byte(`{
		"schema_version": "1",
		"vault_id": "vault-prod",
		"secret_id": "sec-finance",
		"secret_path": "finance/payroll-key",
		"version": 1,
		"classification": "restricted",
		"created_at": "2026-01-01T00:00:00Z",
		"envelope": {
			"algorithm": "AES-256-GCM",
			"wrapped_dek": "dek",
			"nonce": "nonce",
			"tag": "tag",
			"kek_id": "kek-1"
		}
	}`)
	_, _ = store.Write(ctx, storage.WriteRequest{
		OperationID:     "op-fin",
		Owner:           "bob@keyhelix.local",
		Scope:           "vault-prod",
		Name:            "finance/payroll-key",
		ExpectedVersion: 0,
		Metadata:        secretPayload,
	})

	mapper := auth.NewScopeMapper(auth.DefaultScopeMapperConfig())
	svc := NewService(store, mapper)

	alice := &auth.Identity{
		Subject:       "usr_alice",
		Email:         "alice@keyhelix.local",
		AllowedOwners: []string{"alice@keyhelix.local"},
		AllowedScopes: []string{"vault:read", "app/prod/*"},
		ExpiresAt:     time.Now().Add(1 * time.Hour).Unix(),
	}

	// 1. Probe unauthorized existing secret
	_, errUnauthorized := svc.GetSecretMetadata(ctx, alice, nil, "vault-prod", "finance/payroll-key", "bob@keyhelix.local", nil)
	if errUnauthorized == nil {
		t.Fatal("expected error for unauthorized secret lookup")
	}

	// 2. Probe completely non-existent secret
	_, errNonExistent := svc.GetSecretMetadata(ctx, alice, nil, "vault-prod", "app/prod/does-not-exist", "alice@keyhelix.local", nil)
	if errNonExistent == nil {
		t.Fatal("expected error for non-existent secret lookup")
	}

	// Anti-Oracle Invariant: Errors must be identical in Code and Message
	if errUnauthorized.Error() != errNonExistent.Error() {
		t.Fatalf("Oracle leak detected! Unauthorized error (%q) != Non-existent error (%q)",
			errUnauthorized.Error(), errNonExistent.Error())
	}
}

func TestVaultService_ForgedHeaderRejected(t *testing.T) {
	dir := t.TempDir()
	store, _, _ := storage.Open(dir)
	defer store.Close()

	svc := NewService(store, auth.NewScopeMapper(auth.DefaultScopeMapperConfig()))
	alice := &auth.Identity{
		Subject:   "usr_alice",
		ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
	}

	headers := http.Header{}
	headers.Set("X-Original-URL", "/v1/vaults/admin/keys")

	_, err := svc.ListAuthorizedMetadata(context.Background(), alice, nil, "vault-prod", "", headers, []string{"app/prod/db"})
	if !auth.IsErrorCode(err, auth.CodeScopeDenied) {
		t.Fatalf("expected CodeScopeDenied for forged header, got %v", err)
	}
}
