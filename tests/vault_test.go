package storage_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/parsa-emami/keyhelix/internal/auth"
	"github.com/parsa-emami/keyhelix/internal/storage"
	"github.com/parsa-emami/keyhelix/internal/vaults"
)

type c12SeededSecret struct {
	Owner              string `json:"owner"`
	Scope              string `json:"scope"`
	Name               string `json:"name"`
	Classification     string `json:"classification"`
	AuthorizedForAlice bool   `json:"authorized_for_alice"`
}

type c12PositiveFixture struct {
	SchemaVersion int    `json:"schema_version"`
	Provenance    string `json:"provenance"`
	License       string `json:"license"`
	Identity      struct {
		Subject       string   `json:"subject"`
		Email         string   `json:"email"`
		VaultRole     string   `json:"vault_role"`
		AllowedOwners []string `json:"allowed_owners"`
		AllowedScopes []string `json:"allowed_scopes"`
	} `json:"identity"`
	VaultID                string            `json:"vault_id"`
	SeededSecrets          []c12SeededSecret `json:"seeded_secrets"`
	ExpectedVisibleSecrets []string          `json:"expected_visible_secrets"`
	ExpectedHiddenSecrets  []string          `json:"expected_hidden_secrets"`
	PlaintextCanary        string            `json:"plaintext_canary"`
	MetadataFile           string            `json:"metadata_file"`
}

type c12NegativeCase struct {
	Case              string            `json:"case"`
	Kind              string            `json:"kind"`
	Description       string            `json:"description"`
	TargetOwner       string            `json:"target_owner,omitempty"`
	TargetSecret      string            `json:"target_secret,omitempty"`
	NonexistentSecret string            `json:"nonexistent_secret,omitempty"`
	Headers           map[string]string `json:"headers,omitempty"`
	ProviderOffline   bool              `json:"provider_offline,omitempty"`
	Canary            string            `json:"canary,omitempty"`
	ExpectedCode      string            `json:"expected_code,omitempty"`
	ExpectedPersisted *bool             `json:"expected_persisted,omitempty"`
}

type c12NegativeFixture struct {
	SchemaVersion int               `json:"schema_version"`
	Provenance    string            `json:"provenance"`
	License       string            `json:"license"`
	Cases         []c12NegativeCase `json:"cases"`
}

type c12ExpectedOutput struct {
	SchemaVersion   int               `json:"schema_version"`
	Provenance      string            `json:"provenance"`
	License         string            `json:"license"`
	MetadataSHA256  string            `json:"metadata_sha256"`
	PlaintextCanary string            `json:"plaintext_canary"`
	GuardCodes      map[string]string `json:"guard_codes"`
}

func loadC12Fixture(t *testing.T, filename string, target any) {
	t.Helper()
	path := filepath.Join("fixtures", "keyhelix", "C12", filename)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read C12 fixture %s: %v", filename, err)
	}
	if err := json.Unmarshal(data, target); err != nil {
		t.Fatalf("unmarshal C12 fixture %s: %v", filename, err)
	}
}

func assertC12ErrorCode(t *testing.T, err error, expected auth.ErrorCode) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error code %s, got nil", expected)
	}
	var authErr *auth.Error
	if errors.As(err, &authErr) {
		if authErr.Code != expected {
			t.Fatalf("expected error code %s, got %s (message: %s)", expected, authErr.Code, authErr.Message)
		}
		return
	}
	t.Fatalf("expected *auth.Error with code %s, got %T: %v", expected, err, err)
}

func TestC12_PositiveVaultListing(t *testing.T) {
	var pos c12PositiveFixture
	loadC12Fixture(t, "positive.json", &pos)

	var exp c12ExpectedOutput
	loadC12Fixture(t, "expected-output.json", &exp)

	// Validate metadata sha256
	metadataBytes, err := os.ReadFile(filepath.Join("fixtures", "keyhelix", "C12", pos.MetadataFile))
	if err != nil {
		t.Fatalf("read metadata file: %v", err)
	}
	digest := sha256.Sum256(metadataBytes)
	digestHex := hex.EncodeToString(digest[:])
	if digestHex != exp.MetadataSHA256 {
		t.Fatalf("metadata sha256 mismatch: got %s, want %s", digestHex, exp.MetadataSHA256)
	}

	dir := t.TempDir()
	store, _, err := storage.Open(dir)
	if err != nil {
		t.Fatalf("open storage: %v", err)
	}
	defer store.Close()

	ctx := context.Background()

	// Seed secrets
	var allPaths []string
	for i, s := range pos.SeededSecrets {
		allPaths = append(allPaths, s.Name)
		meta := fmt.Sprintf(`{
			"schema_version": "1",
			"vault_id": "%s",
			"secret_id": "sec-seed-%02d",
			"secret_path": "%s",
			"version": 1,
			"classification": "%s",
			"created_at": "2026-01-01T00:00:00Z",
			"envelope": {
				"algorithm": "AES-256-GCM",
				"wrapped_dek": "wrapped",
				"nonce": "nonce",
				"tag": "tag",
				"kek_id": "kek-1"
			}
		}`, s.Scope, i+1, s.Name, s.Classification)

		_, err := store.Write(ctx, storage.WriteRequest{
			OperationID:     fmt.Sprintf("seed-op-%04d", i+1),
			Owner:           s.Owner,
			Scope:           s.Scope,
			Name:            s.Name,
			ExpectedVersion: 0,
			Metadata:        []byte(meta),
		})
		if err != nil {
			t.Fatalf("seed secret %s: %v", s.Name, err)
		}
	}

	mapper := auth.NewScopeMapper(auth.DefaultScopeMapperConfig())
	svc := vaults.NewService(store, mapper)

	alice := &auth.Identity{
		Subject:       pos.Identity.Subject,
		Email:         pos.Identity.Email,
		VaultRole:     pos.Identity.VaultRole,
		AllowedOwners: pos.Identity.AllowedOwners,
		AllowedScopes: pos.Identity.AllowedScopes,
		ExpiresAt:     time.Now().Add(1 * time.Hour).Unix(),
	}

	summary, err := svc.ListAuthorizedMetadata(ctx, alice, nil, pos.VaultID, alice.Email, nil, allPaths)
	if err != nil {
		t.Fatalf("ListAuthorizedMetadata failed: %v", err)
	}

	if summary.AuthorizedCount != len(pos.ExpectedVisibleSecrets) {
		t.Fatalf("expected %d authorized secrets, got %d", len(pos.ExpectedVisibleSecrets), summary.AuthorizedCount)
	}

	// Verify all returned secrets are only from authorized list
	visibleMap := make(map[string]bool)
	for _, sec := range summary.Secrets {
		visibleMap[sec.SecretPath] = true
	}

	for _, expectedPath := range pos.ExpectedVisibleSecrets {
		if !visibleMap[expectedPath] {
			t.Errorf("expected authorized secret %q was not returned", expectedPath)
		}
	}

	// Verify no hidden secret names leaked
	for _, hiddenPath := range pos.ExpectedHiddenSecrets {
		if visibleMap[hiddenPath] {
			t.Errorf("LEAK: hidden secret %q was returned in metadata summary!", hiddenPath)
		}
	}
}

func TestC12_NegativeCases_FixtureDriven(t *testing.T) {
	var pos c12PositiveFixture
	loadC12Fixture(t, "positive.json", &pos)

	var neg c12NegativeFixture
	loadC12Fixture(t, "negative.json", &neg)

	dir := t.TempDir()
	store, _, err := storage.Open(dir)
	if err != nil {
		t.Fatalf("open storage: %v", err)
	}
	defer store.Close()

	ctx := context.Background()

	// Seed secrets
	for i, s := range pos.SeededSecrets {
		meta := fmt.Sprintf(`{
			"schema_version": "1",
			"vault_id": "%s",
			"secret_id": "sec-seed-%02d",
			"secret_path": "%s",
			"version": 1,
			"classification": "%s",
			"created_at": "2026-01-01T00:00:00Z",
			"envelope": {
				"algorithm": "AES-256-GCM",
				"wrapped_dek": "wrapped",
				"nonce": "nonce",
				"tag": "tag",
				"kek_id": "kek-1"
			}
		}`, s.Scope, i+1, s.Name, s.Classification)

		_, _ = store.Write(ctx, storage.WriteRequest{
			OperationID:     fmt.Sprintf("seed-op-%04d", i+1),
			Owner:           s.Owner,
			Scope:           s.Scope,
			Name:            s.Name,
			ExpectedVersion: 0,
			Metadata:        []byte(meta),
		})
	}

	mapper := auth.NewScopeMapper(auth.DefaultScopeMapperConfig())
	svc := vaults.NewService(store, mapper)

	alice := &auth.Identity{
		Subject:       pos.Identity.Subject,
		Email:         pos.Identity.Email,
		VaultRole:     pos.Identity.VaultRole,
		AllowedOwners: pos.Identity.AllowedOwners,
		AllowedScopes: pos.Identity.AllowedScopes,
		ExpiresAt:     time.Now().Add(1 * time.Hour).Unix(),
	}

	for _, tc := range neg.Cases {
		t.Run(tc.Case, func(t *testing.T) {
			switch tc.Case {
			case "missing-identity-rejected":
				_, err := svc.ListAuthorizedMetadata(ctx, nil, nil, pos.VaultID, pos.Identity.Email, nil, []string{"app/prod/database-url"})
				assertC12ErrorCode(t, err, auth.ErrorCode(tc.ExpectedCode))

			case "expired-identity-rejected":
				expired := &auth.Identity{
					Subject:       pos.Identity.Subject,
					Email:         pos.Identity.Email,
					AllowedOwners: pos.Identity.AllowedOwners,
					AllowedScopes: pos.Identity.AllowedScopes,
					ExpiresAt:     time.Now().Add(-10 * time.Minute).Unix(),
				}
				_, err := svc.ListAuthorizedMetadata(ctx, expired, nil, pos.VaultID, pos.Identity.Email, nil, []string{"app/prod/database-url"})
				assertC12ErrorCode(t, err, auth.ErrorCode(tc.ExpectedCode))

			case "replayed-identity-rejected":
				oidcConfig := auth.Config{
					IssuerURL:   "https://auth.keyhelix.local",
					ClientID:    "keyhelix-client",
					RedirectURI: "http://localhost:8080/callback",
				}
				provider, _ := auth.NewProvider(oidcConfig)
				now := time.Now().UTC()
				token := makeSyntheticJWT(
					map[string]any{"alg": "RS256"},
					map[string]any{
						"iss":   "https://auth.keyhelix.local",
						"aud":   "keyhelix-client",
						"sub":   pos.Identity.Subject,
						"nonce": "stale-nonce-replayed",
						"exp":   now.Add(10 * time.Minute).Unix(),
					},
				)
				_, err := provider.ParseAndVerifyIDToken(token, "fresh-expected-nonce", now)
				assertC12ErrorCode(t, err, auth.ErrorCode(tc.ExpectedCode))

			case "unrelated-owner-denied":
				_, err := svc.ListAuthorizedMetadata(ctx, alice, nil, pos.VaultID, tc.TargetOwner, nil, []string{"finance/payroll-key"})
				assertC12ErrorCode(t, err, auth.ErrorCode(tc.ExpectedCode))

			case "unauthorized-path-probing-no-leak":
				_, errUnauthorized := svc.GetSecretMetadata(ctx, alice, nil, pos.VaultID, tc.TargetSecret, "bob@keyhelix.local", nil)
				assertC12ErrorCode(t, errUnauthorized, auth.ErrorCode(tc.ExpectedCode))

				_, errNonexistent := svc.GetSecretMetadata(ctx, alice, nil, pos.VaultID, tc.NonexistentSecret, alice.Email, nil)
				assertC12ErrorCode(t, errNonexistent, auth.ErrorCode(tc.ExpectedCode))

				// Both must be completely identical
				if errUnauthorized.Error() != errNonexistent.Error() {
					t.Fatalf("Oracle existence leak: %q != %q", errUnauthorized.Error(), errNonexistent.Error())
				}

			case "forged-header-cannot-widen-listing":
				headers := http.Header{}
				for k, v := range tc.Headers {
					headers.Set(k, v)
				}
				_, err := svc.ListAuthorizedMetadata(ctx, alice, nil, pos.VaultID, alice.Email, headers, []string{"app/prod/database-url"})
				assertC12ErrorCode(t, err, auth.ErrorCode(tc.ExpectedCode))

			case "widened-path-permission-denied":
				_, err := svc.GetSecretMetadata(ctx, alice, nil, pos.VaultID, tc.TargetSecret, alice.Email, nil)
				assertC12ErrorCode(t, err, auth.ErrorCode(tc.ExpectedCode))

			case "identity-provider-unavailable-fails-closed":
				mapper.SetIDPOnline(false)
				defer mapper.SetIDPOnline(true)

				_, err := svc.ListAuthorizedMetadata(ctx, alice, nil, pos.VaultID, alice.Email, nil, []string{"app/prod/database-url"})
				assertC12ErrorCode(t, err, auth.ErrorCode(tc.ExpectedCode))

			case "provider-owns-secret-bytes":
				summary, err := svc.ListAuthorizedMetadata(ctx, alice, nil, pos.VaultID, alice.Email, nil, []string{"app/prod/database-url"})
				if err != nil {
					t.Fatalf("unexpected list error: %v", err)
				}
				sumJSON, _ := json.Marshal(summary)
				if strings.Contains(string(sumJSON), tc.Canary) {
					t.Fatalf("plaintext canary leaked in vault metadata JSON: %s", string(sumJSON))
				}
			}
		})
	}
}

func TestC12_ConcurrentVaultListing(t *testing.T) {
	dir := t.TempDir()
	store, _, err := storage.Open(dir)
	if err != nil {
		t.Fatalf("open storage: %v", err)
	}
	defer store.Close()

	ctx := context.Background()

	// Seed secret
	meta := `{
		"schema_version": "1",
		"vault_id": "vault-prod",
		"secret_id": "sec-concurrent",
		"secret_path": "app/prod/database-url",
		"version": 1,
		"classification": "restricted",
		"created_at": "2026-01-01T00:00:00Z",
		"envelope": {
			"algorithm": "AES-256-GCM",
			"wrapped_dek": "wrapped",
			"nonce": "nonce",
			"tag": "tag",
			"kek_id": "kek-1"
		}
	}`

	_, _ = store.Write(ctx, storage.WriteRequest{
		OperationID:     "seed-concurrent-01",
		Owner:           "alice@keyhelix.local",
		Scope:           "vault-prod",
		Name:            "app/prod/database-url",
		ExpectedVersion: 0,
		Metadata:        []byte(meta),
	})

	mapper := auth.NewScopeMapper(auth.DefaultScopeMapperConfig())
	svc := vaults.NewService(store, mapper)

	alice := &auth.Identity{
		Subject:       "usr_concurrent",
		Email:         "alice@keyhelix.local",
		AllowedOwners: []string{"alice@keyhelix.local"},
		AllowedScopes: []string{"vault:read", "app/prod/*"},
		ExpiresAt:     time.Now().Add(1 * time.Hour).Unix(),
	}

	var wg sync.WaitGroup
	workers := 20
	iterations := 50

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				summary, err := svc.ListAuthorizedMetadata(ctx, alice, nil, "vault-prod", alice.Email, nil, []string{"app/prod/database-url", "finance/payroll"})
				if err != nil {
					t.Errorf("worker %d iteration %d list failed: %v", id, j, err)
					return
				}
				if summary.AuthorizedCount != 1 {
					t.Errorf("worker %d iteration %d unexpected count: %d", id, j, summary.AuthorizedCount)
					return
				}

				sec, err := svc.GetSecretMetadata(ctx, alice, nil, "vault-prod", "app/prod/database-url", alice.Email, nil)
				if err != nil {
					t.Errorf("worker %d iteration %d get failed: %v", id, j, err)
					return
				}
				if sec.SecretPath != "app/prod/database-url" {
					t.Errorf("worker %d iteration %d unexpected secret: %s", id, j, sec.SecretPath)
					return
				}
			}
		}(i)
	}

	wg.Wait()
}
