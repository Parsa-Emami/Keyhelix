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
)

type c11PositiveFixture struct {
	SchemaVersion int    `json:"schema_version"`
	Provenance    string `json:"provenance"`
	License       string `json:"license"`
	Identity      struct {
		Subject       string   `json:"subject"`
		Email         string   `json:"email"`
		VaultRole     string   `json:"vault_role"`
		AllowedOwners []string `json:"allowed_owners"`
		AllowedScopes []string `json:"allowed_scopes"`
		PathScopes    []string `json:"path_scopes"`
	} `json:"identity"`
	TargetReveal struct {
		VaultID                string   `json:"vault_id"`
		SecretPath             string   `json:"secret_path"`
		CanonicalPath          string   `json:"canonical_path"`
		Action                 string   `json:"action"`
		RequiredScope          string   `json:"required_scope"`
		ExpectedProviderScopes []string `json:"expected_provider_scopes"`
		ExpectedKEKID          string   `json:"expected_kek_id"`
		ExpectedProviderMount  string   `json:"expected_provider_mount"`
	} `json:"target_reveal"`
	TargetWrite struct {
		VaultID                string   `json:"vault_id"`
		SecretPath             string   `json:"secret_path"`
		CanonicalPath          string   `json:"canonical_path"`
		Action                 string   `json:"action"`
		RequiredScope          string   `json:"required_scope"`
		ExpectedProviderScopes []string `json:"expected_provider_scopes"`
		ExpectedKEKID          string   `json:"expected_kek_id"`
		ExpectedProviderMount  string   `json:"expected_provider_mount"`
	} `json:"target_write"`
	PlaintextCanary string `json:"plaintext_canary"`
	MetadataFile    string `json:"metadata_file"`
}

type c11NegativeCase struct {
	Case              string            `json:"case"`
	Kind              string            `json:"kind"`
	Description       string            `json:"description"`
	Action            string            `json:"action,omitempty"`
	RawPath           string            `json:"raw_path,omitempty"`
	Actor             string            `json:"actor,omitempty"`
	TargetOwner       string            `json:"target_owner,omitempty"`
	TargetVault       string            `json:"target_vault,omitempty"`
	Headers           map[string]string `json:"headers,omitempty"`
	ProviderOffline   bool              `json:"provider_offline,omitempty"`
	Canary            string            `json:"canary,omitempty"`
	ExpectedCode      string            `json:"expected_code,omitempty"`
	ExpectedPersisted *bool             `json:"expected_persisted,omitempty"`
}

type c11NegativeFixture struct {
	SchemaVersion int               `json:"schema_version"`
	Provenance    string            `json:"provenance"`
	License       string            `json:"license"`
	Cases         []c11NegativeCase `json:"cases"`
}

type c11ExpectedOutput struct {
	SchemaVersion   int               `json:"schema_version"`
	Provenance      string            `json:"provenance"`
	License         string            `json:"license"`
	MetadataSHA256  string            `json:"metadata_sha256"`
	PlaintextCanary string            `json:"plaintext_canary"`
	GuardCodes      map[string]string `json:"guard_codes"`
}

func loadC11Fixture(t *testing.T, filename string, target any) {
	t.Helper()
	path := filepath.Join("fixtures", "keyhelix", "C11", filename)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read C11 fixture %s: %v", filename, err)
	}
	if err := json.Unmarshal(data, target); err != nil {
		t.Fatalf("unmarshal C11 fixture %s: %v", filename, err)
	}
}

func assertC11ErrorCode(t *testing.T, err error, expected auth.ErrorCode) {
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

func TestC11_PositiveScopeMapping(t *testing.T) {
	var pos c11PositiveFixture
	loadC11Fixture(t, "positive.json", &pos)

	var exp c11ExpectedOutput
	loadC11Fixture(t, "expected-output.json", &exp)

	// Verify metadata sha256 against expected output
	metadataBytes, err := os.ReadFile(filepath.Join("fixtures", "keyhelix", "C11", pos.MetadataFile))
	if err != nil {
		t.Fatalf("read C11 metadata file: %v", err)
	}
	metaDigest := sha256.Sum256(metadataBytes)
	metaDigestHex := hex.EncodeToString(metaDigest[:])
	if metaDigestHex != exp.MetadataSHA256 {
		t.Fatalf("metadata sha256 mismatch: expected %s, got %s", exp.MetadataSHA256, metaDigestHex)
	}

	mapper := auth.NewScopeMapper(auth.DefaultScopeMapperConfig())
	ctx := context.Background()

	identity := &auth.Identity{
		Subject:       pos.Identity.Subject,
		Email:         pos.Identity.Email,
		VaultRole:     pos.Identity.VaultRole,
		AllowedOwners: pos.Identity.AllowedOwners,
		AllowedScopes: append(pos.Identity.AllowedScopes, pos.Identity.PathScopes...),
		ExpiresAt:     time.Now().Add(1 * time.Hour).Unix(),
	}

	sessionMgr, err := auth.NewSessionManager(auth.DefaultSessionConfig(), nil)
	if err != nil {
		t.Fatalf("create session manager: %v", err)
	}
	sess, _, err := sessionMgr.CreateSession(ctx, identity, auth.ClientInfo{})
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	stepUpMgr, err := auth.NewStepUpManager(auth.DefaultStepUpConfig(), nil)
	if err != nil {
		t.Fatalf("create step-up manager: %v", err)
	}
	_, stepUpTok, err := stepUpMgr.IssueGrant(ctx, sess, auth.ActionRevealSecret, pos.TargetReveal.CanonicalPath)
	if err != nil {
		t.Fatalf("issue step-up grant: %v", err)
	}

	// 1. Positive Reveal Authorization
	revealScope, err := auth.AuthorizeProviderAction(
		ctx,
		mapper,
		identity,
		sess,
		stepUpMgr,
		stepUpTok.Plaintext(),
		pos.TargetReveal.VaultID,
		pos.TargetReveal.SecretPath,
		pos.Identity.Email,
		pos.TargetReveal.Action,
		nil,
	)
	if err != nil {
		t.Fatalf("authorize reveal: %v", err)
	}

	if revealScope.VaultID != pos.TargetReveal.VaultID {
		t.Fatalf("expected vault ID %q, got %q", pos.TargetReveal.VaultID, revealScope.VaultID)
	}
	if revealScope.CanonicalPath != pos.TargetReveal.CanonicalPath {
		t.Fatalf("expected canonical path %q, got %q", pos.TargetReveal.CanonicalPath, revealScope.CanonicalPath)
	}
	if revealScope.KEKID != pos.TargetReveal.ExpectedKEKID {
		t.Fatalf("expected KEK ID %q, got %q", pos.TargetReveal.ExpectedKEKID, revealScope.KEKID)
	}
	if revealScope.ProviderMount != pos.TargetReveal.ExpectedProviderMount {
		t.Fatalf("expected provider mount %q, got %q", pos.TargetReveal.ExpectedProviderMount, revealScope.ProviderMount)
	}
	if len(revealScope.ProviderScopes) != len(pos.TargetReveal.ExpectedProviderScopes) ||
		revealScope.ProviderScopes[0] != pos.TargetReveal.ExpectedProviderScopes[0] {
		t.Fatalf("expected provider scopes %v, got %v", pos.TargetReveal.ExpectedProviderScopes, revealScope.ProviderScopes)
	}

	// 2. Positive Write Authorization (does not require step-up)
	writeScope, err := auth.AuthorizeProviderAction(
		ctx,
		mapper,
		identity,
		sess,
		nil,
		"",
		pos.TargetWrite.VaultID,
		pos.TargetWrite.SecretPath,
		pos.Identity.Email,
		pos.TargetWrite.Action,
		nil,
	)
	if err != nil {
		t.Fatalf("authorize write: %v", err)
	}
	if writeScope.CanonicalPath != pos.TargetWrite.CanonicalPath {
		t.Fatalf("expected canonical path %q, got %q", pos.TargetWrite.CanonicalPath, writeScope.CanonicalPath)
	}
	if len(writeScope.ProviderScopes) != len(pos.TargetWrite.ExpectedProviderScopes) ||
		writeScope.ProviderScopes[0] != pos.TargetWrite.ExpectedProviderScopes[0] {
		t.Fatalf("expected provider scopes %v, got %v", pos.TargetWrite.ExpectedProviderScopes, writeScope.ProviderScopes)
	}
}

func TestC11_NegativeCases_FixtureDriven(t *testing.T) {
	var pos c11PositiveFixture
	loadC11Fixture(t, "positive.json", &pos)

	var neg c11NegativeFixture
	loadC11Fixture(t, "negative.json", &neg)

	mapper := auth.NewScopeMapper(auth.DefaultScopeMapperConfig())
	ctx := context.Background()

	identity := &auth.Identity{
		Subject:       pos.Identity.Subject,
		Email:         pos.Identity.Email,
		VaultRole:     pos.Identity.VaultRole,
		AllowedOwners: pos.Identity.AllowedOwners,
		AllowedScopes: append(pos.Identity.AllowedScopes, pos.Identity.PathScopes...),
		ExpiresAt:     time.Now().Add(1 * time.Hour).Unix(),
	}

	sessionMgr, _ := auth.NewSessionManager(auth.DefaultSessionConfig(), nil)
	sess, _, _ := sessionMgr.CreateSession(ctx, identity, auth.ClientInfo{})

	stepUpMgr, _ := auth.NewStepUpManager(auth.DefaultStepUpConfig(), nil)
	_, stepUpTok, _ := stepUpMgr.IssueGrant(ctx, sess, auth.ActionRevealSecret, pos.TargetReveal.CanonicalPath)

	for _, tc := range neg.Cases {
		t.Run(tc.Case, func(t *testing.T) {
			switch tc.Case {
			case "missing-identity-rejected":
				_, err := mapper.MapUserToProviderScope(
					ctx,
					nil,
					sess,
					nil,
					pos.TargetReveal.VaultID,
					pos.TargetReveal.CanonicalPath,
					pos.Identity.Email,
					tc.Action,
					nil,
				)
				assertC11ErrorCode(t, err, auth.ErrorCode(tc.ExpectedCode))

			case "expired-identity-rejected":
				expired := &auth.Identity{
					Subject:       pos.Identity.Subject,
					Email:         pos.Identity.Email,
					AllowedOwners: pos.Identity.AllowedOwners,
					AllowedScopes: pos.Identity.AllowedScopes,
					ExpiresAt:     time.Now().Add(-10 * time.Minute).Unix(),
				}
				_, err := mapper.MapUserToProviderScope(
					ctx,
					expired,
					nil,
					nil,
					pos.TargetReveal.VaultID,
					pos.TargetReveal.CanonicalPath,
					pos.Identity.Email,
					tc.Action,
					nil,
				)
				assertC11ErrorCode(t, err, auth.ErrorCode(tc.ExpectedCode))

			case "replayed-identity-rejected":
				// Replay guard: stale or mismatched nonce fails before authorization
				oidcConfig := auth.Config{
					IssuerURL:   "https://auth.keyhelix.local",
					ClientID:    "keyhelix-client",
					RedirectURI: "http://localhost:8080/callback",
				}
				provider, err := auth.NewProvider(oidcConfig)
				if err != nil {
					t.Fatalf("create provider: %v", err)
				}
				now := time.Now().UTC()
				token := makeSyntheticJWT(
					map[string]any{"alg": "RS256"},
					map[string]any{
						"iss":   "https://auth.keyhelix.local",
						"aud":   "keyhelix-client",
						"sub":   pos.Identity.Subject,
						"nonce": "stale-replayed-nonce",
						"exp":   now.Add(10 * time.Minute).Unix(),
						"iat":   now.Add(-1 * time.Minute).Unix(),
					},
				)
				_, err = provider.ParseAndVerifyIDToken(token, "fresh-expected-nonce", now)
				assertC11ErrorCode(t, err, auth.ErrorCode(tc.ExpectedCode))

			case "unrelated-owner-denied":
				_, err := mapper.MapUserToProviderScope(
					ctx,
					identity,
					sess,
					nil,
					pos.TargetReveal.VaultID,
					pos.TargetReveal.CanonicalPath,
					tc.TargetOwner,
					tc.Action,
					nil,
				)
				assertC11ErrorCode(t, err, auth.ErrorCode(tc.ExpectedCode))

			case "unrelated-object-scope-denied":
				_, err := mapper.MapUserToProviderScope(
					ctx,
					identity,
					sess,
					nil,
					pos.TargetReveal.VaultID,
					pos.TargetReveal.CanonicalPath,
					tc.TargetOwner,
					tc.Action,
					nil,
				)
				assertC11ErrorCode(t, err, auth.ErrorCode(tc.ExpectedCode))

			case "directory-traversal-cannot-widen-scope",
				"dot-dot-slash-escape-cannot-widen-scope",
				"url-encoded-traversal-rejected":
				_, err := mapper.MapUserToProviderScope(
					ctx,
					identity,
					sess,
					nil,
					pos.TargetReveal.VaultID,
					tc.RawPath,
					pos.Identity.Email,
					"secret:read",
					nil,
				)
				assertC11ErrorCode(t, err, auth.ErrorCode(tc.ExpectedCode))

			case "null-byte-injection-rejected", "backslash-traversal-rejected":
				_, err := mapper.MapUserToProviderScope(
					ctx,
					identity,
					sess,
					nil,
					pos.TargetReveal.VaultID,
					tc.RawPath,
					pos.Identity.Email,
					"secret:read",
					nil,
				)
				assertC11ErrorCode(t, err, auth.ErrorCode(tc.ExpectedCode))

			case "prefix-collision-cannot-widen-scope":
				// Path app/prod-secret must NOT match app/prod/* scope
				_, err := mapper.MapUserToProviderScope(
					ctx,
					identity,
					sess,
					nil,
					pos.TargetReveal.VaultID,
					tc.RawPath,
					pos.Identity.Email,
					"secret:read",
					nil,
				)
				assertC11ErrorCode(t, err, auth.ErrorCode(tc.ExpectedCode))

			case "forged-header-cannot-widen-permissions":
				headers := http.Header{}
				for k, v := range tc.Headers {
					headers.Set(k, v)
				}
				_, err := mapper.MapUserToProviderScope(
					ctx,
					identity,
					sess,
					nil,
					pos.TargetReveal.VaultID,
					pos.TargetReveal.CanonicalPath,
					pos.Identity.Email,
					"secret:read",
					headers,
				)
				assertC11ErrorCode(t, err, auth.ErrorCode(tc.ExpectedCode))

			case "widened-provider-permission-denied":
				_, err := mapper.MapUserToProviderScope(
					ctx,
					identity,
					sess,
					nil,
					tc.TargetVault,
					pos.TargetReveal.CanonicalPath,
					pos.Identity.Email,
					tc.Action,
					nil,
				)
				assertC11ErrorCode(t, err, auth.ErrorCode(tc.ExpectedCode))

			case "identity-provider-unavailable-fails-closed":
				mapper.SetIDPOnline(false)
				defer mapper.SetIDPOnline(true)

				_, err := mapper.MapUserToProviderScope(
					ctx,
					identity,
					sess,
					nil,
					pos.TargetReveal.VaultID,
					pos.TargetReveal.CanonicalPath,
					pos.Identity.Email,
					"secret:read",
					nil,
				)
				assertC11ErrorCode(t, err, auth.ErrorCode(tc.ExpectedCode))

			case "missing-stepup-for-sensitive-action":
				_, err := auth.AuthorizeProviderAction(
					ctx,
					mapper,
					identity,
					sess,
					stepUpMgr,
					"", // missing step-up token
					pos.TargetReveal.VaultID,
					pos.TargetReveal.CanonicalPath,
					pos.Identity.Email,
					tc.Action,
					nil,
				)
				assertC11ErrorCode(t, err, auth.ErrorCode(tc.ExpectedCode))

			case "provider-owns-secret-bytes":
				canary := tc.Canary
				scope, err := auth.AuthorizeProviderAction(
					ctx,
					mapper,
					identity,
					sess,
					stepUpMgr,
					stepUpTok.Plaintext(),
					pos.TargetReveal.VaultID,
					pos.TargetReveal.CanonicalPath,
					pos.Identity.Email,
					pos.TargetReveal.Action,
					nil,
				)
				if err != nil {
					t.Fatalf("unexpected error authorizing action: %v", err)
				}
				scopeJSON, _ := json.Marshal(scope)
				if strings.Contains(string(scopeJSON), canary) {
					t.Fatalf("plaintext canary leaked in EffectiveProviderScope JSON: %s", string(scopeJSON))
				}
				scopeStr := fmt.Sprintf("%v", scope)
				if strings.Contains(scopeStr, canary) {
					t.Fatalf("plaintext canary leaked in scope string representation: %s", scopeStr)
				}
			}
		})
	}
}

func TestC11_PathManipulationMatrix(t *testing.T) {
	permutations := []string{
		"../secret",
		"../../secret",
		"../../../secret",
		"/../secret",
		"app/../dev/secret",
		"app/prod/../../dev/secret",
		"app/prod/../../../etc/passwd",
		"app/prod/..%2fdev/secret",
		"app/prod/%2e%2e/dev/secret",
		"app/prod/%2e%2e%2fdev/secret",
		"app/prod/%252e%252e/dev/secret",
		"app/prod/database-url\x00/attack",
		"app/prod/database-url%00/attack",
		"app\\prod\\database-url",
		"app/prod/..\\..\\dev\\secret",
		"..",
		"....",
		"app/.../secret",
		"app/prod/.",
		"app/prod/./../secret",
		"/app/prod/../../../root",
		"app/prod/%2f../secret",
	}

	for _, p := range permutations {
		t.Run("perm_"+p, func(t *testing.T) {
			_, err := auth.NormalizePath(p)
			if err == nil {
				t.Fatalf("NormalizePath(%q) succeeded; expected rejection for traversal or manipulation", p)
			}
			if !auth.IsErrorCode(err, auth.CodePathTraversal) && !auth.IsErrorCode(err, auth.CodeInvalidPath) {
				t.Fatalf("expected CodePathTraversal or CodeInvalidPath, got: %v", err)
			}
		})
	}
}

func TestC11_ConcurrentScopeResolution(t *testing.T) {
	mapper := auth.NewScopeMapper(auth.DefaultScopeMapperConfig())
	ctx := context.Background()

	identity := &auth.Identity{
		Subject:       "usr_concurrent_alice",
		Email:         "alice@keyhelix.local",
		VaultRole:     "vault-admin",
		AllowedOwners: []string{"alice@keyhelix.local"},
		AllowedScopes: []string{"vault:read", "secret:read", "secret:write", "app/prod/*"},
		ExpiresAt:     time.Now().Add(1 * time.Hour).Unix(),
	}

	sessionMgr, _ := auth.NewSessionManager(auth.DefaultSessionConfig(), nil)
	sess, _, _ := sessionMgr.CreateSession(ctx, identity, auth.ClientInfo{})

	stepUpMgr, _ := auth.NewStepUpManager(auth.DefaultStepUpConfig(), nil)
	_, stepUpTok, _ := stepUpMgr.IssueGrant(ctx, sess, auth.ActionRevealSecret, "app/prod/database-url")

	var wg sync.WaitGroup
	workers := 20
	iterations := 50

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				// Concurrent read / reveal
				scope, err := auth.AuthorizeProviderAction(
					ctx,
					mapper,
					identity,
					sess,
					stepUpMgr,
					stepUpTok.Plaintext(),
					"vault-prod",
					"app/prod/database-url",
					"alice@keyhelix.local",
					"reveal_secret",
					nil,
				)
				if err != nil {
					t.Errorf("worker %d iteration %d failed: %v", workerID, j, err)
					return
				}
				if scope.KEKID != "kek-v1-openbao" {
					t.Errorf("worker %d iteration %d unexpected KEKID: %s", workerID, j, scope.KEKID)
					return
				}

				// Concurrent write
				writeScope, err := auth.AuthorizeProviderAction(
					ctx,
					mapper,
					identity,
					sess,
					nil,
					"",
					"vault-prod",
					"app/prod/api-keys",
					"alice@keyhelix.local",
					"secret:write",
					nil,
				)
				if err != nil {
					t.Errorf("worker %d write iteration %d failed: %v", workerID, j, err)
					return
				}
				if len(writeScope.ProviderScopes) != 1 || writeScope.ProviderScopes[0] != "transit:encrypt" {
					t.Errorf("worker %d unexpected write provider scopes: %v", workerID, writeScope.ProviderScopes)
					return
				}
			}
		}(i)
	}

	wg.Wait()
}
