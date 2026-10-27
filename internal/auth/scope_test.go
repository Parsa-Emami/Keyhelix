package auth

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestNormalizePath_AntiManipulation(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expected    string
		expectCode  ErrorCode
		shouldError bool
	}{
		{
			name:        "clean canonical path",
			input:       "app/prod/database-url",
			expected:    "app/prod/database-url",
			shouldError: false,
		},
		{
			name:        "leading and trailing slashes normalized",
			input:       "/app/prod/database-url/",
			expected:    "app/prod/database-url",
			shouldError: false,
		},
		{
			name:        "multiple consecutive slashes collapsed",
			input:       "app///prod////database-url",
			expected:    "app/prod/database-url",
			shouldError: false,
		},
		{
			name:        "current directory dot segment rejected",
			input:       "app/./prod/./database-url",
			expectCode:  CodePathTraversal,
			shouldError: true,
		},
		{
			name:        "directory traversal ../ rejected",
			input:       "app/prod/../../../etc/passwd",
			expectCode:  CodePathTraversal,
			shouldError: true,
		},
		{
			name:        "relative traversal within path rejected",
			input:       "app/prod/../dev/secret",
			expectCode:  CodePathTraversal,
			shouldError: true,
		},
		{
			name:        "root traversal rejected",
			input:       "../admin/keys",
			expectCode:  CodePathTraversal,
			shouldError: true,
		},
		{
			name:        "standalone dot-dot rejected",
			input:       "..",
			expectCode:  CodePathTraversal,
			shouldError: true,
		},
		{
			name:        "url-encoded traversal rejected",
			input:       "app/prod/%2e%2e%2fdev/secret",
			expectCode:  CodePathTraversal,
			shouldError: true,
		},
		{
			name:        "double-encoded traversal rejected",
			input:       "app/prod/%252e%252e/dev/secret",
			expectCode:  CodePathTraversal,
			shouldError: true,
		},
		{
			name:        "null byte rejected",
			input:       "app/prod/database-url\x00/inject",
			expectCode:  CodeInvalidPath,
			shouldError: true,
		},
		{
			name:        "encoded null byte rejected",
			input:       "app/prod/database-url%00/inject",
			expectCode:  CodeInvalidPath,
			shouldError: true,
		},
		{
			name:        "backslash rejected",
			input:       "app\\prod\\database-url",
			expectCode:  CodeInvalidPath,
			shouldError: true,
		},
		{
			name:        "empty path rejected",
			input:       "",
			expectCode:  CodeInvalidPath,
			shouldError: true,
		},
		{
			name:        "only slashes rejected",
			input:       "///",
			expectCode:  CodeInvalidPath,
			shouldError: true,
		},
		{
			name:        "path exceeds 1024 runes rejected",
			input:       "app/" + strings.Repeat("a", 1025),
			expectCode:  CodeInvalidPath,
			shouldError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res, err := NormalizePath(tc.input)
			if tc.shouldError {
				if err == nil {
					t.Fatalf("expected error for input %q, got nil result %q", tc.input, res)
				}
				if !IsErrorCode(err, tc.expectCode) {
					t.Fatalf("expected error code %s, got %v", tc.expectCode, err)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error for input %q: %v", tc.input, err)
				}
				if res != tc.expected {
					t.Fatalf("expected %q, got %q", tc.expected, res)
				}
			}
		})
	}
}

func TestMatchPathScope_SegmentBoundary(t *testing.T) {
	tests := []struct {
		name     string
		pattern  string
		target   string
		expected bool
	}{
		{
			name:     "exact match",
			pattern:  "app/prod/database-url",
			target:   "app/prod/database-url",
			expected: true,
		},
		{
			name:     "wildcard suffix matches children",
			pattern:  "app/prod/*",
			target:   "app/prod/database-url",
			expected: true,
		},
		{
			name:     "wildcard suffix matches deep children",
			pattern:  "app/prod/*",
			target:   "app/prod/sub/deep/secret",
			expected: true,
		},
		{
			name:     "prefix collision rejected without segment boundary (app/prod-secret)",
			pattern:  "app/prod/*",
			target:   "app/prod-secret/database-url",
			expected: false,
		},
		{
			name:     "prefix collision rejected without segment boundary (app/production)",
			pattern:  "app/prod/*",
			target:   "app/production",
			expected: false,
		},
		{
			name:     "exact directory pattern does not match sibling prefix",
			pattern:  "app/prod",
			target:   "app/prod-extra",
			expected: false,
		},
		{
			name:     "global wildcard matches everything",
			pattern:  "*",
			target:   "any/arbitrary/path/here",
			expected: true,
		},
		{
			name:     "segment wildcard in middle matches segment",
			pattern:  "app/*/keys",
			target:   "app/prod/keys",
			expected: true,
		},
		{
			name:     "segment wildcard in middle does not match different length",
			pattern:  "app/*/keys",
			target:   "app/prod/sub/keys",
			expected: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := MatchPathScope(tc.pattern, tc.target)
			if got != tc.expected {
				t.Fatalf("MatchPathScope(%q, %q) = %v; want %v", tc.pattern, tc.target, got, tc.expected)
			}
		})
	}
}

func TestValidateRequestHeaders_ForgedHeaders(t *testing.T) {
	forgedHeaders := []string{
		"X-Original-URL",
		"X-Rewrite-URL",
		"X-Forwarded-Prefix",
		"X-Vault-Path",
		"X-Provider-Scope",
		"X-User-Role",
		"X-Remote-User",
		"X-Effective-Scope",
	}

	for _, h := range forgedHeaders {
		t.Run("forged_"+h, func(t *testing.T) {
			reqHeaders := http.Header{}
			reqHeaders.Set(h, "/vaults/admin/keys")

			err := ValidateRequestHeaders(reqHeaders)
			if err == nil {
				t.Fatalf("expected error for forged header %s, got nil", h)
			}
			if !IsErrorCode(err, CodeScopeDenied) {
				t.Fatalf("expected CodeScopeDenied, got: %v", err)
			}
		})
	}

	t.Run("clean headers accepted", func(t *testing.T) {
		reqHeaders := http.Header{}
		reqHeaders.Set("Content-Type", "application/json")
		reqHeaders.Set("Accept", "application/json")
		if err := ValidateRequestHeaders(reqHeaders); err != nil {
			t.Fatalf("unexpected error for clean headers: %v", err)
		}
	})
}

func TestScopeMapper_MapUserToProviderScope(t *testing.T) {
	mapper := NewScopeMapper(DefaultScopeMapperConfig())
	ctx := context.Background()

	identity := &Identity{
		Subject:       "usr_alice",
		Email:         "alice@keyhelix.local",
		VaultRole:     "vault-admin",
		AllowedOwners: []string{"alice@keyhelix.local", "org:platform"},
		AllowedScopes: []string{"vault:read", "secret:read", "secret:write", "app/prod/*"},
		ExpiresAt:     time.Now().Add(1 * time.Hour).Unix(),
	}

	sessionMgr, _ := NewSessionManager(DefaultSessionConfig(), nil)
	sess, _, _ := sessionMgr.CreateSession(ctx, identity, ClientInfo{})

	stepUpMgr, _ := NewStepUpManager(DefaultStepUpConfig(), nil)
	_, stepUpTok, _ := stepUpMgr.IssueGrant(ctx, sess, ActionRevealSecret, "app/prod/database-url")
	grant, _ := stepUpMgr.ValidateStepUp(ctx, sess, stepUpTok.Plaintext(), ActionRevealSecret, "app/prod/database-url")

	t.Run("valid reveal mapped to transit:decrypt", func(t *testing.T) {
		scope, err := mapper.MapUserToProviderScope(
			ctx,
			identity,
			sess,
			grant,
			"vault-prod",
			"app/prod/database-url",
			"alice@keyhelix.local",
			"reveal_secret",
			nil,
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if scope.KEKID != "kek-v1-openbao" {
			t.Fatalf("expected KEKID 'kek-v1-openbao', got %q", scope.KEKID)
		}
		if len(scope.ProviderScopes) != 1 || scope.ProviderScopes[0] != "transit:decrypt" {
			t.Fatalf("expected provider scope ['transit:decrypt'], got %v", scope.ProviderScopes)
		}
		if scope.CanonicalPath != "app/prod/database-url" {
			t.Fatalf("expected canonical path 'app/prod/database-url', got %q", scope.CanonicalPath)
		}
	})

	t.Run("valid write mapped to transit:encrypt without step-up", func(t *testing.T) {
		scope, err := mapper.MapUserToProviderScope(
			ctx,
			identity,
			sess,
			nil, // step-up not required for secret:write
			"vault-prod",
			"app/prod/database-url",
			"alice@keyhelix.local",
			"secret:write",
			nil,
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(scope.ProviderScopes) != 1 || scope.ProviderScopes[0] != "transit:encrypt" {
			t.Fatalf("expected provider scope ['transit:encrypt'], got %v", scope.ProviderScopes)
		}
	})

	t.Run("path manipulation traversal fails closed", func(t *testing.T) {
		_, err := mapper.MapUserToProviderScope(
			ctx,
			identity,
			sess,
			grant,
			"vault-prod",
			"app/prod/../../../etc/shadow",
			"alice@keyhelix.local",
			"reveal_secret",
			nil,
		)
		if !IsErrorCode(err, CodePathTraversal) {
			t.Fatalf("expected CodePathTraversal, got: %v", err)
		}
	})

	t.Run("prefix collision without segment boundary fails closed", func(t *testing.T) {
		_, err := mapper.MapUserToProviderScope(
			ctx,
			identity,
			sess,
			grant,
			"vault-prod",
			"app/prod-secret/database-url",
			"alice@keyhelix.local",
			"reveal_secret",
			nil,
		)
		if !IsErrorCode(err, CodeScopeDenied) {
			t.Fatalf("expected CodeScopeDenied, got: %v", err)
		}
	})

	t.Run("unrelated owner fails closed", func(t *testing.T) {
		_, err := mapper.MapUserToProviderScope(
			ctx,
			identity,
			sess,
			grant,
			"vault-prod",
			"app/prod/database-url",
			"bob@keyhelix.local",
			"reveal_secret",
			nil,
		)
		if !IsErrorCode(err, CodeScopeDenied) {
			t.Fatalf("expected CodeScopeDenied, got: %v", err)
		}
	})

	t.Run("unauthorized foreign vault fails closed", func(t *testing.T) {
		_, err := mapper.MapUserToProviderScope(
			ctx,
			identity,
			sess,
			grant,
			"vault-foreign",
			"app/prod/database-url",
			"alice@keyhelix.local",
			"reveal_secret",
			nil,
		)
		if !IsErrorCode(err, CodeScopeDenied) {
			t.Fatalf("expected CodeScopeDenied, got: %v", err)
		}
	})

	t.Run("idp offline fails closed", func(t *testing.T) {
		mapper.SetIDPOnline(false)
		defer mapper.SetIDPOnline(true)

		_, err := mapper.MapUserToProviderScope(
			ctx,
			identity,
			sess,
			grant,
			"vault-prod",
			"app/prod/database-url",
			"alice@keyhelix.local",
			"reveal_secret",
			nil,
		)
		if !IsErrorCode(err, CodeIDPUnavailable) {
			t.Fatalf("expected CodeIDPUnavailable, got: %v", err)
		}
	})

	t.Run("expired identity fails closed", func(t *testing.T) {
		expiredIdentity := &Identity{
			Subject:       "usr_expired",
			Email:         "expired@keyhelix.local",
			AllowedOwners: []string{"expired@keyhelix.local"},
			AllowedScopes: []string{"secret:read"},
			ExpiresAt:     time.Now().Add(-1 * time.Minute).Unix(),
		}
		_, err := mapper.MapUserToProviderScope(
			ctx,
			expiredIdentity,
			nil,
			nil,
			"vault-prod",
			"app/prod/database-url",
			"expired@keyhelix.local",
			"secret:read",
			nil,
		)
		if !IsErrorCode(err, CodeExpiredToken) {
			t.Fatalf("expected CodeExpiredToken, got: %v", err)
		}
	})
}
