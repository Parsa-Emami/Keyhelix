package provider_test

import (
	"errors"
	"testing"

	"github.com/parsa-emami/keyhelix/internal/provider"
)

func TestWorkloadIdentityHasScope(t *testing.T) {
	cases := []struct {
		name     string
		scopes   []string
		required string
		expected bool
	}{
		{
			name:     "exact-match",
			scopes:   []string{"transit:encrypt", "transit:decrypt"},
			required: "transit:encrypt",
			expected: true,
		},
		{
			name:     "wildcard-all",
			scopes:   []string{"*"},
			required: "transit:encrypt",
			expected: true,
		},
		{
			name:     "prefix-wildcard",
			scopes:   []string{"transit:*"},
			required: "transit:decrypt",
			expected: true,
		},
		{
			name:     "no-match",
			scopes:   []string{"audit:read"},
			required: "transit:encrypt",
			expected: false,
		},
		{
			name:     "empty-scopes",
			scopes:   []string{},
			required: "transit:encrypt",
			expected: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			id := provider.WorkloadIdentity{
				Role:   "test-role",
				Token:  "s.token",
				Scopes: tc.scopes,
			}
			if actual := id.HasScope(tc.required); actual != tc.expected {
				t.Fatalf("scope check mismatch for %s: got %v want %v", tc.required, actual, tc.expected)
			}
		})
	}
}

func TestProviderErrorFormattingAndUnwrap(t *testing.T) {
	rootErr := errors.New("underlying network failure")
	provErr := &provider.Error{
		Code:    provider.CodeProviderUnavailable,
		Message: "dial tcp timeout",
		Err:     rootErr,
	}

	if provErr.Error() != "PROVIDER_UNAVAILABLE: dial tcp timeout" {
		t.Fatalf("unexpected error format: %s", provErr.Error())
	}
	if !errors.Is(provErr, rootErr) {
		t.Fatal("expected unwrap to match root error")
	}

	codeOnlyErr := &provider.Error{
		Code: provider.CodeDevModeRefused,
	}
	if codeOnlyErr.Error() != "DEV_MODE_REFUSED" {
		t.Fatalf("unexpected code-only error format: %s", codeOnlyErr.Error())
	}
}
