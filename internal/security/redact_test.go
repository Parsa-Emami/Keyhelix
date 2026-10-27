package security

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRedactStringAndBytes(t *testing.T) {
	redactor := NewRedactor()
	redactor.RegisterSentinel("secret-canary-12345")
	ctx := context.Background()

	input := "Bearer secret-token-xyz with keyhelix_session=sess-abc-789 and secret-canary-12345"
	redacted, err := redactor.RedactString(ctx, input)
	if err != nil {
		t.Fatalf("redact string: %v", err)
	}

	if strings.Contains(redacted, "secret-canary-12345") {
		t.Fatalf("redacted string leaked sentinel: %s", redacted)
	}
	if strings.Contains(redacted, "secret-token-xyz") {
		t.Fatalf("redacted string leaked bearer token: %s", redacted)
	}
	if strings.Contains(redacted, "sess-abc-789") {
		t.Fatalf("redacted string leaked cookie token: %s", redacted)
	}
	if !strings.Contains(redacted, RedactedPlaceholder) {
		t.Fatalf("expected placeholder in redacted string: %s", redacted)
	}

	rawBytes := []byte("secret-canary-12345 in bytes")
	redactedBytes, err := redactor.RedactBytes(ctx, rawBytes)
	if err != nil {
		t.Fatalf("redact bytes: %v", err)
	}
	if strings.Contains(string(redactedBytes), "secret-canary-12345") {
		t.Fatalf("redacted bytes leaked sentinel: %s", string(redactedBytes))
	}
}

func TestRedactOverLimit(t *testing.T) {
	redactor := NewRedactor(func(o *RedactorOptions) {
		o.MaxBytes = 10
	})
	ctx := context.Background()

	_, err := redactor.RedactString(ctx, "this is a very long string exceeding limit")
	if err == nil {
		t.Fatalf("expected error for exceeding byte limit")
	}
	var secErr *SecurityError
	if !errors.As(err, &secErr) || secErr.Code != CodeOverLimit {
		t.Fatalf("expected %s error code, got %v", CodeOverLimit, err)
	}
}

func TestAssertCleanAndDirectoryClean(t *testing.T) {
	sentinel := "sentinel-canary-val-999"

	cleanData := []byte("normal operational data")
	if err := AssertClean(cleanData, sentinel); err != nil {
		t.Fatalf("assert clean failed on clean data: %v", err)
	}

	dirtyData := []byte("data with sentinel-canary-val-999 embedded")
	if err := AssertClean(dirtyData, sentinel); err == nil {
		t.Fatalf("assert clean failed to detect sentinel in dirty data")
	}

	tmpDir := t.TempDir()
	f1 := filepath.Join(tmpDir, "file1.txt")
	if err := os.WriteFile(f1, cleanData, 0600); err != nil {
		t.Fatalf("write file1: %v", err)
	}

	count, err := AssertDirectoryClean(tmpDir, sentinel)
	if err != nil || count != 1 {
		t.Fatalf("assert directory clean: count=%d, err=%v", count, err)
	}

	f2 := filepath.Join(tmpDir, "file2.txt")
	if err := os.WriteFile(f2, dirtyData, 0600); err != nil {
		t.Fatalf("write file2: %v", err)
	}
	_, err = AssertDirectoryClean(tmpDir, sentinel)
	if err == nil {
		t.Fatalf("expected directory scan to catch dirty file2")
	}
}

func TestRedactedWriter(t *testing.T) {
	redactor := NewRedactor()
	redactor.RegisterSentinel("secret-sentinel-abc")

	var buf bytes.Buffer
	writer := NewRedactedWriter(&buf, redactor)

	msg := "Log message with secret-sentinel-abc and Bearer sensitive-token-here\n"
	n, err := writer.Write([]byte(msg))
	if err != nil || n != len(msg) {
		t.Fatalf("write failed: n=%d err=%v", n, err)
	}

	out := buf.String()
	if strings.Contains(out, "secret-sentinel-abc") || strings.Contains(out, "sensitive-token-here") {
		t.Fatalf("writer leaked secret: %s", out)
	}
	if !strings.Contains(out, RedactedPlaceholder) {
		t.Fatalf("writer did not include redacted placeholder: %s", out)
	}
}

func TestEnforceNoStoreHeadersAndSanitizeHeaders(t *testing.T) {
	h := make(http.Header)
	EnforceNoStoreHeaders(h)

	if h.Get("Cache-Control") != "no-store, no-cache, must-revalidate" {
		t.Fatalf("unexpected Cache-Control: %s", h.Get("Cache-Control"))
	}
	if h.Get("Pragma") != "no-cache" || h.Get("Expires") != "0" {
		t.Fatalf("unexpected Pragma/Expires: %s / %s", h.Get("Pragma"), h.Get("Expires"))
	}

	h.Set("Authorization", "Bearer my-secret-token")
	h.Set("Cookie", "keyhelix_session=sess-12345")
	h.Set("X-Custom", "safe-value")

	redactor := NewRedactor()
	clean := SanitizeHeaders(h, redactor)

	if clean.Get("Authorization") != RedactedPlaceholder {
		t.Fatalf("expected redacted Authorization: %s", clean.Get("Authorization"))
	}
	if clean.Get("Cookie") != RedactedPlaceholder {
		t.Fatalf("expected redacted Cookie: %s", clean.Get("Cookie"))
	}
	if clean.Get("X-Custom") != "safe-value" {
		t.Fatalf("expected safe X-Custom: %s", clean.Get("X-Custom"))
	}
}

func TestZeroize(t *testing.T) {
	b := []byte("super-confidential-bytes")
	Zeroize(b)
	for i, v := range b {
		if v != 0 {
			t.Fatalf("byte at index %d is not zero: %d", i, v)
		}
	}
}

func TestContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	redactor := NewRedactor()
	_, err := redactor.RedactString(ctx, "text")
	if err == nil {
		t.Fatalf("expected error on cancelled context")
	}
	var secErr *SecurityError
	if !errors.As(err, &secErr) || secErr.Code != CodeCancelled {
		t.Fatalf("expected %s code, got %v", CodeCancelled, err)
	}

	deadlineCtx, cancelDeadline := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancelDeadline()

	_, err = redactor.RedactValue(deadlineCtx, "text")
	if err == nil {
		t.Fatalf("expected error on timed-out context")
	}
	if !errors.As(err, &secErr) || secErr.Code != CodeTimeout {
		t.Fatalf("expected %s code, got %v", CodeTimeout, err)
	}
}
