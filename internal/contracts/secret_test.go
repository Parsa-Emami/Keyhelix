package contracts

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"
)

const validJSON = `{
  "schema_version": "1",
  "vault_id": "vault-prod",
  "secret_id": "sec-01",
  "secret_path": "app/prod/database-url",
  "version": 1,
  "classification": "restricted",
  "created_at": "2026-01-01T00:00:00Z",
  "envelope": {
    "algorithm": "AES-256-GCM",
    "wrapped_dek": "synthetic-wrapped-dek",
    "nonce": "synthetic-nonce",
    "tag": "synthetic-tag",
    "kek_id": "kek-v1-openbao"
  }
}`

func TestValidateSecretPositive(t *testing.T) {
	ctx := context.Background()
	result := Validate(ctx, io.NopCloser(strings.NewReader(validJSON)), "0.0.1")
	if result.Status != "unverified" || !result.Result.Valid {
		t.Fatalf("expected unverified valid result, got %+v", result)
	}
	if result.Result.VaultID != "vault-prod" || result.Result.SecretID != "sec-01" || *result.Result.Version != 1 {
		t.Fatalf("unexpected result fields: %+v", result.Result)
	}
}

func TestValidateSecretRejectsOversized(t *testing.T) {
	ctx := context.Background()
	huge := strings.Repeat("a", MaxInputBytes+10)
	result := Validate(ctx, io.NopCloser(strings.NewReader(huge)), "0.0.1")
	if result.Status != "failed" || result.Result.Error == nil || result.Result.Error.Code != InputTooLarge {
		t.Fatalf("expected INPUT_TOO_LARGE, got %+v", result)
	}
}

func TestValidateSecretRejectsDuplicateKeys(t *testing.T) {
	ctx := context.Background()
	dup := `{
  "schema_version": "1",
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
    "kek_id": "kek"
  }
}`
	result := Validate(ctx, io.NopCloser(strings.NewReader(dup)), "0.0.1")
	if result.Status != "failed" || result.Result.Error == nil || result.Result.Error.Code != InvalidJSON {
		t.Fatalf("expected INVALID_JSON for duplicate keys, got %+v", result)
	}
}

func TestValidateSecretTimeoutAndCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result := Validate(ctx, io.NopCloser(strings.NewReader(validJSON)), "0.0.1")
	if result.Status != "failed" || result.Result.Error == nil || result.Result.Error.Code != Cancelled {
		t.Fatalf("expected CANCELLED, got %+v", result)
	}

	ctxTimeout, cancelTimeout := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancelTimeout()
	time.Sleep(time.Millisecond)
	resultTimeout := Validate(ctxTimeout, io.NopCloser(strings.NewReader(validJSON)), "0.0.1")
	if resultTimeout.Status != "failed" || resultTimeout.Result.Error == nil || resultTimeout.Result.Error.Code != Timeout {
		t.Fatalf("expected TIMEOUT, got %+v", resultTimeout)
	}
}
