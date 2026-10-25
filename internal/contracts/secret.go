// Package contracts defines local secret-metadata validation; it does not grant authorization or persist secrets.
package contracts

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"math/big"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	SchemaVersion           = "1"
	MaxInputBytes           = 8192
	MaxSequence       int64 = 9007199254740991
	ValidationTimeout       = 2 * time.Second
)

type ErrorCode string

const (
	InvalidJSON        ErrorCode = "INVALID_JSON"
	UnsupportedVersion ErrorCode = "UNSUPPORTED_VERSION"
	InvalidInput       ErrorCode = "INVALID_INPUT"
	InputTooLarge      ErrorCode = "INPUT_TOO_LARGE"
	InputReadFailed    ErrorCode = "INPUT_READ_FAILED"
	Cancelled          ErrorCode = "CANCELLED"
	Timeout            ErrorCode = "TIMEOUT"
)

type ValidationError struct {
	Code  ErrorCode `json:"code"`
	Field string    `json:"field,omitempty"`
}

func (e *ValidationError) Error() string { return string(e.Code) }

type Envelope struct {
	Algorithm  string `json:"algorithm"`
	WrappedDEK string `json:"wrapped_dek"`
	Nonce      string `json:"nonce"`
	Tag        string `json:"tag"`
	KEKID      string `json:"kek_id"`
}

type SecretMetadata struct {
	SchemaVersion  string   `json:"schema_version"`
	VaultID        string   `json:"vault_id"`
	SecretID       string   `json:"secret_id"`
	SecretPath     string   `json:"secret_path"`
	Version        int64    `json:"version"`
	Classification string   `json:"classification"`
	CreatedAt      string   `json:"created_at"`
	Envelope       Envelope `json:"envelope"`
}

type Outcome struct {
	Valid    bool             `json:"valid"`
	VaultID  string           `json:"vault_id,omitempty"`
	SecretID string           `json:"secret_id,omitempty"`
	Version  *int64           `json:"version,omitempty"`
	Error    *ValidationError `json:"error,omitempty"`
}

type Result struct {
	SchemaVersion string   `json:"schema_version"`
	Status        string   `json:"status"`
	InputDigest   *string  `json:"input_digest"`
	EngineVersion string   `json:"engine_version"`
	Result        Outcome  `json:"result"`
	Warnings      []string `json:"warnings"`
}

func contextError(ctx context.Context) *ValidationError {
	if ctx.Err() == context.DeadlineExceeded {
		return &ValidationError{Code: Timeout}
	}
	if ctx.Err() != nil {
		return &ValidationError{Code: Cancelled}
	}
	return nil
}

func object(ctx context.Context, raw []byte, allowed []string, scope string) (map[string]json.RawMessage, *ValidationError) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return nil, &ValidationError{Code: InvalidJSON}
	}
	fields := make(map[string]json.RawMessage)
	for decoder.More() {
		if failure := contextError(ctx); failure != nil {
			return nil, failure
		}
		key, err := decoder.Token()
		if err != nil {
			return nil, &ValidationError{Code: InvalidJSON}
		}
		name := key.(string)
		if _, exists := fields[name]; exists {
			return nil, &ValidationError{Code: InvalidJSON}
		}
		var value json.RawMessage
		if decoder.Decode(&value) != nil {
			return nil, &ValidationError{Code: InvalidJSON}
		}
		known := false
		for _, field := range allowed {
			if name == field {
				known = true
				break
			}
		}
		if !known {
			return nil, &ValidationError{Code: InvalidInput, Field: scope}
		}
		fields[name] = value
	}
	if _, err := decoder.Token(); err != nil {
		return nil, &ValidationError{Code: InvalidJSON}
	}
	return fields, nil
}

func parseVersion(raw []byte) (int64, bool) {
	number := strings.TrimSpace(string(raw))
	if number == "" || !(number[0] == '-' || number[0] >= '0' && number[0] <= '9') {
		return 0, false
	}
	mantissa, exponent, hasExponent := strings.Cut(strings.ToLower(number), "e")
	if strings.Trim(mantissa, "-0.") == "" {
		return 0, false
	}
	if hasExponent {
		power, err := strconv.Atoi(exponent)
		if err != nil || power < -MaxInputBytes || power > MaxInputBytes {
			return 0, false
		}
	}
	value, ok := new(big.Rat).SetString(number)
	if !ok || !value.IsInt() || !value.Num().IsInt64() {
		return 0, false
	}
	n := value.Num().Int64()
	return n, n >= 1 && n <= MaxSequence
}

var timestamp = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](\.[0-9]+)?(Z|[+-]([01][0-9]|2[0-3]):[0-5][0-9])$`)

func validEscapes(data []byte) bool {
	for i := 0; i < len(data); i++ {
		if data[i] != '\\' {
			continue
		}
		i++
		if data[i] != 'u' {
			continue
		}
		unit, _ := strconv.ParseUint(string(data[i+1:i+5]), 16, 16)
		i += 4
		if unit >= 0xdc00 && unit <= 0xdfff {
			return false
		}
		if unit >= 0xd800 && unit <= 0xdbff {
			if i+6 >= len(data) || data[i+1] != '\\' || data[i+2] != 'u' {
				return false
			}
			low, _ := strconv.ParseUint(string(data[i+3:i+7]), 16, 16)
			if low < 0xdc00 || low > 0xdfff {
				return false
			}
			i += 6
		}
	}
	return true
}

func DecodeSecret(ctx context.Context, data []byte) (SecretMetadata, *ValidationError) {
	var secret SecretMetadata
	if failure := contextError(ctx); failure != nil {
		return secret, failure
	}
	if len(data) > MaxInputBytes {
		return secret, &ValidationError{Code: InputTooLarge}
	}
	if !utf8.Valid(data) || !json.Valid(data) || !validEscapes(data) {
		return secret, &ValidationError{Code: InvalidJSON}
	}
	allowed := []string{
		"schema_version",
		"vault_id",
		"secret_id",
		"secret_path",
		"version",
		"classification",
		"created_at",
		"envelope",
	}
	fields, failure := object(ctx, data, allowed, "")
	if failure != nil {
		return secret, failure
	}
	if json.Unmarshal(fields["schema_version"], &secret.SchemaVersion) != nil || secret.SchemaVersion != SchemaVersion {
		return SecretMetadata{}, &ValidationError{Code: UnsupportedVersion, Field: "schema_version"}
	}
	for _, field := range []string{"vault_id", "secret_id", "secret_path", "version", "classification", "created_at", "envelope"} {
		if _, exists := fields[field]; !exists {
			return SecretMetadata{}, &ValidationError{Code: InvalidInput, Field: field}
		}
	}
	for _, field := range []struct {
		name   string
		target *string
	}{
		{"vault_id", &secret.VaultID},
		{"secret_id", &secret.SecretID},
		{"secret_path", &secret.SecretPath},
		{"classification", &secret.Classification},
		{"created_at", &secret.CreatedAt},
	} {
		if json.Unmarshal(fields[field.name], field.target) != nil {
			return SecretMetadata{}, &ValidationError{Code: InvalidInput, Field: field.name}
		}
	}
	for _, field := range []struct{ name, value string }{
		{"vault_id", secret.VaultID},
		{"secret_id", secret.SecretID},
	} {
		if length := utf8.RuneCountInString(field.value); length < 1 || length > 128 {
			return SecretMetadata{}, &ValidationError{Code: InvalidInput, Field: field.name}
		}
	}
	if length := utf8.RuneCountInString(secret.SecretPath); length < 1 || length > 1024 {
		return SecretMetadata{}, &ValidationError{Code: InvalidInput, Field: "secret_path"}
	}
	switch secret.Classification {
	case "restricted", "confidential", "internal":
	default:
		return SecretMetadata{}, &ValidationError{Code: InvalidInput, Field: "classification"}
	}
	v, ok := parseVersion(fields["version"])
	if !ok {
		return SecretMetadata{}, &ValidationError{Code: InvalidInput, Field: "version"}
	}
	secret.Version = v
	if _, err := time.Parse(time.RFC3339Nano, secret.CreatedAt); err != nil || !timestamp.MatchString(secret.CreatedAt) {
		return SecretMetadata{}, &ValidationError{Code: InvalidInput, Field: "created_at"}
	}
	if !bytes.HasPrefix(bytes.TrimSpace(fields["envelope"]), []byte("{")) {
		return SecretMetadata{}, &ValidationError{Code: InvalidInput, Field: "envelope"}
	}
	envelopeFields, failure := object(ctx, fields["envelope"], []string{"algorithm", "wrapped_dek", "nonce", "tag", "kek_id"}, "envelope")
	if failure != nil {
		return SecretMetadata{}, failure
	}
	for _, field := range []struct {
		name   string
		target *string
	}{
		{"algorithm", &secret.Envelope.Algorithm},
		{"wrapped_dek", &secret.Envelope.WrappedDEK},
		{"nonce", &secret.Envelope.Nonce},
		{"tag", &secret.Envelope.Tag},
		{"kek_id", &secret.Envelope.KEKID},
	} {
		if _, exists := envelopeFields[field.name]; !exists || json.Unmarshal(envelopeFields[field.name], field.target) != nil || *field.target == "" {
			return SecretMetadata{}, &ValidationError{Code: InvalidInput, Field: "envelope"}
		}
	}
	if secret.Envelope.Algorithm != "AES-256-GCM" {
		return SecretMetadata{}, &ValidationError{Code: InvalidInput, Field: "envelope"}
	}
	if length := utf8.RuneCountInString(secret.Envelope.KEKID); length < 1 || length > 128 {
		return SecretMetadata{}, &ValidationError{Code: InvalidInput, Field: "envelope"}
	}
	if failure := contextError(ctx); failure != nil {
		return SecretMetadata{}, failure
	}
	return secret, nil
}

func Validate(ctx context.Context, input io.ReadCloser, engineVersion string) Result {
	defer input.Close()
	result := Result{
		SchemaVersion: SchemaVersion,
		Status:        "failed",
		EngineVersion: engineVersion,
		Warnings:      []string{},
	}
	if failure := contextError(ctx); failure != nil {
		result.Result.Error = failure
		return result
	}
	type readResult struct {
		data []byte
		err  error
	}
	read := make(chan readResult, 1)
	go func() {
		data, err := io.ReadAll(io.LimitReader(input, MaxInputBytes+1))
		read <- readResult{data, err}
	}()
	select {
	case <-ctx.Done():
		result.Result.Error = contextError(ctx)
	case bytes := <-read:
		if failure := contextError(ctx); failure != nil {
			result.Result.Error = failure
			break
		}
		if len(bytes.data) > MaxInputBytes {
			result.Result.Error = &ValidationError{Code: InputTooLarge}
			break
		}
		if bytes.err != nil {
			result.Result.Error = &ValidationError{Code: InputReadFailed}
			break
		}
		hash := sha256.Sum256(bytes.data)
		digest := hex.EncodeToString(hash[:])
		result.InputDigest = &digest
		secret, failure := DecodeSecret(ctx, bytes.data)
		if failure != nil {
			result.Result.Error = failure
			if failure.Code == Cancelled || failure.Code == Timeout {
				result.InputDigest = nil
			}
			break
		}
		result.Status = "unverified"
		result.Result = Outcome{
			Valid:    true,
			VaultID:  secret.VaultID,
			SecretID: secret.SecretID,
			Version:  &secret.Version,
		}
	}
	return result
}
