// Package security provides centralized redaction, sanitization, and leak
// prevention barriers across engine and persistence boundaries (Requirement F09).
//
// Invariants:
//  1. Sentinel secrets never appear in logs, DB, trace, disk or browser storage.
//  2. Cyclic, high-degree or over-limit input terminates with explicit
//     truncation, deadline or cancellation status without unbounded recursion.
//  3. Equivalent reordered input produces deterministic canonical output;
//     a changed semantic fact has a distinct, explainable effect.
//  4. Provider owns secret bytes; engine persistence sinks accept only metadata.
package security

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// Redaction placeholders.
const (
	RedactedPlaceholder  = "[REDACTED]"
	TruncatedPlaceholder = "[TRUNCATED]"
	CyclePlaceholder     = "[CYCLE_DETECTED]"
)

// Default limits to prevent unbounded resource consumption on cyclic or high-degree structures.
const (
	DefaultMaxDepth = 32
	DefaultMaxNodes = 1024
	DefaultMaxBytes = 64 * 1024
)

// Typed security error codes.
const (
	CodeOverLimit              = "OVER_LIMIT"
	CodeCycleDetected          = "CYCLE_DETECTED"
	CodeCancelled              = "CANCELLED"
	CodeTimeout                = "TIMEOUT"
	CodePlaintextLeakDetected  = "PLAINTEXT_LEAK_DETECTED"
	CodeInvalidInput           = "INVALID_INPUT"
)

// Standard sensitive pattern detectors.
var (
	bearerTokenPattern = regexp.MustCompile(`(?i)\b(Bearer\s+)[A-Za-z0-9\-_=.]+`)
	cookieTokenPattern = regexp.MustCompile(`(?i)(keyhelix_session=)[^;\s]+`)
	stepUpTokenPattern = regexp.MustCompile(`(?i)(StepUp\s+|stepup_token=)[A-Za-z0-9\-_=.]+`)
	apiSecretPattern   = regexp.MustCompile(`(?i)("(?:password|secret|token|api[_-]?key|client[_-]?secret)":\s*")[^"]+(")`)
)

// SecurityError represents a typed failure encountered during security scanning or redaction.
type SecurityError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Err     error  `json:"-"`
}

func (e *SecurityError) Error() string {
	if e.Message != "" {
		return e.Code + ": " + e.Message
	}
	return e.Code
}

func (e *SecurityError) Unwrap() error { return e.Err }

// RedactorOptions configures a Redactor instance.
type RedactorOptions struct {
	MaxDepth  int
	MaxNodes  int
	MaxBytes  int
	Sentinels []string
}

// Redactor performs bounded, deterministic sanitization and sentinel leak blocking.
type Redactor struct {
	mu        sync.RWMutex
	sentinels []string
	maxDepth  int
	maxNodes  int
	maxBytes  int
}

// NewRedactor creates a new configured Redactor.
func NewRedactor(opts ...func(*RedactorOptions)) *Redactor {
	cfg := RedactorOptions{
		MaxDepth: DefaultMaxDepth,
		MaxNodes: DefaultMaxNodes,
		MaxBytes: DefaultMaxBytes,
	}
	for _, opt := range opts {
		opt(&cfg)
	}
	return &Redactor{
		sentinels: append([]string(nil), cfg.Sentinels...),
		maxDepth:  cfg.MaxDepth,
		maxNodes:  cfg.MaxNodes,
		maxBytes:  cfg.MaxBytes,
	}
}

// RegisterSentinel adds a known sentinel secret or canary string to the redaction table.
func (r *Redactor) RegisterSentinel(sentinel string) {
	trimmed := strings.TrimSpace(sentinel)
	if trimmed == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, s := range r.sentinels {
		if s == trimmed {
			return
		}
	}
	r.sentinels = append(r.sentinels, trimmed)
}

// RedactString sanitizes a string by replacing registered sentinels and sensitive patterns.
func (r *Redactor) RedactString(ctx context.Context, input string) (string, error) {
	if err := checkContext(ctx); err != nil {
		return "", err
	}
	if len(input) > r.maxBytes {
		return input[:r.maxBytes] + TruncatedPlaceholder, &SecurityError{
			Code:    CodeOverLimit,
			Message: "input string exceeds byte limit",
		}
	}

	r.mu.RLock()
	sentinels := append([]string(nil), r.sentinels...)
	r.mu.RUnlock()

	res := input
	for _, s := range sentinels {
		if s != "" {
			res = strings.ReplaceAll(res, s, RedactedPlaceholder)
		}
	}

	res = bearerTokenPattern.ReplaceAllString(res, "${1}"+RedactedPlaceholder)
	res = cookieTokenPattern.ReplaceAllString(res, "${1}"+RedactedPlaceholder)
	res = stepUpTokenPattern.ReplaceAllString(res, "${1}"+RedactedPlaceholder)
	res = apiSecretPattern.ReplaceAllString(res, "${1}"+RedactedPlaceholder+"${2}")

	return res, nil
}

// RedactBytes sanitizes raw byte slices.
func (r *Redactor) RedactBytes(ctx context.Context, input []byte) ([]byte, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	if len(input) == 0 {
		return input, nil
	}
	redacted, err := r.RedactString(ctx, string(input))
	return []byte(redacted), err
}

// RedactValue recursively sanitizes arbitrary structured data (maps, slices, structs, pointers)
// with cycle detection, depth limits, and node bounds.
func (r *Redactor) RedactValue(ctx context.Context, val any) (any, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	if val == nil {
		return nil, nil
	}

	visited := make(map[uintptr]bool)
	nodeCount := 0
	return r.redactReflect(ctx, reflect.ValueOf(val), visited, 0, &nodeCount)
}

func (r *Redactor) redactReflect(ctx context.Context, val reflect.Value, visited map[uintptr]bool, depth int, nodeCount *int) (any, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}

	*nodeCount++
	if *nodeCount > r.maxNodes {
		return TruncatedPlaceholder, &SecurityError{
			Code:    CodeOverLimit,
			Message: "node count exceeded traversal limit",
		}
	}
	if depth > r.maxDepth {
		return TruncatedPlaceholder, &SecurityError{
			Code:    CodeOverLimit,
			Message: "traversal depth exceeded limit",
		}
	}

	for val.Kind() == reflect.Interface {
		if val.IsNil() {
			return nil, nil
		}
		val = val.Elem()
	}

	switch val.Kind() {
	case reflect.Invalid:
		return nil, nil

	case reflect.Pointer:
		if val.IsNil() {
			return nil, nil
		}
		ptr := val.Pointer()
		if visited[ptr] {
			return CyclePlaceholder, &SecurityError{
				Code:    CodeCycleDetected,
				Message: "cyclic reference detected in pointer graph",
			}
		}
		visited[ptr] = true
		defer delete(visited, ptr)
		return r.redactReflect(ctx, val.Elem(), visited, depth+1, nodeCount)

	case reflect.String:
		redacted, err := r.RedactString(ctx, val.String())
		return redacted, err

	case reflect.Slice, reflect.Array:
		if val.Kind() == reflect.Slice && val.IsNil() {
			return nil, nil
		}
		if val.Type().Elem().Kind() == reflect.Uint8 {
			// Byte slice
			b := val.Bytes()
			return r.RedactBytes(ctx, b)
		}
		n := val.Len()
		out := make([]any, 0, n)
		var combinedErr error
		for i := 0; i < n; i++ {
			elem, err := r.redactReflect(ctx, val.Index(i), visited, depth+1, nodeCount)
			if err != nil && combinedErr == nil {
				combinedErr = err
			}
			out = append(out, elem)
		}
		return out, combinedErr

	case reflect.Map:
		if val.IsNil() {
			return nil, nil
		}
		ptr := val.Pointer()
		if visited[ptr] {
			return CyclePlaceholder, &SecurityError{
				Code:    CodeCycleDetected,
				Message: "cyclic reference detected in map graph",
			}
		}
		visited[ptr] = true
		defer delete(visited, ptr)

		keys := val.MapKeys()
		keyStrs := make([]string, 0, len(keys))
		keyMap := make(map[string]reflect.Value, len(keys))
		for _, k := range keys {
			s := fmt.Sprint(k.Interface())
			keyStrs = append(keyStrs, s)
			keyMap[s] = k
		}
		// Sort keys deterministically
		sort.Strings(keyStrs)

		out := make(map[string]any, len(keys))
		var combinedErr error
		for _, kStr := range keyStrs {
			v := val.MapIndex(keyMap[kStr])
			redactedKey, kErr := r.RedactString(ctx, kStr)
			if kErr != nil && combinedErr == nil {
				combinedErr = kErr
			}
			elem, vErr := r.redactReflect(ctx, v, visited, depth+1, nodeCount)
			if vErr != nil && combinedErr == nil {
				combinedErr = vErr
			}
			out[redactedKey] = elem
		}
		return out, combinedErr

	case reflect.Struct:
		t := val.Type()
		out := make(map[string]any, t.NumField())
		fieldNames := make([]string, 0, t.NumField())
		fieldIndices := make(map[string]int, t.NumField())

		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if !f.IsExported() {
				continue
			}
			name := f.Name
			tag := f.Tag.Get("json")
			if tag != "" {
				parts := strings.Split(tag, ",")
				if parts[0] == "-" {
					continue
				}
				if parts[0] != "" {
					name = parts[0]
				}
			}
			fieldNames = append(fieldNames, name)
			fieldIndices[name] = i
		}
		sort.Strings(fieldNames)

		var combinedErr error
		for _, name := range fieldNames {
			idx := fieldIndices[name]
			fieldVal := val.Field(idx)
			elem, err := r.redactReflect(ctx, fieldVal, visited, depth+1, nodeCount)
			if err != nil && combinedErr == nil {
				combinedErr = err
			}
			out[name] = elem
		}
		return out, combinedErr

	default:
		return val.Interface(), nil
	}
}

// CanonicalJSON marshals a value deterministically with sorted keys.
func CanonicalJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	b := bytes.TrimRight(buf.Bytes(), "\n")
	return b, nil
}

// AssertClean verifies that none of the provided sentinel secrets appear in the data.
func AssertClean(data []byte, sentinels ...string) error {
	str := string(data)
	for _, sentinel := range sentinels {
		if sentinel != "" && strings.Contains(str, sentinel) {
			return &SecurityError{
				Code:    CodePlaintextLeakDetected,
				Message: "sentinel leak detected in persistence payload",
			}
		}
	}
	return nil
}

// AssertDirectoryClean walks a disk directory and asserts that no sentinel appears
// in any non-directory file. Returns the count of files inspected.
func AssertDirectoryClean(dir string, sentinels ...string) (int, error) {
	inspected := 0
	err := filepath.Walk(dir, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil || info.IsDir() {
			return walkErr
		}
		inspected++
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if cleanErr := AssertClean(content, sentinels...); cleanErr != nil {
			return &SecurityError{
				Code:    CodePlaintextLeakDetected,
				Message: fmt.Sprintf("sentinel leak detected in file %s", path),
				Err:     cleanErr,
			}
		}
		return nil
	})
	if err != nil {
		return inspected, err
	}
	return inspected, nil
}

// RedactedWriter wraps an io.Writer to ensure all emitted bytes are scrubbed.
type RedactedWriter struct {
	writer   io.Writer
	redactor *Redactor
}

// NewRedactedWriter wraps an io.Writer with active redaction.
func NewRedactedWriter(w io.Writer, redactor *Redactor) *RedactedWriter {
	return &RedactedWriter{
		writer:   w,
		redactor: redactor,
	}
}

func (rw *RedactedWriter) Write(p []byte) (n int, err error) {
	redacted, _ := rw.redactor.RedactBytes(context.Background(), p)
	_, writeErr := rw.writer.Write(redacted)
	if writeErr != nil {
		return 0, writeErr
	}
	return len(p), nil
}

// EnforceNoStoreHeaders sets HTTP response headers that mandate zero client-side caching.
func EnforceNoStoreHeaders(h http.Header) {
	h.Set("Cache-Control", "no-store, no-cache, must-revalidate")
	h.Set("Pragma", "no-cache")
	h.Set("Expires", "0")
	h.Set("X-Content-Type-Options", "nosniff")
}

// SanitizeHeaders returns a sanitized shallow copy of HTTP headers.
func SanitizeHeaders(h http.Header, redactor *Redactor) http.Header {
	clean := make(http.Header)
	sensitiveHeaders := map[string]bool{
		"authorization":   true,
		"cookie":          true,
		"set-cookie":      true,
		"x-stepup-token":  true,
		"x-api-key":       true,
		"proxy-auth":      true,
	}

	for k, vv := range h {
		lower := strings.ToLower(k)
		for _, v := range vv {
			if sensitiveHeaders[lower] {
				clean.Add(k, RedactedPlaceholder)
			} else {
				redacted, _ := redactor.RedactString(context.Background(), v)
				clean.Add(k, redacted)
			}
		}
	}
	return clean
}

// Zeroize zeroes out a sensitive memory slice to prevent memory dumping exposure.
func Zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func checkContext(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	if err := ctx.Err(); err != nil {
		if errors.Is(err, context.Canceled) {
			return &SecurityError{
				Code:    CodeCancelled,
				Message: "operation cancelled",
				Err:     err,
			}
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return &SecurityError{
				Code:    CodeTimeout,
				Message: "operation deadline exceeded",
				Err:     err,
			}
		}
		return &SecurityError{
			Code:    CodeCancelled,
			Message: err.Error(),
			Err:     err,
		}
	}
	return nil
}
