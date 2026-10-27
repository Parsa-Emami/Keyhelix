// Package audit provides attributable metadata audit event emission and recording
// adhering to the CloudEvents 1.0 profile (Requirement F10).
//
// Invariants:
//  1. Actor, provider action and outcome exist on every emitted audit event.
//  2. Plaintext secret values, canaries, and bearer credentials are strictly excluded.
//  3. Envelopes comply with CloudEvents 1.0 profile declared in AsyncAPI contracts.
package audit

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/parsa-emami/keyhelix/internal/security"
)

// CloudEvents 1.0 Constants.
const (
	SpecVersion     = "1.0"
	ContentTypeJSON = "application/json"
	DefaultSource   = "/keyhelix/engine"
)

// Registered event types matching contracts/event-types.v1.json and AsyncAPI schema.
const (
	EventSecretVersionCreated  = "secret.version_created.v1"
	EventSecretRevealed        = "secret.revealed.v1"
	EventGrantCreated          = "grant.created.v1"
	EventGrantRevoked          = "grant.revoked.v1"
	EventKeyRotationStarted    = "key.rotation_started.v1"
	EventKeyEnvelopeRewrapped  = "key.envelope_rewrapped.v1"
	EventKeyRotationCompleted  = "key.rotation_completed.v1"
	EventAuditCheckpointSigned = "audit.checkpoint_signed.v1"
)

var validEventTypes = map[string]bool{
	EventSecretVersionCreated:  true,
	EventSecretRevealed:        true,
	EventGrantCreated:          true,
	EventGrantRevoked:          true,
	EventKeyRotationStarted:    true,
	EventKeyEnvelopeRewrapped:  true,
	EventKeyRotationCompleted:  true,
	EventAuditCheckpointSigned: true,
}

// Error codes for audit operations.
const (
	CodeInvalidEvent     = "INVALID_EVENT"
	CodeAuditLeakBlocked = "AUDIT_LEAK_BLOCKED"
)

// AuditError represents a typed failure during audit validation or emission.
type AuditError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Err     error  `json:"-"`
}

func (e *AuditError) Error() string {
	if e.Message != "" {
		return e.Code + ": " + e.Message
	}
	return e.Code
}

func (e *AuditError) Unwrap() error { return e.Err }

// EventEnvelope is a CloudEvents-compatible 1.0 envelope matching AsyncAPI EventEnvelope schema.
type EventEnvelope struct {
	SpecVersion     string  `json:"specversion"`
	ID              string  `json:"id"`
	Source          string  `json:"source"`
	Type            string  `json:"type"`
	Time            string  `json:"time"`
	Subject         string  `json:"subject"`
	DataContentType string  `json:"datacontenttype"`
	Data            any     `json:"data"`
	TraceParent     *string `json:"traceparent,omitempty"`
}

// AuditData carries attributable action metadata without secrets or credentials.
type AuditData struct {
	Actor          string         `json:"actor"`
	VaultID        string         `json:"vault_id,omitempty"`
	SecretPath     string         `json:"secret_path,omitempty"`
	Version        int64          `json:"version,omitempty"`
	Classification string         `json:"classification,omitempty"`
	Action         string         `json:"action"`
	Outcome        string         `json:"outcome"`
	Details        map[string]any `json:"details,omitempty"`
}

// NewID generates a cryptographic hex identifier of at least 16 characters for CloudEvents.
func NewID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// NewEvent constructs a validated CloudEvents 1.0 envelope for attributable audit metadata.
func NewEvent(eventType, subject string, data AuditData) (EventEnvelope, error) {
	if !validEventTypes[eventType] {
		return EventEnvelope{}, &AuditError{
			Code:    CodeInvalidEvent,
			Message: fmt.Sprintf("unregistered event type: %s", eventType),
		}
	}
	if strings.TrimSpace(subject) == "" {
		return EventEnvelope{}, &AuditError{
			Code:    CodeInvalidEvent,
			Message: "subject is required",
		}
	}
	if strings.TrimSpace(data.Actor) == "" {
		return EventEnvelope{}, &AuditError{
			Code:    CodeInvalidEvent,
			Message: "actor is required for attributable audit events",
		}
	}
	if strings.TrimSpace(data.Action) == "" {
		return EventEnvelope{}, &AuditError{
			Code:    CodeInvalidEvent,
			Message: "action is required for attributable audit events",
		}
	}
	if strings.TrimSpace(data.Outcome) == "" {
		return EventEnvelope{}, &AuditError{
			Code:    CodeInvalidEvent,
			Message: "outcome is required for attributable audit events",
		}
	}

	return EventEnvelope{
		SpecVersion:     SpecVersion,
		ID:              NewID(),
		Source:          DefaultSource,
		Type:            eventType,
		Time:            time.Now().UTC().Format(time.RFC3339Nano),
		Subject:         subject,
		DataContentType: ContentTypeJSON,
		Data:            data,
	}, nil
}

// Recorder is a bounded in-memory audit log recorder and sanitizer.
type Recorder struct {
	mu        sync.RWMutex
	events    []EventEnvelope
	maxEvents int
	redactor  *security.Redactor
}

// NewRecorder constructs a new bounded audit Recorder.
func NewRecorder(maxEvents int, redactor *security.Redactor) *Recorder {
	if maxEvents <= 0 {
		maxEvents = 1000
	}
	if redactor == nil {
		redactor = security.NewRedactor()
	}
	return &Recorder{
		events:    make([]EventEnvelope, 0, maxEvents),
		maxEvents: maxEvents,
		redactor:  redactor,
	}
}

// Record validates, scrubs, and records an audit event.
func (r *Recorder) Record(ctx context.Context, evt EventEnvelope) error {
	if evt.SpecVersion != SpecVersion {
		return &AuditError{Code: CodeInvalidEvent, Message: "specversion must be 1.0"}
	}
	if len(evt.ID) < 16 {
		return &AuditError{Code: CodeInvalidEvent, Message: "event id must be at least 16 characters"}
	}
	if !validEventTypes[evt.Type] {
		return &AuditError{Code: CodeInvalidEvent, Message: "unsupported event type"}
	}
	if strings.TrimSpace(evt.Subject) == "" {
		return &AuditError{Code: CodeInvalidEvent, Message: "subject cannot be empty"}
	}
	if evt.Data == nil {
		return &AuditError{Code: CodeInvalidEvent, Message: "event data cannot be nil"}
	}

	// Sanitize data using security.Redactor to guarantee zero secret leak
	sanitizedData, err := r.redactor.RedactValue(ctx, evt.Data)
	if err != nil {
		var secErr *security.SecurityError
		if errors.As(err, &secErr) {
			return &AuditError{Code: secErr.Code, Message: secErr.Message, Err: err}
		}
		return &AuditError{Code: CodeInvalidEvent, Message: err.Error(), Err: err}
	}

	// Verify that the sanitized data JSON contains no registered sentinel or raw token patterns
	marshaled, err := json.Marshal(sanitizedData)
	if err != nil {
		return &AuditError{Code: CodeInvalidEvent, Message: "failed to marshal event data", Err: err}
	}
	if err := security.AssertClean(marshaled); err != nil {
		return &AuditError{Code: CodeAuditLeakBlocked, Message: "prohibited sensitive token pattern detected in audit data"}
	}

	evt.Data = sanitizedData

	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.events) >= r.maxEvents {
		// Evict oldest (ring buffer behavior)
		r.events = r.events[1:]
	}
	r.events = append(r.events, evt)
	return nil
}

// Events returns a copy of all recorded audit events.
func (r *Recorder) Events() []EventEnvelope {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]EventEnvelope, len(r.events))
	copy(out, r.events)
	return out
}

// FindEvents returns recorded events matching subject and eventType.
func (r *Recorder) FindEvents(subject, eventType string) []EventEnvelope {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var matches []EventEnvelope
	for _, e := range r.events {
		if (subject == "" || e.Subject == subject) && (eventType == "" || e.Type == eventType) {
			matches = append(matches, e)
		}
	}
	return matches
}
