package audit

import (
	"context"
	"testing"
	"time"

	"github.com/parsa-emami/keyhelix/internal/security"
)

func TestNewEventValidation(t *testing.T) {
	// 1. Missing actor fails
	_, err := NewEvent(EventSecretRevealed, "vault/path", AuditData{
		Action:  "reveal",
		Outcome: "success",
	})
	if err == nil {
		t.Fatalf("expected error on missing actor")
	}

	// 2. Missing action fails
	_, err = NewEvent(EventSecretRevealed, "vault/path", AuditData{
		Actor:   "alice@keyhelix.local",
		Outcome: "success",
	})
	if err == nil {
		t.Fatalf("expected error on missing action")
	}

	// 3. Missing outcome fails
	_, err = NewEvent(EventSecretRevealed, "vault/path", AuditData{
		Actor:  "alice@keyhelix.local",
		Action: "reveal",
	})
	if err == nil {
		t.Fatalf("expected error on missing outcome")
	}

	// 4. Unregistered type fails
	_, err = NewEvent("unregistered.custom.v1", "vault/path", AuditData{
		Actor:   "alice@keyhelix.local",
		Action:  "reveal",
		Outcome: "success",
	})
	if err == nil {
		t.Fatalf("expected error on unregistered event type")
	}

	// 5. Valid event succeeds
	evt, err := NewEvent(EventSecretVersionCreated, "vault/path", AuditData{
		Actor:   "alice@keyhelix.local",
		Action:  "secret:write",
		Outcome: "success",
	})
	if err != nil {
		t.Fatalf("unexpected error on valid event: %v", err)
	}
	if evt.SpecVersion != SpecVersion || len(evt.ID) < 16 || evt.Source != DefaultSource {
		t.Fatalf("invalid CloudEvents envelope fields: %+v", evt)
	}
}

func TestRecorderRingBufferAndFind(t *testing.T) {
	redactor := security.NewRedactor()
	recorder := NewRecorder(2, redactor)
	ctx := context.Background()

	evt1, _ := NewEvent(EventSecretVersionCreated, "vault/secret1", AuditData{
		Actor:   "alice@keyhelix.local",
		Action:  "write",
		Outcome: "success",
	})
	evt2, _ := NewEvent(EventSecretRevealed, "vault/secret2", AuditData{
		Actor:   "alice@keyhelix.local",
		Action:  "reveal",
		Outcome: "success",
	})
	evt3, _ := NewEvent(EventGrantCreated, "vault/secret3", AuditData{
		Actor:   "bob@keyhelix.local",
		Action:  "grant",
		Outcome: "success",
	})

	_ = recorder.Record(ctx, evt1)
	_ = recorder.Record(ctx, evt2)
	_ = recorder.Record(ctx, evt3)

	events := recorder.Events()
	if len(events) != 2 {
		t.Fatalf("expected 2 events in ring buffer, got %d", len(events))
	}
	// Oldest (evt1) should be evicted
	if events[0].ID != evt2.ID || events[1].ID != evt3.ID {
		t.Fatalf("ring buffer eviction order mismatch")
	}

	matches := recorder.FindEvents("vault/secret3", EventGrantCreated)
	if len(matches) != 1 || matches[0].ID != evt3.ID {
		t.Fatalf("FindEvents failed: %+v", matches)
	}
}

func TestRecorderScrubbing(t *testing.T) {
	redactor := security.NewRedactor()
	redactor.RegisterSentinel("super-confidential-sentinel-value")
	recorder := NewRecorder(10, redactor)
	ctx := context.Background()

	evt := EventEnvelope{
		SpecVersion:     SpecVersion,
		ID:              NewID(),
		Source:          DefaultSource,
		Type:            EventSecretRevealed,
		Time:            time.Now().UTC().Format(time.RFC3339),
		Subject:         "vault/target",
		DataContentType: ContentTypeJSON,
		Data: map[string]any{
			"actor":  "alice@keyhelix.local",
			"action": "reveal",
			"leak":   "super-confidential-sentinel-value",
		},
	}

	err := recorder.Record(ctx, evt)
	if err != nil {
		t.Fatalf("record failed: %v", err)
	}

	stored := recorder.Events()
	if len(stored) != 1 {
		t.Fatalf("expected 1 event")
	}
	m, ok := stored[0].Data.(map[string]any)
	if !ok || m["leak"] != security.RedactedPlaceholder {
		t.Fatalf("expected leak field to be redacted: %+v", stored[0].Data)
	}
}
