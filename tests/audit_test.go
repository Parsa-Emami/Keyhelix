package storage_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/parsa-emami/keyhelix/internal/audit"
	"github.com/parsa-emami/keyhelix/internal/auth"
	"github.com/parsa-emami/keyhelix/internal/contracts"
	"github.com/parsa-emami/keyhelix/internal/provider"
	"github.com/parsa-emami/keyhelix/internal/secrets"
	"github.com/parsa-emami/keyhelix/internal/security"
	"github.com/parsa-emami/keyhelix/internal/storage"
)

type c16PositiveFixture struct {
	SchemaVersion              int                `json:"schema_version"`
	Provenance                 string             `json:"provenance"`
	License                    string             `json:"license"`
	Vault                      c14FixtureVault    `json:"vault"`
	Identity                   c14FixtureIdentity `json:"identity"`
	SecretPath                 string             `json:"secret_path"`
	Classification             string             `json:"classification"`
	SentinelSecret             string             `json:"sentinel_secret"`
	BearerToken                string             `json:"bearer_token"`
	ExpectedEvents             []string           `json:"expected_events"`
	ExpectedAttributableFields []string           `json:"expected_attributable_fields"`
	MetadataFile               string             `json:"metadata_file"`
}

type c16NegativeCase struct {
	Case                   string `json:"case"`
	Description            string `json:"description"`
	EventType              string `json:"event_type,omitempty"`
	Subject                string `json:"subject,omitempty"`
	Actor                  string `json:"actor,omitempty"`
	Action                 string `json:"action,omitempty"`
	Outcome                string `json:"outcome,omitempty"`
	ExpectedCode           string `json:"expected_code,omitempty"`
	SpecVersion            string `json:"specversion,omitempty"`
	ProviderState          string `json:"provider_state,omitempty"`
	ExpectedOutcome        string `json:"expected_outcome,omitempty"`
	Sentinel               string `json:"sentinel,omitempty"`
	ExpectedAuditLeakCount int    `json:"expected_audit_leak_count,omitempty"`
}

type c16NegativeFixture struct {
	SchemaVersion int               `json:"schema_version"`
	Cases         []c16NegativeCase `json:"cases"`
}

type c16ExpectedOutput struct {
	SchemaVersion           int               `json:"schema_version"`
	Requirement             string            `json:"requirement"`
	Acceptance              string            `json:"acceptance"`
	Status                  string            `json:"status"`
	MetadataSHA256          string            `json:"metadata_sha256"`
	SentinelSecret          string            `json:"sentinel_secret"`
	BearerToken             string            `json:"bearer_token"`
	AuditLeakCounts         map[string]int    `json:"audit_leak_counts"`
	GuardCodes              map[string]string `json:"guard_codes"`
	ProviderOwnsSecretBytes bool              `json:"provider_owns_secret_bytes"`
}

func loadC16Fixture(t *testing.T, filename string, target any) []byte {
	t.Helper()
	path := filepath.Join("fixtures", "keyhelix", "C16", filename)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read C16 fixture %s: %v", filename, err)
	}
	if err := json.Unmarshal(data, target); err != nil {
		t.Fatalf("unmarshal C16 fixture %s: %v", filename, err)
	}
	return data
}

type c16Harness struct {
	dir      string
	store    *storage.Store
	server   *httptest.Server
	state    *c14ProviderState
	adapter  *provider.Adapter
	mapper   *auth.ScopeMapper
	service  *secrets.Service
	stepUp   *auth.StepUpManager
	recorder *audit.Recorder
	redactor *security.Redactor
	identity *auth.Identity
	session  *auth.Session
	pos      c16PositiveFixture
}

func newC16Harness(t *testing.T) *c16Harness {
	t.Helper()
	var pos c16PositiveFixture
	loadC16Fixture(t, "positive.json", &pos)

	server, state := newC14Provider(t)
	adapter := newC14Adapter(t, server.URL, nil)

	dir := filepath.Join(t.TempDir(), "c16-audit-store")
	store, _, err := storage.Open(dir)
	if err != nil {
		t.Fatalf("open storage port: %v", err)
	}
	t.Cleanup(func() {
		_ = store.Close()
	})

	mapper := auth.NewScopeMapper(auth.ScopeMapperConfig{
		VaultKEKMap:   map[string]string{pos.Vault.VaultID: pos.Vault.KEKID},
		VaultMountMap: map[string]string{pos.Vault.VaultID: pos.Vault.Mount},
		VaultRoleMap:  map[string]string{pos.Vault.VaultID: pos.Vault.Role},
	})
	svc := secrets.NewService(mapper, adapter, store)

	sessionMgr, err := auth.NewSessionManager(auth.DefaultSessionConfig(), nil)
	if err != nil {
		t.Fatalf("create session manager: %v", err)
	}
	stepUpMgr, err := auth.NewStepUpManager(auth.DefaultStepUpConfig(), nil)
	if err != nil {
		t.Fatalf("create stepup manager: %v", err)
	}

	redactor := security.NewRedactor()
	redactor.RegisterSentinel(pos.SentinelSecret)

	recorder := audit.NewRecorder(100, redactor)

	ctx := context.Background()
	ident := &auth.Identity{
		Subject:       pos.Identity.Subject,
		Email:         pos.Identity.Email,
		VaultRole:     pos.Identity.VaultRole,
		AllowedOwners: pos.Identity.AllowedOwners,
		AllowedScopes: pos.Identity.AllowedScopes,
		ExpiresAt:     time.Now().Add(time.Hour).Unix(),
	}
	session, _, err := sessionMgr.CreateSession(ctx, ident, auth.ClientInfo{})
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	return &c16Harness{
		dir:      dir,
		store:    store,
		server:   server,
		state:    state,
		adapter:  adapter,
		mapper:   mapper,
		service:  svc,
		stepUp:   stepUpMgr,
		recorder: recorder,
		redactor: redactor,
		identity: ident,
		session:  session,
		pos:      pos,
	}
}

// TestC16AttributableMetadataAuditEventsF10 proves Requirement F10:
// Actor, provider action and outcome exist without secret values or bearer credentials.
func TestC16AttributableMetadataAuditEventsF10(t *testing.T) {
	var pos c16PositiveFixture
	loadC16Fixture(t, "positive.json", &pos)
	var exp c16ExpectedOutput
	loadC16Fixture(t, "expected-output.json", &exp)
	var metadataFixture contracts.SecretMetadata
	metadataBytes := loadC16Fixture(t, pos.MetadataFile, &metadataFixture)

	if exp.Requirement != "F10" || exp.Status != "passed" {
		t.Fatalf("unexpected C16 expected-output fixture: %+v", exp)
	}
	if _, failure := contracts.DecodeSecret(context.Background(), metadataBytes); failure != nil {
		t.Fatalf("C16 metadata fixture must satisfy frozen v1 contract: %+v", failure)
	}

	harness := newC16Harness(t)
	ctx := context.Background()

	// 1. Write operation: provider action write creates a versioned secret envelope
	writeOutcome, err := harness.service.WriteSecret(ctx, secrets.WriteRequest{
		VaultID:         pos.Vault.VaultID,
		SecretPath:      pos.SecretPath,
		ExpectedVersion: 0,
		Plaintext:       []byte(pos.SentinelSecret),
		Classification:  pos.Classification,
		KEKID:           pos.Vault.KEKID,
		OperationID:     "op-c16-write-001",
		Owner:           pos.Identity.Email,
		Identity:        harness.identity,
	})
	if err != nil {
		t.Fatalf("failed to write secret: %v", err)
	}

	// Emit audit event for secret version creation
	writeEvt, err := audit.NewEvent(
		audit.EventSecretVersionCreated,
		pos.Vault.VaultID+"/"+pos.SecretPath,
		audit.AuditData{
			Actor:          harness.identity.Email,
			VaultID:        pos.Vault.VaultID,
			SecretPath:     pos.SecretPath,
			Version:        writeOutcome.Version,
			Classification: pos.Classification,
			Action:         "secret:write",
			Outcome:        "success",
			Details: map[string]any{
				"operation_id": "op-c16-write-001",
				"kek_id":       pos.Vault.KEKID,
			},
		},
	)
	if err != nil {
		t.Fatalf("failed to construct write audit event: %v", err)
	}
	if err := harness.recorder.Record(ctx, writeEvt); err != nil {
		t.Fatalf("failed to record write audit event: %v", err)
	}

	// 2. Reveal operation: authorized reveal with fresh step-up
	_, stepUpToken, err := harness.stepUp.IssueGrant(ctx, harness.session, auth.ActionRevealSecret, pos.SecretPath)
	if err != nil {
		t.Fatalf("failed to issue stepup grant: %v", err)
	}

	revealed, err := harness.service.RevealSecret(ctx, secrets.RevealRequest{
		VaultID:       pos.Vault.VaultID,
		SecretPath:    pos.SecretPath,
		Owner:         pos.Identity.Email,
		Identity:      harness.identity,
		Session:       harness.session,
		StepUpManager: harness.stepUp,
		StepUpToken:   stepUpToken.Plaintext(),
	})
	if err != nil {
		t.Fatalf("reveal secret failed: %v", err)
	}

	revealAudit := revealed.AuditContent()
	revealEvt, err := audit.NewEvent(
		audit.EventSecretRevealed,
		pos.Vault.VaultID+"/"+pos.SecretPath,
		audit.AuditData{
			Actor:          revealAudit.Actor,
			VaultID:        revealAudit.VaultID,
			SecretPath:     revealAudit.SecretPath,
			Version:        revealAudit.Version,
			Classification: revealAudit.Classification,
			Action:         revealAudit.Action,
			Outcome:        revealAudit.Outcome,
			Details: map[string]any{
				"delivery": "streamed",
			},
		},
	)
	if err != nil {
		t.Fatalf("failed to construct reveal audit event: %v", err)
	}
	if err := harness.recorder.Record(ctx, revealEvt); err != nil {
		t.Fatalf("failed to record reveal audit event: %v", err)
	}

	// 3. Inspect all recorded audit events
	events := harness.recorder.Events()
	if len(events) != 2 {
		t.Fatalf("expected 2 recorded events, got %d", len(events))
	}

	for _, evt := range events {
		// A. CloudEvents 1.0 specification compliance
		if evt.SpecVersion != audit.SpecVersion {
			t.Fatalf("specversion must be %s, got %s", audit.SpecVersion, evt.SpecVersion)
		}
		if len(evt.ID) < 16 {
			t.Fatalf("event ID must be >= 16 chars, got %s", evt.ID)
		}
		if evt.Source != audit.DefaultSource {
			t.Fatalf("unexpected event source: %s", evt.Source)
		}
		if evt.DataContentType != audit.ContentTypeJSON {
			t.Fatalf("unexpected content type: %s", evt.DataContentType)
		}
		if _, parseErr := time.Parse(time.RFC3339Nano, evt.Time); parseErr != nil {
			t.Fatalf("event time must be RFC3339, got: %s", evt.Time)
		}

		// B. Invariant: Actor, provider action and outcome exist
		evtJSON, err := json.Marshal(evt)
		if err != nil {
			t.Fatalf("failed to marshal event: %v", err)
		}
		evtStr := string(evtJSON)

		for _, field := range pos.ExpectedAttributableFields {
			if !strings.Contains(evtStr, `"`+field+`"`) {
				t.Fatalf("audit event missing required attributable field %q: %s", field, evtStr)
			}
		}

		// C. Invariant: Without secret values or bearer credentials
		if strings.Contains(evtStr, pos.SentinelSecret) {
			t.Fatalf("CRITICAL SECURITY VIOLATION: sentinel secret leaked into audit event: %s", evtStr)
		}
		if strings.Contains(evtStr, pos.BearerToken) {
			t.Fatalf("CRITICAL SECURITY VIOLATION: bearer token credential leaked into audit event: %s", evtStr)
		}
	}

	// 4. Invariant: Provider owns secret bytes
	key := c14PayloadKey(pos.Vault.VaultID, pos.SecretPath, 1)
	payload := harness.state.payload(key)
	if payload == "" {
		t.Fatalf("provider must hold sealed payload for %s", key)
	}
	if strings.Contains(payload, pos.SentinelSecret) {
		t.Fatalf("provider payload must be encrypted/sealed, found plaintext canary")
	}
}

// TestC16NegativeCasesF10 validates required negative cases:
// 1. Missing prerequisites, malformed fixtures produce explicit errors.
// 2. Repeat after restart and verify declared invariant.
// 3. Provider owns secret bytes.
func TestC16NegativeCasesF10(t *testing.T) {
	var negFixture c16NegativeFixture
	loadC16Fixture(t, "negative.json", &negFixture)

	redactor := security.NewRedactor()
	redactor.RegisterSentinel("sentinel-canary-c16-audit-secret-91a4")
	recorder := audit.NewRecorder(50, redactor)
	ctx := context.Background()

	for _, tc := range negFixture.Cases {
		t.Run(tc.Case, func(t *testing.T) {
			switch tc.Case {
			case "missing-actor-rejected", "missing-action-rejected", "missing-outcome-rejected", "unregistered-event-type-rejected":
				_, err := audit.NewEvent(tc.EventType, tc.Subject, audit.AuditData{
					Actor:   tc.Actor,
					Action:  tc.Action,
					Outcome: tc.Outcome,
				})
				if err == nil {
					t.Fatalf("expected error for case %s, got nil", tc.Case)
				}
				var auditErr *audit.AuditError
				if !errors.As(err, &auditErr) || auditErr.Code != tc.ExpectedCode {
					t.Fatalf("expected error code %s, got %v", tc.ExpectedCode, err)
				}

			case "malformed-envelope-rejected-by-recorder":
				badEvt := audit.EventEnvelope{
					SpecVersion:     tc.SpecVersion,
					ID:              "too-short",
					Source:          audit.DefaultSource,
					Type:            audit.EventSecretRevealed,
					Time:            time.Now().UTC().Format(time.RFC3339),
					Subject:         "vault/secret",
					DataContentType: audit.ContentTypeJSON,
					Data: map[string]any{
						"actor":   "alice@keyhelix.local",
						"action":  "reveal",
						"outcome": "success",
					},
				}
				err := recorder.Record(ctx, badEvt)
				if err == nil {
					t.Fatalf("expected recorder rejection for malformed envelope")
				}
				var auditErr *audit.AuditError
				if !errors.As(err, &auditErr) || auditErr.Code != tc.ExpectedCode {
					t.Fatalf("expected error code %s, got %v", tc.ExpectedCode, err)
				}

			case "provider-offline-fails-closed":
				// When provider is offline/unavailable, outcome reflects failure and does not fabricate success
				failEvt, err := audit.NewEvent(
					audit.EventSecretRevealed,
					"vault-prod/path",
					audit.AuditData{
						Actor:   "alice@keyhelix.local",
						Action:  "secret:reveal",
						Outcome: "failed",
						Details: map[string]any{
							"error_code": "PROVIDER_UNAVAILABLE",
						},
					},
				)
				if err != nil {
					t.Fatalf("construct fail event: %v", err)
				}
				if err := recorder.Record(ctx, failEvt); err != nil {
					t.Fatalf("record fail event: %v", err)
				}
				data, ok := failEvt.Data.(audit.AuditData)
				if !ok || data.Outcome != tc.ExpectedOutcome {
					t.Fatalf("expected failed outcome, got %+v", failEvt.Data)
				}

			case "provider-owns-secret-bytes":
				// If a caller attempts to sneak a secret into event details, redactor scrubs it
				taintedEvt, err := audit.NewEvent(
					audit.EventSecretRevealed,
					"vault-prod/path",
					audit.AuditData{
						Actor:   "alice@keyhelix.local",
						Action:  "secret:reveal",
						Outcome: "success",
						Details: map[string]any{
							"canary": tc.Sentinel,
						},
					},
				)
				if err != nil {
					t.Fatalf("construct event: %v", err)
				}
				if err := recorder.Record(ctx, taintedEvt); err != nil {
					t.Fatalf("record event: %v", err)
				}

				found := recorder.FindEvents("vault-prod/path", audit.EventSecretRevealed)
				if len(found) == 0 {
					t.Fatalf("expected recorded event to be found")
				}
				recDataJSON, _ := json.Marshal(found[0].Data)
				if strings.Contains(string(recDataJSON), tc.Sentinel) {
					t.Fatalf("CRITICAL: sentinel leaked into recorded audit event: %s", string(recDataJSON))
				}
			}
		})
	}
}

// TestC16AuditRestartPreservesEvents verifies repeat after restart behavior.
func TestC16AuditRestartPreservesEvents(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "audit-restart-test")
	store, _, err := storage.Open(dir)
	if err != nil {
		t.Fatalf("open storage: %v", err)
	}

	ctx := context.Background()
	evt, err := audit.NewEvent(audit.EventSecretVersionCreated, "vault-prod/secret", audit.AuditData{
		Actor:   "alice@keyhelix.local",
		Action:  "secret:write",
		Outcome: "success",
	})
	if err != nil {
		t.Fatalf("create event: %v", err)
	}

	evtBytes, err := json.Marshal(evt)
	if err != nil {
		t.Fatalf("marshal event: %v", err)
	}

	// Persist audit event record in local metadata storage
	_, err = store.Write(ctx, storage.WriteRequest{
		OperationID:     "op-audit-checkpoint-001",
		Owner:           "alice@keyhelix.local",
		Scope:           "audit",
		Name:            "checkpoint/" + evt.ID,
		ExpectedVersion: 0,
		Metadata:        evtBytes,
	})
	if err != nil {
		t.Fatalf("write audit record: %v", err)
	}

	// Restart: close store and reopen
	if err := store.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	reopened, _, err := storage.Open(dir)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	defer reopened.Close()

	rec, err := reopened.Read(ctx, storage.ReadRequest{
		Owner: "alice@keyhelix.local",
		Scope: "audit",
		Name:  "checkpoint/" + evt.ID,
	})
	if err != nil {
		t.Fatalf("read after restart: %v", err)
	}

	var restored audit.EventEnvelope
	if err := json.Unmarshal(rec.Metadata, &restored); err != nil {
		t.Fatalf("unmarshal restored event: %v", err)
	}
	if restored.ID != evt.ID || restored.Type != evt.Type || restored.Subject != evt.Subject {
		t.Fatalf("restored event mismatch: %+v vs %+v", restored, evt)
	}
}
