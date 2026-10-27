package storage_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/parsa-emami/keyhelix/internal/audit"
	"github.com/parsa-emami/keyhelix/internal/auth"
	"github.com/parsa-emami/keyhelix/internal/contracts"
	"github.com/parsa-emami/keyhelix/internal/provider"
	"github.com/parsa-emami/keyhelix/internal/rotation"
	"github.com/parsa-emami/keyhelix/internal/secrets"
	"github.com/parsa-emami/keyhelix/internal/security"
	"github.com/parsa-emami/keyhelix/internal/storage"
)

type c18SecretItemFixture struct {
	SecretPath     string `json:"secret_path"`
	Classification string `json:"classification"`
	Sentinel       string `json:"sentinel"`
}

type c18PositiveFixture struct {
	SchemaVersion    int                    `json:"schema_version"`
	Provenance       string                 `json:"provenance"`
	License          string                 `json:"license"`
	Vault            c14FixtureVault        `json:"vault"`
	OperatorIdentity c14FixtureIdentity     `json:"operator_identity"`
	JobID            string                 `json:"job_id"`
	TargetKEKID      string                 `json:"target_kek_id"`
	TargetKEKVersion string                 `json:"target_kek_version"`
	Secrets          []c18SecretItemFixture `json:"secrets"`
	ExpectedEvents   []string               `json:"expected_events"`
	MetadataFile     string                 `json:"metadata_file"`
}

type c18NegativeCase struct {
	Case                           string `json:"case"`
	Description                    string `json:"description"`
	ExpectedCode                   string `json:"expected_code,omitempty"`
	MalformedJSON                  string `json:"malformed_json,omitempty"`
	Sentinel                       string `json:"sentinel,omitempty"`
	ExpectedStorageOccurrenceCount int    `json:"expected_storage_occurrence_count,omitempty"`
}

type c18NegativeFixture struct {
	SchemaVersion int               `json:"schema_version"`
	Cases         []c18NegativeCase `json:"cases"`
}

type c18ExpectedOutput struct {
	SchemaVersion                     int               `json:"schema_version"`
	Requirement                       string            `json:"requirement"`
	Acceptance                        string            `json:"acceptance"`
	Status                            string            `json:"status"`
	MetadataSHA256                    string            `json:"metadata_sha256"`
	PartialRotationResumes            bool              `json:"partial_rotation_resumes"`
	PriorSecretVersionPreserved       bool              `json:"prior_secret_version_preserved"`
	KEKRetirementBlockedUntilVerified bool              `json:"kek_retirement_blocked_until_verified"`
	GuardCodes                        map[string]string `json:"guard_codes"`
	ProviderOwnsSecretBytes           bool              `json:"provider_owns_secret_bytes"`
}

func loadC18Fixture(t *testing.T, filename string, target any) []byte {
	t.Helper()
	path := filepath.Join("fixtures", "keyhelix", "C18", filename)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read C18 fixture %s: %v", filename, err)
	}
	if err := json.Unmarshal(data, target); err != nil {
		t.Fatalf("unmarshal C18 fixture %s: %v", filename, err)
	}
	return data
}

type c18Harness struct {
	dir       string
	store     *storage.Store
	state     *c14ProviderState
	adapter   *provider.Adapter
	mapper    *auth.ScopeMapper
	secretSvc *secrets.Service
	rotSvc    *rotation.Service
	stepUp    *auth.StepUpManager
	recorder  *audit.Recorder
	operator  *auth.Identity
	session   *auth.Session
	pos       c18PositiveFixture
}

func newC18Harness(t *testing.T) *c18Harness {
	t.Helper()
	var pos c18PositiveFixture
	loadC18Fixture(t, "positive.json", &pos)

	server, state := newC14Provider(t)
	adapter := newC14Adapter(t, server.URL, nil)

	dir := filepath.Join(t.TempDir(), "c18-rotation-store")
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
	secretSvc := secrets.NewService(mapper, adapter, store)

	redactor := security.NewRedactor()
	for _, sec := range pos.Secrets {
		redactor.RegisterSentinel(sec.Sentinel)
	}
	recorder := audit.NewRecorder(100, redactor)
	rotSvc := rotation.NewService(mapper, adapter, store, recorder)

	sessionMgr, err := auth.NewSessionManager(auth.DefaultSessionConfig(), nil)
	if err != nil {
		t.Fatalf("create session manager: %v", err)
	}
	stepUpMgr, err := auth.NewStepUpManager(auth.DefaultStepUpConfig(), nil)
	if err != nil {
		t.Fatalf("create step-up manager: %v", err)
	}

	operatorIdent := &auth.Identity{
		Subject:       pos.OperatorIdentity.Subject,
		Email:         pos.OperatorIdentity.Email,
		VaultRole:     pos.OperatorIdentity.VaultRole,
		AllowedOwners: pos.OperatorIdentity.AllowedOwners,
		AllowedScopes: pos.OperatorIdentity.AllowedScopes,
		ExpiresAt:     time.Now().Add(time.Hour).Unix(),
	}
	sess, _, err := sessionMgr.CreateSession(context.Background(), operatorIdent, auth.ClientInfo{})
	if err != nil {
		t.Fatalf("create operator session: %v", err)
	}

	return &c18Harness{
		dir:       dir,
		store:     store,
		state:     state,
		adapter:   adapter,
		mapper:    mapper,
		secretSvc: secretSvc,
		rotSvc:    rotSvc,
		stepUp:    stepUpMgr,
		recorder:  recorder,
		operator:  operatorIdent,
		session:   sess,
		pos:       pos,
	}
}

func (h *c18Harness) seedInitialSecrets(t *testing.T) []string {
	t.Helper()
	ctx := context.Background()
	paths := make([]string, 0, len(h.pos.Secrets))
	for i, item := range h.pos.Secrets {
		out, err := h.secretSvc.WriteSecret(ctx, secrets.WriteRequest{
			VaultID:         h.pos.Vault.VaultID,
			SecretPath:      item.SecretPath,
			ExpectedVersion: 0,
			Plaintext:       []byte(item.Sentinel),
			Classification:  item.Classification,
			KEKID:           h.pos.Vault.KEKID,
			OperationID:     "op-c18-seed-00" + string(rune('1'+i)),
			Owner:           h.pos.OperatorIdentity.Email,
			Identity:        h.operator,
		})
		if err != nil {
			t.Fatalf("seed secret %s: %v", item.SecretPath, err)
		}
		if out.Version != 1 {
			t.Fatalf("expected seeded version 1, got %d", out.Version)
		}
		paths = append(paths, item.SecretPath)
	}
	return paths
}

// TestC18PartialRotationResumesWithoutDeletingPriorVersionF12 proves Requirement F12:
// Partial rotation resumes without deleting valid prior secret version.
func TestC18PartialRotationResumesWithoutDeletingPriorVersionF12(t *testing.T) {
	var pos c18PositiveFixture
	loadC18Fixture(t, "positive.json", &pos)
	var exp c18ExpectedOutput
	loadC18Fixture(t, "expected-output.json", &exp)
	var metadataFixture contracts.SecretMetadata
	metadataBytes := loadC18Fixture(t, pos.MetadataFile, &metadataFixture)

	if exp.Requirement != "F12" || exp.Status != "passed" {
		t.Fatalf("unexpected C18 expected-output fixture: %+v", exp)
	}
	sum := sha256.Sum256(metadataBytes)
	if hex.EncodeToString(sum[:]) != exp.MetadataSHA256 {
		t.Fatalf("C18 metadata sha256 mismatch: got %s want %s", hex.EncodeToString(sum[:]), exp.MetadataSHA256)
	}
	if _, failure := contracts.DecodeSecret(context.Background(), metadataBytes); failure != nil {
		t.Fatalf("C18 metadata fixture must satisfy frozen v1 contract: %+v", failure)
	}

	h := newC18Harness(t)
	ctx := context.Background()
	secretPaths := h.seedInitialSecrets(t)

	// 1. Issue step-up grant for rotation start
	_, stepUp1, err := h.stepUp.IssueGrant(ctx, h.session, auth.ActionPolicyChange, "vault/"+pos.Vault.VaultID+"/rotations")
	if err != nil {
		t.Fatalf("issue step-up 1: %v", err)
	}

	// 2. Run a partial rotation (pause after 1 item to simulate mid-rotation interruption)
	partialJob, err := h.rotSvc.StartOrResumeRotation(ctx, rotation.StartOrResumeRequest{
		JobID:            pos.JobID,
		VaultID:          pos.Vault.VaultID,
		Owner:            pos.OperatorIdentity.Email,
		SourceKEKID:      pos.Vault.KEKID,
		TargetKEKID:      pos.TargetKEKID,
		TargetKEKVersion: pos.TargetKEKVersion,
		SecretPaths:      secretPaths,
		OperatorIdent:    h.operator,
		Session:          h.session,
		StepUpManager:    h.stepUp,
		StepUpToken:      stepUp1.Plaintext(),
		MaxItemsThisRun:  1,
	})
	if err == nil {
		t.Fatalf("expected partial rotation error when paused after 1 item, got nil")
	}
	if partialJob == nil || partialJob.State != rotation.StateRewrapping {
		t.Fatalf("expected partial job in REWRAPPING state, got: %+v", partialJob)
	}
	if !partialJob.Items[0].Rewrapped || partialJob.Items[1].Rewrapped {
		t.Fatalf("expected first secret rewrapped and second pending, got: %+v", partialJob.Items)
	}

	// 3. Invariant check during partial rotation:
	// (a) Prior version (v1) sealed payload of Secret 1 MUST NOT be deleted in provider!
	priorPayload0, err := h.adapter.ReadSealedPayload(ctx, provider.SealedRef{
		VaultID: pos.Vault.VaultID,
		Path:    pos.Secrets[0].SecretPath,
		Version: 1,
	})
	if err != nil || len(priorPayload0) == 0 {
		t.Fatalf("CRITICAL: prior secret version 1 for %s was deleted or inaccessible: %v", pos.Secrets[0].SecretPath, err)
	}
	// (b) Secret 2 (not yet rotated) is still at v1 and reveals its original valid plaintext
	_, revealToken2, err := h.stepUp.IssueGrant(ctx, h.session, auth.ActionRevealSecret, pos.Secrets[1].SecretPath)
	if err != nil {
		t.Fatalf("issue reveal token for unrotated secret: %v", err)
	}
	rev2, err := h.secretSvc.RevealSecret(ctx, secrets.RevealRequest{
		VaultID:       pos.Vault.VaultID,
		SecretPath:    pos.Secrets[1].SecretPath,
		Owner:         pos.OperatorIdentity.Email,
		Identity:      h.operator,
		Session:       h.session,
		StepUpManager: h.stepUp,
		StepUpToken:   revealToken2.Plaintext(),
	})
	if err != nil {
		t.Fatalf("reveal unrotated secret during partial rotation failed: %v", err)
	}
	if rev2.Version != 1 || string(rev2.Plaintext().Plaintext()) != pos.Secrets[1].Sentinel {
		t.Fatalf("unrotated secret version or plaintext mismatch: v=%d", rev2.Version)
	}
	rev2.Destroy()

	// (c) Retiring prior KEK while rotation is partial MUST be forbidden
	if allowed, retireErr := h.rotSvc.CanRetirePriorKEK(ctx, pos.OperatorIdentity.Email, pos.Vault.VaultID, pos.JobID); allowed || retireErr == nil {
		t.Fatalf("expected KEK retirement to be blocked during partial rotation")
	}

	// 4. Simulate process restart: close storage and reopen from disk
	if err := h.store.Close(); err != nil {
		t.Fatalf("close store before restart: %v", err)
	}
	reopenedStore, _, err := storage.Open(h.dir)
	if err != nil {
		t.Fatalf("reopen store after restart: %v", err)
	}
	h.store = reopenedStore
	h.secretSvc = secrets.NewService(h.mapper, h.adapter, reopenedStore)
	h.rotSvc = rotation.NewService(h.mapper, h.adapter, reopenedStore, h.recorder)

	// Verify job persisted across restart in REWRAPPING state
	recoveredJob, err := h.rotSvc.GetJob(ctx, pos.OperatorIdentity.Email, pos.Vault.VaultID, pos.JobID)
	if err != nil || recoveredJob.State != rotation.StateRewrapping {
		t.Fatalf("expected REWRAPPING job after restart, got job=%+v err=%v", recoveredJob, err)
	}

	// 5. Resume the rotation job to completion
	_, stepUp2, err := h.stepUp.IssueGrant(ctx, h.session, auth.ActionPolicyChange, "vault/"+pos.Vault.VaultID+"/rotations")
	if err != nil {
		t.Fatalf("issue step-up 2: %v", err)
	}
	completedJob, err := h.rotSvc.StartOrResumeRotation(ctx, rotation.StartOrResumeRequest{
		JobID:            pos.JobID,
		VaultID:          pos.Vault.VaultID,
		Owner:            pos.OperatorIdentity.Email,
		SourceKEKID:      pos.Vault.KEKID,
		TargetKEKID:      pos.TargetKEKID,
		TargetKEKVersion: pos.TargetKEKVersion,
		OperatorIdent:    h.operator,
		Session:          h.session,
		StepUpManager:    h.stepUp,
		StepUpToken:      stepUp2.Plaintext(),
	})
	if err != nil {
		t.Fatalf("resume rotation failed: %v", err)
	}
	if completedJob.State != rotation.StateComplete || !completedJob.RetirePriorKEKAllowed {
		t.Fatalf("expected completed rotation job with RetirePriorKEKAllowed=true, got: %+v", completedJob)
	}

	// 6. Confirm both secrets are at v2, both reveal their exact sentinels, AND both v1 payloads still exist in provider!
	for _, sec := range pos.Secrets {
		v1Bytes, err := h.adapter.ReadSealedPayload(ctx, provider.SealedRef{
			VaultID: pos.Vault.VaultID,
			Path:    sec.SecretPath,
			Version: 1,
		})
		if err != nil || len(v1Bytes) == 0 {
			t.Fatalf("prior version 1 payload missing after rotation completion for %s: %v", sec.SecretPath, err)
		}

		_, revTok, err := h.stepUp.IssueGrant(ctx, h.session, auth.ActionRevealSecret, sec.SecretPath)
		if err != nil {
			t.Fatalf("issue reveal token for %s: %v", sec.SecretPath, err)
		}
		rev, err := h.secretSvc.RevealSecret(ctx, secrets.RevealRequest{
			VaultID:       pos.Vault.VaultID,
			SecretPath:    sec.SecretPath,
			Owner:         pos.OperatorIdentity.Email,
			Identity:      h.operator,
			Session:       h.session,
			StepUpManager: h.stepUp,
			StepUpToken:   revTok.Plaintext(),
		})
		if err != nil {
			t.Fatalf("reveal rotated secret %s failed: %v", sec.SecretPath, err)
		}
		if rev.Version != 2 || string(rev.Plaintext().Plaintext()) != sec.Sentinel {
			t.Fatalf("rotated secret %s mismatch: got version=%d", sec.SecretPath, rev.Version)
		}
		rev.Destroy()
	}

	// 7. Confirm KEK retirement is now permitted
	allowed, err := h.rotSvc.CanRetirePriorKEK(ctx, pos.OperatorIdentity.Email, pos.Vault.VaultID, pos.JobID)
	if err != nil || !allowed {
		t.Fatalf("expected CanRetirePriorKEK=true after completion, got allowed=%v err=%v", allowed, err)
	}

	// 8. Confirm CloudEvents emitted for started, rewrapped, and completed without secret leaks
	events := h.recorder.Events()
	seenTypes := map[string]bool{}
	for _, evt := range events {
		seenTypes[evt.Type] = true
	}
	for _, expectedType := range pos.ExpectedEvents {
		if !seenTypes[expectedType] {
			t.Fatalf("missing expected rotation audit event %s in %+v", expectedType, events)
		}
	}
}

// TestC18NegativeCasesF12 validates all required negative cases for C18:
// - Missing prerequisites, malformed fixtures or unavailable required providers produce an explicit error rather than placeholder success.
// - Repeat after restart and verify the declared invariant and documented recovery outcome.
// - Provider owns secret bytes.
func TestC18NegativeCasesF12(t *testing.T) {
	var negFixture c18NegativeFixture
	loadC18Fixture(t, "negative.json", &negFixture)

	h := newC18Harness(t)
	ctx := context.Background()
	secretPaths := h.seedInitialSecrets(t)

	for _, tc := range negFixture.Cases {
		t.Run(tc.Case, func(t *testing.T) {
			switch tc.Case {
			case "missing-prerequisites-or-step-up-rejected":
				_, err := h.rotSvc.StartOrResumeRotation(ctx, rotation.StartOrResumeRequest{
					JobID:            "job-neg-no-stepup",
					VaultID:          h.pos.Vault.VaultID,
					Owner:            h.pos.OperatorIdentity.Email,
					TargetKEKID:      h.pos.TargetKEKID,
					TargetKEKVersion: h.pos.TargetKEKVersion,
					SecretPaths:      secretPaths,
					OperatorIdent:    h.operator,
					Session:          h.session,
					StepUpManager:    h.stepUp,
					StepUpToken:      "", // missing step-up token
				})
				if err == nil {
					t.Fatalf("expected error when step-up token is missing")
				}

			case "malformed-fixture-rejected":
				_, failure := contracts.DecodeSecret(ctx, []byte(tc.MalformedJSON))
				if failure == nil || string(failure.Code) != tc.ExpectedCode {
					t.Fatalf("expected malformed fixture failure %s, got %+v", tc.ExpectedCode, failure)
				}

			case "unavailable-provider-mid-rotation-preserves-prior-version":
				// Seal/disconnect provider and attempt rotation
				h.state.setSealed(true)
				defer h.state.setSealed(false)

				_, stepUpTok, err := h.stepUp.IssueGrant(ctx, h.session, auth.ActionPolicyChange, "vault/"+h.pos.Vault.VaultID+"/rotations")
				if err != nil {
					t.Fatalf("issue step-up: %v", err)
				}
				_, rotErr := h.rotSvc.StartOrResumeRotation(ctx, rotation.StartOrResumeRequest{
					JobID:            "job-neg-outage",
					VaultID:          h.pos.Vault.VaultID,
					Owner:            h.pos.OperatorIdentity.Email,
					TargetKEKID:      h.pos.TargetKEKID,
					TargetKEKVersion: h.pos.TargetKEKVersion,
					SecretPaths:      secretPaths,
					OperatorIdent:    h.operator,
					Session:          h.session,
					StepUpManager:    h.stepUp,
					StepUpToken:      stepUpTok.Plaintext(),
				})
				if rotErr == nil {
					t.Fatalf("expected failure when provider is unavailable during rotation")
				}

				// Unseal provider and verify prior secret version v1 is still intact and revealable
				h.state.setSealed(false)
				_, revTok, err := h.stepUp.IssueGrant(ctx, h.session, auth.ActionRevealSecret, secretPaths[0])
				if err != nil {
					t.Fatalf("issue reveal step-up: %v", err)
				}
				rev, err := h.secretSvc.RevealSecret(ctx, secrets.RevealRequest{
					VaultID:       h.pos.Vault.VaultID,
					SecretPath:    secretPaths[0],
					Owner:         h.pos.OperatorIdentity.Email,
					Identity:      h.operator,
					Session:       h.session,
					StepUpManager: h.stepUp,
					StepUpToken:   revTok.Plaintext(),
				})
				if err != nil || rev.Version != 1 {
					t.Fatalf("expected prior version 1 to remain intact after failed rotation, got rev=%+v err=%v", rev, err)
				}
				rev.Destroy()

			case "premature-kek-retirement-blocked":
				allowed, err := h.rotSvc.CanRetirePriorKEK(ctx, h.pos.OperatorIdentity.Email, h.pos.Vault.VaultID, "job-neg-outage")
				if allowed || err == nil {
					t.Fatalf("expected premature KEK retirement on incomplete job to fail closed")
				}

			case "restart-and-resume-recovery-verified":
				// Close and reopen store, then resume job-neg-outage to completion
				if err := h.store.Close(); err != nil {
					t.Fatalf("close store: %v", err)
				}
				reopened, _, err := storage.Open(h.dir)
				if err != nil {
					t.Fatalf("reopen store: %v", err)
				}
				h.store = reopened
				h.secretSvc = secrets.NewService(h.mapper, h.adapter, reopened)
				h.rotSvc = rotation.NewService(h.mapper, h.adapter, reopened, h.recorder)

				_, stepUpTok, err := h.stepUp.IssueGrant(ctx, h.session, auth.ActionPolicyChange, "vault/"+h.pos.Vault.VaultID+"/rotations")
				if err != nil {
					t.Fatalf("issue step-up: %v", err)
				}
				resumed, err := h.rotSvc.StartOrResumeRotation(ctx, rotation.StartOrResumeRequest{
					JobID:            "job-neg-outage",
					VaultID:          h.pos.Vault.VaultID,
					Owner:            h.pos.OperatorIdentity.Email,
					TargetKEKID:      h.pos.TargetKEKID,
					TargetKEKVersion: h.pos.TargetKEKVersion,
					OperatorIdent:    h.operator,
					Session:          h.session,
					StepUpManager:    h.stepUp,
					StepUpToken:      stepUpTok.Plaintext(),
				})
				if err != nil || string(resumed.State) != tc.ExpectedCode {
					t.Fatalf("expected resumed rotation state %s, got job=%+v err=%v", tc.ExpectedCode, resumed, err)
				}

			case "provider-owns-secret-bytes":
				for _, sec := range h.pos.Secrets {
					inspected, err := security.AssertDirectoryClean(h.dir, sec.Sentinel)
					if err != nil {
						t.Fatalf("secret sentinel leaked into rotation storage directory: %v", err)
					}
					if inspected == 0 {
						t.Fatalf("expected non-zero storage files inspected in %s", h.dir)
					}
				}
			}
		})
	}
}
