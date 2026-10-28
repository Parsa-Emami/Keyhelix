package storage_test

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/parsa-emami/keyhelix/internal/audit"
	"github.com/parsa-emami/keyhelix/internal/security"
)

type c25SignerFixture struct {
	SignerID     string `json:"signer_id"`
	Algorithm    string `json:"algorithm"`
	PublicKeyHex string `json:"public_key_hex"`
	PrivateKeyHex string `json:"private_key_hex"`
}

type c25TrustPolicyFixture struct {
	TrustedSigners        []string `json:"trusted_signers"`
	AllowedAlgorithms     []string `json:"allowed_algorithms"`
	MaxAgeSeconds         int64    `json:"max_age_seconds"`
	ClockToleranceSeconds int64    `json:"clock_tolerance_seconds"`
	MinSequence           int64    `json:"min_sequence"`
}

type c25PositiveFixture struct {
	SchemaVersion   int                   `json:"schema_version"`
	Provenance      string                `json:"provenance"`
	License         string                `json:"license"`
	TrustedSigner   c25SignerFixture      `json:"trusted_signer"`
	UntrustedSigner c25SignerFixture      `json:"untrusted_signer"`
	TrustPolicy     c25TrustPolicyFixture `json:"trust_policy"`
	SampleEvents    []audit.EventEnvelope `json:"sample_events"`
	Batch2Events    []audit.EventEnvelope `json:"batch2_events"`
	PlaintextCanary string                `json:"plaintext_canary"`
}

type c25NegativeCase struct {
	Case                string `json:"case"`
	Description         string `json:"description"`
	ExpectedStatus      string `json:"expected_status"`
	ExpectedTrusted     bool   `json:"expected_trusted"`
	ExpectedCanaryCount int    `json:"expected_canary_count,omitempty"`
}

type c25NegativeFixture struct {
	SchemaVersion int               `json:"schema_version"`
	Provenance    string            `json:"provenance"`
	License       string            `json:"license"`
	Cases         []c25NegativeCase `json:"cases"`
}

type c25ExpectedOutput struct {
	SchemaVersion                    int               `json:"schema_version"`
	Requirement                      string            `json:"requirement"`
	Acceptance                       string            `json:"acceptance"`
	Status                           string            `json:"status"`
	SignatureTrustPolicyExplicit     bool              `json:"signature_trust_policy_explicit"`
	UnavailableStatusExplicit        bool              `json:"unavailable_status_explicit"`
	HashChainAloneNotImmutable       bool              `json:"hash_chain_alone_not_immutable"`
	OneModifiedByteRejected          bool              `json:"one_modified_byte_rejected"`
	StaleOrReplayedRevisionRejected  bool              `json:"stale_or_replayed_revision_rejected"`
	ProviderOwnsSecretBytes          bool              `json:"provider_owns_secret_bytes"`
	GuardStatuses                    map[string]string `json:"guard_statuses"`
	PlaintextCanaryOccurrences       int               `json:"plaintext_canary_occurrences"`
}

func loadC25Fixture(t *testing.T, filename string, target any) []byte {
	t.Helper()
	path := filepath.Join("fixtures", "keyhelix", "C25", filename)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read C25 fixture %s: %v", filename, err)
	}
	if err := json.Unmarshal(data, target); err != nil {
		t.Fatalf("unmarshal C25 fixture %s: %v", filename, err)
	}
	return data
}

func parseEd25519PrivKey(t *testing.T, hexPriv string) ed25519.PrivateKey {
	t.Helper()
	b, err := hex.DecodeString(hexPriv)
	if err != nil {
		t.Fatalf("decode privkey hex: %v", err)
	}
	if len(b) != ed25519.PrivateKeySize {
		t.Fatalf("invalid privkey length: %d", len(b))
	}
	return ed25519.PrivateKey(b)
}

func parseEd25519PubKey(t *testing.T, hexPub string) ed25519.PublicKey {
	t.Helper()
	b, err := hex.DecodeString(hexPub)
	if err != nil {
		t.Fatalf("decode pubkey hex: %v", err)
	}
	if len(b) != ed25519.PublicKeySize {
		t.Fatalf("invalid pubkey length: %d", len(b))
	}
	return ed25519.PublicKey(b)
}

// TestC25SeparatelyStoredAuditCheckpointsF19 verifies Requirement F19:
// "Signature trust policy and unavailable checkpoint status are explicit; hash chain alone is not immutable."
func TestC25SeparatelyStoredAuditCheckpointsF19(t *testing.T) {
	var pos c25PositiveFixture
	loadC25Fixture(t, "positive.json", &pos)
	var exp c25ExpectedOutput
	loadC25Fixture(t, "expected-output.json", &exp)

	if exp.Requirement != "F19" || exp.Status != "passed" {
		t.Fatalf("unexpected C25 expected-output fixture: %+v", exp)
	}

	ctx := context.Background()

	// 1. Setup Signer & Policy
	trustedPriv := parseEd25519PrivKey(t, pos.TrustedSigner.PrivateKeyHex)
	trustedPub := parseEd25519PubKey(t, pos.TrustedSigner.PublicKeyHex)

	signer, err := audit.NewEd25519Signer(pos.TrustedSigner.SignerID, trustedPriv)
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}

	policy := audit.TrustPolicy{
		TrustedSigners: map[string]ed25519.PublicKey{
			pos.TrustedSigner.SignerID: trustedPub,
		},
		AllowedAlgorithms: pos.TrustPolicy.AllowedAlgorithms,
		MaxAge:            time.Duration(pos.TrustPolicy.MaxAgeSeconds) * time.Second,
		ClockTolerance:    time.Duration(pos.TrustPolicy.ClockToleranceSeconds) * time.Second,
		MinSequence:       pos.TrustPolicy.MinSequence,
	}
	if err := policy.Validate(); err != nil {
		t.Fatalf("validate policy: %v", err)
	}

	// 2. Setup Separate Checkpoint Store
	store := audit.NewInMemoryCheckpointStore()

	// 3. Setup Verifier
	verifier, err := audit.NewVerifier(policy, store)
	if err != nil {
		t.Fatalf("create verifier: %v", err)
	}

	// 4. Verify that hash chain alone without an authorized checkpoint produces UNANCHORED_CHAIN
	unanchoredRes := verifier.VerifyUnanchored(pos.SampleEvents)
	if unanchoredRes.Status != audit.StatusUnanchoredChain || unanchoredRes.Trusted {
		t.Fatalf("hash chain alone must NOT produce trusted success: %+v", unanchoredRes)
	}
	if unanchoredRes.EventCount != int64(len(pos.SampleEvents)) {
		t.Fatalf("unanchored event count mismatch: got %d, want %d", unanchoredRes.EventCount, len(pos.SampleEvents))
	}

	// 5. Create Checkpoint 1 (Sequence 1) over batch 1
	cp1, err := audit.NewCheckpoint(
		"chk-c25-seq-001",
		1,
		pos.SampleEvents,
		nil,
		signer,
	)
	if err != nil {
		t.Fatalf("create checkpoint 1: %v", err)
	}
	if cp1.EventCount != int64(len(pos.SampleEvents)) {
		t.Fatalf("checkpoint 1 event count mismatch: %d", cp1.EventCount)
	}

	// Emit attributable checkpoint CloudEvent
	evt1, err := audit.NewCheckpointSignedEvent("alice@keyhelix.local", cp1)
	if err != nil {
		t.Fatalf("create checkpoint CloudEvent: %v", err)
	}
	if evt1.Type != audit.EventAuditCheckpointSigned {
		t.Fatalf("unexpected CloudEvent type: %s", evt1.Type)
	}

	// Publish Checkpoint 1 to separate sink
	if err := store.SaveCheckpoint(ctx, cp1); err != nil {
		t.Fatalf("save checkpoint 1: %v", err)
	}

	// 6. Verify Checkpoint 1 against batch 1 events
	res1 := verifier.VerifyLogAgainstCheckpoint(ctx, cp1.ID, pos.SampleEvents, "")
	if res1.Status != audit.StatusTrusted || !res1.Trusted {
		t.Fatalf("expected checkpoint 1 to be trusted: %+v", res1)
	}
	if res1.Sequence != 1 || res1.CheckpointID != cp1.ID {
		t.Fatalf("res1 metadata mismatch: %+v", res1)
	}

	// Accept authority for sequence 1
	if err := verifier.AcceptAuthority(res1); err != nil {
		t.Fatalf("accept authority seq 1: %v", err)
	}
	authRecord1 := verifier.CurrentAuthority()
	if authRecord1 == nil || authRecord1.Sequence != 1 || authRecord1.CheckpointID != cp1.ID {
		t.Fatalf("invalid authority record 1: %+v", authRecord1)
	}

	// 7. Create Checkpoint 2 (Sequence 2) over batch 2, chaining to Checkpoint 1
	cp2, err := audit.NewCheckpoint(
		"chk-c25-seq-002",
		2,
		pos.Batch2Events,
		cp1,
		signer,
	)
	if err != nil {
		t.Fatalf("create checkpoint 2: %v", err)
	}
	if cp2.Sequence != 2 || cp2.PreviousCheckpointID != cp1.ID {
		t.Fatalf("checkpoint 2 chain mismatch: %+v", cp2)
	}
	expectedCount := cp1.EventCount + int64(len(pos.Batch2Events))
	if cp2.EventCount != expectedCount {
		t.Fatalf("checkpoint 2 event count mismatch: got %d, want %d", cp2.EventCount, expectedCount)
	}

	// Publish Checkpoint 2 to separate sink
	if err := store.SaveCheckpoint(ctx, cp2); err != nil {
		t.Fatalf("save checkpoint 2: %v", err)
	}

	// 8. Verify Checkpoint 2 using VerifyLatest
	res2 := verifier.VerifyLatest(ctx, pos.Batch2Events, cp1.LogRootHash)
	if res2.Status != audit.StatusTrusted || !res2.Trusted {
		t.Fatalf("expected checkpoint 2 to be trusted: %+v", res2)
	}
	if err := verifier.AcceptAuthority(res2); err != nil {
		t.Fatalf("accept authority seq 2: %v", err)
	}

	authRecord2 := verifier.CurrentAuthority()
	if authRecord2 == nil || authRecord2.Sequence != 2 || authRecord2.CheckpointID != cp2.ID {
		t.Fatalf("invalid authority record 2: %+v", authRecord2)
	}
}

// TestC25NegativeCases verifies every required negative failure condition.
func TestC25NegativeCases(t *testing.T) {
	var pos c25PositiveFixture
	loadC25Fixture(t, "positive.json", &pos)
	var neg c25NegativeFixture
	loadC25Fixture(t, "negative.json", &neg)

	ctx := context.Background()

	trustedPriv := parseEd25519PrivKey(t, pos.TrustedSigner.PrivateKeyHex)
	trustedPub := parseEd25519PubKey(t, pos.TrustedSigner.PublicKeyHex)
	signer, _ := audit.NewEd25519Signer(pos.TrustedSigner.SignerID, trustedPriv)

	untrustedPriv := parseEd25519PrivKey(t, pos.UntrustedSigner.PrivateKeyHex)
	untrustedSigner, _ := audit.NewEd25519Signer(pos.UntrustedSigner.SignerID, untrustedPriv)

	policy := audit.TrustPolicy{
		TrustedSigners: map[string]ed25519.PublicKey{
			pos.TrustedSigner.SignerID: trustedPub,
		},
		AllowedAlgorithms: pos.TrustPolicy.AllowedAlgorithms,
		MaxAge:            time.Duration(pos.TrustPolicy.MaxAgeSeconds) * time.Second,
		ClockTolerance:    time.Duration(pos.TrustPolicy.ClockToleranceSeconds) * time.Second,
		MinSequence:       pos.TrustPolicy.MinSequence,
	}

	store := audit.NewInMemoryCheckpointStore()
	verifier, err := audit.NewVerifier(policy, store)
	if err != nil {
		t.Fatalf("create verifier: %v", err)
	}

	// Baseline: create valid Checkpoint 1 & 2
	cp1, err := audit.NewCheckpoint("chk-neg-001", 1, pos.SampleEvents, nil, signer)
	if err != nil {
		t.Fatalf("baseline cp1: %v", err)
	}
	_ = store.SaveCheckpoint(ctx, cp1)

	// Accept authority for sequence 1
	baselineRes1 := verifier.VerifyLogAgainstCheckpoint(ctx, cp1.ID, pos.SampleEvents, "")
	if !baselineRes1.Trusted {
		t.Fatalf("baseline verification failed: %+v", baselineRes1)
	}
	if err := verifier.AcceptAuthority(baselineRes1); err != nil {
		t.Fatalf("baseline accept authority: %v", err)
	}

	// Iterate cases
	for _, tc := range neg.Cases {
		t.Run(tc.Case, func(t *testing.T) {
			switch tc.Case {
			case "single-byte-event-modified":
				// Mutate 1 byte in event payload
				tamperedEvents := make([]audit.EventEnvelope, len(pos.SampleEvents))
				copy(tamperedEvents, pos.SampleEvents)
				// Alter action in event data
				dataMap := map[string]any{
					"actor":          "alice@keyhelix.local",
					"vault_id":       "vault-prod",
					"secret_path":    "app/prod/database-url",
					"version":        1,
					"classification": "restricted",
					"action":         "secret:tampered", // altered byte
					"outcome":        "success",
				}
				tamperedEvents[0].Data = dataMap

				res := verifier.VerifyLogAgainstCheckpoint(ctx, cp1.ID, tamperedEvents, "")
				if res.Status != audit.VerificationStatus(tc.ExpectedStatus) || res.Trusted != tc.ExpectedTrusted {
					t.Fatalf("[%s] expected status %s trusted %v, got status %s trusted %v",
						tc.Case, tc.ExpectedStatus, tc.ExpectedTrusted, res.Status, res.Trusted)
				}

			case "single-byte-log-root-modified":
				// Alter 1 byte in Checkpoint LogRootHash
				tamperedCP := *cp1
				tamperedCP.ID = "chk-tampered-root"
				rawRoot := []byte(tamperedCP.LogRootHash)
				if rawRoot[0] == 'a' {
					rawRoot[0] = 'b'
				} else {
					rawRoot[0] = 'a'
				}
				tamperedCP.LogRootHash = string(rawRoot)
				_ = store.SaveCheckpoint(ctx, &tamperedCP)

				res := verifier.VerifyLogAgainstCheckpoint(ctx, tamperedCP.ID, pos.SampleEvents, "")
				if res.Status != audit.VerificationStatus(tc.ExpectedStatus) || res.Trusted != tc.ExpectedTrusted {
					t.Fatalf("[%s] expected status %s trusted %v, got status %s trusted %v",
						tc.Case, tc.ExpectedStatus, tc.ExpectedTrusted, res.Status, res.Trusted)
				}

			case "single-byte-signature-modified":
				// Alter 1 byte in Checkpoint Signature
				tamperedCP := *cp1
				tamperedCP.ID = "chk-tampered-sig"
				rawSig := []byte(tamperedCP.Signature)
				if rawSig[10] == 'A' {
					rawSig[10] = 'B'
				} else {
					rawSig[10] = 'A'
				}
				tamperedCP.Signature = string(rawSig)
				_ = store.SaveCheckpoint(ctx, &tamperedCP)

				res := verifier.VerifyLogAgainstCheckpoint(ctx, tamperedCP.ID, pos.SampleEvents, "")
				if res.Status != audit.VerificationStatus(tc.ExpectedStatus) || res.Trusted != tc.ExpectedTrusted {
					t.Fatalf("[%s] expected status %s trusted %v, got status %s trusted %v",
						tc.Case, tc.ExpectedStatus, tc.ExpectedTrusted, res.Status, res.Trusted)
				}

			case "checkpoint-store-unavailable":
				// 1. Missing checkpoint
				missingRes := verifier.VerifyLogAgainstCheckpoint(ctx, "non-existent-chk-id", pos.SampleEvents, "")
				if missingRes.Status != audit.VerificationStatus(tc.ExpectedStatus) || missingRes.Trusted != tc.ExpectedTrusted {
					t.Fatalf("[%s] missing checkpoint: expected %s, got %s", tc.Case, tc.ExpectedStatus, missingRes.Status)
				}

				// 2. Failing store
				failingVerifier, _ := audit.NewVerifier(policy, &audit.FailingCheckpointStore{Err: audit.ErrStoreUnavailable})
				failingRes := failingVerifier.VerifyLogAgainstCheckpoint(ctx, cp1.ID, pos.SampleEvents, "")
				if failingRes.Status != audit.VerificationStatus(tc.ExpectedStatus) || failingRes.Trusted != tc.ExpectedTrusted {
					t.Fatalf("[%s] failing store: expected %s, got %s", tc.Case, tc.ExpectedStatus, failingRes.Status)
				}

			case "untrusted-signer":
				// Signed with untrusted key
				rogueCP, err := audit.NewCheckpoint("chk-rogue-001", 2, pos.Batch2Events, cp1, untrustedSigner)
				if err != nil {
					t.Fatalf("create rogue checkpoint: %v", err)
				}
				_ = store.SaveCheckpoint(ctx, rogueCP)

				res := verifier.VerifyLogAgainstCheckpoint(ctx, rogueCP.ID, pos.Batch2Events, cp1.LogRootHash)
				if res.Status != audit.VerificationStatus(tc.ExpectedStatus) || res.Trusted != tc.ExpectedTrusted {
					t.Fatalf("[%s] expected status %s trusted %v, got status %s trusted %v",
						tc.Case, tc.ExpectedStatus, tc.ExpectedTrusted, res.Status, res.Trusted)
				}

			case "stale-revision-replay":
				// Advance authority to sequence 2 first
				cp2, _ := audit.NewCheckpoint("chk-neg-002", 2, pos.Batch2Events, cp1, signer)
				_ = store.SaveCheckpoint(ctx, cp2)
				res2 := verifier.VerifyLogAgainstCheckpoint(ctx, cp2.ID, pos.Batch2Events, cp1.LogRootHash)
				_ = verifier.AcceptAuthority(res2)

				// Now attempt to present stale sequence 1
				staleRes := verifier.VerifyLogAgainstCheckpoint(ctx, cp1.ID, pos.SampleEvents, "")
				if staleRes.Status != audit.VerificationStatus(tc.ExpectedStatus) || staleRes.Trusted != tc.ExpectedTrusted {
					t.Fatalf("[%s] expected status %s trusted %v, got status %s trusted %v",
						tc.Case, tc.ExpectedStatus, tc.ExpectedTrusted, staleRes.Status, staleRes.Trusted)
				}

			case "forked-revision-replay":
				// Current authority is at sequence 2. Present another sequence 2 with conflicting events/root.
				forkCP, _ := audit.NewCheckpoint("chk-fork-002", 2, pos.SampleEvents, cp1, signer)
				_ = store.SaveCheckpoint(ctx, forkCP)

				res := verifier.VerifyLogAgainstCheckpoint(ctx, forkCP.ID, pos.SampleEvents, cp1.LogRootHash)
				if res.Status != audit.VerificationStatus(tc.ExpectedStatus) || res.Trusted != tc.ExpectedTrusted {
					t.Fatalf("[%s] expected status %s trusted %v, got status %s trusted %v",
						tc.Case, tc.ExpectedStatus, tc.ExpectedTrusted, res.Status, res.Trusted)
				}

			case "expired-checkpoint":
				// Checkpoint older than policy MaxAge
				expiredCP, _ := audit.NewCheckpoint("chk-expired-003", 3, pos.Batch2Events, cp1, signer)
				// Set timestamp to 30 days ago
				expiredCP.Timestamp = time.Now().UTC().Add(-30 * 24 * time.Hour).Format(time.RFC3339Nano)
				// Re-sign with expired timestamp
				sig, _ := signer.Sign(audit.CanonicalSigningBytes(expiredCP))
				expiredCP.Signature = sig
				_ = store.SaveCheckpoint(ctx, expiredCP)

				res := verifier.VerifyLogAgainstCheckpoint(ctx, expiredCP.ID, pos.Batch2Events, cp1.LogRootHash)
				if res.Status != audit.VerificationStatus(tc.ExpectedStatus) || res.Trusted != tc.ExpectedTrusted {
					t.Fatalf("[%s] expected status %s trusted %v, got status %s trusted %v",
						tc.Case, tc.ExpectedStatus, tc.ExpectedTrusted, res.Status, res.Trusted)
				}

			case "hash-chain-alone":
				// Local hash chain without external signed checkpoint
				res := verifier.VerifyUnanchored(pos.SampleEvents)
				if res.Status != audit.VerificationStatus(tc.ExpectedStatus) || res.Trusted != tc.ExpectedTrusted {
					t.Fatalf("[%s] expected status %s trusted %v, got status %s trusted %v",
						tc.Case, tc.ExpectedStatus, tc.ExpectedTrusted, res.Status, res.Trusted)
				}

			case "provider-owns-secret-bytes":
				// Ensure canary never leaks in checkpoint, event envelope, or verification output
				canary := pos.PlaintextCanary
				cpBytes, _ := json.Marshal(cp1)
				if strings.Contains(string(cpBytes), canary) {
					t.Fatalf("[%s] plaintext canary found in checkpoint: %s", tc.Case, canary)
				}
				resBytes, _ := json.Marshal(baselineRes1)
				if strings.Contains(string(resBytes), canary) {
					t.Fatalf("[%s] plaintext canary found in verification result: %s", tc.Case, canary)
				}
				if err := security.AssertClean(cpBytes); err != nil {
					t.Fatalf("[%s] security.AssertClean failed on checkpoint: %v", tc.Case, err)
				}
				if err := security.AssertClean(resBytes); err != nil {
					t.Fatalf("[%s] security.AssertClean failed on verification result: %v", tc.Case, err)
				}

			default:
				t.Fatalf("unhandled negative case: %s", tc.Case)
			}
		})
	}
}

// TestC25FileStoreDrill verifies DirectoryCheckpointStore file persistence and atomic publishing.
func TestC25FileStoreDrill(t *testing.T) {
	tempDir := filepath.Join(t.TempDir(), "separate-audit-sink")
	fileStore, err := audit.NewDirectoryCheckpointStore(tempDir)
	if err != nil {
		t.Fatalf("create directory checkpoint store: %v", err)
	}

	var pos c25PositiveFixture
	loadC25Fixture(t, "positive.json", &pos)

	trustedPriv := parseEd25519PrivKey(t, pos.TrustedSigner.PrivateKeyHex)
	trustedPub := parseEd25519PubKey(t, pos.TrustedSigner.PublicKeyHex)
	signer, _ := audit.NewEd25519Signer(pos.TrustedSigner.SignerID, trustedPriv)

	ctx := context.Background()

	// Initial store should report not found
	_, err = fileStore.GetLatestCheckpoint(ctx)
	if err != audit.ErrCheckpointNotFound {
		t.Fatalf("expected ErrCheckpointNotFound on empty store, got %v", err)
	}

	// Create and persist Checkpoint 1
	cp1, err := audit.NewCheckpoint("chk-file-001", 1, pos.SampleEvents, nil, signer)
	if err != nil {
		t.Fatalf("create cp1: %v", err)
	}
	if err := fileStore.SaveCheckpoint(ctx, cp1); err != nil {
		t.Fatalf("save cp1 to file store: %v", err)
	}

	// Load by ID
	loaded1, err := fileStore.GetCheckpoint(ctx, cp1.ID)
	if err != nil {
		t.Fatalf("get cp1 from file store: %v", err)
	}
	if loaded1.Digest() != cp1.Digest() || loaded1.Signature != cp1.Signature {
		t.Fatalf("loaded cp1 mismatch")
	}

	// Load latest
	latest, err := fileStore.GetLatestCheckpoint(ctx)
	if err != nil {
		t.Fatalf("get latest cp: %v", err)
	}
	if latest.ID != cp1.ID {
		t.Fatalf("latest checkpoint id mismatch: %s vs %s", latest.ID, cp1.ID)
	}

	// Verify using Verifier over file store
	policy := audit.TrustPolicy{
		TrustedSigners: map[string]ed25519.PublicKey{
			pos.TrustedSigner.SignerID: trustedPub,
		},
		AllowedAlgorithms: pos.TrustPolicy.AllowedAlgorithms,
		MaxAge:            24 * time.Hour,
		ClockTolerance:    5 * time.Minute,
		MinSequence:       1,
	}
	verifier, err := audit.NewVerifier(policy, fileStore)
	if err != nil {
		t.Fatalf("create verifier: %v", err)
	}

	res := verifier.VerifyLatest(ctx, pos.SampleEvents, "")
	if res.Status != audit.StatusTrusted || !res.Trusted {
		t.Fatalf("file store verification failed: %+v", res)
	}
}

// TestC25ConcurrencyRace exercises the Verifier and Stores concurrently under the race detector.
func TestC25ConcurrencyRace(t *testing.T) {
	var pos c25PositiveFixture
	loadC25Fixture(t, "positive.json", &pos)

	trustedPriv := parseEd25519PrivKey(t, pos.TrustedSigner.PrivateKeyHex)
	trustedPub := parseEd25519PubKey(t, pos.TrustedSigner.PublicKeyHex)
	signer, _ := audit.NewEd25519Signer(pos.TrustedSigner.SignerID, trustedPriv)

	store := audit.NewInMemoryCheckpointStore()
	policy := audit.TrustPolicy{
		TrustedSigners: map[string]ed25519.PublicKey{
			pos.TrustedSigner.SignerID: trustedPub,
		},
		AllowedAlgorithms: []string{"ed25519"},
		MaxAge:            24 * time.Hour,
		ClockTolerance:    5 * time.Minute,
	}

	verifier, err := audit.NewVerifier(policy, store)
	if err != nil {
		t.Fatalf("create verifier: %v", err)
	}

	ctx := context.Background()

	// Seed Checkpoint 1
	cp1, _ := audit.NewCheckpoint("chk-race-001", 1, pos.SampleEvents, nil, signer)
	_ = store.SaveCheckpoint(ctx, cp1)
	res1 := verifier.VerifyLogAgainstCheckpoint(ctx, cp1.ID, pos.SampleEvents, "")
	_ = verifier.AcceptAuthority(res1)

	var wg sync.WaitGroup
	workers := 16
	iterations := 50

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				// Concurrent reads & authority checks
				auth := verifier.CurrentAuthority()
				if auth == nil || auth.Sequence < 1 {
					t.Errorf("worker %d: unexpected authority state", workerID)
				}

				res := verifier.VerifyLogAgainstCheckpoint(ctx, cp1.ID, pos.SampleEvents, "")
				if res.Status != audit.StatusTrusted {
					t.Errorf("worker %d: verification failed: %+v", workerID, res)
				}

				unanchored := verifier.VerifyUnanchored(pos.SampleEvents)
				if unanchored.Trusted {
					t.Errorf("worker %d: unanchored chain must not be trusted", workerID)
				}
			}
		}(w)
	}

	wg.Wait()
}
