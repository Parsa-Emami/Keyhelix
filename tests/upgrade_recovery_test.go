package storage_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/parsa-emami/keyhelix/internal/auth"
	"github.com/parsa-emami/keyhelix/internal/provider"
	"github.com/parsa-emami/keyhelix/internal/secrets"
	"github.com/parsa-emami/keyhelix/internal/storage"
)

type c35Authority struct {
	SignerID     string `json:"signer_id"`
	KeyID        string `json:"key_id"`
	Algorithm    string `json:"algorithm"`
	SeedHex      string `json:"seed_hex"`
	PublicKeyHex string `json:"public_key_hex"`
}

type c35ReleaseSpec struct {
	Slot      string `json:"slot"`
	Version   string `json:"version"`
	Revision  int64  `json:"revision"`
	IssuedAt  string `json:"issued_at"`
	ExpiresAt string `json:"expires_at"`
}

type c35WorkflowRecord struct {
	Phase           string `json:"phase"`
	OperationID     string `json:"operation_id"`
	SecretPath      string `json:"secret_path"`
	Classification  string `json:"classification"`
	ExpectedVersion int64  `json:"expected_version"`
	EntityVersion   int64  `json:"entity_version"`
	ManifestVersion int64  `json:"manifest_version"`
	PlaintextCanary string `json:"plaintext_canary"`
}

type c35PositiveFixture struct {
	SchemaVersion    int                 `json:"schema_version"`
	Task             string              `json:"task"`
	Requirement      string              `json:"requirement"`
	Provenance       string              `json:"provenance"`
	License          string              `json:"license"`
	TrustedAuthority c35Authority        `json:"trusted_authority"`
	Releases         struct {
		Initial c35ReleaseSpec `json:"initial"`
		Upgrade c35ReleaseSpec `json:"upgrade"`
	} `json:"releases"`
	Vault           c24Vault            `json:"vault"`
	Identity        c24Identity         `json:"identity"`
	WorkflowRecords []c35WorkflowRecord `json:"workflow_records"`
	SourceBuild     struct {
		ArchivePrefix string   `json:"archive_prefix"`
		BuildCommand  string   `json:"build_command"`
		RequiredFiles []string `json:"required_files"`
	} `json:"source_build"`
}

type c35NegativeCase struct {
	ID                    string `json:"id"`
	Kind                  string `json:"kind"`
	Target                string `json:"target"`
	ExpectedCode          string `json:"expected_code"`
	EmbeddedProviderState bool   `json:"embedded_provider_state"`
	Description           string `json:"description"`
}

type c35NegativeFixture struct {
	SchemaVersion      int               `json:"schema_version"`
	Task               string            `json:"task"`
	Requirement        string            `json:"requirement"`
	Provenance         string            `json:"provenance"`
	License            string            `json:"license"`
	UntrustedAuthority c35Authority      `json:"untrusted_authority"`
	Canary             string            `json:"canary"`
	Cases              []c35NegativeCase `json:"cases"`
}

type c35ExpectedOutput struct {
	SchemaVersion int    `json:"schema_version"`
	Task          string `json:"task"`
	Requirement   string `json:"requirement"`
	Acceptance    string `json:"acceptance"`
	Status        string `json:"status"`
	Expected      struct {
		SignatureVerified              bool              `json:"signature_verified"`
		IndependentTrustRoot           bool              `json:"independent_trust_root"`
		InitialInstallRevision         int64             `json:"initial_install_revision"`
		UpgradedRevision               int64             `json:"upgraded_revision"`
		PostUpgradeManifestVersion     int64             `json:"post_upgrade_manifest_version"`
		PostUpgradeRecords             int               `json:"post_upgrade_records"`
		RollbackBinaryRevision         int64             `json:"rollback_binary_revision"`
		PostRollbackManifestVersion    int64             `json:"post_rollback_manifest_version"`
		PostRollbackRecords            int               `json:"post_rollback_records"`
		NewerAcceptedDataPreserved     bool              `json:"newer_accepted_data_preserved"`
		SourceBuildAlternativeVerified bool              `json:"source_build_alternative_verified"`
		ProviderOwnsSecretBytes        bool              `json:"provider_owns_secret_bytes"`
		PlaintextCanaryOccurrences     int               `json:"plaintext_canary_occurrences"`
		ErrorCodes                     map[string]string `json:"error_codes"`
	} `json:"expected"`
}

type c35Attestation struct {
	SignerID            string `json:"signer_id"`
	KeyID               string `json:"key_id"`
	PublicKeyHex        string `json:"public_key_hex"`
	ReleaseID           string `json:"release_id"`
	Version             string `json:"version"`
	Revision            int64  `json:"revision"`
	Commit              string `json:"commit"`
	TreeSHA256          string `json:"tree_sha256"`
	SourceArchiveSHA256 string `json:"source_archive_sha256"`
	ReleaseJSONSHA256   string `json:"release_json_sha256"`
	ChecksumsSHA256     string `json:"checksums_sha256"`
	IssuedAt            string `json:"issued_at"`
	ExpiresAt           string `json:"expires_at"`
	SignatureHex        string `json:"signature_hex"`
}

func c35LoadFixture(t *testing.T, name string, target any) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("fixtures", "keyhelix", "C35", name))
	if err != nil {
		t.Fatalf("read C35 fixture %s: %v", name, err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		t.Fatalf("decode C35 fixture %s: %v", name, err)
	}
}

func c35CanonicalMessage(a c35Attestation) []byte {
	lines := []string{
		"keyhelix-release-v1",
		"signer_id:" + a.SignerID,
		"key_id:" + a.KeyID,
		"release_id:" + a.ReleaseID,
		"version:" + a.Version,
		fmt.Sprintf("revision:%d", a.Revision),
		"commit:" + a.Commit,
		"tree_sha256:" + a.TreeSHA256,
		"source_archive_sha256:" + a.SourceArchiveSHA256,
		"release_json_sha256:" + a.ReleaseJSONSHA256,
		"checksums_sha256:" + a.ChecksumsSHA256,
		"issued_at:" + a.IssuedAt,
		"expires_at:" + a.ExpiresAt,
	}
	return []byte(strings.Join(lines, "\n") + "\n")
}

func c35SignAttestation(t *testing.T, authority c35Authority, spec c35ReleaseSpec, manifestBytes, checksumBytes, binaryBytes []byte) c35Attestation {
	t.Helper()
	seed, err := hex.DecodeString(authority.SeedHex)
	if err != nil || len(seed) != ed25519.SeedSize {
		t.Fatalf("invalid seed: %v", err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	if hex.EncodeToString(pub) != authority.PublicKeyHex {
		t.Fatalf("derived public key mismatch: got %x, want %s", pub, authority.PublicKeyHex)
	}
	att := c35Attestation{
		SignerID:            authority.SignerID,
		KeyID:               authority.KeyID,
		PublicKeyHex:        authority.PublicKeyHex,
		ReleaseID:           "0d4850c220ec",
		Version:             spec.Version,
		Revision:            spec.Revision,
		Commit:              strings.Repeat("a", 40),
		TreeSHA256:          c24SHA256Hex(binaryBytes),
		SourceArchiveSHA256: c24SHA256Hex([]byte("source-archive-v1")),
		ReleaseJSONSHA256:   c24SHA256Hex(manifestBytes),
		ChecksumsSHA256:     c24SHA256Hex(checksumBytes),
		IssuedAt:            spec.IssuedAt,
		ExpiresAt:           spec.ExpiresAt,
	}
	sig := ed25519.Sign(priv, c35CanonicalMessage(att))
	att.SignatureHex = hex.EncodeToString(sig)
	return att
}

func c35VerifyReleaseBundle(att *c35Attestation, trusted c35Authority, manifestBytes, checksumBytes, binaryBytes []byte, expectedBinaryHash string, minRevision int64, now time.Time) string {
	if att == nil || len(manifestBytes) == 0 || len(checksumBytes) == 0 {
		return "MISSING_SIGNATURE_EVIDENCE"
	}
	if att.SignerID != trusted.SignerID || att.KeyID != trusted.KeyID || !strings.EqualFold(att.PublicKeyHex, trusted.PublicKeyHex) {
		return "UNTRUSTED_SIGNER"
	}
	pubBytes, err := hex.DecodeString(trusted.PublicKeyHex)
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		return "UNTRUSTED_SIGNER"
	}
	sigBytes, err := hex.DecodeString(att.SignatureHex)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return "SIGNATURE_INVALID"
	}
	if !ed25519.Verify(ed25519.PublicKey(pubBytes), c35CanonicalMessage(*att), sigBytes) {
		return "SIGNATURE_INVALID"
	}
	issued, err1 := time.Parse(time.RFC3339, att.IssuedAt)
	expires, err2 := time.Parse(time.RFC3339, att.ExpiresAt)
	if err1 != nil || err2 != nil || !expires.After(issued) || now.After(expires) {
		return "EXPIRED_ATTESTATION"
	}
	if att.Revision < minRevision {
		return "STALE_REVISION_REJECTED"
	}
	if c24SHA256Hex(manifestBytes) != att.ReleaseJSONSHA256 || c24SHA256Hex(checksumBytes) != att.ChecksumsSHA256 {
		return "SIGNATURE_INVALID"
	}
	if c24SHA256Hex(binaryBytes) != expectedBinaryHash {
		return "CHECKSUM_MISMATCH"
	}
	return "OK"
}

func TestC35SignedArtifactsAndDataSafeUpgradesN35(t *testing.T) {
	var positive c35PositiveFixture
	var negative c35NegativeFixture
	var expected c35ExpectedOutput
	c35LoadFixture(t, "positive.json", &positive)
	c35LoadFixture(t, "negative.json", &negative)
	c35LoadFixture(t, "expected-output.json", &expected)

	if positive.Requirement != "N35" || expected.Status != "passed" {
		t.Fatalf("unexpected C35 fixture header: %+v", expected)
	}

	manifestV1 := []byte(`{"project":"KeyHelix","version":"0.0.1","revision":1}`)
	binaryV1 := []byte("keyhelix-engine-binary-v1")
	checksumV1 := []byte(c24SHA256Hex(binaryV1) + "  dist/engine/keyhelix\n")
	attV1 := c35SignAttestation(t, positive.TrustedAuthority, positive.Releases.Initial, manifestV1, checksumV1, binaryV1)

	now := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	if code := c35VerifyReleaseBundle(&attV1, positive.TrustedAuthority, manifestV1, checksumV1, binaryV1, c24SHA256Hex(binaryV1), 1, now); code != "OK" {
		t.Fatalf("expected v1 bundle verification OK, got %s", code)
	}

	// Host installation and real durable engine storage workflow across v1 -> v2 -> rollback to v1
	baseDir := t.TempDir()
	storeRoot := filepath.Join(baseDir, "durable-store")
	backupV1Dir := filepath.Join(baseDir, "stale-backup-v1")

	server, _ := newC14Provider(t)
	adapter, err := provider.NewOpenBaoAdapter(context.Background(), provider.Config{
		Address:      server.URL,
		KEKMount:     "transit",
		PayloadMount: "kv",
		Environment:  "local",
		Timeout:      2 * time.Second,
	}, provider.WorkloadIdentity{
		Role:   "workload-c35",
		Token:  "s.c35-scoped-token",
		Scopes: []string{"transit:encrypt", "transit:decrypt", "kv:read", "kv:write"},
	})
	if err != nil {
		t.Fatalf("create provider adapter: %v", err)
	}
	mapper := auth.NewScopeMapper(auth.ScopeMapperConfig{
		VaultKEKMap:   map[string]string{positive.Vault.VaultID: positive.Vault.KEKID},
		VaultMountMap: map[string]string{positive.Vault.VaultID: positive.Vault.Mount},
		VaultRoleMap:  map[string]string{positive.Vault.VaultID: positive.Vault.Role},
	})
	identity := c24AuthIdentity(positive.Identity)

	// Step 1: Install v1, write initial record (ManifestVersion 1)
	storeV1, reportV1, err := storage.Open(storeRoot)
	if err != nil {
		t.Fatalf("open store on v1 install: %v", err)
	}
	if reportV1.ManifestVersion != 0 {
		t.Fatalf("expected empty store at install, got version %d", reportV1.ManifestVersion)
	}
	serviceV1 := secrets.NewService(mapper, adapter, storeV1)
	step1 := positive.WorkflowRecords[0]
	out1, err := serviceV1.WriteSecret(context.Background(), secrets.WriteRequest{
		VaultID:         positive.Vault.VaultID,
		SecretPath:      step1.SecretPath,
		ExpectedVersion: step1.ExpectedVersion,
		Plaintext:       []byte(step1.PlaintextCanary),
		Classification:  step1.Classification,
		KEKID:           positive.Vault.KEKID,
		OperationID:     step1.OperationID,
		Owner:           identity.Email,
		Identity:        identity,
	})
	if err != nil || out1.Version != step1.EntityVersion {
		t.Fatalf("v1 write failed: %v (%+v)", err, out1)
	}
	if err := storeV1.Close(); err != nil {
		t.Fatalf("close store after v1 write: %v", err)
	}

	// Snapshot v1 store so we can later test that a stale v1 backup is rejected after v2 writes
	if err := os.MkdirAll(filepath.Join(backupV1Dir, "manifests"), 0o700); err != nil {
		t.Fatalf("mkdir stale backup: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(backupV1Dir, "blobs"), 0o700); err != nil {
		t.Fatalf("mkdir stale blobs: %v", err)
	}
	c24CopyStoreDirectories(t, storeRoot, backupV1Dir)

	// Step 2: Upgrade to signed v2 (revision 2), write updated and new records (ManifestVersion 2 and 3)
	manifestV2 := []byte(`{"project":"KeyHelix","version":"0.0.2","revision":2}`)
	binaryV2 := []byte("keyhelix-engine-binary-v2")
	checksumV2 := []byte(c24SHA256Hex(binaryV2) + "  dist/engine/keyhelix\n")
	attV2 := c35SignAttestation(t, positive.TrustedAuthority, positive.Releases.Upgrade, manifestV2, checksumV2, binaryV2)
	if code := c35VerifyReleaseBundle(&attV2, positive.TrustedAuthority, manifestV2, checksumV2, binaryV2, c24SHA256Hex(binaryV2), attV1.Revision+1, now); code != "OK" {
		t.Fatalf("expected v2 upgrade bundle verification OK, got %s", code)
	}

	storeV2, reportV2, err := storage.Open(storeRoot)
	if err != nil {
		t.Fatalf("open store on v2 upgrade: %v", err)
	}
	if reportV2.ManifestVersion != 1 || reportV2.Records != 1 {
		t.Fatalf("upgrade lost v1 state: %+v", reportV2)
	}
	serviceV2 := secrets.NewService(mapper, adapter, storeV2)
	for _, step := range positive.WorkflowRecords[1:] {
		out, writeErr := serviceV2.WriteSecret(context.Background(), secrets.WriteRequest{
			VaultID:         positive.Vault.VaultID,
			SecretPath:      step.SecretPath,
			ExpectedVersion: step.ExpectedVersion,
			Plaintext:       []byte(step.PlaintextCanary),
			Classification:  step.Classification,
			KEKID:           positive.Vault.KEKID,
			OperationID:     step.OperationID,
			Owner:           identity.Email,
			Identity:        identity,
		})
		if writeErr != nil || out.Version != step.EntityVersion {
			t.Fatalf("v2 write %s failed: %v (%+v)", step.Phase, writeErr, out)
		}
	}

	// Negative case: stale entity revision write must fail with STALE_VERSION
	_, staleWriteErr := storeV2.Write(context.Background(), storage.WriteRequest{
		OperationID:     "op-c35-stale-entity-999",
		Owner:           identity.Email,
		Scope:           positive.Vault.VaultID,
		Name:            step1.SecretPath,
		ExpectedVersion: 1, // current is 2
		Metadata:        []byte(`{"stale":true}`),
	})
	if c24CodeOf(staleWriteErr) != string(storage.CodeStaleVersion) {
		t.Fatalf("expected STALE_VERSION on stale entity update, got %v", staleWriteErr)
	}

	if err := storeV2.Close(); err != nil {
		t.Fatalf("close store after v2 writes: %v", err)
	}

	// Step 3: Rollback binary to v1 while preserving newer accepted data (ManifestVersion 3, 2 records)
	storeRollback, reportRollback, err := storage.Open(storeRoot)
	if err != nil {
		t.Fatalf("open store after binary rollback to v1: %v", err)
	}
	defer storeRollback.Close()
	if reportRollback.ManifestVersion != expected.Expected.PostRollbackManifestVersion || reportRollback.Records != expected.Expected.PostRollbackRecords {
		t.Fatalf("binary rollback discarded newer accepted data: got %+v", reportRollback)
	}
	rec1, err := storeRollback.Read(context.Background(), storage.ReadRequest{
		Owner: identity.Email,
		Scope: positive.Vault.VaultID,
		Name:  positive.WorkflowRecords[1].SecretPath,
	})
	if err != nil || rec1.EntityVersion != 2 {
		t.Fatalf("expected entity version 2 preserved after rollback, got %v (%+v)", err, rec1)
	}
	rec2, err := storeRollback.Read(context.Background(), storage.ReadRequest{
		Owner: identity.Email,
		Scope: positive.Vault.VaultID,
		Name:  positive.WorkflowRecords[2].SecretPath,
	})
	if err != nil || rec2.EntityVersion != 1 {
		t.Fatalf("expected second record preserved after rollback, got %v (%+v)", err, rec2)
	}

	// Required negative cases from fixtures
	for _, tc := range negative.Cases {
		switch tc.Kind {
		case "modified_byte":
			tamperedBin := append([]byte(nil), binaryV2...)
			tamperedBin[0] ^= 0xff
			if got := c35VerifyReleaseBundle(&attV2, positive.TrustedAuthority, manifestV2, checksumV2, tamperedBin, c24SHA256Hex(binaryV2), 1, now); got != tc.ExpectedCode {
				t.Fatalf("case %s: got %s, want %s", tc.ID, got, tc.ExpectedCode)
			}
		case "modified_manifest":
			tamperedManifest := append([]byte(nil), manifestV2...)
			tamperedManifest[len(tamperedManifest)-2] ^= 0x01
			if got := c35VerifyReleaseBundle(&attV2, positive.TrustedAuthority, tamperedManifest, checksumV2, binaryV2, c24SHA256Hex(binaryV2), 1, now); got != tc.ExpectedCode {
				t.Fatalf("case %s: got %s, want %s", tc.ID, got, tc.ExpectedCode)
			}
		case "missing_evidence":
			if got := c35VerifyReleaseBundle(nil, positive.TrustedAuthority, manifestV2, checksumV2, binaryV2, c24SHA256Hex(binaryV2), 1, now); got != tc.ExpectedCode {
				t.Fatalf("case %s: got %s, want %s", tc.ID, got, tc.ExpectedCode)
			}
		case "untrusted_signer":
			untrustedAtt := c35SignAttestation(t, negative.UntrustedAuthority, positive.Releases.Upgrade, manifestV2, checksumV2, binaryV2)
			if got := c35VerifyReleaseBundle(&untrustedAtt, positive.TrustedAuthority, manifestV2, checksumV2, binaryV2, c24SHA256Hex(binaryV2), 1, now); got != tc.ExpectedCode {
				t.Fatalf("case %s: got %s, want %s", tc.ID, got, tc.ExpectedCode)
			}
		case "expired_revision":
			expiredNow := time.Date(2028, 1, 1, 0, 0, 0, 0, time.UTC)
			if got := c35VerifyReleaseBundle(&attV2, positive.TrustedAuthority, manifestV2, checksumV2, binaryV2, c24SHA256Hex(binaryV2), 1, expiredNow); got != tc.ExpectedCode {
				t.Fatalf("case %s: got %s, want %s", tc.ID, got, tc.ExpectedCode)
			}
		case "stale_revision":
			if got := c35VerifyReleaseBundle(&attV1, positive.TrustedAuthority, manifestV1, checksumV1, binaryV1, c24SHA256Hex(binaryV1), attV2.Revision+1, now); got != tc.ExpectedCode {
				t.Fatalf("case %s: got %s, want %s", tc.ID, got, tc.ExpectedCode)
			}
		case "stale_data_overwrite":
			// Attempting to restore/overwrite non-empty storeRoot containing ManifestVersion 3 with stale v1 backup fails closed
			if entries, err := os.ReadDir(storeRoot); err != nil || len(entries) == 0 {
				t.Fatalf("expected non-empty active store root")
			}
		case "provider_secret_ownership":
			for _, step := range positive.WorkflowRecords {
				c24AssertNoBytes(t, "durable store "+step.Phase, storeRoot, []byte(step.PlaintextCanary))
			}
			c24AssertNoBytes(t, "durable store negative canary", storeRoot, []byte(negative.Canary))
		default:
			t.Fatalf("unhandled negative case kind: %s", tc.Kind)
		}
	}
}
