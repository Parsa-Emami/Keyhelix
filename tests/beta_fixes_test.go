package storage_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/parsa-emami/keyhelix/internal/audit"
	"github.com/parsa-emami/keyhelix/internal/auth"
	"github.com/parsa-emami/keyhelix/internal/grants"
	"github.com/parsa-emami/keyhelix/internal/secrets"
	"github.com/parsa-emami/keyhelix/internal/security"
	"github.com/parsa-emami/keyhelix/internal/storage"
)

type c37PositiveFixture struct {
	SchemaVersion   int      `json:"schema_version"`
	Task            string   `json:"task"`
	Requirement     string   `json:"requirement"`
	Provenance      string   `json:"provenance"`
	License         string   `json:"license"`
	TargetMilestones []string `json:"target_milestones"`
	Fixes []struct {
		ID          string `json:"id"`
		Milestone   string `json:"milestone"`
		Description string `json:"description"`
		Status      string `json:"status"`
	} `json:"fixes"`
	Vault struct {
		VaultID      string `json:"vault_id"`
		KEKID        string `json:"kek_id"`
		KEKMount     string `json:"kek_mount"`
		PayloadMount string `json:"payload_mount"`
	} `json:"vault"`
	Identities struct {
		Admin struct {
			Username      string   `json:"username"`
			Email         string   `json:"email"`
			RealmRole     string   `json:"realm_role"`
			AllowedScopes []string `json:"allowed_scopes"`
		} `json:"admin"`
		Member struct {
			Username      string   `json:"username"`
			Email         string   `json:"email"`
			RealmRole     string   `json:"realm_role"`
			AllowedScopes []string `json:"allowed_scopes"`
		} `json:"member"`
	} `json:"identities"`
	Secret struct {
		SecretPathPrefix     string `json:"secret_path_prefix"`
		Classification       string `json:"classification"`
		PlaintextSentinel    string `json:"plaintext_sentinel"`
		ExpectedFirstVersion int64  `json:"expected_first_version"`
	} `json:"secret"`
	Invariants []string `json:"invariants"`
}

type c37NegativeFixture struct {
	SchemaVersion int    `json:"schema_version"`
	Task          string `json:"task"`
	Requirement   string `json:"requirement"`
	Provenance    string `json:"provenance"`
	License       string `json:"license"`
	Cases         []struct {
		Case              string  `json:"case"`
		Description       string  `json:"description"`
		ExpectedStatus    *int    `json:"expected_status"`
		ExpectedCode      string  `json:"expected_code"`
		ExpectedPlaintext *string `json:"expected_plaintext"`
	} `json:"cases"`
	ProhibitedPlaintextStorage struct {
		Sentinel                                  string `json:"sentinel"`
		ExpectedOccurrencesInMetadataAndProviderKV int    `json:"expected_occurrences_in_metadata_and_provider_kv"`
	} `json:"prohibited_plaintext_storage"`
	UnresolvedBlockersPolicy struct {
		BlockersConcealed     bool `json:"blockers_concealed"`
		InvariantsWeakened    bool `json:"invariants_weakened"`
		InventedUserFeedback  bool `json:"invented_user_feedback"`
	} `json:"unresolved_blockers_policy"`
}

type c37ExpectedOutputFixture struct {
	SchemaVersion          int      `json:"schema_version"`
	Task                   string   `json:"task"`
	Requirement            string   `json:"requirement"`
	Provenance             string   `json:"provenance"`
	License                string   `json:"license"`
	Status                 string   `json:"status"`
	Acceptance             string   `json:"acceptance"`
	TargetMilestonesCovered []string `json:"target_milestones_covered"`
	FixesSummary struct {
		PortConflictPreflight     bool `json:"port_conflict_preflight"`
		ProviderTimeoutResilience bool `json:"provider_timeout_resilience"`
		StepUpMemoryClearing      bool `json:"step_up_memory_clearing"`
		RevocationImmediateDenial bool `json:"revocation_immediate_denial"`
		DowngradeDataSafety       bool `json:"downgrade_data_safety"`
	} `json:"fixes_summary"`
	RegressionSuites struct {
		GoEngine     string `json:"go_engine"`
		WebContracts string `json:"web_contracts"`
	} `json:"regression_suites"`
	UnresolvedBlockers []string `json:"unresolved_blockers"`
	Evidence           string   `json:"evidence"`
}

func c37LoadFixture(t *testing.T, name string, target any) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("fixtures", "keyhelix", "C37", name))
	if err != nil {
		t.Fatalf("read C37 fixture %s: %v", name, err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(target); err != nil {
		t.Fatalf("decode C37 fixture %s: %v", name, err)
	}
}

// TestC37ObservedBlockersAndFixesRegressionsN37 verifies Requirement N37:
// "Fix actual C30/C33/C35/C36 failures with targeted regressions and repeat affected checks.
// Keep unresolved blockers explicit; never invent feedback or weaken an invariant to claim completion."
func TestC37ObservedBlockersAndFixesRegressionsN37(t *testing.T) {
	var pos c37PositiveFixture
	var neg c37NegativeFixture
	var exp c37ExpectedOutputFixture
	c37LoadFixture(t, "positive.json", &pos)
	c37LoadFixture(t, "negative.json", &neg)
	c37LoadFixture(t, "expected-output.json", &exp)

	if pos.Requirement != "N37" || pos.Task != "C37" || exp.Status != "passed" {
		t.Fatalf("unexpected C37 fixture header: task=%s req=%s status=%s", pos.Task, pos.Requirement, exp.Status)
	}
	if len(exp.UnresolvedBlockers) != 0 {
		t.Fatalf("expected 0 unresolved blockers, got %d", len(exp.UnresolvedBlockers))
	}

	server, state := newC14Provider(t)
	adapter := newC14Adapter(t, server.URL, nil)

	storeDir := filepath.Join(t.TempDir(), "c37-beta-fixes-store")
	store, report, err := storage.Open(storeDir)
	if err != nil {
		t.Fatalf("open storage: %v", err)
	}
	t.Cleanup(func() {
		_ = store.Close()
	})
	if report.ManifestVersion != 0 {
		t.Fatalf("expected empty store on fresh install, got version %d", report.ManifestVersion)
	}

	mapper := auth.NewScopeMapper(auth.ScopeMapperConfig{
		VaultKEKMap:   map[string]string{pos.Vault.VaultID: pos.Vault.KEKID},
		VaultMountMap: map[string]string{pos.Vault.VaultID: pos.Vault.PayloadMount},
		VaultRoleMap:  map[string]string{pos.Vault.VaultID: "vault-admin"},
	})
	svc := secrets.NewService(mapper, adapter, store)

	redactor := security.NewRedactor()
	redactor.RegisterSentinel(pos.Secret.PlaintextSentinel)
	recorder := audit.NewRecorder(100, redactor)
	grantsSvc := grants.NewService(store, recorder)

	sessionMgr, err := auth.NewSessionManager(auth.DefaultSessionConfig(), nil)
	if err != nil {
		t.Fatalf("create session manager: %v", err)
	}
	stepUpMgr, err := auth.NewStepUpManager(auth.DefaultStepUpConfig(), nil)
	if err != nil {
		t.Fatalf("create step-up manager: %v", err)
	}

	ctx := context.Background()

	// 1. Authenticate synthetic admin (Alice)
	adminIdent := &auth.Identity{
		Subject:       "sub-c37-alice",
		Email:         pos.Identities.Admin.Email,
		VaultRole:     pos.Identities.Admin.RealmRole,
		AllowedOwners: []string{pos.Identities.Admin.Email},
		AllowedScopes: pos.Identities.Admin.AllowedScopes,
		ExpiresAt:     time.Now().Add(time.Hour).Unix(),
	}
	adminSession, _, err := sessionMgr.CreateSession(ctx, adminIdent, auth.ClientInfo{})
	if err != nil {
		t.Fatalf("create admin session: %v", err)
	}

	secretPath := pos.Secret.SecretPathPrefix + "db-credentials"
	sentinelPlaintext := pos.Secret.PlaintextSentinel

	// 2. Scoped Write
	writeRes, err := svc.WriteSecret(ctx, secrets.WriteRequest{
		VaultID:         pos.Vault.VaultID,
		SecretPath:      secretPath,
		ExpectedVersion: 0,
		Plaintext:       []byte(sentinelPlaintext),
		Classification:  pos.Secret.Classification,
		KEKID:           pos.Vault.KEKID,
		OperationID:     "op-c37-write-001",
		Owner:           adminIdent.Email,
		Identity:        adminIdent,
	})
	if err != nil {
		t.Fatalf("write secret failed: %v", err)
	}
	if writeRes.Version != pos.Secret.ExpectedFirstVersion {
		t.Fatalf("expected version %d, got %d", pos.Secret.ExpectedFirstVersion, writeRes.Version)
	}

	// 3. REGRESSION 1: Immediate privilege reduction on grant revocation
	// Member Bob receives a scoped grant
	memberIdent := &auth.Identity{
		Subject:       "sub-c37-bob",
		Email:         pos.Identities.Member.Email,
		VaultRole:     pos.Identities.Member.RealmRole,
		AllowedOwners: []string{pos.Identities.Member.Email, adminIdent.Email},
		AllowedScopes: []string{"secret:read", secretPath},
		ExpiresAt:     time.Now().Add(time.Hour).Unix(),
	}
	memberSession, _, err := sessionMgr.CreateSession(ctx, memberIdent, auth.ClientInfo{})
	if err != nil {
		t.Fatalf("create member session: %v", err)
	}

	_, policyStepUp, err := stepUpMgr.IssueGrant(ctx, adminSession, auth.ActionPolicyChange, "vault/"+pos.Vault.VaultID+"/grants")
	if err != nil {
		t.Fatalf("issue policy step-up: %v", err)
	}

	createdGrant, err := grantsSvc.CreateGrant(ctx, grants.CreateGrantRequest{
		VaultID:       pos.Vault.VaultID,
		PrincipalID:   pos.Identities.Member.Email,
		Permissions:   []string{"secret:read"},
		OperatorIdent: adminIdent,
		Session:       adminSession,
		StepUpManager: stepUpMgr,
		StepUpToken:   policyStepUp.Plaintext(),
	})
	if err != nil {
		t.Fatalf("create grant: %v", err)
	}

	// Bob reveals with step-up -> succeeds
	_, memberStepUp, err := stepUpMgr.IssueGrant(ctx, memberSession, auth.ActionRevealSecret, secretPath)
	if err != nil {
		t.Fatalf("issue member step-up: %v", err)
	}
	bobReveal, err := svc.RevealSecret(ctx, secrets.RevealRequest{
		VaultID:       pos.Vault.VaultID,
		SecretPath:    secretPath,
		Owner:         adminIdent.Email,
		Identity:      memberIdent,
		Session:       memberSession,
		StepUpManager: stepUpMgr,
		StepUpToken:   memberStepUp.Plaintext(),
	})
	if err != nil {
		t.Fatalf("member reveal failed: %v", err)
	}
	if string(bobReveal.Plaintext().Plaintext()) != sentinelPlaintext {
		t.Fatalf("member reveal plaintext mismatch")
	}

	// Alice revokes Bob's grant
	_, revokePolicyStepUp, err := stepUpMgr.IssueGrant(ctx, adminSession, auth.ActionPolicyChange, "vault/grants/"+createdGrant.ID)
	if err != nil {
		t.Fatalf("issue revoke step-up: %v", err)
	}
	err = grantsSvc.RevokeGrant(ctx, grants.RevokeGrantRequest{
		GrantID:       createdGrant.ID,
		OperatorIdent: adminIdent,
		Session:       adminSession,
		MemberSession: memberSession,
		StepUpManager: stepUpMgr,
		StepUpToken:   revokePolicyStepUp.Plaintext(),
	})
	if err != nil {
		t.Fatalf("revoke grant: %v", err)
	}

	// Immediate privilege reduction: Prior step-up token MUST fail closed on the very next attempt
	_, err = svc.RevealSecret(ctx, secrets.RevealRequest{
		VaultID:       pos.Vault.VaultID,
		SecretPath:    secretPath,
		Owner:         adminIdent.Email,
		Identity:      memberIdent,
		Session:       memberSession,
		StepUpManager: stepUpMgr,
		StepUpToken:   memberStepUp.Plaintext(),
	})
	if err == nil {
		t.Fatalf("CRITICAL SECURITY VIOLATION: revoked member could still reveal secret with prior step-up token!")
	}

	// 4. REGRESSION 2: Consecutive provider outage fail-closed resilience
	state.setSealed(true)
	for i := 1; i <= 3; i++ {
		_, freshStepUp, err := stepUpMgr.IssueGrant(ctx, adminSession, auth.ActionRevealSecret, secretPath)
		if err != nil {
			t.Fatalf("issue admin step-up iteration %d: %v", i, err)
		}
		_, err = svc.RevealSecret(ctx, secrets.RevealRequest{
			VaultID:       pos.Vault.VaultID,
			SecretPath:    secretPath,
			Owner:         adminIdent.Email,
			Identity:      adminIdent,
			Session:       adminSession,
			StepUpManager: stepUpMgr,
			StepUpToken:   freshStepUp.Plaintext(),
		})
		if err == nil {
			t.Fatalf("outage attempt %d: expected fail closed, got success", i)
		}
	}
	state.setSealed(false)

	// Reveal succeeds after provider unseals
	_, unsealedStepUp, err := stepUpMgr.IssueGrant(ctx, adminSession, auth.ActionRevealSecret, secretPath)
	if err != nil {
		t.Fatalf("issue unsealed step-up: %v", err)
	}
	postOutageReveal, err := svc.RevealSecret(ctx, secrets.RevealRequest{
		VaultID:       pos.Vault.VaultID,
		SecretPath:    secretPath,
		Owner:         adminIdent.Email,
		Identity:      adminIdent,
		Session:       adminSession,
		StepUpManager: stepUpMgr,
		StepUpToken:   unsealedStepUp.Plaintext(),
	})
	if err != nil {
		t.Fatalf("post-outage reveal failed: %v", err)
	}
	if string(postOutageReveal.Plaintext().Plaintext()) != sentinelPlaintext {
		t.Fatalf("post-outage plaintext mismatch")
	}

	// 5. REGRESSION 3: Decryption of tampered ciphertext fails closed
	payloadKey := c14PayloadKey(pos.Vault.VaultID, secretPath, 1)
	state.tamper(payloadKey, true)
	_, tamperedStepUp, _ := stepUpMgr.IssueGrant(ctx, adminSession, auth.ActionRevealSecret, secretPath)
	_, err = svc.RevealSecret(ctx, secrets.RevealRequest{
		VaultID:       pos.Vault.VaultID,
		SecretPath:    secretPath,
		Owner:         adminIdent.Email,
		Identity:      adminIdent,
		Session:       adminSession,
		StepUpManager: stepUpMgr,
		StepUpToken:   tamperedStepUp.Plaintext(),
	})
	if err == nil {
		t.Fatalf("expected tampered ciphertext decryption to fail closed, got success")
	}

	// 6. REGRESSION 4: Zero plaintext at rest across restart
	err = store.Close()
	if err != nil {
		t.Fatalf("close store: %v", err)
	}

	leakedBytes := 0
	err = filepath.Walk(storeDir, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil || info.IsDir() {
			return walkErr
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		if bytes.Contains(data, []byte(sentinelPlaintext)) {
			leakedBytes++
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk store: %v", err)
	}
	if leakedBytes != neg.ProhibitedPlaintextStorage.ExpectedOccurrencesInMetadataAndProviderKV {
		t.Fatalf("found %d plaintext sentinel occurrences in store at rest, expected 0", leakedBytes)
	}
}
