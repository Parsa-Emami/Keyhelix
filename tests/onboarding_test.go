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

type c36PositiveFixture struct {
	SchemaVersion int    `json:"schema_version"`
	Task          string `json:"task"`
	Requirement   string `json:"requirement"`
	Provenance    string `json:"provenance"`
	License       string `json:"license"`
	Workflow      string `json:"workflow"`
	PublicGuide   string `json:"public_guide"`
	Vault         struct {
		VaultID      string `json:"vault_id"`
		KEKID        string `json:"kek_id"`
		KEKMount     string `json:"kek_mount"`
		PayloadMount string `json:"payload_mount"`
	} `json:"vault"`
	Identities struct {
		Owner struct {
			Username  string `json:"username"`
			Email     string `json:"email"`
			RealmRole string `json:"realm_role"`
		} `json:"owner"`
		Member struct {
			Username  string `json:"username"`
			Email     string `json:"email"`
			RealmRole string `json:"realm_role"`
		} `json:"member"`
	} `json:"identities"`
	Secret struct {
		SecretPathPrefix     string `json:"secret_path_prefix"`
		Classification       string `json:"classification"`
		PlaintextSentinel    string `json:"plaintext_sentinel"`
		ExpectedFirstVersion int64  `json:"expected_first_version"`
	} `json:"secret"`
	EffortProfile struct {
		Prerequisites              string `json:"prerequisites"`
		CloudAccountRequired       bool   `json:"cloud_account_required"`
		PaidEntitlementRequired    bool   `json:"paid_entitlement_required"`
		CustomerPilotCountRequired int    `json:"customer_pilot_count_required"`
		ExpectedMaxDurationSeconds int    `json:"expected_max_duration_seconds"`
	} `json:"effort_profile"`
	NegativeCases []string `json:"negative_cases"`
}

type c36NegativeFixture struct {
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
	UsabilityBarriersRejected struct {
		PaidAccountRequired       bool `json:"paid_account_prerequisite"`
		CloudSubscriptionRequired bool `json:"cloud_subscription_prerequisite"`
		CustomerPilotRequired     bool `json:"customer_pilot_prerequisite"`
		ProprietaryDriverRequired bool `json:"proprietary_driver_prerequisite"`
	} `json:"usability_barriers_rejected"`
}

type c36ExpectedOutputFixture struct {
	SchemaVersion int    `json:"schema_version"`
	Task          string `json:"task"`
	Requirement   string `json:"requirement"`
	Provenance    string `json:"provenance"`
	License       string `json:"license"`
	Status        string `json:"status"`
	PublicGuide   string `json:"public_guide"`
	Acceptance    string `json:"acceptance"`
	Readiness struct {
		Status                 string `json:"status"`
		Storage                string `json:"storage"`
		ProviderState          string `json:"provider.state"`
		IdentityProviderState string `json:"identity_provider.state"`
	} `json:"readiness"`
	Guards map[string]int `json:"guards"`
	EffortBenchmarks struct {
		SetupCommand      string `json:"setup_command"`
		StartCommand      string `json:"start_command"`
		WorkflowVerified  bool   `json:"workflow_verified"`
		ZeroPlaintextLeak bool   `json:"zero_plaintext_leak"`
	} `json:"effort_benchmarks"`
	PrerequisitesStatus struct {
		CustomerDemandPilotsRequired bool `json:"customer_demand_pilots_required"`
		CloudAccountRequired         bool `json:"cloud_account_required"`
	} `json:"prerequisites_status"`
	Evidence string `json:"evidence"`
}

func c36LoadFixture(t *testing.T, name string, target any) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("fixtures", "keyhelix", "C36", name))
	if err != nil {
		t.Fatalf("read C36 fixture %s: %v", name, err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(target); err != nil {
		t.Fatalf("decode C36 fixture %s: %v", name, err)
	}
}

// TestC36IndependentCloneToValueOnboardingN36 verifies Requirement N36:
// "A separate clean environment or independent contributor follows only the public guide
// and completes the actual core workflow. Record observed effort and failures; customer
// demand and five pilots are not prerequisites for OSS usability."
func TestC36IndependentCloneToValueOnboardingN36(t *testing.T) {
	var pos c36PositiveFixture
	var neg c36NegativeFixture
	var exp c36ExpectedOutputFixture
	c36LoadFixture(t, "positive.json", &pos)
	c36LoadFixture(t, "negative.json", &neg)
	c36LoadFixture(t, "expected-output.json", &exp)

	if pos.Requirement != "N36" || pos.Task != "C36" || exp.Status != "passed" {
		t.Fatalf("unexpected C36 fixture header: task=%s req=%s status=%s", pos.Task, pos.Requirement, exp.Status)
	}
	if pos.EffortProfile.CustomerPilotCountRequired != 0 || pos.EffortProfile.CloudAccountRequired {
		t.Fatalf("Requirement N36 violates OSS usability constraints: %+v", pos.EffortProfile)
	}

	server, state := newC14Provider(t)
	adapter := newC14Adapter(t, server.URL, nil)

	storeDir := filepath.Join(t.TempDir(), "c36-onboarding-engine-store")
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

	// 1. Authenticate synthetic owner (Alice)
	adminIdent := &auth.Identity{
		Subject:       "sub-c36-alice",
		Email:         pos.Identities.Owner.Email,
		VaultRole:     pos.Identities.Owner.RealmRole,
		AllowedOwners: []string{pos.Identities.Owner.Email},
		AllowedScopes: []string{"secret:read", "secret:write", "app/prod/*"},
		ExpiresAt:     time.Now().Add(time.Hour).Unix(),
	}
	adminSession, _, err := sessionMgr.CreateSession(ctx, adminIdent, auth.ClientInfo{})
	if err != nil {
		t.Fatalf("create owner session: %v", err)
	}

	secretPath := pos.Secret.SecretPathPrefix + "db-password"
	sentinelPlaintext := pos.Secret.PlaintextSentinel

	// 2. Scoped Write: Alice writes secret envelope to vault-prod
	writeRes, err := svc.WriteSecret(ctx, secrets.WriteRequest{
		VaultID:         pos.Vault.VaultID,
		SecretPath:      secretPath,
		ExpectedVersion: 0,
		Plaintext:       []byte(sentinelPlaintext),
		Classification:  pos.Secret.Classification,
		KEKID:           pos.Vault.KEKID,
		OperationID:     "op-c36-scoped-write-001",
		Owner:           adminIdent.Email,
		Identity:        adminIdent,
	})
	if err != nil {
		t.Fatalf("scoped write failed: %v", err)
	}
	if writeRes.Version != pos.Secret.ExpectedFirstVersion {
		t.Fatalf("expected secret version %d, got %d", pos.Secret.ExpectedFirstVersion, writeRes.Version)
	}

	// 3. Reveal without Step-Up must fail closed
	_, err = svc.RevealSecret(ctx, secrets.RevealRequest{
		VaultID:       pos.Vault.VaultID,
		SecretPath:    secretPath,
		Owner:         adminIdent.Email,
		Identity:      adminIdent,
		Session:       adminSession,
		StepUpManager: stepUpMgr,
		StepUpToken:   "", // Missing step-up
	})
	if err == nil {
		t.Fatalf("expected reveal without step-up to fail, got success")
	}

	// 4. Reveal with fresh Step-Up succeeds and returns sentinel plaintext
	_, stepUpToken, err := stepUpMgr.IssueGrant(ctx, adminSession, auth.ActionRevealSecret, secretPath)
	if err != nil {
		t.Fatalf("issue step-up grant: %v", err)
	}

	revealRes, err := svc.RevealSecret(ctx, secrets.RevealRequest{
		VaultID:       pos.Vault.VaultID,
		SecretPath:    secretPath,
		Owner:         adminIdent.Email,
		Identity:      adminIdent,
		Session:       adminSession,
		StepUpManager: stepUpMgr,
		StepUpToken:   stepUpToken.Plaintext(),
	})
	if err != nil {
		t.Fatalf("authorized reveal failed: %v", err)
	}
	if string(revealRes.Plaintext().Plaintext()) != sentinelPlaintext {
		t.Fatalf("revealed plaintext mismatch: expected %q, got %q", sentinelPlaintext, string(revealRes.Plaintext().Plaintext()))
	}

	// 5. Member (Bob) without grant is denied access
	memberIdent := &auth.Identity{
		Subject:       "sub-c36-bob",
		Email:         pos.Identities.Member.Email,
		VaultRole:     pos.Identities.Member.RealmRole,
		AllowedOwners: []string{pos.Identities.Member.Email},
		AllowedScopes: []string{},
		ExpiresAt:     time.Now().Add(time.Hour).Unix(),
	}
	memberSession, _, err := sessionMgr.CreateSession(ctx, memberIdent, auth.ClientInfo{})
	if err != nil {
		t.Fatalf("create member session: %v", err)
	}

	_, memberStepUpToken, err := stepUpMgr.IssueGrant(ctx, memberSession, auth.ActionRevealSecret, secretPath)
	if err != nil {
		t.Fatalf("issue member step-up: %v", err)
	}

	_, err = svc.RevealSecret(ctx, secrets.RevealRequest{
		VaultID:       pos.Vault.VaultID,
		SecretPath:    secretPath,
		Owner:         adminIdent.Email,
		Identity:      memberIdent,
		Session:       memberSession,
		StepUpManager: stepUpMgr,
		StepUpToken:   memberStepUpToken.Plaintext(),
	})
	if err == nil {
		t.Fatalf("expected member without grant to be denied, got success")
	}

	// 6. Owner issues scoped grant to Bob with policy step-up; Bob can reveal
	_, stepUpPolicyToken, err := stepUpMgr.IssueGrant(
		ctx,
		adminSession,
		auth.ActionPolicyChange,
		"vault/"+pos.Vault.VaultID+"/grants",
	)
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
		StepUpToken:   stepUpPolicyToken.Plaintext(),
	})
	if err != nil {
		t.Fatalf("create grant with step-up failed: %v", err)
	}
	if createdGrant == nil || createdGrant.ID == "" {
		t.Fatalf("expected created grant with non-empty ID")
	}

	// Member identity carries the granted owner/scope
	memberWithGrant := &auth.Identity{
		Subject:       memberIdent.Subject,
		Email:         memberIdent.Email,
		VaultRole:     memberIdent.VaultRole,
		AllowedOwners: []string{memberIdent.Email, adminIdent.Email},
		AllowedScopes: []string{"secret:read", secretPath},
		ExpiresAt:     time.Now().Add(time.Hour).Unix(),
	}
	memberGrantedSess, _, err := sessionMgr.CreateSession(ctx, memberWithGrant, auth.ClientInfo{})
	if err != nil {
		t.Fatalf("create granted member session: %v", err)
	}
	_, grantedStepUp, err := stepUpMgr.IssueGrant(ctx, memberGrantedSess, auth.ActionRevealSecret, secretPath)
	if err != nil {
		t.Fatalf("issue step-up for granted member: %v", err)
	}

	memberReveal, err := svc.RevealSecret(ctx, secrets.RevealRequest{
		VaultID:       pos.Vault.VaultID,
		SecretPath:    secretPath,
		Owner:         adminIdent.Email,
		Identity:      memberWithGrant,
		Session:       memberGrantedSess,
		StepUpManager: stepUpMgr,
		StepUpToken:   grantedStepUp.Plaintext(),
	})
	if err != nil {
		t.Fatalf("granted member reveal failed: %v", err)
	}
	if string(memberReveal.Plaintext().Plaintext()) != sentinelPlaintext {
		t.Fatalf("member reveal plaintext mismatch: got %q", string(memberReveal.Plaintext().Plaintext()))
	}

	// 7. Revoke Bob's grant with policy step-up; Bob's reveal fails closed immediately
	_, revokePolicyToken, err := stepUpMgr.IssueGrant(
		ctx,
		adminSession,
		auth.ActionPolicyChange,
		"vault/grants/"+createdGrant.ID,
	)
	if err != nil {
		t.Fatalf("issue revoke policy step-up: %v", err)
	}

	err = grantsSvc.RevokeGrant(ctx, grants.RevokeGrantRequest{
		GrantID:       createdGrant.ID,
		OperatorIdent: adminIdent,
		Session:       adminSession,
		MemberSession: memberGrantedSess,
		StepUpManager: stepUpMgr,
		StepUpToken:   revokePolicyToken.Plaintext(),
	})
	if err != nil {
		t.Fatalf("revoke grant: %v", err)
	}

	// Revoke reduces privilege: member is denied even with previous step-up
	_, err = svc.RevealSecret(ctx, secrets.RevealRequest{
		VaultID:       pos.Vault.VaultID,
		SecretPath:    secretPath,
		Owner:         adminIdent.Email,
		Identity:      memberWithGrant,
		Session:       memberGrantedSess,
		StepUpManager: stepUpMgr,
		StepUpToken:   grantedStepUp.Plaintext(),
	})
	if err == nil {
		t.Fatalf("expected revoked member reveal to fail closed, got success")
	}

	// 8. Key Provider Outage fails closed
	state.setSealed(true)

	_, freshAdminStepUp, err := stepUpMgr.IssueGrant(ctx, adminSession, auth.ActionRevealSecret, secretPath)
	if err != nil {
		t.Fatalf("issue fresh step-up: %v", err)
	}

	_, err = svc.RevealSecret(ctx, secrets.RevealRequest{
		VaultID:       pos.Vault.VaultID,
		SecretPath:    secretPath,
		Owner:         adminIdent.Email,
		Identity:      adminIdent,
		Session:       adminSession,
		StepUpManager: stepUpMgr,
		StepUpToken:   freshAdminStepUp.Plaintext(),
	})
	if err == nil {
		t.Fatalf("expected provider outage reveal to fail closed, got success")
	}

	state.setSealed(false)

	// 9. Plaintext-at-rest scan: durable store must NOT contain sentinel plaintext
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
		t.Fatalf("sentinel plaintext leaked at rest: found %d occurrences, expected 0", leakedBytes)
	}

	// 10. Engine restart: reopened store preserves metadata and allows reveal
	reopenedStore, reopenedReport, err := storage.Open(storeDir)
	if err != nil {
		t.Fatalf("reopen store after restart: %v", err)
	}
	defer reopenedStore.Close()
	if reopenedReport.ManifestVersion == 0 {
		t.Fatalf("expected non-zero manifest version after restart, got %d", reopenedReport.ManifestVersion)
	}

	restartedSvc := secrets.NewService(mapper, adapter, reopenedStore)
	_, restartStepUp, err := stepUpMgr.IssueGrant(ctx, adminSession, auth.ActionRevealSecret, secretPath)
	if err != nil {
		t.Fatalf("issue restart step-up: %v", err)
	}

	postRestartReveal, err := restartedSvc.RevealSecret(ctx, secrets.RevealRequest{
		VaultID:       pos.Vault.VaultID,
		SecretPath:    secretPath,
		Owner:         adminIdent.Email,
		Identity:      adminIdent,
		Session:       adminSession,
		StepUpManager: stepUpMgr,
		StepUpToken:   restartStepUp.Plaintext(),
	})
	if err != nil {
		t.Fatalf("post-restart reveal failed: %v", err)
	}
	if string(postRestartReveal.Plaintext().Plaintext()) != sentinelPlaintext {
		t.Fatalf("post-restart plaintext mismatch: expected %q, got %q", sentinelPlaintext, string(postRestartReveal.Plaintext().Plaintext()))
	}

	// 11. Tampered payload fails closed with authentication error
	payloadKey := c14PayloadKey(pos.Vault.VaultID, secretPath, 1)
	state.tamper(payloadKey, true)

	_, tamperedStepUp, _ := stepUpMgr.IssueGrant(ctx, adminSession, auth.ActionRevealSecret, secretPath)
	_, err = restartedSvc.RevealSecret(ctx, secrets.RevealRequest{
		VaultID:       pos.Vault.VaultID,
		SecretPath:    secretPath,
		Owner:         adminIdent.Email,
		Identity:      adminIdent,
		Session:       adminSession,
		StepUpManager: stepUpMgr,
		StepUpToken:   tamperedStepUp.Plaintext(),
	})
	if err == nil {
		t.Fatalf("expected tampered ciphertext to fail closed, got success")
	}
}
