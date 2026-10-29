// Package grants implements least-privilege provider access control and membership grants (Requirement F11).
//
// Invariants:
//  1. Member changes require step-up authentication (ActionPolicyChange).
//  2. Privilege reduction takes effect synchronously on the next sensitive request.
//  3. Emits attributable CloudEvents (grant.created.v1, grant.revoked.v1) without secret or bearer credential leakage.
package grants

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/parsa-emami/keyhelix/internal/audit"
	"github.com/parsa-emami/keyhelix/internal/auth"
	"github.com/parsa-emami/keyhelix/internal/contracts"
	"github.com/parsa-emami/keyhelix/internal/storage"
)

// Grant error codes.
const (
	CodeGrantNotFound  = "GRANT_NOT_FOUND"
	CodeStepUpRequired = "STEP_UP_REQUIRED"
	CodeUnauthorized   = "UNAUTHORIZED"
	CodeInvalidInput   = "INVALID_INPUT"
	CodeGrantRevoked   = "GRANT_REVOKED"
)

// Error represents a typed grant error.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Err     error  `json:"-"`
}

func (e *Error) Error() string {
	if e.Message != "" {
		return e.Code + ": " + e.Message
	}
	return e.Code
}

func (e *Error) Unwrap() error { return e.Err }

// Grant represents an attributable access grant bound to a principal and vault.
type Grant struct {
	ID          string     `json:"id"`
	VaultID     string     `json:"vault_id"`
	PrincipalID string     `json:"principal_id"`
	Permissions []string   `json:"permissions"`
	CreatedAt   time.Time  `json:"created_at"`
	ExpiresAt   time.Time  `json:"expires_at"`
	RevokedAt   *time.Time `json:"revoked_at,omitempty"`
	RevokedBy   string     `json:"revoked_by,omitempty"`
}

// IsActive returns whether the grant is currently active (unrevoked and unexpired).
func (g *Grant) IsActive(now time.Time) bool {
	if g.RevokedAt != nil {
		return false
	}
	if !g.ExpiresAt.IsZero() && now.After(g.ExpiresAt) {
		return false
	}
	return true
}

// AllowsPath checks whether the grant's permissions allow access to the given path and action.
func (g *Grant) AllowsPath(action, canonicalPath string) bool {
	actionAllowed := false
	pathAllowed := false
	hasPathRestrictions := false

	for _, perm := range g.Permissions {
		if perm == action || perm == "*" {
			actionAllowed = true
		}
		if strings.Contains(perm, "/") {
			hasPathRestrictions = true
			if auth.MatchPathScope(perm, canonicalPath) {
				pathAllowed = true
			}
		}
	}

	if !hasPathRestrictions {
		pathAllowed = true
	}
	return actionAllowed && pathAllowed
}

// CreateGrantRequest defines inputs for creating a member grant.
type CreateGrantRequest struct {
	VaultID       string
	PrincipalID   string
	Permissions   []string
	ExpiresAt     time.Time
	OperatorIdent *auth.Identity
	Session       *auth.Session
	StepUpManager *auth.StepUpManager
	StepUpToken   string
}

// RevokeGrantRequest defines inputs for revoking a member grant.
type RevokeGrantRequest struct {
	GrantID       string
	OperatorIdent *auth.Identity
	Session       *auth.Session
	MemberSession *auth.Session
	StepUpManager *auth.StepUpManager
	StepUpToken   string
}

// Service manages least privilege member grants and authorizations.
type Service struct {
	mu       sync.RWMutex
	store    storage.Port
	recorder *audit.Recorder
	grants   map[string]*Grant
}

// NewService constructs a new Grants Service.
func NewService(store storage.Port, recorder *audit.Recorder) *Service {
	return &Service{
		store:    store,
		recorder: recorder,
		grants:   make(map[string]*Grant),
	}
}

// Restore rebuilds the in-memory grant index from committed metadata records.
// It runs once at engine startup before any request is served.
func (s *Service) Restore(ctx context.Context) (int, error) {
	lister, ok := s.store.(storage.Lister)
	if !ok || s.store == nil {
		return 0, nil
	}
	records, err := lister.List(ctx, storage.ListRequest{Scope: "grants"})
	if err != nil {
		return 0, err
	}
	restored := 0
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, record := range records {
		var grant Grant
		if err := json.Unmarshal(record.Metadata, &grant); err != nil {
			return restored, &contracts.ValidationError{Code: contracts.InvalidInput, Field: "grant_metadata"}
		}
		if grant.ID == "" || grant.ID != record.Name {
			return restored, &contracts.ValidationError{Code: contracts.InvalidInput, Field: "grant_id"}
		}
		s.grants[grant.ID] = &grant
		restored++
	}
	return restored, nil
}

// List returns the grants for one vault, newest first. It includes revoked
// grants so the operator can audit the final state after revocation.
func (s *Service) List(vaultID string) []*Grant {
	s.mu.RLock()
	defer s.mu.RUnlock()
	list := make([]*Grant, 0, len(s.grants))
	for _, grant := range s.grants {
		if vaultID == "" || grant.VaultID == vaultID {
			copy := *grant
			list = append(list, &copy)
		}
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].CreatedAt.Equal(list[j].CreatedAt) {
			return list[i].ID > list[j].ID
		}
		return list[i].CreatedAt.After(list[j].CreatedAt)
	})
	return list
}

// CreateGrant requires step-up authentication and establishes a least privilege member grant.
func (s *Service) CreateGrant(ctx context.Context, req CreateGrantRequest) (*Grant, error) {
	if strings.TrimSpace(req.VaultID) == "" {
		return nil, &contracts.ValidationError{Code: contracts.InvalidInput, Field: "vault_id"}
	}
	if strings.TrimSpace(req.PrincipalID) == "" {
		return nil, &contracts.ValidationError{Code: contracts.InvalidInput, Field: "principal_id"}
	}
	if len(req.Permissions) == 0 {
		return nil, &contracts.ValidationError{Code: contracts.InvalidInput, Field: "permissions"}
	}

	// 1. Invariant: Member changes require fresh step-up (ActionPolicyChange)
	if req.StepUpManager == nil || req.Session == nil {
		return nil, &Error{Code: CodeStepUpRequired, Message: "step-up authentication required for policy changes"}
	}
	_, err := req.StepUpManager.ValidateStepUp(
		ctx,
		req.Session,
		req.StepUpToken,
		auth.ActionPolicyChange,
		"vault/"+req.VaultID+"/grants",
	)
	if err != nil {
		return nil, &Error{Code: CodeUnauthorized, Message: "step-up authorization failed for member grant creation", Err: err}
	}

	// 2. Generate unique grant ID
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	grantID := "grnt-" + hex.EncodeToString(b)

	now := time.Now().UTC()
	grant := &Grant{
		ID:          grantID,
		VaultID:     req.VaultID,
		PrincipalID: req.PrincipalID,
		Permissions: append([]string(nil), req.Permissions...),
		CreatedAt:   now,
		ExpiresAt:   req.ExpiresAt,
	}

	// 3. Persist grant metadata
	grantBytes, err := json.Marshal(grant)
	if err != nil {
		return nil, err
	}
	if s.store != nil {
		_, err = s.store.Write(ctx, storage.WriteRequest{
			OperationID:     "op-create-" + grantID,
			Owner:           req.OperatorIdent.Email,
			Scope:           "grants",
			Name:            grantID,
			ExpectedVersion: 0,
			Metadata:        grantBytes,
		})
		if err != nil {
			return nil, err
		}
	}

	s.mu.Lock()
	s.grants[grantID] = grant
	s.mu.Unlock()

	// 4. Emit attributable audit event
	if s.recorder != nil {
		evt, evtErr := audit.NewEvent(
			audit.EventGrantCreated,
			req.VaultID+"/"+req.PrincipalID,
			audit.AuditData{
				Actor:   req.OperatorIdent.Email,
				VaultID: req.VaultID,
				Action:  "grant:create",
				Outcome: "success",
				Details: map[string]any{
					"grant_id":     grantID,
					"principal_id": req.PrincipalID,
					"permissions":  req.Permissions,
				},
			},
		)
		if evtErr == nil {
			_ = s.recorder.Record(ctx, evt)
		}
	}

	return grant, nil
}

// RevokeGrant requires step-up authentication and immediately revokes a member's privilege.
// Invariant: Privilege reduction takes effect synchronously on the next sensitive request.
func (s *Service) RevokeGrant(ctx context.Context, req RevokeGrantRequest) error {
	if strings.TrimSpace(req.GrantID) == "" {
		return &contracts.ValidationError{Code: contracts.InvalidInput, Field: "grant_id"}
	}

	// 1. Invariant: Member changes require step-up
	if req.StepUpManager == nil || req.Session == nil {
		return &Error{Code: CodeStepUpRequired, Message: "step-up authentication required for policy changes"}
	}
	_, err := req.StepUpManager.ValidateStepUp(
		ctx,
		req.Session,
		req.StepUpToken,
		auth.ActionPolicyChange,
		"vault/grants/"+req.GrantID,
	)
	if err != nil {
		return &Error{Code: CodeUnauthorized, Message: "step-up authorization failed for grant revocation", Err: err}
	}

	s.mu.Lock()
	grant, exists := s.grants[req.GrantID]
	if !exists {
		s.mu.Unlock()
		return &Error{Code: CodeGrantNotFound, Message: fmt.Sprintf("grant %s not found", req.GrantID)}
	}

	now := time.Now().UTC()
	grant.RevokedAt = &now
	grant.RevokedBy = req.OperatorIdent.Email
	s.mu.Unlock()

	// 2. Immediate privilege reduction: Invalidate step-up grants associated with member session
	// to ensure the very next sensitive request fails closed.
	if req.MemberSession != nil {
		req.StepUpManager.RevokeAllForSession(ctx, req.MemberSession.ID)
	} else {
		req.StepUpManager.RevokeAllForSession(ctx, req.Session.ID)
	}

	// 3. Persist revocation record
	if s.store != nil {
		grantBytes, _ := json.Marshal(grant)
		_, _ = s.store.Write(ctx, storage.WriteRequest{
			OperationID:     "op-revoke-" + req.GrantID,
			Owner:           req.OperatorIdent.Email,
			Scope:           "grants",
			Name:            req.GrantID,
			ExpectedVersion: 1,
			Metadata:        grantBytes,
		})
	}

	// 4. Emit attributable audit event
	if s.recorder != nil {
		evt, evtErr := audit.NewEvent(
			audit.EventGrantRevoked,
			grant.VaultID+"/"+grant.PrincipalID,
			audit.AuditData{
				Actor:   req.OperatorIdent.Email,
				VaultID: grant.VaultID,
				Action:  "grant:revoke",
				Outcome: "success",
				Details: map[string]any{
					"grant_id":     req.GrantID,
					"principal_id": grant.PrincipalID,
				},
			},
		)
		if evtErr == nil {
			_ = s.recorder.Record(ctx, evt)
		}
	}

	return nil
}

// AuthorizeMemberAccess checks if a principal holds an active, unrevoked grant
// for the given vault, action and secret path.
func (s *Service) AuthorizeMemberAccess(principalID, vaultID, action, canonicalPath string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	now := time.Now().UTC()
	for _, g := range s.grants {
		if g.PrincipalID == principalID && g.VaultID == vaultID && g.IsActive(now) {
			if g.AllowsPath(action, canonicalPath) {
				return true
			}
		}
	}
	return false
}

// GetGrant retrieves a grant by ID.
func (s *Service) GetGrant(grantID string) (*Grant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	g, ok := s.grants[grantID]
	if !ok {
		return nil, &Error{Code: CodeGrantNotFound, Message: "grant not found"}
	}
	return g, nil
}
