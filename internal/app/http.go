package app

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"time"

	"github.com/parsa-emami/keyhelix/internal/audit"
	"github.com/parsa-emami/keyhelix/internal/auth"
	"github.com/parsa-emami/keyhelix/internal/contracts"
	"github.com/parsa-emami/keyhelix/internal/grants"
	"github.com/parsa-emami/keyhelix/internal/provider"
	"github.com/parsa-emami/keyhelix/internal/secrets"
	"github.com/parsa-emami/keyhelix/internal/storage"
)

const (
	stateCookieName = "keyhelix_oidc_state"
	maxBodyBytes    = 1<<20 + 16*1024
	revealTTL       = 30 * time.Second
)

// NewServer builds the engine HTTP surface.
func NewServer(engine *Runtime) http.Handler {
	server := &Server{runtime: engine}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", server.health)
	mux.HandleFunc("GET /readyz", server.ready)
	mux.HandleFunc("GET /api/v1/auth/session", server.sessionState)
	mux.HandleFunc("GET /api/v1/auth/login", server.login)
	mux.HandleFunc("GET /api/v1/auth/callback", server.callback)
	mux.HandleFunc("GET /api/v1/auth/step-up", server.beginStepUp)
	mux.HandleFunc("POST /api/v1/auth/logout", server.logout)
	mux.HandleFunc("GET /api/vaults/{vault}/metadata", server.metadata)
	mux.HandleFunc("POST /api/vaults/{vault}/secrets", server.writeSecret)
	mux.HandleFunc("POST /api/vaults/{vault}/reveal", server.revealSecret)
	mux.HandleFunc("GET /api/vaults/{vault}/grants", server.listGrants)
	mux.HandleFunc("POST /api/vaults/{vault}/grants", server.createGrant)
	mux.HandleFunc("POST /api/vaults/{vault}/grants/{grant}/revoke", server.revokeGrant)
	mux.HandleFunc("GET /api/vaults/{vault}/rotations", server.listRotations)
	mux.HandleFunc("POST /api/vaults/{vault}/rotations/{job}/resume", server.resumeRotation)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusNotFound, "not_found", "No engine route matches this request.")
	})
	return server.middleware(mux)
}

// Server wires engine handlers to one composed runtime.
type Server struct {
	runtime *Runtime
}

func (s *Server) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
		defer func() {
			if recovered := recover(); recovered != nil {
				writeError(w, http.StatusInternalServerError, "engine_error", "The engine could not complete this request.")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":    "ok",
		"scope":     "engine-runtime",
		"version":   Version,
		"toolchain": runtime.Version(),
		"coreReady": true,
	})
}

func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
	defer cancel()
	report := s.runtime.CheckReadiness(ctx)
	status := http.StatusOK
	if report.Status != "ready" {
		status = http.StatusServiceUnavailable
	}
	writeJSON(w, status, report)
}

func (s *Server) vault(w http.ResponseWriter, r *http.Request, vaultID string) bool {
	for _, configured := range s.runtime.config.Engine.Vaults {
		if configured == vaultID {
			return true
		}
	}
	writeError(w, http.StatusNotFound, "vault_not_found", "This vault is not configured in the local engine.")
	return false
}

func (s *Server) session(r *http.Request) (*auth.Session, error) {
	cookie, err := r.Cookie(s.runtime.sessions.Config().CookieName)
	if err != nil || strings.TrimSpace(cookie.Value) == "" {
		return nil, &auth.Error{Code: auth.CodeSessionNotFound, Message: "no session cookie"}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	return s.runtime.sessions.ValidateSessionToken(ctx, cookie.Value, auth.ClientInfo{UserAgent: r.UserAgent()})
}

func (s *Server) requireSession(w http.ResponseWriter, r *http.Request) *auth.Session {
	session, err := s.session(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "unauthenticated", "Sign in with the local identity provider to continue.")
		return nil
	}
	return session
}

func (s *Server) sameOrigin(w http.ResponseWriter, r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" || origin != s.runtime.config.Web.Origin {
		writeError(w, http.StatusForbidden, "origin_rejected", "State-changing requests must come from the local workspace origin.")
		return false
	}
	return true
}

func ownerFor(identity *auth.Identity) string {
	if identity == nil {
		return ""
	}
	if identity.Email != "" {
		allowed := false
		for _, candidate := range identity.AllowedOwners {
			if candidate == identity.Email {
				allowed = true
				break
			}
		}
		if !allowed && len(identity.AllowedOwners) > 0 {
			return identity.AllowedOwners[0]
		}
		return identity.Email
	}
	if len(identity.AllowedOwners) > 0 {
		return identity.AllowedOwners[0]
	}
	return identity.Subject
}

func isAdmin(identity *auth.Identity) bool {
	for _, scope := range identity.AllowedScopes {
		if scope == "vault-admin" || scope == "policy:write" || scope == "*" {
			return true
		}
	}
	return false
}

func (s *Server) memberAllowed(identity *auth.Identity, vaultID, action, path string) bool {
	owner := ownerFor(identity)
	if owner == "" || owner == identity.Email || isAdmin(identity) {
		return true
	}
	return s.runtime.grants.AuthorizeMemberAccess(identity.Email, vaultID, action, path)
}

func (s *Server) sessionState(w http.ResponseWriter, r *http.Request) {
	response := map[string]any{
		"authenticated": false,
		"sign_in_url":   "/api/v1/auth/login",
		"vaults":        s.runtime.config.Engine.Vaults,
	}
	session, err := s.session(r)
	if err == nil && session != nil && session.Identity != nil {
		identity := session.Identity
		response["authenticated"] = true
		response["user"] = map[string]any{
			"subject":       identity.Subject,
			"email":         identity.Email,
			"vault_role":    identity.VaultRole,
			"scopes":        identity.AllowedScopes,
			"allowed_owner": ownerFor(identity),
		}
		response["step_up"] = s.elevationState(session.ID)
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) elevationState(sessionID string) any {
	s.runtime.mu.Lock()
	defer s.runtime.mu.Unlock()
	value, ok := s.runtime.elevated[sessionID]
	if !ok || time.Now().After(value.expiresAt) {
		return nil
	}
	return map[string]any{
		"action":     string(value.action),
		"resource":   value.resource,
		"expires_at": value.expiresAt.UTC().Format(time.RFC3339),
	}
}

func safeReturn(value string) string {
	if value == "" {
		return "/#vaults"
	}
	if len(value) > 512 || !strings.HasPrefix(value, "/") || strings.HasPrefix(value, "//") ||
		strings.ContainsAny(value, "\\\r\n") {
		return "/#vaults"
	}
	return value
}

func (s *Server) setStateCookie(w http.ResponseWriter, state string) {
	http.SetCookie(w, &http.Cookie{
		Name:     stateCookieName,
		Value:    state,
		Path:     "/api/v1/auth",
		MaxAge:   300,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

func (s *Server) clearStateCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     stateCookieName,
		Value:    "",
		Path:     "/api/v1/auth",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

func (s *Server) beginFlow(w http.ResponseWriter, r *http.Request, flow *pendingFlow, forceLogin bool) {
	request, authURL, err := s.runtime.oidc.BeginAuthFlow()
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "identity_provider_unavailable", "The identity provider could not start an authorization request.")
		return
	}
	flow.request = request
	flow.returnTo = safeReturn(flow.returnTo)
	flow.expiresAt = time.Now().Add(5 * time.Minute)
	if forceLogin {
		authURL += "&prompt=login&max_age=0"
	}
	s.runtime.rememberFlow(flow)
	s.setStateCookie(w, request.State)
	w.Header().Set("Location", authURL)
	w.WriteHeader(http.StatusSeeOther)
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	s.beginFlow(w, r, &pendingFlow{flow: "login", returnTo: r.URL.Query().Get("return_to")}, false)
}

func (s *Server) beginStepUp(w http.ResponseWriter, r *http.Request) {
	session := s.requireSession(w, r)
	if session == nil {
		return
	}
	action := r.URL.Query().Get("action")
	resource := r.URL.Query().Get("resource")
	if len(resource) == 0 || len(resource) > 256 || strings.ContainsAny(resource, "\r\n\\\x00") {
		writeError(w, http.StatusBadRequest, "invalid_step_up_resource", "A bounded step-up resource is required.")
		return
	}
	var sensitive auth.SensitiveAction
	switch action {
	case "reveal":
		canonical, err := auth.NormalizePath(resource)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_step_up_resource", "The reveal step-up resource must be a canonical secret path.")
			return
		}
		resource = canonical
		sensitive = auth.ActionRevealSecret
	case "grant:create":
		sensitive = auth.ActionPolicyChange
	case "grant:revoke":
		sensitive = auth.ActionPolicyChange
	default:
		writeError(w, http.StatusBadRequest, "invalid_step_up_action", "Unsupported step-up action.")
		return
	}
	s.beginFlow(w, r, &pendingFlow{
		flow:      "stepup",
		returnTo:  r.URL.Query().Get("return_to"),
		action:    sensitive,
		resource:  resource,
		sessionID: session.ID,
		subject:   session.Identity.Subject,
	}, true)
}

func (s *Server) callback(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	s.clearStateCookie(w)
	if code := query.Get("error"); code != "" {
		writeError(w, http.StatusBadRequest, "authorization_failed", "The identity provider did not authorize this request.")
		return
	}
	code := query.Get("code")
	state := query.Get("state")
	cookie, cookieErr := r.Cookie(stateCookieName)
	if code == "" || state == "" || cookieErr != nil || subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(state)) != 1 {
		writeError(w, http.StatusBadRequest, "state_mismatch", "The authorization response state is missing or does not match this browser.")
		return
	}
	flow := s.runtime.takeFlow(state)
	if flow == nil {
		writeError(w, http.StatusBadRequest, "state_expired", "This authorization request has expired or was already used.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	identity, err := s.runtime.oidc.ExchangeAndValidate(ctx, code, state, flow.request)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "authentication_failed", "The identity provider response could not be verified.")
		return
	}
	if flow.flow == "login" {
		session, token, err := s.runtime.sessions.CreateSession(ctx, identity, auth.ClientInfo{UserAgent: r.UserAgent()})
		if err != nil {
			writeError(w, http.StatusInternalServerError, "session_failed", "A local session could not be established.")
			return
		}
		cookie, err := s.runtime.sessions.BuildSessionCookie(token, session.Expiration())
		if err != nil {
			writeError(w, http.StatusInternalServerError, "session_failed", "A secure session cookie could not be built.")
			return
		}
		http.SetCookie(w, cookie)
		w.Header().Set("Location", flow.returnTo)
		w.WriteHeader(http.StatusSeeOther)
		return
	}

	session, err := s.session(r)
	if err != nil || session.ID != flow.sessionID || session.Identity.Subject != flow.subject || identity.Subject != flow.subject {
		writeError(w, http.StatusUnauthorized, "step_up_session_mismatch", "Step-up authorization must be completed in the same session that requested it.")
		return
	}
	now := time.Now().Unix()
	if identity.AuthTime == 0 || now-identity.AuthTime > 300 || identity.AuthTime > now+60 {
		writeError(w, http.StatusUnauthorized, "step_up_stale", "The identity provider did not prove a fresh reauthentication.")
		return
	}
	grant, token, err := s.runtime.stepUp.IssueGrant(ctx, session, flow.action, flow.resource)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "step_up_failed", "A step-up grant could not be issued.")
		return
	}
	s.runtime.setElevation(session.ID, grant, token)
	w.Header().Set("Location", flow.returnTo)
	w.WriteHeader(http.StatusSeeOther)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if !s.sameOrigin(w, r) {
		return
	}
	session := s.requireSession(w, r)
	if session == nil {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	_ = s.runtime.sessions.RevokeSession(ctx, session.ID, "operator_logout")
	_, _ = s.runtime.stepUp.RevokeAllForSession(ctx, session.ID)
	s.runtime.clearElevation(session.ID)
	http.SetCookie(w, &http.Cookie{
		Name:     s.runtime.sessions.Config().CookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	writeJSON(w, http.StatusOK, map[string]any{"logged_out": true})
}

func (s *Server) metadata(w http.ResponseWriter, r *http.Request) {
	vaultID := r.PathValue("vault")
	if !s.vault(w, r, vaultID) {
		return
	}
	session := s.requireSession(w, r)
	if session == nil {
		return
	}
	identity := session.Identity
	owner := ownerFor(identity)
	lister, ok := any(s.runtime.store).(storage.Lister)
	if !ok {
		writeError(w, http.StatusInternalServerError, "storage_unavailable", "Durable metadata enumeration is unavailable.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	records, err := lister.List(ctx, storage.ListRequest{Owner: owner, Scope: vaultID})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "storage_unavailable", "Durable metadata is unavailable.")
		return
	}
	paths := make([]string, 0, len(records))
	for _, record := range records {
		if owner != identity.Email && !isAdmin(identity) && !s.runtime.grants.AuthorizeMemberAccess(identity.Email, vaultID, "secret:read", record.Name) {
			continue
		}
		paths = append(paths, record.Name)
	}
	summary, err := s.runtime.vaults.ListAuthorizedMetadata(ctx, identity, session, vaultID, owner, r.Header, paths)
	if err != nil {
		s.domainError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"vault_id":         summary.VaultID,
		"total_secrets":    summary.TotalSecrets,
		"authorized_count": summary.AuthorizedCount,
		"secrets":          summary.Secrets,
	})
}

type writeBody struct {
	SecretPath      string `json:"secret_path"`
	Plaintext       string `json:"plaintext"`
	ExpectedVersion int64  `json:"expected_version"`
	Classification  string `json:"classification"`
}

func (s *Server) writeSecret(w http.ResponseWriter, r *http.Request) {
	vaultID := r.PathValue("vault")
	if !s.vault(w, r, vaultID) || !s.sameOrigin(w, r) {
		return
	}
	session := s.requireSession(w, r)
	if session == nil {
		return
	}
	var body writeBody
	if !decodeBody(w, r, &body) {
		return
	}
	if body.Plaintext == "" {
		writeError(w, http.StatusBadRequest, "invalid_input", "plaintext is required.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	outcome, err := s.runtime.secrets.WriteSecret(ctx, secrets.WriteRequest{
		VaultID:         vaultID,
		SecretPath:      body.SecretPath,
		ExpectedVersion: body.ExpectedVersion,
		Plaintext:       []byte(body.Plaintext),
		Classification:  body.Classification,
		KEKID:           s.runtime.config.OpenBao.KEKID,
		Owner:           ownerFor(session.Identity),
		Identity:        session.Identity,
	})
	if err != nil {
		s.domainError(w, err)
		return
	}
	s.runtime.record(audit.EventSecretVersionCreated, outcome.SecretID, audit.AuditData{
		Actor:   session.Identity.Subject,
		VaultID: vaultID,
		Action:  "secret:write",
		Outcome: "success",
		Details: map[string]any{"secret_path": outcome.SecretPath, "version": outcome.Version},
	})
	status := http.StatusCreated
	if body.ExpectedVersion > 0 {
		status = http.StatusOK
	}
	writeJSON(w, status, map[string]any{
		"vault_id":      outcome.VaultID,
		"secret_id":     outcome.SecretID,
		"secret_path":   outcome.SecretPath,
		"version":       outcome.Version,
		"metadata_hash": outcome.MetadataHash,
		"created_at":    outcome.CreatedAt,
	})
}

type revealBody struct {
	SecretPath string `json:"secret_path"`
}

func (s *Server) revealSecret(w http.ResponseWriter, r *http.Request) {
	vaultID := r.PathValue("vault")
	if !s.vault(w, r, vaultID) || !s.sameOrigin(w, r) {
		return
	}
	session := s.requireSession(w, r)
	if session == nil {
		return
	}
	var body revealBody
	if !decodeBody(w, r, &body) {
		return
	}
	canonical, err := auth.NormalizePath(body.SecretPath)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_input", "secret_path is not a canonical secret path.")
		return
	}
	owner := ownerFor(session.Identity)
	if !s.memberAllowed(session.Identity, vaultID, "secret:read", canonical) {
		writeError(w, http.StatusForbidden, "access_denied", "No active member grant authorizes this secret.")
		return
	}
	token, elevated := s.runtime.elevationFor(session.ID, auth.ActionRevealSecret, canonical)
	if !elevated {
		authorize := "/api/v1/auth/step-up?action=reveal&resource=" + url.QueryEscape(canonical) +
			"&return_to=" + url.QueryEscape(safeReturn(vaultReturn(vaultID)))
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"error":         "step_up_required",
			"message":       "Fresh step-up reauthentication is required before this secret can be revealed.",
			"authorize_url": authorize,
		})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	response, err := s.runtime.secrets.RevealSecret(ctx, secrets.RevealRequest{
		VaultID:       vaultID,
		SecretPath:    canonical,
		Owner:         owner,
		Identity:      session.Identity,
		Session:       session,
		StepUpManager: s.runtime.stepUp,
		StepUpToken:   token.Plaintext(),
		Headers:       r.Header,
	})
	if err != nil {
		s.runtime.clearElevation(session.ID)
		s.domainError(w, err)
		return
	}
	plaintext := append([]byte(nil), response.Plaintext()...)
	content := response.AuditContent()
	response.Destroy()
	s.runtime.clearElevation(session.ID)
	s.runtime.record(audit.EventSecretRevealed, session.Identity.Subject, audit.AuditData{
		Actor:   content.Actor,
		VaultID: content.VaultID,
		Action:  content.Action,
		Outcome: content.Outcome,
		Details: map[string]any{"secret_path": content.SecretPath, "version": content.Version},
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"vault_id":           response.VaultID,
		"secret_path":        response.SecretPath,
		"version":            response.Version,
		"classification":     response.Classification,
		"created_at":         response.CreatedAt,
		"metadata_digest":    response.MetadataDigest,
		"algorithm":          response.Algorithm,
		"plaintext":          base64.StdEncoding.EncodeToString(plaintext),
		"plaintext_encoding": "base64",
		"no_store":           true,
		"ttl_seconds":        int(revealTTL.Seconds()),
	})
}

func vaultReturn(vaultID string) string { return "/#vaults" }

func grantDTO(grant *grants.Grant) map[string]any {
	status := "ACTIVE"
	var revokedAt any
	if grant.RevokedAt != nil {
		status = "REVOKED"
		revokedAt = grant.RevokedAt.UTC().Format(time.RFC3339)
	}
	return map[string]any{
		"grant_id":       grant.ID,
		"vault_id":       grant.VaultID,
		"subject":        grant.PrincipalID,
		"email":          grant.PrincipalID,
		"vault_role":     "vault-member",
		"allowed_scopes": grant.Permissions,
		"created_at":     grant.CreatedAt.UTC().Format(time.RFC3339),
		"expires_at":     grant.ExpiresAt.UTC().Format(time.RFC3339),
		"status":         status,
		"revoked_at":     revokedAt,
		"revoked_by":     grant.RevokedBy,
	}
}

func (s *Server) listGrants(w http.ResponseWriter, r *http.Request) {
	vaultID := r.PathValue("vault")
	if !s.vault(w, r, vaultID) {
		return
	}
	session := s.requireSession(w, r)
	if session == nil {
		return
	}
	if !isAdmin(session.Identity) {
		writeError(w, http.StatusForbidden, "access_denied", "Only the vault administrator can inspect grants.")
		return
	}
	grantList := s.runtime.grants.List(vaultID)
	items := make([]map[string]any, 0, len(grantList))
	for _, grant := range grantList {
		items = append(items, grantDTO(grant))
	}
	writeJSON(w, http.StatusOK, map[string]any{"vault_id": vaultID, "grants": items})
}

type grantBody struct {
	PrincipalID      string   `json:"principal_id"`
	Permissions      []string `json:"permissions"`
	ExpiresInSeconds int      `json:"expires_in_seconds"`
}

func (s *Server) createGrant(w http.ResponseWriter, r *http.Request) {
	vaultID := r.PathValue("vault")
	if !s.vault(w, r, vaultID) || !s.sameOrigin(w, r) {
		return
	}
	session := s.requireSession(w, r)
	if session == nil {
		return
	}
	var body grantBody
	if !decodeBody(w, r, &body) {
		return
	}
	if !isAdmin(session.Identity) {
		writeError(w, http.StatusForbidden, "access_denied", "Only the vault administrator can create grants.")
		return
	}
	if len(body.Permissions) == 0 {
		writeError(w, http.StatusBadRequest, "invalid_input", "permissions are required.")
		return
	}
	resource := "vault/" + vaultID + "/grants"
	token, elevated := s.runtime.elevationFor(session.ID, auth.ActionPolicyChange, resource)
	if !elevated {
		s.stepUpRequired(w, "grant:create", resource)
		return
	}
	expires := time.Now().UTC().Add(24 * time.Hour)
	if body.ExpiresInSeconds > 0 && body.ExpiresInSeconds <= 86400*30 {
		expires = time.Now().UTC().Add(time.Duration(body.ExpiresInSeconds) * time.Second)
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	grant, err := s.runtime.grants.CreateGrant(ctx, grants.CreateGrantRequest{
		VaultID:       vaultID,
		PrincipalID:   body.PrincipalID,
		Permissions:   body.Permissions,
		ExpiresAt:     expires,
		OperatorIdent: session.Identity,
		Session:       session,
		StepUpManager: s.runtime.stepUp,
		StepUpToken:   token.Plaintext(),
	})
	if err != nil {
		s.domainError(w, err)
		return
	}
	s.runtime.clearElevation(session.ID)
	writeJSON(w, http.StatusCreated, grantDTO(grant))
}

func (s *Server) stepUpRequired(w http.ResponseWriter, action, resource string) {
	authorize := "/api/v1/auth/step-up?action=" + url.QueryEscape(action) +
		"&resource=" + url.QueryEscape(resource) + "&return_to=" + url.QueryEscape("/#access")
	writeJSON(w, http.StatusUnauthorized, map[string]any{
		"error":         "step_up_required",
		"message":       "Fresh step-up reauthentication is required for this policy change.",
		"authorize_url": authorize,
	})
}

func (s *Server) revokeGrant(w http.ResponseWriter, r *http.Request) {
	vaultID := r.PathValue("vault")
	grantID := r.PathValue("grant")
	if !s.vault(w, r, vaultID) || !s.sameOrigin(w, r) {
		return
	}
	session := s.requireSession(w, r)
	if session == nil {
		return
	}
	if !isAdmin(session.Identity) {
		writeError(w, http.StatusForbidden, "access_denied", "Only the vault administrator can revoke grants.")
		return
	}
	resource := "vault/grants/" + grantID
	token, elevated := s.runtime.elevationFor(session.ID, auth.ActionPolicyChange, resource)
	if !elevated {
		s.stepUpRequired(w, "grant:revoke", resource)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	err := s.runtime.grants.RevokeGrant(ctx, grants.RevokeGrantRequest{
		GrantID:       grantID,
		OperatorIdent: session.Identity,
		Session:       session,
		StepUpManager: s.runtime.stepUp,
		StepUpToken:   token.Plaintext(),
	})
	if err != nil {
		s.domainError(w, err)
		return
	}
	s.runtime.clearElevation(session.ID)
	writeJSON(w, http.StatusOK, map[string]any{"grant_id": grantID, "status": "REVOKED"})
}

func (s *Server) listRotations(w http.ResponseWriter, r *http.Request) {
	vaultID := r.PathValue("vault")
	if !s.vault(w, r, vaultID) {
		return
	}
	if s.requireSession(w, r) == nil {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"vault_id": vaultID, "rotations": []any{}})
}

func (s *Server) resumeRotation(w http.ResponseWriter, r *http.Request) {
	vaultID := r.PathValue("vault")
	if !s.vault(w, r, vaultID) || !s.sameOrigin(w, r) {
		return
	}
	if s.requireSession(w, r) == nil {
		return
	}
	writeError(w, http.StatusNotFound, "rotation_not_found", "No rotation job exists for this identifier.")
}

func (s *Server) domainError(w http.ResponseWriter, err error) {
	var authErr *auth.Error
	if errors.As(err, &authErr) {
		switch authErr.Code {
		case auth.CodeScopeDenied, auth.CodeStepUpScopeDenied:
			writeError(w, http.StatusForbidden, "access_denied", authErr.Message)
		case auth.CodeIDPUnavailable:
			writeError(w, http.StatusServiceUnavailable, "identity_provider_unavailable", authErr.Message)
		case auth.CodeStepUpRequired, auth.CodeStepUpExpired, auth.CodeStepUpInvalid, auth.CodeStepUpSessionMismatch:
			writeError(w, http.StatusUnauthorized, "step_up_required", authErr.Message)
		default:
			writeError(w, http.StatusUnauthorized, "unauthenticated", authErr.Message)
		}
		return
	}
	var providerErr *provider.Error
	if errors.As(err, &providerErr) {
		switch providerErr.Code {
		case provider.CodeProviderUnavailable, provider.CodeProviderSealed:
			writeError(w, http.StatusServiceUnavailable, "provider_unavailable", providerErr.Message)
		case provider.CodeUnauthorized, provider.CodeUnscopedIdentity:
			writeError(w, http.StatusForbidden, "provider_denied", providerErr.Message)
		default:
			writeError(w, http.StatusBadGateway, "provider_error", providerErr.Message)
		}
		return
	}
	var storageErr *storage.Error
	if errors.As(err, &storageErr) {
		switch storageErr.Code {
		case storage.CodeStaleVersion, storage.CodeAlreadyExists, storage.CodeOperationConflict:
			writeError(w, http.StatusConflict, strings.ToLower(string(storageErr.Code)), "The secret changed since this form was loaded; refresh and retry.")
		case storage.CodeNotFound:
			writeError(w, http.StatusNotFound, "not_found", "No matching committed record exists.")
		default:
			writeError(w, http.StatusInternalServerError, "storage_error", "Durable metadata storage could not complete this operation.")
		}
		return
	}
	var validation *contracts.ValidationError
	if errors.As(err, &validation) {
		writeError(w, http.StatusBadRequest, "invalid_input", "A required field is invalid: "+validation.Field)
		return
	}
	var revealErr *secrets.RevealError
	if errors.As(err, &revealErr) {
		if revealErr.Code == secrets.CodeRevealCiphertextTampered || revealErr.Code == secrets.CodeRevealIntegrityFailure {
			writeError(w, http.StatusConflict, "integrity_failure", revealErr.Message)
			return
		}
		writeError(w, http.StatusInternalServerError, "reveal_failed", "The secret could not be revealed.")
		return
	}
	var grantErr *grants.Error
	if errors.As(err, &grantErr) {
		switch grantErr.Code {
		case grants.CodeGrantNotFound:
			writeError(w, http.StatusNotFound, "grant_not_found", grantErr.Message)
		case grants.CodeStepUpRequired, grants.CodeUnauthorized:
			writeError(w, http.StatusUnauthorized, "step_up_required", grantErr.Message)
		default:
			writeError(w, http.StatusBadRequest, "grant_failed", grantErr.Message)
		}
		return
	}
	writeError(w, http.StatusInternalServerError, "engine_error", "The engine could not complete this request.")
}

func decodeBody(w http.ResponseWriter, r *http.Request, target any) bool {
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		writeError(w, http.StatusUnsupportedMediaType, "invalid_content_type", "Requests must use application/json.")
		return false
	}
	reader := http.MaxBytesReader(w, r.Body, maxBodyBytes)
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_input", "The JSON request body is invalid or too large.")
		return false
	}
	if decoder.More() {
		writeError(w, http.StatusBadRequest, "invalid_input", "The JSON request body must contain one object.")
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	body, err := json.Marshal(value)
	if err != nil {
		http.Error(w, `{"error":"engine_error"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{"error": code, "message": message})
}
