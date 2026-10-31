package app

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/parsa-emami/keyhelix/internal/auth"
)

func newMockInfra(t *testing.T) (*httptest.Server, *httptest.Server) {
	t.Helper()

	baoMux := http.NewServeMux()
	baoMux.HandleFunc("/v1/sys/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"initialized":true,"sealed":false,"version":"2.2.2"}`))
	})
	payloads := map[string]string{}
	baoMux.HandleFunc("/v1/transit/encrypt/", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Plaintext string `json:"plaintext"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"ciphertext":"vault:v1:` + body.Plaintext + `","key_version":1}}`))
	})
	baoMux.HandleFunc("/v1/transit/decrypt/", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Ciphertext string `json:"ciphertext"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		plain := strings.TrimPrefix(body.Ciphertext, "vault:v1:")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"plaintext":"` + plain + `"}}`))
	})
	baoMux.HandleFunc("/v1/secret/data/", func(w http.ResponseWriter, r *http.Request) {
		key := strings.TrimPrefix(r.URL.Path, "/v1/secret/data/")
		switch r.Method {
		case http.MethodPost, http.MethodPut:
			var body struct {
				Data struct {
					Sealed string `json:"sealed"`
				} `json:"data"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			payloads[key] = body.Data.Sealed
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":{"version":1}}`))
		case http.MethodGet:
			ct, ok := payloads[key]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":{"data":{"sealed":"` + ct + `"},"metadata":{"version":1}}}`))
		case http.MethodDelete:
			delete(payloads, key)
			w.WriteHeader(http.StatusNoContent)
		}
	})
	baoMux.HandleFunc("/v1/secret/metadata/", func(w http.ResponseWriter, r *http.Request) {
		key := strings.TrimPrefix(r.URL.Path, "/v1/secret/metadata/")
		delete(payloads, key)
		w.WriteHeader(http.StatusNoContent)
	})
	baoServer := httptest.NewServer(baoMux)
	t.Cleanup(baoServer.Close)

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa key: %v", err)
	}
	var idpServer *httptest.Server
	idpMux := http.NewServeMux()
	idpMux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 idpServer.URL,
			"authorization_endpoint": idpServer.URL + "/auth",
			"token_endpoint":         idpServer.URL + "/token",
			"jwks_uri":               idpServer.URL + "/jwks",
		})
	})
	idpMux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{{
				"kty": "RSA",
				"kid": "k1",
				"alg": "RS256",
				"use": "sig",
				"n":   base64.RawURLEncoding.EncodeToString(privKey.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(privKey.E)).Bytes()),
			}},
		})
	})
	idpServer = httptest.NewServer(idpMux)
	t.Cleanup(idpServer.Close)

	return baoServer, idpServer
}

func TestServerLifecycleRotationAndGrantsBFF(t *testing.T) {
	baoServer, idpServer := newMockInfra(t)
	var cfg Config
	cfg.SchemaVersion = 1
	cfg.Profile = "local"
	cfg.OpenBao.Address = baoServer.URL
	cfg.OpenBao.Token = "s.validtoken123456"
	cfg.OpenBao.KEKMount = "transit"
	cfg.OpenBao.KEKID = "kek-v1-openbao"
	cfg.OpenBao.PayloadMount = "secret"
	cfg.OpenBao.Scopes = []string{"transit:encrypt", "transit:decrypt", "transit:rewrap", "kv:write", "kv:read", "kv:delete"}
	cfg.OIDC.Issuer = idpServer.URL
	cfg.OIDC.ClientID = "keyhelix-web"
	cfg.OIDC.RedirectURI = "http://localhost:4173/api/v1/auth/callback"
	cfg.Engine.DataDir = t.TempDir()
	cfg.Engine.Vaults = []string{"vault-prod"}
	cfg.Web.Origin = "http://localhost:4173"
	cfg.Web.Port = 4173

	ctx := context.Background()
	rt, err := New(ctx, cfg)
	if err != nil {
		t.Fatalf("New runtime failed: %v", err)
	}
	defer rt.Close()

	handler := NewServer(rt)

	// Create an authenticated admin session
	adminIdent := &auth.Identity{
		Subject:       "sub-alice",
		Email:         "alice@keyhelix.local",
		VaultRole:     "vault-admin",
		AllowedOwners: []string{"alice@keyhelix.local"},
		AllowedScopes: []string{"vault:read", "vault:write", "secret:read", "secret:write", "app/prod/*"},
		AuthTime:      time.Now().Unix(),
		ExpiresAt:     time.Now().Add(time.Hour).Unix(),
	}
	adminSession, adminToken, err := rt.sessions.CreateSession(ctx, adminIdent, auth.ClientInfo{UserAgent: "test"})
	if err != nil {
		t.Fatalf("create admin session: %v", err)
	}
	adminCookie, err := rt.sessions.BuildSessionCookie(adminToken, adminSession.Expiration())
	if err != nil {
		t.Fatalf("build admin cookie: %v", err)
	}

	doJSON := func(method, path string, body any) *httptest.ResponseRecorder {
		var raw []byte
		if body != nil {
			raw, _ = json.Marshal(body)
		}
		req := httptest.NewRequest(method, path, bytes.NewReader(raw))
		req.Header.Set("Origin", "http://localhost:4173")
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(adminCookie)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}

	// 1. Write secret via /api/v1/vaults/vault-prod/secrets
	writeRec := doJSON(http.MethodPost, "/api/v1/vaults/vault-prod/secrets", map[string]any{
		"secret_path":      "app/prod/db-pass",
		"plaintext":        "s3cr3t-val",
		"expected_version": 0,
		"classification":   "restricted",
	})
	if writeRec.Code != http.StatusCreated {
		t.Fatalf("expected 201 on writeSecret, got %d: %s", writeRec.Code, writeRec.Body.String())
	}

	// 2. Soft-delete, verify metadata status=SOFT_DELETED, then undelete
	delRec := doJSON(http.MethodPost, "/api/v1/vaults/vault-prod/secrets/delete", map[string]any{
		"secret_path":                "app/prod/db-pass",
		"version":                    1,
		"retention_duration_seconds": 3600,
	})
	if delRec.Code != http.StatusOK {
		t.Fatalf("expected 200 on deleteSecret, got %d: %s", delRec.Code, delRec.Body.String())
	}

	metaRec := doJSON(http.MethodGet, "/api/v1/vaults/vault-prod/metadata", nil)
	if metaRec.Code != http.StatusOK || !strings.Contains(metaRec.Body.String(), `"DELETED"`) {
		t.Fatalf("expected DELETED in metadata response, got %d: %s", metaRec.Code, metaRec.Body.String())
	}

	undelRec := doJSON(http.MethodPost, "/api/v1/vaults/vault-prod/secrets/undelete", map[string]any{
		"secret_path": "app/prod/db-pass",
		"version":     1,
	})
	if undelRec.Code != http.StatusOK {
		t.Fatalf("expected 200 on undeleteSecret, got %d: %s", undelRec.Code, undelRec.Body.String())
	}

	// 3. Start rotation with step-up elevation
	rotGrant, rotTok, err := rt.stepUp.IssueGrant(ctx, adminSession, auth.ActionPolicyChange, "vault/vault-prod/rotations")
	if err != nil {
		t.Fatalf("issue rotation step-up: %v", err)
	}
	rt.setElevation(adminSession.ID, rotGrant, rotTok)

	rotRec := doJSON(http.MethodPost, "/api/v1/vaults/vault-prod/rotations", map[string]any{
		"target_kek_id":      "kek-v1-openbao",
		"target_kek_version": "v2",
		"secret_paths":       []string{"app/prod/db-pass"},
	})
	if rotRec.Code != http.StatusCreated {
		t.Fatalf("expected 201 on startRotation, got %d: %s", rotRec.Code, rotRec.Body.String())
	}

	listRotRec := doJSON(http.MethodGet, "/api/v1/vaults/vault-prod/rotations", nil)
	if listRotRec.Code != http.StatusOK || !strings.Contains(listRotRec.Body.String(), `"COMPLETE"`) {
		t.Fatalf("expected COMPLETE rotation in listRotations, got %d: %s", listRotRec.Code, listRotRec.Body.String())
	}

	// 4. Verify checkpoint endpoint
	cpRec := doJSON(http.MethodGet, "/api/v1/audit/checkpoints/cp-001/verify", nil)
	if cpRec.Code != http.StatusOK {
		t.Fatalf("expected 200 on verifyCheckpoint, got %d: %s", cpRec.Code, cpRec.Body.String())
	}
}
