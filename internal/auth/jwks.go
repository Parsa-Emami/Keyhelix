package auth

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// jwksCacheTTL bounds how long a fetched signing key set is reused.
const jwksCacheTTL = 5 * time.Minute

type jsonWebKeySet struct {
	Keys []jsonWebKey `json:"keys"`
}

type jsonWebKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type jwksVerifier struct {
	url    string
	client *http.Client
	mu     sync.Mutex
	keys   map[string]*rsa.PublicKey
	algs   map[string]string
	at     time.Time
}

func newJWKSVerifier(url string, client *http.Client) *jwksVerifier {
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	return &jwksVerifier{url: url, client: client, keys: map[string]*rsa.PublicKey{}, algs: map[string]string{}}
}

func (v *jwksVerifier) refresh(ctx context.Context) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, v.url, nil)
	if err != nil {
		return &Error{Code: CodeIDPUnavailable, Message: "failed to construct JWKS request", Err: err}
	}
	request.Header.Set("Accept", "application/json")
	response, err := v.client.Do(request)
	if err != nil {
		return &Error{Code: CodeIDPUnavailable, Message: "identity provider signing keys are unreachable", Err: err}
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return &Error{Code: CodeIDPUnavailable, Message: fmt.Sprintf("identity provider JWKS returned status %d", response.StatusCode)}
	}
	var set jsonWebKeySet
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&set); err != nil {
		return &Error{Code: CodeInvalidToken, Message: "identity provider JWKS is malformed", Err: err}
	}
	keys := make(map[string]*rsa.PublicKey, len(set.Keys))
	algs := make(map[string]string, len(set.Keys))
	for _, key := range set.Keys {
		if key.Kty != "RSA" || (key.Use != "" && key.Use != "sig") {
			continue
		}
		if key.Alg != "RS256" && key.Alg != "PS256" && key.Alg != "" {
			continue
		}
		modulus, err := base64.RawURLEncoding.DecodeString(key.N)
		if err != nil {
			continue
		}
		exponent, err := base64.RawURLEncoding.DecodeString(key.E)
		if err != nil || len(exponent) == 0 || len(exponent) > 4 {
			continue
		}
		value := 0
		for _, b := range exponent {
			value = value<<8 | int(b)
		}
		if value < 3 || value > 1<<31-1 {
			continue
		}
		kid := key.Kid
		if kid == "" {
			kid = "default"
		}
		keys[kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(modulus), E: value}
		algs[kid] = key.Alg
	}
	if len(keys) == 0 {
		return &Error{Code: CodeInvalidToken, Message: "identity provider published no usable RSA signing key"}
	}
	v.keys = keys
	v.algs = algs
	v.at = time.Now()
	return nil
}

// VerifySignature checks the compact JWS signature against the cached JWKS.
// Only RS256 and PS256 RSA signatures are accepted; "none" and HMAC keys are
// refused before any claim is trusted.
func (v *jwksVerifier) VerifySignature(ctx context.Context, rawToken string) error {
	parts := strings.Split(rawToken, ".")
	if len(parts) != 3 {
		return &Error{Code: CodeInvalidToken, Message: "malformed ID token: must contain 3 segments"}
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return &Error{Code: CodeInvalidToken, Message: "invalid token header encoding"}
	}
	var header struct {
		Algorithm string `json:"alg"`
		Kid       string `json:"kid"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return &Error{Code: CodeInvalidToken, Message: "malformed token header"}
	}
	if header.Algorithm != "RS256" && header.Algorithm != "PS256" {
		return &Error{Code: CodeInvalidToken, Message: "unsupported ID token signing algorithm"}
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return &Error{Code: CodeInvalidToken, Message: "invalid ID token signature encoding"}
	}

	v.mu.Lock()
	defer v.mu.Unlock()
	needsRefresh := len(v.keys) == 0 || time.Since(v.at) > jwksCacheTTL
	if !needsRefresh && header.Kid != "" {
		_, needsRefresh = v.keys[header.Kid]
	}
	if needsRefresh {
		if err := v.refresh(ctx); err != nil {
			return err
		}
	}
	lookup := header.Kid
	if lookup == "" {
		lookup = "default"
	}
	key, ok := v.keys[lookup]
	if !ok {
		return &Error{Code: CodeInvalidToken, Message: "ID token references an unknown signing key"}
	}
	if published := v.algs[lookup]; published != "" && published != header.Algorithm {
		return &Error{Code: CodeInvalidToken, Message: "ID token algorithm does not match the published key algorithm"}
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if header.Algorithm == "PS256" {
		if err := rsa.VerifyPSS(key, crypto.SHA256, digest[:], signature, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}); err != nil {
			return &Error{Code: CodeInvalidToken, Message: "ID token signature verification failed"}
		}
		return nil
	}
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature); err != nil {
		return &Error{Code: CodeInvalidToken, Message: "ID token signature verification failed"}
	}
	return nil
}
