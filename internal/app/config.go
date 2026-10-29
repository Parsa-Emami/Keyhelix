// Package app composes the KeyHelix engine runtime and exposes the local HTTP
// API used by the supported web workspace. Domain rules stay in their packages;
// this package only wires identity, storage and provider adapters together.
package app

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var vaultPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{2,63}$`)

// Config is the local runtime contract written by scripts/providers.mjs.
type Config struct {
	SchemaVersion int    `json:"schema_version"`
	Profile       string `json:"profile"`
	OpenBao       struct {
		Address      string   `json:"address"`
		Token        string   `json:"token"`
		KEKMount     string   `json:"kek_mount"`
		KEKID        string   `json:"kek_id"`
		PayloadMount string   `json:"payload_mount"`
		Scopes       []string `json:"scopes"`
	} `json:"openbao"`
	OIDC struct {
		Issuer      string `json:"issuer"`
		ClientID    string `json:"client_id"`
		RedirectURI string `json:"redirect_uri"`
	} `json:"oidc"`
	Engine struct {
		DataDir string   `json:"data_dir"`
		Vaults  []string `json:"vaults"`
	} `json:"engine"`
	Web struct {
		Origin string `json:"origin"`
		Port   int    `json:"port"`
	} `json:"web"`
}

// LoadConfig reads and validates the local runtime configuration.
func LoadConfig(path string) (Config, error) {
	var config Config
	data, err := os.ReadFile(path)
	if err != nil {
		return config, fmt.Errorf("runtime configuration is unavailable; run npm run setup: %w", err)
	}
	if err := json.Unmarshal(data, &config); err != nil {
		return config, fmt.Errorf("runtime configuration is invalid: %w", err)
	}
	if err := config.Validate(); err != nil {
		return config, err
	}
	return config, nil
}

// Validate enforces the loopback-only local profile and complete adapter wiring.
func (c *Config) Validate() error {
	if c.SchemaVersion != 1 || c.Profile != "local" {
		return fmt.Errorf("unsupported runtime configuration schema or profile")
	}
	if err := requireLoopbackHTTP(c.OpenBao.Address, "openbao address"); err != nil {
		return err
	}
	if strings.TrimSpace(c.OpenBao.Token) == "" {
		return fmt.Errorf("openbao workload token is required")
	}
	if strings.EqualFold(c.OpenBao.Token, "root") || strings.HasPrefix(strings.ToLower(c.OpenBao.Token), "s.root") {
		return fmt.Errorf("openbao workload token must be scoped, not root")
	}
	if len(c.OpenBao.Scopes) == 0 {
		return fmt.Errorf("openbao workload scopes are required")
	}
	if c.OpenBao.KEKMount == "" {
		c.OpenBao.KEKMount = "transit"
	}
	if c.OpenBao.PayloadMount == "" {
		c.OpenBao.PayloadMount = "secret"
	}
	if c.OpenBao.KEKID == "" {
		return fmt.Errorf("openbao KEK id is required")
	}
	issuer, err := url.Parse(c.OIDC.Issuer)
	if err != nil || issuer.Scheme != "http" && issuer.Scheme != "https" || issuer.Host == "" {
		return fmt.Errorf("oidc issuer must be an absolute http(s) URL")
	}
	if c.OIDC.ClientID == "" {
		return fmt.Errorf("oidc client id is required")
	}
	redirect, err := url.Parse(c.OIDC.RedirectURI)
	if err != nil || redirect.Scheme == "" || redirect.Host == "" {
		return fmt.Errorf("oidc redirect URI must be absolute")
	}
	if c.Web.Origin == "" {
		c.Web.Origin = "http://localhost:4173"
	}
	origin, err := url.Parse(c.Web.Origin)
	if err != nil || origin.Scheme != "http" || origin.Host == "" || origin.Path != "" {
		return fmt.Errorf("web origin must be a loopback http origin")
	}
	host := origin.Hostname()
	if host != "localhost" && host != "127.0.0.1" && host != "::1" {
		return fmt.Errorf("web origin must be loopback")
	}
	if c.Engine.DataDir == "" {
		return fmt.Errorf("engine data directory is required")
	}
	if len(c.Engine.Vaults) == 0 {
		c.Engine.Vaults = []string{"vault-prod"}
	}
	for _, vault := range c.Engine.Vaults {
		if !vaultPattern.MatchString(vault) {
			return fmt.Errorf("invalid vault identifier %q", vault)
		}
	}
	return nil
}

// ResolvePath resolves a configuration-relative path against the working directory.
func ResolvePath(value string) (string, error) {
	if filepath.IsAbs(value) {
		return filepath.Clean(value), nil
	}
	absolute, err := filepath.Abs(value)
	if err != nil {
		return "", err
	}
	return filepath.Clean(absolute), nil
}

func requireLoopbackHTTP(value, field string) error {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "http" || parsed.Host == "" {
		return fmt.Errorf("%s must be an absolute http URL", field)
	}
	host := parsed.Hostname()
	if host != "localhost" && host != "127.0.0.1" && host != "::1" {
		return fmt.Errorf("%s must be loopback", field)
	}
	return nil
}
