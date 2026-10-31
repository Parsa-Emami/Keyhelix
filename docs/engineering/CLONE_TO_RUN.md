# KeyHelix: Clone-to-Run Guide

Complete operator runbook for cloning, compiling from source, running, testing, and recovering KeyHelix on a local or private host.

---

## 1. Prerequisites

KeyHelix runs entirely on open-source toolchains without requiring any cloud subscription, third-party API keys, or proprietary software.

- **Operating System**: Linux x86_64 (tested on Ubuntu 22.04 LTS and 24.04 LTS)
- **Node.js**: `>= 24.19.0 < 25` (npm included)
- **Go**: `1.26.2+` (1.26.x)
- **Podman**: `4.9.3+` (rootless container runtime)
- **Git**: `2.34+`

---

## 2. Quickstart: Clone, Bootstrap, and Run

Execute the following commands in an interactive terminal:

```sh
git clone https://github.com/Parsa-Emami/Keyhelix.git
cd Keyhelix
npm run setup
npm start
```

### What Happens During Setup?

The bootstrap script (`scripts/oss-bootstrap.mjs setup`):
1. **Toolchain Validation**: Confirms Node.js, Go, and rootless Podman meet minimum version requirements.
2. **Dependency Installation**: Installs committed npm dependencies using `npm ci --ignore-scripts` to guarantee reproducible, tamper-free builds.
3. **Web & Engine Compilation**: Compiles the web application bundle with Vite and builds the Go engine binary (`bin/keyhelix`).
4. **Provider Initialization**: Starts rootless containers for OpenBao (listening on `127.0.0.1:8200`) and Keycloak (listening on `127.0.0.1:8080`).
5. **Cryptographic Initialization**: Initializes OpenBao transit key engines and KV mounts; imports the KeyHelix realm and synthetic user identities (`alice`, `bob`) into Keycloak.
6. **Runtime Configuration**: Emits operational tokens and endpoints into `.local-data/runtime.json`.

---

## 3. Building from Source

KeyHelix provides dedicated build recipes for each subsystem:

### 3.1 Build the Go BFF Engine
```sh
npm run build:engine
# Under the hood:
# node scripts/build-engine.mjs
# go build -trimpath -ldflags="-s -w" -o bin/keyhelix cmd/keyhelix/main.go
```

### 3.2 Build the Web Application
```sh
npm run build
# Under the hood:
# npm run prepare:web && npm run typecheck && vite build --config apps/web/vite.config.ts && npm run build:engine
```

### 3.3 Create Reproducible Distribution Packages
```sh
npm run package
# Under the hood:
# bash scripts/package.sh
# Bundles bin/keyhelix, dist/web, offline contracts, SBOM, third-party notices, and SHA-256 checksums into dist/release/
```

---

## 4. Operating the Workspace

Open your browser to `http://localhost:4173`:

- **Sign In**: Authenticate as `alice` (vault-admin) or `bob` (vault-member).
  - Alice: username `alice`, password `keyhelix-local-alice`
  - Bob: username `bob`, password `keyhelix-local-bob`
- **Write Secrets**: Select vault `vault-prod` and save a new secret path and value. OpenBao encrypts the payload and the engine stores only encrypted metadata envelopes.
- **Transient Reveal**: Click **Reveal** on an existing secret. Fresh step-up reauthentication is required. The plaintext displays with a 10-second auto-clearing timer and clears immediately upon modal dismissal (<kbd>Escape</kbd>).
- **Access Management**: Grant or revoke permissions for `bob@keyhelix.local`. Revocation takes effect synchronously.
- **Diagnostics**: Access `GET /api/diagnostics` or view the **Availability** banner to inspect live provider and storage health.

---

## 5. Network Boundaries and Private Hosting

KeyHelix requires no owned public domain:

1. **Loopback Isolation**: The web server (`scripts/serve-web.mjs`) and the Go BFF engine (`cmd/keyhelix`) bind strictly to loopback interfaces (`127.0.0.1`, `::1`). The engine listens on an ephemeral loopback port (`127.0.0.1:0`).
2. **DNS Rebinding Defense**: The web server validates incoming `Host` headers against loopback hostnames (`localhost`, `127.0.0.1`, `[::1]`) and rejects external hosts with `400 Bad Request`.
3. **Origin Boundary**: State-changing and data-access routes under `/api/*` enforce same-origin semantics; untrusted cross-origin requests are rejected with `403 Forbidden`.
4. **Cache Boundaries**: Sensitive routes (`/`, `/healthz`, `/readyz`, `/runtime-config.json`, `/api/diagnostics`, `/api/*`) emit `Cache-Control: no-store` and `Pragma: no-cache`.
5. **Optional TLS / Private Ingress**: Operators can terminate TLS using reverse proxies (e.g., Nginx with `ops/web/nginx.conf.template`) and proxy to loopback, enforcing CIDR allowlists. See [infra/deployment.md](../../infra/deployment.md).

---

## 6. Verification and Smoke Testing

Verify the complete repository and reference workflow locally:

```sh
# 1. Run unit, web, and contract checks
npm test

# 2. Run Go engine test suite
PATH=/usr/local/go/bin:$PATH go test ./...

# 3. Run browser end-to-end and accessibility tests
npm run test:browser

# 4. Run clone smoke test (verifies setup, restart, and restore)
npm run test:clone

# 5. Run system diagnostic health check
npm run doctor

# 6. Validate repository invariants and JSON schemas
python3 scripts/validate_repo.py
```

### Shared Development Host Flags

When developing on a host where provider containers are already running, use environment overrides:

```sh
KEYHELIX_CLONE_WORKTREE=1 KEYHELIX_REUSE_PROVIDERS=1 KEYHELIX_CLONE_RESTORE=1 npm run test:clone
```
- `KEYHELIX_CLONE_WORKTREE=1`: Snapshots the working tree instead of the git index.
- `KEYHELIX_REUSE_PROVIDERS=1`: Reuses existing provider containers and recovery material.
- `KEYHELIX_CLONE_RESTORE=1`: Executes full provider backup and restore verification.

---

## 7. Data Storage, Recovery, and Support

- **Runtime Directory**: `.local-data/` holds provider storage and recovery keys; keep private and never commit to version control.
- **Disaster Recovery**: Back up `.local-data/` periodically. To restore, extract into `.local-data/` and run `npm run providers` followed by `npm start`.
- **Support & Issues**: Consult [docs/release/USER_GUIDE.md](../release/USER_GUIDE.md) and report issues on [GitHub](https://github.com/Parsa-Emami/Keyhelix/issues).
- **Security Policy**: Follow the coordinated disclosure route in [SECURITY.md](../../SECURITY.md).
