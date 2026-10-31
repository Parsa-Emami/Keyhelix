# KeyHelix: Deployment, Network Boundaries, and Private Ingress

## Overview

KeyHelix is designed for **open-source, local-first operation** ([ADR-0003](file:///home/amirreza/Desktop/Projects/Keyhelix/docs/architecture/ADR-0003-open-source-local-first.md)). Full functionality requires **no owned public domain**, no cloud subscription, and no third-party account. The application stack runs as a supervised pair of local processes on loopback interfaces, with sealed secret bytes stored directly in local providers.

---

## 1. Network Boundaries and Architecture

KeyHelix enforces strict multi-tier network boundaries across all services:

```
+-------------------------------------------------------------------------+
| Local Host Boundary                                                     |
|                                                                         |
|  [Optional Private Ingress: Nginx / TLS Termination]                   |
|       | (terminates TLS, checks CIDR allowlist, proxies to 127.0.0.1:4305)|
|       v                                                                 |
|  [Web Server: Node.js (scripts/serve-web.mjs)]                          |
|   - Bound to: 127.0.0.1:4173 (dev) or 127.0.0.1:4305 (packaged)        |
|   - Host Header Validation: rejects foreign host (DNS rebinding defense)|
|   - Origin Enforcement: rejects untrusted cross-origin /api requests    |
|   - Cache Boundaries: no-store on sensitive routes, immutable on assets |
|       |                                                                 |
|       | (internal loopback proxy /api/* to ephemeral engine port)       |
|       v                                                                 |
|  [Go Domain Engine & BFF (cmd/keyhelix)]                                |
|   - Bound strictly to: 127.0.0.1:0 (ephemeral loopback port)            |
|   - Internal IPC: never exposed to external or non-loopback interfaces  |
|       |                                                                 |
|       +------------------------+------------------------+               |
|       |                        |                        |               |
|       v                        v                        v               |
|  [Storage Engine]       [OpenBao KV & Transit]   [Keycloak OIDC]        |
|  (internal/storage)     (127.0.0.1:8200)         (127.0.0.1:8080)       |
+-------------------------------------------------------------------------+
```

### 1.1 Loopback Isolation
- **Web Server (`scripts/serve-web.mjs`)**: Binds exclusively to loopback addresses (`127.0.0.1` or `::1`). Attempts to bind to external interfaces (such as `0.0.0.0` or public IPs) fail closed immediately with an explicit error.
- **Go Engine (`cmd/keyhelix`)**: Binds strictly to an ephemeral loopback address (`127.0.0.1:0`). On startup, the engine reports its assigned port to the supervisor via stdout handshake. The engine is **never directly exposed or published** to external networks.
- **Provider Services**: OpenBao and Keycloak run in rootless containers binding exclusively to `127.0.0.1:8200` and `127.0.0.1:8080` respectively.

### 1.2 DNS Rebinding Defense (Host Header Boundary)
Browsers visiting malicious websites on the internet can be targeted by DNS rebinding attacks (e.g. `attacker.com` pointing to `127.0.0.1`). To eliminate this risk:
- The web server inspects the `Host` header on every incoming HTTP request.
- Only loopback hosts (`localhost`, `127.0.0.1`, `::1`, `[::1]`) or explicitly declared `allowedHosts` are admitted.
- Requests with foreign or unrecognized `Host` headers are rejected with `400 Bad Request` (`{"error":"invalid_host"}`).

### 1.3 Origin Boundary (Same-Origin API Enforcement)
- All `/api` and `/api/*` endpoints enforce same-origin communication.
- When an `Origin` header is present on API requests, it must match loopback or the validated request host.
- Requests from untrusted origins are rejected with `403 Forbidden` (`{"error":"cross_origin_forbidden"}`).
- The web application Content Security Policy (CSP) enforces `default-src 'none'; script-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`.

### 1.4 Cache Boundaries
- **Sensitive and Dynamic Routes**: `/`, `/index.html`, `/healthz`, `/readyz`, `/runtime-config.json`, `/api/diagnostics`, and all `/api/*` routes set `Cache-Control: no-store` and `Pragma: no-cache`. Sensitive secret data, tokens, and health states are never cached by browsers or intermediary proxies.
- **Fingerprinted Static Assets**: Assets served under `/assets/*` contain cryptographic content hashes and are served with `Cache-Control: public, max-age=31536000, immutable`.

---

## 2. Optional Private Hosting and TLS Ingress

When deploying KeyHelix for private team use over a private network, internal VPC, or VPN, operators should place a TLS-terminating reverse proxy in front of the local loopback server.

### 2.1 Ingress Reverse Proxy Architecture
The reverse proxy terminates HTTPS, provides HSTS, validates client certificates or network ranges, and forwards traffic over loopback to the packaged KeyHelix web server on port `4305`:

1. **Template**: `ops/web/nginx.conf.template`
2. **TLS Protocols**: Minimum `TLSv1.2` and `TLSv1.3`.
3. **HSTS**: `Strict-Transport-Security: max-age=31536000`.
4. **Access Control**: By default, all external traffic is blocked (`deny all;`). Operators must explicitly allow trusted CIDR blocks:
   ```nginx
   allow 127.0.0.1;
   allow ::1;
   allow 10.0.0.0/8;      # Example trusted internal network CIDR
   deny all;
   ```
5. **Proxy Forwarding**:
   ```nginx
   location / {
       proxy_pass http://127.0.0.1:4305;
       proxy_http_version 1.1;
       proxy_set_header Host $host;
       proxy_set_header X-Forwarded-Proto https;
       proxy_set_header X-Forwarded-Host $host;
       proxy_set_header X-Forwarded-For $remote_addr;
       proxy_set_header X-Real-IP $remote_addr;
       proxy_read_timeout 20s;
   }
   ```

### 2.2 Systemd Service Hardening
The production service template (`ops/web/service.systemd`) runs under systemd with strict sandbox isolation:
- `NoNewPrivileges=true`
- `PrivateTmp=true`
- `ProtectSystem=strict`
- `ProtectHome=true`
- `ProtectKernelTunables=true`
- `ProtectControlGroups=true`
- `CapabilityBoundingSet=` (drops all kernel capabilities)

---

## 3. Provider Ownership & Fail-Closed Semantics

KeyHelix maintains strict separation of duties:
1. **OpenBao**: Owns and seals secret bytes using transit keys and KV version 2 engines.
2. **Keycloak**: Issues OIDC identity tokens and fresh step-up challenge verifications (`prompt=login&max_age=0`).
3. **Go Engine**: Persists only encrypted metadata envelopes and cryptographic digests; plaintext secrets exist only transiently in memory during authenticated, step-up authorized reveal operations.
4. **Provider Outage**: If OpenBao or Keycloak becomes unavailable, the engine and web shell immediately return `503 Service Unavailable` with `{"error":"engine_unavailable"}` or `{"status":"not_ready"}`. Stale, unauthenticated, or unsealed secrets are never returned from cache.

---

## 4. Verification and Operational Runbook

### Pre-flight Verification
```sh
npm run doctor
npm run validate:plan
npm test
PATH=/usr/local/go/bin:$PATH go test ./...
```

### Local Launch
```sh
npm run setup
npm start
```
The supervisor starts both the web shell and the loopback Go engine, serving at `http://127.0.0.1:4173` (or configured port).

### Verification of Network Boundaries
Run the dedicated network boundary test suite:
```sh
node --test tests/web/network-boundaries.test.mjs
```
This suite verifies:
- Loopback binding enforcement and non-loopback bind rejection.
- DNS rebinding mitigation (Host header validation).
- Same-origin enforcement on API endpoints (Origin header rejection).
- Cache-control header segregation between sensitive routes and static assets.
- Complete engine isolation and fail-closed outage handling.
