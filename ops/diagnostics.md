# KeyHelix Operational Diagnostics & Readiness Guide

Requirement: **N29** (`C29`)

## 1. Architectural Overview

KeyHelix follows a zero-trust, local-first architecture where liveness and readiness probes are cleanly decoupled across system boundaries. A responsive web shell must never mask backend or key provider outages, nor should a locked key vault collapse the application into an undiagnosable error state.

```
+-----------------------------------------------------------------------------------+
| Web Layer (Loopback Proxy / Web Shell)                                            |
|   - GET /healthz  -> Web Shell Liveness Probe (HTTP 200)                          |
|   - GET /readyz   -> Web Static Asset Readiness Probe (HTTP 200 / 503)            |
+-----------------------------------------------------------------------------------+
                                       |
                                       v
+-----------------------------------------------------------------------------------+
| Engine BFF Layer (Go Runtime)                                                     |
|   - GET /healthz  -> Engine Liveness Probe (toolchain, version, coreReady)         |
|   - GET /readyz   -> Engine & Storage Readiness Probe                             |
+-----------------------------------------------------------------------------------+
                                       |
                                       v
+-----------------------------------------------------------------------------------+
| Storage & Provider Surveillance                                                   |
|   - Local Store Mount & Integrity Verification                                     |
|   - OpenBao Transit / KV v2 Key Provider Surveillance (health.Monitor)            |
|   - Audit Pipeline Commitment Verification                                        |
+-----------------------------------------------------------------------------------+
```

---

## 2. Health & Readiness Probe Matrix

| Endpoint | Layer | Purpose | Success (HTTP 200) | Failure (HTTP 503/4xx) |
|---|---|---|---|---|
| `GET /healthz` | Web Shell | Process liveness | Web process is responsive | Process hung / crashed |
| `GET /readyz` | Web Shell | Static asset readiness | `index.html` confined & accessible | `index.html` missing or corrupt |
| `GET /api/engine/health` | Web Proxy -> Engine | Engine BFF liveness | Engine process alive & responsive | Engine stopped / unreachable |
| `GET /api/engine/readiness` | Web Proxy -> Engine | Engine & storage readiness | Storage opened & ready for writes | Engine down / storage lock failed |
| `GET /api/diagnostics` | Web Proxy -> Composite | Multi-component health | All required components operational | Any component degraded or down |

---

## 3. Composite Diagnostics Endpoint (`/api/diagnostics`)

The `/api/diagnostics` endpoint provides operators with immediate visibility into which specific subsystem is experiencing degradation.

### Healthy Response Example (HTTP 200)
```json
{
  "status": "ready",
  "scope": "composite-diagnostics",
  "timestamp": "2026-10-29T10:20:00Z",
  "components": {
    "web": {
      "status": "ok",
      "scope": "web-shell"
    },
    "engine": {
      "status": "ready",
      "scope": "engine-runtime",
      "version": "0.0.1",
      "toolchain": "go1.26.2"
    },
    "storage": {
      "status": "ready",
      "scope": "local-metadata-store"
    },
    "provider": {
      "status": "ready",
      "provider_id": "openbao",
      "sealed": false,
      "audit_ready": true
    }
  }
}
```

### Degraded / Outage Response Example (HTTP 503)
When the key provider is sealed or the engine is unreachable, `/api/diagnostics` returns HTTP 503 with the failing component explicitly highlighted:
```json
{
  "status": "not_ready",
  "scope": "composite-diagnostics",
  "timestamp": "2026-10-29T10:20:00Z",
  "error": "component_degraded",
  "components": {
    "web": {
      "status": "ok",
      "scope": "web-shell"
    },
    "engine": {
      "status": "unavailable",
      "error": "engine_unavailable"
    },
    "storage": {
      "status": "unknown"
    },
    "provider": {
      "status": "sealed"
    }
  }
}
```

---

## 4. Redacted and Bounded Diagnostic Logging

In accordance with KeyHelix security invariants:
1. **Zero Plaintext Secrets**: Diagnostic logs, trace logs, and error responses must never contain plaintext secrets, passwords, Bearer tokens, session cookies, or synthetic canary sentinels (`sentinel-canary-...`).
2. **Deterministic Masking**: Sensitive tokens are strictly replaced with `[REDACTED]`.
3. **Bounded Log Entries**: Individual diagnostic log lines are bounded to a maximum of 2048 bytes to eliminate memory bloat and log injection denial-of-service attack vectors.
