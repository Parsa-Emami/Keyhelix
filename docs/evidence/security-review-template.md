# KeyHelix Security Review & Verification Matrix

**Standard**: Requirement F20  
**Scope**: Pre-production synthetic security verification before any personal or production credentials enter the provider.  
**Target Profile**: KeyHelix local-first open-source security profile (Go engine + OpenBao/Keycloak adapters).

---

## 1. Security Review Purpose & Mandate

Under **Requirement F20**:
> *"Security matrix passes with synthetic secrets before any personal production credentials enter provider."*

Production keys, API tokens, and user credentials must **never** be injected into a deployment or test environment until the complete access control matrix, privilege revocation mechanics, and zero-leakage assertions have passed automated validation using synthetic sentinel secrets.

---

## 2. Multi-Dimensional Security Matrix

### 2.1 Principal Classifications

| Principal ID | Role | Permitted Actions | Restrictions |
|---|---|---|---|
| `alice@keyhelix.local` | Vault Admin | Full administrative (write, list, grant, revoke, rotate) | Mandatory Step-Up (`ActionPolicyChange`, `ActionReveal`) |
| `bob@keyhelix.local` | Authorized Member | Read/Reveal within granted secret path (`app/prod/*`) | Valid only with active Grant; requires `ActionReveal` Step-Up |
| `bob@keyhelix.local` (Revoked) | Revoked Member | None | Synchronously denied on the immediate next request |
| `charlie@keyhelix.local` | Expired Session | None | Token expired; refused with `SESSION_EXPIRED` / `UNAUTHORIZED` |
| `mallory@attacker.local` | Cross-Tenant Actor | None on target vault | Scopes restricted; unauthorized paths return no existence proof |
| Anonymous / Unauthenticated | None | None | Rejected at transport gate |

### 2.2 Operation & Control Invariant Matrix

| Operation | Step-Up Required | Active Grant Required | Expected Success | Plaintext Leak Permitted | Provider Offline Behavior |
|---|---|---|---|---|---|
| **Write Secret** | No (Auth Token) | Admin Scope | Envelope Created | **NEVER** (0 bytes) | Fail Closed (`PROVIDER_UNAVAILABLE`) |
| **Reveal Secret** | **YES** (`ActionReveal`) | Admin OR Active Grant | Ephemeral Decryption | **NEVER** (Client body only) | Fail Closed (`PROVIDER_UNAVAILABLE`) |
| **List Metadata** | No (Auth Token) | Admin OR Scope Filter | Authorized Paths Only | **NEVER** (Metadata digest only) | Fail Closed (`PROVIDER_UNAVAILABLE`) |
| **Create Grant** | **YES** (`ActionPolicyChange`) | Admin Scope | Attributable CloudEvent | **NEVER** | Fail Closed (`PROVIDER_UNAVAILABLE`) |
| **Revoke Grant** | **YES** (`ActionPolicyChange`) | Admin Scope | Immediate Revocation | **NEVER** | Fail Closed (`PROVIDER_UNAVAILABLE`) |
| **Rotate Key** | **YES** (`ActionPolicyChange`) | Admin Scope | Resumable Checkpoint | **NEVER** | Fail Closed (`PROVIDER_UNAVAILABLE`) |
| **Verify Checkpoint** | No | Any Verifier | Explicit `TRUSTED`/`UNAVAILABLE` | **NEVER** | Explicit `UNAVAILABLE` |

---

## 3. Core Security Invariants Verified

1. **Immediate Synchronous Privilege Revocation (Requirement F11)**:
   - A revoked grant takes effect on the exact next sensitive request.
   - Cached step-up tokens or sessions cannot override a revoked grant.
2. **Mandatory Step-Up Authentication (Requirement F08)**:
   - Secret reveal requires fresh step-up challenge within bounded TTL (default 120s).
   - Member access changes require fresh administrative step-up.
3. **Zero Plaintext Secret Persistence (Requirement F09 / ADR-0001)**:
   - Plaintext secret bytes are exclusively held by the KMS/Transit provider.
   - Storage manifests and blobs contain only encrypted envelopes and SHA-256 digests.
   - In-memory ephemeral buffers are sanitized via `security.Zeroize`.
   - HTTP responses enforce `Cache-Control: no-store` and `X-Content-Type-Options: nosniff`.
   - Logging and audit event sinks are guarded via `security.AssertClean`.
4. **Durability & Restart Invariants (Requirement F18 / F20)**:
   - Engine restart preserves all committed manifests and grant revocation records.
   - Revoked privileges remain revoked after store reload (`storage.Open`).
   - Plaintext canaries remain absent from all storage trees after recovery.
5. **Fail-Closed on Provider Outage (Requirement F17)**:
   - If the provider is sealed, unreachable, or unhealthy, all operations fail closed.
   - No plaintext fallback or mocked success is ever permitted.

---

## 4. Automated Verification Matrix Checklist

- [x] **Positive Path**: Admin creates secret envelope with synthetic canary; member granted access reveals secret with step-up.
- [x] **Immediate Revocation**: Admin revokes member grant; member's subsequent reveal is immediately rejected.
- [x] **Step-Up Enforcement**: Missing or expired step-up challenge is rejected with `STEP_UP_REQUIRED`.
- [x] **Cross-Tenant Isolation**: Out-of-scope actor cannot read secret or deduce existence.
- [x] **Storage Sanitization**: Full disk scan across metadata, manifests, and blobs reports 0 sentinel occurrences.
- [x] **Audit Event Scrubbing**: Audit recorder and CloudEvents envelopes verified clean via `security.AssertClean`.
- [x] **Restart Durability**: Complete close/reopen drill proves revoked grants survive restart.
- [x] **Provider Offline Gate**: Adapter outage fails closed with typed error (`PROVIDER_UNAVAILABLE`).

---

## 5. Operator Sign-Off Procedure

Before introducing production credentials into any KeyHelix instance:
1. Run automated security test suite:
   ```bash
   go test -count=1 -v -run '^TestC26' ./tests/
   go test -count=1 -race -run '^TestC26' ./tests/
   ```
2. Verify all matrix rows reported `PASS`.
3. Confirm `docs/evidence/C26.json` records 0 plaintext canary occurrences.
4. Validate plan integrity:
   ```bash
   npm run validate:plan
   python3 scripts/validate_repo.py
   ```
