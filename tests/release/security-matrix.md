# KeyHelix Release Security Verification Matrix

**Release Requirement:** `N27`  
**Evaluation Standard:** Zero critical or high security findings across all enabled surfaces.  
**Scope:** KeyHelix Local-First Open Source Delivery Profile (ADR-0003).

---

## 1. Surface-by-Surface Verification Matrix

| Matrix ID | Surface | Threat / Abuse Vector | Expected Security Behavior | Test Target & Method | Verification Status |
| --- | --- | --- | --- | --- | --- |
| **SEC-01** | Workspace Import | Prototype Pollution (`__proto__`, `prototype`, `constructor`) | Rejected immediately with `"Unsafe document key."`; `Object.prototype` unmodified | `tests/browser/security.spec.ts` | **PASS** |
| **SEC-02** | Workspace Import | JSON Depth Bomb ($>32$ nesting levels) | Traversal halted; rejected with `"Document is too complex to preview."` | `tests/browser/security.spec.ts` | **PASS** |
| **SEC-03** | Workspace Import | JSON Complexity Bomb ($>20,000$ keys) | Traversal halted; rejected with `"Document is too complex to preview."` | `tests/browser/security.spec.ts` | **PASS** |
| **SEC-04** | Workspace Import | Oversized File ($>64$ KiB preview limit) | Rejected before parse with `"File exceeds the preview limit."` | `tests/browser/security.spec.ts` | **PASS** |
| **SEC-05** | Workspace Import | XSS in Keys and Filename (`<script>`, `<img onerror>`) | React escapes all tokens; text rendered in DOM; `window.__xss_*` undefined | `tests/browser/security.spec.ts` | **PASS** |
| **SEC-06** | Workspace Import | Zero Telemetry Assertion | File inspection strictly in-memory; 0 outbound POST/PUT/PATCH requests | `tests/browser/security.spec.ts` | **PASS** |
| **SEC-07** | Vaults Console | Metadata List Plaintext Leakage | Secret list API returns only paths and digests; zero plaintext payloads | `apps/web/tests/vaults.spec.ts` | **PASS** |
| **SEC-08** | Vaults Console | Cross-Tenant Vault Access | Accessing unauthorized vault returns HTTP 403; UI shows explicit denial alert | `tests/browser/security.spec.ts` | **PASS** |
| **SEC-09** | Vaults Console | Provider Outage Handling | 503 from provider displays `"Vault service unavailable."`; fails closed | `apps/web/tests/vaults.spec.ts` | **PASS** |
| **SEC-10** | Transient Reveal | Step-Up Token Bypass | Blank or missing token blocked by UI and rejected with `STEP_UP_REQUIRED` | `tests/browser/security.spec.ts` | **PASS** |
| **SEC-11** | Transient Reveal | Immediate Privilege Revocation | Revoked member request returns HTTP 403 `GRANT_REVOKED`; plaintext blocked | `tests/browser/security.spec.ts` | **PASS** |
| **SEC-12** | Transient Reveal | Provider Outage During Reveal | 503 from OpenBao halts reveal; zero cached plaintext displayed; fails closed | `tests/browser/security.spec.ts` | **PASS** |
| **SEC-13** | Transient Reveal | Auto-Zeroing & Memory Lifespan | Plaintext cleared on timer expiry, Escape key, modal close, or logout | `apps/web/tests/reveal.spec.ts` | **PASS** |
| **SEC-14** | Transient Reveal | Cache-Control Header Guard | Requests & responses enforce `Cache-Control: no-store` | `apps/web/tests/reveal.spec.ts` | **PASS** |
| **SEC-15** | Access Console | Incomplete / Partial Rotation | Unfinished rotations visibly marked INCOMPLETE; cannot look like success | `apps/web/tests/access.spec.ts` | **PASS** |
| **SEC-16** | Access Console | Revoked Grant Visibility | Revoked grants visibly marked with REVOKED badges in real time | `apps/web/tests/access.spec.ts` | **PASS** |
| **SEC-17** | Engine Secrets | Path Traversal in Secret Paths | Requests containing `..`, `//`, or absolute paths rejected with `INVALID_INPUT` | `tests/abuse_test.go` | **PASS** |
| **SEC-18** | Engine Secrets | Ciphertext / Auth Tag Corruption | Modified ciphertext fails AEAD decryption with `CIPHERTEXT_AUTH_FAILED` | `tests/abuse_test.go` | **PASS** |
| **SEC-19** | Engine Secrets | Expired / Replayed Identity | Expired session or replayed token rejected before provider operations | `tests/abuse_test.go` | **PASS** |
| **SEC-20** | Engine Storage | Zero Plaintext Leakage Assertion | Complete disk sweep verifies 0 sentinel secret canaries across all sinks | `tests/security_matrix_test.go` | **PASS** |
| **SEC-21** | Engine Storage | Engine Restart Durability | Storage reload (`storage.Open`) preserves revoked grant state and integrity | `tests/security_matrix_test.go` | **PASS** |

---

## 2. Negative UAT Execution Checklist

- [x] **Negative UAT 1 (Low-Privilege Access)**: Low-privilege identity (`bob@keyhelix.local`) can only access authorized path scopes (`app/prod/*`); unauthorized paths and cross-tenant vaults (`vault-isolated-finance`) fail closed with `UNAUTHORIZED`.
- [x] **Negative UAT 2 (Step-Up Challenge Enforcement)**: Unauthenticated or unverified requests attempting secret decryption without a fresh, valid step-up token are blocked immediately with `STEP_UP_REQUIRED`.
- [x] **Negative UAT 3 (Immediate Synchronous Revocation)**: Revoking a departing member's grant takes effect immediately on the next request without waiting for cache expiration or background polling.
- [x] **Negative UAT 4 (Provider Outage Fail-Closed)**: When upstream OpenBao or KMS is unreachable (simulated HTTP 503 or network failure), all read/write operations fail closed; no stale cached plaintext is returned.
- [x] **Negative UAT 5 (Tampered Envelope Integrity)**: Altering any byte in encrypted envelopes or authentication tags produces an explicit AEAD authentication error and zero partial plaintext.

---

## 3. Vulnerability Findings Summary

| Severity | Count | Findings Description | Resolution |
| --- | --- | --- | --- |
| **Critical** | 0 | None identified. | — |
| **High** | 0 | None identified. | — |
| **Medium** | 0 | None identified. | — |
| **Low / Info** | 0 | None identified. | — |

**Profile Status**: The KeyHelix Linux Local-First Profile meets all release gate criteria for Requirement **N27**. No supported profile is blocked.

---

## 4. Verification Sign-Off

- **Test Suites Executed**:
  1. `npm run test:browser` (Playwright browser security suite: XSS, prototype pollution, DoS limits, negative UAT, authorization boundaries)
  2. `go test -count=1 -v -run '^TestC27' ./tests/` (Go engine abuse tests: path traversal, auth tag corruption, token replay, provider outage)
  3. `go test -count=1 -race -run '^TestC27' ./tests/` (Concurrency race verification)
  4. `go test -count=1 ./...` (Complete engine test suite regression pass)
- **Operator Review**: Certified compliant with `ADR-0003`, `REFERENCE_WORKFLOW.md`, and Requirement `N27`.
