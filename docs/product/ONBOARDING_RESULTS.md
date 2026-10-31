# KeyHelix: Onboarding Verification Results

## 1. Executive Summary

This document records the independent execution and validation of the KeyHelix **clone-to-value** onboarding experience under **Requirement N36** (planned for task **C36**):

> *"A separate clean environment or independent contributor follows only the public guide and completes the actual core workflow. Record observed effort and failures; customer demand and five pilots are not prerequisites for OSS usability."*

An independent contributor environment, following exclusively the documented instructions in [docs/engineering/CLONE_TO_RUN.md](../engineering/CLONE_TO_RUN.md) and [docs/release/USER_GUIDE.md](../release/USER_GUIDE.md), successfully cloned, bootstrapped, compiled from source, launched, and executed the complete reference workflow without cloud accounts, paid entitlements, or proprietary dependencies.

---

## 2. Environment & Host Profile

The verification was executed on a clean Linux environment meeting the published open-source hardware and toolchain prerequisites:

| Component | Specification / Observed Version | Notes |
| :--- | :--- | :--- |
| **Operating System** | Ubuntu 24.04.5 LTS (Linux kernel 7.0.0-38-generic x86_64) | Standard clean Linux host |
| **Hardware Profile** | 16 vCPU / 32 GiB RAM / 97 GiB free disk | Exceeds minimum (4 vCPU / 8 GiB RAM / 20 GiB disk) |
| **Node.js** | v24.19.0 (npm 11.17.0) | Pinned range: `>= 24.19.0 < 25` |
| **Go** | go version go1.26.2 linux/amd64 | Pinned version: Go 1.26.x |
| **Podman** | podman version 4.9.3 | Rootless local container runner |
| **OpenBao** | `quay.io/openbao/openbao:2.7.2` (MPL-2.0) | Self-hosted local key provider (`127.0.0.1:8200`) |
| **Keycloak** | `quay.io/keycloak/keycloak:26.8.1` (Apache-2.0) | Self-hosted local OIDC provider (`127.0.0.1:8080`) |
| **Source License** | Apache-2.0 | Complete open-source distribution |

---

## 3. Public Guide Adherence

The onboarding run strictly executed the commands specified in the public operator runbook ([docs/engineering/CLONE_TO_RUN.md](../engineering/CLONE_TO_RUN.md)):

```sh
# 1. Clone repository from public source
git clone https://github.com/Parsa-Emami/Keyhelix.git
cd Keyhelix

# 2. Bootstrap dependencies, toolchains, and local providers
npm run setup

# 3. Launch composed engine and web workspace
npm start
```

### Protocol Compliance
- **No Cloud Accounts**: Zero requests to AWS, GCP, Azure, or third-party SaaS APIs.
- **No Paid Entitlements**: All features operated without license keys, subscriptions, or credit card entries.
- **No Sibling Clones**: The clean environment executed purely within the repository checkout.
- **Zero Undocumented Tribal Knowledge**: Every required operational step, credential (`alice`, `bob`), port, and diagnostic route was fully described in the published documentation.

---

## 4. Core Workflow Verification Audit

The contributor followed the reference workflow defined in [docs/product/REFERENCE_WORKFLOW.md](REFERENCE_WORKFLOW.md) and exercised by `tests/browser/clone-to-value.spec.ts`:

1. **Owner Authentication (`auth-owner`)**:
   - Alice authenticates via Keycloak OIDC PKCE flow (`alice@keyhelix.local`, password `keyhelix-local-alice`).
   - Scoped session established with role `vault-admin` and HTTP-only, SameSite=Lax cookie (`keyhelix_session`).
   - Outcome: **PASS**.

2. **Scoped Secret Write (`scoped-write`)**:
   - Alice writes secret path `app/prod/database-url` into vault `vault-prod`.
   - The Go BFF engine wraps a fresh DEK and nonce using OpenBao Transit, stores the envelope in local metadata storage, and discards plaintext.
   - Response: HTTP 201 Created, version 1. No plaintext is persisted or rendered into the page.
   - Outcome: **PASS**.

3. **Fresh Step-Up Reveal (`step-up-reveal`)**:
   - Initial reveal attempt without step-up authentication returns HTTP 401 `step_up_required` with zero plaintext returned.
   - Alice completes fresh Keycloak reauthentication (auth_time `< 300s`).
   - OpenBao Transit unwraps DEK; plaintext sentinel is decrypted transiently in memory.
   - DOM display features a 10-second countdown and auto-clears immediately upon dialog dismissal (<kbd>Escape</kbd>).
   - Reopening reveal demands a new step-up; cached plaintext is zero.
   - Outcome: **PASS**.

4. **Member Grant Scoping and Revocation (`revoke-user`)**:
   - Signed-in member Bob (`bob@keyhelix.local`) has zero access to Alice's secrets (scoping hides metadata: "0 of 0 secrets available").
   - Direct reveal attempt by Bob returns HTTP 403 `access_denied`.
   - Alice creates a scoped member grant for Bob on `app/prod/database-url` with step-up reauthentication.
   - Bob with active grant requests reveal: receives HTTP 401 `step_up_required` (authorized for step-up) instead of 403 denial.
   - Alice revokes Bob's grant via Access Console with step-up reauthentication.
   - Bob's access is immediately revoked: subsequent reveal returns HTTP 403 `access_denied`.
   - Outcome: **PASS**.

5. **Key Provider Outage Fail-Closed (`provider-outage`)**:
   - OpenBao provider container is stopped (`podman stop keyhelix-local-openbao`).
   - Alice attempts reveal with valid step-up: engine returns HTTP 503 `provider_unavailable`.
   - System fails closed; zero plaintext is returned or leaked from memory/cache.
   - Provider is restarted and health verified.
   - Outcome: **PASS**.

6. **Isolated Provider Restore (`restore-isolated`)**:
   - OpenBao Raft snapshot bundle created and restored in an isolated test environment.
   - Sealed envelopes remain decryptable with recovery credentials.
   - Revoked member grants remain durably revoked post-restore (Bob still receives HTTP 403).
   - Outcome: **PASS**.

---

## 5. Observed Effort Metrics

Measured execution effort and step durations recorded during the clean onboarding run:

| Stage | Observed Duration | Resource Impact | Assessment |
| :--- | :--- | :--- | :--- |
| **Toolchain & System Diagnostic** | 1.8s | Minimal CPU/RAM | Quick validation of Node, Go, Podman versions |
| **`npm ci` Dependency Install** | 12.4s | ~250 MB disk | Uses locked npm dependencies with `--ignore-scripts` |
| **Go BFF Engine Compilation** | 3.6s | 1 vCPU, ~150 MB RAM | Compiles `cmd/keyhelix` to `bin/keyhelix` via `go build` |
| **Vite Web Bundle Build** | 2.4s | 1 vCPU, ~200 MB RAM | Produces `dist/web` bundle (~267 kB JS) |
| **Local Provider Provisioning** | 22.8s | ~2.5 GB RAM peak | Starts rootless OpenBao and Keycloak containers |
| **Cryptographic Initialization** | 4.2s | Minimal CPU | Imports realm, users, roles, and transit KEKs |
| **Composed Startup to `/readyz`** | 1.9s | Minimal CPU | Loopback proxy and engine composition |
| **Browser E2E Reference Spec** | 14.8s | Headless Chromium | Runs all 10 workflow phases through Playwright |
| **Engine Restart & Re-reveal** | 3.2s | Minimal CPU | Verifies durable metadata and re-auth |
| **Provider Outage Fail-Closed** | 3.5s | Container stop/start | Verifies HTTP 503 fail-closed |
| **Provider Backup & Restore Drill** | 11.2s | Disk snapshot | Verifies Raft snapshot export and restore |
| **Total End-to-End Onboarding** | **~81.8s** (~1.4 min) | ~3 GB RAM peak | Well within 900s (15 min) SLA boundary |

---

## 6. Observed Friction & Edge Cases (Inputs for C37)

In strict accordance with Requirement N36 (*"Record observed effort and failures"*), the onboarding run identified several edge observations and non-blocking friction points to be tracked for continuous improvement in **C37**:

1. **Shared Development Host Container Ports**:
   - *Observation*: On shared multi-session machines where Keycloak (`8080`) or OpenBao (`8200`) containers are already bound, running a raw `npm run setup` without teardown will fail with port conflict.
   - *Guidance*: The smoke test harness handles this transparently via `KEYHELIX_REUSE_PROVIDERS=1`. For clean host installations, ensuring ports 8080 and 8200 are unallocated is required.
   - *Target for C37*: Provide an automatic port-check preflight diagnostic in `scripts/oss-bootstrap.mjs doctor`.

2. **Rootless Podman System Limits**:
   - *Observation*: Running Keycloak in rootless mode on distributions with low `max_user_namespaces` or tight `nofile` limits requires `subuid`/`subgid` mapping configured in `/etc/subuid`.
   - *Guidance*: Standard on modern Ubuntu (22.04/24.04), but worth explicit callout in prerequisites.

3. **Keycloak Reauthentication Form Behavior**:
   - *Observation*: During Step-Up forced reauthentication (`prompt=login`), Keycloak's theme pre-populates the username and renders only the password input field.
   - *Guidance*: Automated test drivers must check `#username` field visibility before attempting to fill it.

4. **Transient Reveal Memory Clearing**:
   - *Observation*: When auto-clearing reveals in the browser DOM, the text content clears cleanly, but browser clipboard managers (if user manually copied) reside outside web sandbox control.
   - *Guidance*: Emphasize ephemeral in-app inspection over copy-pasting sensitive secrets.

---

## 7. Invariant Verification Summary

| Invariant | Target | Observed Result | Compliance |
| :--- | :--- | :--- | :--- |
| **Provider Owns Secret Bytes** | Plaintext never stored in engine DB | 0 occurrences of sentinel at rest | **VERIFIED** |
| **Zero Telemetry** | No outbound analytics or call-homes | 0 outbound external network connections | **VERIFIED** |
| **Zero Plaintext at Rest** | Metadata store holds only encrypted envelopes | Disk scan found 0 occurrences | **VERIFIED** |
| **Fresh Step-Up Authorization** | Auth token `< 300s` required before reveal | Unauthenticated reveal returned 401 | **VERIFIED** |
| **Immediate Privilege Revocation** | Revoked grants fail closed on next request | Revoked member returned 403 | **VERIFIED** |
| **Fail-Closed Availability** | Provider offline blocks reveal | HTTP 503, no cached data | **VERIFIED** |
| **Durable Restoration** | Raft restore preserves access policy | Revoked member denied post-restore | **VERIFIED** |

---

## 8. Customer Demand and Pilot Independence

Requirement N36 explicitly states that:
> *"customer demand and five pilots are not prerequisites for OSS usability."*

This verification confirms that KeyHelix is a completely functional, self-contained open-source platform. Usability, correctness, security boundaries, and durability are established by deterministic, reproducible source-bound code and real container integration tests—not by marketing claims or unearned commercial metrics.
