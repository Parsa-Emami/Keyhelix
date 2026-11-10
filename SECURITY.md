# KeyHelix Security Policy

KeyHelix takes the security of its open-source secret management workspace and cryptographic authorization architecture seriously. We welcome responsible security research and vulnerability disclosures.

---

## 1. Reporting a Vulnerability

> [!IMPORTANT]
> **Do not report security vulnerabilities through public GitHub Issues, pull requests, or public discussions.** Public disclosure risks exposing operators and active secret management infrastructure before a patch is available.

### Private reporting route

If GitHub's **Report a vulnerability** action is enabled under the Security tab,
submit the report using the [private security advisory form](https://github.com/Parsa-Emami/Keyhelix/security/advisories/new).

The form's availability must be checked before sending sensitive material. This
document cannot confirm that private vulnerability reporting is enabled. If the
form is not available, keep the report private and ask the maintainer to enable
a private reporting channel **without disclosing vulnerability details**.
There is no verified alternative security mailbox; `.local` email addresses
are not publicly routable.

For a private report, include the affected version or commit, exact platform,
impact, minimal synthetic reproduction steps, and redacted evidence. Never attach
real secrets, customer data, production credentials or active provider tokens.

---

## 2. Response and disclosure expectations

Security maintenance is best effort. There is no guaranteed 48-hour response,
fixed triage deadline, patch deadline, or on-call support. When a private
reporting channel is available, the maintainer will assess the affected code
and coordinate remediation and disclosure with the reporter. Do not assume a
fix has shipped until a tagged release or source commit is independently verified.

---

## 3. Supported Versions

The active maintenance target is the current `main` branch on the documented
single-operator Linux x86_64 profile. The publicly published `v1.0.0` release
is a separate tagged artifact; fixes on `main` do not automatically patch its
downloaded binaries. Release-specific fixes and any backports must be confirmed
in release notes. No security support window is guaranteed for historical tags.

---

## 4. Core Security Model & Invariants

When evaluating vulnerabilities, please note KeyHelix's core security boundaries:

1. **Provider Owns Secret Bytes**:
   - The Go BFF engine and web application never persist plaintext secrets on disk, in SQLite/manifests, or in permanent memory.
   - All secret payloads are envelope-encrypted via OpenBao Transit and KV v2.
2. **Transient Reveal & Memory Zeroing**:
   - Plaintext reveal is transient, single-use, and governed by a 10-second auto-clearing countdown.
   - Dismissing the modal (via <kbd>Escape</kbd> or close button) immediately destroys plaintext DOM elements and in-memory references.
3. **Mandatory Step-Up Elevation**:
   - Access to reveal, grant management, and key rotation strictly requires fresh reauthentication with the OIDC identity provider (Keycloak).
4. **Fail-Closed Availability**:
   - An outage of OpenBao or Keycloak results in an immediate fail-closed state (`503 Service Unavailable`). Plaintext is never served from cache.
5. **Loopback & Origin Confinement**:
   - Internal engine binds strictly to ephemeral loopback (`127.0.0.1:0`).
   - The web server rejects non-loopback `Host` headers (`400 Bad Request`) to mitigate DNS rebinding attacks.
   - Sensitive endpoints under `/api/*` enforce same-origin semantics (`403 Forbidden` on untrusted origins).
   - Sensitive routes emit `Cache-Control: no-store` and `Pragma: no-cache`.
6. **Zero Telemetry**:
   - KeyHelix transmits no telemetry, analytics, or automated error crash dumps to external endpoints.

---

## 5. Scope & Exclusions

The following scenarios are considered outside the threat model of the local-first profile:

- Attacks requiring existing root or administrative execution on the local host.
- Physical tampering with unencrypted local storage outside the `.local-data/` access controls.
- Vulnerabilities in third-party dependencies that have not been demonstrated to affect KeyHelix.

---

## 6. Coordinated Vulnerability Disclosure Process

1. **Triage**: Review privately submitted, reproducible evidence against the declared local profile.
2. **Remediation**: Develop and test a bounded fix without exposing embargoed details.
3. **Disclosure**: Coordinate timing with the reporter; publish verified affected/fixed versions and mitigations when ready.
4. **Credit**: Follow the reporter's requested disclosure and attribution preferences.
