# KeyHelix Security Policy

KeyHelix takes the security of its open-source secret management workspace and cryptographic authorization architecture seriously. We welcome responsible security research and vulnerability disclosures.

---

## 1. Reporting a Vulnerability

> [!IMPORTANT]
> **Do not report security vulnerabilities through public GitHub Issues, pull requests, or public discussions.** Public disclosure risks exposing operators and active secret management infrastructure before a patch is available.

### Preferred Reporting Route: GitHub Security Advisories

Submit a private vulnerability report via GitHub's Coordinated Vulnerability Disclosure (CVD) interface:
👉 **[Open a Private Security Advisory](https://github.com/Parsa-Emami/Keyhelix/security/advisories/new)**

### Alternative Reporting Route: Encrypted Email

If you cannot submit via GitHub Security Advisories, send an email directly to the project security maintainer:
- **Email**: `security@keyhelix.local` (or direct maintainer contact via GitHub profile: [Parsa-Emami](https://github.com/Parsa-Emami))
- **Subject**: `[SECURITY VULNERABILITY] KeyHelix - <Brief Description>`
- **Content**:
  - Detailed description of the vulnerability.
  - Step-by-step instructions or proof-of-concept (PoC) to reproduce the issue.
  - Potential impact, attack vector, and affected component(s).
  - Any proposed remediations or patches.

---

## 2. Response Timelines and SLAs

We adhere to the following response timeline for confirmed vulnerability reports:

| Milestone | Target Response Time | Action |
| --- | --- | --- |
| **Initial Acknowledgment** | **Within 48 hours** | Confirm receipt of the report and establish communication. |
| **Triage & Assessment** | **Within 7 days** | Validate the vulnerability, assign CVSS severity, and determine scope. |
| **Remediation & Patching** | **Within 14–30 days** | Develop, test, and package an emergency security update. |
| **Coordinated Disclosure** | **Upon Patch Release** | Publish advisory and credit reporters (unless anonymity is requested). |

---

## 3. Supported Versions

Security updates and patches are provided for the following releases:

| Version Line | Supported | Notes |
| --- | --- | --- |
| `main` (trunk) | ✅ Yes | Active development branch; immediate patches applied. |
| `v0.0.1` (current local profile) | ✅ Yes | Supported release branch for Linux x86_64. |
| `< 0.0.1` | ❌ No | Historical planning baselines and prototypes. |

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

1. **Investigation**: We verify the reported vulnerability in an isolated test environment.
2. **Fix Development**: We prepare a fix on a private security fork.
3. **Release**: We publish a patch release along with a GitHub Security Advisory detailing the issue, severity, and mitigations.
4. **Credit**: We acknowledge and credit the reporter in release notes and security advisories.
