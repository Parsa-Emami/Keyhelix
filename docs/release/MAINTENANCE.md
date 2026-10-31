# KeyHelix Maintenance & Dependency Governance Policy

> **Contract Reference**: Requirement N38, Task C38, [ADR-0003 (Open-Source Local-First Delivery)](../architecture/ADR-0003-open-source-local-first.md), and [SECURITY.md](../../SECURITY.md).

---

## 1. Maintenance Philosophy

KeyHelix is maintained under a **predictable, local-first, zero-telemetry** lifecycle:
- **No Involuntary Updates**: KeyHelix never silently downloads, auto-updates, or restarts background components without explicit operator intervention.
- **Operator-Controlled Cadence**: Upgrades, provider restarts, and migrations are solely triggered by local operator commands (`npm run setup`, `npm run build`, `npm start`).
- **Transparent Artifacts**: All binaries, web assets, and provider images are cryptographically pinned, hash-verified, and signed with detached Ed25519 signatures.

---

## 2. Dependency & Toolchain Governance

To guarantee reproducible builds and auditability across all operating environments, KeyHelix enforces strict dependency locking:

### 2.1 Toolchain Locking
All development, build, and runtime toolchain versions are locked in [`docs/engineering/toolchain-lock.json`](../engineering/toolchain-lock.json):
- **Go Toolchain**: Go `1.26.2+` (packaged engine compiler).
- **Node.js**: Node `v24.19.0` (LTS baseline).
- **NPM**: Pinned version `11.9.0` (executing environment compatibility checked).
- **Container Engine**: Podman `4.9+` or Docker compatible CLI.

### 2.2 Provider Pinned Images & Licenses
External cryptographic and identity providers must adhere to compatible open-source licenses and pinned image digests:
- **OpenBao**: `quay.io/openbao/openbao:2.7.2` (License: **MPL-2.0**).
- **Keycloak**: `quay.io/keycloak/keycloak:26.8.1` (License: **Apache-2.0**).
- **Third-Party Inventory**: All npm libraries, Go modules, and container resources are exhaustively documented with licensing terms and repository URLs in [`THIRD_PARTY_NOTICES.md`](../../THIRD_PARTY_NOTICES.md) and machine-readable SBOM artifacts.

---

## 3. Versioning & Backward Compatibility

KeyHelix adheres strictly to **Semantic Versioning 2.0.0** (`MAJOR.MINOR.PATCH`):

1. **MAJOR Version Bumps (`X.0.0`)**:
   - Reserved for incompatible architectural shifts or breaking changes to public CLI interfaces or persistent storage formats.
   - Breaking migrations must be accompanied by explicit forward-repair migration scripts.
2. **MINOR Version Bumps (`0.X.0`)**:
   - Introduction of backwards-compatible capabilities, provider adapters, or diagnostic tooling.
   - **N-1 Reader Compatibility**: The engine metadata reader is required to read and parse the preceding minor release's store manifests and blob envelopes without data loss.
3. **PATCH Version Bumps (`0.0.X`)**:
   - Backwards-compatible bug fixes, security patches, and performance optimizations.

---

## 4. Upgrade & Safe Rollback Policy

### 4.1 Upgrade Safety Guardrails
1. **Preflight Health Probing**: Prior to launching newer engine binaries, `npm run doctor` and port preflight probes ensure provider containers and ports (8080, 8200) are healthy and uncollided.
2. **Atomic Binary Replacement**: Engine binaries and web build distributions are staged and atomically replaced.
3. **Schema Verification on Startup**: The engine validates store manifest versions upon opening. Unrecognized or corrupt future revisions fail fast with explicit diagnostic error codes.

### 4.2 Safe Rollback and Stale Data Defense
- **Preservation of Accepted Writes**: If an operator reverts engine binaries to an earlier version, the older engine binary must safely read compatible accepted records or fail closed gracefully.
- **Anti-Rollback Invariant**: Restoring an older snapshot over newer accepted records is forbidden to prevent rollback replay attacks.
- **Forward Repair**: In the event of an interrupted upgrade, forward repair using verified migration fixtures is the only supported path to recover system state.

---

## 5. Security Maintenance & Incident Response

### 5.1 Supported Release Windows
- **Current Active Line**: The latest minor release on the `main` branch receives prompt CVE triage, dependency bumps, and bugfix patches.
- **Critical Security Patches**: Critical vulnerabilities affecting cryptographic boundaries (OpenBao integration, token step-up verification, or plaintext leaks) are prioritized for immediate patch releases.

### 5.2 Vulnerability Reporting & Disclosure
- **Private Reporting Route**: Vulnerabilities must be submitted privately via GitHub Security Advisories or by emailing `security@keyhelix.local`.
- **Prohibition of Public Issues**: Reporters must not open public GitHub Issues for unpatched vulnerabilities.
- **Initial Response SLA**: The project maintainers acknowledge and initiate triage for reported vulnerabilities within **48 hours**.

---

## 6. Deprecation Policy

- **Advance Notice**: Any public CLI flag, configuration parameter, or provider adapter planned for deprecation must be marked deprecated for at least **one minor release cycle** before removal.
- **Migration Tooling**: No key provider adapter or storage format may be deprecated without providing an automated export/import bridge to migrate keys and metadata safely.
