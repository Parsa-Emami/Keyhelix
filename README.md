# KeyHelix

[![Source](https://github.com/Parsa-Emami/Keyhelix/actions/workflows/contracts.yml/badge.svg?branch=main)](https://github.com/Parsa-Emami/Keyhelix/actions/workflows/contracts.yml?query=branch%3Amain) [![Plan](https://github.com/Parsa-Emami/Keyhelix/actions/workflows/plan.yml/badge.svg?branch=main)](https://github.com/Parsa-Emami/Keyhelix/actions/workflows/plan.yml?query=branch%3Amain) [![Web](https://github.com/Parsa-Emami/Keyhelix/actions/workflows/web.yml/badge.svg?branch=main)](https://github.com/Parsa-Emami/Keyhelix/actions/workflows/web.yml?query=branch%3Amain)

[CI source integrity and dependency updates](docs/engineering/CI_SOURCE_INTEGRITY.md)

Open-source local-first secret management and cryptographic authorization workspace under [Apache-2.0](LICENSE). **Current implementation: C01–C34 complete local engine, provider integration, web workspace, reproducible release packaging, hardened network boundaries, accessible UX, and full open-source guides verified; C35–C40 signed distribution and installed-host proofs remain.**

---

## Clone and Run the Local Workspace

KeyHelix operates completely offline without mandatory cloud accounts, paid API entitlements, or proprietary dependencies.

### Prerequisites

- **Linux x86_64** (Ubuntu 22.04 / 24.04 LTS)
- **Node.js**: `>= 24.19.0 < 25` (npm included)
- **Go**: `1.26.2+` (1.26.x)
- **Podman**: `4.9.3+` (rootless container runtime)
- **Git**: `2.34+`

### Quickstart

```sh
git clone https://github.com/Parsa-Emami/Keyhelix.git
cd Keyhelix
npm run setup
npm start
```

Open **http://localhost:4173** in your browser.

- **Authentication**: Sign in via local Keycloak OIDC as `alice` (`alice` / `keyhelix-local-alice`) or `bob` (`bob` / `keyhelix-local-bob`).
- **Scoped Writes**: Create envelope-encrypted secrets in `vault-prod` via OpenBao Transit and KV v2.
- **Transient Reveal**: Perform audited, step-up elevation reveals with an auto-zeroing countdown timer (<kbd>Escape</kbd> or close clears browser memory immediately).
- **Access Management**: Grant and synchronously revoke member permissions.
- **Key Rotation**: Execute resumable Key Encryption Key (KEK) rotations.
- **Fail-Closed Provider Resilience**: Provider outages fail closed with explicit `503 Service Unavailable` status and zero plaintext leakage.

For detailed instructions, see the **[User Guide](docs/release/USER_GUIDE.md)** and **[Clone-to-Run Guide](docs/engineering/CLONE_TO_RUN.md)**.

---

## Source Builds & Reproducible Packaging

KeyHelix can be compiled directly from source:

- **Build Go BFF Engine**: `npm run build:engine` (produces `bin/keyhelix`)
- **Build Web Application**: `npm run build` (compiles assets to `dist/web/`)
- **Produce Reproducible Release Artifacts**: `npm run package` (bundles engine binary, web UI, offline contracts, CycloneDX SBOM, third-party notices, and SHA-256 checksums into `dist/release/`)

---

## Core Security & Data Guarantees

1. **Provider Owns Secret Bytes**: OpenBao owns all sealed secret bytes; the engine stores only encrypted metadata envelopes and digests. Plaintext is never persisted to disk or databases.
2. **Zero Telemetry & Cache Segregation**: Zero outbound network telemetry or analytics. Sensitive routes emit `Cache-Control: no-store`.
3. **Loopback & Origin Confinement**: Binds strictly to loopback (`127.0.0.1:0` for engine, `127.0.0.1:4173` for web). Mitigates DNS rebinding via `Host` header validation and enforces same-origin semantics on `/api/*`.
4. **Vulnerability Disclosure**: Review our security policy and confirmed reporting route in **[SECURITY.md](SECURITY.md)**.

---

## Verification and Quality Checks

```sh
npm run check          # Validates plan, builds web/engine, and runs unit tests
npm test               # Runs web and contract test suites
npm run test:browser   # Runs 39 Playwright accessibility and e2e browser tests
npm run doctor         # Inspects local toolchain, binary, and provider readiness
```

---

## Roadmap and Next Task

```sh
npm run plan -- status
npm run plan -- next
npm run plan -- show C35
```

Each roadmap card in `plans/commits/Cxx.md` specifies exact paths, resources, fixtures, acceptance criteria, negative cases, and rollback procedures. See [AGENTS.md](AGENTS.md) and [Execution Contract](docs/agents/EXECUTION_CONTRACT.md). Persian overview: [فارسی](docs/ROADMAP_FA.md).

---

## Documentation Links

- **[User Guide](docs/release/USER_GUIDE.md)** — Complete installation, workflow, data limits, recovery, and support guide
- **[Clone-to-Run Guide](docs/engineering/CLONE_TO_RUN.md)** — Step-by-step developer and operator setup
- **[Open-Source Contract](OPEN_SOURCE.md)** — Apache-2.0 licensing, zero paid cloud guarantee, and upstream inventory
- **[Contributing Guide](CONTRIBUTING.md)** — Contribution workflow, DCO, testing standards, and PR guidelines
- **[Security Policy](SECURITY.md)** — Coordinated vulnerability disclosure, 48h SLA, and security invariants
- **[Third-Party Notices](THIRD_PARTY_NOTICES.md)** — Upstream license inventory
- **[Definition of Done](docs/release/DEFINITION_OF_DONE.md)** — Release readiness and gate criteria
- **[Architecture (ADR-0003)](docs/architecture/ADR-0003-open-source-local-first.md)** — Open-source local-first architecture decision record
