# KeyHelix Contributing Guide

Thank you for your interest in contributing to KeyHelix! We are committed to building an open-source, local-first cryptographic workspace under [Apache-2.0](LICENSE).

---

## 1. Principles and Ground Rules

1. **Local-First & Open Source**: Every core feature must be fully functional offline on a local Linux host without requiring paid subscriptions, cloud services, or closed-source companions. See [OPEN_SOURCE.md](OPEN_SOURCE.md).
2. **Permanent Owner Restrictions**:
   - Do **not** modify database schemas, migrations, `.env` files, or Dockerfiles.
   - Use compatible ADR-0003 adapters and versioned immutable manifest ports.
3. **Plan-Driven Roadmap**:
   Development follows the structured roadmap defined in `plans/roadmap.json`. Each change corresponds to a discrete, dependency-ready task card in `plans/commits/Cxx.md`.
4. **Developer Certificate of Origin (DCO)**:
   By contributing, you certify that you have the right to submit the work under Apache-2.0 and agree to the Developer Certificate of Origin ([DCO.md](DCO.md)).

---

## 2. Setting Up Your Development Environment

### Prerequisites

- **Linux x86_64** (Ubuntu 22.04 / 24.04 LTS recommended)
- **Node.js**: `>= 24.19.0 < 25` (with npm)
- **Go**: `1.26.2+` (1.26.x)
- **Podman**: `4.9.3+` (rootless container runtime)
- **Git**: `2.34+`

### Initial Setup

```sh
git clone https://github.com/Parsa-Emami/Keyhelix.git
cd Keyhelix
npm run setup
```

Verify your environment with the diagnostic doctor:
```sh
npm run doctor
```

Start the local development workspace:
```sh
npm start
```
Open `http://localhost:4173` to interact with the web workspace.

---

## 3. Contribution Workflow

### 3.1 Pick Up the Next Roadmap Task

1. Inspect the roadmap status and retrieve the next dependency-ready task:
   ```sh
   npm run plan -- status
   npm run plan -- next
   ```
2. Read the corresponding task card in `plans/commits/Cxx.md` in full, including exact deliverables, acceptance criteria, negative cases, and verification commands.

### 3.2 Implement Thin, Vertical Slices

- Maintain clean architectural boundaries:
  - Domain logic and provider orchestration belong in Go (`cmd/keyhelix`, `internal/*`).
  - User interface components belong in `apps/web/src/`.
  - Protocol contracts belong in `contracts/`.
  - Versioned test fixtures belong in `tests/fixtures/keyhelix/Cxx/`.
- Never substitute placeholders, mock-only durability, or synthetic success for real provider behavior.

### 3.3 Core Architectural Invariants to Uphold

- **Provider Owns Secret Bytes**: Never store unencrypted secret payloads on disk or in the engine. Delegate encryption to OpenBao Transit/KV.
- **Zero Plaintext Persistence & Zero Telemetry**: Destroy in-memory plaintext upon modal dismissal or timer expiration. Emit no external telemetry.
- **Fail-Closed on Provider Outage**: When OpenBao or Keycloak are unreachable, fail operations with explicit `503 Service Unavailable`.
- **Responsive & Accessible**: Support 360px mobile viewports without horizontal scroll overflow; support full keyboard navigation (skip links, tab order, Escape key dialog dismissal).

---

## 4. Verification and Testing Standards

Before submitting a Pull Request, run the complete verification suite locally:

```sh
# 1. Validate planning consistency across roadmap and evidence
npm run validate:plan

# 2. Run unit and contract tests
npm test

# 3. Run Go engine test suite
PATH=/usr/local/go/bin:$PATH go test ./...

# 4. Run browser end-to-end and accessibility tests
npm run test:browser

# 5. Run full clean-host clone smoke test (verifies setup, restart, and restore)
KEYHELIX_CLONE_WORKTREE=1 KEYHELIX_REUSE_PROVIDERS=1 npm run test:clone

# 6. Validate repository invariants and JSON schemas
python3 scripts/validate_repo.py
```

All checks must pass cleanly with exit code 0. Never disable checks or suppress linter errors.

---

## 5. Commit Guidelines and Pull Requests

### Conventional Commits Format

Commit messages must adhere to the [Conventional Commits](https://www.conventionalcommits.org/) specification:

```
<type>(<scope>): <short description>

[optional body describing technical context, invariants, and validation]
```

Allowed types: `feat`, `fix`, `docs`, `chore`, `test`, `ci`, `perf`, `build`, `refactor`, `style`, `revert`.

### Submitting a Pull Request

1. Push your changes to a feature branch on your fork:
   ```sh
   git checkout -b feat/task-cxx-description
   git push origin feat/task-cxx-description
   ```
2. Open a Pull Request against `main`.
3. In the PR description, summarize:
   - The roadmap task ID and requirement addressed.
   - Files changed and architectural approach.
   - Verification commands executed and observed outcomes.
   - Confirmation that no protected files were altered.

---

## 6. Security Vulnerability Reporting

If you identify a security issue or potential vulnerability in KeyHelix, please do **not** file a public issue. Follow our coordinated vulnerability disclosure process in [SECURITY.md](SECURITY.md) by submitting a private advisory at:
👉 **[Open a Private Security Advisory](https://github.com/Parsa-Emami/Keyhelix/security/advisories/new)**
