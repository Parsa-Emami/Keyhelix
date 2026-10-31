# KeyHelix — Task C39 Implementation Plan (`ci(release): enforce evidence-backed open-source v1 readiness`)

Enforce an evidence-backed open-source v1 release gate (`Requirement N39`) that verifies authentic `C01–C38` proofs, full clone-to-value workflow completion, complete source and engine packaging, upstream dependency and fixture license compliance, and supported-profile security and recovery invariants—failing closed on planning templates, missing proofs, or mismatched source identities.

> [!IMPORTANT]
> **Plan Mode Active — Zero Code Modifications Performed**
> No repository files have been modified. Execution will begin only after your explicit approval of this plan.

---

## 1. Overview & Scope (Complexity: Medium)

- **Task ID & Title**: `C39` — `ci(release): enforce evidence-backed open-source v1 readiness`
- **Dependencies**: `C38` (Verified)
- **Requirement**: `N39`
- **Core Objective**: Upgrade `npm run release:check` (`scripts/roadmap.mjs`), `plans/release-gates.json`, `docs/evidence/v1-gate.json`, and `.github/workflows/release-gate.yml` so release readiness is mechanically enforced against real `C01–C38` evidence and storage/security invariants before `C40` publication.

---

## 2. Architecture & Gate Verification Flow

```
┌──────────────────────────────────────────────────────────────────────────┐
│                   CI Workflow (.github/workflows/release-gate.yml)       │
│  Pinned SHA Actions ─► validate:plan ─► release:check ─► Go & Node Tests │
└───────────────────────────────────────┬──────────────────────────────────┘
                                        │
                                        ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                 Release Gate Engine (scripts/roadmap.mjs)                │
│                                                                          │
│  ┌─────────────────────────┐    ┌─────────────────────────────────────┐  │
│  │ plans/release-gates.json│    │    docs/evidence/C01..C38.json      │  │
│  │ - core_ready: true      │───►│ - passed === true                   │  │
│  │ - C01-C38 prerequisites │    │ - planning_template === false       │  │
│  │ - license & proof rules │    │ - source_identity === progress hash │  │
│  └─────────────────────────┘    │ - commands[].exit_code === 0        │  │
│                                 └─────────────────┬───────────────────┘  │
│                                                   │                      │
│                                                   ▼                      │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │               docs/evidence/v1-gate.json & Inventories             │  │
│  │ - Clone-to-value (C30, C36) & Packaging/Signing (C31, C35)         │  │
│  │ - Toolchain & Notices (toolchain-lock.json, THIRD_PARTY_NOTICES)   │  │
│  │ - Security, Recovery & Policy (C24-C29, C32-C34, C37-C38)          │  │
│  └────────────────────────────────────────────────────────────────────┘  │
└───────────────────────────────────────┬──────────────────────────────────┘
                                        │
                  ┌─────────────────────┴─────────────────────┐
                  ▼                                           ▼
     [All Checks Validated]                      [Template / Missing / Mismatch]
     Exit Code 0 (READY)                         Exit Code 2 (FAIL-CLOSED)
```

---

## 3. Target Files & Implementation Steps

### Step 1: Versioned Fixtures (`tests/fixtures/keyhelix/C39/`)
- **`positive.json`**: Synthetic Apache-2.0 fixture defining a complete, valid v1 release-gate state (`C01–C38` verified, `core_ready: true`, clone-to-value certified, packaging/SBOM/signing verified, permissible Apache-2.0/MIT/BSD/MPL-2.0 licenses, and storage/provider invariants).
- **`negative.json`**: Synthetic negative cases covering:
  1. `planning-template-evidence` (`planning_template: true` rejected)
  2. `missing-prerequisite-proof` (missing or unverified `C01–C38` evidence file)
  3. `wrong-source-identity` (`evidence.source_identity !== progress.source_identity`)
  4. `restricted-or-unknown-license` (unlicensed or incompatible resource blocked)
  5. `staged-byte-writer-crash` (writer killed at staging/manifest boundary)
  6. `operation-replay-and-quota` (duplicate operation ID replay and >1 MiB quota exhaustion)
  7. `provider-owns-secret-bytes` (plaintext secret sentinel barred from engine store)
- **`expected-output.json`**: Expected pass/fail gate outcomes and verified invariants for `N39`.

### Step 2: Release Gate Configuration (`plans/release-gates.json` & `docs/evidence/v1-gate.json`)
- **`plans/release-gates.json`**: Preserve all existing fields (`project`, `core_ready`, `usable_at`, `oss_v1_at`, `local_usable_requires`, `release_prerequisites`, `publish_requires`, `not_required`) so `scripts/roadmap.mjs` validation remains 100% compatible, while adding `v1_gate_evidence: "docs/evidence/v1-gate.json"` and `gate_checks` metadata (clone-to-value, packaging, licenses, security/recovery).
- **`docs/evidence/v1-gate.json`**: Create the consolidated v1 readiness gate proof referencing verified `C01–C38` source identities, clone-to-value proofs (`C30`, `C36`), packaging and signature proofs (`C31`, `C35`), license/toolchain inventories (`docs/engineering/toolchain-lock.json`, `THIRD_PARTY_NOTICES.md`, `LICENSE`), and security/recovery proofs (`C24–C29`, `C32–C34`, `C37–C38`).

### Step 3: Enforce Gate Logic in `scripts/roadmap.mjs`
- Export a pure/testable `releaseCheck(plan, progress, gates, options)` function and wire it into the `release-check` CLI branch:
  - Verify `gates.core_ready === true` and every task in `C01–C38` (`gates.release_prerequisites`) has `status === 'verified'`.
  - Load each `C01–C38` evidence JSON and verify: `passed === true`, `planning_template !== true`, `commit_id === task.id`, `source_identity === state.source_identity`, non-empty `commands` with all `exit_code === 0`, and non-empty `fixtures.license` / `fixtures.hashes` (where applicable).
  - Verify required domain/workflow proofs (`docs/evidence/v1-gate.json`, `docs/engineering/toolchain-lock.json`, `THIRD_PARTY_NOTICES.md`, `LICENSE`) exist and pass structural/license checks (no unknown/restricted licenses, `v1-gate.json` `passed === true` and `planning_template === false`).
  - Exit with code `0` and print structured readiness confirmation when all checks pass; exit with code `2` and descriptive error diagnostics if any check fails.

### Step 4: CI Workflow (`.github/workflows/release-gate.yml`)
- Create `.github/workflows/release-gate.yml` triggered on `pull_request`, `push` (`main`), and `workflow_dispatch`.
- Pin all GitHub Actions to the exact 40-char commit SHAs used across `.github/workflows/runtime.yml` and `contracts.yml` (`actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803`, `actions/setup-node@249970729cb0ef3589644e2896645e5dc5ba9c38`, `actions/setup-go@40f1582b2485089dde7abd97c1529aa768e1baff`).
- Run `npm ci --ignore-scripts`, `npm run validate:plan`, `python3 scripts/validate_repo.py`, `npm run release:check`, Go engine `TestC39*` tests (`go test -count=1 -v ./tests -run TestC39`), and Node release gate tests (`node --test tests/web/release-gate.test.mjs`).

### Step 5: Regression & Negative-Case Tests
- **Go Engine Tests (`tests/release_gate_test.go`)**:
  - `TestC39StagedWriterCrashAuthoritativeRecoveryN39`: Kill writer at staged-byte/manifest boundary; reopen store and verify orphan staging/blobs are purged and only authoritative state is exposed.
  - `TestC39ReplayIdempotencyAndQuotaExhaustionN39`: Verify duplicate `OperationID` replay produces no duplicate manifest version or side effects, and oversized (>1 MiB) write fails closed.
  - `TestC39ProviderOwnsSecretBytesZeroPlaintextN39`: Verify sealed envelope metadata persistence leaves zero plaintext canary bytes on disk.
  - `TestC39EvidenceGateIntegrityN39`: Verify `C01–C38` evidence files and `docs/evidence/v1-gate.json` on disk satisfy non-template, `passed: true`, and `source_identity` invariants.
- **Node Tests (`tests/web/release-gate.test.mjs`)**:
  - Verify `releaseCheck` succeeds on the real repository state (`exit_code === 0`).
  - Verify `releaseCheck` fails closed (`exit_code === 2`) on injected negative cases: `planning_template: true`, missing evidence file, mismatched `source_identity`, failed command exit code (`exit_code !== 0`), unverified task in `C01–C38`, or restricted/missing license in `v1-gate.json`.
  - Verify `.github/workflows/release-gate.yml` pins 40-char action SHAs and runs `npm run release:check`.
  - Verify `tests/fixtures/keyhelix/C39/{positive,negative,expected-output}.json` schema and contract compliance.

### Step 6: Evidence & Handoff Recording
- Compute deterministic `source_identity` over C39-owned files and write `docs/evidence/C39.json`.
- Update `plans/progress.json` (`C39` -> `verified`), `plans/project-state.json` (`next_task` -> `C40`), `docs/agents/SESSION_HANDOFF.json`, and regenerate `apps/web/src/generated/project.json` via `npm run prepare:web`.

---

## 4. Acceptance Criteria & Verification Plan

| Check / Command | Purpose |
| :--- | :--- |
| `npm run validate:plan` | Validates all 40 tasks, dependencies, deliverables, fixtures, and `C39` evidence metadata. |
| `npm run release:check` | Exits `0` after `C01–C38` evidence, `v1-gate.json`, licenses, and core readiness are verified. |
| `go test -count=1 ./tests -run TestC39` & `go test -count=1 ./...` | Verifies C39 storage crash recovery, replay idempotency, quota bounds, provider secret ownership, and all engine suites (using pinned local Go toolchain in `.local-data/oss/bin/go`). |
| `npm test` | Runs all Node web, contract, and `tests/web/release-gate.test.mjs` suites. |
| `python3 scripts/validate_repo.py` & `python3 scripts/plan.py validate` | Validates all JSON files, OpenAPI/AsyncAPI contracts, pinned workflow SHAs, and roadmap consistency. |
| `python3 -m unittest discover -s tests/engineering -p 'test_*.py'` | Verifies CI source integrity regression tests pass. |
