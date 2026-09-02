# KeyHelix — Definitive Sequential Roadmap v7

**Portfolio order:** 9 / 10
**Complexity:** Very high
**Planning estimate:** 14–20 focused weeks (not a promise; recalibrate after Phase 1)

**Why this order:** Secrets management is unforgiving. A portfolio demo is worthwhile only if cryptographic boundaries, recovery, audit and review are disciplined.

## First executable proof
Vault → generated DEK → XChaCha20-Poly1305 encryption → step-up reveal → KEK rewrap → tamper rejection → signed audit checkpoint.

## Rules for this repository
- One phase at a time; no implementation work for phase N+1 before phase N exit evidence is merged.
- Contract/schema changes precede dependent implementation.
- Every retryable operation is idempotent.
- Every derived store/projection has a rebuild path.
- Negative and failure tests are part of the feature, not post-release hardening.
- Status claims must be evidence-backed.

## Phase 0 — Identity/passkeys/step-up

**Implementation deliverables**
- Bootstrap authn and device/session model
- Passkey/WebAuthn flow
- Step-up policy and freshness window
- Session binding and revocation

**Required verification**
- WebAuthn ceremony tests
- step-up expiry tests
- session fixation/revocation tests

**Definition of Done**
- Secret reveal paths are unreachable without a fresh policy-compliant step-up assertion.
- CI is green from a clean checkout.
- New behavior is observable without logging secrets/sensitive payloads.
- Failure behavior and rollback/recovery note are documented.
- Contracts and README status are updated if externally visible behavior changed.

## Phase 1 — Vault policy domain

**Implementation deliverables**
- Vault/member/role domain
- Deny-by-default authorization
- Object-level access checks
- Explicit ownership/recovery roles

**Required verification**
- authorization matrix tests
- cross-tenant IDOR tests

**Definition of Done**
- Every vault operation is deny-by-default and object-level authorization is tested for cross-tenant access.
- CI is green from a clean checkout.
- New behavior is observable without logging secrets/sensitive payloads.
- Failure behavior and rollback/recovery note are documented.
- Contracts and README status are updated if externally visible behavior changed.

## Phase 2 — KeyEnvelope/CryptoProvider

**Implementation deliverables**
- Define versioned envelope format
- Generate random DEK per secret/version
- XChaCha20-Poly1305 AEAD with bound metadata
- OpenBao KEK wrapping provider interface

**Required verification**
- known-answer/round-trip tests
- AAD tamper tests
- nonce uniqueness tests

**Definition of Done**
- Ciphertext or metadata tampering is rejected and raw KEKs never enter application persistence/logs.
- CI is green from a clean checkout.
- New behavior is observable without logging secrets/sensitive payloads.
- Failure behavior and rollback/recovery note are documented.
- Contracts and README status are updated if externally visible behavior changed.

## Phase 3 — Secret versioning

**Implementation deliverables**
- Append-only secret versions
- Reveal audit context
- Optimistic concurrency on updates
- Soft-delete/retention semantics without crypto erasure claims unless implemented

**Required verification**
- version immutability tests
- concurrent update tests
- audit completeness

**Definition of Done**
- Old versions cannot be mutated and every reveal/update has attributable audit evidence.
- CI is green from a clean checkout.
- New behavior is observable without logging secrets/sensitive payloads.
- Failure behavior and rollback/recovery note are documented.
- Contracts and README status are updated if externally visible behavior changed.

## Phase 4 — Rotation/rewrap

**Implementation deliverables**
- KEK version metadata
- Online rewrap without plaintext persistence
- Resumable rotation jobs
- Failure-safe mixed-version reads

**Required verification**
- interrupt/resume tests
- old/new key compatibility
- rollback tests

**Definition of Done**
- Interrupted rewrap resumes safely and no secret becomes unreadable during partial rotation.
- CI is green from a clean checkout.
- New behavior is observable without logging secrets/sensitive payloads.
- Failure behavior and rollback/recovery note are documented.
- Contracts and README status are updated if externally visible behavior changed.

## Phase 5 — Sharing/grants

**Implementation deliverables**
- Time-bound grants
- Least-privilege secret/version scopes
- Single-use capability where applicable
- Revocation propagation

**Required verification**
- grant expiry tests
- replay tests
- revocation race tests

**Definition of Done**
- Revoked/expired grants fail consistently and do not leak secret existence beyond policy.
- CI is green from a clean checkout.
- New behavior is observable without logging secrets/sensitive payloads.
- Failure behavior and rollback/recovery note are documented.
- Contracts and README status are updated if externally visible behavior changed.

## Phase 6 — Audit chain/checkpoints

**Implementation deliverables**
- Append-only audit event chain
- Periodic signed checkpoints to object storage
- Verifier command
- Clock/order ambiguity handling

**Required verification**
- chain tamper tests
- checkpoint signature tests
- rebuild verifier tests

**Definition of Done**
- Deletion/reordering/modification of audited events is detected by checkpoint verification.
- CI is green from a clean checkout.
- New behavior is observable without logging secrets/sensitive payloads.
- Failure behavior and rollback/recovery note are documented.
- Contracts and README status are updated if externally visible behavior changed.

## Phase 7 — Recovery/provider operations

**Implementation deliverables**
- OpenBao outage behavior
- Backup/restore of encrypted metadata
- Key loss/runbook scenarios
- Operator break-glass design with explicit audit

**Required verification**
- provider outage tests
- restore drill
- break-glass audit tests

**Definition of Done**
- Documented recovery works without bypassing encryption guarantees; unrecoverable key-loss cases are explicit.
- CI is green from a clean checkout.
- New behavior is observable without logging secrets/sensitive payloads.
- Failure behavior and rollback/recovery note are documented.
- Contracts and README status are updated if externally visible behavior changed.

## Phase 8 — Crypto review/fuzz/public v1

**Implementation deliverables**
- Independent design review checklist
- Fuzz envelope/parser boundaries
- Secret scanning/log redaction checks
- Signed release and threat model

**Required verification**
- fuzz corpus
- log leakage tests
- clean install test

**Definition of Done**
- No custom cryptographic primitive is introduced; public v1 ships only after crypto-boundary review and tamper/recovery evidence.
- CI is green from a clean checkout.
- New behavior is observable without logging secrets/sensitive payloads.
- Failure behavior and rollback/recovery note are documented.
- Contracts and README status are updated if externally visible behavior changed.

## Public v1 invariant
The project is not called production-ready merely because all phases are coded. `PUBLIC-V1-GO` requires the repository release gate, clean-install proof, security/recovery evidence and signed/verifiable release artifacts.
