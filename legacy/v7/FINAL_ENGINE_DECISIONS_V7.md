# KeyHelix — Final Engine Decisions v7

These are accepted v1 decisions, not open blockers. Alternatives require a future ADR and must preserve public/domain contracts.

1. v1 trust model is server-side envelope encryption. Client-side zero-knowledge encryption is not mixed into v1 and would require a separate major architecture.
2. Each secret version receives a fresh random 256-bit DEK and XChaCha20-Poly1305 AEAD nonce. DEKs are wrapped by a versioned KEK provider key.
3. OpenBao is the reference production KEK/Transit provider. A local development provider exists only for non-production tests and is clearly marked unsafe for production.
4. AAD is canonical and versioned: vault_id, secret_id, secret_version, owner_scope, classification, algorithm_version. AAD mismatch is integrity failure.
5. Plaintext is never persisted, queued, cached, indexed, traced or logged. Sensitive request fields are excluded at the telemetry instrumentation boundary.
6. Passkey/WebAuthn + MFA/step-up is required for reveal/export/key rotation/member privilege changes according to policy.
7. Recovery restores account control, not lost cryptographic roots. If the KEK provider root is irrecoverably lost, ciphertext is intentionally unrecoverable.
8. Audit events are hash-chained; periodic Merkle/checkpoint roots are signed through OpenBao Transit and stored separately for tamper evidence.
9. Algorithm agility is carried in KeyEnvelope v1; no custom primitives are implemented.
