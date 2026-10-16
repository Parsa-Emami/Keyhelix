# KeyHelix — Final Implementation Specification

This specification freezes the v1 implementation contract. Changes that violate an invariant, authority boundary or public contract require an ADR/RFC and migration/compatibility plan.

## Domain objects
- `Vault`
- `VaultMember`
- `Secret`
- `SecretVersion`
- `KeyEnvelope`
- `KeyProviderRef`
- `AccessPolicy`
- `AccessGrant`
- `RotationJob`
- `AuditEvent`
- `AuditCheckpoint`
- `RecoveryProcedure`
- `WebAuthnCredential`

## Aggregate rules
- Aggregate mutations occur through application commands, never controller/model convenience writes.
- Aggregate version is checked on conflicting writes.
- Invariants are tested with illegal-transition/negative cases.
- Domain objects do not import Laravel/Eloquent/vendor SDKs.

## Frozen v1 invariants
1. Every secret version has fresh DEK and nonce.
2. Ciphertext/AAD authentication failure never returns partial plaintext.
3. Plaintext never enters persistent/cache/queue/telemetry boundaries.
4. Retiring a KEK is forbidden until all live envelopes are verified rewrapped.
5. Account recovery cannot silently bypass cryptographic root loss semantics.
