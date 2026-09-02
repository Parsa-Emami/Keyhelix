# KeyHelix — Final Implementation Specification

This specification freezes the v1 implementation contract. Changes that violate an invariant, authority boundary or public contract require an ADR/RFC and migration/compatibility plan.

## Authoritative relational tables
- `vaults`
- `vault_members`
- `secrets`
- `secret_versions`
- `key_envelopes`
- `provider_keys`
- `access_policies`
- `access_grants`
- `rotation_jobs`
- `rotation_items`
- `webauthn_credentials`
- `audit_events`
- `audit_checkpoints`
- `outbox_messages`

## Universal columns
Where applicable: opaque primary ID, owning scope ID, aggregate/version number, created/updated instant, creator/updater actor where meaningful. Sensitive fields are explicit rather than hidden in generic JSON blobs. JSONB is reserved for versioned documents/extensible metadata with JSON Schema and migration plan.

## Constraints
Use database unique/foreign/check constraints for correctness that must survive concurrency. Soft deletion is not a substitute for retention/legal-hold semantics. Outbox rows are inserted in the same transaction as authoritative state changes.

## Index proof
Every nontrivial index is linked to a measured query plan/workload. CI integration tests use real PostgreSQL; production query regressions are captured with representative fixtures before v1.
