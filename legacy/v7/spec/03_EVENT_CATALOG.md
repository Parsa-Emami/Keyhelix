# KeyHelix — Final Implementation Specification

This specification freezes the v1 implementation contract. Changes that violate an invariant, authority boundary or public contract require an ADR/RFC and migration/compatibility plan.

## Versioned domain/integration events
- `secret.version_created.v1`
- `secret.revealed.v1`
- `grant.created.v1`
- `grant.revoked.v1`
- `key.rotation_started.v1`
- `key.envelope_rewrapped.v1`
- `key.rotation_completed.v1`
- `audit.checkpoint_signed.v1`

## Envelope
Every message carries `specversion`, `id`, `source`, `type`, `subject`, `time`, `datacontenttype`, `correlation_id`, `causation_id`, `tenant/workspace scope`, aggregate ID/version and payload schema version.

## Delivery semantics
At-least-once delivery is assumed. Consumers deduplicate by event/command identity and verify aggregate/projection checkpoint. Ordering is guaranteed only within an explicitly versioned stream. Consumers tolerate duplicates and documented reordering; correctness never assumes exactly-once transport.
