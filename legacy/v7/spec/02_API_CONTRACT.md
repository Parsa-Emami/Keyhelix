# KeyHelix — Final Implementation Specification

This specification freezes the v1 implementation contract. Changes that violate an invariant, authority boundary or public contract require an ADR/RFC and migration/compatibility plan.

## HTTP conventions
- Prefix `/api/v1`; JSON UTF-8; explicit content type.
- Resource IDs are opaque UUID/ULID-style identifiers and authorization is re-evaluated after lookup.
- Cursor pagination for unbounded collections.
- Mutation request/response schemas are versioned in OpenAPI; unknown security-sensitive fields are rejected where ambiguity is dangerous.
- Stable error codes follow the common error standard.

| Method | Route | Purpose | Gate |
|---|---|---|---|
| `POST` | `/vaults` | Create vault | auth + validation + idempotency where side-effecting |
| `POST` | `/vaults/{vault}/secrets` | Encrypt new secret version | auth + validation + idempotency where side-effecting |
| `POST` | `/secrets/{secret}/reveal` | Step-up protected reveal | auth + validation + idempotency where side-effecting |
| `POST` | `/vaults/{vault}/rotations` | Start KEK rewrap rotation | auth + validation + idempotency where side-effecting |
| `POST` | `/grants` | Create scoped/expiring grant | auth + validation + idempotency where side-effecting |
| `GET` | `/audit/checkpoints/{id}/verify` | Verify checkpoint integrity | auth + validation + idempotency where side-effecting |

## Compatibility
Additive compatible changes may ship in v1. Removing/renaming/changing semantics requires deprecation + migration and normally a new API major. Golden request/response fixtures run in CI.
