# KeyHelix — Final Implementation Specification

This specification freezes the v1 implementation contract. Changes that violate an invariant, authority boundary or public contract require an ADR/RFC and migration/compatibility plan.

| Data class | v1 rule |
|---|---|
| ciphertext | per vault policy; deletion may cryptographically erase by key destruction where policy supports it |
| audit | append-only/tamper-evident per security policy |
| plaintext | zero retention |
| credentials | public credential metadata only; private authenticators remain client/device side |

## Classification labels
`PUBLIC`, `INTERNAL`, `CONFIDENTIAL`, `SECRET`, plus project-specific `EVIDENCE`/`SECURITY_TELEMETRY`. Classification drives logging, export, encryption, backup and retention behavior.

## Deletion
Deletion is an explicit domain operation with authorization, hold checks, audit and downstream projection/cache invalidation. Derived stores must not resurrect deleted authoritative data during rebuild.
