# KeyHelix — Final Implementation Specification

This specification freezes the v1 implementation contract. Changes that violate an invariant, authority boundary or public contract require an ADR/RFC and migration/compatibility plan.

## Golden E2E scenarios
1. Create/encrypt/reveal with step-up
2. Tamper ciphertext and fail closed
3. Rotate KEK by resumable rewrap then verify
4. Revoke grant and deny subsequent reveal
5. Break OpenBao mid-rotation then resume
6. Verify signed audit checkpoint chain

For every golden scenario record expected authoritative state, emitted event IDs/types, audit action, projection state, critical metrics and cleanup state. Run from a clean environment with deterministic synthetic fixtures. At least one scenario must fail mid-flight and then converge after restart/retry/reconciliation.
