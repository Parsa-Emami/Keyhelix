# KeyHelix — Failure & Recovery Proof v7

## Mandatory injected failures
- OpenBao outage
- wrong key version
- corrupted ciphertext
- AAD mismatch
- partial rewrap
- revocation race
- audit checkpoint failure
- recovery-root loss

## Pass criteria
For every failure: no invariant violation; no unauthorized bypass; no unbounded retry storm; orphan resources are reconciled; user-visible state becomes correct; telemetry identifies cause; retry/cancel/manual recovery is documented; recovery test is automated where feasible.
