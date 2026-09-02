# ADR 0003 — KeyHelix reference decision

**Status:** Accepted for v1

## Decision
OpenBao is the reference production KEK/Transit provider. A local development provider exists only for non-production tests and is clearly marked unsafe for production.

## Consequences
Implementation and tests must preserve this boundary. An alternative is allowed only through the relevant port/adapter when it preserves authority, public contracts, security invariants and migration semantics.

## Revisit trigger
Measured benchmark, security evidence, maintenance/licensing change or operational incident demonstrates the reference choice no longer satisfies the declared workload/threat model. Revisit via a new superseding ADR; never silently rewrite history.
