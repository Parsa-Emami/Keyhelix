# ADR 0001 — KeyHelix reference decision

**Status:** Accepted for v1

## Decision
v1 trust model is server-side envelope encryption. Client-side zero-knowledge encryption is not mixed into v1 and would require a separate major architecture.

## Consequences
Implementation and tests must preserve this boundary. An alternative is allowed only through the relevant port/adapter when it preserves authority, public contracts, security invariants and migration semantics.

## Revisit trigger
Measured benchmark, security evidence, maintenance/licensing change or operational incident demonstrates the reference choice no longer satisfies the declared workload/threat model. Revisit via a new superseding ADR; never silently rewrite history.
