# KeyHelix — State Machines v7

- **SecretVersion:** `CREATED -> ACTIVE -> SUPERSEDED -> DESTROYED_METADATA_ONLY`
- **KeyRotation:** `PLANNED -> REWRAPPING -> VERIFYING -> COMPLETE | FAILED_ROLLBACK`
- **AccessGrant:** `PENDING -> ACTIVE -> EXPIRED | REVOKED`

Transitions are domain commands with authorization, optimistic version check where applicable, audit event and invariant tests. Illegal transitions fail closed and are observable.
