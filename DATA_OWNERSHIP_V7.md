# KeyHelix — Data Ownership v7

- **PostgreSQL:** ciphertext envelopes, metadata, policy, audit records
- **OpenBao:** KEK/signing root operations, never DB plaintext
- **Valkey:** non-secret ephemeral rate/session data only
- **ObjectStore:** signed audit checkpoints/exports, encrypted only

## Universal rules
- cache is never authority
- derived projections have checkpoint + rebuild + staleness metric
- secrets/evidence follow project-specific retention and redaction
- deletion does not rewrite immutable audit/custody history
