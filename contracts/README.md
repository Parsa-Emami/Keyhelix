# Contract authority — KeyHelix v1

`input.schema.json` and `result.schema.json` freeze the v1 domain contract for secret metadata inputs and engine validation results.

## Schemas
- `input.schema.json` (`urn:parsa:keyhelix:input:1`): Strict schema for secret envelope metadata. Enforces exact fields (`schema_version: "1"`, `vault_id`, `secret_id`, `secret_path`, `version`, `classification`, `created_at`, `envelope`), UTF-8 size limit (<=8192 bytes), and prohibits unexpected fields.
- `result.schema.json` (`urn:parsa:keyhelix:result:1`): Strict schema for deterministic engine validation results, returning `status: "unverified"` on valid inputs, or `status: "failed"` with typed error codes.

## Guarantees & Non-Claims
- Successful validation verifies syntactic and schema correctness only; it does not grant authorization, persist records, or prove provider key custody.
- Plaintext secrets never enter metadata contracts.
