# KeyHelix: reference workflow

Status: planned domain acceptance; the current JSON structure preview does not implement this workflow.

Authenticate synthetic owner -> scoped write -> fresh step-up reveal -> revoke other user -> provider outage test -> restore isolated provider from proper recovery material.

Required invariants:

- Provider owns secret bytes
- No plaintext persistence or telemetry
- Fresh step-up and provider authorization before reveal

Required UAT:

- با هویت کم‌اختیار فقط مسیر مجاز reveal شود؛ bypass و object access نامجاز شکست بخورد
- provider قطع شود؛ reveal خطا دهد و plaintext از cache برنگردد
- backup همراه کلیدهای recovery در محیط جدا restore و revoke آزمون شود

Workflow steps:

1. **Authenticate synthetic owner**: Authenticate synthetic owner (`alice@keyhelix.local`) via OIDC identity provider; establish scoped session.
2. **Scoped write**: Authorize and write scoped versioned secret envelope (`app/prod/database-url`) into target vault (`vault-prod`).
3. **Fresh step-up reveal**: Require fresh WebAuthn/step-up reauthentication and verify provider permissions before secret decryption/reveal.
4. **Revoke other user**: Revoke departing user (`bob@keyhelix.local`) and confirm immediate authorization revocation across all vault paths.
5. **Provider outage test**: Simulate provider disconnection; ensure all read/write operations fail closed and no cached plaintext is returned.
6. **Restore isolated provider**: Restore provider in an isolated test environment using recovery materials and verify data integrity.

Machine contract: `tests/scenarios/clone-to-value.json`. C01/C04 create and freeze the actual synthetic positive/negative fixture formats; no real secrets, user source/traffic/case data or unlicensed corpus. A clean source clone must reproduce the entire workflow with restart and restore at C30.
