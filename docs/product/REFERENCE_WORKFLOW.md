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

Machine contract: tests/scenarios/clone-to-value.json. C01/C04 create and freeze the actual synthetic positive/negative fixture formats; no real secrets, user source/traffic/case data or unlicensed corpus. A clean source clone must reproduce the entire workflow with restart and restore at C30.
