# KeyHelix product requirements v0

Status: planning; application source not implemented. English-facing app/docs are the release default. See Persian assessment for commercial hypotheses.

Target user: توسعه‌دهندهٔ مستقل و تیم کوچک با OpenBao

Job to complete: کنسول سادهٔ secret workflow روی provider معتبر

Differentiation hypothesis: UX کنترل دسترسی، audit و recovery روی OpenBao؛ بدون رمزنگاری سفارشی

## MVP acceptance scope

- یک OpenBao خصوصی با KV v2 و storage پایدار
- Go BFF و UI بدون persistence اسرار در مرورگر
- step-up برای reveal و تغییر policy
- audit و backup/restore provider

## Excluded until another decision

- ارائهٔ عمومی vault چندمستاجری
- envelope encryption سفارشی v7
- zero knowledge vault
- dynamic secret integrations گسترده

## End-to-end outcomes

1. با هویت کم‌اختیار فقط مسیر مجاز reveal شود؛ bypass و object access نامجاز شکست بخورد
2. provider قطع شود؛ reveal خطا دهد و plaintext از cache برنگردد
3. backup همراه کلیدهای recovery در محیط جدا restore و revoke آزمون شود

Functional requirements F01–F20 and nonfunctional/release requirements are mapped one-to-one in `plans/requirements.json`. Tests belong with their feature commit, not postponed until launch. Success: a clean installed selected profile performs the core task and recovers from documented failures. Public demand remains unvalidated until real trials are recorded.

## UI flow

Select/import scoped input -> validate limits and permission -> show actual processing state -> explain result and confidence -> review/triage where appropriate -> export -> recover in clean environment. Loading, empty, stale, partial, unauthorized, rejected input, timeout/cancel and permanent failure are explicit. Provide table/keyboard alternatives to canvas, charts and graph paths. No sensitive content in page telemetry.
