# KeyHelix acceptance gate

All scenarios are unexecuted in v0. Use synthetic or explicitly authorized owned data.

1. با هویت کم‌اختیار فقط مسیر مجاز reveal شود؛ bypass و object access نامجاز شکست بخورد
2. provider قطع شود؛ reveal خطا دهد و plaintext از cache برنگردد
3. backup همراه کلیدهای recovery در محیط جدا restore و revoke آزمون شود

Also require negative input/auth tests, crash or interrupted operation, clean install/upgrade, export/restore and workload bounds. Claims must match selected private/public distribution profile.
