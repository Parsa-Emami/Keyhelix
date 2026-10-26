# Local agent skills: provenance and integrity

These directories are unmodified vendored copies of the MIT-licensed
[`addyosmani/agent-skills`](https://github.com/addyosmani/agent-skills) collection.
The upstream license text is in [LICENSE](LICENSE). The copies were taken from
the user-level installation on 2026-10-26 and are committed with the repository so
the team does not depend on a global installation.

- Do not edit a vendored `SKILL.md` or its references.
- Update by deliberately re-vendoring the upstream skill, then re-record its hashes.
- No symlinks or absolute home-directory paths are used.

## Selected skills

| Local skill | Upstream path | Installed folder hash | Local `SKILL.md` SHA-256 |
| --- | --- | --- | --- |
| `using-agent-skills` | `skills/using-agent-skills/SKILL.md` | `81e8196f4dd4bf9fc5f0a1b827f4148af52a4391` | `30787ef2c77bf1a4729fffed0f6523ba6fcbe81bdc436b36371b78c21394d3c3` |
| `context-engineering` | `skills/context-engineering/SKILL.md` | `5da63415256218e76f85e7e371bb21ceef4293e1` | `8b736cb9e55b82b265ab6ff78349c0e826e8a6df550deddf665b7fb3ff858b63` |
| `planning-and-task-breakdown` | `skills/planning-and-task-breakdown/SKILL.md` | `3045f95a156dc71d7b5ac1e29ce795bb5cac2b71` | `ed0f90cc5951ddd4bcab7f871f64efec93a49af9279ef93bc470da77ad8da3f7` |
| `incremental-implementation` | `skills/incremental-implementation/SKILL.md` | `a3e2fab3e3b97e078e2404a505c4b2fa5e123c9b` | `df66536610071727feae1ca95f3c391c248ad828041750ccd3699cce763aa00b` |
| `source-driven-development` | `skills/source-driven-development/SKILL.md` | `29e1dcc180d54898aa7c5f4c466864c59ac2ee41` | `c59faf851377f0eeda45306398d16eb96d77ab1c2fd3e1a7fb58e9a0af33c1e9` |
| `test-driven-development` | `skills/test-driven-development/SKILL.md` | `b812b07dc0c5084dbffe58a1cc856de2fdd99116` | `7c0c6ac057c19d7f8be65d9f49c3a638703b868f4625c78b70da5439d5d74fca` |
| `debugging-and-error-recovery` | `skills/debugging-and-error-recovery/SKILL.md` | `c3b5c340bae3ac952733213b40035820acfb48a3` | `21f3960f5d7ae2cc95c40896545004dbbcbbd752ea65fc2d53962554d4174220` |
| `api-and-interface-design` | `skills/api-and-interface-design/SKILL.md` | `f7eefe1133c8540d00f279a171053cc9551ec5c4` | `5dafd0c44a3aabf11cae5bcb34f6fcc24dfa5c01ba6e0d3176bce997f4d68bc8` |
| `frontend-ui-engineering` | `skills/frontend-ui-engineering/SKILL.md` | `8fdd24f2b93c198e4973f4008d694929a6082406` | `549044e9bd8d7fe993ce8e5c0d2b0f5465650676dc15805329973f936179eb1e` |
| `security-and-hardening` | `skills/security-and-hardening/SKILL.md` | `79b5adb3e84ab5934e3d4b893f9de8fc7b11ffdb` | `2e3fc60eed5aba97fe416f3f3c9317fdb014a682925ec70a733c3ff99e4b9858` |
| `code-review-and-quality` | `skills/code-review-and-quality/SKILL.md` | `8c26aef07c0ac94770d48ed68e72c0fd585420a6` | `8f3cabca581bbf7cb5f0add3f7454e7a4523f9d4353a6a4a217e6fa515309612` |
| `code-simplification` | `skills/code-simplification/SKILL.md` | `15b6e21924188ee46402a8c91963162fd9056c7d` | `f0c5ed754057eb0c1e027e2587f59de816651feb5e837242296c43ea21cf621d` |
| `performance-optimization` | `skills/performance-optimization/SKILL.md` | `d7cc0bec423819ebe153ec70177caaec4bad3fea` | `00694d0c69bbde674d0e39de24052d90afea32d9fef9553eaee21a50a7e9b8cf` |
| `observability-and-instrumentation` | `skills/observability-and-instrumentation/SKILL.md` | `1e8f1c0144e2b8f7859f5870329a31f8abc58193` | `e7fcb0820306d46268de9594d676ad98e35040858926c412b7000faa52a61f87` |
| `documentation-and-adrs` | `skills/documentation-and-adrs/SKILL.md` | `eeff83d93dd39454d0b9d193ba3ea5c85f681530` | `87ae44a0c7bb3eefc2131a9d11caabcc14e4d8dcb27d66a3a675551ee2ce1671` |
| `git-workflow-and-versioning` | `skills/git-workflow-and-versioning/SKILL.md` | `92d87ae1fe98e6b67403bace2ef01264f9664468` | `b7465d187935c52546d39fdc7bd6ac36d94eda25a9500ef8c18b767d2eb116ea` |
| `ci-cd-and-automation` | `skills/ci-cd-and-automation/SKILL.md` | `34db321777a17e268ac425f0f7f2501dda55c955` | `a6ed8ed56456b01ff8314c44eefc69897d9905ae4e06bb2b7036286efb79b5f0` |

The folder hash is the installer lock's upstream skill-folder identifier, not a
commit SHA. The local hash is the integrity value for the vendored copy.

## Shared companion references

Six collection-level references linked by the selected skills were absent from
the installer snapshot. They are vendored unmodified from upstream commit
`aeac41d4d005999432bb7312f7ff06383a91d59d` under the same MIT license at the
relative location the skills expect: `.agents/references/`. They may be newer
than the installed skill snapshot; the links and copies are validated here, and
the repository's own definition-of-done, evidence rules and task cards still take
precedence.

| Local reference | Upstream path | Local SHA-256 |
| --- | --- | --- |
| `accessibility-checklist.md` | `references/accessibility-checklist.md` | `61c759d94d52296231f5f310b92b401f56c44e4430dc3cc95ebac5d7b1d5ffac` |
| `definition-of-done.md` | `references/definition-of-done.md` | `d1c75d2ae65d2c7a9cd01f93fa8de63e00e75f2fe5d08be224d576157054dcee` |
| `observability-checklist.md` | `references/observability-checklist.md` | `25fcd0e854596a5ab6f11b002050d245bf78f5ae0fcbd1df699b89451ae0e1e8` |
| `performance-checklist.md` | `references/performance-checklist.md` | `fffc38b8f3b328a973aab8b1a2efdd72b65710d8f4b57f28f8374ddae7f8a88b` |
| `security-checklist.md` | `references/security-checklist.md` | `37774056502fe8970dcd2fd27dca5fa31f2a55232649fc3056c89c3af7d62755` |
| `testing-patterns.md` | `references/testing-patterns.md` | `f0bf05acd0edcadc27297ad5b74f104c8103ccfedba1a05cd6d6ae4af8364c56` |

`security-and-hardening/references/hardening-patterns.md` is part of that
skill's own directory; its links to the collection-level security checklist now
resolve through `.agents/references/`.
