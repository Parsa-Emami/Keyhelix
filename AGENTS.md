# KeyHelix: agent entry point

Read START_HERE.md, docs/agents/EXECUTION_CONTRACT.md, docs/architecture/ADR-0003-open-source-local-first.md, plans/project-state.json, plans/progress.json and plans/release-gates.json. Actual code/tests and source-bound evidence determine capability. legacy/v7 and *_V7.md are historical; do not run their bootstrap or revive compulsory services.

## Local team skills

Team-owned copies live in `.agents/skills/<name>/SKILL.md`. They are vendored unchanged from `addyosmani/agent-skills` under MIT; provenance and hashes are in `.agents/skills/SOURCES.md`. Read only the skills the task needs, starting with `using-agent-skills` when routing is unclear; do not preload the whole directory.

| Task | Read first |
| --- | --- |
| Route an unclear task or break down large work | `using-agent-skills`, `planning-and-task-breakdown` |
| Recover context, write a handoff, reduce context cost | `context-engineering` |
| Implement a vertical slice or multi-file change | `incremental-implementation`, `test-driven-development` |
| Design or change an API, module boundary or public shape | `api-and-interface-design` |
| Build or change UI, accessibility or responsive layout | `frontend-ui-engineering` |
| Verify a framework, library, version or external API | `source-driven-development` |
| Diagnose a failing test, build or runtime behavior | `debugging-and-error-recovery` |
| Touch auth, storage, secrets, untrusted input or dependencies | `security-and-hardening` |
| Review a change before completion | `code-review-and-quality` |
| Simplify code without changing behavior | `code-simplification` |
| Measure or improve performance | `performance-optimization` |
| Add logs, metrics, readiness or diagnostics | `observability-and-instrumentation` |
| Write an ADR, document a decision or update evidence | `documentation-and-adrs` |
| Commit, branch, review a PR or release | `git-workflow-and-versioning` |
| Change a CI workflow or quality gate | `ci-cd-and-automation` |

Precedence when instructions overlap: this file, `docs/agents/EXECUTION_CONTRACT.md`, the current `plans/commits/Cxx.md` card and the permanent owner restrictions come first; repository source/contracts/tests come next; a local skill is guidance after those. A skill never authorizes a protected-file change, a commit/push, an external service, or invented evidence. Project-specific commands, versions and paths override generic examples in a skill. This repository is Go 1.26 plus React 19/TypeScript/Vite with plain CSS and Node 24.19; do not import Tailwind, shadcn, Next.js, Vercel or cloud examples unless the approved task explicitly requires them.

Use progressive disclosure: read a skill's `SKILL.md`, then only the reference or script it points to when that material is actually needed. Shared companion checklists live in `.agents/references/`; the repository's own definition-of-done, evidence rules and task cards still take precedence.

Quality guardrails for every task: inspect the relevant architecture, contracts, source and tests before editing; verify APIs and versions against current official sources and cite them; make the smallest correct change and reuse existing patterns; add no unrequested dependency, abstraction or configuration; reject generic AI UI, placeholder success and mock-only durability/auth evidence; run the task's real positive, negative and recovery checks and report any unrun or failing check honestly. Do not commit or push without explicit approval.

1. Inspect Git status, current source/manifests/locks/tests/CI and preserve other work.
2. Run npm run validate:plan and npm run plan -- next; read the returned plans/commits/Cxx.md in full. Complete only unmet dependency-ready criteria.
3. Follow its exact targets, implementation actions, resources, fixtures, negative cases and current/future command labels. Domain belongs in the selected engine, UI in apps/web and adapters at boundaries. No sibling repository imports.
4. Implement a real vertical slice and meaningful regressions. A static example, generic JSON preview, successful placeholder endpoint or mocked durability/auth cannot replace the product feature.
5. Run actual relevant checks, record exact source/tool/provider/fixture identities and command exits/output; update only genuinely verified progress and session handoff. W evidence never certifies a C task.
6. C30 needs full clean-host core workflow/restart/restore. C40 needs authorized published source/artifacts and installed full-workflow proof.

Permanent owner restrictions: do not modify database schemas, migrations, .env files or Dockerfiles. Use compatible ADR-0003 adapters; record a precise blocker if a protected change is unavoidable and continue independent authorized work. Preserve existing code including RiskWeft's optional API, and fix observed CI defects without disabling checks or adding broad analysis ignores.

All core features remain open source with no required paid/cloud account, public domain or sibling clone. Pin compatible upstream licenses/provenance. Never invent versions, tests, customer feedback, deployment or release claims. Routine reversible authorized work needs no repeated approval; a planned task title does not authorize destructive data actions or publication. Implementation guidance and UI are English, with Persian overview in docs/ROADMAP_FA.md. There is no requirement to spawn subagents.
