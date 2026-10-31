# KeyHelix roadmap

[Forty detailed work cards](plans/COMMIT_ROADMAP.md): exact targets, work, dependencies, resources, negative tests, command availability, proof and rollback.

- Current: C01–C31 verified (`core_ready: true`); Go BFF engine, durable storage port, OpenBao & Keycloak integration, web workspace (`Vaults`, `Reveal`, `Access & Rotations`, `Workspace`, `Roadmap`) and complete release packaging are active.
- C30: locally usable complete reference workflow/restart/restore on a supported host.
- C31: complete reproducible local artifact with engine, web UI, offline resources, source archive, SBOM, notices, checksums and provenance.
- C40: complete verified and published open-source v1, installed from actual artifacts.

[Clone guide](docs/engineering/CLONE_TO_RUN.md) · [Agent contract](AGENTS.md) · [Definition of done](docs/release/DEFINITION_OF_DONE.md) · [فارسی](docs/ROADMAP_FA.md).

```sh
npm run plan -- status
npm run plan -- next
npm run plan -- show C32
```
