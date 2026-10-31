# Continue KeyHelix

Current: C01–C31 core domain engine, OpenBao/Keycloak local provider integration, React web workspace and complete reproducible release artifact implemented (`core_ready: true`). Tasks C32–C40 remain for OSS v1 publication and installed-host proof.

```sh
npm run setup
npm start
```

Open http://localhost:4173. Read docs/engineering/CLONE_TO_RUN.md for actual prerequisites and capability. For implementation read AGENTS.md, docs/agents/EXECUTION_CONTRACT.md and ROADMAP.md, then use:

```sh
npm run validate:plan
npm run plan -- status
npm run plan -- next
```

Each task links exact work/resources/tests. C30 is first actual local usability and C40 full OSS v1; both require evidence. Do not run historical bootstrap or modify protected files.
