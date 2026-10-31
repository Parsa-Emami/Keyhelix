# KeyHelix

[![Source](https://github.com/Parsa-Emami/Keyhelix/actions/workflows/contracts.yml/badge.svg?branch=main)](https://github.com/Parsa-Emami/Keyhelix/actions/workflows/contracts.yml?query=branch%3Amain) [![Plan](https://github.com/Parsa-Emami/Keyhelix/actions/workflows/plan.yml/badge.svg?branch=main)](https://github.com/Parsa-Emami/Keyhelix/actions/workflows/plan.yml?query=branch%3Amain) [![Web](https://github.com/Parsa-Emami/Keyhelix/actions/workflows/web.yml/badge.svg?branch=main)](https://github.com/Parsa-Emami/Keyhelix/actions/workflows/web.yml?query=branch%3Amain)

[CI source integrity and dependency updates](docs/engineering/CI_SOURCE_INTEGRITY.md)

Open-source local-first secret management and cryptographic authorization workspace under [Apache-2.0](LICENSE). **Current implementation: C01–C30 core engine, provider integration, and web workspace implemented; C31–C40 OSS release packaging in progress.**

## Clone and run the local workspace

Prerequisites: Git, Node 24.19+ within Node 24 (npm included), Go 1.26.2+, and rootless Podman 4.9.3 on Linux x86_64.

```sh
git clone https://github.com/Parsa-Emami/Keyhelix.git
cd Keyhelix
npm run setup
npm start
```

Open http://localhost:4173. Features include OIDC authentication and fresh step-up elevation via local Keycloak, provider-owned envelope encryption via OpenBao Transit & KV v2, versioned secret metadata management (`Vaults`), soft-delete/restore/destroy lifecycle, strict audited transient reveal (`Reveal`), member access grants and synchronous revocation (`Access & Rotations`), resumable KEK rotation, roadmap browser, and bounded local JSON structure preview. [Clone guide](docs/engineering/CLONE_TO_RUN.md).

## Full product endpoint

Authenticate synthetic owner -> scoped write -> fresh step-up reveal -> grant & revoke other user -> provider outage test -> restore isolated provider from proper recovery material.

[C30](plans/commits/C30.md) proves the locally usable supported product from a clone, including restart/restore. [C40](plans/commits/C40.md) proves complete published OSS v1. [Runtime resources](ops/runtime-requirements.json).

## Implement the next commit

```sh
npm run plan -- status
npm run plan -- next
npm run plan -- show C31
npm run check
```

Each [work card](plans/COMMIT_ROADMAP.md) specifies paths, actions, resources, fixtures, acceptance, negative tests, command availability and rollback. [AGENTS.md](AGENTS.md) and [execution contract](docs/agents/EXECUTION_CONTRACT.md) let an agent resume from this repository alone. [فارسی](docs/ROADMAP_FA.md).

[Open-source contract](OPEN_SOURCE.md) · [Contributing](CONTRIBUTING.md) · [Third-party inventory](THIRD_PARTY_NOTICES.md) · [Definition of done](docs/release/DEFINITION_OF_DONE.md) · [Security](SECURITY.md). No DB schema, migration, .env or Dockerfile changes are authorized.
