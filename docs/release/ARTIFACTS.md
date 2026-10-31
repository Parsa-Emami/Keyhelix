# KeyHelix release artifacts

Status: C31 verified the complete local artifact build and failure semantics.
Publication, signatures and an installed-host workflow are C39/C40 work; this
document does not claim that a release has been published.

## Complete artifact, not a web-only shell

`docker` is not used and no database schema is created. A release contains the
compiled Go engine, the built React web application, offline contracts/rules
references, provider templates, the matching source archive, build recipes, a
CycloneDX SBOM, complete third-party notices, SHA-256 checksums and provenance.

The authorization rules are compiled into the Go engine. The portable offline
rule/resource set is the API and event contract set under `contracts/`, the
authorization matrix and related specifications under `spec/`, and the pinned
provider/toolchain resources under `ops/` and `docs/engineering/`. `RESOURCES.json`
inventories every one of those files with its SHA-256 digest.

## Prerequisites

- Git checkout with history, Node 24.19+ within Node 24, and the pinned Go
  toolchain resolved by `npm run build` (Go 1.27.2 at C31).
- No installed npm dependencies are needed to serve the built web UI with
  `node scripts/serve-web.mjs`; provider containers are not embedded.

## Build

From the repository root:

```sh
npm run package
```

The command builds the engine and web UI (unless
`KEYHELIX_PACKAGE_SKIP_BUILD=1` is set after an already verified build), stages
the complete tree, creates the source archive, SBOM, notices, provenance and
checksums, verifies them, and only then atomically publishes `dist/release`.

`KEYHELIX_RELEASE_DIR` selects a different destination for isolated tests.
`npm run package:web` is a compatibility alias for the complete package; the
older web-only behavior is no longer a release path.

## Layout

```text
dist/release/
├── RELEASE.json
├── SHA256SUMS.txt
├── README.md
├── LICENSE
├── NOTICE
├── THIRD_PARTY_NOTICES.md
├── RESOURCES.json
├── web/                       built browser application
├── dist/engine/keyhelix       compiled engine (executable)
├── scripts/                   serve-web, start-local, providers, verify-providers
├── apps/web/src/lib/runtime-config.mjs
├── ops/                       web config/templates and local provider resources
├── contracts/                 API, event, input, result and config schemas
├── spec/                      domain rules, authorization matrix and operations specs
├── docs/                      artifact, runbook, clone and workflow documentation
├── source/keyhelix-<short>.tar.gz
├── sbom/keyhelix-<version>.cdx.json
└── notices/licenses/          complete texts for distributed npm components
```

The previous complete release is retained as `dist/release.previous` for local
rollback. Deployments should copy each verified release to an immutable
directory instead of writing state into the artifact tree.

## Verify

```sh
cd dist/release
sha256sum -c SHA256SUMS.txt
node dist/engine/keyhelix --version
```

`RELEASE.json` records the source commit, dirty/clean state, source tree digest,
source archive digest, build tool versions, engine version/toolchain, provider
image digests, SBOM/notices/resource digests and explicit capability flags.
`artifact.webOnly` must be `false`, `artifact.engineIncluded` must be `true`, and
`artifact.providerOwnedSecretBytes` must be `true`.

`npm run test:release` exercises the packaged engine and web server, verifies all
checksums and inventories, proves the secret/provider exclusion, and repeats the
build for byte-for-byte reproducibility on the recorded host. It also kills the
writer before publication, exhausts a real file-size limit, replays the build and
runs two writers concurrently; the prior or new release must always remain
complete and no partial artifact may be published.

## SBOM and notices

`sbom/keyhelix-<version>.cdx.json` is CycloneDX 1.5 JSON. It contains every npm
lockfile component (distributed runtime components are `required`; build/test
dependencies are `excluded`) and the OpenBao and Keycloak containers by immutable
digest. The two provider images are external services and their blobs are not
embedded.

`THIRD_PARTY_NOTICES.md` is generated from the committed npm and provider locks;
`npm test` rejects a stale checked-in inventory. Complete license texts for the
distributed npm runtime components are copied into `notices/licenses/`. Provider
license URLs and digests are recorded in the notices. Unknown, missing or
restricted licenses stop packaging before publication.

## Security and provider ownership

Packaging copies only an explicit runtime/resource allowlist. It rejects
symlinks, `.local-data`, provider state, `node_modules`, environment files,
private-key extensions, runtime/init files and secret-looking content (private
keys, OpenBao tokens, session tokens and bearer credentials). OpenBao and
Keycloak always own secret bytes; no provider data, token or plaintext is
embedded. The packaged engine can be booted without provider configuration for a
liveness check, but domain readiness still requires the pinned providers and an
operator-owned runtime file outside the artifact.

## Reproducibility limits

The source archive uses a sorted file list, the source commit timestamp and
normalized archive metadata. `gzip -n` semantics and `-buildvcs=false` prevent
wall-clock/VCS variability. It contains the tracked/untracked source and build
recipes, but excludes dependency/build/cache/runtime directories, secret-named
files and `docs/evidence/` release records, so evidence can be written after a
release without rewriting the artifact. Two consecutive package runs from the same source
and toolchain produce identical checksums. Cross-host byte identity, code
signing and publication are not claimed by C31.

A source tree with uncommitted changes is recorded as `dirty: true`; the tree
digest remains authoritative for that build. Rebuild from a clean commit before
publishing. `RELEASE.json` never hides a dirty tree.

## Update and rollback

Build and test from the intended source commit, verify every checksum, copy the
new release to an immutable directory, then switch the service path and restart.
Check `/healthz` and `/readyz`. If either fails, restore the previous immutable
directory and restart. A frontend rollback does not roll back provider or
metadata state; verify OpenBao recovery material and the storage port before any
update that touches durable data.

## Not performed here

- No public domain, signature, registry publication or artifact upload is made.
- No host service is installed, no Nginx/systemd unit is enabled, and no
  provider workflow is run from an installed artifact; C40 owns that proof.
- Cross-host reproducibility and multi-tenant/public runtime admission are
  outside this local profile.
