# KeyHelix web runbook

## Local checkout

Use Node 24.19.0 and npm 11.9.0 from the tested toolchain. From the repository root:

```sh
npm ci --ignore-scripts
npm run check
npx --no-install playwright install chromium
npm run test:browser
npm run dev
```

Browser checks may use an operator-provided Chromium executable through the `WEB_TEST_CHROMIUM` process variable. CI uses the Playwright-managed browser. This test override never changes application configuration.

Development URL: http://127.0.0.1:5173. To run the built shell separately:

```sh
npm run build
npm start -- --port 4305
```

Built URL: http://127.0.0.1:4305. The unified supervisor (`scripts/start-local.mjs`, invoked by `npm start`) launches both the web shell and the loopback Go engine from a single terminal, exposing engine health at `/api/engine/health`. No secondary terminal is required. Browser routing uses hashes and hosting at the origin root. There is no subpath deployment in this release. Change the public nonsecret configuration in `ops/web/runtime-config.json`; `apps/web/public/runtime-config.json` must mirror it for static hosts/development. The Node server validates its config at startup and the browser validates its own project identity. Do not put credentials in either file.

## What is runnable

The responsive React workspace (`Vaults`, `Reveal`, `Access & Rotations`, `Workspace`, `Roadmap`), forty-step product roadmap, local bounded JSON structure preview, Node static/proxy server, and Go BFF engine integration are implemented. JSON preview uses tab memory, does not persist files and does not send them to the server; reload clears the preview. The PWA manifest supplies install metadata; there is no service worker or offline claim. Cache rules retain only fingerprinted static assets; HTML, runtime configuration, and reveal/API responses are `no-store`.

`GET /healthz` covers the web process; `GET /readyz` covers web assets, startup configuration, and (when `.local-data/runtime.json` is active) engine, storage, key provider, and identity provider readiness. `/api` and all `/api/` routes return 503 when the engine is unavailable or launched in unconfigured foundation mode. Engine admission cannot be enabled by a public config flag.

## Build a complete artifact

```sh
npm run package
cd dist/release
sha256sum -c SHA256SUMS.txt
node dist/engine/keyhelix --version
```

The package contains the real Go engine, the built web UI, offline contracts/rules references, provider templates, source archive and build recipes, the CycloneDX SBOM, complete notices and provenance. `RELEASE.json` records the source commit, dirty/clean state, tree digest, engine/toolchain versions and capability flags. Build from a clean commit for a releasable provenance record. Node serving of the built UI needs no installed npm dependencies; provider containers are not embedded.

To serve only the packaged web shell for a transport check:

```sh
node scripts/serve-web.mjs --root web --port 4305 --config ops/web/runtime-config.json
```

For the complete local workflow, the engine needs the operator-owned runtime file produced by `npm run setup` (or an equivalent private file). From the artifact root:

```sh
node scripts/start-local.mjs --host 127.0.0.1 --port 4305 --root web \
  --config ops/web/runtime-config.json --runtime /path/to/private/runtime.json --providers reuse
```

`--providers reuse` never starts or changes provider containers. Keep the runtime file outside the artifact, mode `0600`, and never commit it. `npm run test:release` verifies the packaged engine/web pair, checksums, inventories, exclusions, replay and crash/quota recovery. CI uploads the complete artifact; it does not publish a host or modify repository settings. Copy the complete `dist/release` tree to the chosen immutable release directory.

## Private Linux host

Prerequisites: operator-owned domain/DNS, valid TLS certificate/key, installed Node 24.19.0, Nginx, systemd, an unprivileged `keyhelix-web` account, and already-running pinned OpenBao and Keycloak services. Go/npm are not required to install a prebuilt complete release. Reserve port 4305 for this project. Keep certificates and runtime credentials outside the artifact and never commit either. Install releases under `/srv/keyhelix/releases/<release-id>` and point `/srv/keyhelix/current` to the selected verified release. Ensure the service user has read/execute access to artifact directories. Match the actual Node binary path in the service file.

Create the private runtime file at `/etc/keyhelix/runtime.json` (mode `0600`, owned by the service user) from the local provider workflow or an equivalent private configuration. It must contain the supported `local` profile and provider references; set `engine.data_dir` to an absolute persistent path such as `/var/lib/keyhelix/engine`. It is intentionally not part of the artifact and must never appear in `RELEASE.json`, logs or source control.

Use `ops/web/service.systemd` and render `ops/web/nginx.conf.template` with the real owned domain, TLS paths and reviewed operator network ranges. The service launches the packaged engine and web server together with `--providers reuse`; it does not provision or change provider containers. The proxy initially denies external traffic. Keep the deny-all default until private admission is configured and tested; do not treat an IP range as per-user authentication. Validate the rendered Nginx configuration with `nginx -t` before reload. Install the service under `/etc/systemd/system/keyhelix-web.service`, then run:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now keyhelix-web
curl --fail http://127.0.0.1:4305/healthz
curl --fail http://127.0.0.1:4305/readyz
sudo journalctl -u keyhelix-web --since '10 minutes ago'
```

`/readyz` is composed: it must report web plus engine, storage, key-provider and identity-provider readiness. A web-only 200 is not a complete service check. Test HTTPS access from an allowed operator and rejection from a disallowed network. No domain, certificate, host or credentials were provisioned by the source commit; C40 owns installed-host proof.

## Update and rollback

Build/test/package from a clean source commit; verify SHA256SUMS and `RELEASE.json` before switching the current symlink. Retain the previous immutable release directory; switch the symlink and restart the service in a maintenance window. Check `/healthz`, `/readyz` (including engine, storage, provider and identity readiness) and browser navigation. If any fails, restore the previous symlink and restart. The local `dist/release.previous` directory is only a convenience for the build host, not a replacement for immutable deployed releases. A frontend rollback does not roll back engine or provider data; always verify OpenBao recovery material and the storage port before updates.

## Engine integration and operations

Profile: `private-web` / `local`. Active engine choices: Go BFF (`cmd/keyhelix`, `internal/app`), OpenBao KV v2 & Transit, single-writer local storage port (`internal/storage`), React UI (`apps/web`), and OIDC identity provider (Keycloak). Route only explicitly supported endpoints through the same-origin authenticated BFF. Keep secrets exclusively on the provider. Public marketing/static demonstrations must use synthetic data; they cannot admit arbitrary runtime work.

For KeyHelix, no plaintext secrets may enter browser file preview; import only synthetic nonsecret metadata.

## Reproduce source evidence

Run `python3 scripts/source_identity.py --check` against the committed checkout. The digest covers tracked and deliverable untracked files, excluding only the self-referential evidence JSON and SHA256SUMS.txt. Build/test output directories are ignored.
