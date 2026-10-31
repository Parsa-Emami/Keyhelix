# KeyHelix: clone to run

## Runnable today

Install Git, Node 24.19+ within Node 24, Go 1.26.2+ (1.26.x) and rootless Podman 4.9.3 on Linux x86_64, then:

```sh
git clone https://github.com/Parsa-Emami/Keyhelix.git
cd Keyhelix
npm run setup
npm start
```

Open http://localhost:4173 and sign in as `alice` (vault-admin) or `bob` (vault-member). Both are synthetic local identities defined in `ops/local/keycloak-realm.json`; the browser is redirected to the local Keycloak realm for the OIDC code flow, and reveal, grant changes, and key rotations require fresh step-up reauthentication.

Setup installs the committed web lockfile with lifecycle scripts disabled, builds the web shell and engine, then starts the pinned local OpenBao and Keycloak containers, initializes transit/KV and the scoped workload token, and writes `.local-data/runtime.json`. `npm start` launches the Go engine with that runtime file and supervises both processes; readiness requires storage, the key provider and the identity provider. Ctrl+C stops both.

No paid or cloud account, sibling clone or owned public domain is needed. Provider images are pulled by digest only when absent; `.local-data/` holds recovery material and must stay private and uncommitted. Ports can be selected with `npm start -- --port 4301`, but the registered OIDC redirect origin is `http://localhost:4173`.

`npm run setup -- --check` shows preparation without changes. `--skip-install` builds using already installed dependencies. `--skip-providers` prepares build artifacts only. `npm run doctor` reports actual web/core state and provider readiness. `npm run release:check` deliberately exits 2 until full C01–C38 release evidence is ready.

## Provider ownership

OpenBao owns the sealed secret bytes: the engine stores a wrapped DEK and nonce through the transit and KV mounts and persists only metadata and an integrity digest. Keycloak issues identity and step-up proofs. Readiness and `/api/diagnostics` report web, engine, storage, key provider and identity provider separately; failures are explicit and never cached into success.

## Network boundaries and private hosting

KeyHelix requires no owned public domain for local or private operation:

1. **Loopback isolation**: Both the web server (`scripts/serve-web.mjs`) and the Go BFF engine (`cmd/keyhelix`) bind strictly to loopback interfaces (`127.0.0.1`, `::1`). The engine listens on an ephemeral loopback port (`127.0.0.1:0`) and is never directly exposed to external networks.
2. **DNS rebinding defense**: The web server validates incoming `Host` headers against loopback hostnames (`localhost`, `127.0.0.1`, `[::1]`) and rejects external hosts with `400 Bad Request` (`invalid_host`).
3. **Origin boundary**: State-changing and data-access routes under `/api/*` enforce same-origin semantics; untrusted cross-origin requests are rejected with `403 Forbidden` (`cross_origin_forbidden`).
4. **Cache boundaries**: Sensitive routes (`/`, `/healthz`, `/readyz`, `/runtime-config.json`, `/api/diagnostics`, `/api/*`) emit `Cache-Control: no-store` and `Pragma: no-cache`. Fingerprinted static assets under `/assets/*` are immutable.
5. **Optional TLS / private ingress**: Operators can terminate TLS with Nginx (`ops/web/nginx.conf.template`) and proxy to loopback port `4305`, enforcing strict CIDR allowlists (`deny all` by default). See [infra/deployment.md](file:///home/amirreza/Desktop/Projects/Keyhelix/infra/deployment.md) for full deployment details.

## Checks

```sh
npm run check
npx --no-install playwright install chromium
npm run test:browser
npm run test:clone
npm run doctor
```

`npm run test:clone` proves two things separately:

1. A real transport clone of the staged/committed source, `npm run setup`, and web-only startup with disabled domain admission (`engineReady: false`).
2. The full reference workflow through `tests/browser/clone-to-value.spec.ts`: real readiness, owner sign-in, scoped write, fresh step-up reveal, transient clear, member denial, member grant creation and synchronous revocation, app restart persistence, a plaintext-at-rest scan of the engine and provider data, and OpenBao backup/restore with a reveal afterwards.

On a shared development host that already owns the fixed provider ports and has uncommitted work, use:

```sh
KEYHELIX_CLONE_WORKTREE=1 KEYHELIX_REUSE_PROVIDERS=1 KEYHELIX_CLONE_RESTORE=1 npm run test:clone
```

`KEYHELIX_CLONE_WORKTREE=1` snapshots the working tree instead of the index; `KEYHELIX_REUSE_PROVIDERS=1` seeds the clone with the existing provider recovery material; `KEYHELIX_CLONE_RESTORE=1` adds the backup/restore leg.

`local-demo` uses synthetic fixtures and isolated development providers; `local-private` requires real identity/permission, provider durability, revocation and restore evidence before sensitive use. A development provider mode never becomes a production vault/gateway by relabeling it.
