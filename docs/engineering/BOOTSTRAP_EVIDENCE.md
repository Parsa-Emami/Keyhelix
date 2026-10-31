# KeyHelix: bootstrap evidence

Status: C01–C30 local setup, engine bootstrap, and provider-backed domain workflow verified.

- `npm run setup`: Prepares the Go toolchain, validates rootless Podman, compiles the web workspace, compiles the Go engine binary into `dist/engine/keyhelix`, provisions local OpenBao and Keycloak containers, and writes `.local-data/runtime.json`.
- `npm start`: Supervises both the static web shell and the loopback Go engine from a single terminal.
- Health endpoint `/api/engine/health` and readiness `/api/engine/readiness` report `coreReady: true` when launched with `.local-data/runtime.json` (and `coreReady: false` in unconfigured foundation mode).
