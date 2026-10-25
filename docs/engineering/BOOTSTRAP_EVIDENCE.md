# KeyHelix: bootstrap evidence

Status: C03 local setup and engine bootstrap verified.

- `npm run setup`: Prepares the locked Go toolchain, validates rootless Podman, compiles the web workspace, and compiles the Go engine binary into `dist/engine/keyhelix`.
- `npm start`: Supervises both the static web shell and the loopback Go engine from a single terminal.
- Health endpoint `/api/engine/health` validated on `127.0.0.1` loopback with `coreReady: false`.
