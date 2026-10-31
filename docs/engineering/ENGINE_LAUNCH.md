# KeyHelix: engine launch and local supervisor

The KeyHelix local supervisor (`scripts/start-local.mjs`, invoked by `npm start`) launches both the loopback Go engine and the local web server from a single terminal command.

## Architecture

```
                  +-----------------------------------+
                  |  scripts/start-local.mjs          |
                  |  (Local Process Supervisor)       |
                  +--------+-----------------+--------+
                           |                 |
                spawns & supervises          | launches
                           |                 |
                           v                 v
                 +-------------------+  +-----------------------+
                 | cmd/keyhelix      |  | scripts/serve-web.mjs |
                 | (Go Engine)       |  | (Web Server)          |
                 | 127.0.0.1:EPHEM   |  | 127.0.0.1:4173        |
                 +-------------------+  +-----------------------+
                           ^                 |
                           | reverse proxies |
                           +-----------------+
                     /api/engine/*, /api/v1/*, /api/vaults/*
```

## Security & Isolation
- **Loopback binding only:** The engine binds exclusively to `127.0.0.1:0` (ephemeral loopback port) or an explicitly configured loopback interface. Non-loopback bindings fail closed.
- **IPC Handshake:** On startup, the engine writes its assigned loopback port and PID as a JSON payload to stdout. The supervisor verifies this handshake before initiating web serving.
- **Fail-Closed Shutdown:** Stdin of the engine is owned by the supervisor pipe. If the supervisor terminates or receives SIGINT/SIGTERM, the engine detects EOF and initiates graceful HTTP shutdown within 5 seconds.
- **Composed vs. Foundation Mode:** When `.local-data/runtime.json` is present (after `npm run setup`), the supervisor passes `--config .local-data/runtime.json` to `cmd/keyhelix`, enabling full OpenBao, Keycloak, and durable storage composition (`coreReady: true`). When launched without `--config` (foundation mode), `/healthz` reports `coreReady: false` and domain secret APIs return 503 `engine_not_integrated`.
