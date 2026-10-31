# KeyHelix Open-Source Contract

KeyHelix is free and open-source software developed to provide sovereign, local-first cryptographic authorization and secret management without commercial tollbooths, mandatory cloud accounts, or proprietary subscriptions.

---

## 1. Project License

KeyHelix source code, build scripts, tests, and documentation are licensed under the **Apache License, Version 2.0** ([LICENSE](LICENSE)).

- You are free to inspect, run, modify, redistribute, and operate KeyHelix for personal, educational, research, and commercial purposes in accordance with Apache-2.0 terms.
- `package.json` specifies `"private": true` exclusively to prevent accidental publication of the internal web workspace package to the public npm registry; it does not restrict open-source inspection or redistribution.

---

## 2. Zero Paid or Cloud Entitlements Guarantee

1. **No Cloud Account Prerequisite**:
   KeyHelix requires no AWS, Google Cloud, Azure, HashiCorp Cloud Platform, or proprietary SaaS account to build, run, test, or operate its complete feature set.
2. **Local-First Core**:
   All core capabilities—including OIDC identity flows, transit envelope encryption, key rotation, member grant management, and persistent metadata storage—run locally using rootless Podman containers ([OpenBao](https://openbao.org/) and [Keycloak](https://www.keycloak.org/)) and the local Go engine.
3. **No Mandatory Public Domain**:
   Operation binds strictly to loopback interfaces (`127.0.0.1`, `::1`). Operators do not need to register, purchase, or configure a public DNS domain or external TLS certificate.
4. **No Sibling Repository Requirements**:
   KeyHelix is entirely self-contained. No closed-source, proprietary, or private companion repositories are required for full execution.

---

## 3. Upstream Dependency & Licensing Inventory

All integrated upstream components, tools, and libraries retain their respective open-source licenses and are inventoried in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md):

| Component | Upstream Project | License | Purpose |
| --- | --- | --- | --- |
| **Go Engine** | Go standard library | BSD-3-Clause | Core BFF service & provider orchestration |
| **Web Shell** | React 19 / TypeScript | MIT | Accessible web user interface |
| **Build Tools** | Vite / Node.js | MIT | Frontend asset bundling and development server |
| **Key Provider** | OpenBao | MPL-2.0 | Cryptographic envelope encryption and key storage |
| **Identity Provider** | Keycloak | Apache-2.0 | Local OIDC authentication and step-up elevation |
| **Test Framework** | Playwright | Apache-2.0 | End-to-end browser and accessibility validation |

**Strict Upstream Invariant**: No unknown, restricted, or proprietary dependency may silently become a required core component of KeyHelix. Any change to dependencies must maintain strict compliance with Apache-2.0 distribution.

---

## 4. Data Sovereignty and Privacy

- **Operator Custody**: All secret keys, authorization policies, and encrypted records remain under the operator's absolute control on their local machine.
- **Provider Ownership**: Secret payload bytes are stored solely within the encrypted OpenBao container volume. The KeyHelix engine retains only cryptographic metadata envelopes and digests.
- **Strict Zero-Telemetry**: KeyHelix contains no tracking code, telemetry collection, or remote telemetry transmission. It runs fully air-gapped without outbound internet connectivity after initial setup.

---

## 5. Commercial and Hosted Adapters Policy

While optional enterprise or cloud adapters (e.g. cloud HSM integrations or external identity bridges) may be introduced in future extended profiles, they **must never gate or diminish the capabilities of the open-source local-first core**. The local-first profile remains permanently free and fully functional.

---

## 6. Project Links

- **User Guide**: [docs/release/USER_GUIDE.md](docs/release/USER_GUIDE.md)
- **Clone-to-Run**: [docs/engineering/CLONE_TO_RUN.md](docs/engineering/CLONE_TO_RUN.md)
- **Contributing**: [CONTRIBUTING.md](CONTRIBUTING.md)
- **Security Policy**: [SECURITY.md](SECURITY.md)
- **Third-Party Notices**: [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)
- **Architecture**: [docs/architecture/ADR-0003-open-source-local-first.md](docs/architecture/ADR-0003-open-source-local-first.md)
