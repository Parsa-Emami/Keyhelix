# KeyHelix Service Policy & Local Storage Architecture

> **Contract Reference**: Requirement N38, Task C38, [ADR-0003 (Open-Source Local-First Delivery)](../architecture/ADR-0003-open-source-local-first.md), and [RELEASE_POLICY.md](RELEASE_POLICY.md).

---

## 1. Distribution Model & Open Source Independence

KeyHelix is an entirely open-source, local-first secret orchestration and key management system licensed under **Apache-2.0**.

- **Zero Cloud or Hosted Account Prerequisite**: KeyHelix does not mandate any proprietary cloud vendor account (e.g. AWS, GCP, Azure), SaaS subscription, or remote token authority.
- **Zero Paid Features**: All cryptographic primitives, vault capabilities, grant delegation, step-up access rules, and disaster recovery features are fully functional in the core distribution without paywalled tiers or enterprise feature flags.
- **Zero Telemetry**: KeyHelix does not collect, track, or transmit any analytical telemetry, usage metrics, crash reports, or payload bytes over the network.
- **Strict Loopback Boundary**: All operational network communication between the web frontend, the backend engine BFF, and the local cryptographic providers (OpenBao and Keycloak) binds exclusively to loopback interfaces (`127.0.0.1`) by default.

---

## 2. Local Data Locations

All local persistent state generated during KeyHelix execution is strictly isolated and contained within the local filesystem under the designated runtime directory:

```
<project-root>/
└── .local-data/                          # Designated local runtime state root
    ├── engine/
    │   └── store/                        # Durable engine metadata repository
    │       ├── manifests/
    │       │   ├── manifest_v1.json      # Authoritative versioned metadata manifest
    │       │   └── manifest_v*.json      # Monotonically increasing manifest revisions
    │       ├── blobs/
    │       │   └── <sha256-hex>          # Content-addressed immutable metadata envelopes
    │       └── staging/
    │           └── <tmp-id>.staging      # In-flight transactional staging files
    ├── openbao/
    │   └── data/                         # Local OpenBao file-backed encrypted storage
    └── keycloak/
        └── data/                         # Local Keycloak realm and identity storage
```

### Storage Responsibilities & Invariants:
1. **Engine Metadata Store (`.local-data/engine/store/`)**:
   - Persists only envelope metadata: vault configurations, member grant delegations, access audit logs, and transit-wrapped Data Encryption Key (DEK) records.
   - **Zero Plaintext Sentinel Bytes**: Unsealed secret bytes, user passwords, and plain access tokens are **never** persisted to disk in the engine store.
2. **Provider State (`.local-data/openbao/data/`)**:
   - OpenBao owns sealed secret bytes and the root Key Encryption Key (KEK) in transit mount (`transit/keys/keyhelix-kek`).
   - Secret payloads are stored sealed under the Key-Value mount (`secret/data/`).
3. **Identity State (`.local-data/keycloak/data/`)**:
   - Manages OIDC user realms, client credentials, and session tokens.
4. **Temporary / Cache Isolation**:
   - Sensitive endpoints enforce `Cache-Control: no-store` and `Pragma: no-cache`. Web application assets are statically served, and no secret payload is ever placed in browser storage (`localStorage`, `sessionStorage`, or service-worker caches).

---

## 3. Data Lifecycle: Export, Deletion, Retention, Backup & Recovery

### 3.1 Portable Export
KeyHelix provides portable JSON-formatted metadata export:
- **Scope of Export**: Vault configurations, grant delegation state, access policies, and audit logs.
- **Security Boundary**: Exported manifests contain only transit-wrapped ciphertext envelopes; raw secret bytes remain secured within OpenBao and are never dumped into export files without active step-up authentication.

### 3.2 Deletion and Cryptographic Destruction
KeyHelix implements distinct two-tier deletion:
- **Soft Deletion**: Revoking a member grant or vault secret marks a tombstone in the metadata store and invalidates active session tokens immediately (HTTP 403 access denial).
- **Hard Destruction**: Cryptographic erasure is performed by deleting the versioned secret payload and destroying the associated transit wrapping key within OpenBao. Once destroyed, past ciphertext envelopes become cryptographically irrecoverable.
- **Host Cleanup**: Halting containers via `podman stop` and removing `.local-data/` completely purges all local state, keys, and metadata from the host.

### 3.3 Retention & Bounded Storage
To prevent resource exhaustion and unbounded growth:
- **Structural Bounds**: JSON input previews are restricted to a maximum size of **1 MiB (1,048,576 bytes)**, a maximum object depth of **32 levels**, and a maximum of **20,000 keys**.
- **Automatic Orphan Reclamation**: Incomplete staging files (`staging/*.staging`) resulting from interrupted writes or crashes are automatically identified and cleaned up whenever `storage.Open` initializes the store.
- **Audit Log Retention**: Audit events are retained locally with bounded rotation; no uncollected staging state accumulates indefinitely.

### 3.4 Backup & Disaster Recovery
- **Snapshot Consistency**: Engine metadata backups are created by capturing an atomic point-in-time snapshot of the store directory (`manifests/` and `blobs/`) after completing pending transactions.
- **Provider Key Custody**: OpenBao unseal keys and root recovery tokens must be stored under separate operator custody. Backups of the engine store cannot be decrypted without the separate provider keys.
- **RPO and RTO Targets**:
  - **Recovery Point Objective (RPO)**: $\le 24$ hours for single-node local environments.
  - **Recovery Time Objective (RTO)**: $\le 4$ hours for cold-start restore on a clean host.

### 3.5 Forward Repair Over Stale Rollback
- **Prohibition of Stale Restores**: Restoring an outdated backup or older manifest revision over newer accepted writes is strictly rejected by the engine (`stale_data_rejected`).
- **Forward Repair Principle**: When data format evolves or schema migrations occur, forward migration using verified migration fixtures is required. Rollback must not overwrite accepted user state.

---

## 4. Supported Operational Profiles

KeyHelix officially supports two operational profiles:

| Profile | Target Environment | Identity Provider | Key Provider | Intended Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **`local-demo`** | In-memory / CI | Synthetic OIDC | Synthetic Provider | Rapid testing, CI workflows, architectural demonstrations, and automated unit tests |
| **`local-private`** | Single-host Linux | Self-hosted Keycloak 26.8.1 (OIDC) | Self-hosted OpenBao 2.7.2 | Production-grade self-hosted secret management, offline developer workstations, private engineering infrastructure |

### Verified Hardware Profile (Local-Private):
- **CPU**: 4 vCPU minimum (verified on 16 vCPU)
- **RAM**: 8,192 MiB minimum (verified on 31,341 MiB)
- **Disk**: 20,480 MiB free space minimum (verified on 97,580 MiB free)
- **OS**: Linux x86_64 / arm64 with Podman 4.9+ and Node 24.19+

---

## 5. Service Policy: Zero Unearned SLA

As self-hosted, open-source software:
- **No Hosted Availability Guarantee**: KeyHelix does not offer or claim commercial cloud availability SLAs (e.g. "99.99% uptime SLA").
- **Reliability via Code Invariants**: System resilience and data durability are achieved through rigorous architectural guarantees:
  1. **Fail-Closed Availability**: Network interruptions or key provider outages immediately fail closed with HTTP 503 (`provider_unavailable`), returning zero plaintext.
  2. **Atomic Manifest Publication**: Store state transitions are atomic; interrupted writes leave the prior authoritative manifest intact.
  3. **Immediate Privilege Reduction**: Revoking a grant immediately invalidates access on the very next request.
  4. **Tamper Rejection**: Any bit-flip or corrupted authentication tag in ciphertext triggers immediate rejection with HTTP 500 (`secret_unseal_failed`).
