# Provider root custody, backup and isolated restore

Status: documented and drilled at C24 on an isolated synthetic instance. No live
OpenBao or Keycloak restore has been performed. Clean-host workflow, restart and
restore remain C30 evidence; physical disk-full and resource measurements remain
C28 evidence.

This runbook covers the recovery boundary that the local KeyHelix engine cannot
own: the OpenBao root key, its unseal or auto-unseal material, and the provider
snapshot. The engine stores only metadata and references; OpenBao owns secret
bytes. Losing the provider root does not become recoverable because a metadata
backup exists.

## Custody model

| Material | Purpose | Custody | Must never be stored in |
| --- | --- | --- | --- |
| Shamir unseal key shares | Reconstruct the root key and unseal a Shamir-sealed node | Offline, threshold split between separate custodians | Git, `.env`, app metadata, browser storage, logs, tickets, the backup directory |
| Auto-unseal recovery keys | Authorize quorum operations such as root-token generation; they do not decrypt the root key | Offline, threshold split between separate custodians | The same locations as unseal shares |
| Auto-unseal KMS/HSM credentials | Let the configured seal mechanism decrypt the root key at startup | Provider/HSM access controlled outside KeyHelix | KeyHelix source, metadata or audit streams |
| Root token | Initial setup and break-glass administration | Generated for one use, kept visible only while in use, revoked immediately afterwards | Workload configuration, repository, long-lived agent environment |
| Backup encryption passphrase | Encrypt provider snapshots and metadata backups at rest | Offline, separate from the backup copies | The backup set, repository, chat or logs |
| OIDC/Keycloak signing and client material | Authenticate users and issue tokens | Keycloak/operator custody, backed up separately | KeyHelix metadata backup |

OpenBao documents that the root key is stored alongside OpenBao data encrypted
by the unseal key, that recovery keys cannot decrypt the root key, and that if
the auto-unseal mechanism or its keys are permanently deleted the cluster
cannot be recovered, even from backups. Treat the seal material as a separate
irreplaceable asset, not as part of the snapshot.

Root tokens are omnipotent. OpenBao recommends using them only for initial setup
or emergencies and revoking them as soon as they are no longer needed. KeyHelix
workload identities are scoped and the provider adapter refuses root tokens; do
not work around that guard during recovery.

## Backup scope

| Asset | Included | Notes |
| --- | --- | --- |
| OpenBao integrated-storage snapshot | Yes | Created with `bao operator raft snapshot save`; encrypted at rest with the operator's approved tool; at least two off-host copies |
| KeyHelix metadata | Yes | Every accepted `manifests/` file and every referenced `blobs/` file, copied after the writer is stopped; no `staging/` or `LOCK` |
| Non-secret configuration | Yes | Provider address/mount names, OIDC issuer/client identifiers, deployment profile; keep secrets out |
| Audit sink | Yes | Preserve append-only audit records and, once C25 lands, separately stored checkpoints |
| Unseal/recovery material, root token | No | Operator-held offline; never copied into the backup set |
| Plaintext secrets, DEKs | No | OpenBao owns secret bytes; KeyHelix never persists plaintext |

KeyHelix metadata contains secret names, paths and classifications even though
it contains no secret bytes. Encrypt the metadata backup and restrict access as
confidential data. The provider snapshot is not a replacement for custody of the
unseal or recovery material.

OpenBao's raft snapshot commands are documented at
<https://openbao.org/docs/commands/operator/raft/> and its raft API at
<https://openbao.org/docs/api/system/storage/raft/>. Snapshots are not supported
when raft is used only for HA storage. The API documents a `snapshot-force`
path that bypasses checks ensuring the seal keys are consistent with the
snapshot; do not use it as the normal restore path.

## Backup procedure

1. Announce a maintenance window. Stop KeyHelix writes and close the engine so
   the store releases its writer lock.
2. Create the provider snapshot on the active node:

   ```sh
   bao operator raft snapshot save provider.snap
   ```

3. Copy every accepted metadata manifest and referenced blob from the KeyHelix
   metadata directory into the backup set. Do not copy `staging/` or `LOCK`.
   Do not delete or rewrite the newest manifest in the source store.
4. Export non-secret configuration and the audit sink. Keep OIDC/Keycloak
   client secrets and signing material in their own custody procedure.
5. Encrypt the snapshot and metadata backup with the operator's approved tool,
   record the SHA-256 of each encrypted artifact, and store at least two copies
   off-host. Keep the encryption passphrase and unseal/recovery material outside
   those copies. The backup manifest is not a signature: record its digest
   out-of-band with the drill result and rely on the encrypted storage for
   authenticity.
6. Record the source commit, OpenBao version, Keycloak version (if applicable),
   snapshot digest, metadata manifest version and the drill result.

The local metadata copy is a consistent snapshot only after the writer has
stopped. Copying `manifests/` and `blobs/` while a write is in flight is not a
supported backup procedure.

## Isolated restore procedure

Never restore over a live or newer accepted state. Use a fresh host or fresh
directories and a distinct provider instance. The operator must present the
offline recovery material; it is not read from the backup.

1. Provision an isolated instance with no public ingress. Use new paths and
   provider ports so production state cannot be touched.
2. Restore the provider snapshot into a freshly bootstrapped, isolated OpenBao
   instance using the documented command for the pinned OpenBao version:

   ```sh
   bao operator raft snapshot restore provider.snap
   ```

3. Unseal the restored instance with the operator-held material. The CLI prompts
   for each share; do not pass a key as a command-line argument:

   ```sh
   bao operator unseal
   ```

   Repeat until the threshold is met. With multiple Shamir-sealed nodes, each
   node needs the threshold itself. For auto-unseal, the configured seal
   mechanism must be available; recovery keys authorize quorum operations but
   do not decrypt the root key.

4. Verify the provider is initialized and unsealed before exposing it to the
   engine:

   ```sh
   curl --fail --silent http://127.0.0.1:8200/v1/sys/seal-status
   ```

   A sealed provider must make every KeyHelix read and write fail closed. The
   engine does not cache plaintext during an outage.

5. Restore KeyHelix metadata into an empty target directory. Refuse a non-empty
   target; do not overwrite a newer accepted manifest. The restore must verify
   every file hash before publishing a target, copy through a temporary
   directory, and rename only after the complete state validates. A failed or
   interrupted copy must leave no partial authoritative target.
6. Open the restored store with the current engine and require a successful
   recovery report: the expected manifest version, the expected record count,
   and hash-checked reads. Confirm that revoked grants are still revoked and
   that provider payloads referenced by the metadata are readable.
7. Rebuild derived projections from authority; never restore a derived cache as
   if it were authoritative.
8. Rotate credentials introduced for the drill, revoke temporary root tokens
   with `bao token revoke "<token>"`, and destroy the isolated instance.
9. Record RPO/RTO and every check result. Cut over only after the isolated
   instance passes; keep the previous production instance until the new one is
   verified.

## Verification checklist

- [ ] Provider snapshot digest matches the recorded backup artifact.
- [ ] Isolated provider reports initialized and unsealed.
- [ ] Seal material was presented by the operator and was not present in the
      backup set.
- [ ] Restored metadata manifest version and record count match the source.
- [ ] Every restored metadata record is hash-checked; no partial record is
      visible.
- [ ] Revoked grants remain revoked.
- [ ] Referenced provider payloads are readable and byte-identical to the
      backup; no plaintext appears in metadata or backup files.
- [ ] Replaying a write after restore is idempotent; a lost acknowledgement does
      not create a second manifest.
- [ ] Disk/quota refusal is explicit, bounded and leaves no partial state.
- [ ] RPO/RTO, OpenBao version, Keycloak version, source commit and hardware are
      recorded with the result.

## Failure handling

| Failure | Required behavior |
| --- | --- |
| Missing recovery material | Refuse the restore before writing a target. Do not infer material from the snapshot. |
| Wrong/foreign recovery material | Refuse and keep the provider sealed. Bound unseal attempts; do not retry indefinitely. |
| Corrupt or incomplete backup | Refuse the restore (`CORRUPT_STATE`/backup corruption), keep the target absent and use another verified copy. |
| Non-empty or newer target | Refuse; never overwrite newer accepted state with an older backup. Repair forward. |
| Interrupted restore | Remove staging, publish nothing, and restart from a verified backup. |
| Provider outage or sealed provider | Fail closed with no plaintext fallback; restore provider availability first. |
| Orphan provider payload from an earlier interrupted write | Do not delete provider-owned bytes automatically. Surface the unreferenced version for explicit operator reconciliation; metadata remains authoritative for what may be revealed. |
| Disk full or quota exhausted | Return an explicit typed error, stop retrying, and preserve the last complete state. |

## Local drill in this repository

The C24 drill is `tests/restore_drill_test.go`, with versioned synthetic
fixtures under `tests/fixtures/keyhelix/C24/`. It exercises:

- a real versioned secret write and revoked grant in the local metadata store;
- an isolated backup and restore, with every file hash checked before publish;
- refusal without operator material, refusal with wrong material, and refusal
  of a non-empty/newer target;
- a restored provider that starts sealed and fails closed until the operator
  presents the matching material;
- a killed writer at staged-byte/manifest boundaries, replay after a lost
  acknowledgement, quota exhaustion, and plaintext-canary scans.

Run it with Go 1.26.2 or newer:

```sh
go test -count=1 -run '^TestC24' ./tests/ -v
```

The drill uses an in-process OpenBao-compatible wire fixture for the real
provider adapter. It does not prove a live OpenBao restore, Keycloak recovery,
clean-host installation, physical disk-full behavior or measured RPO/RTO. Those
are C30/C28 obligations. Do not convert this drill result into a claim that a
provider was restored in production.

References:

- <https://openbao.org/docs/commands/operator/raft/>
- <https://openbao.org/docs/api/system/storage/raft/>
- <https://openbao.org/docs/commands/operator/unseal/>
- <https://openbao.org/docs/concepts/seal/>
- <https://openbao.org/docs/commands/operator/generate-root/>
- <https://openbao.org/docs/concepts/tokens/>
- <https://openbao.org/docs/commands/token/revoke/>
- <https://openbao.org/docs/api/system/seal-status/>
- <https://openbao.org/docs/api/system/unseal/>
- <https://www.keycloak.org/documentation>
- [`docs/architecture/STORAGE_PROOF.md`](../docs/architecture/STORAGE_PROOF.md)
- [`spec/13_BACKUP_RESTORE_REBUILD_DRILL.md`](../spec/13_BACKUP_RESTORE_REBUILD_DRILL.md)
