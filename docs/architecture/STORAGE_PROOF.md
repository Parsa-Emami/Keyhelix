# KeyHelix: recoverable local authoritative writes

Status: C05 implementation. This document describes the bounded single-host
metadata port allowed by ADR-0003. It is not evidence that the complete
reference workflow, identity, provider permissions or secret reveal exist.

## Scope and security boundary

`internal/storage` stores immutable, caller-supplied **metadata documents** and
a versioned manifest. It does not accept plaintext secret values, derive keys,
encrypt or decrypt provider payloads, or implement OIDC/session/step-up
authorization. OpenBao remains the authority for provider-owned secret bytes
(C07+), and the C04 metadata contract remains the domain shape above this port.

The adapter therefore proves the filesystem protocol only:

- one local writer;
- bounded state;
- staged and hash-checked bytes;
- one atomic versioned manifest publication;
- directory flushes and acknowledgement only after commit;
- durable operation/idempotency state in the same visible transaction;
- reconciliation of orphan staging and rejected recovery failures.

Plaintext policy, provider outage behavior and reveal authorization remain
C13–C15 and C23 work. Identity, forged headers and provider-scope widening
remain C08–C11 work; the storage port cannot certify them without inventing
authority.

## Layout

```
<root>/
  LOCK                                  # exclusive flock target
  blobs/<sha256>                        # immutable metadata bytes
  staging/                              # uncommitted temporary files
  manifests/manifest-<20-digit>.json    # complete versioned state
```

Each manifest holds `schema_version`, `manifest_version`, `published_at`, all
record metadata and the retained operation window. The manifest stores only a
metadata digest and byte count; the metadata body lives in `blobs/`.

A logical record is identified by `(owner, scope, name)`. Owner and scope are
part of the lookup key, so a read from another owner or scope returns
`NOT_FOUND` exactly like an absent name. This avoids leaking existence across
scopes; C11 still owns the application-level authorization decision.

## Port

The exported boundary is `Port`:

```go
type Port interface {
    Write(ctx context.Context, request WriteRequest) (WriteResult, error)
    Read(ctx context.Context, request ReadRequest) (Record, error)
    Close() error
}
```

`WriteRequest` carries a stable `OperationID`, owner/scope/name, an optimistic
`ExpectedVersion` and bounded metadata bytes. `WriteResult` reports the entity
version, manifest version, metadata digest and whether the operation was a
replay. `Record` returns the verified metadata bytes and timestamps.

Typed error codes are `INVALID_INPUT`, `LOCKED`, `DISK_FULL`, `IO_FAILURE`,
`CORRUPT_STATE`, `OPERATION_CONFLICT`, `ALREADY_EXISTS`, `STALE_VERSION`,
`QUOTA_EXCEEDED`, `NOT_FOUND`, `CANCELLED`, `TIMEOUT` and `CLOSED`. Error
messages do not include local paths or stored metadata.

## Commit protocol

1. Validate the request, the context, owner/scope/name bounds and the
   `ExpectedVersion`; read the operation window before any side effect.
2. Write metadata to a `staging/blob-*.tmp` file, `fsync` it, read it back and
   compare its SHA-256, then `rename` it to `blobs/<digest>` and `fsync` the
   blobs directory.
3. Build the next complete manifest, serialize it within the manifest cap,
   write it to `staging/manifest-*.tmp`, `fsync` it, `rename` it to
   `manifests/manifest-<version>.json` and `fsync` the manifests directory.
4. Only after step 3 succeeds does the in-memory snapshot advance and the
   acknowledgement return. Cleanup of old manifests, old blobs and leftover
   staging is best effort after commit and cannot revoke an acknowledged write.
5. Every error removes uncommitted staging bytes where it is safe. If a
   directory sync fails after the manifest rename, the manifest may already be
   durable; replay/recovery must resolve that ambiguity, never assume the write
   was absent.

A successful write creates exactly one visible manifest version. A replay of
the same operation does not publish another manifest.

## Failure and recovery matrix

| Interruption point | Visible state | Recovery |
|---|---|---|
| Before metadata staging file | Old manifest only | Staging is empty |
| During/after metadata write or file sync | Old manifest only | Leftover staging file is removed on Open |
| After metadata rename, before manifest publication | Old manifest; orphan blob | Orphan blob is removed on Open or on the next commit |
| During manifest staging or file sync | Old manifest; committed blob may remain | Staging is removed; orphan blob is removed |
| After manifest rename, before directory sync | Manifest may be durable | Open loads the highest manifest; if valid, replay is idempotent; if invalid, Open fails closed |
| After directory sync, before acknowledgement | New manifest is durable | Replay returns the recorded result with `Duplicate: true` |
| Missing or corrupt referenced blob | No accepted read | `Open`/`Read` returns `CORRUPT_STATE`; no fallback to an older manifest |
| Corrupt or invalid newest manifest | No accepted state | `Open` returns `CORRUPT_STATE`; the writer lock is released |
| Unexpected staging/manifest/blob entry | No accepted state | `Open` fails closed rather than deleting an unknown object |

`Open` never selects an older manifest when the highest present manifest is
invalid or references missing bytes; those states fail closed. Older manifest
files are retained only as bounded history and are pruned; they are not a
rollback source. Manual deletion of the highest manifest file is outside the
atomic-write guarantee (version discovery would then select the next file), so
backups must include every accepted manifest and operators must never delete
accepted manifest files. An interrupted commit cannot produce this state
because the manifest rename is atomic.

## Bounds

| Bound | Value |
|---|---|
| Metadata body per record | 64 KiB |
| Logical records | 256 |
| Retained operation/idempotency entries | 256 (oldest pruned) |
| Serialized manifest | 1 MiB |
| Retained manifest files | 4 |
| Owner or scope | 128 bytes |
| Logical name | 1024 bytes |

Names are logical keys, not filesystem paths. Validation rejects empty names,
`..` and `.` segments, absolute paths, duplicate slashes, backslashes, control
characters and out-of-pattern owner/scope values before any file is written.
Worst-case referenced blob state is 256 × 64 KiB = 16 MiB, plus at most four
1 MiB manifests and the lock file. The manifest cap is checked before the
metadata body is staged.

Operation IDs are validated and retained in the manifest. Repeating an
operation with the same owner/scope/name, expected version and digest returns
the recorded result. Reusing an ID with different bytes returns
`OPERATION_CONFLICT`. An operation evicted from the 256-entry window can no
longer replay; an update then fails the optimistic version check instead of
silently duplicating the write.

## Single writer and concurrency

`Open` acquires an exclusive `flock` on `LOCK` before reading or cleaning state.
A second process receives `LOCKED`; a crashed process releases the advisory
lock without a stale-lock repair procedure. In-process `Write` calls are
serialized by a mutex and `Read` calls use a read lock, so readers observe
either the old committed snapshot or the new one, never a partial manifest.

The supported local profile is Linux x86_64 (ADR-0003). The lock uses the Unix
advisory API; other host profiles require their own implemented and tested
adapter before being advertised.

## Verification

The real filesystem acceptance tests are `tests/storage_test.go`; they consume
the synthetic fixtures under `tests/fixtures/keyhelix/C05/` and exercise:

- write, read, versioning, replay after restart and fixture-pinned digests;
- wrong owner/scope non-disclosure, missing names and path/owner/scope
  injection before side effects;
- optimistic version conflicts, duplicate creates and operation conflicts;
- single-writer lock and release;
- orphan staging/blob cleanup, missing/corrupt blob and corrupt manifest
  fail-closed behavior;
- manifest history and operation-window bounds, record quota;
- concurrent writes under `-race`;
- read-time hash verification and the plaintext-canary check;
- context cancellation before commit.

`internal/storage/adapter_test.go` injects `ENOSPC` and directory-sync failures
at each device stage using an unexported test seam. A failed stage must not
acknowledge the write, damage accepted state or survive incorrectly after
restart; an ambiguous manifest publication must replay idempotently. This is
injected device-failure evidence, not a physically full volume; C28 must
measure actual resource and full-disk behavior on the supported host.

## Deferred work

- OIDC identity, session expiry/revocation, step-up and forged-header rejection:
  C08–C10.
- Provider authorization and scope mapping: C07 and C11.
- Provider-owned secret writes/reveal and plaintext redaction across logs,
  databases, traces and browser storage: C13–C15.
- HTTP/UI wiring and readiness/diagnostics: C12–C15, C29.
- Real disk-full, saturation and resource measurements: C28.
- Clean-host restart/restore of the complete workflow: C30.

## Rollback

Reverting C05 removes the isolated storage package and its tests; test data
lives only in temporary directories. If a local store was used, preserve the
highest valid manifest and its referenced blobs, never restore an older
manifest over newer accepted state, and repair forward with a new manifest
version after review.
