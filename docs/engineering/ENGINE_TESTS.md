# KeyHelix Engine Test Discovery and CI Verification

This document specifies the test discovery architecture, test suite inventory, local verification commands, and clean-checkout continuous integration pipeline for the KeyHelix engine.

## 1. Test Discovery Architecture

The KeyHelix Go engine and its authoritative local components are organized into modular domain packages. Tests are discovered automatically via standard Go toolchain package patterns (`./...`) and explicitly inventoried in CI:

```
KeyHelix Root
├── cmd/keyhelix/
│   ├── main.go                     # Engine supervisor IPC & HTTP health probe
│   └── main_test.go                # Engine lifecycle, loopback binding & shutdown tests
├── internal/contracts/
│   ├── secret.go                   # Typed secret metadata validation logic
│   └── secret_test.go              # Schema bounds, input size limits, timeout & cancellation tests
├── internal/storage/
│   ├── adapter.go                  # Single-writer storage port, staging blobs, atomic manifests
│   └── adapter_test.go             # Simulated I/O faults, crash recovery matrix, lock contention
└── tests/
    ├── storage_test.go             # Positive/negative fixture validation, concurrency & recovery
    └── engine_ci_test.go           # Clean-checkout integration, test discovery & C06 negative cases
```

### Discovery Command
The complete test list is inspected via:
```sh
go test -list '.*' ./...
```
Expected discovered packages:
- `github.com/parsa-emami/keyhelix/cmd/keyhelix`
- `github.com/parsa-emami/keyhelix/internal/contracts`
- `github.com/parsa-emami/keyhelix/internal/storage`
- `github.com/parsa-emami/keyhelix/tests`

---

## 2. CI Verification & Enforcement Policy

The GitHub Actions workflow `.github/workflows/runtime.yml` validates the complete engine from a clean checkout on every push to `main` and pull request.

### Absence of Collected Domain Tests Fails CI
A dedicated verification step in `.github/workflows/runtime.yml` guarantees that test discovery collects all domain test suites:

```sh
DISCOVERED=$(go test -list '.*' ./...)
for pkg in "cmd/keyhelix" "internal/contracts" "internal/storage" "tests"; do
  if ! echo "$DISCOVERED" | grep -q "$pkg"; then
    echo "CI FAILURE: Absence of collected domain tests for $pkg" >&2
    exit 1
  fi
done
```

If any domain package is missing, has its tests deleted, or is excluded from compilation, the job fails closed immediately.

### Pinned Action Dependencies
All GitHub Actions in `.github/workflows/runtime.yml` are strictly pinned to immutable 40-character commit SHAs:
- `actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803` (fetch-depth: 0)
- `actions/setup-node@249970729cb0ef3589644e2896645e5dc5ba9c38` (Node 24.19 from `.nvmrc`)
- `actions/setup-go@40f1582b2485089dde7abd97c1529aa768e1baff` (Go 1.26+ from `go.mod`)

---

## 3. Test Suites Inventory

| Package | Test Targets | Key Invariants Verified |
| --- | --- | --- |
| `cmd/keyhelix` | Engine Lifecycle | Binds exclusively to loopback (`127.0.0.1:0`), passes stdout handshake, handles graceful shutdown within 5s, rejects external or non-loopback bindings. |
| `internal/contracts` | Contract Validation | Enforces 8 KiB input size bound, strict schema version 1, RFC3339 timestamps, valid KEK/DEK envelope parameters, rejects duplicate JSON keys. |
| `internal/storage` | Authoritative Storage | Single-writer exclusive file lock (`LOCK`), atomic staged rename for blobs and manifests, 256-record bounded capacity, deterministic idempotency window. |
| `tests` | Storage & Engine Integration | Positive fixture execution, version advancement, concurrent writer serialization, crash recovery matrix, and C06 negative cases. |

---

## 4. Required Negative Cases (C06)

Task C06 mandates strict verification of three negative boundary conditions implemented in `tests/engine_ci_test.go`:

1. **One modified byte, missing evidence or untrusted signer must not produce trusted success**:
   - `ModifiedByteInBlobFailsVerification`: Inverting a single bit in a stored blob causes `store.Read` to detect SHA-256 digest corruption and fail closed with `CORRUPT_STATE`.
   - `ModifiedByteInManifestFailsVerification`: Modifying a byte in an existing manifest JSON causes `storage.Open` verification to reject the manifest with `CORRUPT_STATE`.
   - `UntrustedSignerOrMissingKEKFailsClosed`: Omitting or providing an empty KEK reference fails contract validation with `INVALID_INPUT`.

2. **An expired, stale, or replayed revision cannot replace the last valid accepted authority**:
   - `StaleRevisionReplayRejected`: Attempting to write an entity with version 1 when version 2 has already been accepted is rejected with `STALE_VERSION`. Subsequent reads confirm that version 2 remains the active accepted state.

3. **Provider owns secret bytes**:
   - `ProviderOwnsSecretBytesNoPlaintextPersisted`: Plaintext canary strings are verified absent across all persistent store files (manifests, blobs, staging files). The engine and local storage layer never persist unencrypted secret bytes; only provider-wrapped envelopes are stored.

---

## 5. Local Reproduction Commands

To reproduce the exact CI verification on a clean clone:

```sh
# 1. Validate repository invariants and plan consistency
npm run validate:plan
python3 scripts/validate_repo.py
python3 -m unittest discover -s tests/engineering -p 'test_*.py' -v

# 2. Compile the Go engine binary
npm run build:engine

# 3. Verify test collection across all domain packages
go test -list '.*' ./...

# 4. Run all unit and integration tests
go test -count=1 -v ./...

# 5. Run Go race detector across the entire engine and tests
go test -count=1 -race ./...

# 6. Run Go static analysis
go vet ./...

# 7. Run domain contract integration tests
npm run test:contracts
```
