import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import { access, cp, mkdtemp, mkdir, readdir, readFile, rm, writeFile } from 'node:fs/promises';
import { once } from 'node:events';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import {
  ErrorCodes,
  installOrUpgradeRelease,
  readHostAuthorityState,
  recordDurableDataProgress,
  rollbackRelease,
  signRelease,
  verifyRelease,
  verifySourceBuildAlternative
} from '../../scripts/verify-release.mjs';

const root = fileURLToPath(new URL('../../', import.meta.url));
const positive = JSON.parse(await readFile(join(root, 'tests', 'fixtures', 'keyhelix', 'C35', 'positive.json'), 'utf8'));
const negative = JSON.parse(await readFile(join(root, 'tests', 'fixtures', 'keyhelix', 'C35', 'negative.json'), 'utf8'));
const expected = JSON.parse(await readFile(join(root, 'tests', 'fixtures', 'keyhelix', 'C35', 'expected-output.json'), 'utf8'));

const sha256 = value => createHash('sha256').update(value).digest('hex');
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

async function waitFor(predicate, timeout = 15000, interval = 50) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    if (await predicate()) return;
    await delay(interval);
  }
  throw new Error('Timed out waiting for condition.');
}

async function tempDirectory() {
  await mkdir(join(root, 'dist'), { recursive: true });
  return mkdtemp(join(root, 'dist', '.upgrade-test-'));
}

function ensureBuilt() {
  const env = {
    ...process.env,
    PATH: `/usr/local/go/bin:${process.env.PATH ?? ''}`,
    GOFLAGS: `${process.env.GOFLAGS ?? ''} -buildvcs=false`.trim()
  };
  const result = spawnSync('npm', ['run', 'build'], {
    cwd: root,
    encoding: 'utf8',
    timeout: 300000,
    stdio: 'inherit',
    env
  });
  assert.equal(result.status, 0, 'build must succeed before C35 release tests');
}

function packageRelease(dest) {
  const env = {
    ...process.env,
    PATH: `/usr/local/go/bin:${process.env.PATH ?? ''}`,
    KEYHELIX_PACKAGE_SKIP_BUILD: '1',
    KEYHELIX_RELEASE_DIR: dest
  };
  const result = spawnSync('bash', ['scripts/package.sh'], {
    cwd: root,
    encoding: 'utf8',
    timeout: 300000,
    maxBuffer: 8 * 1024 * 1024,
    env
  });
  assert.equal(result.status, 0, result.stderr || result.stdout);
  return JSON.parse(result.stdout.trim());
}

async function startPackagedEngine(releaseDir) {
  const binary = join(releaseDir, 'dist', 'engine', 'keyhelix');
  const child = spawn(binary, ['--listen', '127.0.0.1:0'], {
    cwd: releaseDir,
    stdio: ['pipe', 'pipe', 'pipe']
  });
  let stdout = '';
  child.stdout.on('data', chunk => { stdout += chunk.toString('utf8'); });
  await waitFor(() => stdout.includes('\n'), 10000);
  const ready = JSON.parse(stdout.slice(0, stdout.indexOf('\n')));
  const response = await fetch(`http://${ready.address}/healthz`);
  const health = await response.json();
  return { child, ready, health, status: response.status };
}

async function stopProcess(child) {
  if (child.exitCode !== null) return;
  child.kill('SIGTERM');
  await Promise.race([once(child, 'exit'), delay(5000)]);
  if (child.exitCode === null) child.kill('SIGKILL');
}

async function writeDurableRecord(dataDir, step, owner) {
  const manifestsDir = join(dataDir, 'manifests');
  const blobsDir = join(dataDir, 'blobs');
  const stagingDir = join(dataDir, 'staging');
  await mkdir(manifestsDir, { recursive: true });
  await mkdir(blobsDir, { recursive: true });
  await mkdir(stagingDir, { recursive: true });

  const existingManifests = (await readdir(manifestsDir)).filter(name => /^manifest-\d{20}\.json$/.test(name)).sort();
  let currentRecords = [];
  let currentOperations = [];
  let lastManifestVersion = 0;
  if (existingManifests.length > 0) {
    const latest = JSON.parse(await readFile(join(manifestsDir, existingManifests.at(-1)), 'utf8'));
    currentRecords = latest.records ?? [];
    currentOperations = latest.operations ?? [];
    lastManifestVersion = latest.manifest_version;
  }

  const now = '2026-10-31T00:35:00Z';
  const metadataDoc = JSON.stringify({
    vault_id: positive.vault.vault_id,
    secret_path: step.secret_path,
    classification: step.classification,
    kek_id: positive.vault.kek_id,
    version: step.entity_version,
    sealed_ref: `openbao://${positive.vault.mount}/${positive.vault.vault_id}/${step.secret_path}@v${step.entity_version}`
  });
  const metadataBytes = Buffer.from(metadataDoc, 'utf8');
  const digest = sha256(metadataBytes);
  await writeFile(join(blobsDir, digest), metadataBytes);

  const nextManifestVersion = lastManifestVersion + 1;
  assert.equal(nextManifestVersion, step.manifest_version);

  const existingIndex = currentRecords.findIndex(
    item => item.owner === owner && item.scope === positive.vault.vault_id && item.name === step.secret_path
  );
  const recordEntry = {
    owner,
    scope: positive.vault.vault_id,
    name: step.secret_path,
    entity_version: step.entity_version,
    metadata_digest: digest,
    metadata_bytes: metadataBytes.length,
    created_at: existingIndex >= 0 ? currentRecords[existingIndex].created_at : now,
    updated_at: now
  };
  if (existingIndex >= 0) {
    currentRecords[existingIndex] = recordEntry;
  } else {
    currentRecords.push(recordEntry);
  }
  currentRecords.sort((a, b) => `${a.owner}\0${a.scope}\0${a.name}`.localeCompare(`${b.owner}\0${b.scope}\0${b.name}`));

  currentOperations.push({
    operation_id: step.operation_id,
    owner,
    scope: positive.vault.vault_id,
    name: step.secret_path,
    expected_version: step.expected_version,
    entity_version: step.entity_version,
    manifest_version: nextManifestVersion,
    metadata_digest: digest,
    metadata_bytes: metadataBytes.length,
    recorded_at: now
  });

  const manifestName = `manifest-${String(nextManifestVersion).padStart(20, '0')}.json`;
  const manifestPayload = {
    schema_version: 1,
    manifest_version: nextManifestVersion,
    published_at: now,
    records: currentRecords,
    operations: currentOperations
  };
  await writeFile(join(manifestsDir, manifestName), JSON.stringify(manifestPayload, null, 2) + '\n');
  return recordDurableDataProgress(join(dataDir, '..'), dataDir);
}

async function scanNoCanaries(directory, canaries) {
  let hits = 0;
  async function walk(current) {
    for (const entry of await readdir(current, { withFileTypes: true })) {
      const full = join(current, entry.name);
      if (entry.isDirectory()) {
        await walk(full);
      } else if (entry.isFile()) {
        const bytes = await readFile(full);
        for (const canary of canaries) {
          if (bytes.includes(Buffer.from(canary, 'utf8'))) hits += 1;
        }
      }
    }
  }
  await walk(directory);
  return hits;
}

test('signed release verification, data-safe upgrade, binary rollback preserving newer data, and source-build alternative succeed', { timeout: 300000 }, async t => {
  const workspace = await tempDirectory();
  t.after(() => rm(workspace, { recursive: true, force: true }));

  if (!(await access(join(root, 'dist', 'engine', 'keyhelix')).then(() => true, () => false))) {
    ensureBuilt();
  }

  const releaseV1Source = join(workspace, 'source-v1');
  const releaseV2Source = join(workspace, 'source-v2');
  packageRelease(releaseV1Source);
  await cp(releaseV1Source, releaseV2Source, { recursive: true });

  const sigV1 = await signRelease({
    releaseDir: releaseV1Source,
    signerId: positive.trusted_authority.signer_id,
    keyId: positive.trusted_authority.key_id,
    seedHex: positive.trusted_authority.seed_hex,
    revision: positive.releases.initial.revision,
    versionOverride: positive.releases.initial.version,
    issuedAt: positive.releases.initial.issued_at,
    expiresAt: positive.releases.initial.expires_at
  });
  assert.equal(sigV1.public_key_hex, positive.trusted_authority.public_key_hex);

  const verifiedV1 = await verifyRelease({
    releaseDir: releaseV1Source,
    trustedAuthority: positive.trusted_authority,
    minRevision: 1,
    now: new Date('2026-11-01T00:00:00Z'),
    canary: negative.canary
  });
  assert.equal(verifiedV1.verified, expected.expected.signature_verified);
  assert.equal(verifiedV1.revision, expected.expected.initial_install_revision);

  const hostRoot = join(workspace, 'host');
  const dataDir = join(hostRoot, 'data');

  const installed = await installOrUpgradeRelease({
    hostRoot,
    slot: positive.releases.initial.slot,
    sourceReleaseDir: releaseV1Source,
    trustedAuthority: positive.trusted_authority,
    dataDir,
    now: new Date('2026-11-01T00:00:00Z')
  });
  assert.equal(installed.action, 'install');
  assert.equal(installed.revision, 1);

  const engineV1 = await startPackagedEngine(installed.slotDir);
  try {
    assert.equal(engineV1.status, 200);
    assert.equal(engineV1.health.scope, 'engine-runtime');
  } finally {
    await stopProcess(engineV1.child);
  }

  const afterV1Write = await writeDurableRecord(dataDir, positive.workflow_records[0], positive.identity.email);
  assert.equal(afterV1Write.highestManifestVersion, 1);
  assert.equal(afterV1Write.recordCount, 1);

  await signRelease({
    releaseDir: releaseV2Source,
    signerId: positive.trusted_authority.signer_id,
    keyId: positive.trusted_authority.key_id,
    seedHex: positive.trusted_authority.seed_hex,
    revision: positive.releases.upgrade.revision,
    versionOverride: positive.releases.upgrade.version,
    issuedAt: positive.releases.upgrade.issued_at,
    expiresAt: positive.releases.upgrade.expires_at
  });

  const upgraded = await installOrUpgradeRelease({
    hostRoot,
    slot: positive.releases.upgrade.slot,
    sourceReleaseDir: releaseV2Source,
    trustedAuthority: positive.trusted_authority,
    dataDir,
    now: new Date('2026-11-01T01:00:00Z')
  });
  assert.equal(upgraded.action, 'upgrade');
  assert.equal(upgraded.revision, expected.expected.upgraded_revision);
  assert.equal(upgraded.version, positive.releases.upgrade.version);
  assert.equal(upgraded.manifestVersion, 1);

  await writeDurableRecord(dataDir, positive.workflow_records[1], positive.identity.email);
  const afterV2Writes = await writeDurableRecord(dataDir, positive.workflow_records[2], positive.identity.email);
  assert.equal(afterV2Writes.highestManifestVersion, expected.expected.post_upgrade_manifest_version);
  assert.equal(afterV2Writes.recordCount, expected.expected.post_upgrade_records);

  const rolledBack = await rollbackRelease({
    hostRoot,
    trustedAuthority: positive.trusted_authority,
    dataDir,
    now: new Date('2026-11-01T02:00:00Z')
  });
  assert.equal(rolledBack.action, 'rollback');
  assert.equal(rolledBack.slot, positive.releases.initial.slot);
  assert.equal(rolledBack.revision, expected.expected.rollback_binary_revision);
  assert.equal(rolledBack.preservedManifestVersion, expected.expected.post_rollback_manifest_version);
  assert.equal(rolledBack.preservedRecords, expected.expected.post_rollback_records);

  const engineRolledBack = await startPackagedEngine(rolledBack.slotDir);
  try {
    assert.equal(engineRolledBack.status, 200);
  } finally {
    await stopProcess(engineRolledBack.child);
  }

  const sourceBuild = await verifySourceBuildAlternative({
    releaseDir: rolledBack.slotDir,
    workDir: join(workspace, 'source-build'),
    requiredFiles: positive.source_build.required_files
  });
  assert.equal(sourceBuild.built, expected.expected.source_build_alternative_verified);

  const canaries = [
    negative.canary,
    ...positive.workflow_records.map(item => item.plaintext_canary)
  ];
  assert.equal(await scanNoCanaries(hostRoot, canaries), expected.expected.plaintext_canary_occurrences);
});

test('negative cases: 1-byte modification, missing evidence, untrusted signer, expired attestation, stale revision and stale data overwrite fail closed', { timeout: 300000 }, async t => {
  const workspace = await tempDirectory();
  t.after(() => rm(workspace, { recursive: true, force: true }));

  if (!(await access(join(root, 'dist', 'engine', 'keyhelix')).then(() => true, () => false))) {
    ensureBuilt();
  }

  const baseRelease = join(workspace, 'base-release');
  packageRelease(baseRelease);
  await signRelease({
    releaseDir: baseRelease,
    signerId: positive.trusted_authority.signer_id,
    keyId: positive.trusted_authority.key_id,
    seedHex: positive.trusted_authority.seed_hex,
    revision: 2,
    versionOverride: '0.0.2',
    issuedAt: positive.releases.upgrade.issued_at,
    expiresAt: positive.releases.upgrade.expires_at
  });

  // 1. One modified byte in dist/engine/keyhelix
  const tamperedBinaryRelease = join(workspace, 'tampered-binary');
  await cp(baseRelease, tamperedBinaryRelease, { recursive: true });
  const binaryPath = join(tamperedBinaryRelease, 'dist', 'engine', 'keyhelix');
  const binaryBytes = Buffer.from(await readFile(binaryPath));
  binaryBytes[binaryBytes.length - 1] ^= 0xff;
  await writeFile(binaryPath, binaryBytes);
  await assert.rejects(
    () => verifyRelease({
      releaseDir: tamperedBinaryRelease,
      trustedAuthority: positive.trusted_authority,
      now: new Date('2026-11-01T00:00:00Z')
    }),
    error => error.code === ErrorCodes.CHECKSUM_MISMATCH
  );

  // 2. One modified byte in RELEASE.json
  const tamperedManifestRelease = join(workspace, 'tampered-manifest');
  await cp(baseRelease, tamperedManifestRelease, { recursive: true });
  const manifestPath = join(tamperedManifestRelease, 'RELEASE.json');
  const manifestText = await readFile(manifestPath, 'utf8');
  await writeFile(manifestPath, manifestText.replace('"KeyHelix"', '"KeyHeliX"'));
  await assert.rejects(
    () => verifyRelease({
      releaseDir: tamperedManifestRelease,
      trustedAuthority: positive.trusted_authority,
      now: new Date('2026-11-01T00:00:00Z')
    }),
    error => error.code === ErrorCodes.SIGNATURE_INVALID
  );

  // 3. Missing signature evidence (RELEASE.sig removed)
  const missingSigRelease = join(workspace, 'missing-sig');
  await cp(baseRelease, missingSigRelease, { recursive: true });
  await rm(join(missingSigRelease, 'RELEASE.sig'));
  await assert.rejects(
    () => verifyRelease({
      releaseDir: missingSigRelease,
      trustedAuthority: positive.trusted_authority,
      now: new Date('2026-11-01T00:00:00Z')
    }),
    error => error.code === ErrorCodes.MISSING_SIGNATURE_EVIDENCE
  );

  // 4. Wrong / untrusted signer
  const untrustedRelease = join(workspace, 'untrusted-signer');
  await cp(baseRelease, untrustedRelease, { recursive: true });
  await signRelease({
    releaseDir: untrustedRelease,
    signerId: negative.untrusted_authority.signer_id,
    keyId: negative.untrusted_authority.key_id,
    seedHex: negative.untrusted_authority.seed_hex,
    revision: 3,
    issuedAt: positive.releases.upgrade.issued_at,
    expiresAt: positive.releases.upgrade.expires_at
  });
  await assert.rejects(
    () => verifyRelease({
      releaseDir: untrustedRelease,
      trustedAuthority: positive.trusted_authority,
      now: new Date('2026-11-01T00:00:00Z')
    }),
    error => error.code === ErrorCodes.UNTRUSTED_SIGNER
  );

  // Also test right signer_id claim but signed with untrusted private key while claiming trusted public key
  const forgedSigPath = join(untrustedRelease, 'RELEASE.sig');
  const forgedSig = JSON.parse(await readFile(forgedSigPath, 'utf8'));
  forgedSig.signer_id = positive.trusted_authority.signer_id;
  forgedSig.key_id = positive.trusted_authority.key_id;
  forgedSig.public_key_hex = positive.trusted_authority.public_key_hex;
  await writeFile(forgedSigPath, JSON.stringify(forgedSig, null, 2) + '\n');
  await assert.rejects(
    () => verifyRelease({
      releaseDir: untrustedRelease,
      trustedAuthority: positive.trusted_authority,
      now: new Date('2026-11-01T00:00:00Z')
    }),
    error => error.code === ErrorCodes.SIGNATURE_INVALID
  );

  // 5. Expired attestation
  await assert.rejects(
    () => verifyRelease({
      releaseDir: baseRelease,
      trustedAuthority: positive.trusted_authority,
      now: new Date('2028-01-01T00:00:00Z')
    }),
    error => error.code === ErrorCodes.EXPIRED_ATTESTATION
  );

  // 6. Stale / replayed release revision cannot replace accepted authority
  const hostRoot = join(workspace, 'host-negative');
  const dataDir = join(hostRoot, 'data');
  await installOrUpgradeRelease({
    hostRoot,
    slot: 'v2',
    sourceReleaseDir: baseRelease,
    trustedAuthority: positive.trusted_authority,
    dataDir,
    now: new Date('2026-11-01T00:00:00Z')
  });
  await assert.rejects(
    () => installOrUpgradeRelease({
      hostRoot,
      slot: 'v2-replay',
      sourceReleaseDir: baseRelease,
      trustedAuthority: positive.trusted_authority,
      dataDir,
      now: new Date('2026-11-01T00:00:00Z')
    }),
    error => error.code === ErrorCodes.STALE_REVISION_REJECTED
  );

  // 7. Stale data backup cannot replace newer accepted manifest state
  await writeDurableRecord(dataDir, positive.workflow_records[0], positive.identity.email);
  await writeDurableRecord(dataDir, positive.workflow_records[1], positive.identity.email);
  const stateAfterWrites = await readHostAuthorityState(hostRoot);
  assert.equal(stateAfterWrites.highest_manifest_version, 2);

  await rm(join(dataDir, 'manifests', 'manifest-00000000000000000002.json'));
  await assert.rejects(
    () => recordDurableDataProgress(hostRoot, dataDir),
    error => error.code === ErrorCodes.STALE_DATA_REJECTED
  );
  await assert.rejects(
    () => rollbackRelease({
      hostRoot,
      targetSlot: 'v2',
      trustedAuthority: positive.trusted_authority,
      dataDir,
      now: new Date('2026-11-01T00:00:00Z')
    }),
    error => error.code === ErrorCodes.STALE_DATA_REJECTED
  );
});
