import { spawnSync } from 'node:child_process';
import { createHash, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import { cp, lstat, mkdir, open, readdir, readFile, rename, rm, stat, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { scanForSecrets } from './package-web.mjs';

const ED25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const ATTESTATION_SCHEMA = 1;
const SIGNATURE_FILE = 'RELEASE.sig';

export const ErrorCodes = Object.freeze({
  MISSING_SIGNATURE_EVIDENCE: 'MISSING_SIGNATURE_EVIDENCE',
  UNTRUSTED_SIGNER: 'UNTRUSTED_SIGNER',
  SIGNATURE_INVALID: 'SIGNATURE_INVALID',
  CHECKSUM_MISMATCH: 'CHECKSUM_MISMATCH',
  EXPIRED_ATTESTATION: 'EXPIRED_ATTESTATION',
  STALE_REVISION_REJECTED: 'STALE_REVISION_REJECTED',
  STALE_DATA_REJECTED: 'STALE_DATA_REJECTED',
  SOURCE_BUILD_INVALID: 'SOURCE_BUILD_INVALID',
  SECRET_MATERIAL_DETECTED: 'SECRET_MATERIAL_DETECTED'
});

export class ReleaseVerificationError extends Error {
  constructor(code, detail = '') {
    super(detail ? `${code}:${detail}` : code);
    this.name = 'ReleaseVerificationError';
    this.code = code;
    this.detail = detail;
  }
}

const sha256 = value => createHash('sha256').update(value).digest('hex');
const exists = async path => { try { await lstat(path); return true; } catch { return false; } };

export function ed25519KeyPairFromSeedHex(seedHex) {
  if (typeof seedHex !== 'string' || !/^[a-f0-9]{64}$/i.test(seedHex)) {
    throw new ReleaseVerificationError(ErrorCodes.SIGNATURE_INVALID, 'invalid-seed');
  }
  const seed = Buffer.from(seedHex, 'hex');
  const privateKey = createPrivateKey({
    key: Buffer.concat([ED25519_PKCS8_PREFIX, seed]),
    format: 'der',
    type: 'pkcs8'
  });
  const publicKey = createPublicKey(privateKey);
  const spki = publicKey.export({ format: 'der', type: 'spki' });
  const publicKeyHex = spki.subarray(ED25519_SPKI_PREFIX.length).toString('hex');
  return { privateKey, publicKey, publicKeyHex };
}

export function ed25519PublicKeyFromHex(publicKeyHex) {
  if (typeof publicKeyHex !== 'string' || !/^[a-f0-9]{64}$/i.test(publicKeyHex)) {
    throw new ReleaseVerificationError(ErrorCodes.UNTRUSTED_SIGNER, 'invalid-public-key');
  }
  return createPublicKey({
    key: Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(publicKeyHex, 'hex')]),
    format: 'der',
    type: 'spki'
  });
}

export function canonicalAttestationPayload(statement) {
  const fields = [
    'keyhelix-release-v1',
    `signer_id:${statement.signer_id}`,
    `key_id:${statement.key_id}`,
    `release_id:${statement.release_id}`,
    `version:${statement.version}`,
    `revision:${statement.revision}`,
    `commit:${statement.commit}`,
    `tree_sha256:${statement.tree_sha256}`,
    `source_archive_sha256:${statement.source_archive_sha256}`,
    `release_json_sha256:${statement.release_json_sha256}`,
    `checksums_sha256:${statement.checksums_sha256}`,
    `issued_at:${statement.issued_at}`,
    `expires_at:${statement.expires_at}`
  ];
  return fields.join('\n') + '\n';
}

async function walkReleaseFiles(directory, prefix = '') {
  const files = [];
  const entries = (await readdir(directory, { withFileTypes: true })).sort((a, b) => a.name.localeCompare(b.name));
  for (const entry of entries) {
    const relative = prefix ? `${prefix}/${entry.name}` : entry.name;
    if (entry.isSymbolicLink()) {
      throw new ReleaseVerificationError(ErrorCodes.CHECKSUM_MISMATCH, `symlink:${relative}`);
    }
    if (entry.isDirectory()) {
      files.push(...await walkReleaseFiles(join(directory, entry.name), relative));
    } else if (entry.isFile()) {
      files.push(relative);
    } else {
      throw new ReleaseVerificationError(ErrorCodes.CHECKSUM_MISMATCH, `irregular-file:${relative}`);
    }
  }
  return files;
}

export async function verifyChecksumTree(releaseDir) {
  const checksumPath = join(releaseDir, 'SHA256SUMS.txt');
  const releaseJsonPath = join(releaseDir, 'RELEASE.json');
  if (!(await exists(checksumPath))) {
    throw new ReleaseVerificationError(ErrorCodes.MISSING_SIGNATURE_EVIDENCE, 'SHA256SUMS.txt');
  }
  if (!(await exists(releaseJsonPath))) {
    throw new ReleaseVerificationError(ErrorCodes.MISSING_SIGNATURE_EVIDENCE, 'RELEASE.json');
  }
  const rawChecksums = await readFile(checksumPath, 'utf8');
  const lines = rawChecksums.trim().split('\n').filter(Boolean);
  if (lines.length === 0) {
    throw new ReleaseVerificationError(ErrorCodes.MISSING_SIGNATURE_EVIDENCE, 'empty-checksums');
  }
  const expectedFiles = new Map();
  for (const line of lines) {
    if (line.length < 67 || line.slice(64, 66) !== '  ') {
      throw new ReleaseVerificationError(ErrorCodes.CHECKSUM_MISMATCH, 'malformed-checksum-line');
    }
    const expectedHash = line.slice(0, 64);
    const relativePath = line.slice(66);
    if (!/^[a-f0-9]{64}$/.test(expectedHash) || !relativePath || relativePath.includes('..') || relativePath.startsWith('/')) {
      throw new ReleaseVerificationError(ErrorCodes.CHECKSUM_MISMATCH, relativePath || 'invalid-path');
    }
    if (expectedFiles.has(relativePath)) {
      throw new ReleaseVerificationError(ErrorCodes.CHECKSUM_MISMATCH, `duplicate:${relativePath}`);
    }
    expectedFiles.set(relativePath, expectedHash);
  }

  const actualFiles = (await walkReleaseFiles(releaseDir))
    .filter(path => path !== 'SHA256SUMS.txt' && path !== SIGNATURE_FILE)
    .sort();
  const listedPaths = [...expectedFiles.keys()].sort();
  if (JSON.stringify(actualFiles) !== JSON.stringify(listedPaths)) {
    throw new ReleaseVerificationError(ErrorCodes.CHECKSUM_MISMATCH, 'file-inventory-mismatch');
  }

  for (const [relativePath, expectedHash] of expectedFiles.entries()) {
    const fullPath = join(releaseDir, ...relativePath.split('/'));
    const actualHash = sha256(await readFile(fullPath));
    if (actualHash !== expectedHash) {
      throw new ReleaseVerificationError(ErrorCodes.CHECKSUM_MISMATCH, relativePath);
    }
  }
  return {
    checksumEntries: expectedFiles.size,
    checksumsSha256: sha256(rawChecksums)
  };
}

export async function signRelease({
  releaseDir,
  signerId,
  keyId,
  seedHex,
  revision = 1,
  versionOverride = null,
  issuedAt = new Date().toISOString(),
  expiresAt = new Date(Date.now() + 365 * 24 * 3600 * 1000).toISOString(),
  outputPath = null
}) {
  const resolvedDir = resolve(releaseDir);
  if (versionOverride !== null) {
    const releaseJsonFile = join(resolvedDir, 'RELEASE.json');
    const releaseData = JSON.parse(await readFile(releaseJsonFile, 'utf8'));
    releaseData.version = versionOverride;
    releaseData.engine = { ...releaseData.engine, version: versionOverride };
    await writeFile(releaseJsonFile, JSON.stringify(releaseData, null, 2) + '\n');
    const files = (await walkReleaseFiles(resolvedDir))
      .filter(path => path !== 'SHA256SUMS.txt' && path !== SIGNATURE_FILE)
      .sort();
    const lines = [];
    for (const relative of files) {
      const digest = sha256(await readFile(join(resolvedDir, ...relative.split('/'))));
      lines.push(`${digest}  ${relative}`);
    }
    await writeFile(join(resolvedDir, 'SHA256SUMS.txt'), lines.join('\n') + '\n');
  }

  const { checksumsSha256 } = await verifyChecksumTree(resolvedDir);
  const releaseBytes = await readFile(join(resolvedDir, 'RELEASE.json'));
  const release = JSON.parse(releaseBytes.toString('utf8'));
  const { privateKey, publicKeyHex } = ed25519KeyPairFromSeedHex(seedHex);

  const statement = {
    schema_version: ATTESTATION_SCHEMA,
    project: 'KeyHelix',
    algorithm: 'Ed25519',
    signer_id: signerId,
    key_id: keyId,
    public_key_hex: publicKeyHex,
    release_id: release.releaseId,
    version: release.version,
    revision: Number(revision),
    commit: release.source?.commit ?? '',
    tree_sha256: release.source?.treeSha256 ?? '',
    source_archive_path: release.source?.archive?.path ?? '',
    source_archive_sha256: release.source?.archive?.sha256 ?? '',
    release_json_sha256: sha256(releaseBytes),
    checksums_sha256: checksumsSha256,
    issued_at: issuedAt,
    expires_at: expiresAt
  };

  const payload = Buffer.from(canonicalAttestationPayload(statement), 'utf8');
  const signatureHex = sign(null, payload, privateKey).toString('hex');
  const attestation = {
    ...statement,
    signature_hex: signatureHex
  };

  const destination = outputPath ? resolve(outputPath) : join(resolvedDir, SIGNATURE_FILE);
  await writeFile(destination, JSON.stringify(attestation, null, 2) + '\n');
  return attestation;
}

export async function verifyRelease({
  releaseDir,
  trustedAuthority,
  minRevision = 1,
  now = new Date(),
  signaturePath = null,
  canary = null
}) {
  const resolvedDir = resolve(releaseDir);
  if (!trustedAuthority || typeof trustedAuthority.signer_id !== 'string' || typeof trustedAuthority.key_id !== 'string' || typeof trustedAuthority.public_key_hex !== 'string') {
    throw new ReleaseVerificationError(ErrorCodes.UNTRUSTED_SIGNER, 'missing-trusted-authority');
  }

  const sigFile = signaturePath ? resolve(signaturePath) : join(resolvedDir, SIGNATURE_FILE);
  if (!(await exists(sigFile))) {
    throw new ReleaseVerificationError(ErrorCodes.MISSING_SIGNATURE_EVIDENCE, SIGNATURE_FILE);
  }
  if (!(await exists(join(resolvedDir, 'RELEASE.json')))) {
    throw new ReleaseVerificationError(ErrorCodes.MISSING_SIGNATURE_EVIDENCE, 'RELEASE.json');
  }
  if (!(await exists(join(resolvedDir, 'SHA256SUMS.txt')))) {
    throw new ReleaseVerificationError(ErrorCodes.MISSING_SIGNATURE_EVIDENCE, 'SHA256SUMS.txt');
  }

  let attestation;
  try {
    attestation = JSON.parse(await readFile(sigFile, 'utf8'));
  } catch {
    throw new ReleaseVerificationError(ErrorCodes.SIGNATURE_INVALID, 'malformed-attestation-json');
  }

  if (
    attestation.schema_version !== ATTESTATION_SCHEMA ||
    attestation.algorithm !== 'Ed25519' ||
    typeof attestation.signature_hex !== 'string' ||
    !/^[a-f0-9]{128}$/i.test(attestation.signature_hex)
  ) {
    throw new ReleaseVerificationError(ErrorCodes.SIGNATURE_INVALID, 'invalid-attestation-envelope');
  }

  if (
    attestation.signer_id !== trustedAuthority.signer_id ||
    attestation.key_id !== trustedAuthority.key_id ||
    attestation.public_key_hex.toLowerCase() !== trustedAuthority.public_key_hex.toLowerCase()
  ) {
    throw new ReleaseVerificationError(ErrorCodes.UNTRUSTED_SIGNER, `${attestation.signer_id}:${attestation.key_id}`);
  }

  const publicKey = ed25519PublicKeyFromHex(trustedAuthority.public_key_hex);
  const payload = Buffer.from(canonicalAttestationPayload(attestation), 'utf8');
  const signatureBytes = Buffer.from(attestation.signature_hex, 'hex');
  if (!verify(null, payload, publicKey, signatureBytes)) {
    throw new ReleaseVerificationError(ErrorCodes.SIGNATURE_INVALID, 'ed25519-verify-failed');
  }

  const issuedTime = Date.parse(attestation.issued_at);
  const expiresTime = Date.parse(attestation.expires_at);
  const currentTime = now instanceof Date ? now.getTime() : Date.parse(String(now));
  if (!Number.isFinite(issuedTime) || !Number.isFinite(expiresTime) || expiresTime <= issuedTime || currentTime > expiresTime) {
    throw new ReleaseVerificationError(ErrorCodes.EXPIRED_ATTESTATION, attestation.expires_at);
  }

  if (!Number.isInteger(attestation.revision) || attestation.revision < 1 || attestation.revision < minRevision) {
    throw new ReleaseVerificationError(ErrorCodes.STALE_REVISION_REJECTED, `revision-${attestation.revision}-below-${minRevision}`);
  }

  const releaseBytes = await readFile(join(resolvedDir, 'RELEASE.json'));
  if (sha256(releaseBytes) !== attestation.release_json_sha256) {
    throw new ReleaseVerificationError(ErrorCodes.SIGNATURE_INVALID, 'release-manifest-digest-mismatch');
  }

  const { checksumEntries, checksumsSha256 } = await verifyChecksumTree(resolvedDir);
  if (checksumsSha256 !== attestation.checksums_sha256) {
    throw new ReleaseVerificationError(ErrorCodes.SIGNATURE_INVALID, 'checksums-digest-mismatch');
  }

  const release = JSON.parse(releaseBytes.toString('utf8'));
  if (
    release.project !== 'KeyHelix' ||
    release.license !== 'Apache-2.0' ||
    release.artifact?.webOnly !== false ||
    release.artifact?.engineIncluded !== true ||
    release.artifact?.sourceArchiveIncluded !== true ||
    release.artifact?.providerOwnedSecretBytes !== true ||
    release.artifact?.embeddedProviderState !== false
  ) {
    throw new ReleaseVerificationError(ErrorCodes.SIGNATURE_INVALID, 'release-capability-flags');
  }

  const archivePath = join(resolvedDir, ...(release.source?.archive?.path ?? '').split('/'));
  if (!(await exists(archivePath))) {
    throw new ReleaseVerificationError(ErrorCodes.MISSING_SIGNATURE_EVIDENCE, 'source-archive');
  }
  const archiveSha256 = sha256(await readFile(archivePath));
  if (archiveSha256 !== release.source.archive.sha256 || archiveSha256 !== attestation.source_archive_sha256) {
    throw new ReleaseVerificationError(ErrorCodes.CHECKSUM_MISMATCH, 'source-archive-sha256');
  }

  try {
    await scanForSecrets(resolvedDir);
  } catch (error) {
    throw new ReleaseVerificationError(ErrorCodes.SECRET_MATERIAL_DETECTED, error.message);
  }

  if (canary) {
    const canaryBytes = Buffer.from(String(canary), 'utf8');
    for (const relative of await walkReleaseFiles(resolvedDir)) {
      const content = await readFile(join(resolvedDir, ...relative.split('/')));
      if (content.includes(canaryBytes)) {
        throw new ReleaseVerificationError(ErrorCodes.SECRET_MATERIAL_DETECTED, `canary:${relative}`);
      }
    }
  }

  return {
    verified: true,
    signerId: attestation.signer_id,
    keyId: attestation.key_id,
    releaseId: attestation.release_id,
    version: attestation.version,
    revision: attestation.revision,
    commit: attestation.commit,
    checksumEntries,
    sourceArchivePath: release.source.archive.path,
    sourceArchiveSha256: archiveSha256,
    providerOwnsSecretBytes: true
  };
}

async function readManifestVersions(dataDir) {
  const manifestsDir = join(dataDir, 'manifests');
  if (!(await exists(manifestsDir))) return [];
  const entries = await readdir(manifestsDir, { withFileTypes: true });
  const versions = [];
  for (const entry of entries) {
    if (!entry.isFile()) {
      throw new ReleaseVerificationError(ErrorCodes.STALE_DATA_REJECTED, `irregular-manifest:${entry.name}`);
    }
    const match = /^manifest-(\d{20})\.json$/.exec(entry.name);
    if (!match) {
      throw new ReleaseVerificationError(ErrorCodes.STALE_DATA_REJECTED, `invalid-manifest-name:${entry.name}`);
    }
    const version = Number(BigInt(match[1]));
    const raw = JSON.parse(await readFile(join(manifestsDir, entry.name), 'utf8'));
    if (raw.schema_version !== 1 || raw.manifest_version !== version) {
      throw new ReleaseVerificationError(ErrorCodes.STALE_DATA_REJECTED, `corrupt-manifest:${entry.name}`);
    }
    versions.push({ version, records: Array.isArray(raw.records) ? raw.records.length : 0, raw });
  }
  versions.sort((a, b) => a.version - b.version);
  return versions;
}

async function syncDir(directory) {
  const handle = await open(directory, 'r');
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

export async function readHostAuthorityState(hostRoot) {
  const statePath = join(resolve(hostRoot), 'authority-state.json');
  if (!(await exists(statePath))) {
    return {
      schema_version: 1,
      active_slot: null,
      previous_slot: null,
      active_version: null,
      highest_accepted_revision: 0,
      highest_manifest_version: 0,
      history: []
    };
  }
  return JSON.parse(await readFile(statePath, 'utf8'));
}

async function writeHostAuthorityState(hostRoot, state) {
  const root = resolve(hostRoot);
  await mkdir(root, { recursive: true });
  const tempPath = join(root, `.authority-state.${process.pid}.${Date.now()}.tmp`);
  const finalPath = join(root, 'authority-state.json');
  await writeFile(tempPath, JSON.stringify(state, null, 2) + '\n');
  await rename(tempPath, finalPath);
  await syncDir(root);
}

export async function recordDurableDataProgress(hostRoot, dataDir) {
  const state = await readHostAuthorityState(hostRoot);
  const versions = await readManifestVersions(resolve(dataDir));
  const latest = versions.at(-1)?.version ?? 0;
  if (latest < state.highest_manifest_version) {
    throw new ReleaseVerificationError(
      ErrorCodes.STALE_DATA_REJECTED,
      `manifest-${latest}-below-${state.highest_manifest_version}`
    );
  }
  state.highest_manifest_version = latest;
  await writeHostAuthorityState(hostRoot, state);
  return {
    highestManifestVersion: latest,
    recordCount: versions.at(-1)?.records ?? 0
  };
}

export async function installOrUpgradeRelease({
  hostRoot,
  slot,
  sourceReleaseDir,
  trustedAuthority,
  dataDir,
  now = new Date()
}) {
  const resolvedHost = resolve(hostRoot);
  const resolvedData = resolve(dataDir);
  await mkdir(join(resolvedHost, 'releases'), { recursive: true });
  await mkdir(resolvedData, { recursive: true });

  const state = await readHostAuthorityState(resolvedHost);
  const versionsBefore = await readManifestVersions(resolvedData);
  const currentManifestVersion = versionsBefore.at(-1)?.version ?? 0;
  if (currentManifestVersion < state.highest_manifest_version) {
    throw new ReleaseVerificationError(
      ErrorCodes.STALE_DATA_REJECTED,
      `manifest-${currentManifestVersion}-below-accepted-${state.highest_manifest_version}`
    );
  }

  const minRevision = state.highest_accepted_revision + 1;
  const verified = await verifyRelease({
    releaseDir: sourceReleaseDir,
    trustedAuthority,
    minRevision,
    now
  });

  const targetSlotDir = join(resolvedHost, 'releases', slot);
  const stageSlotDir = join(resolvedHost, 'releases', `.stage-${slot}-${Date.now()}`);
  await rm(stageSlotDir, { recursive: true, force: true });
  await cp(resolve(sourceReleaseDir), stageSlotDir, { recursive: true, dereference: false, force: true });

  await verifyRelease({
    releaseDir: stageSlotDir,
    trustedAuthority,
    minRevision,
    now
  });

  await rm(targetSlotDir, { recursive: true, force: true });
  await rename(stageSlotDir, targetSlotDir);
  await syncDir(join(resolvedHost, 'releases'));

  const nextState = {
    schema_version: 1,
    active_slot: slot,
    previous_slot: state.active_slot,
    active_version: verified.version,
    active_revision: verified.revision,
    highest_accepted_revision: verified.revision,
    highest_manifest_version: Math.max(state.highest_manifest_version, currentManifestVersion),
    updated_at: (now instanceof Date ? now : new Date(now)).toISOString(),
    history: [
      ...(state.history ?? []),
      {
        action: state.active_slot ? 'upgrade' : 'install',
        slot,
        version: verified.version,
        revision: verified.revision,
        manifest_version: Math.max(state.highest_manifest_version, currentManifestVersion)
      }
    ]
  };
  await writeHostAuthorityState(resolvedHost, nextState);
  return {
    action: state.active_slot ? 'upgrade' : 'install',
    slot,
    slotDir: targetSlotDir,
    version: verified.version,
    revision: verified.revision,
    manifestVersion: nextState.highest_manifest_version,
    records: versionsBefore.at(-1)?.records ?? 0
  };
}

export async function rollbackRelease({
  hostRoot,
  targetSlot = null,
  trustedAuthority,
  dataDir,
  now = new Date()
}) {
  const resolvedHost = resolve(hostRoot);
  const resolvedData = resolve(dataDir);
  const state = await readHostAuthorityState(resolvedHost);
  const rollbackSlot = targetSlot ?? state.previous_slot;
  if (!rollbackSlot) {
    throw new ReleaseVerificationError(ErrorCodes.STALE_REVISION_REJECTED, 'no-previous-slot');
  }

  const versionsNow = await readManifestVersions(resolvedData);
  const currentManifestVersion = versionsNow.at(-1)?.version ?? 0;
  if (currentManifestVersion < state.highest_manifest_version) {
    throw new ReleaseVerificationError(
      ErrorCodes.STALE_DATA_REJECTED,
      `rollback-cannot-discard-manifest-${state.highest_manifest_version}`
    );
  }

  const slotDir = join(resolvedHost, 'releases', rollbackSlot);
  const verified = await verifyRelease({
    releaseDir: slotDir,
    trustedAuthority,
    minRevision: 1,
    now
  });

  const nextState = {
    ...state,
    active_slot: rollbackSlot,
    previous_slot: state.active_slot,
    active_version: verified.version,
    active_revision: verified.revision,
    highest_manifest_version: currentManifestVersion,
    updated_at: (now instanceof Date ? now : new Date(now)).toISOString(),
    history: [
      ...(state.history ?? []),
      {
        action: 'rollback',
        slot: rollbackSlot,
        version: verified.version,
        revision: verified.revision,
        preserved_manifest_version: currentManifestVersion
      }
    ]
  };
  await writeHostAuthorityState(resolvedHost, nextState);
  return {
    action: 'rollback',
    slot: rollbackSlot,
    slotDir,
    version: verified.version,
    revision: verified.revision,
    highestAcceptedRevision: state.highest_accepted_revision,
    preservedManifestVersion: currentManifestVersion,
    preservedRecords: versionsNow.at(-1)?.records ?? 0
  };
}

export async function verifySourceBuildAlternative({
  releaseDir,
  workDir,
  requiredFiles = []
}) {
  const resolvedRelease = resolve(releaseDir);
  const resolvedWork = resolve(workDir);
  await mkdir(resolvedWork, { recursive: true });

  const release = JSON.parse(await readFile(join(resolvedRelease, 'RELEASE.json'), 'utf8'));
  const archiveRel = release.source?.archive?.path;
  if (!archiveRel) {
    throw new ReleaseVerificationError(ErrorCodes.SOURCE_BUILD_INVALID, 'missing-archive-path');
  }
  const archiveFull = join(resolvedRelease, ...archiveRel.split('/'));
  const archiveBytes = await readFile(archiveFull);
  if (sha256(archiveBytes) !== release.source.archive.sha256) {
    throw new ReleaseVerificationError(ErrorCodes.CHECKSUM_MISMATCH, archiveRel);
  }

  const extractResult = spawnSync('tar', ['-xzf', archiveFull, '-C', resolvedWork], {
    encoding: 'utf8',
    timeout: 60000
  });
  if (extractResult.status !== 0) {
    throw new ReleaseVerificationError(ErrorCodes.SOURCE_BUILD_INVALID, extractResult.stderr || 'tar-extract-failed');
  }

  const extractedDir = join(resolvedWork, `keyhelix-${release.source.shortCommit}`);
  for (const required of requiredFiles) {
    const candidate = join(extractedDir, ...required.split('/'));
    if (!(await exists(candidate))) {
      throw new ReleaseVerificationError(ErrorCodes.SOURCE_BUILD_INVALID, `missing:${required}`);
    }
  }

  const outputBinary = join(resolvedWork, 'keyhelix-from-source');
  const env = {
    ...process.env,
    PATH: `/usr/local/go/bin:${process.env.PATH ?? ''}`,
    GOFLAGS: '-buildvcs=false'
  };
  const buildResult = spawnSync('go', ['build', '-buildvcs=false', '-o', outputBinary, './cmd/keyhelix'], {
    cwd: extractedDir,
    encoding: 'utf8',
    timeout: 180000,
    env
  });
  if (buildResult.status !== 0) {
    throw new ReleaseVerificationError(ErrorCodes.SOURCE_BUILD_INVALID, buildResult.stderr || 'go-build-failed');
  }

  const versionResult = spawnSync(outputBinary, ['--version'], {
    cwd: extractedDir,
    encoding: 'utf8',
    timeout: 15000
  });
  if (versionResult.status !== 0) {
    throw new ReleaseVerificationError(ErrorCodes.SOURCE_BUILD_INVALID, 'source-binary-version-failed');
  }
  const versionInfo = JSON.parse(versionResult.stdout.trim());
  return {
    built: true,
    extractedDir,
    binaryPath: outputBinary,
    binarySha256: sha256(await readFile(outputBinary)),
    versionInfo
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    const args = process.argv.slice(2);
    let releaseDir = 'dist/release';
    let trustedFile = null;
    let minRevision = 1;
    for (let i = 0; i < args.length; i += 2) {
      if (args[i] === '--release-dir' && args[i + 1]) releaseDir = args[i + 1];
      else if (args[i] === '--trusted-authority' && args[i + 1]) trustedFile = args[i + 1];
      else if (args[i] === '--min-revision' && args[i + 1]) minRevision = Number(args[i + 1]);
      else throw new Error('Usage: node scripts/verify-release.mjs --release-dir <dir> --trusted-authority <json> [--min-revision <n>]');
    }
    if (!trustedFile) {
      throw new Error('Usage: node scripts/verify-release.mjs --release-dir <dir> --trusted-authority <json> [--min-revision <n>]');
    }
    const rawTrusted = JSON.parse(await readFile(resolve(trustedFile), 'utf8'));
    const trustedAuthority = rawTrusted.trusted_authority ?? rawTrusted;
    const result = await verifyRelease({ releaseDir, trustedAuthority, minRevision });
    console.log(JSON.stringify(result, null, 2));
  } catch (error) {
    console.error(error.code ? `${error.code}:${error.detail}` : error.message);
    process.exitCode = 1;
  }
}
