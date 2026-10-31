import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { lstat, mkdir, open, readdir, readFile, rename, rm, stat, writeFile } from 'node:fs/promises';
import { gzipSync } from 'node:zlib';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const repository = fileURLToPath(new URL('../', import.meta.url));
const RELEASE_SCHEMA = 1;
const SOURCE_PREFIX = 'keyhelix-';

export const ALLOWED_LICENSES = new Set(['Apache-2.0', 'MIT', 'BSD-2-Clause', 'BSD-3-Clause', 'ISC', 'MPL-2.0']);
export const RUNTIME_PACKAGES = ['react', 'react-dom', 'scheduler'];
export const SOURCE_EXCLUDED_SEGMENTS = new Set(['.git', 'node_modules', 'dist', '.local-data', 'test-results', 'playwright-report', '.cache', '__pycache__', 'coverage']);

const sha256 = value => createHash('sha256').update(value).digest('hex');
const sha256File = async file => sha256(await readFile(file));
const exists = async path => { try { await lstat(path); return true; } catch { return false; } };

const npmPurl = (name, version) => {
  const parts = name.split('/');
  if (name.startsWith('@') && parts.length === 2) return `pkg:npm/${encodeURIComponent(parts[0])}/${encodeURIComponent(parts[1])}@${encodeURIComponent(version)}`;
  return `pkg:npm/${encodeURIComponent(name)}@${encodeURIComponent(version)}`;
};

const providerPurl = provider => `pkg:oci/${encodeURIComponent(provider.id)}@${encodeURIComponent(provider.version)}?repository_url=${encodeURIComponent(provider.image)}&digest=${encodeURIComponent(provider.digest)}`;

export function uuidV5(name, namespace = '6ba7b810-9dad-11d1-80b4-00c04fd430c8') {
  const bytes = Buffer.from(namespace.replace(/-/g, ''), 'hex');
  const digest = createHash('sha1').update(bytes).update(Buffer.from(name, 'utf8')).digest();
  const uuid = Buffer.from(digest.subarray(0, 16));
  uuid[6] = (uuid[6] & 0x0f) | 0x50;
  uuid[8] = (uuid[8] & 0x3f) | 0x80;
  const hex = uuid.toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

export function collectNpmComponents(lock) {
  const found = new Map();
  for (const [key, entry] of Object.entries(lock.packages ?? {})) {
    if (!key || !entry || typeof entry.version !== 'string') continue;
    const marker = 'node_modules/';
    const markerIndex = key.lastIndexOf(marker);
    if (markerIndex < 0) continue;
    const name = key.slice(markerIndex + marker.length);
    if (!name || name.includes('node_modules/')) continue;
    const license = typeof entry.license === 'string' ? entry.license : entry.license?.type;
    if (!ALLOWED_LICENSES.has(license)) {
      throw new Error(`package-error: unknown-license:${name}@${entry.version}:${license ?? 'missing'}`);
    }
    const purl = npmPurl(name, entry.version);
    if (!found.has(purl)) found.set(purl, {
      type: 'library',
      name,
      version: entry.version,
      purl,
      license,
      dev: Boolean(entry.dev),
      scope: entry.dev ? 'excluded' : 'required'
    });
  }
  return [...found.values()].sort((a, b) => a.purl < b.purl ? -1 : a.purl > b.purl ? 1 : 0);
}

export function collectProviderComponents(providerLock) {
  if (!providerLock || providerLock.schema_version !== 1 || !Array.isArray(providerLock.providers) || providerLock.providers.length === 0) {
    throw new Error('package-error: invalid-provider-lock');
  }
  return providerLock.providers.map(provider => {
    if (!provider || !/^[a-z][a-z0-9-]+$/.test(provider.id) || typeof provider.version !== 'string' || !/^sha256:[a-f0-9]{64}$/.test(provider.digest) || typeof provider.image !== 'string') {
      throw new Error('package-error: invalid-provider-entry');
    }
    if (!ALLOWED_LICENSES.has(provider.license)) {
      throw new Error(`package-error: unknown-license:${provider.id}:${provider.license ?? 'missing'}`);
    }
    return {
      type: 'container',
      name: provider.id,
      version: provider.version,
      purl: providerPurl(provider),
      license: provider.license,
      scope: 'required',
      digest: provider.digest,
      image: provider.image,
      sourceUrl: provider.source_url ?? null,
      licenseUrl: provider.license_url ?? null,
      docsUrl: provider.docs_url ?? null
    };
  }).sort((a, b) => a.purl < b.purl ? -1 : a.purl > b.purl ? 1 : 0);
}

const licenseObject = license => [{ license: { id: license } }];

export function buildSbom({ commit, treeSha256, packageJson, lock, providerLock, timestamp }) {
  const npm = collectNpmComponents(lock);
  const providers = collectProviderComponents(providerLock);
  if (!/^[a-f0-9]{40}$/.test(commit)) throw new Error('package-error: invalid-commit');
  if (!/^[a-f0-9]{64}$/.test(treeSha256)) throw new Error('package-error: invalid-source-tree');
  for (const required of RUNTIME_PACKAGES) {
    if (!npm.some(component => component.name === required && component.scope === 'required')) {
      throw new Error(`package-error: missing-runtime-component:${required}`);
    }
  }
  const appRef = `pkg:generic/keyhelix@${encodeURIComponent(packageJson.version)}`;
  const app = {
    type: 'application',
    'bom-ref': appRef,
    name: 'KeyHelix',
    version: packageJson.version,
    licenses: licenseObject('Apache-2.0')
  };
  const components = [...npm, ...providers].map(component => ({
    type: component.type,
    'bom-ref': component.purl,
    name: component.name,
    version: component.version,
    purl: component.purl,
    scope: component.scope,
    licenses: licenseObject(component.license),
    ...(component.digest ? { properties: [
      { name: 'keyhelix:provider:image', value: component.image },
      { name: 'keyhelix:provider:digest', value: component.digest },
      { name: 'keyhelix:provider:embedded', value: 'false' },
      ...(component.sourceUrl ? [{ name: 'keyhelix:provider:source', value: component.sourceUrl }] : []),
      ...(component.licenseUrl ? [{ name: 'keyhelix:provider:license', value: component.licenseUrl }] : [])
    ] } : {})
  }));
  const requiredRefs = [...npm.filter(component => component.scope === 'required').map(component => component.purl), ...providers.map(component => component.purl)];
  const dependencies = [
    { ref: appRef, dependsOn: requiredRefs },
    ...components.map(component => ({ ref: component['bom-ref'], dependsOn: [] }))
  ];
  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    serialNumber: `urn:uuid:${uuidV5(`keyhelix:${commit}:${treeSha256}`)}`,
    version: 1,
    metadata: {
      timestamp,
      tools: [{ vendor: 'KeyHelix', name: 'package-source.mjs', version: packageJson.version }],
      component: app,
      properties: [
        { name: 'keyhelix:source:commit', value: commit },
        { name: 'keyhelix:source:tree', value: treeSha256 },
        { name: 'keyhelix:artifact:web-only', value: 'false' },
        { name: 'keyhelix:provider:secret-ownership', value: 'provider-owned' }
      ]
    },
    components,
    dependencies
  };
}

const escapeCell = value => String(value ?? '').replace(/\|/g, '\\|');

export function renderNotices({ packageJson, lock, providerLock, toolchain, artifact = false, licenseTexts = [] }) {
  const npm = collectNpmComponents(lock);
  const providers = collectProviderComponents(providerLock);
  const resources = Array.isArray(toolchain?.resources) ? toolchain.resources : [];
  const counts = npm.reduce((result, component) => {
    result[component.license] = (result[component.license] ?? 0) + 1;
    return result;
  }, {});
  const lines = [
    '# Third-party inventory',
    '',
    'Generated from `package-lock.json`, `ops/providers.lock.json` and `docs/engineering/toolchain-lock.json`.',
    'Do not edit by hand; run `npm run notices`. This inventory is not a replacement for the license texts',
    'included with a release artifact under `notices/licenses/`.',
    '',
    `Project license: Apache-2.0. npm components: ${npm.length}. Provider containers: ${providers.length}.`,
    '',
    '## npm packages',
    '',
    '| Resource | Version | Declared license | Distribution |',
    '| --- | --- | --- | --- |'
  ];
  for (const component of npm) {
    lines.push(`| \`${escapeCell(component.name)}\` | ${escapeCell(component.version)} | ${component.license} | ${component.dev ? 'build/test only; not distributed' : 'distributed runtime'} |`);
  }
  lines.push('', '## Provider containers', '', 'These services are pulled by the operator from pinned immutable digests. Their image blobs are not embedded in the release artifact.', '', '| Resource | Version | Digest | Declared license | License source | Distribution |', '| --- | --- | --- | --- | --- | --- |');
  for (const provider of providers) {
    lines.push(`| \`${escapeCell(provider.name)}\` | ${escapeCell(provider.version)} | \`${provider.digest}\` | ${provider.license} | ${escapeCell(provider.licenseUrl ?? 'not recorded')} | external service; not embedded |`);
  }
  lines.push('', '## Toolchain and build prerequisites', '', '| Resource | Version | Declared license | License source | Distribution |', '| --- | --- | --- | --- | --- |');
  for (const resource of resources) {
    lines.push(`| \`${escapeCell(resource.id)}\` | ${escapeCell(resource.version)} | ${escapeCell(resource.license)} | ${escapeCell(resource.license_url ?? 'not recorded')} | build prerequisite; not embedded |`);
  }
  lines.push('', '## Declaration', '', 'KeyHelix source is Apache-2.0. OpenBao and Keycloak keep their upstream licenses and are not relicensed or repackaged by this project. No unknown or restricted required resource is accepted by the packaging gate.');
  if (artifact) {
    lines.push('', '## Distributed license texts', '', 'Complete license texts for distributed npm components are included in this artifact:', '', '| Component | Version | Artifact path |', '| --- | --- | --- |');
    for (const text of licenseTexts) {
      lines.push(`| \`${escapeCell(text.name)}\` | ${escapeCell(text.version)} | \`${text.path}\` |`);
    }
  }
  lines.push('', `License summary: ${Object.entries(counts).sort(([a], [b]) => a.localeCompare(b)).map(([license, count]) => `${license}=${count}`).join(', ')}.`, '');
  return lines.join('\n');
}

export function selectSourceFiles(input) {
  const names = Array.isArray(input) ? input : [];
  const selected = [];
  for (const value of names) {
    const path = String(value).replaceAll('\\', '/');
    if (!path || path.includes('\0') || path.startsWith('/')) continue;
    const parts = path.split('/').filter(Boolean);
    if (parts.length === 0 || parts.some(part => SOURCE_EXCLUDED_SEGMENTS.has(part))) continue;
    if (path.startsWith('docs/evidence/')) continue;
    const name = parts.at(-1);
    if (name === '.env' || (name.startsWith('.env.') && name !== '.env.example') || name === 'runtime.json' || name === 'init.json' || name === 'id_rsa' || /\.(?:pem|key|p12|pfx)$/i.test(name)) continue;
    if (!selected.includes(path)) selected.push(path);
  }
  return selected.sort();
}

function git(root, args) {
  const result = spawnSync('git', args, { cwd: root, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, timeout: 120000 });
  if (result.error || result.status !== 0) {
    throw new Error(`package-error: git-${args[0]}:${(result.stderr ?? result.error?.message ?? '').trim()}`);
  }
  return result.stdout;
}

export async function sourceInventory(root) {
  const commit = git(root, ['log', '-1', '--format=%H']).trim();
  const epoch = Number(git(root, ['log', '-1', '--format=%ct']).trim());
  const dirty = git(root, ['status', '--porcelain', '--untracked-files=normal']).trim() !== '';
  if (!/^[a-f0-9]{40}$/.test(commit) || !Number.isFinite(epoch)) throw new Error('package-error: invalid-git-provenance');
  const files = selectSourceFiles(git(root, ['ls-files', '-z', '--cached', '--others', '--exclude-standard']).split('\0').filter(Boolean));
  const hash = createHash('sha256');
  for (const path of files) {
    const file = join(root, ...path.split('/'));
    const info = await lstat(file);
    if (!info.isFile() || info.isSymbolicLink()) throw new Error(`package-error: invalid-source-file:${path}`);
    hash.update(path).update('\0').update(createHash('sha256').update(await readFile(file)).digest());
  }
  return { commit, epoch, dirty, files, treeSha256: hash.digest('hex') };
}

export async function buildSourceArchive({ root, stage, inventory }) {
  const short = inventory.commit.slice(0, 12);
  const destination = join(stage, 'source');
  await mkdir(destination, { recursive: true });
  const relative = `source/${SOURCE_PREFIX}${short}.tar.gz`;
  const output = join(stage, ...relative.split('/'));
  const result = spawnSync('tar', [
    '--format=gnu',
    '--sort=name',
    `--mtime=@${inventory.epoch}`,
    '--owner=0',
    '--group=0',
    '--numeric-owner',
    '--no-acl',
    '--no-xattrs',
    `--transform=s|^|${SOURCE_PREFIX}${short}/|`,
    '--null',
    '--files-from=-',
    '--create',
    '--file=-'
  ], {
    cwd: root,
    input: inventory.files.join('\0') + '\0',
    maxBuffer: 256 * 1024 * 1024,
    timeout: 120000
  });
  if (result.error || result.status !== 0) {
    throw new Error(`package-error: source-archive:${(result.stderr?.toString() ?? result.error?.message ?? '').trim()}`);
  }
  const bytes = gzipSync(result.stdout, { level: 9 });
  await writeFile(output, bytes);
  return { path: relative, sha256: sha256(bytes), bytes: bytes.length, fileCount: inventory.files.length };
}

async function copyRuntimeLicenseTexts({ root, stage }) {
  const directory = join(stage, 'notices', 'licenses');
  await mkdir(directory, { recursive: true });
  const texts = [];
  for (const name of RUNTIME_PACKAGES) {
    const sourceDirectory = join(root, 'node_modules', name);
    let candidates;
    try {
      candidates = (await readdir(sourceDirectory)).filter(file => /^(?:LICEN[CS]E|COPYING)(?:\..*)?$/i.test(file)).sort();
    } catch {
      throw new Error(`package-error: missing-license-text:${name}`);
    }
    if (!candidates.length) throw new Error(`package-error: missing-license-text:${name}`);
    const content = await readFile(join(sourceDirectory, candidates[0]));
    const fileName = `${name.replace(/[^a-z0-9.-]/gi, '-')}-LICENSE.txt`;
    await writeFile(join(directory, fileName), content);
    texts.push({ name, version: JSON.parse(await readFile(join(sourceDirectory, 'package.json'), 'utf8')).version, path: `notices/licenses/${fileName}`, sha256: sha256(content) });
  }
  return texts;
}

async function walkFiles(root, prefix = '') {
  const files = [];
  for (const entry of (await readdir(root, { withFileTypes: true })).sort((a, b) => a.name.localeCompare(b.name))) {
    const relative = prefix ? prefix + '/' + entry.name : entry.name;
    if (entry.isDirectory()) files.push(...await walkFiles(join(root, entry.name), relative));
    else files.push(relative);
  }
  return files;
}

async function writeChecksums(stage) {
  const files = (await walkFiles(stage)).filter(path => path !== 'SHA256SUMS.txt').sort();
  const entries = [];
  for (const path of files) entries.push(`${await sha256File(join(stage, ...path.split('/')))}  ${path}`);
  await writeFile(join(stage, 'SHA256SUMS.txt'), entries.join('\n') + '\n');
  for (const line of entries) {
    const [expected, path] = line.split('  ');
    const actual = await sha256File(join(stage, ...path.split('/')));
    if (actual !== expected) throw new Error(`package-error: checksum-mismatch:${path}`);
  }
  return entries.length;
}

async function syncDirectory(path) {
  const handle = await open(path, 'r');
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

export async function publishRelease({ stage, dest }) {
  const destination = resolve(dest);
  const previous = destination + '.previous';
  const parent = dirname(destination);
  await mkdir(parent, { recursive: true });
  if (!await exists(destination) && await exists(previous)) await rename(previous, destination);
  if (await exists(destination)) {
    const info = await lstat(destination);
    if (!info.isDirectory()) throw new Error('package-error: destination-not-directory');
    if (await exists(previous)) await rm(previous, { recursive: true, force: true });
    await rename(destination, previous);
  }
  try {
    await rename(stage, destination);
    await syncDirectory(parent);
  } catch (error) {
    if (!await exists(destination) && await exists(previous)) await rename(previous, destination);
    throw new Error(`package-error: publish-failed:${error.message}`);
  }
  return { destination, previous };
}

const engineVersion = (stage, root) => {
  const binary = join(stage, 'dist', 'engine', 'keyhelix');
  const result = spawnSync(binary, ['--version'], { cwd: root, encoding: 'utf8', timeout: 10000 });
  if (result.error || result.status !== 0) throw new Error('package-error: engine-not-runnable');
  try {
    return JSON.parse(result.stdout.trim());
  } catch {
    throw new Error('package-error: engine-version-invalid');
  }
};

const commandVersion = (command, args, root) => {
  const result = spawnSync(command, args, { cwd: root, encoding: 'utf8', timeout: 10000 });
  return result.status === 0 ? result.stdout.trim() : null;
};

export async function buildRelease({ root = repository, stage, dest = join(root, 'dist', 'release') }) {
  const destination = resolve(dest);
  const staging = resolve(stage);
  const required = ['web/index.html', 'dist/engine/keyhelix', 'RESOURCES.json', 'docs/release/ARTIFACTS.md'];
  for (const path of required) {
    try {
      if (!(await stat(join(staging, ...path.split('/')))).isFile()) throw new Error();
    } catch {
      throw new Error(`package-error: missing-stage-file:${path}`);
    }
  }

  const [packageJson, lock, providerLock, toolchain, resources] = await Promise.all([
    JSON.parse(await readFile(join(root, 'package.json'), 'utf8')),
    JSON.parse(await readFile(join(root, 'package-lock.json'), 'utf8')),
    JSON.parse(await readFile(join(root, 'ops', 'providers.lock.json'), 'utf8')),
    JSON.parse(await readFile(join(root, 'docs', 'engineering', 'toolchain-lock.json'), 'utf8')),
    JSON.parse(await readFile(join(staging, 'RESOURCES.json'), 'utf8'))
  ]);
  if (packageJson.license !== 'Apache-2.0') throw new Error('package-error: project-license-invalid');
  if (!Array.isArray(resources.resources) || resources.resources.length === 0) throw new Error('package-error: resources-missing');

  const inventory = await sourceInventory(root);
  const source = await buildSourceArchive({ root, stage: staging, inventory });
  const timestamp = new Date(inventory.epoch * 1000).toISOString();
  const sbom = buildSbom({ commit: inventory.commit, treeSha256: inventory.treeSha256, packageJson, lock, providerLock, timestamp });
  const sbomPath = `sbom/keyhelix-${packageJson.version}.cdx.json`;
  await mkdir(join(staging, 'sbom'), { recursive: true });
  await writeFile(join(staging, ...sbomPath.split('/')), JSON.stringify(sbom, null, 2) + '\n');

  const licenseTexts = await copyRuntimeLicenseTexts({ root, stage: staging });
  const notices = renderNotices({ packageJson, lock, providerLock, toolchain, artifact: true, licenseTexts });
  await writeFile(join(staging, 'THIRD_PARTY_NOTICES.md'), notices.endsWith('\n') ? notices : notices + '\n');

  const engine = engineVersion(staging, root);
  const npmComponents = collectNpmComponents(lock);
  const providers = collectProviderComponents(providerLock);
  const resourcesBytes = await readFile(join(staging, 'RESOURCES.json'));
  const artifact = {
    webOnly: false,
    engineIncluded: true,
    offlineResourcesIncluded: true,
    sourceArchiveIncluded: true,
    sbomIncluded: true,
    providerOwnedSecretBytes: true,
    embeddedProviderState: false,
    signed: false,
    published: false
  };
  const release = {
    schema_version: RELEASE_SCHEMA,
    project: 'KeyHelix',
    releaseId: `${inventory.commit.slice(0, 12)}${inventory.dirty ? '-dirty' : ''}`,
    version: packageJson.version,
    license: packageJson.license,
    scope: 'complete-local-product',
    source: {
      commit: inventory.commit,
      shortCommit: inventory.commit.slice(0, 12),
      dirty: inventory.dirty,
      treeSha256: inventory.treeSha256,
      fileCount: inventory.files.length,
      timestamp,
      archive: source
    },
    build: {
      node: process.version,
      npm: commandVersion('npm', ['--version'], root),
      goDriver: commandVersion('go', ['version'], root),
      engineToolchain: engine.toolchain ?? null,
      platform: `${process.platform}/${process.arch === 'x64' ? 'amd64' : process.arch}`
    },
    engine,
    artifact,
    providers: providers.map(provider => ({ id: provider.name, image: provider.image, version: provider.version, digest: provider.digest, license: provider.license, embedded: false })),
    components: {
      npm: npmComponents.length,
      npmRuntime: npmComponents.filter(component => component.scope === 'required').length,
      providers: providers.length
    },
    resources: {
      path: 'RESOURCES.json',
      count: resources.resources.length,
      sha256: sha256(resourcesBytes),
      rules: resources.rules
    },
    sbom: {
      path: sbomPath,
      sha256: await sha256File(join(staging, ...sbomPath.split('/'))),
      components: sbom.components.length
    },
    notices: {
      path: 'THIRD_PARTY_NOTICES.md',
      sha256: await sha256File(join(staging, 'THIRD_PARTY_NOTICES.md')),
      licenseTexts
    },
    files: {
      checksumFile: 'SHA256SUMS.txt'
    },
    verification: {
      commands: ['sha256sum -c SHA256SUMS.txt', 'npm run test:release', 'go test ./...'],
      limitations: [
        'Publication, signatures, installed-host service proof and the full provider workflow from installed artifacts are C39/C40 work.',
        'Byte-for-byte reproducibility is verified for the recorded host and toolchain; cross-host builds are not claimed.',
        'A dirty source tree is recorded explicitly and must be rebuilt from a clean commit before publication.'
      ]
    }
  };
  await writeFile(join(staging, 'RELEASE.json'), JSON.stringify(release, null, 2) + '\n');
  const checksumEntries = await writeChecksums(staging);

  const pause = Number(process.env.KEYHELIX_PACKAGE_TEST_PAUSE_BEFORE_PUBLISH_MS ?? 0);
  if (Number.isFinite(pause) && pause > 0) await new Promise(resolvePause => setTimeout(resolvePause, Math.min(pause, 300000)));

  const published = await publishRelease({ stage: staging, dest: destination });
  return { ...published, releaseId: release.releaseId, checksumEntries, engine: release.engine, sbomComponents: release.sbom.components, resources: release.resources.count };
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    const args = process.argv.slice(2);
    if (args.includes('--write-notices')) {
      const root = repository;
      const [packageJson, lock, providerLock, toolchain] = await Promise.all([
        JSON.parse(await readFile(join(root, 'package.json'), 'utf8')),
        JSON.parse(await readFile(join(root, 'package-lock.json'), 'utf8')),
        JSON.parse(await readFile(join(root, 'ops', 'providers.lock.json'), 'utf8')),
        JSON.parse(await readFile(join(root, 'docs', 'engineering', 'toolchain-lock.json'), 'utf8'))
      ]);
      const notices = renderNotices({ packageJson, lock, providerLock, toolchain });
      await writeFile(join(root, 'THIRD_PARTY_NOTICES.md'), notices.endsWith('\n') ? notices : notices + '\n');
      console.log('Wrote THIRD_PARTY_NOTICES.md from the committed locks.');
    } else {
      let stage = null;
      let dest = null;
      for (let i = 0; i < args.length; i += 2) {
        if (args[i] === '--stage' && args[i + 1]) stage = args[i + 1];
        else if (args[i] === '--dest' && args[i + 1]) dest = args[i + 1];
        else throw new Error('Usage: node scripts/package-source.mjs --stage <staged-release> [--dest <release-directory>]');
      }
      if (!stage) throw new Error('Usage: node scripts/package-source.mjs --stage <staged-release> [--dest <release-directory>]');
      console.log(JSON.stringify(await buildRelease({ stage, ...(dest ? { dest } : {}) }), null, 2));
    }
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
