import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import { access, mkdtemp, mkdir, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises';
import { once } from 'node:events';
import { createServer } from 'node:net';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';

const root = fileURLToPath(new URL('../../', import.meta.url));
const packageJson = JSON.parse(await readFile(join(root, 'package.json'), 'utf8'));
const providerLock = JSON.parse(await readFile(join(root, 'ops', 'providers.lock.json'), 'utf8'));
const positive = JSON.parse(await readFile(join(root, 'tests', 'fixtures', 'keyhelix', 'C31', 'positive.json'), 'utf8'));
const negative = JSON.parse(await readFile(join(root, 'tests', 'fixtures', 'keyhelix', 'C31', 'negative.json'), 'utf8'));
const expected = JSON.parse(await readFile(join(root, 'tests', 'fixtures', 'keyhelix', 'C31', 'expected-output.json'), 'utf8'));

const sha256 = value => createHash('sha256').update(value).digest('hex');
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

async function walk(directory, prefix = '') {
  const files = [];
  for (const entry of (await readdir(directory, { withFileTypes: true })).sort((a, b) => a.name.localeCompare(b.name))) {
    const relative = prefix ? prefix + '/' + entry.name : entry.name;
    if (entry.isDirectory()) files.push(...await walk(join(directory, entry.name), relative));
    else files.push(relative);
  }
  return files;
}

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
  return mkdtemp(join(root, 'dist', '.package-test-'));
}

function runPackage({ dest, env = {}, timeout = 300000 }) {
  return spawnSync('bash', ['scripts/package.sh'], {
    cwd: root,
    encoding: 'utf8',
    timeout,
    maxBuffer: 8 * 1024 * 1024,
    env: { ...process.env, KEYHELIX_PACKAGE_SKIP_BUILD: '1', KEYHELIX_RELEASE_DIR: dest, ...env }
  });
}

function buildOnce() {
  const result = spawnSync('npm', ['run', 'build'], {
    cwd: root,
    encoding: 'utf8',
    timeout: 300000,
    stdio: 'inherit',
    env: { ...process.env, GOFLAGS: `${process.env.GOFLAGS ?? ''} -buildvcs=false`.trim() }
  });
  assert.equal(result.status, 0, 'initial build must pass');
}

async function verifyChecksums(dest) {
  const lines = (await readFile(join(dest, 'SHA256SUMS.txt'), 'utf8')).trim().split('\n').filter(Boolean);
  const listed = new Map();
  for (const line of lines) {
    const expectedHash = line.slice(0, 64);
    const path = line.slice(66);
    assert.match(expectedHash, /^[a-f0-9]{64}$/);
    assert.equal(sha256(await readFile(join(dest, ...path.split('/')))), expectedHash, path);
    listed.set(path, expectedHash);
  }
  const files = (await walk(dest)).filter(path => path !== 'SHA256SUMS.txt').sort();
  assert.deepEqual([...listed.keys()].sort(), files);
  return listed;
}

async function summaryOf(result) {
  assert.equal(result.status, 0, result.stderr || result.stdout);
  return JSON.parse(result.stdout.trim());
}

async function freePort() {
  const server = createServer();
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const port = server.address().port;
  await new Promise(resolve => server.close(resolve));
  return port;
}

async function startEngine(dest) {
  const child = spawn(join(dest, 'dist', 'engine', 'keyhelix'), ['--listen', '127.0.0.1:0'], {
    cwd: dest,
    stdio: ['pipe', 'pipe', 'pipe']
  });
  let stdout = '';
  let stderr = '';
  child.stdout.on('data', chunk => { stdout += chunk.toString('utf8'); });
  child.stderr.on('data', chunk => { stderr += chunk.toString('utf8'); });
  await waitFor(() => stdout.includes('\n'), 10000);
  const ready = JSON.parse(stdout.slice(0, stdout.indexOf('\n')));
  const response = await fetch(`http://${ready.address}/healthz`);
  const health = await response.json();
  return { child, ready, health, status: response.status, stderr };
}

async function stopProcess(child) {
  if (child.exitCode !== null) return;
  child.kill('SIGTERM');
  await Promise.race([once(child, 'exit'), delay(5000)]);
  if (child.exitCode === null) child.kill('SIGKILL');
}

async function startWeb(dest) {
  const port = await freePort();
  const child = spawn(process.execPath, ['scripts/serve-web.mjs', '--root', 'web', '--port', String(port), '--config', 'ops/web/runtime-config.json'], {
    cwd: dest,
    stdio: ['pipe', 'pipe', 'pipe']
  });
  let stderr = '';
  child.stderr.on('data', chunk => { stderr += chunk.toString('utf8'); });
  const base = `http://127.0.0.1:${port}`;
  await waitFor(async () => {
    try {
      const response = await fetch(base + '/healthz');
      return response.ok;
    } catch {
      return false;
    }
  }, 15000);
  return { child, base, stderr };
}

test('complete release includes engine, web, resources, SBOM, notices, provenance and checksums', { timeout: 300000 }, async t => {
  const directory = await tempDirectory();
  t.after(() => rm(directory, { recursive: true, force: true }));
  buildOnce();
  const dest = join(directory, 'release');
  const result = runPackage({ dest });
  const summary = await summaryOf(result);
  assert.match(summary.releaseId, /^[a-f0-9]{12}(?:-dirty)?$/);
  assert.equal(summary.engine.version, packageJson.version);
  assert.equal(summary.engine.coreReady, false);
  assert.ok(summary.sbomComponents >= positive.release.minimumSbomComponents);
  assert.ok(summary.resources >= positive.release.minimumResourceEntries);

  const files = await walk(dest);
  const fileSet = new Set(files);
  for (const required of positive.release.requiredPaths) assert.ok(fileSet.has(required), required);
  for (const prefix of positive.release.requiredPrefixes) assert.ok(files.some(path => path.startsWith(prefix)), prefix);
  for (const forbidden of positive.release.forbiddenPathSegments) {
    assert.ok(files.every(path => !path.split('/').includes(forbidden)), forbidden);
    assert.ok(files.every(path => !path.includes('/' + forbidden + '/')), forbidden);
  }
  await verifyChecksums(dest);

  const release = JSON.parse(await readFile(join(dest, 'RELEASE.json'), 'utf8'));
  assert.equal(release.schema_version, 1);
  assert.equal(release.scope, expected.expected.release.scope);
  assert.equal(release.license, 'Apache-2.0');
  assert.deepEqual(
    Object.fromEntries(Object.keys(positive.release.requiredFlags).map(key => [key, release.artifact[key]])),
    positive.release.requiredFlags
  );
  assert.match(release.source.commit, /^[a-f0-9]{40}$/);
  assert.equal(typeof release.source.dirty, 'boolean');
  assert.match(release.source.treeSha256, /^[a-f0-9]{64}$/);
  assert.equal(release.source.archive.sha256, sha256(await readFile(join(dest, ...release.source.archive.path.split('/')))));
  assert.equal(release.sbom.sha256, sha256(await readFile(join(dest, ...release.sbom.path.split('/')))));
  assert.equal(release.notices.sha256, sha256(await readFile(join(dest, 'THIRD_PARTY_NOTICES.md'))));
  assert.equal(release.resources.sha256, sha256(await readFile(join(dest, 'RESOURCES.json'))));
  assert.equal(release.engine.version, packageJson.version);
  assert.equal(release.build.platform, 'linux/amd64');
  for (const provider of providerLock.providers) {
    const recorded = release.providers.find(item => item.id === provider.id);
    assert.ok(recorded, provider.id);
    assert.equal(recorded.digest, provider.digest);
    assert.equal(recorded.embedded, false);
  }

  const resources = JSON.parse(await readFile(join(dest, 'RESOURCES.json'), 'utf8'));
  assert.ok(resources.resources.length >= positive.release.minimumResourceEntries);
  assert.ok(resources.resources.some(resource => resource.path === 'spec/04_AUTHORIZATION_MATRIX.md'));
  assert.ok(resources.resources.some(resource => resource.path === 'contracts/openapi.v1.json'));
  for (const resource of resources.resources) {
    assert.equal(sha256(await readFile(join(dest, ...resource.path.split('/')))), resource.sha256, resource.path);
  }

  const sbom = JSON.parse(await readFile(join(dest, ...release.sbom.path.split('/')), 'utf8'));
  assert.equal(sbom.bomFormat, expected.expected.sbom.bomFormat);
  assert.equal(sbom.specVersion, expected.expected.sbom.specVersion);
  assert.ok(sbom.components.length >= positive.release.minimumSbomComponents);
  for (const component of positive.release.requiredSbomComponents) {
    assert.ok(sbom.components.some(item => item.purl === component), component);
  }
  for (const provider of providerLock.providers) {
    const component = sbom.components.find(item => item.name === provider.id);
    assert.ok(component, provider.id);
    assert.equal(component.properties.find(property => property.name === 'keyhelix:provider:digest').value, provider.digest);
    assert.equal(component.properties.find(property => property.name === 'keyhelix:provider:embedded').value, 'false');
  }
  for (const component of sbom.components) {
    for (const license of component.licenses ?? []) assert.ok(positive.release.licenseAllowlist.includes(license.license?.id), component.name);
  }

  for (const text of release.notices.licenseTexts) {
    assert.equal(text.sha256, sha256(await readFile(join(dest, ...text.path.split('/')))), text.path);
  }
  const notices = await readFile(join(dest, 'THIRD_PARTY_NOTICES.md'), 'utf8');
  for (const provider of ['openbao', 'keycloak']) assert.match(notices, new RegExp(provider));
  assert.match(notices, /MPL-2.0/);
  assert.match(notices, /Apache-2.0/);

  const archive = await readFile(join(dest, ...release.source.archive.path.split('/')));
  assert.equal(sha256(archive), release.source.archive.sha256);
  const tar = spawnSync('tar', ['-tzf', join(dest, ...release.source.archive.path.split('/'))], { encoding: 'utf8' });
  assert.equal(tar.status, 0, tar.stderr);
  const entries = tar.stdout.trim().split('\n').filter(Boolean);
  const prefix = `keyhelix-${release.source.shortCommit}/`;
  assert.ok(entries.every(entry => entry.startsWith(prefix)));
  for (const required of positive.release.requiredSourceFiles) assert.ok(entries.includes(prefix + required), required);
  for (const forbidden of positive.release.forbiddenPathSegments) {
    assert.ok(entries.every(entry => !entry.split('/').includes(forbidden)), forbidden);
  }

  const service = await readFile(join(dest, 'ops', 'web', 'service.systemd'), 'utf8');
  assert.match(service, /start-local\.mjs/);
  assert.match(service, /--providers reuse/);
  assert.match(service, /--runtime \/etc\/keyhelix\/runtime\.json/);
  assert.match(service, /ReadWritePaths=\/var\/lib\/keyhelix/);
  assert.doesNotMatch(service, /serve-web\.mjs/);
  const proxy = await readFile(join(dest, 'ops', 'web', 'nginx.conf.template'), 'utf8');
  assert.match(proxy, /proxy_pass http:\/\/127\.0\.0\.1:4305/);
  assert.match(proxy, /deny all;/);
  assert.doesNotMatch(proxy, /8200|8080/);

  const engineStat = await stat(join(dest, 'dist', 'engine', 'keyhelix'));
  assert.ok(engineStat.mode & 0o111);
  const engineBytes = await readFile(join(dest, 'dist', 'engine', 'keyhelix'));
  assert.equal(engineBytes.includes(Buffer.from(negative.canary)), false);
  assert.equal(engineBytes.includes(Buffer.from('c30-synthetic-plaintext-sentinel-9f3a')), false);
  const version = spawnSync(join(dest, 'dist', 'engine', 'keyhelix'), ['--version'], { cwd: dest, encoding: 'utf8' });
  assert.equal(version.status, 0, version.stderr);
  assert.equal(JSON.parse(version.stdout).version, packageJson.version);

  const engine = await startEngine(dest);
  try {
    assert.equal(engine.status, expected.expected.engine.healthStatus);
    assert.equal(engine.health.coreReady, false);
    assert.equal(engine.health.scope, 'engine-runtime');
  } finally {
    await stopProcess(engine.child);
  }

  const web = await startWeb(dest);
  try {
    assert.equal((await fetch(web.base + '/')).status, expected.expected.web.indexStatus);
    assert.equal((await fetch(web.base + '/healthz')).status, expected.expected.web.healthStatus);
    const ready = await fetch(web.base + '/readyz');
    assert.equal(ready.status, expected.expected.web.readyStatus);
    assert.equal((await ready.json()).engineReady, false);
    assert.equal((await fetch(web.base + '/api')).status, expected.expected.web.apiWithoutEngine);
    const asset = (await readdir(join(dest, 'web', 'assets'))).find(name => name.endsWith('.js'));
    assert.ok(asset);
    const assetResponse = await fetch(web.base + '/assets/' + encodeURIComponent(asset));
    assert.equal(assetResponse.status, 200);
    assert.equal(assetResponse.headers.get('cache-control'), expected.expected.web.assetCacheControl);
  } finally {
    await stopProcess(web.child);
  }

  assert.equal(negative.cases.find(item => item.id === 'provider-ownership').embeddedProviderState, false);
});

test('replaying packaging produces identical checksums and a single complete release', { timeout: 180000 }, async t => {
  const directory = await tempDirectory();
  t.after(() => rm(directory, { recursive: true, force: true }));
  const first = join(directory, 'first');
  const second = join(directory, 'second');
  if (!(await access(join(root, 'dist', 'engine', 'keyhelix')).then(() => true, () => false))) buildOnce();
  await summaryOf(runPackage({ dest: first }));
  await summaryOf(runPackage({ dest: second }));
  assert.equal(await readFile(join(first, 'SHA256SUMS.txt'), 'utf8'), await readFile(join(second, 'SHA256SUMS.txt'), 'utf8'));
  assert.equal(await readFile(join(first, 'RELEASE.json'), 'utf8'), await readFile(join(second, 'RELEASE.json'), 'utf8'));
  assert.equal(await readFile(join(first, 'THIRD_PARTY_NOTICES.md'), 'utf8'), await readFile(join(second, 'THIRD_PARTY_NOTICES.md'), 'utf8'));
  const files = await walk(first);
  assert.equal(files.filter(path => path === 'RELEASE.json').length, 1);
  assert.ok(files.every(path => !path.includes('.package-stage')));
});

test('secret material in a staged payload stops publication and preserves the prior release', { timeout: 180000 }, async t => {
  const directory = await tempDirectory();
  t.after(async () => {
    await rm(join(root, 'dist', 'web', 'c31-leaked-canary.txt'), { force: true });
    await rm(directory, { recursive: true, force: true });
  });
  if (!(await access(join(root, 'dist', 'engine', 'keyhelix')).then(() => true, () => false))) buildOnce();
  const dest = join(directory, 'release');
  await summaryOf(runPackage({ dest }));
  const before = await readFile(join(dest, 'SHA256SUMS.txt'), 'utf8');
  await writeFile(join(root, 'dist', 'web', 'c31-leaked-canary.txt'), '-----BEGIN PRIVATE KEY-----\n' + negative.canary + '\n');
  const failed = runPackage({ dest });
  assert.notEqual(failed.status, 0);
  assert.match(failed.stderr, /package-error: secret-material:private-key/);
  assert.equal(await readFile(join(dest, 'SHA256SUMS.txt'), 'utf8'), before);
  await rm(join(root, 'dist', 'web', 'c31-leaked-canary.txt'), { force: true });
  await summaryOf(runPackage({ dest }));
});

test('killing the writer before publish preserves the prior complete release and recovers on restart', { timeout: 180000 }, async t => {
  const directory = await tempDirectory();
  t.after(async () => {
    for (const path of await readdir(join(root, 'dist')).catch(() => [])) {
      if (path.startsWith('.package-stage.')) await rm(join(root, 'dist', path), { recursive: true, force: true });
    }
    await rm(directory, { recursive: true, force: true });
  });
  if (!(await access(join(root, 'dist', 'engine', 'keyhelix')).then(() => true, () => false))) buildOnce();
  const dest = join(directory, 'release');
  await summaryOf(runPackage({ dest }));
  const before = await readFile(join(dest, 'SHA256SUMS.txt'), 'utf8');

  const child = spawn('bash', ['scripts/package.sh'], {
    cwd: root,
    detached: true,
    stdio: ['ignore', 'pipe', 'pipe'],
    env: {
      ...process.env,
      KEYHELIX_PACKAGE_SKIP_BUILD: '1',
      KEYHELIX_RELEASE_DIR: dest,
      KEYHELIX_PACKAGE_TEST_PAUSE_BEFORE_PUBLISH_MS: '60000'
    }
  });
  let stdout = '';
  let stderr = '';
  child.stdout.on('data', chunk => { stdout += chunk.toString('utf8'); });
  child.stderr.on('data', chunk => { stderr += chunk.toString('utf8'); });
  await waitFor(async () => {
    for (const entry of await readdir(join(root, 'dist')).catch(() => [])) {
      if (!entry.startsWith('.package-stage.')) continue;
      try {
        await access(join(root, 'dist', entry, 'RELEASE.json'));
        return true;
      } catch {}
    }
    return false;
  }, 60000);

  const concurrent = runPackage({ dest });
  assert.notEqual(concurrent.status, 0);
  assert.match(concurrent.stderr, /package-error: package-in-progress/);
  assert.equal(await readFile(join(dest, 'SHA256SUMS.txt'), 'utf8'), before);

  process.kill(-child.pid, 'SIGKILL');
  await once(child, 'exit');
  assert.equal(await readFile(join(dest, 'SHA256SUMS.txt'), 'utf8'), before);

  await summaryOf(runPackage({ dest }));
  await verifyChecksums(dest);
  const stale = (await readdir(join(root, 'dist'))).filter(entry => entry.startsWith('.package-stage.'));
  assert.deepEqual(stale, []);
  assert.equal(stdout.trim(), '');
});

test('a real file-size quota aborts staging and the next run recovers a complete release', { timeout: 180000 }, async t => {
  if (process.platform !== 'linux') return t.skip('ulimit -f is verified on the supported Linux profile');
  const directory = await tempDirectory();
  t.after(async () => {
    for (const path of await readdir(join(root, 'dist')).catch(() => [])) {
      if (path.startsWith('.package-stage.')) await rm(join(root, 'dist', path), { recursive: true, force: true });
    }
    await rm(directory, { recursive: true, force: true });
  });
  if (!(await access(join(root, 'dist', 'engine', 'keyhelix')).then(() => true, () => false))) buildOnce();
  const dest = join(directory, 'release');
  await summaryOf(runPackage({ dest }));
  const before = await readFile(join(dest, 'SHA256SUMS.txt'), 'utf8');
  const failed = spawnSync('bash', ['-c', 'ulimit -f 512; exec bash scripts/package.sh'], {
    cwd: root,
    encoding: 'utf8',
    timeout: 120000,
    env: { ...process.env, KEYHELIX_PACKAGE_SKIP_BUILD: '1', KEYHELIX_RELEASE_DIR: dest }
  });
  assert.notEqual(failed.status, 0);
  assert.equal(await readFile(join(dest, 'SHA256SUMS.txt'), 'utf8'), before);
  await summaryOf(runPackage({ dest }));
  await verifyChecksums(dest);
  assert.deepEqual((await readdir(join(root, 'dist'))).filter(entry => entry.startsWith('.package-stage.')), []);
});
