import { spawnSync } from 'node:child_process';
import { chmod, copyFile, mkdir, readFile, rename, rm, stat, writeFile } from 'node:fs/promises';
import { createHash, randomUUID } from 'node:crypto';
import { existsSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
export const localRoot = resolve(root, '.local-data');
export const providerRoot = resolve(localRoot, 'providers');
export const runtimeFile = resolve(localRoot, 'runtime.json');
const lock = JSON.parse(await readFile(resolve(root, 'ops/providers.lock.json'), 'utf8'));
const toolchain = JSON.parse(await readFile(resolve(root, 'docs/engineering/toolchain-lock.json'), 'utf8'));
const pins = Object.fromEntries(lock.providers.map(provider => [provider.id, provider]));
const podmanPin = toolchain.resources.find(resource => resource.id === 'podman-provider').version;

const OPENBAO = 'keyhelix-local-openbao';
const KEYCLOAK = 'keyhelix-local-keycloak';
const OPENBAO_URL = 'http://127.0.0.1:8200';
const KEYCLOAK_URL = 'http://127.0.0.1:8080';
const APP_ORIGIN = 'http://localhost:4173';
const OIDC_ISSUER = `${KEYCLOAK_URL}/realms/keyhelix`;
const SECRET_PATTERN = /\b(?:s\.[A-Za-z0-9]{20,}|hvs\.[A-Za-z0-9_-]{20,}|[a-f0-9]{32,})\b/g;

function scrub(value) {
  return String(value ?? '').replace(SECRET_PATTERN, '[REDACTED]');
}

function execute(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: root,
    encoding: 'utf8',
    timeout: options.timeout ?? 120000,
    maxBuffer: 16 * 1024 * 1024,
    input: options.input,
    env: { ...process.env, ...options.env }
  });
  return {
    ok: result.status === 0 && !result.error,
    stdout: result.stdout ?? '',
    stderr: result.stderr ?? '',
    status: result.status,
    error: result.error
  };
}

function requireOk(result, message) {
  if (!result.ok) {
    const detail = scrub(result.stderr || result.stdout || result.error?.message || '');
    throw new Error(`${message}${detail ? `: ${detail.trim().split('\n').slice(-3).join(' ')}` : ''}`);
  }
  return result.stdout;
}

function podman(args, options) {
  return requireOk(execute('podman', args, options), 'podman ' + args[0] + ' failed');
}

function containerExists(name) {
  return execute('podman', ['container', 'exists', name]).status === 0;
}

function containerRunning(name) {
  const result = execute('podman', ['inspect', '--format', '{{.State.Running}}', name]);
  return result.ok && result.stdout.trim() === 'true';
}

function imagePresent(provider, reference = `${provider.image}:${provider.version}`) {
  const result = execute('podman', ['image', 'inspect', '--format', '{{json .RepoDigests}}', reference]);
  if (!result.ok) return false;
  try {
    const digests = JSON.parse(result.stdout);
    return Array.isArray(digests) && digests.some(digestRef => digestRef.endsWith('@' + provider.digest));
  } catch {
    return false;
  }
}

async function ensureImage(provider) {
  if (imagePresent(provider)) return false;
  if (!imagePresent(provider, `${provider.image}@${provider.digest}`)) {
    if (process.env.KEYHELIX_OFFLINE === '1') {
      throw new Error(`${provider.id} image ${provider.image}@${provider.digest} is not present locally and offline mode forbids pulling it.`);
    }
    podman(['pull', '--quiet', `${provider.image}@${provider.digest}`], { timeout: 600000 });
    if (!imagePresent(provider, `${provider.image}@${provider.digest}`)) {
      throw new Error(`${provider.id} image digest does not match the pinned ${provider.digest} after pull.`);
    }
  }
  podman(['tag', `${provider.image}@${provider.digest}`, `${provider.image}:${provider.version}`]);
  if (!imagePresent(provider)) {
    throw new Error(`${provider.id} image tag ${provider.version} failed after pull.`);
  }
  return true;
}

function verifyPodman() {
  const version = requireOk(execute('podman', ['--version']), 'Podman is unavailable').trim();
  if (version !== `podman version ${podmanPin}`) {
    throw new Error(`Podman ${podmanPin} is required; found ${version}. See docs/engineering/CLONE_TO_RUN.md.`);
  }
  const rootless = requireOk(execute('podman', ['info', '--format', '{{.Host.Security.Rootless}}']), 'Podman info failed').trim();
  if (rootless !== 'true') throw new Error('Rootless Podman is required; run setup as an unprivileged user.');
  return { version, rootless: true };
}

async function waitFor(url, check, label, timeout = 60000) {
  const deadline = Date.now() + timeout;
  let last;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(url, { signal: AbortSignal.timeout(3000), redirect: 'manual' });
      const body = await response.text();
      const value = check(response, body);
      if (value) return value;
      last = `status ${response.status}`;
    } catch (error) {
      last = error.message;
    }
    await new Promise(accept => setTimeout(accept, 400));
  }
  throw new Error(`${label} did not become ready: ${last}`);
}

function openBaoExec(args, options = {}) {
  return execute('podman', ['exec', '-i', '-e', `BAO_ADDR=${OPENBAO_URL}`, ...(options.rootToken ? ['-e', `BAO_TOKEN=${options.rootToken}`] : []), OPENBAO, 'bao', ...args], options);
}

function removeInsideContainer(path) {
  execute('podman', ['exec', OPENBAO, 'rm', '-f', path]);
}

async function readInit() {
  try {
    return JSON.parse(await readFile(join(providerRoot, 'openbao', 'init.json'), 'utf8'));
  } catch (error) {
    if (error.code === 'ENOENT') return null;
    throw error;
  }
}

async function unsealWith(keys) {
  for (let attempt = 0; attempt < 20; attempt += 1) {
    const health = openBaoExec(['status', '-format=json']);
    let sealed = true;
    try {
      sealed = JSON.parse(health.stdout).sealed !== false;
    } catch {
      sealed = true;
    }
    if (!sealed) return;
    if (!keys?.length) throw new Error('OpenBao is sealed and no recovery key is available in .local-data/providers/openbao/init.json.');
    for (const key of keys) {
      const result = openBaoExec(['operator', 'unseal', key]);
      if (!result.ok) throw new Error('OpenBao unseal failed: ' + scrub(result.stderr || result.stdout));
    }
    await new Promise(accept => setTimeout(accept, 600));
  }
  throw new Error('OpenBao remained sealed after repeated unseal attempts.');
}

async function ensureOpenBao(init) {
  const dataDirectory = join(providerRoot, 'openbao', 'data');
  await mkdir(dataDirectory, { recursive: true, mode: 0o700 });
  await chmod(dataDirectory, 0o700);
  if (!containerExists(OPENBAO)) {
    const template = await readFile(join(root, 'ops/local/openbao.hcl.template'), 'utf8');
    const config = template
      .replaceAll('__API_ADDR__', OPENBAO_URL)
      .replaceAll('__CLUSTER_ADDR__', 'http://127.0.0.1:8201')
      .replaceAll('__NODE_ID__', 'keyhelix-local-1');
    const configPath = join(providerRoot, 'openbao', 'openbao.hcl');
    await writeFile(configPath, config, { mode: 0o644 });
    podman(['run', '--detach', '--name', OPENBAO, '--userns=keep-id:uid=100,gid=100',
      '--security-opt=no-new-privileges', '-p', '127.0.0.1:8200:8200', '-p', '127.0.0.1:8201:8201',
      '-v', `${configPath}:/openbao/config/openbao.hcl:ro`,
      '-v', `${dataDirectory}:/openbao/data`,
      `${pins.openbao.image}:${pins.openbao.version}`, 'server', '-config=/openbao/config/openbao.hcl']);
  } else if (!containerRunning(OPENBAO)) {
    podman(['start', OPENBAO]);
  }
  let current = await readInit();
  if (!current) {
    const probe = openBaoExec(['status', '-format=json']);
    let probeState = null;
    try { probeState = JSON.parse(probe.stdout); } catch {}
    if (probeState?.initialized === true) {
      throw new Error('OpenBao reports initialized state without recovery material in .local-data/providers/openbao/init.json. Run npm run providers:down and remove the orphaned .local-data/providers/openbao/data directory to start a fresh local provider.');
    }
    const result = openBaoExec(['operator', 'init', '-key-shares=1', '-key-threshold=1', '-format=json']);
    if (!result.ok) {
      // A concurrent init can win the race; re-read before failing.
      current = await readInit();
      if (!current) throw new Error('OpenBao initialization failed: ' + scrub(result.stderr || result.stdout));
    } else {
      const material = JSON.parse(result.stdout);
      current = {
        root_token: material.root_token,
        unseal_keys: material.unseal_keys_hex ?? []
      };
      if (current.unseal_keys.length === 0) throw new Error('OpenBao init returned no unseal key material.');
      await writeFile(join(providerRoot, 'openbao', 'init.json'), JSON.stringify(current), { mode: 0o600 });
    }
  }
  if (!current) throw new Error('OpenBao credentials are missing after initialization.');
  await waitFor(`${OPENBAO_URL}/v1/sys/health`, response => [200, 501, 503].includes(response.status), 'OpenBao health');
  await unsealWith(current.unseal_keys);
  await waitFor(`${OPENBAO_URL}/v1/sys/health`, response => response.status === 200, 'OpenBao unsealed health');
  return current;
}

async function ensureProviderConfiguration(init) {
  const rootToken = init.root_token;
  const mounts = openBaoExec(['secrets', 'list', '-format=json'], { rootToken });
  if (!mounts.ok) throw new Error('OpenBao mount inspection failed: ' + scrub(mounts.stderr));
  let listing = JSON.parse(mounts.stdout);
  if (!listing['transit/']) {
    requireOk(openBaoExec(['secrets', 'enable', 'transit'], { rootToken }), 'OpenBao transit enable failed');
    listing = JSON.parse(requireOk(openBaoExec(['secrets', 'list', '-format=json'], { rootToken }), 'OpenBao mount inspection failed'));
  }
  if (!listing['secret/']) {
    requireOk(openBaoExec(['secrets', 'enable', '-path=secret', '-version=2', 'kv'], { rootToken }), 'OpenBao kv enable failed');
  } else if (listing['secret/'].type !== 'kv') {
    throw new Error('OpenBao secret/ mount is not a KV engine; refusing to reuse it.');
  }
  const key = openBaoExec(['read', 'transit/keys/keyhelix-kek'], { rootToken });
  if (!key.ok) {
    requireOk(openBaoExec(['write', '-f', 'transit/keys/keyhelix-kek'], { rootToken }), 'OpenBao transit key creation failed');
  }
  const policy = `path "transit/encrypt/keyhelix-kek" { capabilities = ["update"] }
path "transit/decrypt/keyhelix-kek" { capabilities = ["update"] }
path "secret/data/*" { capabilities = ["create", "read", "update", "delete"] }
path "secret/metadata/*" { capabilities = ["read", "delete"] }
`;
  requireOk(openBaoExec(['policy', 'write', 'keyhelix-engine', '-'], { rootToken, input: policy }), 'OpenBao policy write failed');
  const token = JSON.parse(requireOk(openBaoExec(['token', 'create', '-policy=keyhelix-engine', '-ttl=0', '-renewable=false', '-format=json'], { rootToken }), 'OpenBao scoped token creation failed'));
  if (!token.auth?.client_token || token.auth.client_token === rootToken) {
    throw new Error('OpenBao did not issue a distinct scoped workload token.');
  }
  return token.auth.client_token;
}

async function ensureKeycloak() {
  const importDirectory = join(providerRoot, 'keycloak', 'import');
  await mkdir(importDirectory, { recursive: true, mode: 0o755 });
  await copyFile(join(root, 'ops/local/keycloak-realm.json'), join(importDirectory, 'keyhelix-realm.json'));
  await chmod(join(importDirectory, 'keyhelix-realm.json'), 0o644);
  if (!containerExists(KEYCLOAK)) {
    podman(['run', '--detach', '--name', KEYCLOAK, '--userns=keep-id:uid=1000,gid=1000',
      '--security-opt=no-new-privileges', '-p', '127.0.0.1:8080:8080',
      '-e', 'KC_HEALTH_ENABLED=true',
      '-v', `${importDirectory}:/opt/keycloak/data/import:ro`,
      `${pins.keycloak.image}:${pins.keycloak.version}`, 'start-dev', '--import-realm', `--hostname=${KEYCLOAK_URL}`, '--hostname-strict=false']);
  } else if (!containerRunning(KEYCLOAK)) {
    podman(['start', KEYCLOAK]);
  }
  return waitFor(`${OIDC_ISSUER}/.well-known/openid-configuration`, (response, body) => {
    if (response.status !== 200) return false;
    const discovery = JSON.parse(body);
    if (discovery.issuer !== OIDC_ISSUER) throw new Error(`Keycloak issuer mismatch: ${discovery.issuer}`);
    return discovery;
  }, 'Keycloak realm');
}

async function writeRuntime(scopedToken) {
  const runtime = {
    schema_version: 1,
    profile: 'local',
    generated_at: new Date().toISOString(),
    openbao: {
      address: OPENBAO_URL,
      token: scopedToken,
      kek_mount: 'transit',
      kek_id: 'keyhelix-kek',
      payload_mount: 'secret',
      scopes: ['transit:encrypt', 'transit:decrypt', 'kv:write', 'kv:read', 'kv:destroy']
    },
    oidc: {
      issuer: OIDC_ISSUER,
      client_id: 'keyhelix-web',
      redirect_uri: `${APP_ORIGIN}/api/v1/auth/callback`,
      message: 'Synthetic local identity provider. Users: alice / bob (see ops/local/keycloak-realm.json).'
    },
    engine: { data_dir: '.local-data/engine' },
    web: { origin: APP_ORIGIN, port: 4173 }
  };
  await mkdir(localRoot, { recursive: true, mode: 0o700 });
  const temporary = runtimeFile + '.tmp';
  await writeFile(temporary, JSON.stringify(runtime, null, 2), { mode: 0o600 });
  await rename(temporary, runtimeFile);
  await chmod(runtimeFile, 0o600);
  return runtime;
}

export async function ensureProviders({ quiet = false } = {}) {
  const podmanInfo = verifyPodman();
  await mkdir(join(providerRoot, 'openbao'), { recursive: true, mode: 0o700 });
  await mkdir(join(providerRoot, 'keycloak'), { recursive: true, mode: 0o700 });
  const pulled = [];
  if (await ensureImage(pins.openbao)) pulled.push(`${pins.openbao.image}:${pins.openbao.version}`);
  if (await ensureImage(pins.keycloak)) pulled.push(`${pins.keycloak.image}:${pins.keycloak.version}`);
  const init = await ensureOpenBao();
  const scopedToken = await ensureProviderConfiguration(init);
  await ensureKeycloak();
  const runtime = await writeRuntime(scopedToken);
  if (!quiet) {
    console.log(JSON.stringify({
      service: 'keyhelix-providers',
      rootless: podmanInfo.rootless,
      openbao: `${pins.openbao.image}:${pins.openbao.version}@${pins.openbao.digest}`,
      keycloak: `${pins.keycloak.image}:${pins.keycloak.version}@${pins.keycloak.digest}`,
      issuer: runtime.oidc.issuer,
      pulled
    }, null, 2));
  }
  return runtime;
}

export async function providerStatus() {
  const status = { openbao: { running: containerRunning(OPENBAO), ready: false }, keycloak: { running: containerRunning(KEYCLOAK), ready: false } };
  try {
    const response = await fetch(`${OPENBAO_URL}/v1/sys/health`, { signal: AbortSignal.timeout(2000) });
    const body = await response.json();
    status.openbao = { running: status.openbao.running, ready: response.status === 200, initialized: body.initialized === true, sealed: body.sealed !== false, version: body.version };
  } catch {}
  try {
    const response = await fetch(`${OIDC_ISSUER}/.well-known/openid-configuration`, { signal: AbortSignal.timeout(2000) });
    const body = await response.json();
    status.keycloak = { running: status.keycloak.running, ready: response.status === 200 && body.issuer === OIDC_ISSUER };
  } catch {}
  return status;
}

export async function snapshotProviderBundle(destination) {
  const directory = resolve(destination);
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const init = await readInit();
  if (!init) throw new Error('No OpenBao recovery material exists for backup.');
  const remote = `/tmp/keyhelix-${randomUUID()}.snap`;
  requireOk(openBaoExec(['operator', 'raft', 'snapshot', 'save', remote], { rootToken: init.root_token }), 'OpenBao snapshot save failed');
  podman(['cp', `${OPENBAO}:${remote}`, join(directory, 'openbao.snap')]);
  removeInsideContainer(remote);
  await writeFile(join(directory, 'openbao-init.json'), JSON.stringify(init), { mode: 0o600 });
  const digest = createHash('sha256').update(await readFile(join(directory, 'openbao.snap'))).digest('hex');
  const manifest = {
    schema_version: 1,
    provider: `${pins.openbao.image}:${pins.openbao.version}`,
    digest: pins.openbao.digest,
    snapshot_sha256: digest,
    snapshot_bytes: (await stat(join(directory, 'openbao.snap'))).size,
    created_at: new Date().toISOString(),
    recovery_material: 'openbao-init.json (mode 0600, unseal keys and root token)',
    note: 'Synthetic local providers only. Never commit this bundle.'
  };
  await writeFile(join(directory, 'manifest.json'), JSON.stringify(manifest, null, 2), { mode: 0o600 });
  return manifest;
}

export async function restoreProviderBundle(bundle) {
  const directory = resolve(bundle);
  const manifest = JSON.parse(await readFile(join(directory, 'manifest.json'), 'utf8'));
  const snapshot = join(directory, 'openbao.snap');
  const observed = createHash('sha256').update(await readFile(snapshot)).digest('hex');
  if (manifest.snapshot_sha256 !== observed) throw new Error('Backup snapshot digest does not match its manifest.');
  const init = JSON.parse(await readFile(join(directory, 'openbao-init.json'), 'utf8'));
  if (containerExists(OPENBAO)) {
    execute('podman', ['stop', '--time', '10', OPENBAO]);
    execute('podman', ['rm', '-f', OPENBAO]);
  }
  const dataDirectory = join(providerRoot, 'openbao', 'data');
  if (existsSync(dataDirectory)) {
    await rename(dataDirectory, join(providerRoot, 'openbao', `data.pre-restore-${Date.now()}`));
  }
  await mkdir(dataDirectory, { recursive: true, mode: 0o700 });
  await chmod(dataDirectory, 0o700);
  const configPath = join(providerRoot, 'openbao', 'openbao.hcl');
  podman(['run', '--detach', '--name', OPENBAO, '--userns=keep-id:uid=100,gid=100',
    '--security-opt=no-new-privileges', '-p', '127.0.0.1:8200:8200', '-p', '127.0.0.1:8201:8201',
    '-v', `${configPath}:/openbao/config/openbao.hcl:ro`,
    '-v', `${dataDirectory}:/openbao/data`,
    `${pins.openbao.image}:${pins.openbao.version}`, 'server', '-config=/openbao/config/openbao.hcl']);
  await waitFor(`${OPENBAO_URL}/v1/sys/health`, response => response.status === 501 || response.status === 503 || response.status === 200, 'fresh OpenBao');
  const fresh = JSON.parse(requireOk(openBaoExec(['operator', 'init', '-key-shares=1', '-key-threshold=1', '-format=json']), 'fresh OpenBao initialization failed'));
  await unsealWith(fresh.unseal_keys_hex ?? []);
  await waitFor(`${OPENBAO_URL}/v1/sys/health`, response => response.status === 200, 'fresh OpenBao unsealed');
  const remote = `/tmp/keyhelix-restore-${randomUUID()}.snap`;
  podman(['cp', snapshot, `${OPENBAO}:${remote}`]);
  requireOk(openBaoExec(['operator', 'raft', 'snapshot', 'restore', '-force', remote], { rootToken: fresh.root_token }), 'OpenBao snapshot restore failed');
  removeInsideContainer(remote);
  podman(['restart', '--time', '10', OPENBAO]);
  await waitFor(`${OPENBAO_URL}/v1/sys/health`, response => response.status === 503 || response.status === 200, 'restored OpenBao');
  await unsealWith(init.unseal_keys);
  await waitFor(`${OPENBAO_URL}/v1/sys/health`, response => response.status === 200, 'restored OpenBao unsealed');
  await writeFile(join(providerRoot, 'openbao', 'init.json'), JSON.stringify(init), { mode: 0o600 });
  const scopedToken = await ensureProviderConfiguration(init);
  const runtime = await writeRuntime(scopedToken);
  return { manifest, runtime };
}

export async function stopProviders() {
  const stopped = [];
  for (const name of [KEYCLOAK, OPENBAO]) {
    if (containerExists(name)) {
      execute('podman', ['stop', '--time', '10', name]);
      execute('podman', ['rm', '-f', name]);
      stopped.push(name);
    }
  }
  return stopped;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    const action = process.argv[2] ?? 'up';
    if (action === 'up') await ensureProviders();
    else if (action === 'status') console.log(JSON.stringify(await providerStatus(), null, 2));
    else if (action === 'down') console.log(JSON.stringify({ stopped: await stopProviders() }, null, 2));
    else if (action === 'backup') console.log(JSON.stringify(await snapshotProviderBundle(process.argv[3] ?? join(localRoot, 'backup')), null, 2));
    else if (action === 'restore') console.log(JSON.stringify({ restored: (await restoreProviderBundle(process.argv[3] ?? join(localRoot, 'backup'))).manifest }, null, 2));
    else throw new Error('Usage: node scripts/providers.mjs [up|status|down|backup <dir>|restore <dir>]');
  } catch (error) {
    console.error(scrub(error.message));
    process.exitCode = 1;
  }
}
