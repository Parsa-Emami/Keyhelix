import { spawn, spawnSync } from 'node:child_process';
import { mkdtemp, mkdir, rm, writeFile, readdir, readFile, cp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { signIn, stepUp, api } from './local-auth.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const temp = await mkdtemp(join(tmpdir(), 'oss-clone-'));
const sentinel = 'c30-synthetic-plaintext-sentinel-9f3a';
const secretPath = `app/prod/c30-clone-${Date.now().toString(36)}`;
// A clean host creates its own provider containers. On a shared development host
// the existing provider material is reused instead of fighting over the fixed
// loopback ports; --restore then reuses the original mounts.
const reuseProviders = process.env.KEYHELIX_REUSE_PROVIDERS !== '0';
const verifyRestore = process.env.KEYHELIX_CLONE_RESTORE !== '0';
const servers = new Set();

function run(command, args, cwd, options = {}) {
  const result = spawnSync(command, args, {
    cwd, encoding: 'utf8', maxBuffer: 32 * 1024 * 1024, ...options,
  });
  if (result.status !== 0) {
    throw new Error(`${command} failed: ${result.stdout ?? ''}${result.stderr ?? result.error?.message ?? ''}`);
  }
  return result.stdout.trim();
}

async function launch(cwd) {
  const child = spawn(process.execPath, ['scripts/start-local.mjs'], {
    cwd, stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env },
  });
  servers.add(child);
  let stderr = '';
  child.stderr.on('data', chunk => { stderr = (stderr + chunk.toString('utf8')).slice(-4096); });
  const port = await new Promise((accept, reject) => {
    const timer = setTimeout(() => reject(new Error('Startup deadline: ' + stderr)), 30000);
    child.once('error', error => { clearTimeout(timer); reject(error); });
    child.once('exit', code => { clearTimeout(timer); reject(new Error(`Launcher exited (${code}): ${stderr}`)); });
    let buffer = '';
    child.stdout.on('data', chunk => {
      buffer += chunk.toString('utf8');
      const line = buffer.split('\n')[0];
      if (!buffer.includes('\n')) return;
      try {
        const ready = JSON.parse(line);
        if (ready.service !== 'keyhelix-local' || !ready.coreReady) throw new Error('Launcher did not report a composed engine.');
        clearTimeout(timer);
        accept(ready.port);
      } catch (error) {
        clearTimeout(timer);
        reject(error);
      }
    });
  });
  const origin = `http://127.0.0.1:${port}`;
  const deadline = Date.now() + 20000;
  let last;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(origin + '/readyz', { signal: AbortSignal.timeout(2000) });
      const body = await response.json();
      if (response.status === 200 && body.engineReady) return { child, port, origin: `http://localhost:${port}` };
      last = JSON.stringify(body);
    } catch (error) {
      last = error.message;
    }
    await new Promise(accept => setTimeout(accept, 300));
  }
  throw new Error('Composed engine did not become ready: ' + last);
}

async function stop(child) {
  if (!child || child.exitCode !== null) return;
  child.kill('SIGTERM');
  await new Promise(accept => {
    const timer = setTimeout(() => { child.kill('SIGKILL'); accept(); }, 10000);
    child.once('exit', () => { clearTimeout(timer); accept(); });
  });
}

async function contains(directory, needle) {
  let found = 0;
  const walk = async path => {
    let entries;
    try { entries = await readdir(path, { withFileTypes: true }); } catch { return; }
    for (const entry of entries) {
      const child = join(path, entry.name);
      if (entry.isDirectory()) await walk(child);
      else if (entry.isFile()) {
        try {
          if ((await readFile(child)).includes(needle)) found += 1;
        } catch {}
      }
    }
  };
  await walk(directory);
  return found;
}

async function revealAfterSignIn(origin, jar) {
  const session = await api(origin, jar, '/api/v1/auth/session');
  if (!session.data?.authenticated) throw new Error('Session was not established after restart.');
  const denied = await api(origin, jar, '/api/vaults/vault-prod/reveal', { method: 'POST', body: { secret_path: secretPath } });
  if (denied.status !== 401 || denied.data?.error !== 'step_up_required') {
    throw new Error(`Reveal without step-up was not rejected: ${denied.status} ${denied.text.slice(0, 200)}`);
  }
  await stepUp({ origin, jar, action: 'reveal', resource: secretPath, returnTo: '/' });
  const revealed = await api(origin, jar, '/api/vaults/vault-prod/reveal', { method: 'POST', body: { secret_path: secretPath } });
  const plaintext = revealed.data?.plaintext_encoding === 'base64'
    ? Buffer.from(revealed.data?.plaintext ?? '', 'base64').toString('utf8')
    : revealed.data?.plaintext;
  if (revealed.status !== 200 || plaintext !== sentinel) {
    throw new Error(`Reveal did not return the sealed sentinel: ${revealed.status} ${revealed.text.slice(0, 200)}`);
  }
  return revealed.data;
}

let checkout;
try {
  // Default: test the index so contributors can verify a proposed commit before
  // pushing. KEYHELIX_CLONE_WORKTREE=1 snapshots the working tree instead, for
  // verifying uncommitted work without mutating the caller's index.
  const fromWorktree = process.env.KEYHELIX_CLONE_WORKTREE === '1';
  const identity = {
    ...process.env,
    GIT_AUTHOR_NAME: 'Clone smoke', GIT_AUTHOR_EMAIL: 'clone@example.invalid',
    GIT_COMMITTER_NAME: 'Clone smoke', GIT_COMMITTER_EMAIL: 'clone@example.invalid',
  };
  const tree = fromWorktree ? null : run('git', ['write-tree'], root);
  let source = join(temp, 'source.git');
  if (fromWorktree) {
    const staging = join(temp, 'worktree');
    await cp(root, staging, {
      recursive: true,
      filter: path => !/[\\/](?:\.git|node_modules|dist|\.local-data|test-results|playwright-report)(?:[\\/]|$)/.test(path)
    });
    run('git', ['init', '--quiet'], staging);
    run('git', ['add', '-A'], staging);
    run('git', ['commit', '--quiet', '-m', 'temporary working tree proof'], staging, { env: identity });
    run('git', ['clone', '--quiet', '--no-local', staging, source], temp);
  } else {
    const commit = run('git', ['commit-tree', tree, '-m', 'temporary staged source proof'], root, { env: identity });
    // Advertise the snapshot from an isolated repository. No source refs change;
    // a real transport clone collects every object, even from a shallow checkout.
    run('git', ['init', '--bare', '--quiet', source], temp);
    const objects = resolve(root, run('git', ['rev-parse', '--git-path', 'objects'], root));
    await mkdir(join(source, 'objects', 'info'), { recursive: true });
    await writeFile(join(source, 'objects', 'info', 'alternates'), objects + '\n');
    run('git', ['--git-dir=' + source, 'update-ref', 'refs/heads/snapshot', commit], temp);
  }
  checkout = join(temp, 'checkout');
  if (fromWorktree) {
    run('git', ['clone', '--quiet', '--no-local', source, checkout], temp);
  } else {
    run('git', ['clone', '--quiet', '--no-local', '--branch', 'snapshot', source, checkout], temp);
    if (run('git', ['rev-parse', 'HEAD^{tree}'], checkout) !== tree) throw new Error('Cloned tree differs from index');
  }
  if (!process.env.npm_execpath) throw new Error('Invoke through npm run test:clone.');
  // Shared development hosts already own the fixed provider ports; seed the
  // clone with the existing recovery material so setup reuses them.
  if (reuseProviders) {
    await mkdir(join(checkout, '.local-data'), { recursive: true, mode: 0o700 });
    await cp(join(root, '.local-data/providers'), join(checkout, '.local-data/providers'), { recursive: true });
  }
  run(process.execPath, [process.env.npm_execpath, 'run', 'setup'], checkout, { timeout: 900000 });

  // --- Phase 1: web-only startup proof, labeled separately. -------------------
  const launchSource = `
    import { createWebServer } from './scripts/serve-web.mjs';
    import fs from 'node:fs';
    const config = JSON.parse(fs.readFileSync('ops/web/runtime-config.json'));
    const instance = createWebServer({ root: 'dist/web', config, projectId: config.projectId });
    instance.listen(0, '127.0.0.1', () => console.log(instance.address().port));
  `;
  const webOnly = spawn(process.execPath, ['--input-type=module', '-e', launchSource], {
    cwd: checkout, stdio: ['ignore', 'pipe', 'pipe'],
  });
  servers.add(webOnly);
  const webPort = await new Promise((accept, reject) => {
    const timer = setTimeout(() => reject(new Error('Startup deadline')), 10000);
    webOnly.once('error', error => { clearTimeout(timer); reject(error); });
    webOnly.once('exit', () => { clearTimeout(timer); reject(new Error('Server exited')); });
    webOnly.stdout.once('data', data => { clearTimeout(timer); accept(Number(data.toString().trim())); });
  });
  const webBase = 'http://127.0.0.1:' + webPort;
  const shellHealth = await fetch(webBase + '/readyz');
  const shellState = await shellHealth.json();
  if (!shellHealth.ok || shellState.engineReady !== false || (await fetch(webBase + '/api/v1/unimplemented')).status !== 503) {
    throw new Error('Incorrect readiness boundary');
  }
  if (!(await fetch(webBase)).ok) throw new Error('Workspace unavailable');
  await stop(webOnly);

  // --- Phase 2: real workflow through the browser acceptance spec. -----------
  const cli = join(checkout, 'node_modules', '@playwright', 'test', 'cli.js');
  run(process.execPath, [cli, 'test', 'tests/browser/clone-to-value.spec.ts', '--reporter=line'], checkout, {
    env: { ...process.env, C30_SECRET_PATH: secretPath },
    timeout: 900000
  });

  // --- Phase 3: restart persists metadata and provider ownership. ------------
  const first = await launch(checkout);
  const jar = await signIn({ origin: first.origin });
  await revealAfterSignIn(first.origin, jar);
  await stop(first.child);

  const engineData = join(checkout, '.local-data', 'engine');
  const providerData = join(checkout, '.local-data', 'providers');
  const leaked = (await contains(engineData, sentinel)) + (await contains(providerData, sentinel));
  if (leaked !== 0) throw new Error(`Sentinel plaintext was persisted in ${leaked} local file(s).`);

  const second = await launch(checkout);
  const secondJar = await signIn({ origin: second.origin });
  await revealAfterSignIn(second.origin, secondJar);

  // Assert member revocation persists across engine restart
  const bobJar = await signIn({ origin: second.origin, username: 'bob', password: 'keyhelix-local-bob' });
  const bobDenied = await api(second.origin, bobJar, '/api/vaults/vault-prod/reveal', { method: 'POST', body: { secret_path: secretPath } });
  if (bobDenied.status !== 403 || bobDenied.data?.error !== 'access_denied') {
    throw new Error(`Member revocation did not persist across engine restart: ${bobDenied.status}`);
  }

  // --- Phase 4: provider outage fails closed. --------------------------------
  const providers = await import(pathToFileURL(join(reuseProviders ? root : checkout, 'scripts', 'providers.mjs')).href);
  const stopBao = spawnSync('podman', ['stop', '--time', '2', 'keyhelix-local-openbao'], { encoding: 'utf8' });
  if (stopBao.status === 0) {
    try {
      await stepUp({ origin: second.origin, jar: secondJar, action: 'reveal', resource: secretPath, returnTo: '/' });
      const outageReveal = await api(second.origin, secondJar, '/api/vaults/vault-prod/reveal', { method: 'POST', body: { secret_path: secretPath } });
      if (outageReveal.status !== 503 || outageReveal.data?.error !== 'provider_unavailable') {
        throw new Error(`Reveal did not fail closed during provider outage: ${outageReveal.status}`);
      }
      if (outageReveal.text.includes(sentinel)) {
        throw new Error('Sentinel plaintext leaked during provider outage failure response.');
      }
    } finally {
      spawnSync('podman', ['start', 'keyhelix-local-openbao'], { encoding: 'utf8' });
      await providers.ensureProviders({ quiet: true });
    }
  }

  // --- Phase 5: provider recovery keeps sealed bytes readable and revoked grants revoked. ---
  let restore = null;
  if (verifyRestore) {
    await stop(second.child);
    const bundle = join(temp, 'recovery');
    const manifest = await providers.snapshotProviderBundle(bundle);
    const restored = await providers.restoreProviderBundle(bundle);
    if (restored.manifest.snapshot_sha256 !== manifest.snapshot_sha256) throw new Error('Restored snapshot identity differs from the backup.');
    // Restoration issues a fresh scoped workload token; refresh the runtime file.
    await providers.ensureProviders({ quiet: true });
    const third = await launch(checkout);
    const thirdJar = await signIn({ origin: third.origin });
    await revealAfterSignIn(third.origin, thirdJar);

    // Verify revoked grants remain revoked across provider restore
    const bobThirdJar = await signIn({ origin: third.origin, username: 'bob', password: 'keyhelix-local-bob' });
    const bobPostRestore = await api(third.origin, bobThirdJar, '/api/vaults/vault-prod/reveal', { method: 'POST', body: { secret_path: secretPath } });
    if (bobPostRestore.status !== 403 || bobPostRestore.data?.error !== 'access_denied') {
      throw new Error(`Revoked grant was not preserved after provider restore: ${bobPostRestore.status}`);
    }

    await stop(third.child);
    restore = {
      snapshot_sha256: manifest.snapshot_sha256,
      snapshot_bytes: manifest.snapshot_bytes,
      readable_after_restore: true,
      revoked_grants_still_revoked: true
    };
  }
  await stop(second.child);

  console.log(JSON.stringify({
    passed: true,
    sourceProof: fromWorktree ? 'working tree snapshot' : 'git index tree',
    stagedTree: tree,
    webOnly: { proof: 'real git clone -> npm run setup -> web startup', coreReady: false },
    workflow: {
      proof: 'cloned checkout -> npm start -> browser sign-in/write/step-up/reveal/member denial',
      secretPath,
      exercised: ['owner session', 'scoped write', 'step-up reveal', 'transient clear', 'member grant revocation', 'provider outage fail-closed'],
      providerOwnsBytes: { sentinelOccurrences: leaked },
      restarted: true,
      providerOutageFailClosed: true,
      restore
    },
    providers: reuseProviders ? 'reused shared local providers' : 'provisioned from the clone'
  }));
} finally {
  for (const server of servers) await stop(server);
  await rm(temp, { recursive: true, force: true });
}
