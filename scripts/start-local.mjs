import { spawn } from 'node:child_process';
import { readFile, realpath, stat } from 'node:fs/promises';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { resolve, relative, isAbsolute } from 'node:path';
import { createWebServer, formatRedactedDiagnostics, readEngineHealth, readEngineReadiness } from './serve-web.mjs';
import { validateRuntimeConfig } from '../apps/web/src/lib/runtime-config.mjs';

const repository = fileURLToPath(new URL('../', import.meta.url));

export async function startLocal({
  host = '127.0.0.1',
  port = 4173,
  root = resolve(repository, 'dist/web'),
  configPath = resolve(repository, 'ops/web/runtime-config.json'),
  engineBinary = resolve(repository, 'dist/engine/keyhelix'),
  runtimeFile = null,
  ensureProviderServices = false,
  signal
} = {}) {
  if (!['127.0.0.1', '::1'].includes(host)) throw new Error('Bind to loopback.');
  if (!Number.isInteger(port) || port < 0 || port > 65535) throw new Error('Invalid port.');
  const config = JSON.parse(await readFile(configPath, 'utf8'));
  const brand = JSON.parse(await readFile(new URL('../ops/web/brand.json', import.meta.url), 'utf8'));
  let runtimeConfig = null;
  if (runtimeFile) {
    if (ensureProviderServices) {
      const { ensureProviders } = await import('./providers.mjs');
      await ensureProviders({ quiet: true });
    }
    runtimeConfig = JSON.parse(await readFile(runtimeFile, 'utf8'));
    if (runtimeConfig.profile !== 'local' || runtimeConfig.schema_version !== 1) throw new Error('Runtime configuration is not the supported local profile.');
  }
  const publicRoot = await realpath(root);
  const index = await realpath(resolve(publicRoot, 'index.html'));
  const difference = relative(publicRoot, index);
  if (difference.startsWith('..') || isAbsolute(difference) || !(await stat(index)).isFile()) {
    throw new Error('Missing or unconfined web index. Run npm run setup.');
  }
  validateRuntimeConfig(config, brand.slug);
  let server;
  if (signal?.aborted) throw new Error('Launch cancelled.');
  const child = spawn(engineBinary, ['--listen', '127.0.0.1:0', ...(runtimeFile ? ['--config', runtimeFile] : [])], {
    cwd: repository,
    stdio: ['pipe', 'pipe', 'pipe'],
    shell: false
  });
  let finish;
  const closed = new Promise(resolve => { finish = resolve; });
  let shutdown;
  let engineAddress;
  let failed;
  let childEnded = false;
  const exited = new Promise(resolve => {
    child.once('error', error => {
      childEnded = true;
      resolve();
      failed = error;
      void close(error);
    });
    child.once('exit', (code, signal) => {
      childEnded = true;
      resolve();
      if (!shutdown) {
        const detail = formatRedactedDiagnostics(engineStderr, 1024).trim();
        failed = new Error(`Engine exited unexpectedly (${signal ?? code}).${detail ? ' ' + detail : ''}`);
        void close(failed);
      }
    });
  });

  function close(error) {
    if (shutdown) return shutdown;
    shutdown = (async () => {
      signal?.removeEventListener('abort', cancelled);
      const deadline = setTimeout(() => {
        server?.closeAllConnections();
        if (!childEnded) child.kill('SIGKILL');
      }, 10000);
      if (!childEnded) {
        child.stdin.end();
        child.kill('SIGTERM');
      }
      await Promise.all([
        exited,
        new Promise(resolve => {
          if (server) {
            server.close(resolve);
            server.closeIdleConnections();
          } else {
            resolve();
          }
        })
      ]);
      clearTimeout(deadline);
      finish({ exitCode: error ? 1 : 0, error });
    })();
    return shutdown;
  }

  function cancelled() {
    failed = new Error('Launch cancelled.');
    void close();
  }
  signal?.addEventListener('abort', cancelled, { once: true });
  child.stdin.on('error', () => {});
  let engineStderr = '';
  child.stderr.on('data', chunk => {
    engineStderr = (engineStderr + chunk.toString('utf8')).slice(-4096);
    process.stderr.write(formatRedactedDiagnostics(chunk.toString('utf8'), 2048));
  });
  child.stderr.resume();

  const startup = signal ? AbortSignal.any([signal, AbortSignal.timeout(10000)]) : AbortSignal.timeout(10000);
  try {
    engineAddress = await new Promise((accept, reject) => {
      let bytes = '';
      const abort = () => {
        cleanup();
        reject(new Error('Engine startup cancelled or deadline exceeded.'));
      };
      startup.addEventListener('abort', abort, { once: true });
      const data = chunk => {
        bytes += chunk.toString('utf8');
        if (Buffer.byteLength(bytes) > 4096) {
          cleanup();
          reject(new Error('Invalid engine startup response.'));
          return;
        }
        if (!bytes.includes('\n')) return;
        try {
          const ready = JSON.parse(bytes.slice(0, bytes.indexOf('\n')));
          if (ready.service !== 'keyhelix-engine' || ready.pid !== child.pid || !/^127\.0\.0\.1:[1-9]\d{0,4}$/.test(ready.address)) {
            throw new Error('Invalid engine startup response.');
          }
          cleanup();
          accept(ready.address);
        } catch (error) {
          cleanup();
          reject(error);
        }
      };
      child.stdout.on('data', data);
      closed.then(result => reject(failed ?? result.error ?? new Error('Launch cancelled.')));
      const cleanup = () => {
        startup.removeEventListener('abort', abort);
        child.stdout.removeListener('data', data);
        child.stdout.resume();
      };
      child.stdout.once('end', cleanup);
      exited.then(() => reject(failed ?? new Error('Engine exited during startup.')));
    });

    const health = await readEngineHealth(engineAddress, startup);
    if (runtimeFile) {
      const readiness = await readEngineReadiness(engineAddress, AbortSignal.any([startup, AbortSignal.timeout(15000)]));
      if (readiness.status !== 'ready') throw new Error('Engine is running but not ready: ' + JSON.stringify(readiness));
    }
    if (health.coreReady !== Boolean(runtimeFile)) throw new Error('Engine capability does not match the requested runtime mode.');
    if (failed || shutdown) throw failed ?? new Error('Launch cancelled.');

    // Public configuration always reports engineEnabled=false; the shell learns
    // domain capability from the engine readiness endpoint instead.
    server = createWebServer({ root: publicRoot, config, projectId: brand.slug, engineAddress });
    server.on('error', error => { failed = error; void close(error); });

    await new Promise((accept, reject) => {
      const abort = () => reject(new Error('Web startup deadline exceeded.'));
      startup.addEventListener('abort', abort, { once: true });
      server.once('error', reject);
      closed.then(result => reject(result.error ?? new Error('Launch cancelled.')));
      server.listen(port, host, () => {
        startup.removeEventListener('abort', abort);
        accept();
      });
    });

    if (failed || shutdown) throw failed ?? new Error('Launch cancelled.');
    return { server, child, engineAddress, config, coreReady: health.coreReady, close, closed };
  } catch (error) {
    await close(error);
    throw error;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const controller = new AbortController();
  for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, () => controller.abort());
  try {
    const options = { host: '127.0.0.1', port: '4173', root: 'dist/web', config: 'ops/web/runtime-config.json', runtime: '.local-data/runtime.json', providers: 'ensure' };
    const args = process.argv.slice(2);
    for (let i = 0; i < args.length; i += 2) {
      const key = args[i].slice(2);
      if (!args[i].startsWith('--') || !Object.hasOwn(options, key) || !args[i + 1]) {
        throw new Error('Usage: npm start [--host loopback] [--port number] [--root path] [--config path] [--runtime path] [--providers ensure|reuse]');
      }
      options[key] = args[i + 1];
    }
    if (!/^\d+$/.test(options.port)) throw new Error('Invalid port.');
    if (!['ensure', 'reuse'].includes(options.providers)) throw new Error('Invalid provider mode.');
    const running = await startLocal({
      host: options.host,
      port: Number(options.port),
      root: resolve(options.root),
      configPath: resolve(options.config),
      runtimeFile: resolve(options.runtime),
      ensureProviderServices: options.providers === 'ensure',
      signal: controller.signal
    });
    console.log(JSON.stringify({
      service: 'keyhelix-local',
      host: options.host,
      port: running.server.address().port,
      enginePid: running.child.pid,
      engineAddress: running.engineAddress,
      coreReady: running.coreReady,
      engineEnabled: running.config.engineEnabled
    }));
    const result = await running.closed;
    if (result.error) console.error(result.error.message);
    process.exitCode = result.exitCode;
  } catch (error) {
    console.error(error.message);
    process.exitCode = controller.signal.aborted ? 0 : 1;
  }
}
