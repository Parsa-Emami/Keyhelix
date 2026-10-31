import test from 'node:test';
import assert from 'node:assert/strict';
import { access, mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import http from 'node:http';
import { once } from 'node:events';

const config = { projectId: 'keyhelix', apiBasePath: '/api', engineEnabled: false, maxPreviewBytes: 1048576 };

async function workspace(t) {
  const root = await mkdtemp(join(tmpdir(), 'keyhelix-launch-'));
  await mkdir(join(root, 'web'));
  await writeFile(join(root, 'web/index.html'), '<h1>synthetic workspace</h1>');
  await writeFile(join(root, 'config.json'), JSON.stringify(config));
  t.after(() => rm(root, { recursive: true, force: true }));
  return { root: join(root, 'web'), configPath: join(root, 'config.json'), port: 0 };
}

test('real launcher serves engine health, preserves disabled admission, stops and restarts', async t => {
  await assert.doesNotReject(access(new URL('../../scripts/start-local.mjs', import.meta.url)), 'C03 launcher must exist');
  const { startLocal } = await import('../../scripts/start-local.mjs');
  const options = await workspace(t);
  for (let iteration = 0; iteration < 2; iteration++) {
    const running = await startLocal(options);
    t.after(() => running.close());
    const base = `http://127.0.0.1:${running.server.address().port}`;
    const health = await (await fetch(base + '/api/engine/health')).json();
    assert.match(health.toolchain, /^go1\.2[67]\.\d+$/);
    assert.deepEqual(health, { status: 'ok', scope: 'engine-runtime', version: '0.0.1', toolchain: health.toolchain, coreReady: false });
    assert.equal((await fetch(base + '/api/v1/unimplemented')).status, 503);
    assert.equal((await fetch(base + '/api/engine/health', { method: 'POST' })).status, 405);
    assert.equal((await (await fetch(base + '/runtime-config.json')).json()).engineEnabled, false);
    assert.equal((await (await fetch(base + '/readyz')).json()).engineReady, false);
    await running.close();
    assert.equal((await running.closed).exitCode, 0);
    assert.throws(() => process.kill(running.child.pid, 0), /ESRCH/);
    await assert.rejects(fetch(base + '/healthz'));
  }
});

test('engine crash stops the web listener with a failing outcome', async t => {
  const { startLocal } = await import('../../scripts/start-local.mjs');
  const running = await startLocal(await workspace(t));
  t.after(() => running.close());
  const base = `http://127.0.0.1:${running.server.address().port}`;
  assert.equal((await fetch(base + '/healthz')).status, 200);
  process.kill(running.child.pid, 'SIGKILL');
  const outcome = await running.closed;
  assert.equal(outcome.exitCode, 1);
  await assert.rejects(fetch(base + '/healthz'));
});

test('occupied web port fails closed before launch', async t => {
  const { startLocal } = await import('../../scripts/start-local.mjs');
  const blocker = http.createServer((_req, res) => res.end('occupied'));
  blocker.listen(0, '127.0.0.1');
  await once(blocker, 'listening');
  const port = blocker.address().port;
  t.after(() => new Promise(resolve => blocker.close(resolve)));
  const options = { ...(await workspace(t)), port };
  await assert.rejects(startLocal(options), /EADDRINUSE/);
});

test('abort signal cancels launch and cleans up resources', async t => {
  const { startLocal } = await import('../../scripts/start-local.mjs');
  const controller = new AbortController();
  controller.abort();
  await assert.rejects(startLocal({ ...(await workspace(t)), signal: controller.signal }), /cancelled/i);
});
