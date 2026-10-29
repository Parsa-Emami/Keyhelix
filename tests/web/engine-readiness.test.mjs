import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { once } from 'node:events';
import { createWebServer, readEngineReadiness, formatRedactedDiagnostics } from '../../scripts/serve-web.mjs';
import { startLocal } from '../../scripts/start-local.mjs';

const config = { projectId: 'keyhelix', apiBasePath: '/api', engineEnabled: false, maxPreviewBytes: 1048576 };

async function workspace(t) {
  const root = await mkdtemp(join(tmpdir(), 'keyhelix-readiness-'));
  await mkdir(join(root, 'web'));
  await writeFile(join(root, 'web/index.html'), '<h1>readiness workspace</h1>');
  await writeFile(join(root, 'config.json'), JSON.stringify(config));
  t.after(() => rm(root, { recursive: true, force: true }));
  return { root: join(root, 'web'), configPath: join(root, 'config.json'), port: 0 };
}

test('formatRedactedDiagnostics bounds length and strictly sanitizes sentinel and auth secrets', () => {
  // 1. Sentinel canary sanitization
  const canaryInput = 'Operation failed on sentinel sentinel-canary-c29-secret-test-77a1 while querying store';
  const canaryOutput = formatRedactedDiagnostics(canaryInput);
  assert.ok(!canaryOutput.includes('sentinel-canary-c29-secret-test-77a1'), 'Sentinel canary must not appear in output');
  assert.ok(canaryOutput.includes('[REDACTED]'), 'Redaction placeholder must be present');

  // 2. Auth Bearer token sanitization
  const bearerInput = 'API authorization Bearer eyJhbGciOiJIUzI1NiJ9.synthetic_token_123';
  const bearerOutput = formatRedactedDiagnostics(bearerInput);
  assert.ok(!bearerOutput.includes('synthetic_token_123'));
  assert.ok(bearerOutput.includes('[REDACTED]'));

  // 3. Session cookie sanitization
  const cookieInput = 'Cookie header keyhelix_session=sess_synth_secret_val_456; Path=/';
  const cookieOutput = formatRedactedDiagnostics(cookieInput);
  assert.ok(!cookieOutput.includes('sess_synth_secret_val_456'));
  assert.ok(cookieOutput.includes('[REDACTED]'));

  // 4. Bounded log length truncation
  const longEntry = 'A'.repeat(4000);
  const boundedOutput = formatRedactedDiagnostics(longEntry, 2048);
  assert.ok(Buffer.byteLength(boundedOutput) <= 2048 + 50);
  assert.ok(boundedOutput.includes('[TRUNCATED]'));
});

test('web health and diagnostics are cleanly separated when engine is not integrated', async t => {
  const dir = await mkdtemp(join(tmpdir(), 'web-readiness-standalone-'));
  const root = join(dir, 'public');
  await mkdir(root, { recursive: true });
  await writeFile(join(root, 'index.html'), '<!doctype html><h1>readiness</h1>');

  const server = createWebServer({ root, config, projectId: 'keyhelix' });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const base = `http://127.0.0.1:${server.address().port}`;

  t.after(async () => {
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
    await rm(dir, { recursive: true, force: true });
  });

  // 1. Web health remains 200
  const healthRes = await fetch(base + '/healthz');
  assert.equal(healthRes.status, 200);
  const healthJson = await healthRes.json();
  assert.deepEqual(healthJson, { status: 'ok', scope: 'web-shell' });

  // 2. Diagnostics reports web ok and engine disabled
  const diagRes = await fetch(base + '/api/diagnostics');
  assert.equal(diagRes.status, 200);
  const diagJson = await diagRes.json();
  assert.equal(diagJson.status, 'ready');
  assert.equal(diagJson.components.web.status, 'ok');
  assert.equal(diagJson.components.engine.status, 'disabled');

  // 3. Unimplemented engine routes return 503
  assert.equal((await fetch(base + '/api/engine/health')).status, 503);
  assert.equal((await fetch(base + '/api/engine/readiness')).status, 503);
});

test('real launcher exposes engine health, readiness, and unified diagnostics with visibility into engine outage', async t => {
  const options = await workspace(t);
  const running = await startLocal(options);
  t.after(() => running.close());

  const base = `http://127.0.0.1:${running.server.address().port}`;

  // 1. Web Health (Liveness)
  const webHealth = await (await fetch(base + '/healthz')).json();
  assert.deepEqual(webHealth, { status: 'ok', scope: 'web-shell' });

  // 2. Engine Health (Liveness)
  const engineHealthRes = await fetch(base + '/api/engine/health');
  assert.equal(engineHealthRes.status, 200);
  const engineHealth = await engineHealthRes.json();
  assert.equal(engineHealth.status, 'ok');
  assert.equal(engineHealth.scope, 'engine-runtime');

  // 3. Engine Readiness
  const engineReadyRes = await fetch(base + '/api/engine/readiness');
  assert.equal(engineReadyRes.status, 200);
  const engineReady = await engineReadyRes.json();
  assert.equal(engineReady.status, 'ready');
  assert.equal(engineReady.scope, 'engine-runtime');
  assert.equal(engineReady.storage, 'ready');

  // 4. Composite Diagnostics
  const diagRes = await fetch(base + '/api/diagnostics');
  assert.equal(diagRes.status, 200);
  const diagJson = await diagRes.json();
  assert.equal(diagJson.status, 'ready');
  assert.equal(diagJson.components.web.status, 'ok');
  assert.equal(diagJson.components.engine.status, 'ready');
  assert.equal(diagJson.components.storage.status, 'ready');
  assert.equal(diagJson.components.provider.status, 'ready');

  // 5. Direct readEngineReadiness utility call
  const directReadiness = await readEngineReadiness(running.engineAddress);
  assert.equal(directReadiness.status, 'ready');
  assert.equal(directReadiness.storage, 'ready');
});

test('engine outage is visibly reported as 503 while web server detects the failure', async t => {
  const dir = await mkdtemp(join(tmpdir(), 'web-readiness-down-'));
  const root = join(dir, 'public');
  await mkdir(root, { recursive: true });
  await writeFile(join(root, 'index.html'), '<!doctype html><h1>readiness</h1>');

  // Create web server pointing to non-existent engine port
  const deadEngineAddress = '127.0.0.1:49999';
  const server = createWebServer({ root, config, projectId: 'keyhelix', engineAddress: deadEngineAddress });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const base = `http://127.0.0.1:${server.address().port}`;

  t.after(async () => {
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
    await rm(dir, { recursive: true, force: true });
  });

  // 1. Web liveness remains healthy (separation of concerns)
  const healthRes = await fetch(base + '/healthz');
  assert.equal(healthRes.status, 200);

  // 2. Engine health returns explicit 503
  const engineHealthRes = await fetch(base + '/api/engine/health');
  assert.equal(engineHealthRes.status, 503);
  assert.deepEqual(await engineHealthRes.json(), { error: 'engine_unavailable' });

  // 3. Engine readiness returns explicit 503
  const engineReadyRes = await fetch(base + '/api/engine/readiness');
  assert.equal(engineReadyRes.status, 503);
  assert.deepEqual(await engineReadyRes.json(), { error: 'engine_unavailable' });

  // 4. Composite diagnostics reports failing state with 503
  const diagRes = await fetch(base + '/api/diagnostics');
  assert.equal(diagRes.status, 503);
  const diagJson = await diagRes.json();
  assert.equal(diagJson.status, 'not_ready');
  assert.equal(diagJson.components.web.status, 'ok');
  assert.equal(diagJson.components.engine.status, 'unavailable');
});
