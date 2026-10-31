import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { once } from 'node:events';
import http from 'node:http';
import { createWebServer, isAllowedHost, isAllowedOrigin, proxyToEngine } from '../../scripts/serve-web.mjs';

const config = { projectId: 'keyhelix', apiBasePath: '/api', engineEnabled: false, maxPreviewBytes: 1048576 };

async function createTestServer(t, options = {}) {
  const dir = await mkdtemp(join(tmpdir(), 'keyhelix-network-'));
  const root = join(dir, 'public');
  await mkdir(join(root, 'assets'), { recursive: true });
  await writeFile(join(root, 'index.html'), '<!doctype html><h1>KeyHelix Network Hardened</h1>');
  await writeFile(join(root, 'assets', 'bundle-abc123.js'), 'console.log("immutable asset");');
  t.after(() => rm(dir, { recursive: true, force: true }));

  const server = createWebServer({
    root,
    config,
    projectId: 'keyhelix',
    ...options
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const port = server.address().port;
  t.after(async () => {
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
  });

  return { server, port, base: `http://127.0.0.1:${port}` };
}

test('isAllowedHost permits loopback hosts and rejects foreign hosts (DNS rebinding defense)', () => {
  const allowed = [
    'localhost',
    'localhost:4173',
    '127.0.0.1',
    '127.0.0.1:4173',
    '127.0.0.1:4305',
    '::1',
    '[::1]',
    '[::1]:4173'
  ];
  for (const host of allowed) {
    assert.equal(isAllowedHost(host), true, `Host "${host}" should be allowed`);
  }

  const rejected = [
    'evil.com',
    'attacker.example.com',
    '192.168.1.1',
    '10.0.0.1',
    'keyhelix.local',
    '',
    null,
    undefined,
    'evil.com:4173'
  ];
  for (const host of rejected) {
    assert.equal(isAllowedHost(host), false, `Host "${host}" should be rejected`);
  }

  assert.equal(isAllowedHost('private.vault.internal:4305', ['private.vault.internal']), true);
  assert.equal(isAllowedHost('other.vault.internal:4305', ['private.vault.internal']), false);
});

test('isAllowedOrigin permits same-origin and loopback, and rejects untrusted cross-origin requests', () => {
  assert.equal(isAllowedOrigin(undefined, '127.0.0.1:4173'), true);
  assert.equal(isAllowedOrigin(null, '127.0.0.1:4173'), true);

  assert.equal(isAllowedOrigin('http://127.0.0.1:4173', '127.0.0.1:4173'), true);
  assert.equal(isAllowedOrigin('http://localhost:4173', '127.0.0.1:4173'), true);
  assert.equal(isAllowedOrigin('http://localhost:4173', 'localhost:4173'), true);
  assert.equal(isAllowedOrigin('http://[::1]:4173', '[::1]:4173'), true);

  assert.equal(isAllowedOrigin('http://evil.com', '127.0.0.1:4173'), false);
  assert.equal(isAllowedOrigin('https://attacker.invalid', '127.0.0.1:4173'), false);
  assert.equal(isAllowedOrigin('http://192.168.1.100:4173', '127.0.0.1:4173'), false);
  assert.equal(isAllowedOrigin('not-a-valid-url', '127.0.0.1:4173'), false);

  assert.equal(isAllowedOrigin('https://private.vault.internal', 'private.vault.internal:4305', ['private.vault.internal']), true);
});

test('HTTP server rejects foreign Host header with 400 Bad Request', async t => {
  const { port } = await createTestServer(t);

  const request = (hostHeader, path = '/healthz') => new Promise((resolve, reject) => {
    const req = http.request({
      host: '127.0.0.1',
      port,
      path,
      method: 'GET',
      headers: { Host: hostHeader }
    }, res => {
      let body = '';
      res.on('data', chunk => { body += chunk; });
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body }));
    });
    req.on('error', reject);
    req.end();
  });

  const okRes = await request(`127.0.0.1:${port}`);
  assert.equal(okRes.status, 200);
  assert.deepEqual(JSON.parse(okRes.body), { status: 'ok', scope: 'web-shell' });

  const badHostRes = await request('evil-attacker.example.com');
  assert.equal(badHostRes.status, 400);
  assert.deepEqual(JSON.parse(badHostRes.body), { error: 'invalid_host' });
  assert.equal(badHostRes.headers['cache-control'], 'no-store');
  assert.equal(badHostRes.headers['pragma'], 'no-cache');
});

test('HTTP server rejects untrusted Origin header on /api with 403 Forbidden', async t => {
  const { port } = await createTestServer(t);

  const request = (originHeader, path = '/api/v1/auth/session') => new Promise((resolve, reject) => {
    const req = http.request({
      host: '127.0.0.1',
      port,
      path,
      method: 'POST',
      headers: {
        Host: `127.0.0.1:${port}`,
        ...(originHeader ? { Origin: originHeader } : {}),
        'Content-Type': 'application/json'
      }
    }, res => {
      let body = '';
      res.on('data', chunk => { body += chunk; });
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body }));
    });
    req.on('error', reject);
    req.end();
  });

  const forbiddenRes = await request('http://evil.com');
  assert.equal(forbiddenRes.status, 403);
  assert.deepEqual(JSON.parse(forbiddenRes.body), { error: 'cross_origin_forbidden' });
  assert.equal(forbiddenRes.headers['cache-control'], 'no-store');
  assert.equal(forbiddenRes.headers['pragma'], 'no-cache');

  const allowedRes = await request(`http://127.0.0.1:${port}`);
  assert.equal(allowedRes.status, 503);
  assert.deepEqual(JSON.parse(allowedRes.body), { error: 'engine_not_integrated' });
});

test('HTTP server enforces strict cache-control boundaries between sensitive routes and static assets', async t => {
  const { base } = await createTestServer(t);

  const sensitiveRoutes = [
    '/',
    '/index.html',
    '/healthz',
    '/readyz',
    '/runtime-config.json',
    '/api/diagnostics',
    '/api/v1/session'
  ];

  for (const route of sensitiveRoutes) {
    const res = await fetch(base + route);
    assert.equal(res.headers.get('cache-control'), 'no-store', `Route ${route} must have no-store`);
    assert.equal(res.headers.get('pragma'), 'no-cache', `Route ${route} must have pragma no-cache`);
    assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
    assert.equal(res.headers.get('x-frame-options'), 'DENY');
  }

  const assetRes = await fetch(base + '/assets/bundle-abc123.js');
  assert.equal(assetRes.status, 200);
  assert.equal(assetRes.headers.get('cache-control'), 'public, max-age=31536000, immutable');
  assert.equal(assetRes.headers.get('x-content-type-options'), 'nosniff');
});

test('proxyToEngine rejects non-loopback engine addresses and sets no-store on proxied responses', async t => {
  const dummyRes = {
    statusCode: null,
    headers: null,
    body: '',
    headersSent: false,
    writeHead(status, headers) {
      this.statusCode = status;
      this.headers = headers;
    },
    end(data) {
      this.body = data;
    }
  };

  proxyToEngine('192.168.1.100:8080', { headers: {} }, dummyRes);
  assert.equal(dummyRes.statusCode, 503);
  assert.deepEqual(JSON.parse(dummyRes.body), { error: 'engine_unavailable' });

  proxyToEngine('public.cloud.com:8080', { headers: {} }, dummyRes);
  assert.equal(dummyRes.statusCode, 503);

  const mockEngine = http.createServer((_req, res) => {
    res.writeHead(200, { 'Content-Type': 'application/json', 'X-Custom-Header': 'engine-value' });
    res.end(JSON.stringify({ status: 'ok', scope: 'engine-runtime' }));
  });
  mockEngine.listen(0, '127.0.0.1');
  await once(mockEngine, 'listening');
  const enginePort = mockEngine.address().port;
  t.after(() => new Promise(resolve => mockEngine.close(resolve)));

  const { base } = await createTestServer(t, { engineAddress: `127.0.0.1:${enginePort}` });
  const proxiedRes = await fetch(base + '/api/v1/test');
  assert.equal(proxiedRes.status, 200);
  assert.equal(proxiedRes.headers.get('cache-control'), 'no-store');
  assert.equal(proxiedRes.headers.get('pragma'), 'no-cache');
  assert.equal(proxiedRes.headers.get('x-custom-header'), 'engine-value');
});

test('C32 positive, negative, and expected-output fixtures validate contract boundaries', async () => {
  const root = new URL('../../', import.meta.url);
  const read = async path => JSON.parse(await (await import('node:fs/promises')).readFile(new URL(path, root), 'utf8'));

  const positive = await read('tests/fixtures/keyhelix/C32/positive.json');
  const negative = await read('tests/fixtures/keyhelix/C32/negative.json');
  const expected = await read('tests/fixtures/keyhelix/C32/expected-output.json');

  assert.equal(positive.schema_version, 1);
  assert.equal(positive.task, 'C32');
  assert.equal(positive.requirement, 'N32');
  assert.equal(positive.network_boundaries.loopback_only, true);
  assert.equal(positive.network_boundaries.owned_domain_required, false);
  assert.ok(positive.network_boundaries.allowed_loopback_hosts.includes('127.0.0.1'));
  assert.ok(positive.network_boundaries.allowed_loopback_hosts.includes('localhost'));

  assert.equal(negative.schema_version, 1);
  assert.equal(negative.task, 'C32');
  assert.equal(negative.cases.external_host_header.expected_status, 400);
  assert.equal(negative.cases.external_host_header.expected_error, 'invalid_host');
  assert.equal(negative.cases.cross_origin_api_request.expected_status, 403);
  assert.equal(negative.cases.cross_origin_api_request.expected_error, 'cross_origin_forbidden');

  assert.equal(expected.schema_version, 1);
  assert.equal(expected.results.external_host_rejection.status, 400);
  assert.equal(expected.results.external_host_rejection.body.error, 'invalid_host');
  assert.equal(expected.results.cross_origin_api_rejection.status, 403);
  assert.equal(expected.results.cross_origin_api_rejection.body.error, 'cross_origin_forbidden');
});
