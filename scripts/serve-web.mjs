import http from 'node:http';
import { readFile, realpath, stat } from 'node:fs/promises';
import { resolve, relative, extname, isAbsolute } from 'node:path';
import { pathToFileURL } from 'node:url';
import { validateRuntimeConfig, validateHealth } from '../apps/web/src/lib/runtime-config.mjs';

const types = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.webmanifest': 'application/manifest+json'
};
const csp = "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; manifest-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'";

const SENSITIVE_PATTERNS = [
  /sentinel-canary-[a-z0-9-_]+/gi,
  /\bBearer\s+[A-Za-z0-9\-._~+/]+=*/gi,
  /keyhelix_session=[^;\s]+/gi,
  /su_[a-z0-9-_]+/gi,
  /"(?:password|secret|token|apiKey|clientSecret)":\s*"[^"]+"/gi
];

export function formatRedactedDiagnostics(entry, maxBytes = 2048) {
  if (entry === null || entry === undefined) return '';
  let str = typeof entry === 'string' ? entry : JSON.stringify(entry);
  for (const pattern of SENSITIVE_PATTERNS) {
    str = str.replace(pattern, '[REDACTED]');
  }
  if (Buffer.byteLength(str, 'utf8') > maxBytes) {
    const buf = Buffer.from(str, 'utf8').subarray(0, maxBytes);
    return buf.toString('utf8') + '...[TRUNCATED]';
  }
  return str;
}

export function readEngineHealth(address, signal) {
  if (!/^127\.0\.0\.1:[1-9]\d{0,4}$/.test(address) || Number(address.split(':')[1]) > 65535) {
    return Promise.reject(new Error('Invalid loopback engine address.'));
  }
  return new Promise((accept, reject) => {
    const request = http.get(`http://${address}/healthz`, {
      agent: false,
      signal: signal ? AbortSignal.any([signal, AbortSignal.timeout(2000)]) : AbortSignal.timeout(2000)
    }, response => {
      if (response.statusCode !== 200) {
        response.destroy();
        reject(new Error('Engine unavailable.'));
        return;
      }
      let body = '';
      response.on('data', chunk => {
        body += chunk.toString('utf8');
        if (Buffer.byteLength(body) > 4096) response.destroy(new Error('Engine health exceeds limit.'));
      });
      response.on('error', reject);
      response.on('end', () => {
        try {
          accept(validateHealth(JSON.parse(body)));
        } catch (error) {
          reject(error);
        }
      });
    });
    request.on('error', reject);
  });
}

export function readEngineReadiness(address, signal) {
  if (!/^127\.0\.0\.1:[1-9]\d{0,4}$/.test(address) || Number(address.split(':')[1]) > 65535) {
    return Promise.reject(new Error('Invalid loopback engine address.'));
  }
  return new Promise((accept, reject) => {
    const request = http.get(`http://${address}/readyz`, {
      agent: false,
      signal: signal ? AbortSignal.any([signal, AbortSignal.timeout(2000)]) : AbortSignal.timeout(2000)
    }, response => {
      if (response.statusCode !== 200 && response.statusCode !== 503) {
        response.destroy();
        reject(new Error('Engine unavailable.'));
        return;
      }
      let body = '';
      response.on('data', chunk => {
        body += chunk.toString('utf8');
        if (Buffer.byteLength(body) > 4096) response.destroy(new Error('Engine readiness exceeds limit.'));
      });
      response.on('error', reject);
      response.on('end', () => {
        try {
          const parsed = JSON.parse(body);
          if (parsed.scope !== 'engine-runtime' || !['ready', 'not_ready'].includes(parsed.status)) {
            throw new Error('Invalid engine readiness response.');
          }
          accept(parsed);
        } catch (error) {
          reject(error);
        }
      });
    });
    request.on('error', reject);
  });
}

export function proxyToEngine(engineAddress, req, res) {
  if (!/^127\.0\.0\.1:[1-9]\d{0,4}$/.test(engineAddress)) {
    res.writeHead(503, { 'Content-Type': 'application/json; charset=utf-8' });
    res.end(JSON.stringify({ error: 'engine_unavailable' }));
    return;
  }
  const headers = {};
  for (const name of ['accept', 'content-type', 'cookie', 'origin', 'x-keyhelix-stepup', 'user-agent', 'cache-control', 'pragma']) {
    if (req.headers[name] !== undefined) headers[name] = req.headers[name];
  }
  const upstream = http.request({
    host: '127.0.0.1',
    port: Number(engineAddress.split(':')[1]),
    method: req.method,
    path: req.url,
    headers,
    timeout: 15000
  }, response => {
    const outgoing = {};
    for (const [name, value] of Object.entries(response.headers)) {
      if (['connection', 'keep-alive', 'transfer-encoding', 'upgrade', 'content-length'].includes(name)) continue;
      outgoing[name] = value;
    }
    res.writeHead(response.statusCode ?? 502, outgoing);
    response.pipe(res);
  });
  upstream.on('timeout', () => upstream.destroy(new Error('engine timeout')));
  upstream.on('error', () => {
    if (res.headersSent) {
      res.destroy();
      return;
    }
    res.writeHead(503, { 'Content-Type': 'application/json; charset=utf-8' });
    res.end(JSON.stringify({ error: 'engine_unavailable' }));
  });
  let received = 0;
  req.on('data', chunk => {
    received += chunk.length;
    if (received > 1114112) upstream.destroy(new Error('request too large'));
  });
  req.pipe(upstream);
}

export function createWebServer({ root, config, projectId, engineAddress }) {
  const valid = validateRuntimeConfig(config, projectId);
  const publicRoot = resolve(root);
  const within = path => {
    const diff = relative(publicRoot, path);
    return diff !== '..' && !diff.startsWith('../') && !isAbsolute(diff);
  };
  return http.createServer({ requestTimeout: 15000, headersTimeout: 10000, keepAliveTimeout: 5000, maxHeaderSize: 16384 }, async (req, res) => {
    res.setHeader('Content-Security-Policy', csp);
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Cache-Control', 'no-store');
    const send = (status, body, type = 'application/json; charset=utf-8') => {
      res.writeHead(status, { 'Content-Type': type, 'Content-Length': Buffer.byteLength(body) });
      res.end(req.method === 'HEAD' ? undefined : body);
    };
    const apiRequest = (req.url ?? '/').startsWith('/api/') || (req.url ?? '/') === '/api';
    if (!apiRequest && !['GET', 'HEAD'].includes(req.method ?? '')) {
      res.setHeader('Allow', 'GET, HEAD');
      send(405, '{"error":"method_not_allowed"}');
      return;
    }
    let path;
    try {
      path = decodeURIComponent((req.url ?? '/').split('?')[0]);
      if (!path.startsWith('/') || path.includes('\\') || path.includes('\0') || path.split('/').some(part => part.startsWith('.'))) throw new Error();
    } catch {
      send(400, '{"error":"invalid_path"}');
      return;
    }
    if (['/api/engine/health', '/api/engine/readiness', '/api/diagnostics', '/runtime-config.json'].includes(path)) {
      if (!['GET', 'HEAD'].includes(req.method ?? '')) {
        res.setHeader('Allow', 'GET, HEAD');
        send(405, '{"error":"method_not_allowed"}');
        return;
      }
    }
    if (path === '/healthz') {
      send(200, '{"status":"ok","scope":"web-shell"}');
      return;
    }
    if (path === '/readyz') {
      try {
        await stat(resolve(publicRoot, 'index.html'));
        let engineReady = false;
        if (engineAddress) {
          try {
            // Domain admission requires both a healthy engine and a composed core;
            // a foundation engine answers /readyz but cannot process secrets.
            const [readiness, health] = await Promise.all([
              readEngineReadiness(engineAddress, AbortSignal.timeout(2000)),
              readEngineHealth(engineAddress, AbortSignal.timeout(2000))
            ]);
            engineReady = readiness.status === 'ready' && health.coreReady;
          } catch {
            engineReady = false;
          }
        }
        send(engineAddress && !engineReady ? 503 : 200, JSON.stringify({ status: engineAddress ? (engineReady ? 'ready' : 'not_ready') : 'ready', scope: 'web-shell', engineReady }));
      } catch {
        send(503, '{"status":"not_ready","scope":"web-shell","engineReady":false}');
      }
      return;
    }
    if (path === '/api/engine/health' && engineAddress) {
      try {
        send(200, JSON.stringify(await readEngineHealth(engineAddress)));
      } catch {
        send(503, '{"error":"engine_unavailable"}');
      }
      return;
    }
    if (path === '/api/engine/readiness' && engineAddress) {
      try {
        send(200, JSON.stringify(await readEngineReadiness(engineAddress)));
      } catch {
        send(503, '{"error":"engine_unavailable"}');
      }
      return;
    }
    if (path === '/api/diagnostics') {
      let webStatus = { status: 'ok', scope: 'web-shell' };
      try {
        await stat(resolve(publicRoot, 'index.html'));
      } catch {
        webStatus = { status: 'not_ready', scope: 'web-shell' };
      }

      let engineInfo = null;
      let engineOk = false;
      if (engineAddress) {
        try {
          engineInfo = await readEngineReadiness(engineAddress);
          engineOk = engineInfo.status === 'ready';
        } catch {
          engineInfo = { status: 'unavailable', error: 'engine_unavailable' };
          engineOk = false;
        }
      } else {
        engineInfo = { status: 'disabled', scope: 'engine-runtime' };
      }

      const isReady = webStatus.status === 'ok' && (engineAddress ? engineOk : true);
      const statusCode = isReady ? 200 : 503;

      const report = {
        status: isReady ? 'ready' : 'not_ready',
        scope: 'composite-diagnostics',
        timestamp: new Date().toISOString(),
        components: {
          web: webStatus,
          engine: engineInfo,
          storage: { status: engineInfo?.storage === 'ready' ? 'ready' : engineOk ? 'unknown' : 'unavailable' },
          provider: { status: engineInfo?.provider?.state === 'ready' ? 'ready' : engineOk ? 'unknown' : 'unavailable' },
          identity_provider: { status: engineInfo?.identity_provider?.state === 'ready' ? 'ready' : engineOk ? 'unknown' : 'unavailable' }
        }
      };

      send(statusCode, JSON.stringify(report));
      return;
    }
    if (path === '/api' || path.startsWith('/api/')) {
      if (engineAddress) {
        proxyToEngine(engineAddress, req, res);
      } else {
        send(503, '{"error":"engine_not_integrated"}');
      }
      return;
    }
    if (path === '/runtime-config.json') {
      send(200, JSON.stringify(valid));
      return;
    }
    const asset = path.startsWith('/assets/');
    if (!(asset || ['/', '/index.html', '/icon.svg', '/manifest.webmanifest', '/robots.txt'].includes(path))) {
      send(404, '{"error":"not_found"}');
      return;
    }
    try {
      const filename = await realpath(resolve(publicRoot, '.' + (path === '/' ? '/index.html' : path)));
      if (!within(filename) || !(await stat(filename)).isFile()) {
        send(404, '{"error":"not_found"}');
        return;
      }
      const bytes = await readFile(filename);
      res.writeHead(200, {
        'Content-Type': types[extname(filename)] ?? 'application/octet-stream',
        'Content-Length': bytes.length,
        'Cache-Control': asset ? 'public, max-age=31536000, immutable' : 'no-store'
      });
      res.end(req.method === 'HEAD' ? undefined : bytes);
    } catch {
      send(404, '{"error":"not_found"}');
    }
  });
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const args = process.argv.slice(2);
  const options = { host: '127.0.0.1', port: '4173', root: 'dist/web', config: 'ops/web/runtime-config.json' };
  for (let i = 0; i < args.length; i += 2) {
    const key = args[i].slice(2);
    if (!args[i].startsWith('--') || !Object.hasOwn(options, key) || !args[i + 1]) {
      throw new Error('Usage: node scripts/serve-web.mjs [--host 127.0.0.1] [--port 4173] [--root dist/web] [--config path]');
    }
    options[key] = args[i + 1];
  }
  if (!['127.0.0.1', '::1'].includes(options.host)) throw new Error('Bind to loopback and use the documented TLS proxy.');
  if (!/^\d+$/.test(options.port) || +options.port < 1 || +options.port > 65535) throw new Error('Invalid port.');
  const product = JSON.parse(await readFile(new URL('../ops/web/brand.json', import.meta.url), 'utf8'));
  const config = JSON.parse(await readFile(resolve(options.config), 'utf8'));
  await stat(resolve(options.root, 'index.html'));
  const server = createWebServer({ root: options.root, config, projectId: product.slug });
  server.maxRequestsPerSocket = 1000;
  server.on('error', error => { console.error(error.message); process.exitCode = 1; });
  server.listen(+options.port, options.host, () => console.log(JSON.stringify({ service: product.slug + '-web', host: options.host, port: +options.port, engineReady: Boolean(options.engine) })));
  for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, () => {
    server.close(() => process.exit(0));
    setTimeout(() => { server.closeAllConnections(); process.exit(1); }, 10000).unref();
  });
}
