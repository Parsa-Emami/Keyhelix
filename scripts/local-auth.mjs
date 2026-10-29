// Drives the synthetic local Keycloak login form exactly as a browser would:
// authorization redirect, HTML form submission, callback and session cookie.
// It is test tooling only; it does not bypass PKCE, nonce, state or signatures.

export class CookieJar {
  constructor() {
    this.cookies = new Map();
  }

  header(url) {
    const host = new URL(url).host;
    return [...this.cookies.entries()]
      .filter(([key]) => key.startsWith(host + ' '))
      .map(([, cookie]) => `${cookie.name}=${cookie.value}`)
      .join('; ');
  }

  store(url, response) {
    const host = new URL(url).host;
    const values = response.headers.getSetCookie?.() ?? [];
    for (const raw of values) {
      const [pair, ...attributes] = raw.split(';');
      const index = pair.indexOf('=');
      if (index < 1) continue;
      const name = pair.slice(0, index).trim();
      const value = pair.slice(index + 1);
      const expired = attributes.some(attribute => /^\s*max-age=0\s*$/i.test(attribute));
      const key = host + ' ' + name;
      if (expired) this.cookies.delete(key);
      else this.cookies.set(key, { name, value });
    }
  }
}

export async function request(url, { jar, method = 'GET', headers = {}, body, redirect = 'manual' } = {}) {
  const cookie = jar?.header(url);
  const response = await fetch(url, {
    method,
    body,
    redirect,
    headers: {
      ...headers,
      ...(cookie ? { cookie } : {})
    },
    signal: AbortSignal.timeout(15000)
  });
  if (jar) jar.store(url, response);
  return response;
}

function decodeFormAction(html) {
  const match = html.match(/<form[^>]*id="kc-form-login"[^>]*action="([^"]+)"/i) ?? html.match(/<form[^>]*action="([^"]+)"/i);
  return match ? match[1].replaceAll('&amp;', '&') : null;
}

async function submitCredentials(url, { jar, username, password }) {
  const page = await request(url, { jar });
  if (page.status !== 200) {
    const detail = await page.text();
    throw new Error(`Keycloak login page returned ${page.status}: ${detail.slice(0, 200)}`);
  }
  const html = await page.text();
  const action = decodeFormAction(html);
  if (!action) throw new Error('Keycloak login form was not found.');
  const form = new URLSearchParams({ username, password, credentialId: '' });
  const submitted = await request(action.startsWith('http') ? action : new URL(action, url).toString(), {
    jar,
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: form
  });
  if (submitted.status !== 302 && submitted.status !== 303) {
    const detail = await submitted.text();
    throw new Error(`Synthetic credential submission failed with ${submitted.status}: ${detail.slice(0, 200)}`);
  }
  return submitted.headers.get('location');
}

async function follow(url, jar) {
  let current = url;
  for (let hop = 0; hop < 10; hop += 1) {
    const response = await request(current, { jar });
    if (response.status >= 300 && response.status < 400 && response.headers.get('location')) {
      current = new URL(response.headers.get('location'), current).toString();
      continue;
    }
    return { response, url: current };
  }
  throw new Error('Too many redirects during the local OIDC flow.');
}

export async function signIn({ origin, username = 'alice', password = 'keyhelix-local-alice' }) {
  const jar = new CookieJar();
  const started = await request(`${origin}/api/v1/auth/login?return_to=/`, { jar });
  if (started.status !== 303 || !started.headers.get('location')) {
    throw new Error(`Login start failed with ${started.status}`);
  }
  const callback = await submitCredentials(started.headers.get('location'), { jar, username, password });
  const finished = await follow(callback, jar);
  if (finished.response.status !== 200) throw new Error(`Login callback did not complete: ${finished.response.status}`);
  return jar;
}

export async function stepUp({ origin, jar, action, resource, returnTo = '/', username = 'alice', password = 'keyhelix-local-alice' }) {
  const query = new URLSearchParams({ action, resource, return_to: returnTo });
  const started = await request(`${origin}/api/v1/auth/step-up?${query}`, { jar });
  if (started.status !== 303 || !started.headers.get('location')) {
    const detail = await started.text();
    throw new Error(`Step-up start failed with ${started.status}: ${detail.slice(0, 200)}`);
  }
  const callback = await submitCredentials(started.headers.get('location'), { jar, username, password });
  const finished = await follow(callback, jar);
  if (finished.response.status !== 200) throw new Error(`Step-up did not complete: ${finished.response.status}`);
  return finished.url;
}

export async function api(origin, jar, path, { method = 'GET', body, headers = {} } = {}) {
  const response = await request(origin + path, {
    jar,
    method,
    body: body === undefined ? undefined : JSON.stringify(body),
    headers: {
      origin,
      ...(body === undefined ? {} : { 'content-type': 'application/json' }),
      ...headers
    }
  });
  const text = await response.text();
  let data = null;
  try { data = JSON.parse(text); } catch {}
  return { status: response.status, data, text, headers: response.headers };
}
