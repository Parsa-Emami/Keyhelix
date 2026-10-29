import { test, expect, type Page } from '@playwright/test';
import positive from '../fixtures/keyhelix/C30/positive.json' with { type: 'json' };

// The OIDC client registers http://localhost:4173 as its redirect origin, so this
// spec drives the real origin instead of the 127.0.0.1 test base URL.
const ORIGIN = 'http://localhost:4173';
const SENTINEL = positive.secret.plaintext_sentinel;
const secretPath = process.env.C30_SECRET_PATH ?? `${positive.secret.secret_path_prefix}${Date.now().toString(36)}`;

async function submitKeycloakCredentials(page: Page, username: string, password: string) {
  // Keycloak's forced reauthentication keeps the username and asks only for the
  // password, so both the full and the reduced login form must work.
  await page.waitForSelector('#password', { timeout: 20000 });
  const usernameField = page.locator('#username');
  if (await usernameField.isVisible().catch(() => false)) await usernameField.fill(username);
  await page.fill('#password', password);
  await page.click('#kc-login');
  await page.waitForURL(url => url.origin === ORIGIN, { timeout: 30000 });
}

async function signIn(page: Page, username: string, password: string, email: string) {
  await page.getByRole('banner').getByRole('link', { name: /Sign in/ }).click();
  await submitKeycloakCredentials(page, username, password);
  await expect(page.getByTestId('signed-in-user')).toHaveText(email);
}

test.describe('C30: reference workflow from a clone', () => {
  test('owner writes and reveals a real provider-sealed secret; member is denied', async ({ page, browser }) => {
    test.slow();

    // 0. Readiness proves storage, key provider and identity provider are composed.
    const webReady = await page.request.get(`${ORIGIN}/readyz`);
    expect(webReady.status()).toBe(200);
    expect(await webReady.json()).toMatchObject({ status: 'ready', engineReady: true });
    const engineReady = await page.request.get(`${ORIGIN}/api/engine/readiness`);
    expect(engineReady.status()).toBe(200);
    const readyBody = await engineReady.json();
    expect(readyBody.storage).toBe('ready');
    expect(readyBody.provider.state).toBe('ready');
    expect(readyBody.identity_provider.state).toBe('ready');

    await page.goto(`${ORIGIN}/#vaults`);
    await expect(page.getByTestId('vaults-console')).toBeVisible();
    await signIn(page, 'alice', 'keyhelix-local-alice', 'alice@keyhelix.local');
    await page.goto(`${ORIGIN}/#vaults`);
    await expect(page.getByTestId('vaults-console')).toBeVisible();

    // 1. Scoped write: the engine seals a fresh DEK in OpenBao and stores only metadata.
    await page.getByLabel('Secret path', { exact: true }).fill(secretPath);
    await page.getByLabel('Secret value', { exact: true }).fill(SENTINEL);
    const writeResponse = page.waitForResponse(response =>
      response.url().endsWith(`/api/vaults/vault-prod/secrets`) && response.request().method() === 'POST');
    await page.getByTestId('write-secret-btn').click();
    const written = await writeResponse;
    expect(written.status()).toBe(201);
    const writtenBody = await written.json();
    expect(writtenBody).toMatchObject({ secret_path: secretPath, version: 1 });
    await expect(page.getByText(new RegExp(`Wrote ${secretPath} version 1`))).toBeVisible();
    await expect(page.getByTestId(`secret-${secretPath}`)).toBeVisible();
    expect(await page.innerText('body')).not.toContain(SENTINEL);

    // 2. Reveal without a fresh step-up must fail closed and return no plaintext.
    await page.getByTestId(`reveal-btn-${secretPath}`).click();
    await expect(page.getByTestId('reveal-dialog')).toBeVisible();
    const deniedReveal = await page.evaluate(async path => {
      const response = await fetch(`/api/vaults/vault-prod/reveal`, {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ secret_path: path })
      });
      return { status: response.status, body: await response.json(), cacheControl: response.headers.get('cache-control') };
    }, secretPath);
    expect(deniedReveal.status).toBe(401);
    expect(deniedReveal.body.error).toBe('step_up_required');
    expect(await page.getByTestId('plaintext-display').count()).toBe(0);

    // 3. Fresh step-up reauthentication, then the provider unwraps the DEK.
    await page.getByTestId('request-reveal-btn').click();
    await submitKeycloakCredentials(page, 'alice', 'keyhelix-local-alice');
    const revealResponse = page.waitForResponse(response =>
      response.url().endsWith(`/api/vaults/vault-prod/reveal`) && response.request().method() === 'POST');
    const revealed = await revealResponse;
    expect(revealed.status()).toBe(200);
    expect(revealed.headers()['cache-control']).toBe('no-store');
    await expect(page.getByTestId('plaintext-display')).toHaveText(SENTINEL);
    await expect(page.getByTestId('reveal-countdown')).toContainText('Auto-clearing in');

    // 4. Closing clears the transient plaintext from the DOM.
    await page.keyboard.press('Escape');
    await expect(page.getByTestId('reveal-dialog')).toHaveCount(0);
    expect(await page.innerText('body')).not.toContain(SENTINEL);

    // 5. The reveal is single-use: reopening requires a new step-up and shows no cache.
    await page.getByTestId(`reveal-btn-${secretPath}`).click();
    await expect(page.getByTestId('reveal-dialog')).toBeVisible();
    await expect(page.getByTestId('request-reveal-btn')).toHaveText('Re-authenticate & Reveal');
    await expect(page.getByTestId('plaintext-display')).toHaveCount(0);
    await page.keyboard.press('Escape');

    // 6. A signed-in member without a grant is denied metadata access.
    const member = await browser.newContext();
    const memberPage = await member.newPage();
    try {
      await memberPage.goto(`${ORIGIN}/#vaults`);
      await signIn(memberPage, 'bob', 'keyhelix-local-bob', 'bob@keyhelix.local');
      await memberPage.goto(`${ORIGIN}/#vaults`);
      // Ownership scoping hides other owners' secrets without leaking their existence.
      await expect(memberPage.getByTestId('secret-count')).toContainText('0 of 0 secrets available');
      await expect(memberPage.locator('.secrets-list > li')).toHaveCount(0);
      expect(await memberPage.innerText('body')).not.toContain(SENTINEL);

      // A direct reveal attempt with a valid session but no grant is denied.
      const initialDenied = await memberPage.evaluate(async path => {
        const response = await fetch(`/api/vaults/vault-prod/reveal`, {
          method: 'POST',
          credentials: 'same-origin',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ secret_path: path })
        });
        return { status: response.status, body: await response.json() };
      }, secretPath);
      expect(initialDenied.status).toBe(403);
      expect(initialDenied.body.error).toBe('access_denied');

      // 7. Owner creates an access grant for member (bob) with step-up elevation.
      let createRes = await page.evaluate(async ({ path, recipient }) => {
        const res = await fetch('/api/vaults/vault-prod/grants', {
          method: 'POST',
          credentials: 'same-origin',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            principal_id: recipient,
            permissions: ['secret:read', path],
            expires_in_seconds: 3600
          })
        });
        return { status: res.status, body: await res.json() };
      }, { path: secretPath, recipient: 'bob@keyhelix.local' });

      if (createRes.status === 401 && createRes.body.authorize_url) {
        const authorizeUrl = createRes.body.authorize_url.startsWith('http')
          ? createRes.body.authorize_url
          : `${ORIGIN}${createRes.body.authorize_url}`;
        await page.goto(authorizeUrl);
        await submitKeycloakCredentials(page, 'alice', 'keyhelix-local-alice');
        await page.waitForURL(url => url.origin === ORIGIN, { timeout: 30000 });

        createRes = await page.evaluate(async ({ path, recipient }) => {
          const res = await fetch('/api/vaults/vault-prod/grants', {
            method: 'POST',
            credentials: 'same-origin',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({
              principal_id: recipient,
              permissions: ['secret:read', path],
              expires_in_seconds: 3600
            })
          });
          return { status: res.status, body: await res.json() };
        }, { path: secretPath, recipient: 'bob@keyhelix.local' });
      }
      expect(createRes.status, `createGrant failed: ${JSON.stringify(createRes)}`).toBe(201);
      const grantId = createRes.body.grant_id;
      expect(grantId).toBeTruthy();

      // 8. Member (bob) now has an authorized grant; reveal demands step-up (401) instead of access denial (403).
      const grantedReveal = await memberPage.evaluate(async path => {
        const response = await fetch(`/api/vaults/vault-prod/reveal`, {
          method: 'POST',
          credentials: 'same-origin',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ secret_path: path })
        });
        return { status: response.status, body: await response.json() };
      }, secretPath);
      expect(grantedReveal.status).toBe(401);
      expect(grantedReveal.body.error).toBe('step_up_required');

      // 9. Owner revokes member's grant via the Access console UI with step-up reauthentication.
      await page.goto(`${ORIGIN}/#access`);
      await page.reload();
      await expect(page.getByTestId('access-console')).toBeVisible();
      await expect(page.getByTestId(`grant-${grantId}`)).toBeVisible();
      await expect(page.getByTestId(`grant-status-${grantId}`)).toHaveText('ACTIVE');

      await page.getByTestId(`revoke-grant-${grantId}`).click();
      await page.waitForURL(url => url.port === '8080', { timeout: 10000 });
      await submitKeycloakCredentials(page, 'alice', 'keyhelix-local-alice');
      await page.waitForURL(url => url.origin === ORIGIN && url.hash === '#access', { timeout: 30000 });

      await expect(page.getByTestId(`grant-status-${grantId}`)).toHaveText('REVOKED', { timeout: 15000 });

      // 10. Member's access is immediately revoked; reveal returns 403 access_denied.
      const postRevokeDenied = await memberPage.evaluate(async path => {
        const response = await fetch(`/api/vaults/vault-prod/reveal`, {
          method: 'POST',
          credentials: 'same-origin',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ secret_path: path })
        });
        return { status: response.status, body: await response.json() };
      }, secretPath);
      expect(postRevokeDenied.status).toBe(403);
      expect(postRevokeDenied.body.error).toBe('access_denied');
    } finally {
      await member.close();
    }
  });
});
