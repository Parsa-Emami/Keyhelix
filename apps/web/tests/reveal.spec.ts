import { test, expect } from '@playwright/test';
import metadataFixture from '../../../tests/fixtures/keyhelix/C20/metadata.json' with { type: 'json' };
import positiveRevealFixture from '../../../tests/fixtures/keyhelix/C21/positive.json' with { type: 'json' };

const secretPath = 'production/services/payment/api-key';
const sentinelPlaintext = positiveRevealFixture.response.plaintext;
const encodedResponse = {
  ...positiveRevealFixture.response,
  classification: 'restricted',
  plaintext: Buffer.from(sentinelPlaintext, 'utf8').toString('base64'),
  plaintext_encoding: 'base64',
  no_store: true
};

async function mockSession(page: any, elevated = true) {
  await page.route('**/api/v1/auth/session', route => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify({
      authenticated: true,
      user: { email: 'alice@keyhelix.local', subject: 'alice' },
      step_up: elevated
        ? { action: 'reveal_secret', resource: secretPath, expires_at: new Date(Date.now() + 60000).toISOString() }
        : null
    })
  }));
}

test.describe('Transient reveal interaction', () => {
  test.beforeEach(async ({ page }) => {
    await page.route('**/api/vaults/vault-prod/metadata', route => route.fulfill({
      status: 200,
      contentType: 'application/json',
      headers: { 'Cache-Control': 'no-store' },
      body: JSON.stringify(metadataFixture)
    }));
  });

  test('successful reveal displays provisional plaintext and clears on close', async ({ page }) => {
    await mockSession(page, true);
    const requests: string[] = [];
    await page.route('**/api/vaults/vault-prod/reveal', async route => {
      requests.push(route.request().postData() ?? '');
      await route.fulfill({ status: 200, contentType: 'application/json', headers: { 'Cache-Control': 'no-store' }, body: JSON.stringify(encodedResponse) });
    });

    await page.goto('/#vaults');
    let bodyText = await page.innerText('body');
    expect(bodyText).not.toContain(sentinelPlaintext);

    const revealBtn = page.getByTestId(`reveal-btn-${secretPath}`);
    await revealBtn.click();
    await expect(page.getByTestId('reveal-dialog')).toBeVisible();
    await expect(page.getByTestId('plaintext-display')).toHaveText(sentinelPlaintext);
    expect(requests[0]).toContain(secretPath);

    await page.getByTestId('close-and-clear-btn').click();
    await expect(page.getByTestId('reveal-dialog')).toHaveCount(0);
    bodyText = await page.innerText('body');
    expect(bodyText).not.toContain(sentinelPlaintext);

    await mockSession(page, false);
    await revealBtn.click();
    await expect(page.getByTestId('reveal-dialog')).toBeVisible();
    await expect(page.getByTestId('plaintext-display')).toHaveCount(0);
    await page.getByTestId('reveal-close-btn').click();
  });

  test('plaintext clears strictly upon logout', async ({ page }) => {
    await mockSession(page, true);
    await page.route('**/api/vaults/vault-prod/reveal', route => route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(encodedResponse) }));

    await page.goto('/#vaults');
    await page.getByTestId(`reveal-btn-${secretPath}`).click();
    await expect(page.getByTestId('plaintext-display')).toHaveText(sentinelPlaintext);
    await page.getByTestId('logout-and-purge-btn').click();
    await expect(page.getByTestId('reveal-dialog')).toHaveCount(0);
    expect(await page.innerText('body')).not.toContain(sentinelPlaintext);
  });

  test('auto-clear zeroes plaintext on timer expiration', async ({ page }) => {
    await mockSession(page, true);
    await page.route('**/api/vaults/vault-prod/reveal', route => route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ ...encodedResponse, ttl_seconds: 2 })
    }));

    await page.goto('/#vaults');
    await page.getByTestId(`reveal-btn-${secretPath}`).click();
    await expect(page.getByTestId('plaintext-display')).toHaveText(sentinelPlaintext);
    await expect(page.getByTestId('plaintext-display')).toHaveCount(0, { timeout: 4000 });
    expect(await page.innerText('body')).not.toContain(sentinelPlaintext);
  });

  test('Escape dismisses the modal and clears plaintext', async ({ page }) => {
    await mockSession(page, true);
    await page.route('**/api/vaults/vault-prod/reveal', route => route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(encodedResponse) }));

    await page.goto('/#vaults');
    await page.getByTestId(`reveal-btn-${secretPath}`).click();
    await expect(page.getByTestId('plaintext-display')).toHaveText(sentinelPlaintext);
    await page.keyboard.press('Escape');
    await expect(page.getByTestId('reveal-dialog')).toHaveCount(0);
    expect(await page.innerText('body')).not.toContain(sentinelPlaintext);
  });

  test('missing step-up requires reauthentication and returns no plaintext', async ({ page }) => {
    await mockSession(page, false);
    let revealCalls = 0;
    await page.route('**/api/vaults/vault-prod/reveal', route => {
      revealCalls += 1;
      return route.fulfill({ status: 401, contentType: 'application/json', body: JSON.stringify({ error: 'step_up_required', authorize_url: '/api/v1/auth/step-up?action=reveal' }) });
    });

    await page.goto('/#vaults');
    await page.getByTestId(`reveal-btn-${secretPath}`).click();
    await expect(page.getByTestId('request-reveal-btn')).toHaveText('Re-authenticate & Reveal');
    expect(revealCalls).toBe(0);
    await expect(page.getByTestId('plaintext-display')).toHaveCount(0);
  });

  test('provider outage fails closed with an explicit error', async ({ page }) => {
    await mockSession(page, true);
    await page.route('**/api/vaults/vault-prod/reveal', route => route.fulfill({ status: 503, contentType: 'application/json', body: JSON.stringify({ error: 'provider_unavailable' }) }));

    await page.goto('/#vaults');
    await page.getByTestId(`reveal-btn-${secretPath}`).click();
    await expect(page.getByTestId('reveal-error-msg')).toContainText('Provider unavailable');
    await expect(page.getByTestId('plaintext-display')).toHaveCount(0);
    expect(await page.innerText('body')).not.toContain(sentinelPlaintext);
  });

  test('revoked member grant fails closed with access denied', async ({ page }) => {
    await mockSession(page, true);
    await page.route('**/api/vaults/vault-prod/reveal', route => route.fulfill({ status: 403, contentType: 'application/json', body: JSON.stringify({ error: 'access_denied' }) }));

    await page.goto('/#vaults');
    await page.getByTestId(`reveal-btn-${secretPath}`).click();
    await expect(page.getByTestId('reveal-error-msg')).toContainText('Access denied: no active grant');
    await expect(page.getByTestId('plaintext-display')).toHaveCount(0);
  });
});
