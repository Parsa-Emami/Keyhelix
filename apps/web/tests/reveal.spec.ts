import { test, expect } from '@playwright/test';
import metadataFixture from '../../../tests/fixtures/keyhelix/C20/metadata.json' with { type: 'json' };
import positiveRevealFixture from '../../../tests/fixtures/keyhelix/C21/positive.json' with { type: 'json' };
import negativeRevealFixture from '../../../tests/fixtures/keyhelix/C21/negative.json' with { type: 'json' };

test.describe('C21: Transient Reveal Interaction (Requirement F15)', () => {
  const secretPath = 'production/services/payment/api-key';
  const sentinelPlaintext = positiveRevealFixture.response.plaintext;

  test.beforeEach(async ({ page }) => {
    // Mock metadata API endpoint
    await page.route('**/api/vaults/vault-prod/metadata', async route => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        headers: { 'Cache-Control': 'no-store' },
        body: JSON.stringify(metadataFixture),
      });
    });
  });

  test('F15: Successful transient reveal displays plaintext and clears strictly on close', async ({ page }) => {
    const interceptedRequests: { url: string; headers: Record<string, string> }[] = [];

    await page.route(`**/api/vaults/vault-prod/secrets/${encodeURIComponent(secretPath)}/reveal`, async route => {
      interceptedRequests.push({
        url: route.request().url(),
        headers: route.request().headers(),
      });

      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        headers: {
          'Cache-Control': 'no-store, no-cache, must-revalidate',
          'Pragma': 'no-cache',
        },
        body: JSON.stringify(positiveRevealFixture.response),
      });
    });

    await page.goto('/#vaults');
    await expect(page.getByTestId('vaults-console')).toBeVisible();

    // 1. Initial state: Sentinel plaintext must not exist anywhere in DOM
    let bodyText = await page.innerText('body');
    expect(bodyText).not.toContain(sentinelPlaintext);

    // 2. Open Reveal Dialog
    const revealBtn = page.getByTestId(`reveal-btn-${secretPath}`);
    await expect(revealBtn).toBeVisible();
    await revealBtn.click();

    await expect(page.getByTestId('reveal-dialog')).toBeVisible();
    await expect(page.getByTestId('stepup-token-input')).toBeVisible();

    // 3. Request transient reveal with step-up token
    const requestBtn = page.getByTestId('request-reveal-btn');
    await requestBtn.click();

    // 4. Verify request headers include Cache-Control no-store
    expect(interceptedRequests.length).toBe(1);
    const reqHeaders = interceptedRequests[0].headers;
    expect(reqHeaders['cache-control']).toContain('no-store');
    expect(reqHeaders['x-keyhelix-stepup']).toBe('su_c21_synthetic_stepup_token_valid_99a');

    // 5. Plaintext is now visible in memory container
    await expect(page.getByTestId('plaintext-display')).toBeVisible();
    await expect(page.getByTestId('plaintext-display')).toHaveText(sentinelPlaintext);
    await expect(page.getByTestId('reveal-countdown')).toContainText('Auto-clearing in');

    // 6. Click Close & Zero button
    const closeBtn = page.getByTestId('close-and-clear-btn');
    await closeBtn.click();

    // 7. Verify dialog closed and plaintext completely purged from rendered DOM
    await expect(page.getByTestId('reveal-dialog')).toHaveCount(0);
    bodyText = await page.innerText('body');
    expect(bodyText).not.toContain(sentinelPlaintext);

    // 8. Re-opening dialog must start with clean slate (no cached plaintext)
    await revealBtn.click();
    await expect(page.getByTestId('reveal-dialog')).toBeVisible();
    await expect(page.getByTestId('plaintext-display')).toHaveCount(0);
    bodyText = await page.innerText('body');
    expect(bodyText).not.toContain(sentinelPlaintext);

    // Close with top close button
    await page.getByTestId('reveal-close-btn').click();
    await expect(page.getByTestId('reveal-dialog')).toHaveCount(0);
  });

  test('F15: Plaintext clears strictly upon session logout', async ({ page }) => {
    await page.route(`**/api/vaults/vault-prod/secrets/${encodeURIComponent(secretPath)}/reveal`, async route => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        headers: { 'Cache-Control': 'no-store' },
        body: JSON.stringify(positiveRevealFixture.response),
      });
    });

    await page.goto('/#vaults');
    await page.getByTestId(`reveal-btn-${secretPath}`).click();
    await page.getByTestId('request-reveal-btn').click();

    await expect(page.getByTestId('plaintext-display')).toHaveText(sentinelPlaintext);

    // Click "Logout Session"
    await page.getByTestId('logout-and-purge-btn').click();

    // Dialog is dismissed and plaintext cleared
    await expect(page.getByTestId('reveal-dialog')).toHaveCount(0);
    const bodyText = await page.innerText('body');
    expect(bodyText).not.toContain(sentinelPlaintext);
  });

  test('F15: Auto-clear zeroes plaintext on timer expiration', async ({ page }) => {
    // Return fixture with short 2s ttl
    const shortTtlResponse = {
      ...positiveRevealFixture.response,
      ttl_seconds: 2,
    };

    await page.route(`**/api/vaults/vault-prod/secrets/${encodeURIComponent(secretPath)}/reveal`, async route => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        headers: { 'Cache-Control': 'no-store' },
        body: JSON.stringify(shortTtlResponse),
      });
    });

    await page.goto('/#vaults');
    await page.getByTestId(`reveal-btn-${secretPath}`).click();
    await page.getByTestId('request-reveal-btn').click();

    await expect(page.getByTestId('plaintext-display')).toHaveText(sentinelPlaintext);

    // Wait for auto-clear timer to expire
    await expect(page.getByTestId('plaintext-display')).toHaveCount(0, { timeout: 4000 });
    const bodyText = await page.innerText('body');
    expect(bodyText).not.toContain(sentinelPlaintext);
  });

  test('F15: Escape key dismisses modal and clears plaintext immediately', async ({ page }) => {
    await page.route(`**/api/vaults/vault-prod/secrets/${encodeURIComponent(secretPath)}/reveal`, async route => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        headers: { 'Cache-Control': 'no-store' },
        body: JSON.stringify(positiveRevealFixture.response),
      });
    });

    await page.goto('/#vaults');
    await page.getByTestId(`reveal-btn-${secretPath}`).click();
    await page.getByTestId('request-reveal-btn').click();

    await expect(page.getByTestId('plaintext-display')).toHaveText(sentinelPlaintext);

    // Press Escape
    await page.keyboard.press('Escape');

    await expect(page.getByTestId('reveal-dialog')).toHaveCount(0);
    const bodyText = await page.innerText('body');
    expect(bodyText).not.toContain(sentinelPlaintext);
  });

  test('F15 Negative: Missing or expired step-up token is rejected', async ({ page }) => {
    await page.route(`**/api/vaults/vault-prod/secrets/${encodeURIComponent(secretPath)}/reveal`, async route => {
      await route.fulfill({
        status: 401,
        contentType: 'application/json',
        headers: { 'Cache-Control': 'no-store' },
        body: JSON.stringify({ error: 'step_up_required' }),
      });
    });

    await page.goto('/#vaults');
    await page.getByTestId(`reveal-btn-${secretPath}`).click();
    await page.getByTestId('stepup-token-input').fill('invalid_expired_token');
    await page.getByTestId('request-reveal-btn').click();

    await expect(page.getByTestId('reveal-error-msg')).toContainText('Step-up authentication required or token expired');
    await expect(page.getByTestId('plaintext-display')).toHaveCount(0);
    const bodyText = await page.innerText('body');
    expect(bodyText).not.toContain(sentinelPlaintext);
  });

  test('F15 Negative: Provider outage fails closed with explicit error', async ({ page }) => {
    await page.route(`**/api/vaults/vault-prod/secrets/${encodeURIComponent(secretPath)}/reveal`, async route => {
      await route.fulfill({
        status: 503,
        contentType: 'application/json',
        headers: { 'Cache-Control': 'no-store' },
        body: JSON.stringify({ error: 'provider_unavailable' }),
      });
    });

    await page.goto('/#vaults');
    await page.getByTestId(`reveal-btn-${secretPath}`).click();
    await page.getByTestId('request-reveal-btn').click();

    await expect(page.getByTestId('reveal-error-msg')).toContainText('Provider unavailable: Fails closed to protect secret');
    await expect(page.getByTestId('plaintext-display')).toHaveCount(0);
    const bodyText = await page.innerText('body');
    expect(bodyText).not.toContain(sentinelPlaintext);
  });

  test('F15 Negative: Unrelated owner or scope mismatch fails closed', async ({ page }) => {
    await page.route(`**/api/vaults/vault-prod/secrets/${encodeURIComponent(secretPath)}/reveal`, async route => {
      await route.fulfill({
        status: 403,
        contentType: 'application/json',
        headers: { 'Cache-Control': 'no-store' },
        body: JSON.stringify({ error: 'forbidden_scope' }),
      });
    });

    await page.goto('/#vaults');
    await page.getByTestId(`reveal-btn-${secretPath}`).click();
    await page.getByTestId('request-reveal-btn').click();

    await expect(page.getByTestId('reveal-error-msg')).toContainText('Access denied: Unauthorized owner or scope mismatch');
    await expect(page.getByTestId('plaintext-display')).toHaveCount(0);
    const bodyText = await page.innerText('body');
    expect(bodyText).not.toContain(sentinelPlaintext);
  });
});
