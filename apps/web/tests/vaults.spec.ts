import { test, expect } from '@playwright/test';
import metadataFixture from '../../../tests/fixtures/keyhelix/C20/metadata.json' with { type: 'json' };

test.describe('C20: Authorized Metadata Console (Requirement F14)', () => {
  test('UI renders secret list and never fetches plaintext (F14)', async ({ page }) => {
    const requestedUrls: string[] = [];
    const forbiddenPayloads = [
      'SUPER_SECRET_PAYLOAD_NEVER_FETCH_IN_LIST',
      'sentinel-canary-c20-plaintext-leak-83a1',
    ];

    // Spy on all network requests to prove F14 invariant:
    // UI never fetches plaintext merely to render a secret list.
    page.on('request', request => {
      requestedUrls.push(request.url());
    });

    // Mock metadata API endpoint with synthetic metadata fixture
    await page.route('**/api/vaults/vault-prod/metadata', async route => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        headers: { 'Cache-Control': 'no-store' },
        body: JSON.stringify(metadataFixture),
      });
    });

    await page.goto('/#vaults');

    // 1. Verify header and page navigation
    await expect(page.getByRole('heading', { level: 1 })).toContainText('Authorized secret metadata console');
    await expect(page.getByTestId('vaults-console')).toBeVisible();

    // 2. Verify metadata entries rendered
    await expect(page.getByTestId('secret-count')).toContainText('3 of 3 secrets available');
    await expect(page.getByTestId('secret-production/services/payment/api-key')).toBeVisible();
    await expect(page.getByTestId('secret-production/services/payment/webhook-secret')).toBeVisible();
    await expect(page.getByTestId('secret-production/services/auth/jwt-signing-key')).toBeVisible();

    // 3. Verify specific metadata attributes
    const firstSecret = page.getByTestId('secret-production/services/payment/api-key');
    await expect(firstSecret).toContainText('production/services/payment/api-key');
    await expect(firstSecret).toContainText('v2');
    await expect(firstSecret).toContainText('RESTRICTED');
    await expect(firstSecret).toContainText('ACTIVE');

    // 4. Invariant F14 Assertions:
    // Ensure no reveal/decrypt endpoint was invoked
    const revealRequests = requestedUrls.filter(url => 
      url.includes('/reveal') || 
      url.includes('/decrypt') || 
      url.includes('/secret-value') ||
      url.includes('/plaintext')
    );
    expect(revealRequests).toEqual([]);

    // Ensure forbidden plaintext strings never appear anywhere in the rendered page body
    const bodyText = await page.innerText('body');
    for (const sentinel of forbiddenPayloads) {
      expect(bodyText).not.toContain(sentinel);
    }
  });

  test('Vaults filtering, search, keyboard access and responsive viewport', async ({ page }) => {
    await page.route('**/api/vaults/vault-prod/metadata', async route => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(metadataFixture),
      });
    });

    await page.goto('/#vaults');
    await expect(page.getByTestId('secret-count')).toContainText('3 of 3 secrets available');

    // Filter by search keyword
    const searchInput = page.getByLabel('Search secret paths');
    await searchInput.fill('webhook');
    await expect(page.getByTestId('secret-count')).toContainText('1 of 3 secrets available');
    await expect(page.getByTestId('secret-production/services/payment/webhook-secret')).toBeVisible();
    await expect(page.getByTestId('secret-production/services/payment/api-key')).toHaveCount(0);

    // Clear search
    await searchInput.fill('');
    await expect(page.getByTestId('secret-count')).toContainText('3 of 3 secrets available');

    // Filter by status
    const statusSelect = page.getByLabel('Filter by status');
    await statusSelect.selectOption('deleted');
    await expect(page.getByTestId('secret-count')).toContainText('1 of 3 secrets available');
    await expect(page.getByTestId('secret-production/services/auth/jwt-signing-key')).toBeVisible();

    // Reset status
    await statusSelect.selectOption('all');

    // Responsive check at 360px width
    await page.setViewportSize({ width: 360, height: 800 });
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  });

  test('Vaults console handles provider outage gracefully', async ({ page }) => {
    await page.route('**/api/vaults/vault-prod/metadata', async route => {
      await route.fulfill({
        status: 503,
        contentType: 'application/json',
        body: JSON.stringify({ error: 'provider_unavailable' }),
      });
    });

    await page.goto('/#vaults');
    await expect(page.getByRole('alert')).toContainText('Vault service unavailable');
    await expect(page.locator('.secrets-list > li')).toHaveCount(0);
  });

  test('Vaults console handles access denial gracefully', async ({ page }) => {
    await page.route('**/api/vaults/vault-prod/metadata', async route => {
      await route.fulfill({
        status: 403,
        contentType: 'application/json',
        body: JSON.stringify({ error: 'access_denied' }),
      });
    });

    await page.goto('/#vaults');
    await expect(page.getByRole('alert')).toContainText('Access denied to vault metadata');
    await expect(page.locator('.secrets-list > li')).toHaveCount(0);
  });
});
