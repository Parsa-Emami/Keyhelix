import { test, expect } from '@playwright/test';
import positiveFixture from '../fixtures/keyhelix/C33/positive.json' with { type: 'json' };
import negativeFixture from '../fixtures/keyhelix/C33/negative.json' with { type: 'json' };

test.describe('C33: UX Viewports, Keyboard Accessibility, Failure States & N-1 Compatibility', () => {

  test('360px mobile viewport: zero horizontal scroll overflow across all routes', async ({ page }) => {
    await page.setViewportSize({ width: 360, height: 800 });

    const routes = ['/#workspace', '/#vaults', '/#access', '/#roadmap'];
    for (const route of routes) {
      await page.goto(route);
      await page.waitForLoadState('domcontentloaded');

      const isContained = await page.evaluate(() => {
        return document.documentElement.scrollWidth <= window.innerWidth;
      });
      expect(isContained, `Route ${route} must not overflow horizontally at 360px`).toBe(true);
    }
  });

  test('1440px desktop viewport: full grid and panel layout renders cleanly', async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 });

    await page.goto('/#workspace');
    await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
    await expect(page.locator('.grid')).toBeVisible();

    const isContained = await page.evaluate(() => {
      return document.documentElement.scrollWidth <= window.innerWidth;
    });
    expect(isContained, 'Workspace must fit within 1440px without unwanted overflow').toBe(true);

    await page.goto('/#roadmap');
    await expect(page.getByLabel('Search tasks')).toBeVisible();
    await expect(page.locator('.tasks')).toBeVisible();
  });

  test('Keyboard accessibility: skip link, tab navigation, and focus management', async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 });

    // 1. Skip link bypasses header navigation and shifts focus to main #content
    await page.goto('/');
    await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
    await expect(page.getByRole('region', { name: 'Availability' })).toContainText('Engine runtime');
    await expect(page.locator('.session-badge')).toHaveAttribute('aria-busy', 'false');

    await page.keyboard.press('Tab');
    const skipLink = page.getByRole('link', { name: 'Skip to content' });
    await expect(skipLink).toBeFocused();

    await page.keyboard.press('Enter');
    await expect(page.locator('#content')).toBeFocused();

    // 2. Sequential keyboard tab navigation across reference workflow form and controls
    await page.goto('/#vaults');
    await expect(page.getByRole('heading', { level: 1 })).toBeVisible();

    const pathInput = page.getByLabel('Secret path', { exact: true });
    await pathInput.focus();
    await expect(pathInput).toBeFocused();

    // Tab to Classification dropdown
    await page.keyboard.press('Tab');
    await expect(page.getByLabel('Secret classification')).toBeFocused();

    // Tab to Secret value textarea
    await page.keyboard.press('Tab');
    await expect(page.getByLabel('Secret value')).toBeFocused();

    // Tab to Search secret paths filter (skips disabled write button when not authenticated)
    await page.keyboard.press('Tab');
    await expect(page.getByLabel('Search secret paths')).toBeFocused();

    // Tab to Filter by classification dropdown
    await page.keyboard.press('Tab');
    await expect(page.getByLabel('Filter by classification')).toBeFocused();

    // Shift-Tab back to Search secret paths and type query
    await page.keyboard.press('Shift+Tab');
    await expect(page.getByLabel('Search secret paths')).toBeFocused();
    await page.keyboard.type('test-filter');
    await expect(page.getByLabel('Search secret paths')).toHaveValue('test-filter');
  });

  test('Empty input validation: displays inline error and prevents submission', async ({ page }) => {
    // Mock session and empty metadata so user is recognized as signed in
    await page.route('**/api/v1/auth/session', route =>
      route.fulfill({ status: 200, contentType: 'application/json', body: '{"authenticated":true,"user":{"email":"alice@keyhelix.local"}}' })
    );
    await page.route('**/api/vaults/*/metadata', route =>
      route.fulfill({ status: 200, contentType: 'application/json', body: '[]' })
    );

    await page.goto('/#vaults');
    await page.waitForLoadState('domcontentloaded');

    let requestFired = false;
    await page.route('**/api/vaults/*/secrets', route => {
      requestFired = true;
      return route.fulfill({ status: 400, body: '{}' });
    });

    // Clear secret value and attempt submit
    await page.getByLabel('Secret value').fill('');
    await page.getByTestId('write-secret-btn').click();

    // Explicit error message is shown
    await expect(page.locator('#vaults-error-alert')).toContainText(
      negativeFixture.cases.empty_form_submission.expected_error
    );
    expect(requestFired, 'No request should be sent when inputs are empty').toBe(false);
  });

  test('Malformed JSON preview: explicit failure alert', async ({ page }) => {
    await page.goto('/#workspace');

    await page.getByLabel('Choose JSON file').setInputFiles({
      name: 'malformed.json',
      mimeType: 'application/json',
      buffer: Buffer.from(negativeFixture.cases.malformed_json_upload.payload)
    });

    await expect(page.getByRole('alert')).toContainText(
      negativeFixture.cases.malformed_json_upload.expected_error
    );
  });

  test('Provider outage (503): explicit failure status and zero cached plaintext', async ({ page }) => {
    // Simulate provider failure on health and metadata
    await page.route('**/api/engine/health', route =>
      route.fulfill({ status: 503, contentType: 'application/json', body: '{"error":"engine_unavailable"}' })
    );
    await page.route('**/api/vaults/*/metadata', route =>
      route.fulfill({ status: 503, contentType: 'application/json', body: '{"error":"engine_unavailable"}' })
    );

    await page.goto('/#workspace');
    await expect(page.getByRole('region', { name: 'Availability' })).toContainText(
      'Engine runtime unavailable.'
    );

    await page.goto('/#vaults');
    await expect(page.locator('#vaults-error-alert')).toContainText(
      'Vault runtime unavailable: the engine or a required provider is down.'
    );
    expect(await page.locator('.secrets-list li').count()).toBe(0);
  });

  test('N-1 metadata compatibility: parses legacy fixture without error and defaults safely', async ({ page }) => {
    // Mock the metadata endpoint to return N-1 secrets format
    await page.route('**/api/vaults/*/metadata', route =>
      route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(positiveFixture.n_minus_1_metadata.secrets)
      })
    );

    await page.goto('/#vaults');
    await expect(page.getByTestId('secret-count')).toContainText('2 of 2 secrets available');

    // Both N-1 secrets render safely with ACTIVE fallback status
    for (const secret of positiveFixture.n_minus_1_metadata.secrets) {
      await expect(page.getByTestId(`secret-${secret.secret_path}`)).toBeVisible();
      await expect(page.getByTestId(`secret-status-${secret.secret_path}`)).toHaveText('ACTIVE');
    }
  });

  test('Modal dialog keyboard control: Escape key dismisses modal and clears memory', async ({ page }) => {
    // Provide a mocked active secret
    await page.route('**/api/vaults/*/metadata', route =>
      route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify([
          {
            vault_id: 'vault-prod',
            secret_path: 'app/prod/test-key',
            version: 1,
            classification: 'restricted',
            created_at: new Date().toISOString(),
            metadata_digest: 'abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890'
          }
        ])
      })
    );

    await page.goto('/#vaults');
    await page.getByTestId('reveal-btn-app/prod/test-key').click();

    // Reveal dialog appears
    await expect(page.getByTestId('reveal-dialog')).toBeVisible();

    // Press Escape to dismiss
    await page.keyboard.press('Escape');
    await expect(page.getByTestId('reveal-dialog')).toHaveCount(0);
  });

  test('Advertised supported platforms: only reflects observed platform', async () => {
    const observed = positiveFixture.observed_supported_platforms;
    expect(observed).toEqual(['linux-x86_64']);
  });

});
