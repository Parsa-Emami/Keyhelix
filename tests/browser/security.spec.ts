import { test, expect } from '@playwright/test';
import positiveFixture from '../fixtures/keyhelix/C27/positive.json' with { type: 'json' };
import negativeFixture from '../fixtures/keyhelix/C27/negative.json' with { type: 'json' };
import metadataFixture from '../fixtures/keyhelix/C20/metadata.json' with { type: 'json' };

test.describe('C27: Security Abuse and Authorization Boundaries (Requirement N27)', () => {
  test.beforeEach(async ({ page }) => {
    // Ensure clean state before each test
    await page.goto('/');
  });

  test('SEC-01: Prototype pollution attack via __proto__ is rejected and Object prototype remains unmutated', async ({ page }) => {
    const protoPayload = '{"__proto__":{"polluted":true},"normalKey":"value"}';

    await page.getByLabel('Choose JSON file').setInputFiles({
      name: 'exploit-proto.json',
      mimeType: 'application/json',
      buffer: Buffer.from(protoPayload),
    });

    await expect(page.getByRole('alert')).toContainText('Unsafe document key.');
    await expect(page.getByRole('status')).toHaveCount(0);

    // Verify global Object.prototype was NOT mutated
    const isPolluted = await page.evaluate(() => {
      return (Object.prototype as any).polluted !== undefined || ({} as any).polluted !== undefined;
    });
    expect(isPolluted).toBe(false);
  });

  test('SEC-01b: Prototype pollution via constructor and prototype keys is rejected', async ({ page }) => {
    const constructorPayload = '{"constructor":{"prototype":{"injected":true}}}';

    await page.getByLabel('Choose JSON file').setInputFiles({
      name: 'exploit-constructor.json',
      mimeType: 'application/json',
      buffer: Buffer.from(constructorPayload),
    });

    await expect(page.getByRole('alert')).toContainText('Unsafe document key.');

    const prototypePayload = '{"prototype":{"injected":true}}';
    await page.getByLabel('Choose JSON file').setInputFiles({
      name: 'exploit-prototype.json',
      mimeType: 'application/json',
      buffer: Buffer.from(prototypePayload),
    });

    await expect(page.getByRole('alert')).toContainText('Unsafe document key.');

    const isInjected = await page.evaluate(() => ({} as any).injected !== undefined);
    expect(isInjected).toBe(false);
  });

  test('SEC-02: JSON depth bomb attack (>32 levels) is halted before stack exhaustion', async ({ page }) => {
    // Construct an object nested 35 levels deep
    let deepObj: any = { leaf: 'target' };
    for (let i = 0; i < 35; i++) {
      deepObj = { level: deepObj };
    }

    await page.getByLabel('Choose JSON file').setInputFiles({
      name: 'depth-bomb.json',
      mimeType: 'application/json',
      buffer: Buffer.from(JSON.stringify(deepObj)),
    });

    await expect(page.getByRole('alert')).toContainText('Document is too complex to preview.');
    await expect(page.getByRole('status')).toHaveCount(0);
  });

  test('SEC-03: JSON complexity bomb (>20,000 keys) is rejected before denial of service', async ({ page }) => {
    // Construct an object with 20,050 keys
    const broadObj: Record<string, number> = {};
    for (let i = 0; i < 20050; i++) {
      broadObj[`key_${i}`] = i;
    }

    await page.getByLabel('Choose JSON file').setInputFiles({
      name: 'complexity-bomb.json',
      mimeType: 'application/json',
      buffer: Buffer.from(JSON.stringify(broadObj)),
    });

    await expect(page.getByRole('alert')).toContainText('Document is too complex to preview.');
    await expect(page.getByRole('status')).toHaveCount(0);
  });

  test('SEC-04: Oversized document (>1 MiB preview limit) is rejected before parsing', async ({ page }) => {
    // Construct a document exceeding maxPreviewBytes (1,048,576 bytes)
    const largeObj = {
      description: 'oversized payload',
      data: 'A'.repeat(1050000),
    };

    await page.getByLabel('Choose JSON file').setInputFiles({
      name: 'oversized.json',
      mimeType: 'application/json',
      buffer: Buffer.from(JSON.stringify(largeObj)),
    });

    await expect(page.getByRole('alert')).toContainText('File exceeds the preview limit.');
    await expect(page.getByRole('status')).toHaveCount(0);
  });

  test('SEC-05: XSS injection vectors in file names and JSON field names are safely text-escaped', async ({ page }) => {
    const maliciousPayload = {
      '<script>window.__xss_key=true</script>': 'val1',
      '<img src="invalid-image" onerror="window.__xss_img=true">': 'val2',
      '"><svg/onload=window.__xss_svg=true>': 'val3',
    };

    const maliciousFilename = '<script>window.__xss_filename=true</script>.json';

    await page.getByLabel('Choose JSON file').setInputFiles({
      name: maliciousFilename,
      mimeType: 'application/json',
      buffer: Buffer.from(JSON.stringify(maliciousPayload)),
    });

    // Preview status must render safely
    const status = page.getByRole('status');
    await expect(status).toBeVisible();
    await expect(status).toContainText(maliciousFilename);
    await expect(status).toContainText('3 top-level fields');

    // Assert that no injected script or onerror handler executed in the browser window
    const xssSignals = await page.evaluate(() => {
      const w = window as any;
      return {
        key: Boolean(w.__xss_key),
        img: Boolean(w.__xss_img),
        svg: Boolean(w.__xss_svg),
        filename: Boolean(w.__xss_filename),
      };
    });

    expect(xssSignals.key).toBe(false);
    expect(xssSignals.img).toBe(false);
    expect(xssSignals.svg).toBe(false);
    expect(xssSignals.filename).toBe(false);

    // Verify injected tags are NOT elements in the DOM
    const rawScripts = await page.locator('script:has-text("__xss")').count();
    expect(rawScripts).toBe(0);
  });

  test('SEC-06: File inspection maintains strict zero-telemetry invariant', async ({ page }) => {
    const interceptedMutations: string[] = [];

    page.on('request', request => {
      const method = request.method();
      if (method === 'POST' || method === 'PUT' || method === 'PATCH' || method === 'DELETE') {
        interceptedMutations.push(`${method} ${request.url()}`);
      }
    });

    await page.getByLabel('Choose JSON file').setInputFiles({
      name: positiveFixture.preview.filename,
      mimeType: 'application/json',
      buffer: Buffer.from(positiveFixture.preview.content),
    });

    await expect(page.getByRole('status')).toBeVisible();
    await expect(page.getByRole('status')).toContainText(positiveFixture.preview.filename);

    // Assert zero mutations or uploads occurred
    expect(interceptedMutations).toEqual([]);
  });

  test('SEC-08: Cross-tenant / unauthorized vault access fails closed with explicit alert', async ({ page }) => {
    // Intercept metadata request and fulfill with 403 Forbidden
    await page.route('**/api/vaults/vault-prod/metadata', async route => {
      await route.fulfill({
        status: 403,
        contentType: 'application/json',
        body: JSON.stringify({ error: 'unauthorized_tenant_access' }),
      });
    });

    await page.goto('/#vaults');

    // Verify alert message and zero secrets displayed
    await expect(page.getByRole('alert')).toContainText('Access denied to vault metadata.');
    await expect(page.getByTestId('secret-count')).toContainText('0 of 0 secrets available');
    await expect(page.locator('.secrets-list > li')).toHaveCount(0);
  });

  test('SEC-10: Step-up bypass attempt is rejected', async ({ page }) => {
    await page.route('**/api/vaults/vault-prod/metadata', async route => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(metadataFixture),
      });
    });
    await page.route('**/api/v1/auth/session', async route => {
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ authenticated: false, step_up: null }) });
    });

    await page.goto('/#vaults');
    await expect(page.getByTestId('vaults-console')).toBeVisible();

    const targetSecret = 'production/services/payment/api-key';
    const revealBtn = page.getByTestId(`reveal-btn-${targetSecret}`);
    await expect(revealBtn).toBeVisible();
    await revealBtn.click();

    await expect(page.getByTestId('reveal-dialog')).toBeVisible();
    await expect(page.getByTestId('request-reveal-btn')).toHaveText('Re-authenticate & Reveal');
    await expect(page.getByTestId('plaintext-display')).toHaveCount(0);
  });

  test('SEC-11: Revoked grant reveal attempt is rejected immediately', async ({ page }) => {
    await page.route('**/api/vaults/vault-prod/metadata', async route => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(metadataFixture),
      });
    });

    const targetSecret = 'production/services/payment/api-key';
    await page.route('**/api/v1/auth/session', route => route.fulfill({
      status: 200, contentType: 'application/json',
      body: JSON.stringify({ authenticated: true, step_up: { action: 'reveal_secret', resource: targetSecret, expires_at: new Date(Date.now() + 60000).toISOString() } })
    }));
    await page.route('**/api/vaults/vault-prod/reveal', async route => {
      await route.fulfill({
        status: 403,
        contentType: 'application/json',
        body: JSON.stringify({ error: 'access_denied' }),
      });
    });

    await page.goto('/#vaults');
    await page.getByTestId(`reveal-btn-${targetSecret}`).click();

    // Verify access denial and zero plaintext
    await expect(page.getByRole('alert')).toContainText('Access denied: no active grant authorizes this secret.');
    await expect(page.getByTestId('plaintext-display')).toHaveCount(0);
  });

  test('SEC-12: Provider outage during reveal fails closed with zero cached plaintext', async ({ page }) => {
    await page.route('**/api/vaults/vault-prod/metadata', async route => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(metadataFixture),
      });
    });

    const targetSecret = 'production/services/payment/api-key';
    await page.route('**/api/v1/auth/session', route => route.fulfill({
      status: 200, contentType: 'application/json',
      body: JSON.stringify({ authenticated: true, step_up: { action: 'reveal_secret', resource: targetSecret, expires_at: new Date(Date.now() + 60000).toISOString() } })
    }));
    await page.route('**/api/vaults/vault-prod/reveal', async route => {
      await route.fulfill({
        status: 503,
        contentType: 'application/json',
        body: JSON.stringify({ error: 'provider_unavailable' }),
      });
    });

    await page.goto('/#vaults');
    await page.getByTestId(`reveal-btn-${targetSecret}`).click();

    // Verify provider outage message
    await expect(page.getByRole('alert')).toContainText('Provider unavailable');
    await expect(page.getByTestId('plaintext-display')).toHaveCount(0);
  });
});
