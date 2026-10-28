import { test, expect } from '@playwright/test';
import positiveFixture from '../../../tests/fixtures/keyhelix/C22/positive.json' with { type: 'json' };
import negativeFixture from '../../../tests/fixtures/keyhelix/C22/negative.json' with { type: 'json' };

test.describe('C22: Expose Grants and Rotation Outcomes (Requirement F16)', () => {
  const vaultId = 'vault-prod';

  test('F16: Access console displays complete rotations and active/revoked grants', async ({ page }) => {
    // Mock endpoints with positive fixture
    await page.route(`**/api/vaults/${vaultId}/grants`, async route => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        headers: { 'Cache-Control': 'no-store' },
        body: JSON.stringify(positiveFixture.grants),
      });
    });

    await page.route(`**/api/vaults/${vaultId}/rotations`, async route => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        headers: { 'Cache-Control': 'no-store' },
        body: JSON.stringify(positiveFixture.rotations),
      });
    });

    await page.goto('/#access');

    // 1. Navigation and title
    await expect(page.getByRole('heading', { level: 1 })).toContainText('Provider operations and access control');
    await expect(page.getByTestId('access-console')).toBeVisible();

    // 2. Complete rotation job verification
    await expect(page.getByTestId('rotation-job-rot-c22-complete-01')).toBeVisible();
    await expect(page.getByTestId('job-state-rot-c22-complete-01')).toHaveText('COMPLETE');
    await expect(page.getByTestId('rotation-success-rot-c22-complete-01')).toContainText('Prior KEK can be safely retired');

    // 3. Grants listing verification (active vs revoked)
    await expect(page.getByTestId('grant-grnt-c22-001')).toBeVisible();
    await expect(page.getByTestId('grant-status-grnt-c22-001')).toHaveText('ACTIVE');

    await expect(page.getByTestId('grant-grnt-c22-002')).toBeVisible();
    await expect(page.getByTestId('grant-status-grnt-c22-002')).toHaveText('REVOKED');
  });

  test('F16 Invariant: Partial rotation is visibly incomplete and cannot look like success', async ({ page }) => {
    const partialCase = negativeFixture.cases.find(c => c.case === 'partial-rotation-paused-at-checkpoint')!;

    await page.route(`**/api/vaults/${vaultId}/grants`, async route => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(positiveFixture.grants),
      });
    });

    await page.route(`**/api/vaults/${vaultId}/rotations`, async route => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify([partialCase.job]),
      });
    });

    await page.goto('/#access');

    const jobCard = page.getByTestId(`rotation-job-${partialCase.job.job_id}`);
    await expect(jobCard).toBeVisible();

    // 1. Verify PARTIAL status badge
    const stateBadge = page.getByTestId(`job-state-${partialCase.job.job_id}`);
    await expect(stateBadge).toHaveText('PARTIAL');

    // 2. Invariant F16: Must NOT look like success
    await expect(page.getByTestId(`rotation-success-${partialCase.job.job_id}`)).toHaveCount(0);
    const cardText = await jobCard.innerText();
    expect(cardText).not.toContain('Prior KEK can be safely retired');

    // 3. Verify prominent warning: Prior KEK cannot be retired & paused at checkpoint
    const warningAlert = page.getByTestId(`rotation-warning-${partialCase.job.job_id}`);
    await expect(warningAlert).toBeVisible();
    await expect(warningAlert).toContainText('Prior KEK cannot be retired');
    await expect(warningAlert).toContainText(partialCase.job.checkpoint_secret);

    // 4. Verify resume button is available for partial rotation
    await expect(page.getByTestId(`resume-btn-${partialCase.job.job_id}`)).toBeVisible();
  });

  test('F16 Invariant: Provider failure produces explicit error alert and fails closed', async ({ page }) => {
    await page.route(`**/api/vaults/${vaultId}/grants`, async route => {
      await route.fulfill({
        status: 503,
        contentType: 'application/json',
        body: JSON.stringify({ error: 'provider_unavailable' }),
      });
    });

    await page.route(`**/api/vaults/${vaultId}/rotations`, async route => {
      await route.fulfill({
        status: 503,
        contentType: 'application/json',
        body: JSON.stringify({ error: 'provider_unavailable' }),
      });
    });

    await page.goto('/#access');

    // Invariant F16: Error alert must be explicitly rendered
    const alert = page.getByTestId('provider-error-alert');
    await expect(alert).toBeVisible();
    await expect(alert).toContainText('Access provider unavailable: Operations fail closed');

    // Zero fake or stale success elements rendered
    await expect(page.locator('.rotations-list > div')).toHaveCount(0);
  });

  test('F16: Responsive layout constraints at 360px viewport', async ({ page }) => {
    await page.route(`**/api/vaults/${vaultId}/grants`, async route => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(positiveFixture.grants),
      });
    });

    await page.route(`**/api/vaults/${vaultId}/rotations`, async route => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(positiveFixture.rotations),
      });
    });

    await page.goto('/#access');
    await expect(page.getByTestId('access-console')).toBeVisible();

    await page.setViewportSize({ width: 360, height: 800 });
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  });
});
