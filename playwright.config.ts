import { defineConfig } from '@playwright/test';
export default defineConfig({
  testDir: '.',
  testMatch: ['tests/browser/**/*.spec.ts', 'apps/web/tests/**/*.spec.ts'],
  timeout: 30000,
  use: {
    baseURL: 'http://127.0.0.1:4173', browserName: 'chromium', headless: true,
    launchOptions: process.env.WEB_TEST_CHROMIUM ? { executablePath: process.env.WEB_TEST_CHROMIUM, args: ['--no-sandbox'] } : {},
  },
  webServer: {
    command: process.env.KEYHELIX_INSTALLED_RELEASE ? 'node scripts/start-local.mjs --root web --providers reuse' : 'npm start',
    cwd: process.env.KEYHELIX_INSTALLED_RELEASE, url: 'http://127.0.0.1:4173/readyz', reuseExistingServer: false, timeout: 180000 },
  reporter: 'list',
});
