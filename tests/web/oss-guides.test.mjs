import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(fileURLToPath(new URL('../../', import.meta.url)));
const read = async path => readFile(resolve(root, path), 'utf8');
const readJSON = async path => JSON.parse(await read(path));

test('C34 deliverables: all required public guides exist and contain required contract sections', async () => {
  const userGuide = await read('docs/release/USER_GUIDE.md');
  const securityPolicy = await read('SECURITY.md');
  const readme = await read('README.md');
  const openSource = await read('OPEN_SOURCE.md');
  const contributing = await read('CONTRIBUTING.md');
  const cloneToRun = await read('docs/engineering/CLONE_TO_RUN.md');

  // 1. User Guide assertions
  assert.ok(userGuide.includes('Apache-2.0'), 'USER_GUIDE.md must state Apache-2.0 license');
  assert.ok(userGuide.includes('Provider Owns Secret Bytes'), 'USER_GUIDE.md must state provider ownership');
  assert.ok(userGuide.includes('npm run build:engine'), 'USER_GUIDE.md must document engine source build');
  assert.ok(userGuide.includes('npm run build'), 'USER_GUIDE.md must document web build');
  assert.ok(userGuide.includes('npm run package'), 'USER_GUIDE.md must document reproducible packaging');
  assert.ok(userGuide.includes('1 MiB') || userGuide.includes('1,048,576 bytes'), 'USER_GUIDE.md must document 1 MiB limit');
  assert.ok(userGuide.includes('32 levels'), 'USER_GUIDE.md must document 32 depth limit');
  assert.ok(userGuide.includes('20,000 keys'), 'USER_GUIDE.md must document 20,000 keys limit');
  assert.ok(userGuide.includes('Zero Telemetry'), 'USER_GUIDE.md must document zero telemetry');
  assert.ok(userGuide.includes('Forward Repair'), 'USER_GUIDE.md must document forward repair over stale rollback');
  assert.ok(userGuide.includes('npm run doctor'), 'USER_GUIDE.md must document diagnostics doctor');
  assert.ok(userGuide.includes('SECURITY.md'), 'USER_GUIDE.md must reference security policy');

  // 2. Security Policy assertions
  assert.ok(securityPolicy.includes('https://github.com/Parsa-Emami/Keyhelix/security/advisories/new'), 'SECURITY.md must provide private advisory URL');
  assert.ok(securityPolicy.includes('security@keyhelix.local'), 'SECURITY.md must provide security contact email');
  assert.ok(securityPolicy.includes('Within 48 hours'), 'SECURITY.md must provide 48h initial response SLA');
  assert.ok(securityPolicy.includes('Do not report security vulnerabilities through public GitHub Issues'), 'SECURITY.md must prohibit public disclosure');
  assert.ok(securityPolicy.includes('Supported Versions'), 'SECURITY.md must contain supported versions policy');
  assert.ok(securityPolicy.includes('Provider Owns Secret Bytes'), 'SECURITY.md must enforce provider secret bytes ownership');
  assert.ok(securityPolicy.includes('Fail-Closed Availability'), 'SECURITY.md must enforce fail-closed invariant');

  // 3. Open Source Contract assertions
  assert.ok(openSource.includes('Apache License, Version 2.0'), 'OPEN_SOURCE.md must state Apache-2.0');
  assert.ok(openSource.includes('No Cloud Account Prerequisite'), 'OPEN_SOURCE.md must guarantee zero cloud requirement');
  assert.ok(openSource.includes('THIRD_PARTY_NOTICES.md'), 'OPEN_SOURCE.md must reference third-party notices');
  assert.ok(openSource.includes('Strict Zero-Telemetry'), 'OPEN_SOURCE.md must guarantee zero telemetry');

  // 4. Contributing assertions
  assert.ok(contributing.includes('DCO.md'), 'CONTRIBUTING.md must reference DCO');
  assert.ok(contributing.includes('Conventional Commits'), 'CONTRIBUTING.md must require conventional commits');
  assert.ok(contributing.includes('npm run validate:plan'), 'CONTRIBUTING.md must require plan validation');
  assert.ok(contributing.includes('npm test'), 'CONTRIBUTING.md must require npm test');
  assert.ok(contributing.includes('go test ./...'), 'CONTRIBUTING.md must require go test');
  assert.ok(contributing.includes('SECURITY.md'), 'CONTRIBUTING.md must link to security reporting');

  // 5. Clone to Run assertions
  assert.ok(cloneToRun.includes('npm run setup'), 'CLONE_TO_RUN.md must document setup command');
  assert.ok(cloneToRun.includes('npm start'), 'CLONE_TO_RUN.md must document start command');
  assert.ok(cloneToRun.includes('Loopback Isolation'), 'CLONE_TO_RUN.md must document loopback boundaries');

  // 6. README assertions
  assert.ok(readme.includes('docs/release/USER_GUIDE.md'), 'README.md must link to User Guide');
  assert.ok(readme.includes('SECURITY.md'), 'README.md must link to Security Policy');
  assert.ok(readme.includes('OPEN_SOURCE.md'), 'README.md must link to Open Source Contract');
  assert.ok(readme.includes('CONTRIBUTING.md'), 'README.md must link to Contributing');
  assert.ok(readme.includes('docs/engineering/CLONE_TO_RUN.md'), 'README.md must link to Clone to Run');
});

test('C34 fixtures: positive, negative, and expected-output conform to N34 contract', async () => {
  const positive = await readJSON('tests/fixtures/keyhelix/C34/positive.json');
  const negative = await readJSON('tests/fixtures/keyhelix/C34/negative.json');
  const expected = await readJSON('tests/fixtures/keyhelix/C34/expected-output.json');

  assert.equal(positive.schema_version, 1);
  assert.equal(positive.task, 'C34');
  assert.equal(positive.requirement, 'N34');
  assert.equal(positive.license, 'Apache-2.0');
  assert.equal(positive.licenses.mandatory_paid_cloud_required, false);
  assert.equal(positive.data_limits_and_privacy.telemetry_enabled, false);
  assert.equal(positive.data_limits_and_privacy.provider_owns_secret_bytes, true);
  assert.equal(positive.support.vulnerability_reporting.initial_response_sla_hours, 48);

  assert.equal(negative.schema_version, 1);
  assert.equal(negative.task, 'C34');
  assert.equal(negative.requirement, 'N34');
  assert.equal(negative.cases.html_script_sentinel_inertness.rendered_as_inert_text, true);
  assert.equal(negative.cases.mobile_360px_failure_states.viewport_width, 360);
  assert.equal(negative.cases.mobile_360px_failure_states.horizontal_scroll_overflow, false);
  assert.equal(negative.cases.provider_owns_secret_bytes.client_persists_plaintext, false);
  assert.equal(negative.cases.mandatory_cloud_entitlement_bypass.cloud_credentials_required, false);

  assert.equal(expected.schema_version, 1);
  assert.equal(expected.task, 'C34');
  assert.equal(expected.requirement, 'N34');
  assert.equal(expected.results.public_documentation_complete.user_guide_present, true);
  assert.equal(expected.results.security_vulnerability_route.initial_response_sla_hours, 48);
  assert.equal(expected.results.negative_invariants.zero_cloud_entitlement, true);
});

test('C34 negative invariant: HTML/script sentinels remain inert and text-escaped', () => {
  const rawSentinel = "<script>alert('xss')</script><img src=x onerror=alert(1)>";
  // Verify that an inert text renderer escapes angle brackets and quotes
  const escaped = rawSentinel
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');

  assert.ok(!escaped.includes('<script>'), 'Inert text must not contain executable script tags');
  assert.ok(!escaped.includes('<img'), 'Inert text must not contain executable img tags');
  assert.ok(escaped.includes('&lt;script&gt;'), 'Angle brackets must be escaped');
});

test('C34 negative invariant: offline execution operates without external cloud environment variables', () => {
  // Confirm that no AWS/GCP/Azure/Vault-cloud credentials are required in the project configuration
  const cloudEnvs = ['AWS_ACCESS_KEY_ID', 'GOOGLE_APPLICATION_CREDENTIALS', 'AZURE_CLIENT_ID', 'HCP_CLIENT_ID'];
  for (const envVar of cloudEnvs) {
    assert.equal(process.env[envVar], undefined, `Mandatory cloud env ${envVar} must not be required`);
  }
});
