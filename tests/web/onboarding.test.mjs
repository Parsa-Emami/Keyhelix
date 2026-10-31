import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(fileURLToPath(new URL('../../', import.meta.url)));
const read = async path => readFile(resolve(root, path), 'utf8');
const readJSON = async path => JSON.parse(await read(path));

test('C36 deliverables: ONBOARDING_RESULTS.md exists and contains required sections', async () => {
  const results = await read('docs/product/ONBOARDING_RESULTS.md');

  // Core sections required by Requirement N36
  assert.ok(results.includes('Onboarding Verification Results'), 'Must include title');
  assert.ok(results.includes('Requirement N36'), 'Must reference Requirement N36');
  assert.ok(results.includes('docs/engineering/CLONE_TO_RUN.md'), 'Must reference public runbook');
  assert.ok(results.includes('Observed Effort Metrics'), 'Must record observed effort metrics');
  assert.ok(results.includes('Observed Friction & Edge Cases') || results.includes('Observed Friction and Edge Cases'), 'Must record observed friction and failures');
  assert.ok(results.includes('Provider Owns Secret Bytes'), 'Must confirm provider ownership');
  assert.ok(results.includes('Zero Telemetry'), 'Must confirm zero telemetry');
  assert.ok(results.includes('Zero Plaintext at Rest'), 'Must confirm zero plaintext leakage at rest');
  assert.ok(results.includes('Apache-2.0'), 'Must confirm Apache-2.0 open source license');
  assert.ok(results.toLowerCase().includes('customer demand and five pilots are not prerequisites'), 'Must reiterate OSS usability invariant');
});

test('C36 fixtures: positive, negative, and expected-output conform to N36 contract', async () => {
  const positive = await readJSON('tests/fixtures/keyhelix/C36/positive.json');
  const negative = await readJSON('tests/fixtures/keyhelix/C36/negative.json');
  const expected = await readJSON('tests/fixtures/keyhelix/C36/expected-output.json');

  // Positive fixture assertions
  assert.equal(positive.schema_version, 1);
  assert.equal(positive.task, 'C36');
  assert.equal(positive.requirement, 'N36');
  assert.equal(positive.license, 'Apache-2.0');
  assert.equal(positive.workflow, 'reference-workflow');
  assert.equal(positive.public_guide, 'docs/engineering/CLONE_TO_RUN.md');
  assert.equal(positive.effort_profile.cloud_account_required, false);
  assert.equal(positive.effort_profile.paid_entitlement_required, false);
  assert.equal(positive.effort_profile.customer_pilot_count_required, 0);
  assert.ok(Array.isArray(positive.steps) && positive.steps.length >= 6);

  // Negative fixture assertions
  assert.equal(negative.schema_version, 1);
  assert.equal(negative.task, 'C36');
  assert.equal(negative.requirement, 'N36');
  assert.equal(negative.license, 'Apache-2.0');
  assert.equal(negative.prohibited_plaintext_storage.expected_occurrences_in_metadata_and_provider_kv, 0);
  assert.equal(negative.usability_barriers_rejected.paid_account_prerequisite, false);
  assert.equal(negative.usability_barriers_rejected.cloud_subscription_prerequisite, false);
  assert.equal(negative.usability_barriers_rejected.customer_pilot_prerequisite, false);
  assert.ok(Array.isArray(negative.cases) && negative.cases.length >= 6);

  // Expected output assertions
  assert.equal(expected.schema_version, 1);
  assert.equal(expected.task, 'C36');
  assert.equal(expected.requirement, 'N36');
  assert.equal(expected.license, 'Apache-2.0');
  assert.equal(expected.status, 'passed');
  assert.equal(expected.public_guide, 'docs/engineering/CLONE_TO_RUN.md');
  assert.equal(expected.guards.step_up_required, 401);
  assert.equal(expected.guards.access_denied, 403);
  assert.equal(expected.guards.provider_unavailable, 503);
  assert.equal(expected.guards.authentication_failed, 422);
  assert.equal(expected.effort_benchmarks.workflow_verified, true);
  assert.equal(expected.effort_benchmarks.zero_plaintext_leak, true);
  assert.equal(expected.prerequisites_status.customer_demand_pilots_required, false);
  assert.equal(expected.prerequisites_status.cloud_account_required, false);
});

test('C36 scenario contract: tests/scenarios/clone-to-value.json references C36 verification', async () => {
  const scenario = await readJSON('tests/scenarios/clone-to-value.json');

  assert.equal(scenario.schema_version, 1);
  assert.equal(scenario.status, 'verified');
  assert.ok(scenario.fixtures.includes('tests/fixtures/keyhelix/C36/positive.json'));
  assert.ok(scenario.fixtures.includes('tests/fixtures/keyhelix/C36/negative.json'));
  assert.ok(scenario.fixtures.includes('tests/fixtures/keyhelix/C36/expected-output.json'));

  assert.ok(scenario.independent_onboarding_C36, 'Scenario must include independent_onboarding_C36 metadata');
  assert.equal(scenario.independent_onboarding_C36.task, 'C36');
  assert.equal(scenario.independent_onboarding_C36.requirement, 'N36');
  assert.equal(scenario.independent_onboarding_C36.public_guide, 'docs/engineering/CLONE_TO_RUN.md');
  assert.equal(scenario.independent_onboarding_C36.customer_demand_pilots_required, false);
  assert.equal(scenario.independent_onboarding_C36.cloud_account_required, false);
  assert.equal(scenario.independent_onboarding_C36.status, 'verified');
});
