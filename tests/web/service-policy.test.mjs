import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(fileURLToPath(new URL('../../', import.meta.url)));
const read = async path => readFile(resolve(root, path), 'utf8');
const readJSON = async path => JSON.parse(await read(path));

test('C38 deliverables: SERVICE_POLICY.md exists and covers all required local data and service policies', async () => {
  const content = await read('docs/release/SERVICE_POLICY.md');

  assert.ok(content.includes('Requirement N38'), 'SERVICE_POLICY.md must cite Requirement N38');
  assert.ok(content.includes('ADR-0003'), 'SERVICE_POLICY.md must cite ADR-0003');
  assert.ok(content.includes('Apache-2.0'), 'SERVICE_POLICY.md must cite Apache-2.0 license');
  assert.ok(content.includes('.local-data/'), 'SERVICE_POLICY.md must document .local-data/ runtime root');
  assert.ok(content.includes('engine/store/'), 'SERVICE_POLICY.md must document engine/store directory');
  assert.ok(content.includes('manifests/'), 'SERVICE_POLICY.md must document manifests/ directory');
  assert.ok(content.includes('blobs/'), 'SERVICE_POLICY.md must document blobs/ directory');
  assert.ok(content.includes('staging/'), 'SERVICE_POLICY.md must document staging/ directory');
  assert.ok(content.includes('Portable Export') || content.includes('Export'), 'SERVICE_POLICY.md must document export lifecycle');
  assert.ok(content.includes('Deletion') || content.includes('Destruction'), 'SERVICE_POLICY.md must document deletion lifecycle');
  assert.ok(content.includes('Retention') || content.includes('Bounded Storage'), 'SERVICE_POLICY.md must document retention limits');
  assert.ok(content.includes('1 MiB') || content.includes('1,048,576 bytes'), 'SERVICE_POLICY.md must document 1 MiB limit');
  assert.ok(content.includes('Backup') || content.includes('Disaster Recovery'), 'SERVICE_POLICY.md must document backup and recovery');
  assert.ok(content.includes('Forward Repair'), 'SERVICE_POLICY.md must document forward repair over stale rollback');
  assert.ok(content.includes('local-demo'), 'SERVICE_POLICY.md must document local-demo profile');
  assert.ok(content.includes('local-private'), 'SERVICE_POLICY.md must document local-private profile');
  assert.ok(content.includes('Zero Unearned SLA') || content.includes('Zero SLA'), 'SERVICE_POLICY.md must enforce zero unearned SLA policy');
  assert.ok(content.includes('Zero Telemetry'), 'SERVICE_POLICY.md must enforce zero telemetry policy');
});

test('C38 deliverables: MAINTENANCE.md exists and covers dependency governance and versioning policies', async () => {
  const content = await read('docs/release/MAINTENANCE.md');

  assert.ok(content.includes('Requirement N38'), 'MAINTENANCE.md must cite Requirement N38');
  assert.ok(content.includes('toolchain-lock.json'), 'MAINTENANCE.md must cite toolchain lock');
  assert.ok(content.includes('THIRD_PARTY_NOTICES.md'), 'MAINTENANCE.md must cite third-party notices');
  assert.ok(content.includes('OpenBao'), 'MAINTENANCE.md must cite OpenBao image pin');
  assert.ok(content.includes('Keycloak'), 'MAINTENANCE.md must cite Keycloak image pin');
  assert.ok(content.includes('Semantic Versioning') || content.includes('SemVer'), 'MAINTENANCE.md must document SemVer');
  assert.ok(content.includes('N-1 Reader Compatibility') || content.includes('N-1'), 'MAINTENANCE.md must document N-1 compatibility');
  assert.ok(content.includes('Upgrade Safety') || content.includes('Rollback'), 'MAINTENANCE.md must document upgrade and rollback guardrails');
  assert.ok(content.includes('48 hours'), 'MAINTENANCE.md must document 48h initial security response SLA');
  assert.ok(content.includes('Deprecation Policy') || content.includes('deprecation'), 'MAINTENANCE.md must document deprecation policy');
});

test('C38 fixtures: positive, negative, and expected-output conform to N38 contract', async () => {
  const positive = await readJSON('tests/fixtures/keyhelix/C38/positive.json');
  const negative = await readJSON('tests/fixtures/keyhelix/C38/negative.json');
  const expected = await readJSON('tests/fixtures/keyhelix/C38/expected-output.json');

  // Positive assertions
  assert.equal(positive.schema_version, 1);
  assert.equal(positive.task, 'C38');
  assert.equal(positive.requirement, 'N38');
  assert.equal(positive.license, 'Apache-2.0');
  assert.equal(positive.distribution.open_source_local_first, true);
  assert.equal(positive.distribution.hosted_subscription_required, false);
  assert.equal(positive.distribution.paid_features_required, false);
  assert.equal(positive.distribution.unearned_sla_claimed, false);
  assert.equal(positive.local_data_locations.runtime_root, '.local-data');
  assert.equal(positive.data_lifecycle.max_preview_size_bytes, 1048576);
  assert.equal(positive.data_lifecycle.stale_restore_prohibited, true);
  assert.equal(positive.data_lifecycle.forward_repair_preferred, true);
  assert.equal(positive.supported_profiles.private_profile, 'local-private');

  // Negative assertions
  assert.equal(negative.schema_version, 1);
  assert.equal(negative.task, 'C38');
  assert.equal(negative.requirement, 'N38');
  assert.equal(negative.cases.length, 6);

  const cases = negative.cases.map(c => c.case);
  assert.ok(cases.includes('staged-byte-writer-crash'), 'Must include staged-byte-writer-crash negative case');
  assert.ok(cases.includes('operation-replay-duplicate'), 'Must include operation-replay-duplicate negative case');
  assert.ok(cases.includes('quota-bounds-exhaustion'), 'Must include quota-bounds-exhaustion negative case');
  assert.ok(cases.includes('stale-manifest-downgrade'), 'Must include stale-manifest-downgrade negative case');
  assert.ok(cases.includes('provider-owns-secret-bytes'), 'Must include provider-owns-secret-bytes negative case');
  assert.ok(cases.includes('unearned-cloud-sla-bypass'), 'Must include unearned-cloud-sla-bypass negative case');

  // Expected output assertions
  assert.equal(expected.schema_version, 1);
  assert.equal(expected.task, 'C38');
  assert.equal(expected.requirement, 'N38');
  assert.equal(expected.status, 'passed');
  assert.equal(expected.deliverables.service_policy_present, true);
  assert.equal(expected.deliverables.maintenance_policy_present, true);
  assert.equal(expected.invariants_verified.atomic_manifest_on_writer_crash, true);
  assert.equal(expected.invariants_verified.replay_idempotency_enforced, true);
  assert.equal(expected.invariants_verified.quota_bounds_enforced, true);
  assert.equal(expected.invariants_verified.stale_restore_rejected, true);
  assert.equal(expected.invariants_verified.provider_owns_secret_bytes, true);
  assert.equal(expected.invariants_verified.zero_unearned_sla, true);
});
