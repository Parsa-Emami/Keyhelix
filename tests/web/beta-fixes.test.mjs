import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createServer } from 'node:net';
import { once } from 'node:events';
import { checkPortConflict } from '../../scripts/oss-bootstrap.mjs';

const root = resolve(fileURLToPath(new URL('../../', import.meta.url)));
const read = async path => readFile(resolve(root, path), 'utf8');
const readJSON = async path => JSON.parse(await read(path));

test('C37 deliverables: BETA_FIXES.md exists and covers all required milestone audits', async () => {
  const content = await read('docs/product/BETA_FIXES.md');

  assert.ok(content.includes('Acceptance Fixes & Blocker Resolutions') || content.includes('Acceptance Fixes and Blocker Resolutions'), 'Title required');
  assert.ok(content.includes('Requirement N37'), 'Must cite Requirement N37');
  assert.ok(content.includes('C30'), 'Must audit C30');
  assert.ok(content.includes('C33'), 'Must audit C33');
  assert.ok(content.includes('C35'), 'Must audit C35');
  assert.ok(content.includes('C36'), 'Must audit C36');
  assert.ok(content.includes('FIX-01-PORT-PREFLIGHT'), 'Must document FIX-01');
  assert.ok(content.includes('FIX-02-PROVIDER-TIMEOUT-RESILIENCE'), 'Must document FIX-02');
  assert.ok(content.includes('FIX-03-STEPUP-MEM-CLEAR'), 'Must document FIX-03');
  assert.ok(content.includes('FIX-04-REVOCATION-IMMEDIACY'), 'Must document FIX-04');
  assert.ok(content.includes('FIX-05-DOWNGRADE-DATA-SAFETY'), 'Must document FIX-05');
  assert.ok(content.includes('Targeted Regressions Matrix'), 'Must include regressions matrix');
  assert.ok(content.includes('Zero Unresolved Blockers') || content.includes('zero unresolved blockers'), 'Must explicitly confirm zero unresolved blockers');
});

test('C37 fixtures: positive, negative, and expected-output conform to N37 contract', async () => {
  const positive = await readJSON('tests/fixtures/keyhelix/C37/positive.json');
  const negative = await readJSON('tests/fixtures/keyhelix/C37/negative.json');
  const expected = await readJSON('tests/fixtures/keyhelix/C37/expected-output.json');

  // Positive fixture assertions
  assert.equal(positive.schema_version, 1);
  assert.equal(positive.task, 'C37');
  assert.equal(positive.requirement, 'N37');
  assert.equal(positive.license, 'Apache-2.0');
  assert.deepEqual(positive.target_milestones, ['C30', 'C33', 'C35', 'C36']);
  assert.equal(positive.fixes.length, 5);

  // Negative fixture assertions
  assert.equal(negative.schema_version, 1);
  assert.equal(negative.task, 'C37');
  assert.equal(negative.requirement, 'N37');
  assert.equal(negative.license, 'Apache-2.0');
  assert.equal(negative.prohibited_plaintext_storage.expected_occurrences_in_metadata_and_provider_kv, 0);
  assert.equal(negative.unresolved_blockers_policy.blockers_concealed, false);
  assert.equal(negative.unresolved_blockers_policy.invariants_weakened, false);

  // Expected output assertions
  assert.equal(expected.schema_version, 1);
  assert.equal(expected.task, 'C37');
  assert.equal(expected.requirement, 'N37');
  assert.equal(expected.status, 'passed');
  assert.equal(expected.fixes_summary.port_conflict_preflight, true);
  assert.equal(expected.fixes_summary.revocation_immediate_denial, true);
  assert.equal(expected.fixes_summary.downgrade_data_safety, true);
  assert.deepEqual(expected.unresolved_blockers, []);
});

test('checkPortConflict utility correctly identifies listening vs unbound ports', async t => {
  const server = createServer();
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const port = server.address().port;

  t.after(() => new Promise(resolve => server.close(resolve)));

  const busyBeforeClose = await checkPortConflict(port);
  assert.equal(busyBeforeClose, true, `Bound port ${port} should be detected as listening`);

  await new Promise(resolve => server.close(resolve));

  const freeAfterClose = await checkPortConflict(port);
  assert.equal(freeAfterClose, false, `Closed port ${port} should be detected as free`);
});
