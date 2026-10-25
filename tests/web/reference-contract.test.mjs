import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { validateReference } from '../../scripts/verify-reference.mjs';

const root = fileURLToPath(new URL('../../', import.meta.url));
const valid = {
  schema_version: 1,
  status: 'planned',
  steps: [{ id: 'auth-owner', action: 'Authenticate synthetic owner', expected_result: 'Session established' }],
  expected_invariants: ['Provider owns secret bytes'],
  negative_cases: [{ id: 'unauthorized-bypass', action: 'Reveal without step-up', expected_failure: 'Access denied' }],
  fixtures: [
    'tests/fixtures/keyhelix/C01/positive.json',
    'tests/fixtures/keyhelix/C01/invalid.json',
    'tests/fixtures/keyhelix/C01/expected-output.json'
  ],
  execution: { engine: 'not implemented', passed: false }
};

test('accepts the repository reference scenario and its licensed fixtures', async () => {
  assert.deepEqual(await validateReference(root, valid), []);
});

test('rejects missing workflow requirements and fixture provenance', async () => {
  for (const mutate of [
    s => { delete s.steps[0].action; },
    s => { delete s.steps[0].expected_result; },
    s => { s.expected_invariants = []; },
    s => { s.fixtures = []; }
  ]) {
    const scenario = structuredClone(valid);
    mutate(scenario);
    assert.notDeepEqual(await validateReference(root, scenario), []);
  }
  const scenario = structuredClone(valid);
  scenario.fixtures[0] = 'tests/fixtures/keyhelix/C01/missing.json';
  assert.ok((await validateReference(root, scenario)).some(error => error.includes('fixture')));
});

test('rejects fixture metadata without provenance or license', async () => {
  const temp = await mkdtemp(join(tmpdir(), 'keyhelix-reference-'));
  try {
    const dir = join(temp, 'fixtures');
    await mkdir(dir);
    for (const fixture of [{ license: 'Apache-2.0' }, { provenance: 'Synthetic fixture' }]) {
      await writeFile(join(dir, 'fixture.json'), JSON.stringify(fixture));
      const scenario = structuredClone(valid);
      scenario.fixtures = ['fixtures/fixture.json'];
      assert.ok((await validateReference(temp, scenario)).some(error => error.includes('provenance and license')));
    }
  } finally {
    await rm(temp, { recursive: true, force: true });
  }
});

test('rejects escaping paths, unsupported versions and false engine success claims', async () => {
  for (const mutate of [
    s => { s.schema_version = 2; },
    s => { s.fixtures[0] = '../outside.json'; },
    s => { s.execution = { engine: 'implemented', passed: true }; }
  ]) {
    const scenario = structuredClone(valid);
    mutate(scenario);
    assert.notDeepEqual(await validateReference(root, scenario), []);
  }
});
