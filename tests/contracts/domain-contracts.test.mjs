import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { resolve } from 'node:path';

const binary = resolve('dist/engine/keyhelix');
const read = async name => JSON.parse(await readFile(new URL(`../fixtures/keyhelix/C04/${name}.json`, import.meta.url)));
const positive = await read('positive');
const expected = await read('expected-output');
const invalid = await read('invalid');
const wire = await readFile(new URL('../fixtures/keyhelix/C04/valid-secret.txt', import.meta.url));

const run = input => spawnSync(binary, ['--validate-secret'], { input, encoding: 'utf8', timeout: 4000 });

let schemas;
async function validators() {
  if (!schemas) {
    const [{ default: Ajv }, { default: formats }] = await Promise.all([
      import('ajv/dist/2020.js'),
      import('ajv-formats')
    ]);
    const ajv = new Ajv({ strict: true });
    formats(ajv);
    const load = async name => JSON.parse(await readFile(new URL(`../../contracts/${name}.schema.json`, import.meta.url)));
    schemas = {
      input: ajv.compile(await load('input')),
      output: ajv.compile(await load('result'))
    };
  }
  return schemas;
}

test('CLI accepts the exact v1 fixture and reports validation without storage authority', () => {
  const actual = run(wire);
  assert.equal(actual.status, 0, actual.stderr);
  assert.equal(actual.stderr, '');
  assert.deepEqual(JSON.parse(actual.stdout), expected.output);
  assert.deepEqual(JSON.parse(run(wire).stdout), expected.output, 'repeat process must preserve deterministic validation output');
});

test('real schemas and Go reject every incompatible structural fixture', async () => {
  const schema = await validators();
  assert.equal(schema.input(positive.secret), true, JSON.stringify(schema.input.errors));
  assert.equal(schema.output(expected.output), true, JSON.stringify(schema.output.errors));

  for (const fixture of invalid.cases) {
    if (fixture.input) {
      assert.equal(schema.input(fixture.input), false, `${fixture.name} should fail schema validation`);
    }
    const bytes = fixture.raw ?? JSON.stringify(fixture.input);
    const actual = run(bytes);
    assert.equal(actual.status, 1, `${fixture.name}: ${actual.stderr}`);
    const parsed = JSON.parse(actual.stdout);
    assert.equal(parsed.status, 'failed', fixture.name);
    assert.equal(parsed.result.valid, false, fixture.name);
    assert.equal(parsed.result.error.code, fixture.expected_code, fixture.name);
    assert.equal(schema.output(parsed), true, `${fixture.name} error output must match result.schema.json: ${JSON.stringify(schema.output.errors)}`);
  }
});
