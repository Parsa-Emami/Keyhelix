import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { load, releaseCheck } from '../../scripts/roadmap.mjs';

const root = resolve(fileURLToPath(new URL('../../', import.meta.url)));
const read = async path => readFile(resolve(root, path), 'utf8');
const readJSON = async path => JSON.parse(await read(path));

test('C39 releaseCheck passes (exit 0) with verified C01-C38 evidence and v1-gate.json', async () => {
  const { plan, progress, gates, errors } = await load();
  assert.deepEqual(errors, []);

  const result = await releaseCheck(plan, progress, gates);
  assert.equal(result.ready, true, `Expected ready=true, got failures: ${result.failures.join('; ')}`);
  assert.equal(result.exit_code, 0);
  assert.equal(result.verified_prerequisites, 38);
  assert.deepEqual(result.failures, []);

  const cli = spawnSync(process.execPath, [resolve(root, 'scripts/roadmap.mjs'), 'release-check'], {
    cwd: root,
    encoding: 'utf8'
  });
  assert.equal(cli.status, 0, `Expected release:check CLI exit 0, stderr: ${cli.stderr}`);
  const output = JSON.parse(cli.stdout.trim());
  assert.equal(output.status, 'RELEASE_GATE_PASSED');
  assert.equal(output.verified_prerequisites, 38);
});

test('C39 releaseCheck fails closed (exit 2) on planning templates, missing proofs, wrong-source evidence, and restricted licenses', async () => {
  const { plan, progress, gates } = await load();

  // 1. Planning template in C01-C38 evidence must fail the release gate
  const templateResult = await releaseCheck(plan, progress, gates, {
    readJson: async path => {
      const data = await readJSON(path);
      if (path === 'docs/evidence/C15.json') data.planning_template = true;
      return data;
    }
  });
  assert.equal(templateResult.ready, false);
  assert.equal(templateResult.exit_code, 2);
  assert.ok(templateResult.failures.some(f => f.includes('C15') && f.includes('planning_template')));

  // 2. Missing prerequisite proof must fail the release gate
  const missingProofProgress = structuredClone(progress);
  missingProofProgress.commits.find(c => c.id === 'C30').status = 'planned';
  const missingResult = await releaseCheck(plan, missingProofProgress, gates);
  assert.equal(missingResult.ready, false);
  assert.equal(missingResult.exit_code, 2);
  assert.ok(missingResult.failures.some(f => f.includes('C30')));

  // 3. Wrong source_identity between evidence and progress.json must fail the release gate
  const wrongSourceResult = await releaseCheck(plan, progress, gates, {
    readJson: async path => {
      const data = await readJSON(path);
      if (path === 'docs/evidence/C38.json') {
        data.source_identity = 'sha256:0000000000000000000000000000000000000000000000000000000000000000';
      }
      return data;
    }
  });
  assert.equal(wrongSourceResult.ready, false);
  assert.equal(wrongSourceResult.exit_code, 2);
  assert.ok(wrongSourceResult.failures.some(f => f.includes('C38') && f.includes('wrong source_identity')));

  // 4. Restricted or unknown license in toolchain or v1-gate must fail the release gate
  const restrictedLicenseResult = await releaseCheck(plan, progress, gates, {
    readJson: async path => {
      const data = await readJSON(path);
      if (path === 'docs/evidence/v1-gate.json') {
        data.licenses_and_provenance.shipped_resources.push({
          id: 'proprietary-plugin',
          license: 'Proprietary-Commercial-Only'
        });
      }
      return data;
    }
  });
  assert.equal(restrictedLicenseResult.ready, false);
  assert.equal(restrictedLicenseResult.exit_code, 2);
  assert.ok(restrictedLicenseResult.failures.some(f => f.includes('restricted or unknown shipped resource license')));
});

test('C39 deliverables: release-gate.yml workflow and v1-gate.json conform to N39 contract', async () => {
  const workflow = await read('.github/workflows/release-gate.yml');
  assert.match(workflow, /actions\/checkout@[0-9a-f]{40}/);
  assert.match(workflow, /actions\/setup-node@[0-9a-f]{40}/);
  assert.match(workflow, /actions\/setup-go@[0-9a-f]{40}/);
  assert.ok(workflow.includes('npm run release:check'), 'release-gate.yml must run npm run release:check');
  assert.ok(workflow.includes('TestC39'), 'release-gate.yml must run Go TestC39 suite');

  const v1Gate = await readJSON('docs/evidence/v1-gate.json');
  assert.equal(v1Gate.passed, true);
  assert.equal(v1Gate.planning_template, false);
  assert.equal(v1Gate.task, 'C39');
  assert.equal(v1Gate.requirement, 'N39');
  assert.equal(Object.keys(v1Gate.verified_commits).length, 38);
});

test('C39 fixtures: positive, negative, and expected-output conform to N39 contract', async () => {
  const positive = await readJSON('tests/fixtures/keyhelix/C39/positive.json');
  const negative = await readJSON('tests/fixtures/keyhelix/C39/negative.json');
  const expected = await readJSON('tests/fixtures/keyhelix/C39/expected-output.json');

  assert.equal(positive.schema_version, 1);
  assert.equal(positive.task, 'C39');
  assert.equal(positive.requirement, 'N39');
  assert.equal(positive.license, 'Apache-2.0');
  assert.equal(positive.gate.prerequisite_count, 38);
  assert.equal(positive.gate.planning_templates_allowed, false);
  assert.equal(positive.verifications.security_and_recovery.provider_owns_secret_bytes, true);

  assert.equal(negative.schema_version, 1);
  assert.equal(negative.task, 'C39');
  assert.equal(negative.requirement, 'N39');
  const caseNames = negative.cases.map(c => c.case);
  assert.ok(caseNames.includes('planning-template-evidence'));
  assert.ok(caseNames.includes('missing-prerequisite-proof'));
  assert.ok(caseNames.includes('wrong-source-identity'));
  assert.ok(caseNames.includes('restricted-or-unknown-license'));
  assert.ok(caseNames.includes('staged-byte-writer-crash'));
  assert.ok(caseNames.includes('operation-replay-and-quota'));
  assert.ok(caseNames.includes('provider-owns-secret-bytes'));

  assert.equal(expected.schema_version, 1);
  assert.equal(expected.task, 'C39');
  assert.equal(expected.requirement, 'N39');
  assert.equal(expected.status, 'passed');
  assert.equal(expected.invariants_verified.c01_through_c38_verified, true);
  assert.equal(expected.invariants_verified.planning_templates_rejected, true);
  assert.equal(expected.invariants_verified.missing_proofs_rejected, true);
  assert.equal(expected.invariants_verified.wrong_source_evidence_rejected, true);
  assert.equal(expected.invariants_verified.provider_owns_secret_bytes, true);
});
