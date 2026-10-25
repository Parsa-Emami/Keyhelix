import { readFile, realpath } from 'node:fs/promises';
import { isAbsolute, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

export async function validateReference(root, scenario) {
  const errors = [];
  if (scenario?.schema_version !== 1) errors.push('unsupported scenario version');
  if (scenario?.status !== 'planned') errors.push('scenario must remain planned');
  if (!Array.isArray(scenario?.steps) || !scenario.steps.length) {
    errors.push('scenario requires workflow steps');
  } else {
    for (const [index, step] of scenario.steps.entries()) {
      if (!step?.id || !step?.action || !step?.expected_result) {
        errors.push(`step ${index + 1} requires id, action and expected_result`);
      }
    }
  }
  if (!Array.isArray(scenario?.expected_invariants) || !scenario.expected_invariants.length || scenario.expected_invariants.some(value => typeof value !== 'string' || !value.trim())) {
    errors.push('scenario requires expected invariants');
  }
  if (!Array.isArray(scenario?.negative_cases) || !scenario.negative_cases.length || scenario.negative_cases.some(item => !item?.id || !item?.action || !item?.expected_failure)) {
    errors.push('scenario requires negative cases with expected failures');
  }
  if (scenario?.execution?.engine !== 'not implemented' || scenario?.execution?.passed !== false) {
    errors.push('scenario cannot claim an unimplemented engine passed');
  }
  if (!Array.isArray(scenario?.fixtures) || scenario.fixtures.length < 3) {
    errors.push('scenario requires positive, invalid and expected-output fixture references');
  }

  let canonicalRoot;
  try {
    canonicalRoot = await realpath(root);
  } catch {
    return [...errors, 'repository root is unavailable'];
  }

  for (const fixture of scenario?.fixtures ?? []) {
    if (typeof fixture !== 'string' || !fixture || isAbsolute(fixture)) {
      errors.push(`fixture path must be repository-relative: ${fixture}`);
      continue;
    }
    const path = resolve(canonicalRoot, fixture);
    const rel = relative(canonicalRoot, path);
    if (rel === '..' || rel.startsWith(`..${sep}`) || isAbsolute(rel)) {
      errors.push(`fixture path escapes repository: ${fixture}`);
      continue;
    }
    try {
      const canonicalFixture = await realpath(path);
      const realRel = relative(canonicalRoot, canonicalFixture);
      if (realRel === '..' || realRel.startsWith(`..${sep}`) || isAbsolute(realRel)) throw new Error('escape');
      const data = JSON.parse(await readFile(canonicalFixture, 'utf8'));
      if (typeof data.provenance !== 'string' || !data.provenance.trim() || typeof data.license !== 'string' || !data.license.trim()) {
        errors.push(`fixture requires provenance and license: ${fixture}`);
      }
    } catch {
      errors.push(`fixture is missing, outside repository or invalid JSON: ${fixture}`);
    }
  }
  return errors;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const root = fileURLToPath(new URL('../', import.meta.url));
  try {
    const scenario = JSON.parse(await readFile(resolve(root, 'tests/scenarios/clone-to-value.json'), 'utf8'));
    const errors = await validateReference(root, scenario);
    if (errors.length) {
      console.error(errors.join('\n'));
      process.exitCode = 1;
    } else {
      console.log('Reference scenario and fixture metadata are valid; workflow execution is not verified.');
    }
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
