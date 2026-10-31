import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { validateBuildInputs, scanForSecrets } from '../../scripts/package-web.mjs';
import { ALLOWED_LICENSES, buildSbom, collectNpmComponents, renderNotices, selectSourceFiles } from '../../scripts/package-source.mjs';

const root = new URL('../../', import.meta.url);
const readJson = async path => JSON.parse(await readFile(new URL(path, root), 'utf8'));

const locks = async () => {
  const [packageJson, lock, providerLock, toolchain] = await Promise.all([
    readJson('package.json'),
    readJson('package-lock.json'),
    readJson('ops/providers.lock.json'),
    readJson('docs/engineering/toolchain-lock.json')
  ]);
  return { packageJson, lock, providerLock, toolchain };
};

test('committed third-party notices exactly match the committed npm and provider locks', async () => {
  const values = await locks();
  const actual = await readFile(new URL('THIRD_PARTY_NOTICES.md', root), 'utf8');
  const expected = renderNotices(values);
  assert.equal(actual, expected);
  const components = collectNpmComponents(values.lock);
  assert.equal(components.length, 76);
  assert.deepEqual(components.filter(component => component.scope === 'required').map(component => component.name).sort(), ['react', 'react-dom', 'scheduler']);
  assert.ok(components.every(component => ALLOWED_LICENSES.has(component.license)));
});

test('SBOM is deterministic and rejects unknown licenses and missing runtime components', async () => {
  const values = await locks();
  const input = { commit: 'a'.repeat(40), treeSha256: 'b'.repeat(64), ...values, timestamp: '2026-01-01T00:00:00.000Z' };
  const first = buildSbom(input);
  const second = buildSbom(input);
  assert.deepEqual(first, second);
  assert.equal(first.bomFormat, 'CycloneDX');
  assert.equal(first.specVersion, '1.5');
  assert.ok(first.components.some(component => component.purl === 'pkg:npm/react@19.3.1' && component.scope === 'required'));
  assert.ok(first.components.some(component => component.name === 'openbao' && component.type === 'container'));
  assert.ok(first.components.every(component => component.licenses.every(entry => ALLOWED_LICENSES.has(entry.license.id))));

  const bad = structuredClone(values.lock);
  const key = Object.keys(bad.packages).find(candidate => candidate.startsWith('node_modules/'));
  bad.packages[key].license = 'UNLICENSED';
  assert.throws(() => buildSbom({ ...input, lock: bad }), /unknown-license/);

  const missing = structuredClone(values.lock);
  const reactKey = 'node_modules/react';
  delete missing.packages[reactKey];
  assert.throws(() => buildSbom({ ...input, lock: missing }), /missing-runtime-component/);
});

test('source selection excludes runtime state, secret files and build output but keeps the env template', () => {
  assert.deepEqual(selectSourceFiles([
    'src/a.js',
    '.env',
    '.env.local',
    '.env.example',
    'node_modules/react/index.js',
    'dist/web/index.html',
    '.local-data/runtime.json',
    'provider/key.pem',
    'provider/runtime.json',
    'provider/init.json',
    'docs/evidence/C01.json',
    'docs/readme.md'
  ]), ['.env.example', 'docs/readme.md', 'src/a.js']);
});

test('secret scanning rejects private keys and OpenBao tokens while allowing references', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'keyhelix-secret-scan-'));
  try {
    await mkdir(join(directory, 'docs'), { recursive: true });
    await writeFile(join(directory, 'docs', 'safe.md'), 'OPENBAO_TOKEN_REF=secret://local/openbao-token\n');
    await scanForSecrets(directory);
    await writeFile(join(directory, 'docs', 'leak.txt'), 'hvs.' + 'a'.repeat(32) + '\n');
    await assert.rejects(() => scanForSecrets(directory), /secret-material:openbao-token/);
    await writeFile(join(directory, 'docs', 'leak.txt'), '-----BEGIN PRIVATE KEY-----\nnot-real\n');
    await assert.rejects(() => scanForSecrets(directory), /secret-material:private-key/);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('build input validation fails closed without an engine binary', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'keyhelix-build-input-'));
  try {
    await mkdir(join(directory, 'dist', 'web'), { recursive: true });
    await writeFile(join(directory, 'dist', 'web', 'index.html'), '<!doctype html>');
    await assert.rejects(() => validateBuildInputs(directory), /package-error: missing-engine/);
    assert.equal((await stat(new URL('scripts/package.sh', root))).isFile(), true);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
