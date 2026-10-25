import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { createHash } from 'node:crypto';
import { join } from 'node:path';
import { validateResources } from '../../scripts/verify-resources.mjs';

const digest = value => createHash('sha256').update(value).digest('hex');
const sources = {
  'node-runtime': ['https://nodejs.org/dist/v24.19.0/node-v24.19.0-linux-x64.tar.xz', 'https://github.com/nodejs/node', 'https://github.com/nodejs/node/blob/main/LICENSE'],
  'npm-cli': ['https://registry.npmjs.org/npm/-/npm-11.9.0.tgz', 'https://github.com/npm/cli', 'https://github.com/npm/cli/blob/latest/LICENSE'],
  'go-toolchain': ['https://proxy.golang.org/golang.org/toolchain/@v/toolchain.zip', 'https://go.googlesource.com/go', 'https://go.dev/LICENSE'],
  'podman-provider': ['https://archive.ubuntu.com/ubuntu/pool/universe/libp/libpod/podman.deb', 'https://launchpad.net/ubuntu/+source/libpod', 'https://github.com/containers/podman/blob/main/LICENSE'],
  'optional-report-import': ['https://registry.npmjs.org/report-import', 'https://github.com/example/report-import', 'https://github.com/example/report-import/blob/main/LICENSE']
};
const artifact = id => ({
  id,
  version: '1.2.3',
  required: true,
  artifact_url: sources[id][0],
  source_url: sources[id][1],
  license: 'Apache-2.0',
  license_url: sources[id][2],
  integrity: { algorithm: 'sha256', expected: 'a'.repeat(64), observed: 'a'.repeat(64) },
  source_build: 'Build from the versioned upstream source tag 1.2.3.',
  probe: { command: `${id} --version`, exit_code: 0, version: '1.2.3' }
});

async function context() {
  const root = await mkdtemp(join(tmpdir(), 'keyhelix-resources-'));
  const fixturePath = 'tests/fixtures/keyhelix/C02/positive.json';
  const fixture = JSON.stringify({ provenance: 'Repository-authored synthetic fixture.', license: 'Apache-2.0' });
  await mkdir(join(root, 'tests/fixtures/keyhelix/C02'), { recursive: true });
  await writeFile(join(root, 'package-lock.json'), 'locked');
  await writeFile(join(root, fixturePath), fixture);
  return {
    root,
    manifest: {
      schema_version: 1,
      web_lockfile: { path: 'package-lock.json', sha256: digest('locked') },
      resources: ['node-runtime', 'npm-cli', 'go-toolchain', 'podman-provider'].map(artifact),
      not_applicable: ['oci-image', 'grammar', 'rule'].map(id => ({ id, reason: 'No corresponding upstream artifact is selected by the current task cards.' })),
      fixtures: [{ path: fixturePath, sha256: digest(fixture) }]
    }
  };
}

test('accepts exact versioned resources, an explicitly optional missing tool and synthetic fixtures', async () => {
  const c = await context();
  try {
    c.manifest.resources.push({
      ...artifact('optional-report-import'),
      required: false,
      probe: { command: 'report-import --version', exit_code: 127, version: null }
    });
    c.manifest.web_lockfile.sha256 = digest('locked');
    assert.deepEqual(await validateResources(c.root, c.manifest), []);
  } finally {
    await rm(c.root, { recursive: true, force: true });
  }
});

test('rejects floating resources, missing official metadata and mismatched integrity', async () => {
  const c = await context();
  try {
    for (const mutate of [
      m => { m.resources = m.resources.filter(resource => resource.id !== 'go-toolchain'); },
      m => { m.resources[0].artifact_url = 'https://nodejs.org/dist/latest/node-v24-linux-x64.tar.xz'; },
      m => { m.resources[0].version = 'latest'; },
      m => { m.resources[0].integrity = null; },
      m => { m.resources[0].source_url = ''; },
      m => { m.resources[0].license = ''; },
      m => { m.resources[0].integrity.observed = 'b'.repeat(64); }
    ]) {
      const manifest = structuredClone(c.manifest);
      mutate(manifest);
      assert.notDeepEqual(await validateResources(c.root, manifest), []);
    }
    const badLockfile = structuredClone(c.manifest);
    badLockfile.web_lockfile.sha256 = '0'.repeat(64);
    assert.ok((await validateResources(c.root, badLockfile)).some(error => error.includes('web lockfile checksum')));
  } finally {
    await rm(c.root, { recursive: true, force: true });
  }
});

test('rejects unavailable required resources and fixture escapes or checksum changes', async () => {
  const c = await context();
  try {
    let manifest = structuredClone(c.manifest);
    manifest.resources[2].probe = { command: 'go version', exit_code: 127, version: null };
    assert.ok((await validateResources(c.root, manifest)).some(error => error.includes('required resource')));
    manifest = structuredClone(c.manifest);
    manifest.fixtures[0].path = '../outside.json';
    assert.ok((await validateResources(c.root, manifest)).some(error => error.includes('fixture')));
    manifest = structuredClone(c.manifest);
    manifest.fixtures[0].sha256 = '0'.repeat(64);
    assert.ok((await validateResources(c.root, manifest)).some(error => error.includes('checksum')));
    manifest = structuredClone(c.manifest);
    manifest.schema_version = 2;
    assert.ok((await validateResources(c.root, manifest)).some(error => error.includes('unsupported')));
    const invalidFixture = JSON.stringify({ license: 'Apache-2.0' });
    await writeFile(join(c.root, 'tests/fixtures/keyhelix/C02/positive.json'), invalidFixture);
    manifest = structuredClone(c.manifest);
    manifest.fixtures[0].sha256 = digest(invalidFixture);
    assert.ok((await validateResources(c.root, manifest)).some(error => error.includes('provenance/license')));
  } finally {
    await rm(c.root, { recursive: true, force: true });
  }
});
