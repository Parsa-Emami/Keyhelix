import { readFile, realpath } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));

const officialHosts = new Set([
  'nodejs.org',
  'github.com',
  'registry.npmjs.org',
  'go.dev',
  'go.googlesource.com',
  'proxy.golang.org',
  'sum.golang.org',
  'archive.ubuntu.com',
  'launchpad.net',
  'openbao.org',
  'keycloak.org',
  'openid.net'
]);

const isOfficial = value => {
  if (typeof value !== 'string') return false;
  try {
    const url = new URL(value);
    return url.protocol === 'https:' && [...officialHosts].some(host => url.hostname === host || url.hostname.endsWith(`.${host}`));
  } catch {
    return false;
  }
};

export async function validateResources(repositoryRoot = root, manifest) {
  const errors = [];
  if (!manifest || manifest.schema_version !== 1 || !Array.isArray(manifest.resources) || !Array.isArray(manifest.not_applicable) || !Array.isArray(manifest.fixtures)) {
    return ['unsupported or incomplete resource manifest'];
  }
  const required = ['node-runtime', 'npm-cli', 'go-toolchain', 'podman-provider'];
  const present = new Set(manifest.resources.map(resource => resource?.id));
  for (const id of required) {
    if (!present.has(id)) errors.push(`required resource ${id} is missing`);
  }
  if (manifest.web_lockfile?.path && manifest.web_lockfile?.sha256) {
    try {
      const lockPath = path.resolve(repositoryRoot, manifest.web_lockfile.path);
      const base = await realpath(repositoryRoot);
      const target = await realpath(lockPath);
      if (!target.startsWith(`${base}${path.sep}`)) throw new Error('path escapes repository');
      const actual = createHash('sha256').update(await readFile(target)).digest('hex');
      if (actual !== manifest.web_lockfile.sha256) errors.push('web lockfile checksum mismatch');
    } catch (error) {
      errors.push(`web lockfile: ${error.message}`);
    }
  } else {
    errors.push('web lockfile path or checksum missing');
  }

  const seen = new Set();
  for (const resource of manifest.resources) {
    if (!resource?.id || seen.has(resource.id)) {
      errors.push(`duplicate or missing resource id: ${resource?.id ?? '(missing)'}`);
      continue;
    }
    seen.add(resource.id);
    if (!/^\d+\.\d+\.\d+(?:[+-][0-9A-Za-z.-]+)?$/.test(resource.version ?? '')) {
      errors.push(`${resource.id}: version must be exact and non-floating`);
    }
    if (typeof resource.artifact_url === 'string' && /(?:^|[/:@_-])(latest|stable|edge)(?:$|[/:@_-])/i.test(resource.artifact_url)) {
      errors.push(`${resource.id}: artifact URL uses a floating tag`);
    }
    for (const key of ['artifact_url', 'source_url', 'license_url']) {
      if (!isOfficial(resource[key])) errors.push(`${resource.id}: missing official ${key}`);
    }
    if (typeof resource.license !== 'string' || !resource.license.trim()) {
      errors.push(`${resource.id}: missing license`);
    }
    if (typeof resource.source_build !== 'string' || !resource.source_build.trim()) {
      errors.push(`${resource.id}: missing source-build route`);
    }
    const i = resource.integrity;
    if (!i || !['sha256', 'sha512', 'go-module-h1'].includes(i.algorithm) || !i.expected || i.expected !== i.observed) {
      errors.push(`${resource.id}: missing or mismatched integrity checksum`);
    } else if (i.algorithm === 'sha256' && !/^[a-f0-9]{64}$/.test(i.expected)) {
      errors.push(`${resource.id}: invalid sha256 checksum`);
    } else if (i.algorithm === 'sha512' && !/^sha512-[A-Za-z0-9+/]{86}==$/.test(i.expected)) {
      errors.push(`${resource.id}: invalid sha512 integrity`);
    } else if (i.algorithm === 'go-module-h1' && !/^h1:[A-Za-z0-9+/]{43}=$/.test(i.expected)) {
      errors.push(`${resource.id}: invalid Go module checksum`);
    }
    if (!resource.probe || typeof resource.probe.command !== 'string' || !resource.probe.command.trim()) {
      errors.push(`${resource.id}: missing version probe`);
    } else if (resource.probe.exit_code !== 0 && resource.required !== false) {
      errors.push(`${resource.id}: required resource probe failed`);
    }
  }

  for (const item of manifest.not_applicable) {
    if (!item?.id || !item.reason?.trim()) errors.push('not-applicable resource is missing its reason');
  }

  for (const fixture of manifest.fixtures) {
    try {
      if (!fixture?.path || path.isAbsolute(fixture.path) || fixture.path.split(/[\\/]/).includes('..')) {
        throw new Error('unsafe fixture path');
      }
      const target = await realpath(path.resolve(repositoryRoot, fixture.path));
      const base = await realpath(repositoryRoot);
      if (!target.startsWith(`${base}${path.sep}`)) throw new Error('fixture escapes repository');
      const bytes = await readFile(target);
      const actual = createHash('sha256').update(bytes).digest('hex');
      if (!/^[a-f0-9]{64}$/.test(fixture.sha256 ?? '') || actual !== fixture.sha256) {
        throw new Error('fixture checksum mismatch');
      }
      const parsed = JSON.parse(bytes.toString('utf8'));
      if (!parsed.provenance?.trim() || !parsed.license?.trim()) {
        throw new Error('fixture provenance/license missing');
      }
    } catch (error) {
      errors.push(`fixture ${fixture?.path ?? '(missing)'}: ${error.message}`);
    }
  }
  return errors;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const manifest = JSON.parse(await readFile(path.join(root, 'docs/engineering/toolchain-lock.json'), 'utf8'));
    const errors = await validateResources(root, manifest);
    if (errors.length) {
      console.error(errors.join('\n'));
      process.exitCode = 1;
    } else {
      console.log('Resource metadata, recorded probes, and fixture digests are valid; this does not verify engine execution.');
    }
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
