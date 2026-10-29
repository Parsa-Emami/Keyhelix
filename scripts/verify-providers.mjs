import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
const officialHosts = new Set(['quay.io', 'openbao.org', 'keycloak.org', 'github.com']);
const imageRepos = { openbao: 'quay.io/openbao/openbao', keycloak: 'quay.io/keycloak/keycloak' };
const licenses = { openbao: 'MPL-2.0', keycloak: 'Apache-2.0' };

const official = value => {
  if (typeof value !== 'string') return false;
  try {
    const url = new URL(value);
    return url.protocol === 'https:' && [...officialHosts].some(host => url.hostname === host || url.hostname.endsWith(`.${host}`));
  } catch {
    return false;
  }
};

export async function validateProviders(manifest) {
  const errors = [];
  if (!manifest || manifest.schema_version !== 1) return ['unsupported provider lock schema'];
  if (manifest.profile?.os !== 'linux' || manifest.profile?.architecture !== 'amd64' || manifest.profile?.rootless !== true || manifest.profile?.loopback_only !== true) {
    errors.push('provider profile must be linux/amd64, rootless and loopback-only');
  }
  if (!Array.isArray(manifest.providers) || manifest.providers.length !== 2) {
    errors.push('provider lock must contain exactly OpenBao and Keycloak');
    return errors;
  }
  const seen = new Set();
  for (const provider of manifest.providers) {
    if (!provider || typeof provider !== 'object') {
      errors.push('provider entry must be an object');
      continue;
    }
    if (seen.has(provider.id)) errors.push(`duplicate provider id: ${provider.id}`);
    seen.add(provider.id);
    if (!imageRepos[provider.id]) {
      errors.push(`unknown provider: ${provider.id}`);
      continue;
    }
    if (provider.image !== imageRepos[provider.id]) errors.push(`${provider.id}: image repository must be ${imageRepos[provider.id]}`);
    if (!/^\d+\.\d+\.\d+$/.test(provider.version ?? '')) errors.push(`${provider.id}: version must be exact semver`);
    if (!/^sha256:[a-f0-9]{64}$/.test(provider.digest ?? '')) errors.push(`${provider.id}: digest must be a pinned sha256`);
    if (provider.license !== licenses[provider.id]) errors.push(`${provider.id}: license must be ${licenses[provider.id]}`);
    for (const key of ['source_url', 'license_url', 'docs_url']) {
      if (!official(provider[key])) errors.push(`${provider.id}: ${key} must be an official https source`);
    }
    if (provider.container_port !== (provider.id === 'openbao' ? 8200 : 8080)) errors.push(`${provider.id}: unexpected container port`);
    if (typeof provider.role !== 'string' || !provider.role.trim()) errors.push(`${provider.id}: role is required`);
  }
  for (const id of Object.keys(imageRepos)) if (!seen.has(id)) errors.push(`missing provider: ${id}`);
  return errors;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const manifest = JSON.parse(await readFile(path.join(root, 'ops/providers.lock.json'), 'utf8'));
    const errors = await validateProviders(manifest);
    if (errors.length) {
      console.error(errors.join('\n'));
      process.exitCode = 1;
    } else {
      console.log('Provider pins, licenses and official sources are valid; no container was started.');
    }
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
