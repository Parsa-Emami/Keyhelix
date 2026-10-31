import { chmod, cp, mkdir, readdir, readFile, lstat, stat, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { dirname, join, resolve, sep } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const repository = fileURLToPath(new URL('../', import.meta.url));

// Only these runtime files are copied. Everything else in the checkout (including
// .local-data, provider state, node_modules, build caches and evidence) is excluded.
export const RUNTIME_SCRIPTS = [
  'scripts/serve-web.mjs',
  'scripts/start-local.mjs',
  'scripts/providers.mjs',
  'scripts/verify-providers.mjs'
];

export const RESOURCE_DIRECTORIES = ['contracts', 'spec', 'ops/web', 'ops/local'];

export const RESOURCE_FILES = [
  'infra/deployment.md',
  'ops/DEPLOYMENT_PREREQUISITES.md',
  'ops/deployment-profiles.json',
  'ops/diagnostics.md',
  'ops/provider-recovery.md',
  'ops/providers.lock.json',
  'ops/runtime-requirements.json',
  'docs/engineering/CLONE_TO_RUN.md',
  'docs/engineering/ENGINE_LAUNCH.md',
  'docs/engineering/WEB_RUNBOOK.md',
  'docs/engineering/toolchain-lock.json',
  'docs/product/REFERENCE_WORKFLOW.md',
  'docs/release/ARTIFACTS.md'
];

export const REQUIRED_STAGE_FILES = [
  'web/index.html',
  'dist/engine/keyhelix',
  'scripts/serve-web.mjs',
  'scripts/start-local.mjs',
  'scripts/providers.mjs',
  'apps/web/src/lib/runtime-config.mjs',
  'ops/web/runtime-config.json',
  'ops/web/brand.json',
  'ops/providers.lock.json',
  'docs/engineering/toolchain-lock.json',
  'docs/release/ARTIFACTS.md',
  'contracts/openapi.v1.json',
  'spec/04_AUTHORIZATION_MATRIX.md',
  'LICENSE',
  'NOTICE'
];

export const SECRET_PATTERNS = [
  { id: 'private-key', pattern: /-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/ },
  { id: 'openbao-token', pattern: /\b(?:hvs|hvb)\.[A-Za-z0-9_-]{20,}/ },
  { id: 'session-token', pattern: /\bkeyhelix_session=[A-Za-z0-9._~+/=-]{20,}/ },
  { id: 'bearer-token', pattern: /\bBearer\s+[A-Za-z0-9._~+/=-]{24,}/ }
];

const FORBIDDEN_PATH_SEGMENTS = new Set(['node_modules', '.local-data', '.git', 'test-results', 'playwright-report']);
const FORBIDDEN_FILE_NAMES = new Set(['.env', 'runtime.json', 'init.json', 'id_rsa']);
const FORBIDDEN_EXTENSIONS = /\.(?:pem|key|p12|pfx)$/i;

const categoryFor = path => {
  if (path.startsWith('contracts/')) return 'contract';
  if (path.startsWith('spec/')) return 'rule';
  if (path.startsWith('ops/')) return 'ops';
  if (path.startsWith('docs/release/')) return 'release';
  if (path.startsWith('docs/engineering/')) return 'engineering';
  if (path.startsWith('docs/product/')) return 'workflow';
  return 'resource';
};

const sha256 = value => createHash('sha256').update(value).digest('hex');

export async function walkFiles(root, prefix = '') {
  const files = [];
  for (const entry of (await readdir(root, { withFileTypes: true })).sort((a, b) => a.name.localeCompare(b.name))) {
    const relative = prefix ? prefix + '/' + entry.name : entry.name;
    if (entry.isDirectory()) files.push(...await walkFiles(join(root, entry.name), relative));
    else files.push({ path: relative, directory: entry.isDirectory(), symbolic: entry.isSymbolicLink() });
  }
  return files;
}

export async function validateBuildInputs(root = repository) {
  try {
    const index = await stat(join(root, 'dist/web/index.html'));
    if (!index.isFile()) throw new Error();
  } catch {
    throw new Error('package-error: missing-web-build');
  }
  let engine;
  try {
    engine = await stat(join(root, 'dist/engine/keyhelix'));
  } catch {
    throw new Error('package-error: missing-engine');
  }
  if (!engine.isFile() || (engine.mode & 0o111) === 0) throw new Error('package-error: missing-engine');
}

async function assertSafeTree(stage) {
  for (const entry of await walkFiles(stage)) {
    if (entry.symbolic) throw new Error(`package-error: forbidden-symlink:${entry.path}`);
    const parts = entry.path.split('/');
    if (parts.some(part => FORBIDDEN_PATH_SEGMENTS.has(part))) {
      throw new Error(`package-error: forbidden-path:${entry.path}`);
    }
    const name = parts.at(-1);
    if (FORBIDDEN_FILE_NAMES.has(name) || (name.startsWith('.env.') && name !== '.env.example') || FORBIDDEN_EXTENSIONS.test(name)) {
      throw new Error(`package-error: forbidden-path:${entry.path}`);
    }
  }
}

export async function scanForSecrets(root) {
  for (const entry of await walkFiles(root)) {
    const file = join(root, ...entry.path.split('/'));
    const info = await lstat(file);
    if (info.isSymbolicLink()) throw new Error(`package-error: forbidden-symlink:${entry.path}`);
    if (!info.isFile()) continue;
    if (info.size > 128 * 1024 * 1024) throw new Error(`package-error: oversized-file:${entry.path}`);
    const text = (await readFile(file)).toString('latin1');
    for (const { id, pattern } of SECRET_PATTERNS) {
      if (pattern.test(text)) throw new Error(`package-error: secret-material:${id}:${entry.path}`);
    }
  }
}

async function copyPath(root, stage, path) {
  const source = join(root, ...path.split('/'));
  const destination = join(stage, ...path.split('/'));
  await mkdir(dirname(destination), { recursive: true });
  await cp(source, destination, { recursive: true, dereference: false, force: true, preserveTimestamps: false });
}

async function resourcesAt(stage) {
  const paths = [];
  for (const directory of RESOURCE_DIRECTORIES) {
    for (const entry of await walkFiles(join(stage, ...directory.split('/')))) paths.push(directory + '/' + entry.path);
  }
  paths.push(...RESOURCE_FILES);
  const unique = [...new Set(paths)].sort();
  const resources = [];
  for (const path of unique) {
    const file = join(stage, ...path.split('/'));
    const info = await lstat(file);
    if (!info.isFile() || info.isSymbolicLink()) throw new Error(`package-error: invalid-resource:${path}`);
    const bytes = await readFile(file);
    resources.push({
      path,
      category: categoryFor(path),
      license: 'Apache-2.0',
      bytes: bytes.length,
      sha256: sha256(bytes)
    });
  }
  return resources;
}

const readme = `# KeyHelix release artifact

This artifact contains the complete local KeyHelix product:

- the compiled Go engine (\`dist/engine/keyhelix\`),
- the built React web application (\`web/\`),
- offline contracts, rules references and provider resources (\`contracts/\`, \`spec/\`, \`ops/\`),
- the matching source archive and build recipes,
- a CycloneDX SBOM, third-party notices and license texts,
- SHA-256 checksums and provenance.

Verify before use:

\`\`\`sh
sha256sum -c SHA256SUMS.txt
\`\`\`

Read \`docs/release/ARTIFACTS.md\` for layout, verification and limitations, and
\`docs/engineering/WEB_RUNBOOK.md\` for local and private-host operation. Provider
containers are not embedded; OpenBao and Keycloak are pulled by their pinned
digests and always own secret bytes. Runtime configuration belongs outside this
artifact and must stay private.
`;

export async function stageWeb({ root = repository, stage } = {}) {
  if (!stage) throw new Error('package-error: missing-stage');
  const destination = resolve(stage);
  await mkdir(destination, { recursive: true });
  if ((await readdir(destination)).length) throw new Error('package-error: stage-not-empty');
  await validateBuildInputs(root);

  await cp(join(root, 'dist', 'web'), join(destination, 'web'), { recursive: true, dereference: false, force: true, preserveTimestamps: false });
  await mkdir(join(destination, 'dist', 'engine'), { recursive: true });
  await cp(join(root, 'dist', 'engine', 'keyhelix'), join(destination, 'dist', 'engine', 'keyhelix'));
  await chmod(join(destination, 'dist', 'engine', 'keyhelix'), 0o755);

  for (const script of RUNTIME_SCRIPTS) await copyPath(root, destination, script);
  await copyPath(root, destination, 'apps/web/src/lib/runtime-config.mjs');
  for (const directory of RESOURCE_DIRECTORIES) await copyPath(root, destination, directory);
  for (const file of RESOURCE_FILES) await copyPath(root, destination, file);
  await copyPath(root, destination, 'LICENSE');
  await copyPath(root, destination, 'NOTICE');
  await writeFile(join(destination, 'README.md'), readme);

  await assertSafeTree(destination);
  await scanForSecrets(destination);

  const resources = await resourcesAt(destination);
  await writeFile(join(destination, 'RESOURCES.json'), JSON.stringify({
    schema_version: 1,
    project: 'KeyHelix',
    license: 'Apache-2.0',
    rules: 'authorization rules compile into the Go engine; offline contracts and the authorization matrix are included',
    resources
  }, null, 2) + '\n');

  for (const required of REQUIRED_STAGE_FILES) {
    try {
      const info = await stat(join(destination, ...required.split('/')));
      if (!info.isFile()) throw new Error();
    } catch {
      throw new Error(`package-error: missing-stage-file:${required}`);
    }
  }

  return {
    staged: destination,
    resources: resources.length,
    files: (await walkFiles(destination)).length
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    const args = process.argv.slice(2);
    let stage = null;
    let root = repository;
    for (let i = 0; i < args.length; i += 2) {
      if (args[i] === '--stage' && args[i + 1]) stage = args[i + 1];
      else if (args[i] === '--root' && args[i + 1]) root = resolve(args[i + 1]);
      else throw new Error('Usage: node scripts/package-web.mjs --stage <empty-directory> [--root <checkout>]');
    }
    if (!stage) throw new Error('Usage: node scripts/package-web.mjs --stage <empty-directory> [--root <checkout>]');
    console.log(JSON.stringify(await stageWeb({ root, stage }), null, 2));
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
