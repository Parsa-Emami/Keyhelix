import { spawnSync } from 'node:child_process';
import { readFile, access } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';
import { readFileSync } from 'node:fs';

const root = fileURLToPath(new URL('../', import.meta.url));
const lock = JSON.parse(readFileSync(new URL('../docs/engineering/toolchain-lock.json', import.meta.url)));
const goVersion = lock.resources.find(resource => resource.id === 'go-toolchain').version;
const podmanVersion = lock.resources.find(resource => resource.id === 'podman-provider').version;

export const goEnvironment = {
  ...process.env,
  GOTOOLCHAIN: `go${goVersion}`,
  GOSUMDB: 'sum.golang.org',
  GOPROXY: 'https://proxy.golang.org|direct'
};

export function prerequisites(run = spawnSync) {
  const go = run('go', ['version'], { cwd: root, encoding: 'utf8', timeout: 120000, env: goEnvironment });
  if (go.error || go.status !== 0 || !go.stdout?.trim().startsWith(`go version go`)) {
    throw new Error(`Go prerequisite failed; install Go and run npm run setup.`);
  }
  const podman = run('podman', ['--version'], { encoding: 'utf8', timeout: 10000 });
  if (podman.error || podman.status !== 0 || podman.stdout?.trim() !== `podman version ${podmanVersion}`) {
    throw new Error(`Podman ${podmanVersion} prerequisite failed.`);
  }
  const provider = run('podman', ['info', '--format', '{{.Host.Security.Rootless}}'], { encoding: 'utf8', timeout: 10000 });
  if (provider.error || provider.status !== 0 || provider.stdout?.trim() !== 'true') {
    throw new Error('Rootless Podman prerequisite failed.');
  }
  return { go: go.stdout.trim(), podman: podman.stdout.trim(), rootless: true };
}

export const supportedNode = version => {
  const [major, minor] = version.replace(/^v/, '').split('.').map(Number);
  return major === 24 && minor >= 19;
};

export function setup(args = [], run = spawnSync, version = process.version) {
  if (!supportedNode(version)) throw new Error('Use Node 24.19 or a newer Node 24 release.');
  if (args.some(arg => !['--check', '--skip-install'].includes(arg))) {
    throw new Error('Supported setup options: --check, --skip-install');
  }
  const steps = args.includes('--skip-install')
    ? [['run', 'build']]
    : [['ci', '--ignore-scripts', '--no-fund'], ['run', 'build']];
  if (!args.includes('--check')) {
    prerequisites(run);
    for (const step of steps) {
      if (!process.env.npm_execpath) throw new Error('Run this command through npm run setup.');
      const result = run(process.execPath, [process.env.npm_execpath, ...step], { cwd: root, stdio: 'inherit' });
      if (result.error || result.status !== 0) throw new Error('Setup failed at npm ' + step.join(' '));
    }
  }
  return {
    executed: !args.includes('--check'),
    prerequisites: [`Go ${goVersion}`, `rootless Podman ${podmanVersion}`],
    steps,
    capability: 'local-runtime',
    engineReady: false
  };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    if (process.argv[2] === 'doctor') {
      let built = false;
      try {
        await access(new URL('../dist/web/index.html', import.meta.url));
        built = true;
      } catch {}
      const tools = prerequisites(spawnSync);
      const engine = spawnSync(resolve(root, 'dist/engine/keyhelix'), ['--version'], { encoding: 'utf8', timeout: 2000 });
      const { validateHealth } = await import('../apps/web/src/lib/runtime-config.mjs');
      if (engine.error || engine.status !== 0) throw new Error('Engine binary unavailable. Run npm run setup.');
      const runtime = validateHealth(JSON.parse(engine.stdout));
      const state = JSON.parse(await readFile(new URL('../plans/project-state.json', import.meta.url), 'utf8'));
      console.log(JSON.stringify({
        nodeSupported: supportedNode(process.version),
        webAssetsBuilt: built,
        tools,
        runtime,
        readiness: state.readiness,
        engineReady: state.core_ready,
        start: 'npm start',
        next: 'npm run plan -- next'
      }, null, 2));
      if (!built || !supportedNode(process.version)) process.exitCode = 1;
    } else {
      console.log(JSON.stringify({
        ...setup(process.argv.slice(3)),
        start: 'npm start',
        note: 'Full product usability requires the C30 workflow; complete OSS v1 requires C40.'
      }, null, 2));
    }
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
