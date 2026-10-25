import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, renameSync, rmSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { goEnvironment } from './oss-bootstrap.mjs';

export function buildEngine(root = fileURLToPath(new URL('../', import.meta.url))) {
  const output = resolve(root, 'dist/engine');
  mkdirSync(output, { recursive: true });
  const staging = mkdtempSync(join(output, '.build-'));
  try {
    const binary = join(staging, 'keyhelix');
    const result = spawnSync('go', ['build', '-trimpath', '-o', binary, './cmd/keyhelix'], {
      cwd: root,
      env: goEnvironment,
      stdio: 'inherit',
      timeout: 120000
    });
    if (result.error || result.status !== 0) {
      throw new Error('Engine build failed; previous binary preserved.');
    }
    renameSync(binary, join(output, 'keyhelix'));
  } finally {
    rmSync(staging, { recursive: true, force: true });
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    buildEngine();
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
