#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';

const semver = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
export function validateVersions(versions, tag = '') {
  const version = versions.rust;
  for (const [surface, value] of Object.entries(versions)) {
    if (!semver.test(value) || value !== version) throw new Error(`${surface} version ${value} does not match workspace version ${version}`);
  }
  if (tag && tag !== `v${version}`) throw new Error(`release tag ${tag} does not match v${version}`);
  return version;
}
export function readVersions(root) {
  const cargo = fs.readFileSync(path.join(root, 'Cargo.toml'), 'utf8');
  const rust = cargo.match(/\[workspace\.package\]([\s\S]*?)(?=\n\[|$)/)?.[1].match(/^version\s*=\s*"([^"]+)"/m)?.[1];
  const json = p => JSON.parse(fs.readFileSync(path.join(root, p), 'utf8'));
  return { rust, desktop: json('crates/locket-app/src-tauri/tauri.conf.json').version,
    ui: json('crates/locket-app/ui/package.json').version, editor: json('extensions/vscode/package.json').version };
}
export function bundleOverlay(cli, frontend) {
  const filename = cli.replaceAll('\\', '/').split('/').at(-1);
  if (!['locket', 'locket.exe'].includes(filename)) throw new Error('CLI filename must be locket or locket.exe');
  return { build: { frontendDist: frontend, beforeBuildCommand: '' }, bundle: { resources: { [cli]: filename } } };
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const [command = 'versions', ...args] = process.argv.slice(2);
    const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
    const version = validateVersions(readVersions(root), process.env.LOCKET_RELEASE_TAG || '');
    if (command === 'versions') console.log(version);
    else if (command === 'overlay') {
      const [cli, frontend, output] = args.map(p => path.resolve(p));
      const actual = execFileSync(cli, ['--version'], { encoding: 'utf8', timeout: 5000, maxBuffer: 8192 }).trim();
      if (actual !== `locket ${version}`) throw new Error(`bundled CLI version mismatch: expected locket ${version}`);
      fs.writeFileSync(output, `${JSON.stringify(bundleOverlay(cli, frontend), null, 2)}\n`, { mode: 0o600 });
    } else throw new Error(`unknown command: ${command}`);
  } catch (error) { console.error(error.message); process.exitCode = 1; }
}
