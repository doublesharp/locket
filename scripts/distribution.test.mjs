import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { validateVersions, bundleOverlay } from './distribution.mjs';

test('all shipped surfaces must match the workspace and release tag', () => {
  const versions = { rust: '0.1.0', desktop: '0.1.0', ui: '0.1.0', editor: '0.1.0' };
  assert.equal(validateVersions(versions, 'v0.1.0'), '0.1.0');
  assert.throws(() => validateVersions({ ...versions, editor: '0.0.0-dev' }), /editor/);
  assert.throws(() => validateVersions(versions, 'v0.2.0'), /tag/);
  assert.throws(() => validateVersions({ ...versions, rust: 'not-semver' }), /version/);
});

test('native bundle includes exactly the matching CLI and isolated frontend', () => {
  const overlay = bundleOverlay('/scratch/locket', '/scratch/ui');
  assert.deepEqual(overlay.bundle.resources, { '/scratch/locket': 'locket' });
  assert.equal(overlay.build.frontendDist, '/scratch/ui');
  assert.equal(overlay.build.beforeBuildCommand, '');
  assert.deepEqual(bundleOverlay('C:/scratch/locket.exe', 'C:/scratch/ui').bundle.resources,
    { 'C:/scratch/locket.exe': 'locket.exe' });
  assert.throws(() => bundleOverlay('/scratch/target', '/scratch/ui'), /CLI filename/);
});

test('Windows builds have a configured ICO resource with a complete PNG frame', () => {
  const root = new URL('../crates/locket-app/src-tauri/', import.meta.url);
  const config = JSON.parse(readFileSync(new URL('tauri.conf.json', root), 'utf8'));
  const icon = config.bundle.icon.find(path => path.endsWith('.ico'));
  assert.ok(icon, 'Windows requires a configured ICO icon');
  const bytes = readFileSync(new URL(icon, root));
  assert.equal(bytes.readUInt16LE(0), 0);
  assert.equal(bytes.readUInt16LE(2), 1);
  assert.ok(bytes.readUInt16LE(4) > 0);
  const length = bytes.readUInt32LE(14);
  const offset = bytes.readUInt32LE(18);
  assert.ok(offset >= 22 && offset + length <= bytes.length);
  assert.deepEqual(bytes.subarray(offset, offset + 8), Buffer.from([137,80,78,71,13,10,26,10]));
});
