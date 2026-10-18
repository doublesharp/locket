import test from 'node:test';
import assert from 'node:assert/strict';
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
