import test from 'node:test';
import assert from 'node:assert/strict';

import { locketDiagnosticPlans } from './diagnosticsModel';

test('flags process env references missing from the active profile', () => {
  const plans = locketDiagnosticPlans('const url = process.env.DATABASE_URL;', {
    activeSecrets: [{ name: 'REDIS_URL' }],
    versions: [],
    nowUnixNanos: 1_000,
  });

  assert.equal(plans.length, 1);
  assert.equal(plans[0]?.code, 'locket.missingEnvSecret');
  assert.equal(plans[0]?.severity, 'warning');
  assert.equal(plans[0]?.startOffset, 12);
  assert.equal(plans[0]?.endOffset, 36);
});

test('does not flag process env references present in active metadata', () => {
  const plans = locketDiagnosticPlans('const url = process.env.DATABASE_URL;', {
    activeSecrets: [{ name: 'DATABASE_URL' }],
    versions: [],
    nowUnixNanos: 1_000,
  });

  assert.deepEqual(plans, []);
});

test('flags pinned references past grace expiry', () => {
  const plans = locketDiagnosticPlans('DATABASE_URL=lk://dev/DATABASE_URL@v2', {
    activeSecrets: [],
    versions: [
      {
        name: 'DATABASE_URL',
        version: 2,
        versionState: 'deprecated',
        graceUntil: 1_000,
        pinnedReferenceEligible: false,
      },
    ],
    nowUnixNanos: 2_000,
  });

  assert.equal(plans.length, 1);
  assert.equal(plans[0]?.code, 'locket.pinnedVersionExpired');
  assert.equal(plans[0]?.severity, 'error');
});

test('warns on pinned references near grace expiry', () => {
  const plans = locketDiagnosticPlans('DATABASE_URL=lk://dev/DATABASE_URL@v2', {
    activeSecrets: [],
    versions: [
      {
        name: 'DATABASE_URL',
        version: 2,
        versionState: 'deprecated',
        graceUntil: 1_500,
        pinnedReferenceEligible: true,
      },
    ],
    nowUnixNanos: 1_000,
    nearGraceWindowNanos: 1_000,
  });

  assert.equal(plans.length, 1);
  assert.equal(plans[0]?.code, 'locket.pinnedVersionExpiring');
  assert.equal(plans[0]?.severity, 'warning');
});

test('ignores unpinned lk references and unknown version metadata', () => {
  const plans = locketDiagnosticPlans('A=lk://dev/DATABASE_URL\nB=lk://dev/DATABASE_URL@v3', {
    activeSecrets: [],
    versions: [{ name: 'DATABASE_URL', version: 2, versionState: 'deprecated', pinnedReferenceEligible: false }],
    nowUnixNanos: 1_000,
  });

  assert.deepEqual(plans, []);
});
