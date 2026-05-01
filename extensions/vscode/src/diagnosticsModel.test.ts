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

test('flags process env bracket references missing from the active profile', () => {
  const plans = locketDiagnosticPlans('const url = process.env["DATABASE_URL"];', {
    activeSecrets: [],
    versions: [],
    nowUnixNanos: 1_000,
    languageId: 'typescript',
  });

  assert.equal(plans.length, 1);
  assert.equal(plans[0]?.code, 'locket.missingEnvSecret');
  assert.match(plans[0]?.message ?? '', /DATABASE_URL/);
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

test('flags Python os.environ index references missing from the active profile', () => {
  const plans = locketDiagnosticPlans('value = os.environ["DATABASE_URL"]', {
    activeSecrets: [],
    versions: [],
    nowUnixNanos: 1_000,
    languageId: 'python',
  });
  assert.equal(plans.length, 1);
  assert.equal(plans[0]?.code, 'locket.missingEnvSecret');
  assert.match(plans[0]?.message ?? '', /DATABASE_URL/);
});

test('flags Python os.environ.get and os.getenv references', () => {
  const text = 'a = os.environ.get("DATABASE_URL")\nb = os.getenv("API_KEY")\n';
  const plans = locketDiagnosticPlans(text, {
    activeSecrets: [],
    versions: [],
    nowUnixNanos: 1_000,
    languageId: 'python',
  });
  assert.equal(plans.length, 2);
  const names = plans.map((p) => p.message);
  assert.ok(names.some((m) => m.includes('DATABASE_URL')));
  assert.ok(names.some((m) => m.includes('API_KEY')));
});

test('does not flag Python references present in active metadata', () => {
  const plans = locketDiagnosticPlans('os.environ["DATABASE_URL"]', {
    activeSecrets: [{ name: 'DATABASE_URL' }],
    versions: [],
    nowUnixNanos: 1_000,
    languageId: 'python',
  });
  assert.deepEqual(plans, []);
});

test('flags Rust env::var references missing from the active profile', () => {
  const text = 'let url = env::var("DATABASE_URL")?;\nlet key = std::env::var("API_KEY")?;\n';
  const plans = locketDiagnosticPlans(text, {
    activeSecrets: [],
    versions: [],
    nowUnixNanos: 1_000,
    languageId: 'rust',
  });
  assert.equal(plans.length, 2);
});

test('flags Go os.Getenv references missing from the active profile', () => {
  const plans = locketDiagnosticPlans('url := os.Getenv("DATABASE_URL")', {
    activeSecrets: [],
    versions: [],
    nowUnixNanos: 1_000,
    languageId: 'go',
  });
  assert.equal(plans.length, 1);
  assert.match(plans[0]?.message ?? '', /DATABASE_URL/);
});

test('flags Swift ProcessInfo environment references missing from the active profile', () => {
  const plans = locketDiagnosticPlans('let url = ProcessInfo.processInfo.environment["DATABASE_URL"]', {
    activeSecrets: [],
    versions: [],
    nowUnixNanos: 1_000,
    languageId: 'swift',
  });
  assert.equal(plans.length, 1);
  assert.match(plans[0]?.message ?? '', /DATABASE_URL/);
});

test('flags shell ${KEY} and $KEY references missing from the active profile', () => {
  const text = 'echo ${DATABASE_URL}\necho $API_KEY\n';
  const plans = locketDiagnosticPlans(text, {
    activeSecrets: [],
    versions: [],
    nowUnixNanos: 1_000,
    languageId: 'shellscript',
  });
  assert.equal(plans.length, 2);
});

test('shell pattern does not flag positional params or single-letter vars', () => {
  const plans = locketDiagnosticPlans('echo $1 $@ $X', {
    activeSecrets: [],
    versions: [],
    nowUnixNanos: 1_000,
    languageId: 'shellscript',
  });
  assert.deepEqual(plans, []);
});

test('falls back to Node patterns when languageId is unknown', () => {
  const plans = locketDiagnosticPlans('process.env.API_KEY', {
    activeSecrets: [],
    versions: [],
    nowUnixNanos: 1_000,
    languageId: 'totally-not-a-real-language',
  });
  assert.equal(plans.length, 1);
});

test('python language does not flag JS-style process.env references', () => {
  const plans = locketDiagnosticPlans('value = process.env.API_KEY', {
    activeSecrets: [],
    versions: [],
    nowUnixNanos: 1_000,
    languageId: 'python',
  });
  assert.deepEqual(plans, []);
});
