import test from 'node:test';
import assert from 'node:assert/strict';

import { locateReferenceFragment, referenceCompletionPlans } from './referenceCompletionModel';

test('locates lk reference fragments at completion position', () => {
  const fragment = locateReferenceFragment('DATABASE_URL="lk://dev/DATABASE_URL?source=');

  assert.deepEqual(fragment, {
    text: 'lk://dev/DATABASE_URL?source=',
    startOffset: 14,
  });
});

test('ignores non-reference words that end in lk', () => {
  assert.equal(locateReferenceFragment('const value = "walk'), undefined);
});

test('plans reference snippet with active profile metadata', () => {
  const plans = referenceCompletionPlans('lk', 'dev');

  assert.equal(plans[0]?.label, 'lk://dev/KEY');
  assert.equal(plans[0]?.insertText, 'lk://dev/${1:KEY}');
});

test('plans version and source completions after profile and key are present', () => {
  const plans = referenceCompletionPlans('lk://dev/DATABASE_URL', 'dev');

  assert.deepEqual(
    plans.map((plan) => plan.label),
    [
      'lk://dev/KEY',
      'lk://dev/DATABASE_URL@v1',
      'lk://dev/DATABASE_URL?source=user-local',
      'lk://dev/DATABASE_URL?source=machine-local',
      'lk://dev/DATABASE_URL?source=team-managed',
    ],
  );
});

test('falls back to placeholder profile when agent status is unavailable', () => {
  const plans = referenceCompletionPlans('lk', null);

  assert.equal(plans[0]?.label, 'lk://profile/KEY');
});
