// Tests for the profile-switcher pure model.

import { describe, expect, it } from 'vitest';

import {
  isValidProfileName,
  profileEntries,
  profileSwitchRequiresTypedConfirmation,
  rememberTarget,
  type ProfileSwitchState,
} from './switcher';

function state(overrides: Partial<ProfileSwitchState> = {}): ProfileSwitchState {
  return {
    activeProfile: 'dev',
    activeDangerous: false,
    recentTargets: [],
    ...overrides,
  };
}

describe('profileEntries', () => {
  it('puts the active profile first and marks dangerous accordingly', () => {
    const entries = profileEntries(state({ activeProfile: 'prod', activeDangerous: true }));
    expect(entries).toEqual([{ name: 'prod', dangerous: true }]);
  });

  it('appends recent targets, deduped against the active profile', () => {
    const entries = profileEntries(
      state({
        activeProfile: 'dev',
        recentTargets: ['stage', 'dev', 'prod'],
      }),
    );
    expect(entries.map((entry) => entry.name)).toEqual(['dev', 'stage', 'prod']);
    expect(entries.every((entry) => entry.dangerous === (entry.name === 'dev' ? false : false))).toBe(
      true,
    );
  });

  it('returns an empty list when no active profile and no targets', () => {
    expect(profileEntries(state({ activeProfile: null }))).toEqual([]);
  });
});

describe('profileSwitchRequiresTypedConfirmation', () => {
  it('requires typed confirmation when the target is dangerous', () => {
    expect(profileSwitchRequiresTypedConfirmation('prod', true)).toBe(true);
  });

  it('does not require confirmation for non-dangerous targets', () => {
    expect(profileSwitchRequiresTypedConfirmation('dev', false)).toBe(false);
  });

  it('skips the gate for an empty target', () => {
    expect(profileSwitchRequiresTypedConfirmation('', true)).toBe(false);
  });
});

describe('isValidProfileName', () => {
  it('accepts well-formed names', () => {
    expect(isValidProfileName('dev')).toBe(true);
    expect(isValidProfileName('prod-1')).toBe(true);
    expect(isValidProfileName('staging.us')).toBe(true);
  });

  it('rejects empty, oversized, or invalid names', () => {
    expect(isValidProfileName('')).toBe(false);
    expect(isValidProfileName('   ')).toBe(false);
    expect(isValidProfileName('bad name')).toBe(false);
    expect(isValidProfileName('a'.repeat(129))).toBe(false);
  });
});

describe('rememberTarget', () => {
  it('moves a fresh target to the head of the recent list', () => {
    const updated = rememberTarget(state({ recentTargets: ['dev', 'prod'] }), 'staging');
    expect(updated.recentTargets).toEqual(['staging', 'dev', 'prod']);
  });

  it('dedupes an existing target', () => {
    const updated = rememberTarget(state({ recentTargets: ['dev', 'prod'] }), 'dev');
    expect(updated.recentTargets).toEqual(['dev', 'prod']);
  });

  it('caps the list at 8 entries', () => {
    let acc = state({ recentTargets: [] });
    for (const name of ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i']) {
      acc = rememberTarget(acc, name);
    }
    expect(acc.recentTargets).toHaveLength(8);
    expect(acc.recentTargets[0]).toBe('i');
  });

  it('ignores blank input', () => {
    const updated = rememberTarget(state({ recentTargets: ['dev'] }), '   ');
    expect(updated.recentTargets).toEqual(['dev']);
  });
});
