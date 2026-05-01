// Tests for the desktop secret-list metadata filter helpers.
//
// Tests run under vitest. When the runner is not configured locally,
// the file is skipped at collection time. The assertions below are
// hand-verifiable for code review.

import { describe, expect, it } from 'vitest';

import type { SecretRowMeta } from '../types/views';
import {
  defaultSecretFilter,
  filterSecretRows,
  isSecretFilterActive,
} from './filter';

function row(overrides: Partial<SecretRowMeta>): SecretRowMeta {
  return {
    id: 'id-0',
    name: 'KEY',
    source: 'user-local',
    required: false,
    optional: true,
    createdAt: '2026-01-01T00:00:00Z',
    currentVersion: 1,
    hasDeprecatedGrace: false,
    ...overrides,
  };
}

describe('filterSecretRows', () => {
  const rows: SecretRowMeta[] = [
    row({ id: 't1', name: 'TEAM_KEY', source: 'team', required: true }),
    row({ id: 'u1', name: 'USER_KEY', source: 'user-local', required: false }),
    row({ id: 'm1', name: 'MACH_KEY', source: 'machine-local', hasDeprecatedGrace: true }),
  ];

  it('returns every row when filter is default', () => {
    expect(filterSecretRows(rows, defaultSecretFilter())).toHaveLength(3);
  });

  it('filters by source', () => {
    expect(
      filterSecretRows(rows, { ...defaultSecretFilter(), source: 'team' }),
    ).toEqual([rows[0]]);
  });

  it('filters by required vs optional', () => {
    expect(
      filterSecretRows(rows, { ...defaultSecretFilter(), required: 'required' }),
    ).toEqual([rows[0]]);
    expect(
      filterSecretRows(rows, { ...defaultSecretFilter(), required: 'optional' }),
    ).toEqual([rows[1], rows[2]]);
  });

  it('filters by deprecated grace', () => {
    expect(
      filterSecretRows(rows, { ...defaultSecretFilter(), deprecation: 'deprecated' }),
    ).toEqual([rows[2]]);
    expect(
      filterSecretRows(rows, { ...defaultSecretFilter(), deprecation: 'current' }),
    ).toEqual([rows[0], rows[1]]);
  });

  it('combines independent filters', () => {
    expect(
      filterSecretRows(rows, {
        source: 'team',
        required: 'required',
        deprecation: 'current',
      }),
    ).toEqual([rows[0]]);
  });
});

describe('isSecretFilterActive', () => {
  it('reports false on the default filter', () => {
    expect(isSecretFilterActive(defaultSecretFilter())).toBe(false);
  });

  it('reports true when any filter is non-default', () => {
    expect(
      isSecretFilterActive({ ...defaultSecretFilter(), source: 'team' }),
    ).toBe(true);
    expect(
      isSecretFilterActive({ ...defaultSecretFilter(), required: 'required' }),
    ).toBe(true);
    expect(
      isSecretFilterActive({ ...defaultSecretFilter(), deprecation: 'deprecated' }),
    ).toBe(true);
  });
});
