import { describe, expect, it } from 'vitest';
import {
  readinessSummary,
  readinessDisplay,
  readinessBlocksRun,
  readinessPolicyDisplay,
} from './readiness';

const rows = [
  {
    name: 'DATABASE_URL',
    required: true,
    classification: 'secret' as const,
    state: 'missing' as const,
    selected_source: null,
    description: 'API database',
    setup_hint: 'Ask a teammate',
    next_action: 'locket set DATABASE_URL',
    warning: null,
  },
  {
    name: 'PORT',
    required: true,
    classification: 'public' as const,
    state: 'ready' as const,
    selected_source: 'public-default',
    description: null,
    setup_hint: null,
    next_action: null,
    warning: null,
  },
  {
    name: 'NEXT_PUBLIC_TOKEN',
    required: false,
    classification: 'secret' as const,
    state: 'unverified' as const,
    selected_source: null,
    description: null,
    setup_hint: null,
    next_action: null,
    warning: 'NEXT_PUBLIC_TOKEN may be exposed in browser bundles.',
  },
];

describe('configuration readiness presentation', () => {
  it('separates missing requirements from deferred checks', () => {
    expect(readinessSummary(rows)).toEqual({
      required: 2,
      available: 1,
      missing: 1,
      unverified: 1,
      warnings: 1,
      label: '1 required variable missing',
    });
    expect(readinessSummary([rows[1]!]).label).toBe('Required names available');
    expect(readinessSummary([]).label).toBe('No variables requested');
  });
  it('shows setup and source guidance without adding a value field', () => {
    expect(readinessDisplay(rows[0]!, false)).toMatchObject({
      name: 'DATABASE_URL',
      guidance: ['API database', 'Ask a teammate', 'locket set DATABASE_URL'],
    });
    expect(readinessDisplay(rows[1]!, false).source).toBe('Public default');
  });
  it('hides names and author descriptions in privacy mode, including warning names', () => {
    const text = JSON.stringify(rows.map((row) => readinessDisplay(row, true)));
    for (const name of ['DATABASE_URL', 'NEXT_PUBLIC_TOKEN', 'API database', 'Ask a teammate'])
      expect(text).not.toContain(name);
    expect(text).toContain('browser');
  });
});

describe('partial command readiness failures', () => {
  it('does not call a failed check ready or an empty configuration', () => {
    expect(readinessSummary([], 1).label).toBe('1 command could not be checked');
    expect(readinessSummary([rows[1]!], 2).label).toBe('2 commands could not be checked');
  });
});

it('blocks only the selected denied command while preserving usable commands', () => {
  const policies = [
    { policy_name: 'allowed', profile_id: 'real-id', rows: [rows[1]!] },
    { policy_name: 'denied', profile_id: 'real-id', rows: [], error: 'Access denied' },
  ];
  expect(readinessBlocksRun(policies, 'denied')).toBe(true);
  expect(readinessBlocksRun(policies, 'allowed')).toBe(false);
  expect(readinessBlocksRun(policies)).toBe(false);
  expect(readinessBlocksRun([{ ...policies[0]!, rows: [rows[0]!] }], 'allowed')).toBe(true);
});

it('redacts policy error metadata in privacy mode and hides untrusted rows after failure', () => {
  const failed = {
    policy_name: 'private-command',
    profile_id: 'real-id',
    rows: [rows[0]!],
    error: 'private-command: DATABASE_URL canary-metadata',
  };
  const shown = readinessPolicyDisplay(failed, true, 0);
  expect(shown.name).toBe('Command 1');
  expect(shown.rows).toEqual([]);
  expect(shown.error).toBe('Configuration check unavailable for this command.');
  expect(JSON.stringify(shown)).not.toMatch(/DATABASE_URL|private-command|canary-metadata/);
  expect(readinessPolicyDisplay(failed, false, 0).error).toBe(failed.error);
});
