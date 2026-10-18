import { describe, expect, it } from 'vitest';
import {
  auditHealth,
  scanHealth,
  auditRowVerified,
  unlockTtl,
  projectStatusMatches,
} from './health';
describe('truthful health', () => {
  it.each([null, undefined])('never verifies unknown audit state %s', (state) => {
    expect(auditHealth(state).label).toBe('Not verified');
    expect(auditHealth(state).tone).not.toBe('ok');
  });
  it('requires explicit audit success', () => {
    expect(auditHealth(true).label).toBe('Verified');
    expect(auditHealth(false).label).toBe('Verification failed');
    expect(auditRowVerified({ hmac_ok: null, first_break_sequence: null }, 1)).toBeNull();
    expect(auditRowVerified({ hmac_ok: false, first_break_sequence: null }, 1)).toBe(false);
    expect(auditRowVerified({ hmac_ok: false, first_break_sequence: 3 }, 2)).toBe(true);
  });
  it('requires a completed unlocked scan', () => {
    expect(scanHealth(undefined, false, null, 0).label).toBe('Not checked');
    expect(scanHealth('today', true, null, 0).label).toBe('Limited scan');
    expect(scanHealth('today', false, 'Failed', 0).label).toBe('Scan failed');
    expect(scanHealth('today', false, null, 0).label).toBe('No findings');
  });
  it('defaults to fifteen minutes unless a safe TTL is set', () => {
    expect(unlockTtl(0)).toBe(900);
    expect(unlockTtl(1.5)).toBe(900);
    expect(unlockTtl(28801)).toBe(900);
    expect(unlockTtl(1200)).toBe(1200);
  });
});

it('does not reuse another project or environment unlock status', () => {
  expect(
    projectStatusMatches(
      { project_id: 'other', profile_name: 'dev' },
      { project_id: 'selected', profile_name: 'dev' },
    ),
  ).toBe(false);
  expect(
    projectStatusMatches(
      { project_id: 'selected', profile_name: 'production' },
      { project_id: 'selected', profile_name: 'dev' },
    ),
  ).toBe(false);
  expect(
    projectStatusMatches(
      { project_id: 'selected', profile_name: 'dev' },
      { project_id: 'selected', profile_name: 'dev' },
    ),
  ).toBe(true);
});

it('rejects a retained status after its connection closes', () => {
  expect(
    projectStatusMatches(
      { project_id: 'selected', profile_name: 'dev' },
      { project_id: 'selected', profile_name: 'dev' },
      false,
    ),
  ).toBe(false);
});

it('rejects global status without an explicitly selected real project', () => {
  expect(projectStatusMatches({ project_id: 'global', profile_name: 'dev' }, null)).toBe(false);
});
