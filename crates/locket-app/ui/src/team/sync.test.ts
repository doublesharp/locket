import { describe, expect, it } from 'vitest';
import { joinCommand, syncMessage } from './sync';
describe('authenticated team sharing guidance', () => {
  it('requires an independent full pin and safely quotes folder paths', () => {
    expect(joinCommand('/team', 'short')).toBeNull();
    expect(joinCommand("/team's folder", 'a'.repeat(64))).toBe(
      `locket team join --folder '/team'"'"'s folder' --owner '${'a'.repeat(64)}'`,
    );
  });
  it('counts held profiles separately from conflicting values', () => {
    const message = syncMessage({
      state: 'pending-values',
      conflicts: 1,
      waiting: 0,
      pending_profiles: { prod: 'consent-required', preview: 'profile-name-collision' },
    });
    expect(message).toContain('2 profiles need');
    expect(message).toContain('1 value needs');
    expect(message).toContain('membership and key changes still apply');
    expect(
      syncMessage({
        state: 'pending-values',
        conflicts: 0,
        waiting: 0,
        pending_profiles: { prod: 'consent-required' },
      }),
    ).toContain('1 profile needs');
    expect(
      syncMessage({
        state: 'locked',
        conflicts: 1,
        waiting: 0,
        pending_profiles: { prod: 'consent-required' },
      }),
    ).toContain('Unlock');
  });
  it('never claims global freshness and makes blocked states actionable', () => {
    expect(syncMessage({ state: 'fork', conflicts: 0, waiting: 0 })).toContain('Stopped');
    expect(syncMessage({ state: 'locked', conflicts: 0, waiting: 2 })).toContain('Unlock');
    expect(syncMessage({ state: 'active', conflicts: 2, waiting: 0 })).toContain('2 values');
    expect(syncMessage({ state: 'active', conflicts: 0, waiting: 0 })).toContain('last verified');
  });
});
