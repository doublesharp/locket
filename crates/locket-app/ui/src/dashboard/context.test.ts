import { describe, expect, it } from 'vitest';
import { scopedProjectContext, actionAvailability } from './context';
import type { DesktopProjectContext } from '../agent/types';
const selected: DesktopProjectContext = {
  root: '/fixture',
  project_id: 'project-real',
  project_name: 'Fixture',
  profile_id: 'profile-uuid-real',
  profile_name: 'development',
};
const status = { project_id: selected.project_id, profile_name: selected.profile_name };
describe('real scoped project identity', () => {
  it('returns the real ID rather than the environment name', () => {
    expect(scopedProjectContext(status, selected, true)?.profile_id).toBe('profile-uuid-real');
  });
  it('never invents an ID from global status, a name, mismatch or disconnect', () => {
    expect(scopedProjectContext(status, null, true)).toBeNull();
    expect(scopedProjectContext(status, { ...selected, profile_id: '' }, true)).toBeNull();
    expect(scopedProjectContext({ ...status, project_id: 'other' }, selected, true)).toBeNull();
    expect(scopedProjectContext(status, selected, false)).toBeNull();
  });
});
describe('native action availability and checked-empty meaning', () => {
  const ready = {
    projectSelected: true,
    connected: true,
    scoped: true,
    unlocked: true,
    loaded: true,
    loading: false,
    error: null,
  };
  it('enables actions only after a successful metadata load', () => {
    expect(actionAvailability(ready)).toEqual({ enabled: true, guidance: null });
    expect(actionAvailability({ ...ready, loaded: false }).enabled).toBe(false);
  });
  it.each([
    ['projectSelected', 'Connect'],
    ['connected', 'Start'],
    ['scoped', 'Reconnect'],
    ['unlocked', 'Unlock'],
  ] as const)('explains a missing %s prerequisite', (key, guidance) => {
    expect(actionAvailability({ ...ready, [key]: false }).guidance).toContain(guidance);
  });
  it('keeps absent, loading and failed metadata distinct from checked empty', () => {
    expect(actionAvailability({ ...ready, loaded: false }).guidance).toContain('Load');
    expect(actionAvailability({ ...ready, loading: true }).guidance).toContain('Loading');
    expect(actionAvailability({ ...ready, error: 'Request rejected' }).guidance).toContain(
      'Request rejected',
    );
  });
});
