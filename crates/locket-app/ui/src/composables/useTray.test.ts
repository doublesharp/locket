import { describe, expect, it } from 'vitest';

import { deriveTrayState } from './useTray';
import type { AgentStatus } from '../agent/types';

function status(overrides: Partial<AgentStatus> = {}): AgentStatus {
  return {
    lock_state: 'locked',
    project_id: null,
    profile_name: null,
    live_grant_count: 0,
    agent_version: '0.0.0-test',
    unlock_ttl_seconds: null,
    running_session_count: 0,
    scan_warning_count: 0,
    recent_audit_status: 'unknown',
    pinned_reference_warning_count: 0,
    ...overrides,
  };
}

describe('deriveTrayState', () => {
  it('returns scan-warning when unresolved scan warnings exist', () => {
    expect(deriveTrayState(status({ lock_state: 'unlocked', scan_warning_count: 2 }), null)).toBe(
      'scan-warning',
    );
  });

  it('keeps agent errors ahead of scan-warning status metadata', () => {
    expect(
      deriveTrayState(status({ scan_warning_count: 2 }), {
        kind: 'unavailable',
        reason: 'socket missing',
        display_reason: 'Agent unavailable',
        next_action: 'Start the agent.',
        socket_path: '/tmp/locket.sock',
      }),
    ).toBe('agent-stopped');
  });

  it('falls back to lock state when scan warnings are resolved', () => {
    expect(deriveTrayState(status({ lock_state: 'unlocked', scan_warning_count: 0 }), null)).toBe(
      'agent-unlocked',
    );
  });
});
