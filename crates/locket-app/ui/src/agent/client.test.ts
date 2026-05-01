// Unit tests for the SubscribeStatus event dispatcher.
//
// Tests run under vitest (or any compatible runner that resolves
// `vitest`). When the runner is not configured locally, the file is
// skipped at collection time, but the assertions below are
// hand-verifiable for code review.
//
// These tests pin the heartbeat-filter contract: heartbeats must reach
// `onHeartbeat` (so the connection-health badge can advance its "last
// seen" timestamp) but must not reach `onStatus` (so the rest of the UI
// does not re-render on idle keepalives).

import { describe, expect, it, vi } from 'vitest';

import { handleStatusEvent } from './client';
import type { AgentStatusEvent } from './types';

function makeEvent(kind: 'status' | 'heartbeat', sequence: number): AgentStatusEvent {
  return {
    kind,
    sequence,
    lock_state: 'locked',
    project_id: null,
    profile_name: null,
    live_grant_count: 0,
    agent_version: '0.0.0-test',
    unlock_ttl_seconds: null,
  };
}

describe('handleStatusEvent', () => {
  it('routes status frames to onStatus and onHeartbeat', () => {
    const onStatus = vi.fn();
    const onHeartbeat = vi.fn();
    const event = makeEvent('status', 1);
    handleStatusEvent(event, onStatus, onHeartbeat);
    expect(onStatus).toHaveBeenCalledTimes(1);
    expect(onStatus).toHaveBeenCalledWith(event);
    expect(onHeartbeat).toHaveBeenCalledTimes(1);
    expect(onHeartbeat).toHaveBeenCalledWith(event);
  });

  it('routes heartbeats to onHeartbeat only', () => {
    const onStatus = vi.fn();
    const onHeartbeat = vi.fn();
    const event = makeEvent('heartbeat', 2);
    handleStatusEvent(event, onStatus, onHeartbeat);
    expect(onStatus).not.toHaveBeenCalled();
    expect(onHeartbeat).toHaveBeenCalledTimes(1);
    expect(onHeartbeat).toHaveBeenCalledWith(event);
  });

  it('still calls onStatus for status frames when onHeartbeat is omitted', () => {
    const onStatus = vi.fn();
    const event = makeEvent('status', 3);
    handleStatusEvent(event, onStatus);
    expect(onStatus).toHaveBeenCalledTimes(1);
    expect(onStatus).toHaveBeenCalledWith(event);
  });

  it('drops heartbeats silently when onHeartbeat is omitted', () => {
    const onStatus = vi.fn();
    const event = makeEvent('heartbeat', 4);
    handleStatusEvent(event, onStatus);
    expect(onStatus).not.toHaveBeenCalled();
  });

  it('only fires onStatus for non-heartbeat events across a mixed stream', () => {
    const onStatus = vi.fn();
    const onHeartbeat = vi.fn();
    const stream: AgentStatusEvent[] = [
      makeEvent('status', 1),
      makeEvent('heartbeat', 2),
      makeEvent('heartbeat', 3),
      makeEvent('status', 4),
    ];
    for (const event of stream) {
      handleStatusEvent(event, onStatus, onHeartbeat);
    }
    expect(onStatus).toHaveBeenCalledTimes(2);
    expect(onHeartbeat).toHaveBeenCalledTimes(4);
    expect(onStatus.mock.calls.map((call) => (call[0] as AgentStatusEvent).sequence)).toEqual([
      1, 4,
    ]);
  });
});
