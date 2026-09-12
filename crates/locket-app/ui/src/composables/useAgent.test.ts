import { effectScope } from 'vue';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { fetchStatus, subscribeStatus, type AgentStatusResult } from '../agent/client';
import type { AgentStatusEvent } from '../agent/types';
import { useAgent } from './useAgent';

vi.mock('../agent/client', () => ({ fetchStatus: vi.fn(), subscribeStatus: vi.fn() }));

function event(
  kind: 'status' | 'heartbeat',
  lockState: 'locked' | 'unlocked' = 'locked',
): AgentStatusEvent {
  return {
    kind,
    sequence: 1,
    lock_state: lockState,
    project_id: null,
    profile_name: null,
    live_grant_count: 0,
    agent_version: 'test',
    unlock_ttl_seconds: null,
    running_session_count: 0,
    scan_warning_count: 0,
    recent_audit_status: 'unknown',
    pinned_reference_warning_count: 0,
  };
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

function setup() {
  const scope = effectScope();
  const state = scope.run(useAgent)!;
  const [onStatus, onError, options] = vi.mocked(subscribeStatus).mock.calls[0]!;
  return { scope, state, onStatus, onError, options: options! };
}

beforeEach(() => {
  vi.resetAllMocks();
  vi.mocked(subscribeStatus).mockResolvedValue({ ok: true, value: vi.fn() });
});

describe('useAgent lifecycle', () => {
  it('cleans up a subscription that completes after scope disposal', async () => {
    const pending = deferred<Awaited<ReturnType<typeof subscribeStatus>>>();
    const unlisten = vi.fn();
    vi.mocked(subscribeStatus).mockReturnValue(pending.promise);
    const { scope, state, onStatus, options } = setup();
    scope.stop();
    pending.resolve({ ok: true, value: unlisten });
    await pending.promise;
    expect(unlisten).toHaveBeenCalledTimes(1);
    onStatus(event('status'));
    options.onHeartbeat?.(event('heartbeat'));
    expect(state.status.value).toBeNull();
    expect(state.connected.value).toBe(false);
  });

  it('cleans up an established subscription exactly once', async () => {
    const unlisten = vi.fn();
    vi.mocked(subscribeStatus).mockResolvedValue({ ok: true, value: unlisten });
    const { scope } = setup();
    await Promise.resolve();
    scope.stop();
    scope.stop();
    expect(unlisten).toHaveBeenCalledTimes(1);
  });

  it('initializes from a heartbeat after remount without rerendering subsequent heartbeats', () => {
    const { scope, state, options } = setup();
    try {
      options.onHeartbeat?.(event('heartbeat'));
      expect(state.status.value?.lock_state).toBe('locked');
      expect(state.loading.value).toBe(false);
      expect(state.connected.value).toBe(true);
      const initial = state.status.value;
      options.onHeartbeat?.(event('heartbeat'));
      expect(state.status.value).toBe(initial);
    } finally {
      scope.stop();
    }
  });

  it('does not let a pending refresh overwrite a newer locked status', async () => {
    const pending = deferred<AgentStatusResult>();
    vi.mocked(fetchStatus).mockReturnValue(pending.promise);
    const { scope, state, onStatus } = setup();
    try {
      const refresh = state.refresh();
      onStatus(event('status', 'locked'));
      pending.resolve({ ok: true, status: event('status', 'unlocked') });
      await refresh;
      expect(state.status.value?.lock_state).toBe('locked');
      expect(state.loading.value).toBe(false);
    } finally {
      scope.stop();
    }
  });

  it('keeps the most recent refresh when requests complete out of order', async () => {
    const older = deferred<AgentStatusResult>();
    const newer = deferred<AgentStatusResult>();
    vi.mocked(fetchStatus).mockReturnValueOnce(older.promise).mockReturnValueOnce(newer.promise);
    const { scope, state } = setup();
    try {
      const first = state.refresh();
      const second = state.refresh();
      newer.resolve({ ok: true, status: event('status', 'locked') });
      await second;
      older.resolve({ ok: true, status: event('status', 'unlocked') });
      await first;
      expect(state.status.value?.lock_state).toBe('locked');
    } finally {
      scope.stop();
    }
  });

  it('ignores refresh completion and stream errors after disposal', async () => {
    const pending = deferred<AgentStatusResult>();
    vi.mocked(fetchStatus).mockReturnValue(pending.promise);
    const { scope, state, onError } = setup();
    const refresh = state.refresh();
    scope.stop();
    pending.resolve({ ok: true, status: event('status') });
    await refresh;
    onError({ kind: 'protocol', reason: 'late error' });
    expect(state.status.value).toBeNull();
    expect(state.error.value).toBeNull();
  });
});
