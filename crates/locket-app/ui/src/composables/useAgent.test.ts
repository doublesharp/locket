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

async function settle(): Promise<void> {
  for (let index = 0; index < 12; index++) await Promise.resolve();
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
  vi.mocked(fetchStatus).mockResolvedValue({
    ok: true,
    status: { ...event('status'), project_id: 'selected', profile_name: 'development' },
  });
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

  it('treats global frames as invalidation and obtains native scoped identity', async () => {
    const { scope, state, onStatus } = setup();
    try {
      onStatus(event('status', 'unlocked'));
      await state.refresh();
      expect(fetchStatus).toHaveBeenCalled();
      expect(state.status.value).toMatchObject({
        project_id: 'selected',
        profile_name: 'development',
        lock_state: 'locked',
      });
      expect(state.connected.value).toBe(true);
    } finally {
      scope.stop();
    }
  });

  it('refreshes on every heartbeat so expired unlocks cannot remain unlocked', async () => {
    vi.mocked(fetchStatus).mockResolvedValueOnce({
      ok: true,
      status: {
        ...event('status', 'unlocked'),
        project_id: 'selected',
        profile_name: 'development',
      },
    });
    const { scope, state, options } = setup();
    try {
      await state.refresh();
      expect(state.status.value?.lock_state).toBe('unlocked');
      options.onHeartbeat?.(event('heartbeat', 'unlocked'));
      await state.refresh();
      expect(state.status.value?.lock_state).toBe('locked');
    } finally {
      scope.stop();
    }
  });

  it('serializes a burst into one pending refresh and one latest refresh', async () => {
    const pending = deferred<AgentStatusResult>();
    vi.mocked(fetchStatus).mockReturnValueOnce(pending.promise);
    const { scope, state, onStatus, options } = setup();
    try {
      const first = state.refresh();
      onStatus(event('status', 'unlocked'));
      options.onHeartbeat?.(event('heartbeat'));
      onStatus(event('status'));
      expect(fetchStatus).toHaveBeenCalledTimes(1);
      pending.resolve({
        ok: true,
        status: { ...event('status', 'unlocked'), project_id: 'old', profile_name: 'old' },
      });
      await first;
      expect(fetchStatus).toHaveBeenCalledTimes(2);
      expect(state.status.value?.project_id).toBe('selected');
    } finally {
      scope.stop();
    }
  });

  it('fails closed when native scoped status rejects and ignores late success after disconnect', async () => {
    const { scope, state, options } = setup();
    try {
      await state.refresh();
      vi.mocked(fetchStatus).mockResolvedValueOnce({
        ok: false,
        error: { kind: 'protocol', reason: 'Selected project unavailable' },
      });
      options.onHeartbeat?.(event('heartbeat'));
      await settle();
      expect(state.status.value).toBeNull();
      expect(state.connected.value).toBe(false);
      const pending = deferred<AgentStatusResult>();
      vi.mocked(fetchStatus).mockReturnValueOnce(pending.promise);
      const refresh = state.refresh();
      options.onDisconnected?.();
      pending.resolve({ ok: true, status: event('status', 'unlocked') });
      await refresh;
      expect(state.status.value).toBeNull();
      expect(state.connected.value).toBe(false);
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
