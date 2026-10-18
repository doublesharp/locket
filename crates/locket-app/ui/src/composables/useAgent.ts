// Reactive agent state for Vue views. Subscribes to the agent's
// metadata-only `SubscribeStatus` stream and exposes the latest typed
// result. `refresh()` remains a one-shot fallback for explicit user
// actions.
//
// The stream is global and has no selected project identity. Events and
// heartbeats invalidate cached state and request scoped native status.
// Refreshes serialize and coalesce bursts; rejected status fails closed.

import { onScopeDispose, ref, type Ref } from 'vue';

import { fetchStatus, subscribeStatus } from '../agent/client';
import type { AgentClientError, AgentStatus } from '../agent/types';

export interface AgentState {
  status: Ref<AgentStatus | null>;
  error: Ref<AgentClientError | null>;
  loading: Ref<boolean>;
  /** ISO timestamp of the last status or heartbeat frame from the agent. */
  lastSeenAt: Ref<string | null>;
  /** Whether the underlying socket is currently connected. */
  connected: Ref<boolean>;
  refresh: () => Promise<void>;
}

export function useAgent(): AgentState {
  const status = ref<AgentStatus | null>(null);
  const error = ref<AgentClientError | null>(null);
  const loading = ref<boolean>(true);
  const lastSeenAt = ref<string | null>(null);
  const connected = ref<boolean>(false);

  let unlisten: (() => void) | null = null;
  let disposed = false;
  let refreshGeneration = 0;
  let refreshPending = false;
  let refreshPromise: Promise<void> | null = null;

  function refresh(): Promise<void> {
    if (disposed) return Promise.resolve();
    ++refreshGeneration;
    refreshPending = true;
    if (refreshPromise !== null) return refreshPromise;
    refreshPromise = (async () => {
      while (refreshPending && !disposed) {
        refreshPending = false;
        const generation = refreshGeneration;
        loading.value = true;
        const result = await fetchStatus();
        if (disposed) return;
        if (generation !== refreshGeneration) continue;
        if (result.ok) {
          status.value = result.status;
          error.value = null;
          connected.value = true;
          lastSeenAt.value = new Date().toISOString();
        } else {
          status.value = null;
          error.value = result.error;
          connected.value = false;
        }
        loading.value = false;
      }
    })().finally(() => {
      refreshPromise = null;
    });
    return refreshPromise;
  }

  function invalidateStatus(): void {
    if (disposed) return;
    connected.value = true;
    lastSeenAt.value = new Date().toISOString();
    // Global subscription frames carry no project identity. Only the native
    // scoped Status request may replace this selected project's state.
    void refresh();
  }

  function disconnect(streamError?: AgentClientError): void {
    if (disposed) return;
    ++refreshGeneration;
    refreshPending = false;
    status.value = null;
    connected.value = false;
    loading.value = false;
    if (streamError) error.value = streamError;
  }

  async function startSubscription(): Promise<void> {
    loading.value = true;
    const result = await subscribeStatus(
      invalidateStatus,
      (streamError) => disconnect(streamError),
      {
        onHeartbeat: (event) => {
          if (event.kind === 'heartbeat') invalidateStatus();
        },
        onDisconnected: () => disconnect(),
      },
    );
    if (disposed) {
      if (result.ok) result.value();
      return;
    }
    if (result.ok) {
      unlisten = result.value;
    } else {
      status.value = null;
      error.value = result.error;
      loading.value = false;
    }
  }

  void startSubscription();

  onScopeDispose(() => {
    disposed = true;
    unlisten?.();
    unlisten = null;
  });

  return { status, error, loading, lastSeenAt, connected, refresh };
}
