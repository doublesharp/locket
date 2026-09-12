// Reactive agent state for Vue views. Subscribes to the agent's
// metadata-only `SubscribeStatus` stream and exposes the latest typed
// result. `refresh()` remains a one-shot fallback for explicit user
// actions.
//
// Heartbeats from the stream do not bump `status` (they would re-render
// every consumer for no useful reason). Instead they advance
// `lastSeenAt`, which the connection-health badge in the shell renders
// without touching any other reactive surface.

import { onScopeDispose, ref, type Ref } from 'vue';

import { fetchStatus, subscribeStatus } from '../agent/client';
import type { AgentClientError, AgentStatus, AgentStatusEvent } from '../agent/types';

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

function statusFromEvent(event: AgentStatusEvent): AgentStatus {
  return {
    lock_state: event.lock_state,
    project_id: event.project_id,
    profile_name: event.profile_name,
    live_grant_count: event.live_grant_count,
    agent_version: event.agent_version,
    unlock_ttl_seconds: event.unlock_ttl_seconds,
    running_session_count: event.running_session_count,
    scan_warning_count: event.scan_warning_count,
    recent_audit_status: event.recent_audit_status,
    pinned_reference_warning_count: event.pinned_reference_warning_count,
  };
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

  function applyStatus(event: AgentStatusEvent): void {
    ++refreshGeneration;
    status.value = statusFromEvent(event);
    error.value = null;
    loading.value = false;
  }

  async function refresh(): Promise<void> {
    if (disposed) return;
    const generation = ++refreshGeneration;
    loading.value = true;
    const result = await fetchStatus();
    if (disposed || generation !== refreshGeneration) return;
    if (result.ok) {
      status.value = result.status;
      error.value = null;
      lastSeenAt.value = new Date().toISOString();
    } else {
      status.value = null;
      error.value = result.error;
    }
    loading.value = false;
  }

  async function startSubscription(): Promise<void> {
    loading.value = true;
    const result = await subscribeStatus(
      (event) => {
        if (disposed) return;
        // Push-based state-change frames replace the previous polling
        // path; heartbeats are filtered out by `subscribeStatus`.
        applyStatus(event);
        lastSeenAt.value = new Date().toISOString();
        connected.value = true;
      },
      (streamError) => {
        if (disposed) return;
        ++refreshGeneration;
        error.value = streamError;
        connected.value = false;
        loading.value = false;
      },
      {
        onHeartbeat: (event) => {
          if (disposed) return;
          // An existing backend stream may send only heartbeats after remount.
          if (status.value === null) applyStatus(event);
          // Heartbeats only refresh the connection-health timestamp;
          // they must never trigger a status re-render.
          lastSeenAt.value = new Date().toISOString();
          connected.value = true;
        },
        onDisconnected: () => {
          if (disposed) return;
          // The Tauri side reconnects with exponential backoff; mark
          // the connection stale so the badge can show "reconnecting".
          connected.value = false;
        },
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
