// Reactive agent state for Vue views. Subscribes to the agent's
// metadata-only `SubscribeStatus` stream and exposes the latest typed
// result. `refresh()` remains a one-shot fallback for explicit user
// actions.

import { onScopeDispose, ref, type Ref } from 'vue';

import { fetchStatus, subscribeStatus } from '../agent/client';
import type { AgentClientError, AgentStatus } from '../agent/types';

export interface AgentState {
  status: Ref<AgentStatus | null>;
  error: Ref<AgentClientError | null>;
  loading: Ref<boolean>;
  refresh: () => Promise<void>;
}

export function useAgent(): AgentState {
  const status = ref<AgentStatus | null>(null);
  const error = ref<AgentClientError | null>(null);
  const loading = ref<boolean>(true);

  let unlisten: (() => void) | null = null;

  async function refresh(): Promise<void> {
    loading.value = true;
    const result = await fetchStatus();
    if (result.ok) {
      status.value = result.status;
      error.value = null;
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
        status.value = {
          lock_state: event.lock_state,
          project_id: event.project_id,
          profile_name: event.profile_name,
          live_grant_count: event.live_grant_count,
          agent_version: event.agent_version,
          unlock_ttl_seconds: event.unlock_ttl_seconds,
        };
        error.value = null;
        loading.value = false;
      },
      (streamError) => {
        status.value = null;
        error.value = streamError;
        loading.value = false;
      },
    );
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
    unlisten?.();
    unlisten = null;
  });

  return { status, error, loading, refresh };
}
