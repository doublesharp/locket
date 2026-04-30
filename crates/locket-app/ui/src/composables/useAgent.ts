// Reactive agent state for Vue views. Polls `agent_status` on a fixed
// interval and exposes the latest typed result. Slice 3 will replace
// the polling fallback with a `SubscribeStatus` stream.

import { onScopeDispose, ref, type Ref } from 'vue';

import { fetchStatus } from '../agent/client';
import type { AgentClientError, AgentStatus } from '../agent/types';

export interface AgentState {
  status: Ref<AgentStatus | null>;
  error: Ref<AgentClientError | null>;
  loading: Ref<boolean>;
  refresh: () => Promise<void>;
}

const POLL_INTERVAL_MS = 5_000;

export function useAgent(): AgentState {
  const status = ref<AgentStatus | null>(null);
  const error = ref<AgentClientError | null>(null);
  const loading = ref<boolean>(true);

  let timer: ReturnType<typeof setInterval> | null = null;

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

  void refresh();
  timer = setInterval(() => {
    void refresh();
  }, POLL_INTERVAL_MS);

  onScopeDispose(() => {
    if (timer !== null) {
      clearInterval(timer);
      timer = null;
    }
  });

  return { status, error, loading, refresh };
}
