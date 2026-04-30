// Thin wrapper around the Tauri `agent_status` command. Exposes a
// promise-typed result so callers can branch on success vs typed error
// without juggling Tauri's invoke() exceptions.

import { invoke, isTauri } from '@tauri-apps/api/core';

import type { AgentClientError, AgentStatus } from './types';

export type AgentStatusResult =
  | { ok: true; status: AgentStatus }
  | { ok: false; error: AgentClientError };

/**
 * Issue a single `Status` request to the agent.
 *
 * Returns a typed `AgentClientError` for every failure mode — connection,
 * protocol, or agent-side rejection. Outside a Tauri webview (e.g. a
 * plain `vite preview` shell) returns an `unavailable` result so the UI
 * can render a sensible fallback banner instead of crashing.
 */
export async function fetchStatus(): Promise<AgentStatusResult> {
  if (!isTauri()) {
    return {
      ok: false,
      error: {
        kind: 'unavailable',
        reason: 'desktop shell not running inside a Tauri webview',
        socket_path: '',
      },
    };
  }
  try {
    const status = await invoke<AgentStatus>('agent_status');
    return { ok: true, status };
  } catch (raw) {
    return { ok: false, error: normalizeError(raw) };
  }
}

function normalizeError(raw: unknown): AgentClientError {
  if (raw && typeof raw === 'object' && 'kind' in raw) {
    return raw as AgentClientError;
  }
  return {
    kind: 'protocol',
    reason: typeof raw === 'string' ? raw : 'unknown agent error',
  };
}
