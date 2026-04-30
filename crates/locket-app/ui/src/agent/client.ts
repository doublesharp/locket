// Thin wrappers around the desktop's typed Tauri commands. Each exposes
// a promise-typed result so callers can branch on success vs typed error
// without juggling Tauri's invoke() exceptions.

import { invoke, isTauri } from '@tauri-apps/api/core';

import type {
  AgentClientError,
  AgentStatus,
  CopyRequest,
  CopyResponse,
  PrepareExecRequest,
  PrepareExecResponse,
  ResolveRequest,
  ResolveResponse,
  RevealRequest,
  RevealResponse,
  ScanRequest,
  ScanResponse,
} from './types';

export type AgentStatusResult =
  | { ok: true; status: AgentStatus }
  | { ok: false; error: AgentClientError };

export type AgentResult<T> = { ok: true; value: T } | { ok: false; error: AgentClientError };

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

async function callTyped<T>(
  command: string,
  args: Record<string, unknown>,
): Promise<AgentResult<T>> {
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
    const value = await invoke<T>(command, args);
    return { ok: true, value };
  } catch (raw) {
    return { ok: false, error: normalizeError(raw) };
  }
}

export async function reveal(request: RevealRequest): Promise<AgentResult<RevealResponse>> {
  return callTyped<RevealResponse>('agent_reveal', { request });
}

export async function copy(request: CopyRequest): Promise<AgentResult<CopyResponse>> {
  return callTyped<CopyResponse>('agent_copy', { request });
}

export async function scan(request: ScanRequest): Promise<AgentResult<ScanResponse>> {
  return callTyped<ScanResponse>('agent_scan', { request });
}

export async function resolveReference(
  request: ResolveRequest,
): Promise<AgentResult<ResolveResponse>> {
  return callTyped<ResolveResponse>('agent_resolve', { request });
}

export async function prepareExec(
  request: PrepareExecRequest,
): Promise<AgentResult<PrepareExecResponse>> {
  return callTyped<PrepareExecResponse>('agent_prepare_exec', { request });
}
