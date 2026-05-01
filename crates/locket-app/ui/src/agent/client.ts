// Thin wrappers around the desktop's typed Tauri commands. Each exposes
// a promise-typed result so callers can branch on success vs typed error
// without juggling Tauri's invoke() exceptions.

import { invoke, isTauri } from '@tauri-apps/api/core';
import { listen, type UnlistenFn } from '@tauri-apps/api/event';

import type {
  AgentClientError,
  AgentConfigSettings,
  AgentStatus,
  AgentStatusEvent,
  BackupActionResponse,
  CopyRequest,
  CopyResponse,
  ExportBundleRequest,
  ImportBundleRequest,
  ListDeviceMembersRequest,
  ListDeviceMembersResponse,
  ListAuditRequest,
  ListAuditResponse,
  ListPoliciesRequest,
  ListPoliciesResponse,
  ListVersionsRequest,
  ListVersionsResponse,
  ListRuntimeSessionsRequest,
  ListRuntimeSessionsResponse,
  ListSecretsRequest,
  ListSecretsResponse,
  PolicyDoctorRequest,
  PolicyDoctorResponse,
  PrepareExecRequest,
  PrepareExecResponse,
  ReadConfigRequest,
  RecoveryRotateRequest,
  RegisterCommandPoliciesRequest,
  ResolveRequest,
  ResolveResponse,
  SetActiveProfileRequest,
  SetActiveProfileResponse,
  RevealRequest,
  RevealResponse,
  ScanRequest,
  ScanResponse,
  WriteConfigRequest,
  WriteConfigResponse,
  VerifyAuditRequest,
  VerifyAuditResponse,
  VerifyBundleRequest,
  VerifyBundleResponse,
} from './types';

export type AgentStatusResult =
  | { ok: true; status: AgentStatus }
  | { ok: false; error: AgentClientError };

export type AgentResult<T> = { ok: true; value: T } | { ok: false; error: AgentClientError };

const AGENT_STATUS_EVENT = 'agent-status';
const AGENT_STATUS_ERROR_EVENT = 'agent-status-error';
const AGENT_STATUS_DISCONNECTED_EVENT = 'agent-status-disconnected';

function tauriUnavailableError(): AgentClientError {
  return {
    kind: 'unavailable',
    reason: 'desktop shell not running inside a Tauri webview',
    display_reason: 'The local agent is unavailable.',
    next_action: 'Run locket agent start, then retry.',
    socket_path: '',
  };
}

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
      error: tauriUnavailableError(),
    };
  }
  try {
    const status = await invoke<AgentStatus>('agent_status');
    return { ok: true, status };
  } catch (raw) {
    return { ok: false, error: normalizeError(raw) };
  }
}

/**
 * Optional handlers passed to {@link subscribeStatus}.
 *
 * - `onStatus`: receives only `kind === 'status'` events. Heartbeats
 *   are filtered out so callers do not re-render on idle keepalives.
 * - `onHeartbeat`: receives every event (status or heartbeat). Used by
 *   the connection-health badge to update the "last seen" timestamp
 *   without spamming the rest of the UI.
 * - `onDisconnected`: fires once whenever the underlying socket closes.
 *   The Tauri loop reconnects automatically so callers should treat
 *   this as a hint to mark the connection as stale.
 */
export interface SubscribeStatusOptions {
  onHeartbeat?: (event: AgentStatusEvent) => void;
  onDisconnected?: () => void;
}

export async function subscribeStatus(
  onStatus: (event: AgentStatusEvent) => void,
  onError: (error: AgentClientError) => void,
  options: SubscribeStatusOptions = {},
): Promise<AgentResult<UnlistenFn>> {
  if (!isTauri()) {
    return {
      ok: false,
      error: tauriUnavailableError(),
    };
  }

  const unlistenStatus = await listen<AgentStatusEvent>(AGENT_STATUS_EVENT, (event) => {
    handleStatusEvent(event.payload, onStatus, options.onHeartbeat);
  });
  const unlistenError = await listen<AgentClientError>(AGENT_STATUS_ERROR_EVENT, (event) => {
    onError(event.payload);
  });
  const unlistenDisconnected = await listen<unknown>(AGENT_STATUS_DISCONNECTED_EVENT, () => {
    options.onDisconnected?.();
  });

  try {
    await invoke<void>('agent_subscribe_status');
  } catch (raw) {
    unlistenStatus();
    unlistenError();
    unlistenDisconnected();
    return { ok: false, error: normalizeError(raw) };
  }

  return {
    ok: true,
    value: () => {
      unlistenStatus();
      unlistenError();
      unlistenDisconnected();
    },
  };
}

/**
 * Pure dispatcher that splits a raw status frame into the live state
 * callback and the heartbeat keepalive callback. Heartbeats never reach
 * `onStatus` so the Vue store doesn't re-render on idle frames.
 *
 * Exported for unit tests so the heartbeat-filter behavior is pinned
 * without spinning up a Tauri listener.
 */
export function handleStatusEvent(
  event: AgentStatusEvent,
  onStatus: (event: AgentStatusEvent) => void,
  onHeartbeat?: (event: AgentStatusEvent) => void,
): void {
  onHeartbeat?.(event);
  if (event.kind !== 'heartbeat') {
    onStatus(event);
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
      error: tauriUnavailableError(),
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

export async function lockVault(): Promise<AgentResult<void>> {
  return callTyped<void>('agent_lock', {});
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

export async function policyDoctor(
  request: PolicyDoctorRequest,
): Promise<AgentResult<PolicyDoctorResponse>> {
  return callTyped<PolicyDoctorResponse>('agent_policy_doctor', { request });
}

export async function exportBundle(
  request: ExportBundleRequest,
): Promise<AgentResult<BackupActionResponse>> {
  return callTyped<BackupActionResponse>('agent_export_bundle', { request });
}

export async function importBundle(
  request: ImportBundleRequest,
): Promise<AgentResult<BackupActionResponse>> {
  return callTyped<BackupActionResponse>('agent_import_bundle', { request });
}

export async function verifyBundle(
  request: VerifyBundleRequest,
): Promise<AgentResult<VerifyBundleResponse>> {
  return callTyped<VerifyBundleResponse>('agent_verify_bundle', { request });
}

export async function recoveryRotate(
  request: RecoveryRotateRequest,
): Promise<AgentResult<BackupActionResponse>> {
  return callTyped<BackupActionResponse>('agent_recovery_rotate', { request });
}

export async function listRuntimeSessions(
  request: ListRuntimeSessionsRequest,
): Promise<AgentResult<ListRuntimeSessionsResponse>> {
  return callTyped<ListRuntimeSessionsResponse>('agent_list_runtime_sessions', { request });
}

export async function listPolicies(
  request: ListPoliciesRequest,
): Promise<AgentResult<ListPoliciesResponse>> {
  return callTyped<ListPoliciesResponse>('agent_list_policies', { request });
}

/**
 * Replace the agent's in-memory snapshot for a project. The desktop
 * policy editor calls this for create / edit / delete operations; the
 * agent appends the metadata-only `POLICY_UPDATE` audit row server-side.
 */
export async function registerCommandPolicies(
  request: RegisterCommandPoliciesRequest,
): Promise<AgentResult<void>> {
  return callTyped<void>('agent_register_command_policies', { request });
}

/**
 * Switch the active project profile. The agent enforces dangerous-
 * profile gating via the typed `confirmation` field; the desktop
 * surfaces a typed-confirmation modal before forwarding it.
 */
export async function setActiveProfile(
  request: SetActiveProfileRequest,
): Promise<AgentResult<SetActiveProfileResponse>> {
  return callTyped<SetActiveProfileResponse>('agent_set_active_profile', { request });
}

export async function listDeviceMembers(
  request: ListDeviceMembersRequest,
): Promise<AgentResult<ListDeviceMembersResponse>> {
  return callTyped<ListDeviceMembersResponse>('agent_list_device_members', { request });
}

export async function listSecrets(
  request: ListSecretsRequest,
): Promise<AgentResult<ListSecretsResponse>> {
  return callTyped<ListSecretsResponse>('agent_list_secrets', { request });
}

/**
 * Wire shape for the `agent_set_secret` and `agent_rotate_secret`
 * Tauri commands. The desktop forwards a plaintext value through a
 * single Tauri invoke; the agent's `SetSecret` handler validates the
 * live grant, encrypts the value, and never echoes it back.
 */
export interface SetSecretRequest {
  project_id: string;
  profile_id: string;
  secret_name: string;
  value: string;
  source?: string;
  grace_until?: number;
  grant_id?: string;
  store_path?: string;
}

export interface SetSecretResponse {
  action: string;
  secret_id: string;
  version: number;
  source: string;
}

export async function setSecret(
  request: SetSecretRequest,
): Promise<AgentResult<SetSecretResponse>> {
  return callTyped<SetSecretResponse>('agent_set_secret', { request });
}

export async function rotateSecret(
  request: SetSecretRequest,
): Promise<AgentResult<SetSecretResponse>> {
  return callTyped<SetSecretResponse>('agent_rotate_secret', { request });
}

export async function readConfig(
  request: ReadConfigRequest,
): Promise<AgentResult<AgentConfigSettings>> {
  return callTyped<AgentConfigSettings>('agent_read_config', { request });
}

export async function writeConfig(
  request: WriteConfigRequest,
): Promise<AgentResult<WriteConfigResponse>> {
  return callTyped<WriteConfigResponse>('agent_write_config', { request });
}

export async function listAudit(
  request: ListAuditRequest,
): Promise<AgentResult<ListAuditResponse>> {
  return callTyped<ListAuditResponse>('agent_list_audit', { request });
}

export async function verifyAudit(
  request: VerifyAuditRequest,
): Promise<AgentResult<VerifyAuditResponse>> {
  return callTyped<VerifyAuditResponse>('agent_verify_audit', { request });
}

export async function listVersions(
  request: ListVersionsRequest,
): Promise<AgentResult<ListVersionsResponse>> {
  return callTyped<ListVersionsResponse>('agent_list_versions', { request });
}

/**
 * Wire shape for the `agent_copy_secret` Tauri command. The desktop
 * shell calls the agent's `Copy` RPC, writes the returned value to the
 * clipboard, and schedules a TTL-bound clear; the webview only sees
 * the metadata-only outcome.
 */
export interface CopySecretRequest {
  secret_name: string;
  profile_id: string;
  project_id?: string;
  store_path?: string;
  grant_id?: string;
  ttl_seconds?: number;
}

export type CopySecretResponse =
  | { kind: 'copied'; ttl_seconds: number }
  | { kind: 'unsupported'; unsupported_reason: string };

export async function copySecret(
  request: CopySecretRequest,
): Promise<AgentResult<CopySecretResponse>> {
  return callTyped<CopySecretResponse>('agent_copy_secret', { request });
}
