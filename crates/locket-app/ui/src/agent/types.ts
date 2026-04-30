// Types mirroring locket-agent::StatusPayload and the Rust-side
// AgentClientError. Kept in sync by the locket-desktop tests/config.rs
// regression and the agent_client integration tests.

export type LockState = 'locked' | 'unlocked' | 'unknown';

export interface AgentStatus {
  lock_state: LockState;
  project_id: string | null;
  profile_name: string | null;
  live_grant_count: number;
  agent_version: string;
}

export type AgentClientError =
  | {
      kind: 'unavailable';
      reason: string;
      display_reason: string;
      next_action: string;
      socket_path: string;
    }
  | {
      kind: 'protocol';
      reason: string;
    }
  | {
      kind: 'rejected';
      code: string;
      message: string;
      display_reason: string;
      next_action: string;
      retryable: boolean;
    };

export function isUnavailable(
  error: AgentClientError,
): error is Extract<AgentClientError, { kind: 'unavailable' }> {
  return error.kind === 'unavailable';
}

export function isProtocol(
  error: AgentClientError,
): error is Extract<AgentClientError, { kind: 'protocol' }> {
  return error.kind === 'protocol';
}

export function isRejected(
  error: AgentClientError,
): error is Extract<AgentClientError, { kind: 'rejected' }> {
  return error.kind === 'rejected';
}

// RPC payloads. Mirrors the wire shapes in locket-agent/src/{reveal,scan,resolve,prepare_exec}.rs.
// Names use snake_case to match the agent's serde defaults.

export interface RevealRequest {
  secret_name: string;
  profile_id: string;
}

export interface RevealResponse {
  value: string;
  ttl_seconds: number;
}

export type CopyRequest = RevealRequest;
export type CopyResponse = RevealResponse;

export interface ScanRequest {
  paths: string[];
  require_known: boolean;
}

export interface ScanFinding {
  rule: string;
  path: string;
  line: number;
  column: number;
  severity: string;
  redacted_summary: string;
  suppressed_by: string | null;
}

export interface ScanResponse {
  findings: ScanFinding[];
  locked: boolean;
}

export interface ResolveRequest {
  reference: string;
}

export interface ResolveResponse {
  value: string;
  version: number;
  profile_id: string;
}

export interface PrepareExecRequest {
  policy_name: string;
  profile_id: string;
}

export interface PrepareExecResponse {
  allowed_env_names: string[];
  command_kind: string;
  ttl_seconds: number;
}
