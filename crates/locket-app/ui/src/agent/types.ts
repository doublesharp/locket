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
  unlock_ttl_seconds: number | null;
}

export type AgentStatusEventKind = 'status' | 'heartbeat';

export interface AgentStatusEvent extends AgentStatus {
  kind: AgentStatusEventKind;
  sequence: number;
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
  project_id?: string;
  profile_id?: string;
  store_path?: string;
  grant_id?: string;
  binding?: GrantBinding;
}

export interface ResolveResponse {
  value: string;
  version: number;
  profile_id: string;
}

export interface PrepareExecRequest {
  policy_name: string;
  profile_id: string;
  project_id?: string;
  binding?: GrantBinding;
}

export interface GrantBinding {
  pid: number;
  process_start_time: string;
}

export interface PrepareExecResponse {
  allowed_env_names: string[];
  command_kind: string;
  ttl_seconds: number;
}

export type RuntimeSessionState = 'running' | 'completed' | 'failed' | 'stale';

export interface ListRuntimeSessionsRequest {
  project_id: string;
  profile_id: string;
  privacy_redact_names: boolean;
}

export interface RuntimeSessionWireRow {
  session_id: string;
  profile: string;
  profile_alias?: string;
  policy: string;
  policy_alias?: string;
  pid: number;
  process_start_time: number;
  started_at: number;
  ended_at?: number;
  exit_status?: number;
  state: RuntimeSessionState;
  secret_name_count: number;
  spawn_audit_sequence?: number;
  completion_audit_sequence?: number;
}

export interface ListRuntimeSessionsResponse {
  rows: RuntimeSessionWireRow[];
}

export interface ListPoliciesRequest {
  project_id: string;
  privacy_redact_names: boolean;
}

export type CommandKindWire = 'argv' | 'shell';
export type CommandEnvModeWire = 'minimal' | 'inherit' | 'strict';
export type CommandOverrideModeWire = 'locket' | 'preserve' | 'fail';

export interface CommandPolicyWireRow {
  id: string;
  name: string;
  alias?: string;
  command_kind: CommandKindWire;
  command_preview: string;
  required_secrets: string[];
  optional_secrets: string[];
  allowed_secrets: string[];
  confirm: boolean;
  require_user_verification: boolean;
  require_agent: boolean;
  allow_remote_docker: boolean;
  ttl_seconds: number;
  env_mode: CommandEnvModeWire;
  override_mode: CommandOverrideModeWire;
  updated_at_unix_nanos: number;
}

export interface ListPoliciesResponse {
  rows: CommandPolicyWireRow[];
}

export interface ListDeviceMembersRequest {
  store_path?: string;
  project_id: string;
  redact_names: boolean;
  include_revoked_devices?: boolean;
}

export type DeviceMemberKindWire = 'device' | 'member';
export type DeviceMemberStatusWire = 'active' | 'revoked' | 'removed';

export interface DeviceMemberWireRow {
  id: string;
  kind: DeviceMemberKindWire;
  name: string;
  alias?: string;
  role?: 'owner' | 'maintainer' | 'developer' | 'viewer' | 'read-only';
  fingerprint?: string;
  fingerprint_alias?: string;
  trusted_device_count?: number;
  local_device?: boolean;
  status: DeviceMemberStatusWire;
  created_at: number;
  last_seen_at?: number;
}

export interface ListDeviceMembersResponse {
  rows: DeviceMemberWireRow[];
}

export interface ListSecretsRequest {
  store_path?: string;
  project_id: string;
  profile_id: string;
  redact_names: boolean;
}

export type SecretSourceWire = 'team-managed' | 'user-local' | 'machine-local';

export interface SecretWireRow {
  id: string;
  profile_id: string;
  name: string;
  source: SecretSourceWire;
  source_precedence: number;
  origin: string;
  current_version: number;
  state: string;
  required: boolean;
  created_at: number;
  updated_at: number;
  last_rotated_at: number | null;
}

export interface ListSecretsResponse {
  rows: SecretWireRow[];
}

export interface ReadConfigRequest {
  config_path?: string | null;
  store_path?: string | null;
  project_id?: string | null;
  profile_name?: string | null;
}

export interface WriteConfigRequest {
  config_path?: string | null;
  store_path?: string | null;
  project_id: string;
  profile_name?: string | null;
  changes: WriteConfigChanges;
}

export interface WriteConfigChanges {
  privacy_redact_names?: boolean | null;
  agent_unlock_ttl?: string | null;
  user_verification_required_for?: UserVerificationSettings | null;
  dangerous_profile?: boolean | null;
}

export interface UserVerificationSettings {
  unlock?: boolean | null;
  reveal?: boolean | null;
  copy?: boolean | null;
  dangerous_profile_switch?: boolean | null;
  recovery?: boolean | null;
  team_accept?: boolean | null;
  device_register?: boolean | null;
}

export interface EffectiveUserVerificationSettings {
  unlock: boolean;
  reveal: boolean;
  copy: boolean;
  dangerous_profile_switch: boolean;
  recovery: boolean;
  team_accept: boolean;
  device_register: boolean;
}

export interface DangerousProfileSetting {
  profile_id: string;
  profile_name: string;
  dangerous: boolean;
}

export interface AgentConfigSettings {
  privacy_redact_names: boolean;
  agent_unlock_ttl: string | null;
  user_verification_required_for: EffectiveUserVerificationSettings;
  dangerous_profile: DangerousProfileSetting | null;
}

export interface WriteConfigResponse {
  settings: AgentConfigSettings;
  changed_keys: string[];
}

export interface ListAuditRequest {
  store_path?: string | null;
  project_id: string;
  profile_id?: string | null;
  action?: string | null;
  status?: string | null;
  since_unix_nanos?: number | null;
  until_unix_nanos?: number | null;
  limit?: number | null;
  redact_names?: boolean;
}

export interface AuditChainStatus {
  hmac_ok: boolean | null;
  first_break_sequence: number | null;
  rows_verified: number;
  locked: boolean;
}

export interface AuditWireRow {
  sequence: number;
  timestamp: number;
  profile_id: string | null;
  action: string;
  status: string;
  secret_name: string | null;
  command: string | null;
}

export interface ListAuditResponse {
  rows: AuditWireRow[];
  chain_status: AuditChainStatus;
}

export interface VerifyAuditRequest {
  project_id: string;
}

export interface VerifyAuditResponse {
  hmac_ok: boolean | null;
  first_break_sequence: number | null;
  first_break_reason: string | null;
  rows_verified: number;
  locked: boolean;
}

export interface ListVersionsRequest {
  store_path?: string;
  project_id: string;
  profile_id: string;
  secret_name?: string;
  source?: string;
  now_unix_nanos: number;
  redact_names: boolean;
}

export type VersionSourceWire = 'team-managed' | 'user-local' | 'machine-local';
export type VersionStateWire = 'current' | 'deprecated' | 'purged';

export interface VersionWireRow {
  secret_id: string;
  profile_id: string;
  name: string;
  source: VersionSourceWire;
  source_precedence: number;
  origin: string;
  secret_state: string;
  current_version: number;
  last_rotated_at: number | null;
  version: number;
  version_state: VersionStateWire;
  created_at: number;
  deprecated_at: number | null;
  grace_until: number | null;
  purged_at: number | null;
  pinned_reference_eligible: boolean;
  scan_included: boolean;
}

export interface ListVersionsResponse {
  rows: VersionWireRow[];
}
