// Pure helpers for the Locket VS Code command-palette routers.
//
// These builders construct wire payloads for the agent RPCs the
// extension drives from `commands.ts`. They live in a vscode-free
// module so they can be unit-tested with `node --test`.

import { AgentClientError } from './agentClient';
import { AuditRow } from './auditView';

/// Default TTL applied to IDE env-name sessions and directory grants. The
/// agent enforces its own ceiling; this value mirrors the agent's default.
export const IDE_SESSION_DEFAULT_TTL_SECONDS = 1800;

/// Resolved Locket project descriptor for a workspace folder. The
/// terminal-autobind handler and IDE env-session register code reuse the
/// same shape so they can share the workspace-folder discovery helper.
export interface ResolvedLocketProject {
  readonly root: string;
  readonly projectId: string;
  readonly defaultProfileId: string;
}

export interface LockRequestPayload {
  readonly source: string;
}

export interface UnlockAuditPayload {
  readonly store_path: string;
  readonly profile_id: string | null;
}

export interface UnlockRequestPayload {
  readonly project_id: string;
  readonly passphrase: string | null;
  readonly ttl_seconds: number;
  readonly audit: UnlockAuditPayload;
}

export interface SetActiveProfileRequestPayload {
  readonly config_path: string;
  readonly store_path: string;
  readonly project_id: string;
  readonly profile_name: string;
  readonly privacy_redact_names: boolean;
}

export interface ListPoliciesRequestPayload {
  readonly project_id: string;
  readonly privacy_redact_names: boolean;
}

export interface ScanKnownValuesRequestPayload {
  readonly paths: readonly string[];
  readonly require_known: boolean;
  readonly redact_names: boolean;
}

export interface ListAuditRequestPayload {
  readonly store_path: string;
  readonly project_id: string;
  readonly limit: number;
  readonly redact_names: boolean;
}

export interface ListAuditResponsePayload {
  readonly rows: ReadonlyArray<AuditRow>;
  readonly chain_status: {
    readonly hmac_ok: boolean | null;
    readonly first_break_sequence: number | null;
    readonly rows_verified: number;
    readonly locked: boolean;
  };
}

export interface ListPoliciesResponsePayload {
  readonly rows: ReadonlyArray<{
    readonly id: string;
    readonly name: string;
    readonly alias?: string;
    readonly command_kind: string;
    readonly command_preview: string;
    readonly required_secrets: readonly string[];
    readonly optional_secrets: readonly string[];
  }>;
}

/// Subset of `ListPoliciesResponsePayload` the IDE env-session register
/// path needs. `allowed_secrets` is the policy's allow-list union; the
/// IDE-session env-name list is derived from this field's values.
export interface ListPoliciesResponseLike {
  readonly rows: ReadonlyArray<{
    readonly name?: string;
    readonly allowed_secrets?: readonly string[];
    readonly required_secrets?: readonly string[];
    readonly optional_secrets?: readonly string[];
  }>;
}

/// Wire payload for a directory `RequestGrant` issued when an integrated
/// terminal opens inside a Locket project. The grant is bound to the
/// host VS Code process so the agent can fail closed if the requesting
/// pid disappears mid-flight.
export interface RequestGrantDirectoryPayload {
  readonly project_id: string;
  readonly profile_id: string;
  readonly action: 'ResolveReference';
  readonly ttl_seconds: number;
  readonly binding: {
    readonly pid: number;
    readonly process_start_time: string;
  };
}

/// Wire payload for `RegisterIdeEnvSession`. The IDE generates the
/// session id locally, then the agent stores a names-only map under that
/// id for the lifetime of the IDE session.
export interface RegisterIdeEnvSessionPayload {
  readonly session_id: string;
  readonly project_id: string;
  readonly store_path: string;
  readonly profile_id: string | null;
  readonly env_names: readonly string[];
  readonly ttl_seconds: number;
}

export interface CopyResponsePayload {
  readonly value: string;
  readonly ttl_seconds: number;
}

// Default upper bound on rows returned to the audit view. Mirrors the
// agent's `MAX_LIST_AUDIT_ROWS` ceiling and stays comfortably below it
// so the metadata view loads quickly.
export const AUDIT_VIEW_LIMIT = 200;

// Authoritative mapping from VS Code command id to the agent RPC the
// command routes to. The registrar in `commands.ts` is expected to
// exercise every entry; tests verify the table covers the spec.
export const LOCKET_COMMAND_ROUTES: ReadonlyArray<{
  readonly commandId: string;
  readonly agentMethod: string;
}> = [
  { commandId: 'locket.unlock', agentMethod: 'Unlock' },
  { commandId: 'locket.lock', agentMethod: 'Lock' },
  { commandId: 'locket.switchProfile', agentMethod: 'SetActiveProfile' },
  { commandId: 'locket.runPolicy', agentMethod: 'ListPolicies' },
  { commandId: 'locket.scanWorkspace', agentMethod: 'ScanKnownValues' },
  { commandId: 'locket.revealSecret', agentMethod: 'Reveal' },
  { commandId: 'locket.copySecret', agentMethod: 'Copy' },
  { commandId: 'locket.openAuditView', agentMethod: 'ListAudit' },
];

// Build a `Lock` request. The extension always reports the `desktop`
// session-lock source so the agent's audit row reflects the editor.
export function buildLockRequest(): LockRequestPayload {
  return { source: 'desktop' };
}

// Build a `SetActiveProfile` request. Throws if any field is empty.
export function buildSetActiveProfileRequest(
  configPath: string,
  storePath: string,
  projectId: string,
  profileName: string,
): SetActiveProfileRequestPayload {
  const trimmedConfigPath = configPath.trim();
  const trimmedStorePath = storePath.trim();
  const trimmedProjectId = projectId.trim();
  const trimmedProfileName = profileName.trim();
  if (trimmedConfigPath.length === 0) {
    throw new Error('config path is required');
  }
  if (trimmedStorePath.length === 0) {
    throw new Error('store path is required');
  }
  if (trimmedProjectId.length === 0) {
    throw new Error('project id is required');
  }
  if (trimmedProfileName.length === 0) {
    throw new Error('profile name is required');
  }
  return {
    config_path: trimmedConfigPath,
    store_path: trimmedStorePath,
    project_id: trimmedProjectId,
    profile_name: trimmedProfileName,
    privacy_redact_names: false,
  };
}

// Build a `ListPolicies` request.
export function buildListPoliciesRequest(projectId: string): ListPoliciesRequestPayload {
  const trimmedProjectId = projectId.trim();
  if (trimmedProjectId.length === 0) {
    throw new Error('project id is required');
  }
  return { project_id: trimmedProjectId, privacy_redact_names: false };
}

// Build a `ScanKnownValues` request scoped to the workspace folder.
// The extension only supplies path labels; the agent never opens files
// on its behalf for editor-driven scans.
export function buildScanKnownValuesRequest(
  workspacePaths: readonly string[],
): ScanKnownValuesRequestPayload {
  return {
    paths: workspacePaths.filter((value) => value.trim().length > 0),
    require_known: false,
    redact_names: false,
  };
}

// Build a `ListAudit` request. Throws if required fields are empty.
export function buildListAuditRequest(
  storePath: string,
  projectId: string,
): ListAuditRequestPayload {
  const trimmedStorePath = storePath.trim();
  const trimmedProjectId = projectId.trim();
  if (trimmedStorePath.length === 0) {
    throw new Error('store path is required');
  }
  if (trimmedProjectId.length === 0) {
    throw new Error('project id is required');
  }
  return {
    store_path: trimmedStorePath,
    project_id: trimmedProjectId,
    limit: AUDIT_VIEW_LIMIT,
    redact_names: false,
  };
}

// Build an `Unlock` request. The agent owns the keychain unwrap path,
// so the extension never sends raw key bytes; `passphrase` is null on
// the first attempt and re-sent only after the agent surfaces a typed
// `UnlockRequired` error and the user provides one in a password prompt.
export function buildUnlockRequest(
  projectId: string,
  storePath: string,
  profileId: string | null,
  passphrase: string | null,
  ttlSeconds: number = IDE_SESSION_DEFAULT_TTL_SECONDS,
): UnlockRequestPayload {
  const trimmedProjectId = projectId.trim();
  const trimmedStorePath = storePath.trim();
  if (trimmedProjectId.length === 0) {
    throw new Error('project id is required');
  }
  if (trimmedStorePath.length === 0) {
    throw new Error('store path is required');
  }
  return {
    project_id: trimmedProjectId,
    passphrase,
    ttl_seconds: ttlSeconds,
    audit: {
      store_path: trimmedStorePath,
      profile_id: profileId,
    },
  };
}

/// Build a directory `RequestGrant` payload. The action is fixed to
/// `ResolveReference` because that is the only grant the autobind path
/// needs to authorize; widening it would require an explicit policy
/// match.
export function buildDirectoryGrantPayload(options: {
  readonly projectId: string;
  readonly profileId: string;
  readonly pid: number;
  readonly processStartTime: string;
  readonly ttlSeconds?: number;
}): RequestGrantDirectoryPayload {
  return {
    project_id: options.projectId,
    profile_id: options.profileId,
    action: 'ResolveReference',
    ttl_seconds: options.ttlSeconds ?? IDE_SESSION_DEFAULT_TTL_SECONDS,
    binding: {
      pid: options.pid,
      process_start_time: options.processStartTime,
    },
  };
}

/// Build a `RegisterIdeEnvSession` payload. The agent enforces an upper
/// bound on the env-name list; we trust the caller to have already
/// derived the union via `policyAllowList`.
export function buildRegisterIdeEnvSessionPayload(options: {
  readonly sessionId: string;
  readonly projectId: string;
  readonly storePath: string;
  readonly profileId: string | null;
  readonly envNames: readonly string[];
  readonly ttlSeconds?: number;
}): RegisterIdeEnvSessionPayload {
  return {
    session_id: options.sessionId,
    project_id: options.projectId,
    store_path: options.storePath,
    profile_id: options.profileId,
    env_names: [...options.envNames],
    ttl_seconds: options.ttlSeconds ?? IDE_SESSION_DEFAULT_TTL_SECONDS,
  };
}

/// Compute the deduplicated, order-preserving union of every policy's
/// `allowed_secrets` (falling back to `required_secrets ∪ optional_secrets`
/// if the agent only emits the split lists).
export function policyAllowList(
  response: ListPoliciesResponseLike,
): readonly string[] {
  const seen = new Set<string>();
  const ordered: string[] = [];
  for (const row of response.rows) {
    const candidates: readonly string[] =
      row.allowed_secrets !== undefined
        ? row.allowed_secrets
        : [...(row.required_secrets ?? []), ...(row.optional_secrets ?? [])];
    for (const name of candidates) {
      if (typeof name !== 'string' || name.length === 0) {
        continue;
      }
      if (seen.has(name)) {
        continue;
      }
      seen.add(name);
      ordered.push(name);
    }
  }
  return ordered;
}

/// Format 16 random bytes as a v4 UUID string. Centralized here so both
/// the IDE-session register flow and any future client-side id derivation
/// share an identical format.
export function uuidV4FromBytes(bytes: Uint8Array): string {
  if (bytes.length < 16) {
    throw new Error('uuidV4FromBytes requires at least 16 bytes');
  }
  const buffer = new Uint8Array(16);
  buffer.set(bytes.subarray(0, 16));
  // Set version (4) and variant (RFC 4122) bits per the v4 spec.
  buffer[6] = (buffer[6]! & 0x0f) | 0x40;
  buffer[8] = (buffer[8]! & 0x3f) | 0x80;
  const hex = Array.from(buffer, (byte) => byte.toString(16).padStart(2, '0')).join('');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;
}

// Format a one-line user-facing message for an `AgentClientError`.
export function agentErrorMessage(error: unknown): string {
  if (error instanceof AgentClientError) {
    if (error.displayReason !== undefined) {
      return `${error.displayReason} ${error.nextAction ?? ''}`.trim();
    }
    if (error.kind === 'agent' && error.code !== undefined) {
      return `Locket agent rejected request: ${error.code}`;
    }
    if (error.kind === 'protocol') {
      return `Locket agent protocol error: ${error.message}`;
    }
    return `Locket agent unavailable: ${error.message}`;
  }
  return 'Locket command failed.';
}
