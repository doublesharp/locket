// Pure helpers for the Locket VS Code command-palette routers.
//
// These builders construct wire payloads for the agent RPCs the
// extension drives from `commands.ts`. They live in a vscode-free
// module so they can be unit-tested with `node --test`.

import { AgentClientError } from './agentClient';
import { AuditRow } from './auditView';

export interface LockRequestPayload {
  readonly source: string;
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
