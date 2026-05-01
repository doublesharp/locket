import { randomBytes } from 'node:crypto';

import { AgentClient, AgentClientError } from './agentClient';
import {
  ListPoliciesResponseLike,
  ResolvedLocketProject,
  buildRegisterIdeEnvSessionPayload,
  policyAllowList,
  uuidV4FromBytes,
} from './commandsModel';

export const LOCKET_IDE_ENV_SESSION_VARIABLE = 'LOCKET_IDE_ENV_SESSION';

export interface IdeEnvSessionDeps {
  readonly agentClient: AgentClient;
  readonly project: ResolvedLocketProject;
  readonly storePath: string;
  /// Optional override so tests can inject a deterministic id.
  readonly sessionIdFactory?: () => string;
}

export interface IdeEnvSessionResult {
  readonly sessionId: string;
  readonly envNames: readonly string[];
}

/// Registers an IDE env-name session with the local agent and returns the
/// generated session id plus the env-name allow-list. Returns `undefined`
/// when the project has no policies (no IDE allow-list available) or when
/// the agent rejects the request.
export async function registerIdeEnvSessionWithAgent(
  deps: IdeEnvSessionDeps,
): Promise<IdeEnvSessionResult | undefined> {
  let policies: ListPoliciesResponseLike;
  try {
    policies = await deps.agentClient.invoke<ListPoliciesResponseLike>('ListPolicies', {
      project_id: deps.project.projectId,
      privacy_redact_names: false,
    });
  } catch {
    // Agent unavailable or rejected: skip silently — terminal-injection is
    // best-effort and must never block terminal creation.
    return undefined;
  }
  const envNames = policyAllowList(policies);
  if (envNames.length === 0) {
    return undefined;
  }
  const sessionId = (deps.sessionIdFactory ?? defaultSessionIdFactory)();
  const payload = buildRegisterIdeEnvSessionPayload({
    sessionId,
    projectId: deps.project.projectId,
    storePath: deps.storePath,
    profileId: deps.project.defaultProfileId,
    envNames,
  });
  try {
    await deps.agentClient.invoke('RegisterIdeEnvSession', payload);
  } catch (error) {
    if (error instanceof AgentClientError) {
      return undefined;
    }
    return undefined;
  }
  return { sessionId, envNames };
}

/// Minimal shape of the `vscode.EnvironmentVariableCollection` API the
/// extension actually uses. Defining it here keeps this module free of a
/// `vscode` import so it stays unit-testable.
export interface EnvironmentVariableCollectionLike {
  replace(name: string, value: string): void;
  delete(name: string): void;
}

/// Applies `LOCKET_IDE_ENV_SESSION` to the integrated terminal environment
/// collection.
export function applyIdeEnvSessionToTerminals(
  collection: EnvironmentVariableCollectionLike,
  sessionId: string,
): void {
  collection.replace(LOCKET_IDE_ENV_SESSION_VARIABLE, sessionId);
}

export function clearIdeEnvSessionFromTerminals(
  collection: EnvironmentVariableCollectionLike,
): void {
  collection.delete(LOCKET_IDE_ENV_SESSION_VARIABLE);
}

function defaultSessionIdFactory(): string {
  return uuidV4FromBytes(new Uint8Array(randomBytes(16)));
}
