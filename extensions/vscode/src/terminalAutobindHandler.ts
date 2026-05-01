import { AgentClient, AgentClientError } from './agentClient';
import { RequestGrantDirectoryPayload, ResolvedLocketProject } from './commandsModel';
import {
  EnvironmentVariableCollectionLike,
  applyIdeEnvSessionToTerminals,
  registerIdeEnvSessionWithAgent,
} from './ideEnvSession';
import {
  TerminalAutobindContext,
  WarnOnceLatch,
  planTerminalAutobind,
} from './terminalAutobindModel';

export interface TerminalAutobindHandlerDeps {
  readonly agentClient: AgentClient;
  readonly environmentVariableCollection: EnvironmentVariableCollectionLike;
  readonly autobindContext: TerminalAutobindContext;
  readonly storePath: string;
  readonly sessionIdFactory?: () => string;
  readonly notifyDirectoryGrantRejected: (reason: string) => void;
  readonly warnOnce: WarnOnceLatch;
}

export interface TerminalAutobindOutcome {
  readonly applied: boolean;
  readonly project?: ResolvedLocketProject;
  readonly sessionId?: string;
  readonly grantPayload?: RequestGrantDirectoryPayload;
}

/// Event handler that runs whenever VS Code opens an integrated terminal.
/// Performs two best-effort actions:
///   1. Inject `LOCKET_IDE_ENV_SESSION` into the environment-variable
///      collection so subsequent terminals see the value.
///   2. Fire-and-forget a directory `RequestGrant`. On rejection with a
///      typed agent error, surface a single warning notification per
///      session via `notifyDirectoryGrantRejected`.
export async function handleOpenTerminal(
  cwd: string | undefined,
  deps: TerminalAutobindHandlerDeps,
): Promise<TerminalAutobindOutcome> {
  const plan = planTerminalAutobind(cwd, deps.autobindContext);
  if (plan === undefined) {
    return { applied: false };
  }

  const session = await registerIdeEnvSessionWithAgent({
    agentClient: deps.agentClient,
    project: plan.project,
    storePath: deps.storePath,
    sessionIdFactory: deps.sessionIdFactory,
  });
  if (session !== undefined) {
    applyIdeEnvSessionToTerminals(deps.environmentVariableCollection, session.sessionId);
  }

  // Fire-and-forget; we deliberately do not await this from the caller's
  // perspective so terminal creation never blocks on the agent.
  void requestDirectoryGrant(deps, plan.grantPayload);

  return {
    applied: true,
    project: plan.project,
    sessionId: session?.sessionId,
    grantPayload: plan.grantPayload,
  };
}

/// Visible for tests. Awaits the directory grant request (instead of the
/// fire-and-forget the production handler does) so unit tests can observe
/// the warning side-effect deterministically.
export async function requestDirectoryGrant(
  deps: TerminalAutobindHandlerDeps,
  grantPayload: RequestGrantDirectoryPayload,
): Promise<void> {
  try {
    await deps.agentClient.invoke('RequestGrant', grantPayload);
  } catch (error) {
    if (!(error instanceof AgentClientError)) {
      return;
    }
    if (error.kind !== 'agent') {
      return;
    }
    if (!deps.warnOnce.shouldFire()) {
      return;
    }
    const reason =
      error.displayReason !== undefined
        ? `${error.displayReason} ${error.nextAction ?? ''}`.trim()
        : `Locket agent denied directory grant: ${error.code ?? error.message}`;
    deps.notifyDirectoryGrantRejected(reason);
  }
}
