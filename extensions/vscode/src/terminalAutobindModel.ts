import {
  ResolvedLocketProject,
  buildDirectoryGrantPayload,
  RequestGrantDirectoryPayload,
} from './commandsModel';

export interface TerminalAutobindContext {
  /// Returns a Locket project for the workspace folder containing the
  /// given path, or `undefined` when no Locket project is in scope.
  readonly resolveProject: (cwd: string | undefined) => ResolvedLocketProject | undefined;
  /// Currently-running process pid (or a stable surrogate for tests).
  readonly pid: number;
  /// Stable token derived from the host VS Code process start time.
  readonly processStartTime: string;
  /// Optional TTL override; defaults to the IDE-session window.
  readonly ttlSeconds?: number;
}

export interface TerminalAutobindResult {
  readonly project: ResolvedLocketProject;
  readonly grantPayload: RequestGrantDirectoryPayload;
}

/// Pure planner: given the directory a terminal was opened in, returns the
/// directory-grant payload to send to the agent, or `undefined` when the
/// terminal is not inside a Locket project.
export function planTerminalAutobind(
  cwd: string | undefined,
  context: TerminalAutobindContext,
): TerminalAutobindResult | undefined {
  const project = context.resolveProject(cwd);
  if (project === undefined) {
    return undefined;
  }
  const grantPayload = buildDirectoryGrantPayload({
    projectId: project.projectId,
    profileId: project.defaultProfileId,
    pid: context.pid,
    processStartTime: context.processStartTime,
    ttlSeconds: context.ttlSeconds,
  });
  return { project, grantPayload };
}

/// Tracks whether the once-per-session "directory not trusted" warning has
/// already fired. The state is intentionally mutable so a single instance
/// is shared across terminal-creation events.
export class WarnOnceLatch {
  private fired = false;

  public shouldFire(): boolean {
    if (this.fired) {
      return false;
    }
    this.fired = true;
    return true;
  }

  public reset(): void {
    this.fired = false;
  }
}
