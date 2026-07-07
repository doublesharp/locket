import type {
  AuditLogRow,
  CommandPolicyRow,
  RuntimeSessionRow,
  ScanFindingRow,
  SecretRowMeta,
} from '../types/views';

export type StartHereTarget =
  | 'settings'
  | 'secret-editor'
  | 'policies'
  | 'scan'
  | 'audit'
  | 'execution'
  | 'team';

export type StartHereTone = 'ok' | 'warn' | 'critical' | 'neutral';

export interface StartHereAction {
  id: string;
  title: string;
  detail: string;
  target: StartHereTarget;
  actionLabel: string;
  tone: StartHereTone;
}

export interface StartHereInput {
  lockLabel: string;
  secrets: SecretRowMeta[];
  policies: CommandPolicyRow[];
  sessions: RuntimeSessionRow[];
  auditRows: AuditLogRow[];
  findings: ScanFindingRow[];
  auditChainOk: boolean;
  lastScanAt?: string;
}

export function startHereActions(input: StartHereInput): StartHereAction[] {
  const actions: StartHereAction[] = [];
  const highRiskFindings = input.findings.filter(
    (finding) => finding.severity === 'high' || finding.severity === 'critical',
  );
  const failedSessions = input.sessions.filter(
    (session) => session.state === 'failed' || session.state === 'stale',
  );
  const auditIssues = input.auditRows.filter((row) => row.status !== 'OK' || !row.hmacOk);

  if (input.lockLabel !== 'Unlocked') {
    actions.push({
      id: 'unlock',
      title: input.lockLabel === 'Locked' ? 'Unlock the vault' : 'Start the local agent',
      detail: 'Locket needs an available unlocked agent before it can run or reveal secrets.',
      target: 'settings',
      actionLabel: 'Open settings',
      tone: input.lockLabel === 'Unavailable' ? 'critical' : 'warn',
    });
  }

  if (input.secrets.length === 0) {
    actions.push({
      id: 'add-secret',
      title: 'Add your first secret',
      detail: 'Store a local value or import an env file so commands can use Locket safely.',
      target: 'secret-editor',
      actionLabel: 'Add secret',
      tone: 'warn',
    });
  }

  if (input.policies.length === 0) {
    actions.push({
      id: 'create-policy',
      title: 'Create a run policy',
      detail: 'Policies define which command gets which secret names and approval gates.',
      target: 'policies',
      actionLabel: 'Create policy',
      tone: 'warn',
    });
  }

  if (input.lastScanAt === undefined) {
    actions.push({
      id: 'scan-project',
      title: 'Scan the project',
      detail: 'Check source files for accidental secret values before sharing the project.',
      target: 'scan',
      actionLabel: 'Run scan',
      tone: 'neutral',
    });
  }

  if (highRiskFindings.length > 0) {
    actions.push({
      id: 'review-scan',
      title: 'Review scan warnings',
      detail: `${highRiskFindings.length.toString()} high-risk finding${highRiskFindings.length === 1 ? '' : 's'} need attention.`,
      target: 'scan',
      actionLabel: 'Review scan',
      tone: 'critical',
    });
  }

  if (!input.auditChainOk || auditIssues.length > 0) {
    actions.push({
      id: 'review-audit',
      title: 'Review audit health',
      detail: 'Audit entries should verify cleanly before relying on this vault.',
      target: 'audit',
      actionLabel: 'Open audit',
      tone: 'critical',
    });
  }

  if (failedSessions.length > 0) {
    actions.push({
      id: 'review-runs',
      title: 'Review failed runs',
      detail: `${failedSessions.length.toString()} session${failedSessions.length === 1 ? '' : 's'} failed or went stale.`,
      target: 'execution',
      actionLabel: 'Open runs',
      tone: 'warn',
    });
  }

  if (input.secrets.length > 0 && input.policies.length > 0) {
    actions.push({
      id: 'share-access',
      title: 'Share access with an agent or teammate',
      detail: 'Create a pasteable invite when another local agent needs the same setup.',
      target: 'team',
      actionLabel: 'Share access',
      tone: 'ok',
    });
  }

  return actions.slice(0, 5);
}
