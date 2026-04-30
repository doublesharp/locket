import type { RuntimeSessionWireRow } from './types';
import type { RuntimeSessionRow } from '../types/views';

const NANOS_PER_MILLI = 1_000_000;

function nanosToIso(nanos: number): string {
  const millis = Math.trunc(nanos / NANOS_PER_MILLI);
  const date = new Date(millis);
  if (Number.isNaN(date.getTime())) {
    return 'Invalid timestamp';
  }
  return date.toISOString();
}

function classifySessionState(row: RuntimeSessionWireRow): RuntimeSessionRow['state'] {
  if (row.state === 'stale') {
    return 'stale';
  }
  if (typeof row.ended_at !== 'number') {
    return 'running';
  }
  return row.exit_status === 0 ? 'completed' : 'failed';
}

export function runtimeSessionRow(row: RuntimeSessionWireRow): RuntimeSessionRow {
  return {
    sessionId: row.session_id,
    profile: row.profile,
    profileAlias: row.profile_alias,
    policy: row.policy,
    policyAlias: row.policy_alias,
    pid: row.pid,
    processStartTime: nanosToIso(row.process_start_time),
    startedAt: nanosToIso(row.started_at),
    endedAt: typeof row.ended_at === 'number' ? nanosToIso(row.ended_at) : undefined,
    exitStatus: row.exit_status,
    state: classifySessionState(row),
    secretNameCount: row.secret_name_count,
    spawnAuditSequence: row.spawn_audit_sequence,
    completionAuditSequence: row.completion_audit_sequence,
  };
}
