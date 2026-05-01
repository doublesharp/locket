import type { AuditWireRow } from './types';
import type { AuditLogRow } from '../types/views';

const NANOS_PER_MILLI = 1_000_000;

function nanosToIso(nanos: number): string {
  const millis = Math.trunc(nanos / NANOS_PER_MILLI);
  const date = new Date(millis);
  if (Number.isNaN(date.getTime())) {
    return 'Invalid timestamp';
  }
  return date.toISOString();
}

function auditStatus(status: string): AuditLogRow['status'] {
  switch (status.toUpperCase()) {
    case 'OK':
    case 'SUCCESS':
      return 'OK';
    case 'DENIED':
      return 'DENIED';
    case 'FAILED':
    case 'FAILURE':
    case 'ERROR':
      return 'FAILED';
    default:
      return 'FAILED';
  }
}

export function auditLogRow(row: AuditWireRow, hmacOk: boolean): AuditLogRow {
  return {
    sequence: row.sequence,
    action: row.action,
    status: auditStatus(row.status),
    timestamp: nanosToIso(row.timestamp),
    profile: row.profile_id ?? undefined,
    secretName: row.secret_name ?? undefined,
    metadataJson: '{}',
    hmacOk,
  };
}
