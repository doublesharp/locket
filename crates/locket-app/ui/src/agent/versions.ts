import type { VersionWireRow } from './types';
import type { VersionHistoryRow } from '../types/views';

const NANOS_PER_MILLI = 1_000_000;

function nanosToIso(nanos: number): string {
  const millis = Math.trunc(nanos / NANOS_PER_MILLI);
  const date = new Date(millis);
  if (Number.isNaN(date.getTime())) {
    return 'Invalid timestamp';
  }
  return date.toISOString();
}

function optionalNanosToIso(nanos: number | null): string | undefined {
  return typeof nanos === 'number' ? nanosToIso(nanos) : undefined;
}

function sourceLabel(source: VersionWireRow['source']): string {
  return source === 'team-managed' ? 'team' : source;
}

export function versionHistoryRow(row: VersionWireRow): VersionHistoryRow {
  return {
    id: `${row.secret_id}:${row.source}:v${row.version}`,
    secretName: row.name,
    source: sourceLabel(row.source),
    version: row.version,
    state: row.version_state,
    deprecatedAt: optionalNanosToIso(row.deprecated_at),
    graceUntil: optionalNanosToIso(row.grace_until),
    pinnedReferenceEligible: row.pinned_reference_eligible,
    scanInclusion: row.scan_included,
  };
}
