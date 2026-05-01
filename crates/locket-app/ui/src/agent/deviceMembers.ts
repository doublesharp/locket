import type { DeviceMemberWireRow } from './types';
import type { DeviceMemberRow } from '../types/views';

const NANOS_PER_MILLI = 1_000_000;

function nanosToIso(nanos: number): string {
  const millis = Math.trunc(nanos / NANOS_PER_MILLI);
  const date = new Date(millis);
  if (Number.isNaN(date.getTime())) {
    return 'Invalid timestamp';
  }
  return date.toISOString();
}

function optionalNanosToIso(nanos: number | undefined): string | undefined {
  return typeof nanos === 'number' ? nanosToIso(nanos) : undefined;
}

function roleLabel(role: DeviceMemberWireRow['role']): DeviceMemberRow['role'] | undefined {
  return role === 'read-only' ? 'viewer' : role;
}

export function deviceMemberRow(row: DeviceMemberWireRow): DeviceMemberRow {
  return {
    id: row.id,
    kind: row.kind,
    name: row.name,
    alias: row.alias,
    role: roleLabel(row.role),
    fingerprint: row.fingerprint,
    fingerprintAlias: row.fingerprint_alias,
    trustedDeviceCount: row.trusted_device_count,
    localDevice: row.local_device,
    status: row.status,
    createdAt: nanosToIso(row.created_at),
    lastSeenAt: optionalNanosToIso(row.last_seen_at),
  };
}
