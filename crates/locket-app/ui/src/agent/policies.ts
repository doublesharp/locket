import type { CommandPolicyWireRow } from './types';
import type { CommandPolicyRow } from '../types/views';

const NANOS_PER_MILLI = 1_000_000;

function nanosToIso(nanos: number): string {
  const millis = Math.trunc(nanos / NANOS_PER_MILLI);
  const date = new Date(millis);
  if (Number.isNaN(date.getTime())) {
    return 'Invalid timestamp';
  }
  return date.toISOString();
}

export function commandPolicyRow(row: CommandPolicyWireRow): CommandPolicyRow {
  return {
    id: row.id,
    name: row.name,
    alias: row.alias,
    commandKind: row.command_kind,
    commandPreview: row.command_preview,
    requiredSecrets: row.required_secrets,
    optionalSecrets: row.optional_secrets,
    allowedSecrets: row.allowed_secrets,
    confirm: row.confirm,
    requireUserVerification: row.require_user_verification,
    allowRemoteDocker: row.allow_remote_docker,
    ttlSeconds: row.ttl_seconds,
    envMode: row.env_mode,
    overrideMode: row.override_mode,
    updatedAt: nanosToIso(row.updated_at_unix_nanos),
  };
}
