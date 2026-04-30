export type PrivacyAliasKind = 'project' | 'profile' | 'secret' | 'policy' | 'device' | 'member';

const ALIAS_PREFIX = 'locket-privacy-alias-v1';
const textEncoder = new TextEncoder();

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');
}

export async function privacyAlias(kind: PrivacyAliasKind, id: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    'SHA-256',
    textEncoder.encode(`${ALIAS_PREFIX}kind:${kind};id:${id}`),
  );
  return `${kind}-${toHex(new Uint8Array(digest).slice(0, 4))}`;
}

export function privacyLabel(
  kind: PrivacyAliasKind,
  value: string | null | undefined,
  redactNames: boolean,
  alias: string | null,
): string {
  if (value === null || value === undefined || value.length === 0) {
    return '—';
  }
  if (!redactNames) {
    return value;
  }
  return alias ?? `${kind}-redacted`;
}
