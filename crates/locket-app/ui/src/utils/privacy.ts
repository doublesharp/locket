// Privacy-preserving display aliases shared with the Rust crates.
//
// Mirrors `crates/locket-core/src/privacy.rs::privacy_alias`. The
// canonical body per `docs/specs/invariants.md:37` is
// `SHA-256("locket-privacy-alias-v1" || field("kind", kind) || field("id", id))`
// where `field()` is the length-prefixed UTF-8 layout from
// `docs/specs/crypto.md:134-136`:
//
//   field(name, value) =
//     u16_le(byte_len(name)) || UTF-8(name) ||
//     u32_le(byte_len(value)) || UTF-8(value)
//
// Earlier revisions hashed `format!("kind:{kind};id:{id}")` here and in
// the CLI; that produced an alias body that disagreed with the spec.
// Both impls now use the canonical encoding.

export type PrivacyAliasKind = 'project' | 'profile' | 'secret' | 'policy' | 'device' | 'member';

const ALIAS_DOMAIN = 'locket-privacy-alias-v1';
const textEncoder = new TextEncoder();

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');
}

/** Length-prefixed `field(name, value)` matching `docs/specs/crypto.md:134`. */
function encodeField(name: string, value: string): Uint8Array {
  const nameBytes = textEncoder.encode(name);
  const valueBytes = textEncoder.encode(value);
  if (nameBytes.length > 0xffff) {
    throw new RangeError('privacyAlias: field name exceeds u16');
  }
  if (valueBytes.length > 0xffff_ffff) {
    throw new RangeError('privacyAlias: field value exceeds u32');
  }
  const out = new Uint8Array(2 + nameBytes.length + 4 + valueBytes.length);
  const view = new DataView(out.buffer);
  let offset = 0;
  view.setUint16(offset, nameBytes.length, true);
  offset += 2;
  out.set(nameBytes, offset);
  offset += nameBytes.length;
  view.setUint32(offset, valueBytes.length, true);
  offset += 4;
  out.set(valueBytes, offset);
  return out;
}

function concatBytes(...chunks: Uint8Array[]): Uint8Array {
  const total = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

export async function privacyAlias(kind: PrivacyAliasKind, id: string): Promise<string> {
  const payload = concatBytes(
    textEncoder.encode(ALIAS_DOMAIN),
    encodeField('kind', kind),
    encodeField('id', id),
  );
  const digest = await crypto.subtle.digest('SHA-256', payload);
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
