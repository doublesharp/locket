// Cross-language vector test for privacyAlias.
//
// Mirrors `crates/locket-core/src/privacy.rs::tests`. The expected hex
// prefixes here MUST match the prefixes the Rust impl produces; if you
// touch the canonical encoding, regenerate both sides together.

import { describe, expect, it } from 'vitest';

import { privacyAlias } from './privacy';

function digestInput(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

async function sha256First4Hex(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', digestInput(bytes));
  return Array.from(new Uint8Array(digest).slice(0, 4))
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');
}

function buildCanonicalBody(kind: string, id: string): Uint8Array {
  // u16_le(name_len) || name || u32_le(value_len) || value
  const enc = new TextEncoder();
  const domain = enc.encode('locket-privacy-alias-v1');
  const kindName = enc.encode('kind');
  const kindValue = enc.encode(kind);
  const idName = enc.encode('id');
  const idValue = enc.encode(id);
  const out = new Uint8Array(
    domain.length +
      2 +
      kindName.length +
      4 +
      kindValue.length +
      2 +
      idName.length +
      4 +
      idValue.length,
  );
  const view = new DataView(out.buffer);
  let offset = 0;
  out.set(domain, offset);
  offset += domain.length;
  view.setUint16(offset, kindName.length, true);
  offset += 2;
  out.set(kindName, offset);
  offset += kindName.length;
  view.setUint32(offset, kindValue.length, true);
  offset += 4;
  out.set(kindValue, offset);
  offset += kindValue.length;
  view.setUint16(offset, idName.length, true);
  offset += 2;
  out.set(idName, offset);
  offset += idName.length;
  view.setUint32(offset, idValue.length, true);
  offset += 4;
  out.set(idValue, offset);
  return out;
}

describe('privacyAlias', () => {
  it('matches canonical field-prefixed SHA-256 body', async () => {
    for (const [kind, id] of [
      ['profile', 'prod'],
      ['secret', 'DATABASE_URL'],
      ['project', 'lk_proj_demo'],
    ] as const) {
      const expectedHex = await sha256First4Hex(buildCanonicalBody(kind, id));
      const alias = await privacyAlias(kind, id);
      expect(alias).toBe(`${kind}-${expectedHex}`);
    }
  });

  it('differs from legacy unprefixed body', async () => {
    const legacyBody = new TextEncoder().encode(`locket-privacy-alias-v1kind:profile;id:prod`);
    const legacyHex = await sha256First4Hex(legacyBody);
    const alias = await privacyAlias('profile', 'prod');
    expect(alias).not.toBe(`profile-${legacyHex}`);
  });

  it('is stable across calls and kind-scoped', async () => {
    const a = await privacyAlias('profile', 'prod');
    const b = await privacyAlias('profile', 'prod');
    const c = await privacyAlias('policy', 'prod');
    expect(a).toBe(b);
    expect(a).not.toBe(c);
    expect(a.startsWith('profile-')).toBe(true);
  });
});
