import test from 'node:test';
import assert from 'node:assert/strict';

import { buildAuditWebviewHtml } from './auditView';

test('audit view uses a strict csp and disables scripts', () => {
  const html = buildAuditWebviewHtml({
    nonce: 'nonce-test',
    rows: [],
    chainStatus: { hmac_ok: true, first_break_sequence: null, rows_verified: 0, locked: false },
  });
  assert.match(html, /default-src 'none'/u);
  assert.match(html, /style-src 'nonce-nonce-test'/u);
  assert.doesNotMatch(html, /script-src/u);
  assert.doesNotMatch(html, /<script/u);
  assert.doesNotMatch(html, /localStorage|sessionStorage|acquireVsCodeApi|postMessage/u);
});

test('audit view renders metadata-only columns and escapes html', () => {
  const html = buildAuditWebviewHtml({
    nonce: 'nonce-test',
    rows: [
      {
        sequence: 7,
        timestamp: 1_700_000_000_000_000_000,
        profile_id: 'profile-1',
        action: 'REVEAL',
        status: 'OK',
        secret_name: '<DATABASE_URL>',
        command: null,
      },
    ],
    chainStatus: { hmac_ok: true, first_break_sequence: null, rows_verified: 1, locked: false },
  });
  assert.match(html, /Locket Audit \(metadata only\)/u);
  assert.match(html, /Chain verified\. 1 rows\./u);
  assert.match(html, />REVEAL</u);
  assert.match(html, /&lt;DATABASE_URL&gt;/u);
  assert.doesNotMatch(html, /<DATABASE_URL>/u);
});

test('audit view surfaces locked chain status', () => {
  const html = buildAuditWebviewHtml({
    nonce: 'nonce-test',
    rows: [],
    chainStatus: { hmac_ok: null, first_break_sequence: null, rows_verified: 5, locked: true },
  });
  assert.match(html, /Vault is locked\. 5 rows shown without HMAC verification\./u);
});

test('audit view surfaces broken chain with sequence', () => {
  const html = buildAuditWebviewHtml({
    nonce: 'nonce-test',
    rows: [],
    chainStatus: { hmac_ok: false, first_break_sequence: 42, rows_verified: 41, locked: false },
  });
  assert.match(html, /Chain verification failed at sequence 42/u);
});

test('audit view shows empty state when there are no rows', () => {
  const html = buildAuditWebviewHtml({
    nonce: 'nonce-test',
    rows: [],
    chainStatus: { hmac_ok: true, first_break_sequence: null, rows_verified: 0, locked: false },
  });
  assert.match(html, /No audit rows match the current filters\./u);
});
