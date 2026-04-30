import test from 'node:test';
import assert from 'node:assert/strict';

import {
  buildRevealRequest,
  buildRevealWebviewHtml,
  revealTtlMilliseconds,
} from './revealWebview';

test('reveal request trims user input and uses the agent payload shape', () => {
  assert.deepEqual(buildRevealRequest('  DATABASE_URL  ', '  profile-dev  '), {
    secret_name: 'DATABASE_URL',
    profile_id: 'profile-dev',
  });
});

test('reveal request rejects blank fields', () => {
  assert.throws(() => buildRevealRequest(' ', 'profile-dev'), /secret name is required/u);
  assert.throws(() => buildRevealRequest('DATABASE_URL', ' '), /profile id is required/u);
});

test('reveal ttl is bounded for the webview lifetime', () => {
  assert.equal(revealTtlMilliseconds(1), 1_000);
  assert.equal(revealTtlMilliseconds(0), 30_000);
  assert.equal(revealTtlMilliseconds(Number.NaN), 30_000);
  assert.equal(revealTtlMilliseconds(301), 300_000);
});

test('reveal webview uses a strict csp and does not include persistence APIs', () => {
  const html = buildRevealWebviewHtml({
    nonce: 'nonce-test',
    secretName: 'DATABASE_URL',
    ttlSeconds: 4,
    value: 'fixture-reveal-value',
  });

  assert.match(html, /default-src 'none'/u);
  assert.match(html, /style-src 'nonce-nonce-test'/u);
  assert.match(html, /script-src 'nonce-nonce-test'/u);
  assert.match(html, /fixture-reveal-value/u);
  assert.doesNotMatch(html, /localStorage|sessionStorage|acquireVsCodeApi|postMessage|workspaceState|globalState/u);
});

test('reveal webview clears plaintext on ttl expiry or focus loss', () => {
  const html = buildRevealWebviewHtml({
    nonce: 'nonce-test',
    secretName: 'DATABASE_URL',
    ttlSeconds: 4,
    value: 'fixture-reveal-value',
  });

  assert.match(html, /secretElement\.textContent = 'Cleared'/u);
  assert.match(html, /window\.addEventListener\('blur'/u);
  assert.match(html, /document\.addEventListener\('visibilitychange'/u);
  assert.match(html, /window\.setInterval\(tick, 250\)/u);
});

test('reveal webview escapes secret labels and values', () => {
  const html = buildRevealWebviewHtml({
    nonce: 'nonce-test',
    secretName: '<name>',
    ttlSeconds: 4,
    value: '<script>alert("value")</script>',
  });

  assert.match(html, /&lt;name&gt;/u);
  assert.match(html, /&lt;script&gt;alert\(&quot;value&quot;\)&lt;\/script&gt;/u);
  assert.doesNotMatch(html, /<script>alert/u);
});
