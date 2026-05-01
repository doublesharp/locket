// Locket audit-view webview HTML builder.
//
// Renders metadata-only audit rows. The view never displays secret
// values, key bytes, or any field that the agent has not already
// redacted. The webview disables scripts and uses a strict CSP so it
// cannot exfiltrate the rendered metadata.

export interface AuditRow {
  readonly sequence: number;
  readonly timestamp: number;
  readonly profile_id: string | null;
  readonly action: string;
  readonly status: string;
  readonly secret_name: string | null;
  readonly command: string | null;
}

export interface AuditChainStatus {
  readonly hmac_ok: boolean | null;
  readonly first_break_sequence: number | null;
  readonly rows_verified: number;
  readonly locked: boolean;
}

export interface AuditWebviewHtmlOptions {
  readonly nonce: string;
  readonly rows: ReadonlyArray<AuditRow>;
  readonly chainStatus: AuditChainStatus;
}

export function buildAuditWebviewHtml(options: AuditWebviewHtmlOptions): string {
  const nonce = escapeHtmlAttribute(options.nonce);
  const chain = formatChainStatus(options.chainStatus);
  const rows = options.rows.length === 0
    ? '<tr><td colspan="6" class="empty">No audit rows match the current filters.</td></tr>'
    : options.rows.map(renderRow).join('');
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'nonce-${nonce}';">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Locket Audit</title>
  <style nonce="${nonce}">
    :root {
      color-scheme: light dark;
      font-family: var(--vscode-font-family);
      font-size: var(--vscode-font-size);
      color: var(--vscode-foreground);
      background: var(--vscode-editor-background);
    }
    body { margin: 0; padding: 16px; }
    h1 { font-size: 14px; margin: 0 0 12px; }
    .chain {
      border: 1px solid var(--vscode-input-border, var(--vscode-editorWidget-border));
      padding: 8px 12px;
      margin-bottom: 12px;
      background: var(--vscode-input-background);
      color: var(--vscode-input-foreground);
    }
    table { border-collapse: collapse; width: 100%; }
    th, td {
      border-bottom: 1px solid var(--vscode-editorWidget-border);
      padding: 6px 8px;
      text-align: left;
      font-size: 12px;
      vertical-align: top;
    }
    th { color: var(--vscode-descriptionForeground); font-weight: normal; text-transform: uppercase; }
    td.numeric { text-align: right; font-variant-numeric: tabular-nums; }
    td.empty { color: var(--vscode-descriptionForeground); text-align: center; padding: 24px; }
    code { font-family: var(--vscode-editor-font-family); font-size: 11px; }
  </style>
</head>
<body>
  <h1>Locket Audit (metadata only)</h1>
  <div class="chain">${chain}</div>
  <table>
    <thead>
      <tr>
        <th>Seq</th>
        <th>Timestamp</th>
        <th>Action</th>
        <th>Status</th>
        <th>Profile</th>
        <th>Label</th>
      </tr>
    </thead>
    <tbody>
      ${rows}
    </tbody>
  </table>
</body>
</html>`;
}

function renderRow(row: AuditRow): string {
  const sequence = escapeHtml(String(row.sequence));
  const timestamp = escapeHtml(formatTimestamp(row.timestamp));
  const action = escapeHtml(row.action);
  const status = escapeHtml(row.status);
  const profile = escapeHtml(row.profile_id ?? '');
  const label = escapeHtml(row.command ?? row.secret_name ?? '');
  return `<tr>
    <td class="numeric">${sequence}</td>
    <td><code>${timestamp}</code></td>
    <td>${action}</td>
    <td>${status}</td>
    <td>${profile}</td>
    <td>${label}</td>
  </tr>`;
}

function formatChainStatus(status: AuditChainStatus): string {
  if (status.locked) {
    return `Vault is locked. ${escapeHtml(String(status.rows_verified))} rows shown without HMAC verification.`;
  }
  if (status.hmac_ok === true) {
    return `Chain verified. ${escapeHtml(String(status.rows_verified))} rows.`;
  }
  if (status.hmac_ok === false) {
    const seq = status.first_break_sequence === null ? 'unknown' : String(status.first_break_sequence);
    return `Chain verification failed at sequence ${escapeHtml(seq)}. Investigate audit integrity.`;
  }
  return `Chain status unavailable. ${escapeHtml(String(status.rows_verified))} rows shown.`;
}

function formatTimestamp(unixNanos: number): string {
  if (!Number.isFinite(unixNanos)) {
    return '';
  }
  const millis = Math.floor(unixNanos / 1_000_000);
  const date = new Date(millis);
  if (Number.isNaN(date.getTime())) {
    return '';
  }
  return date.toISOString();
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/gu, '&amp;')
    .replace(/</gu, '&lt;')
    .replace(/>/gu, '&gt;')
    .replace(/"/gu, '&quot;')
    .replace(/'/gu, '&#39;');
}

function escapeHtmlAttribute(value: string): string {
  return escapeHtml(value).replace(/`/gu, '&#96;');
}
