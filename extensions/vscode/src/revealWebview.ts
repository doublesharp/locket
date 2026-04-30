const DEFAULT_TTL_SECONDS = 30;
const MAX_TTL_SECONDS = 300;

export interface RevealRequestPayload {
  readonly secret_name: string;
  readonly profile_id: string;
}

export interface RevealResponsePayload {
  readonly value: string;
  readonly ttl_seconds: number;
}

export interface RevealWebviewHtmlOptions {
  readonly nonce: string;
  readonly secretName: string;
  readonly ttlSeconds: number;
  readonly value: string;
}

export function buildRevealRequest(secretName: string, profileId: string): RevealRequestPayload {
  const trimmedSecretName = secretName.trim();
  const trimmedProfileId = profileId.trim();
  if (trimmedSecretName.length === 0) {
    throw new Error('secret name is required');
  }
  if (trimmedProfileId.length === 0) {
    throw new Error('profile id is required');
  }
  return { secret_name: trimmedSecretName, profile_id: trimmedProfileId };
}

export function revealTtlMilliseconds(ttlSeconds: number): number {
  if (!Number.isFinite(ttlSeconds) || ttlSeconds <= 0) {
    return DEFAULT_TTL_SECONDS * 1_000;
  }
  return Math.min(Math.ceil(ttlSeconds), MAX_TTL_SECONDS) * 1_000;
}

export function buildRevealWebviewHtml(options: RevealWebviewHtmlOptions): string {
  const ttlMs = revealTtlMilliseconds(options.ttlSeconds);
  const nonce = escapeHtmlAttribute(options.nonce);
  const secretName = escapeHtml(options.secretName);
  const secretValue = escapeHtml(options.value);

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'nonce-${nonce}'; script-src 'nonce-${nonce}';">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Locket Reveal</title>
  <style nonce="${nonce}">
    :root {
      color-scheme: light dark;
      font-family: var(--vscode-font-family);
      font-size: var(--vscode-font-size);
      color: var(--vscode-foreground);
      background: var(--vscode-editor-background);
    }
    body {
      margin: 0;
      padding: 18px;
    }
    main {
      display: grid;
      gap: 14px;
      max-width: 820px;
    }
    .label {
      color: var(--vscode-descriptionForeground);
      font-size: 12px;
      text-transform: uppercase;
    }
    .name {
      overflow-wrap: anywhere;
    }
    .value {
      border: 1px solid var(--vscode-input-border, var(--vscode-editorWidget-border));
      background: var(--vscode-input-background);
      color: var(--vscode-input-foreground);
      font-family: var(--vscode-editor-font-family);
      font-size: var(--vscode-editor-font-size);
      line-height: 1.45;
      margin: 0;
      min-height: 88px;
      overflow-wrap: anywhere;
      padding: 12px;
      white-space: pre-wrap;
    }
    .value[data-cleared="true"] {
      color: var(--vscode-descriptionForeground);
    }
    .actions {
      align-items: center;
      display: flex;
      gap: 12px;
    }
    button {
      background: var(--vscode-button-background);
      border: 0;
      color: var(--vscode-button-foreground);
      cursor: pointer;
      padding: 6px 12px;
    }
    button:hover {
      background: var(--vscode-button-hoverBackground);
    }
    .ttl {
      color: var(--vscode-descriptionForeground);
    }
  </style>
</head>
<body>
  <main>
    <section>
      <div class="label">Secret</div>
      <div class="name">${secretName}</div>
    </section>
    <pre id="secret-value" class="value">${secretValue}</pre>
    <section class="actions">
      <button id="clear-now" type="button">Clear</button>
      <div id="countdown" class="ttl" aria-live="polite"></div>
    </section>
  </main>
  <script nonce="${nonce}">
    (() => {
      const ttlMs = ${ttlMs};
      const secretElement = document.getElementById('secret-value');
      const countdownElement = document.getElementById('countdown');
      const clearButton = document.getElementById('clear-now');
      const expiresAt = Date.now() + ttlMs;
      let cleared = false;

      const clearSecret = (status) => {
        if (cleared) {
          return;
        }
        cleared = true;
        if (secretElement !== null) {
          secretElement.textContent = 'Cleared';
          secretElement.setAttribute('data-cleared', 'true');
        }
        if (countdownElement !== null) {
          countdownElement.textContent = status;
        }
      };

      const tick = () => {
        const remainingMs = Math.max(0, expiresAt - Date.now());
        if (countdownElement !== null && !cleared) {
          countdownElement.textContent = Math.ceil(remainingMs / 1000).toString() + 's';
        }
        if (remainingMs <= 0) {
          clearSecret('Expired');
          window.clearInterval(timer);
        }
      };

      clearButton?.addEventListener('click', () => clearSecret('Cleared'));
      window.addEventListener('blur', () => clearSecret('Cleared'));
      document.addEventListener('visibilitychange', () => {
        if (document.hidden) {
          clearSecret('Cleared');
        }
      });
      const timer = window.setInterval(tick, 250);
      tick();
    })();
  </script>
</body>
</html>`;
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
