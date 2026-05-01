export type LocketDiagnosticSeverity = 'error' | 'warning';

export interface LocketSecretMetadata {
  readonly name: string;
}

export interface LocketVersionMetadata {
  readonly name: string;
  readonly version: number;
  readonly versionState: 'current' | 'deprecated' | 'purged' | string;
  readonly graceUntil?: number | null;
  readonly pinnedReferenceEligible: boolean;
}

export interface LocketDiagnosticContext {
  readonly activeSecrets: readonly LocketSecretMetadata[];
  readonly versions: readonly LocketVersionMetadata[];
  readonly nowUnixNanos: number;
  readonly nearGraceWindowNanos?: number;
  /**
   * Optional VS Code `document.languageId`. When present, the diagnostics scan
   * uses the per-language env-reference patterns from
   * {@link ENV_REFERENCE_PATTERNS_BY_LANGUAGE_ID}. When absent or unknown, the
   * scan falls back to the JS/TS `process.env.KEY` pattern so that arbitrary
   * documents (such as `.env.example`, JSON, TOML, YAML) keep their existing
   * Node-flavored coverage.
   */
  readonly languageId?: string;
}

export interface LocketDiagnosticPlan {
  readonly code:
    | 'locket.missingEnvSecret'
    | 'locket.pinnedVersionExpiring'
    | 'locket.pinnedVersionExpired';
  readonly severity: LocketDiagnosticSeverity;
  readonly message: string;
  readonly startOffset: number;
  readonly endOffset: number;
}

const DEFAULT_NEAR_GRACE_WINDOW_NANOS = 7 * 24 * 60 * 60 * 1_000_000_000;
const PROCESS_ENV_PATTERN = /\bprocess\.env\.([A-Z][A-Z0-9_]*)\b/gu;
const PROCESS_ENV_BRACKET_PATTERN = /\bprocess\.env\[\s*["']([A-Z][A-Z0-9_]*)["']\s*\]/gu;

// Python: os.environ["KEY"], os.environ.get("KEY"), os.getenv("KEY")
const PYTHON_OS_ENVIRON_INDEX_PATTERN = /\bos\.environ\[\s*["']([A-Z][A-Z0-9_]*)["']\s*\]/gu;
const PYTHON_OS_ENVIRON_GET_PATTERN = /\bos\.environ\.get\(\s*["']([A-Z][A-Z0-9_]*)["']/gu;
const PYTHON_OS_GETENV_PATTERN = /\bos\.getenv\(\s*["']([A-Z][A-Z0-9_]*)["']/gu;

// Rust: env::var("KEY"), std::env::var("KEY")
const RUST_ENV_VAR_PATTERN = /\b(?:std::)?env::var(?:_os)?\(\s*["]([A-Z][A-Z0-9_]*)["]/gu;

// Go: os.Getenv("KEY"), os.LookupEnv("KEY")
const GO_OS_GETENV_PATTERN = /\bos\.(?:Getenv|LookupEnv)\(\s*["`]([A-Z][A-Z0-9_]*)["`]/gu;

// Ruby: ENV["KEY"], ENV.fetch("KEY")
const RUBY_ENV_INDEX_PATTERN = /\bENV\[\s*["']([A-Z][A-Z0-9_]*)["']\s*\]/gu;
const RUBY_ENV_FETCH_PATTERN = /\bENV\.fetch\(\s*["']([A-Z][A-Z0-9_]*)["']/gu;

// Java: System.getenv("KEY")
const JAVA_GETENV_PATTERN = /\bSystem\.getenv\(\s*"([A-Z][A-Z0-9_]*)"/gu;

// PHP: getenv("KEY"), $_ENV["KEY"], $_SERVER["KEY"]
const PHP_GETENV_PATTERN = /\bgetenv\(\s*["']([A-Z][A-Z0-9_]*)["']/gu;
const PHP_ENV_SUPERGLOBAL_PATTERN = /\$_(?:ENV|SERVER)\[\s*["']([A-Z][A-Z0-9_]*)["']\s*\]/gu;

// C/C++: getenv("KEY")
const C_GETENV_PATTERN = /\bgetenv\(\s*"([A-Z][A-Z0-9_]*)"/gu;

// C#: Environment.GetEnvironmentVariable("KEY")
const CSHARP_GETENV_PATTERN = /\bEnvironment\.GetEnvironmentVariable\(\s*"([A-Z][A-Z0-9_]*)"/gu;

// Swift: ProcessInfo.processInfo.environment["KEY"]
const SWIFT_PROCESS_INFO_ENV_PATTERN =
  /\bProcessInfo\.processInfo\.environment\[\s*"([A-Z][A-Z0-9_]*)"\s*\]/gu;

// Shell: $KEY, ${KEY}. Avoid `$0..$9` positional params and intentionally
// require a non-identifier prefix so substrings like `bar$FOO` do not match
// while `$X` (single letter) is excluded by the {2,} lower bound.
const SHELL_BRACE_PATTERN = /\$\{\s*([A-Z][A-Z0-9_]*)\s*[}:]/gu;
const SHELL_BARE_PATTERN = /(?<![A-Za-z0-9_$\\])\$([A-Z][A-Z0-9_]+)\b/gu;

interface EnvReferencePatternEntry {
  readonly pattern: RegExp;
}

const NODE_PROCESS_ENV_PATTERNS: readonly EnvReferencePatternEntry[] = [
  { pattern: PROCESS_ENV_PATTERN },
  { pattern: PROCESS_ENV_BRACKET_PATTERN },
];

/**
 * Per-language env-reference patterns. Languages we recognise but whose
 * idiom differs from `process.env.KEY` map here. Anything not listed (or a
 * document with no `languageId`) falls through to the Node patterns so the
 * existing JS/TS/`.env.example`/JSON behaviour is preserved.
 */
const ENV_REFERENCE_PATTERNS_BY_LANGUAGE_ID: Readonly<Record<string, readonly EnvReferencePatternEntry[]>> = {
  javascript: NODE_PROCESS_ENV_PATTERNS,
  javascriptreact: NODE_PROCESS_ENV_PATTERNS,
  typescript: NODE_PROCESS_ENV_PATTERNS,
  typescriptreact: NODE_PROCESS_ENV_PATTERNS,
  python: [
    { pattern: PYTHON_OS_ENVIRON_INDEX_PATTERN },
    { pattern: PYTHON_OS_ENVIRON_GET_PATTERN },
    { pattern: PYTHON_OS_GETENV_PATTERN },
  ],
  rust: [{ pattern: RUST_ENV_VAR_PATTERN }],
  go: [{ pattern: GO_OS_GETENV_PATTERN }],
  ruby: [{ pattern: RUBY_ENV_INDEX_PATTERN }, { pattern: RUBY_ENV_FETCH_PATTERN }],
  java: [{ pattern: JAVA_GETENV_PATTERN }],
  kotlin: [{ pattern: JAVA_GETENV_PATTERN }],
  php: [{ pattern: PHP_GETENV_PATTERN }, { pattern: PHP_ENV_SUPERGLOBAL_PATTERN }],
  c: [{ pattern: C_GETENV_PATTERN }],
  cpp: [{ pattern: C_GETENV_PATTERN }],
  csharp: [{ pattern: CSHARP_GETENV_PATTERN }],
  swift: [{ pattern: SWIFT_PROCESS_INFO_ENV_PATTERN }],
  shellscript: [{ pattern: SHELL_BRACE_PATTERN }, { pattern: SHELL_BARE_PATTERN }],
};

const PINNED_REFERENCE_PATTERN = /\blk:\/\/[a-z][a-z0-9_-]*\/([A-Z][A-Z0-9_]*)@v([1-9][0-9]*)\b/gu;

export function locketDiagnosticPlans(
  text: string,
  context: LocketDiagnosticContext,
): readonly LocketDiagnosticPlan[] {
  const plans: LocketDiagnosticPlan[] = [];
  const activeSecretNames = new Set(context.activeSecrets.map((secret) => secret.name));
  const nearGraceWindowNanos = context.nearGraceWindowNanos ?? DEFAULT_NEAR_GRACE_WINDOW_NANOS;

  const envPatterns = envReferencePatternsForLanguage(context.languageId);
  // Track ranges already reported so overlapping per-language alternations
  // (e.g. `$KEY` inside `${KEY}`) don't double-emit the same diagnostic.
  const reportedRanges = new Set<string>();
  for (const entry of envPatterns) {
    for (const match of text.matchAll(entry.pattern)) {
      const name = match[1];
      if (name === undefined || activeSecretNames.has(name)) {
        continue;
      }
      const startOffset = match.index;
      const endOffset = match.index + match[0].length;
      const rangeKey = `${startOffset}:${endOffset}`;
      if (reportedRanges.has(rangeKey)) {
        continue;
      }
      reportedRanges.add(rangeKey);
      plans.push({
        code: 'locket.missingEnvSecret',
        severity: 'warning',
        message: `${match[0]} is not present in the active Locket profile.`,
        startOffset,
        endOffset,
      });
    }
  }

  for (const match of text.matchAll(PINNED_REFERENCE_PATTERN)) {
    const name = match[1];
    const version = Number(match[2]);
    const row = context.versions.find(
      (candidate) => candidate.name === name && candidate.version === version,
    );
    if (row === undefined) {
      continue;
    }
    const referenceStart = match.index;
    const referenceEnd = match.index + match[0].length;
    const graceExpired =
      row.graceUntil !== undefined &&
      row.graceUntil !== null &&
      row.graceUntil <= context.nowUnixNanos;
    if (!row.pinnedReferenceEligible || graceExpired) {
      plans.push({
        code: 'locket.pinnedVersionExpired',
        severity: 'error',
        message: `${name}@v${version} is outside its Locket grace window and will not resolve.`,
        startOffset: referenceStart,
        endOffset: referenceEnd,
      });
      continue;
    }
    if (
      row.versionState === 'deprecated' &&
      row.graceUntil !== undefined &&
      row.graceUntil !== null &&
      row.graceUntil - context.nowUnixNanos <= nearGraceWindowNanos
    ) {
      plans.push({
        code: 'locket.pinnedVersionExpiring',
        severity: 'warning',
        message: `${name}@v${version} is deprecated and near its Locket grace-window expiry.`,
        startOffset: referenceStart,
        endOffset: referenceEnd,
      });
    }
  }

  return plans;
}

/**
 * Returns the env-reference patterns to scan for a given `languageId`. When
 * `languageId` is undefined or not registered, falls back to the JS/TS Node
 * `process.env.KEY` patterns so callers that do not thread a `languageId`
 * (such as plain text scans of `.env.example` fragments) keep their previous
 * coverage.
 */
function envReferencePatternsForLanguage(
  languageId: string | undefined,
): readonly EnvReferencePatternEntry[] {
  if (languageId === undefined) {
    return NODE_PROCESS_ENV_PATTERNS;
  }
  return ENV_REFERENCE_PATTERNS_BY_LANGUAGE_ID[languageId] ?? NODE_PROCESS_ENV_PATTERNS;
}
