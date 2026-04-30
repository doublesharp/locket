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
const PINNED_REFERENCE_PATTERN = /\blk:\/\/[a-z][a-z0-9_-]*\/([A-Z][A-Z0-9_]*)@v([1-9][0-9]*)\b/gu;

export function locketDiagnosticPlans(
  text: string,
  context: LocketDiagnosticContext,
): readonly LocketDiagnosticPlan[] {
  const plans: LocketDiagnosticPlan[] = [];
  const activeSecretNames = new Set(context.activeSecrets.map((secret) => secret.name));
  const nearGraceWindowNanos = context.nearGraceWindowNanos ?? DEFAULT_NEAR_GRACE_WINDOW_NANOS;

  for (const match of text.matchAll(PROCESS_ENV_PATTERN)) {
    const name = match[1];
    if (name !== undefined && !activeSecretNames.has(name)) {
      plans.push({
        code: 'locket.missingEnvSecret',
        severity: 'warning',
        message: `process.env.${name} is not present in the active Locket profile.`,
        startOffset: match.index,
        endOffset: match.index + match[0].length,
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
