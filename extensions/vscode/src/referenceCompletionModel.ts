export const REFERENCE_COMPLETION_TRIGGER_CHARACTERS = ['l', 'k', ':', '/', '?', '@'];

export interface ReferenceFragment {
  readonly text: string;
  readonly startOffset: number;
}

export interface ReferenceCompletionPlan {
  readonly label: string;
  readonly insertText: string;
  readonly detail: string;
  readonly kind: 'reference' | 'source' | 'version';
}

const SOURCE_VALUES = ['user-local', 'machine-local', 'team-managed'] as const;
const REFERENCE_FRAGMENT_PATTERN =
  /(^|[\s"'`=([{,:])(?<fragment>lk(?::(?:\/{0,2})?)?[A-Za-z0-9_/-]*(?:@v[0-9]*)?(?:\?source=[A-Za-z-]*)?)$/u;

export function locateReferenceFragment(linePrefix: string): ReferenceFragment | undefined {
  const match = REFERENCE_FRAGMENT_PATTERN.exec(linePrefix);
  const fragment = match?.groups?.fragment;
  if (fragment === undefined) {
    return undefined;
  }
  return {
    text: fragment,
    startOffset: linePrefix.length - fragment.length,
  };
}

export function referenceCompletionPlans(
  fragment: string,
  activeProfileName: string | null | undefined,
): readonly ReferenceCompletionPlan[] {
  const profileName = validProfileName(activeProfileName) ? activeProfileName : 'profile';
  const referenceBase = baseReference(fragment);
  const plans: ReferenceCompletionPlan[] = [
    {
      label: `lk://${profileName}/KEY`,
      insertText: `lk://${profileName}/\${1:KEY}`,
      detail: 'Locket reference',
      kind: 'reference',
    },
  ];

  if (referenceBase !== undefined) {
    plans.push({
      label: `${referenceBase}@v1`,
      insertText: `${referenceBase}@v\${1:1}`,
      detail: 'Pin a Locket reference version',
      kind: 'version',
    });
    for (const source of SOURCE_VALUES) {
      plans.push({
        label: `${referenceBase}?source=${source}`,
        insertText: `${referenceBase}?source=${source}`,
        detail: 'Select a Locket source',
        kind: 'source',
      });
    }
  }

  return plans;
}

function baseReference(fragment: string): string | undefined {
  const withoutQuery = fragment.split('?', 1)[0];
  const withoutVersion = withoutQuery.replace(/@v[0-9]*$/u, '');
  if (!/^lk:\/\/[a-z][a-z0-9_-]*\/[A-Z][A-Z0-9_]*$/u.test(withoutVersion)) {
    return undefined;
  }
  return withoutVersion;
}

function validProfileName(value: string | null | undefined): value is string {
  return value !== null && value !== undefined && /^[a-z][a-z0-9_-]*$/u.test(value);
}
