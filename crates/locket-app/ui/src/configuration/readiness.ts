import type { VariableReadinessResponse, VariableReadinessRow } from '../agent/types';

type PolicyReadiness = VariableReadinessResponse['policies'][number];

export function readinessSummary(rows: readonly VariableReadinessRow[], policyErrors = 0) {
  const required = rows.filter((row) => row.required).length;
  const available = rows.filter((row) => row.required && row.state === 'ready').length;
  const missing = rows.filter((row) => row.required && row.state === 'missing').length;
  const unverified = rows.filter((row) => row.state === 'unverified').length;
  const warnings = rows.filter((row) => row.warning).length;
  const label =
    policyErrors > 0
      ? `${policyErrors} command${policyErrors === 1 ? '' : 's'} could not be checked`
      : missing > 0
        ? `${missing} required variable${missing === 1 ? '' : 's'} missing`
        : unverified > 0
          ? 'Some sources need a launch check'
          : rows.length === 0
            ? 'No variables requested'
            : 'Required names available';
  return { required, available, missing, unverified, warnings, label };
}

export function readinessDisplay(row: VariableReadinessRow, privacyMode: boolean) {
  const source =
    row.selected_source === 'public-default'
      ? 'Public default'
      : row.selected_source
        ? privacyMode
          ? 'Available source'
          : row.selected_source
        : 'No confirmed source';
  return {
    name: privacyMode ? 'Variable' : row.name,
    classification: row.classification,
    requirement: row.required ? 'Required' : 'Optional',
    state: row.state,
    source,
    guidance: privacyMode
      ? []
      : [row.description, row.setup_hint, row.next_action].filter((value): value is string =>
          Boolean(value),
        ),
    warning: row.warning
      ? privacyMode
        ? 'A secret uses a prefix that may expose values in browser bundles.'
        : row.warning
      : null,
  };
}

export function readinessBlocksRun(
  policies: readonly PolicyReadiness[],
  policyName?: string,
): boolean {
  if (!policyName) return false;
  const selected = policies.find((policy) => policy.policy_name === policyName);
  return (
    Boolean(selected?.error) ||
    Boolean(selected?.rows.some((row) => row.required && row.state === 'missing'))
  );
}

export function readinessPolicyDisplay(
  policy: PolicyReadiness,
  privacyMode: boolean,
  index: number,
) {
  return {
    name: privacyMode ? `Command ${index + 1}` : policy.policy_name,
    error: policy.error
      ? privacyMode
        ? 'Configuration check unavailable for this command.'
        : policy.error
      : null,
    rows: policy.error ? [] : policy.rows.map((row) => readinessDisplay(row, privacyMode)),
  };
}
