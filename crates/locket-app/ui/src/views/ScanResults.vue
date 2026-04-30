<script setup lang="ts">
import { computed } from 'vue';

import type { ScanFindingRow } from '../types/views';

interface Props {
  findings: ScanFindingRow[];
  scanning: boolean;
  lastScanAt?: string;
  locked: boolean;
  errorMessage?: string | null;
}

const props = defineProps<Props>();

const emit = defineEmits<{
  (e: 'rescan'): void;
}>();

const isEmpty = computed<boolean>(
  () => !props.scanning && !props.errorMessage && props.findings.length === 0,
);

function severityLabel(severity: ScanFindingRow['severity']): string {
  return severity;
}

function locationLabel(row: ScanFindingRow): string {
  return `${row.path}:${row.line}:${row.column}`;
}

function onRescan(): void {
  emit('rescan');
}
</script>

<template>
  <section class="view" aria-labelledby="scan-results-heading">
    <header class="view__header">
      <h2 id="scan-results-heading">Scan results</h2>
      <div class="view__actions">
        <span v-if="lastScanAt" class="view__last-scan">
          Last scan
          <time :datetime="lastScanAt">{{ lastScanAt }}</time>
        </span>
        <button
          type="button"
          class="view__action"
          aria-label="Run scan again"
          :disabled="scanning"
          @click="onRescan"
        >
          {{ scanning ? 'Scanning…' : 'Rescan' }}
        </button>
      </div>
    </header>

    <p v-if="scanning" class="view__loading" role="status">Scanning project tree…</p>

    <p v-else-if="errorMessage" class="view__error" role="alert">{{ errorMessage }}</p>

    <p v-else-if="locked" class="view__notice" role="status">
      Vault locked; known-value matching is unavailable.
    </p>

    <p v-else-if="isEmpty" class="view__empty">No scan findings.</p>

    <table v-else class="view__table" aria-describedby="scan-results-heading">
      <thead>
        <tr>
          <th scope="col">Severity</th>
          <th scope="col">Rule</th>
          <th scope="col">Location</th>
          <th scope="col">Summary</th>
          <th scope="col">Suppressed</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="row in findings" :key="row.id">
          <td>
            <span :class="['badge', `badge--severity-${row.severity}`]">
              {{ severityLabel(row.severity) }}
            </span>
          </td>
          <td>
            <span class="view__name">{{ row.rule }}</span>
          </td>
          <td>
            <code class="view__location">{{ locationLabel(row) }}</code>
          </td>
          <td>
            <span class="view__muted">{{ row.redactedSummary }}</span>
          </td>
          <td>
            <span v-if="row.suppressedBy" class="badge badge--suppressed">
              {{ row.suppressedBy }}
            </span>
            <span v-else class="view__muted">—</span>
          </td>
        </tr>
      </tbody>
    </table>
  </section>
</template>

<style scoped>
.view {
  background: #0f1115;
  color: #e6e8ec;
  padding: 1rem;
  border-radius: 0.5rem;
}

.view__header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 0.75rem;
  gap: 0.75rem;
}

.view__header h2 {
  margin: 0;
  font-size: 1rem;
  letter-spacing: 0.04em;
  text-transform: uppercase;
}

.view__actions {
  display: inline-flex;
  align-items: center;
  gap: 0.75rem;
}

.view__last-scan {
  font-size: 0.75rem;
  color: #9aa3b2;
}

.view__action {
  background: rgba(255, 255, 255, 0.04);
  color: #e6e8ec;
  border: 1px solid rgba(255, 255, 255, 0.08);
  border-radius: 0.375rem;
  padding: 0.25rem 0.75rem;
  font-size: 0.8125rem;
  cursor: pointer;
}

.view__action:hover:not(:disabled) {
  background: rgba(255, 255, 255, 0.08);
}

.view__action:disabled {
  cursor: progress;
  opacity: 0.6;
}

.view__action:focus-visible {
  outline: 2px solid #f8d77a;
  outline-offset: 2px;
}

.view__loading,
.view__empty,
.view__notice,
.view__error {
  margin: 0;
  font-size: 0.875rem;
  color: #9aa3b2;
}

.view__notice {
  color: #f8d77a;
}

.view__error {
  color: #f4b3b3;
}

.view__table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.875rem;
}

.view__table th,
.view__table td {
  text-align: left;
  padding: 0.5rem 0.75rem;
  border-bottom: 1px solid rgba(255, 255, 255, 0.08);
  vertical-align: top;
}

.view__table th {
  font-weight: 600;
  color: #9aa3b2;
  font-size: 0.75rem;
  text-transform: uppercase;
  letter-spacing: 0.04em;
}

.view__name {
  font-weight: 600;
}

.view__muted {
  color: #9aa3b2;
}

.view__location {
  font-size: 0.8125rem;
  color: #e6e8ec;
}

.badge {
  display: inline-block;
  padding: 0.125rem 0.5rem;
  border-radius: 0.375rem;
  font-size: 0.75rem;
  letter-spacing: 0.02em;
  border: 1px solid rgba(255, 255, 255, 0.08);
  background: rgba(255, 255, 255, 0.04);
  color: #e6e8ec;
  text-transform: capitalize;
}

.badge--severity-low {
  background: rgba(255, 255, 255, 0.04);
  color: #9aa3b2;
}

.badge--severity-medium {
  background: rgba(248, 215, 122, 0.1);
  border-color: rgba(248, 215, 122, 0.28);
  color: #f8d77a;
}

.badge--severity-high {
  background: rgba(255, 168, 120, 0.12);
  border-color: rgba(255, 168, 120, 0.32);
  color: #ffb98e;
}

.badge--severity-critical {
  background: rgba(240, 138, 138, 0.14);
  border-color: rgba(240, 138, 138, 0.4);
  color: #f4b3b3;
}

.badge--suppressed {
  background: rgba(255, 255, 255, 0.04);
  color: #9aa3b2;
  text-transform: none;
}
</style>
