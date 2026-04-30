<script setup lang="ts">
import { computed } from 'vue';

import type { AuditLogRow } from '../types/views';

interface Props {
  rows: AuditLogRow[];
  privacyMode: boolean;
  chainOk: boolean;
}

const props = defineProps<Props>();

const emit = defineEmits<{
  (e: 'verify'): void;
}>();

const isEmpty = computed<boolean>(() => props.rows.length === 0);

const firstBrokenSequence = computed<number | null>(() => {
  for (const row of props.rows) {
    if (!row.hmacOk) {
      return row.sequence;
    }
  }
  return null;
});

const chainBannerText = computed<string>(() => {
  if (props.chainOk) {
    return 'Audit chain verified.';
  }
  if (firstBrokenSequence.value !== null) {
    return `Audit chain broken at row ${firstBrokenSequence.value}.`;
  }
  return 'Audit chain broken.';
});

function profileLabel(row: AuditLogRow): string {
  if (props.privacyMode) {
    return row.profileAlias ?? row.profile ?? '—';
  }
  return row.profile ?? '—';
}

function secretLabel(row: AuditLogRow): string {
  if (props.privacyMode) {
    return row.secretAlias ?? row.secretName ?? '—';
  }
  return row.secretName ?? '—';
}

function statusLabel(status: AuditLogRow['status']): string {
  switch (status) {
    case 'OK':
      return 'OK';
    case 'DENIED':
      return 'DENIED';
    case 'FAILED':
      return 'FAILED';
    default:
      return status;
  }
}

function onVerify(): void {
  emit('verify');
}
</script>

<template>
  <section class="view" aria-labelledby="audit-log-heading">
    <header class="view__header">
      <h2 id="audit-log-heading">Audit log</h2>
      <button
        type="button"
        class="view__action"
        aria-label="Verify audit chain"
        @click="onVerify"
      >
        Verify chain
      </button>
    </header>

    <p
      :class="['view__chain', chainOk ? 'view__chain--ok' : 'view__chain--broken']"
      role="status"
      aria-live="polite"
    >
      {{ chainBannerText }}
    </p>

    <p v-if="isEmpty" class="view__empty">No audit rows.</p>

    <table v-else class="view__table" aria-describedby="audit-log-heading">
      <thead>
        <tr>
          <th scope="col">Seq</th>
          <th scope="col">Timestamp</th>
          <th scope="col">Action</th>
          <th scope="col">Status</th>
          <th scope="col">Profile</th>
          <th scope="col">Secret</th>
          <th scope="col">Denial reason</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="row in rows" :key="row.sequence">
          <td>
            <span class="view__muted">{{ row.sequence }}</span>
          </td>
          <td>
            <time :datetime="row.timestamp">{{ row.timestamp }}</time>
          </td>
          <td>
            <span class="view__name">{{ row.action }}</span>
          </td>
          <td>
            <span :class="['badge', `badge--status-${row.status.toLowerCase()}`]">
              {{ statusLabel(row.status) }}
            </span>
          </td>
          <td>{{ profileLabel(row) }}</td>
          <td>{{ secretLabel(row) }}</td>
          <td>
            <span v-if="row.status === 'DENIED' && row.denialReason" class="badge badge--warning">
              {{ row.denialReason }}
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

.view__action {
  background: rgba(255, 255, 255, 0.04);
  color: #e6e8ec;
  border: 1px solid rgba(255, 255, 255, 0.08);
  border-radius: 0.375rem;
  padding: 0.25rem 0.75rem;
  font-size: 0.8125rem;
  cursor: pointer;
}

.view__action:hover {
  background: rgba(255, 255, 255, 0.08);
}

.view__action:focus-visible {
  outline: 2px solid #f8d77a;
  outline-offset: 2px;
}

.view__chain {
  margin: 0 0 0.75rem;
  padding: 0.5rem 0.75rem;
  border-radius: 0.5rem;
  font-size: 0.8125rem;
  border: 1px solid rgba(255, 255, 255, 0.08);
}

.view__chain--ok {
  background: rgba(170, 230, 200, 0.08);
  border-color: rgba(170, 230, 200, 0.28);
  color: #b8e6c8;
}

.view__chain--broken {
  background: rgba(240, 138, 138, 0.1);
  border-color: rgba(240, 138, 138, 0.32);
  color: #f4b3b3;
}

.view__empty {
  margin: 0;
  font-size: 0.875rem;
  color: #9aa3b2;
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

.badge {
  display: inline-block;
  padding: 0.125rem 0.5rem;
  border-radius: 0.375rem;
  font-size: 0.75rem;
  letter-spacing: 0.02em;
  border: 1px solid rgba(255, 255, 255, 0.08);
  background: rgba(255, 255, 255, 0.04);
  color: #e6e8ec;
}

.badge--status-ok {
  background: rgba(170, 230, 200, 0.1);
  border-color: rgba(170, 230, 200, 0.28);
  color: #b8e6c8;
}

.badge--status-denied {
  background: rgba(248, 215, 122, 0.12);
  border-color: rgba(248, 215, 122, 0.32);
  color: #f8d77a;
}

.badge--status-failed {
  background: rgba(240, 138, 138, 0.12);
  border-color: rgba(240, 138, 138, 0.32);
  color: #f4b3b3;
}

.badge--warning {
  background: rgba(248, 215, 122, 0.12);
  border-color: rgba(248, 215, 122, 0.32);
  color: #f8d77a;
}
</style>
