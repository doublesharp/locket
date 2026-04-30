<script setup lang="ts">
import { computed } from 'vue';

import type { RuntimeSessionRow } from '../types/views';

interface Props {
  rows: RuntimeSessionRow[];
  privacyMode: boolean;
}

const props = defineProps<Props>();

const isEmpty = computed<boolean>(() => props.rows.length === 0);

function profileLabel(row: RuntimeSessionRow): string {
  if (props.privacyMode) {
    return row.profileAlias ?? row.profile;
  }
  return row.profile;
}

function policyLabel(row: RuntimeSessionRow): string {
  if (props.privacyMode) {
    return row.policyAlias ?? row.policy;
  }
  return row.policy;
}

function stateLabel(state: RuntimeSessionRow['state']): string {
  switch (state) {
    case 'running':
      return 'running';
    case 'completed':
      return 'completed';
    case 'failed':
      return 'failed';
    case 'stale':
      return 'stale';
    default:
      return state;
  }
}

function auditLabel(row: RuntimeSessionRow): string {
  if (typeof row.completionAuditSequence === 'number') {
    return `${row.spawnAuditSequence} → ${row.completionAuditSequence}`;
  }
  return `${row.spawnAuditSequence} → —`;
}
</script>

<template>
  <section class="view" aria-labelledby="execution-monitor-heading">
    <header class="view__header">
      <h2 id="execution-monitor-heading">Runtime sessions</h2>
    </header>

    <p v-if="isEmpty" class="view__empty">No runtime sessions yet.</p>

    <table v-else class="view__table" aria-describedby="execution-monitor-heading">
      <thead>
        <tr>
          <th scope="col">State</th>
          <th scope="col">Session</th>
          <th scope="col">Profile</th>
          <th scope="col">Policy</th>
          <th scope="col">Process</th>
          <th scope="col">Started</th>
          <th scope="col">Ended</th>
          <th scope="col">Exit</th>
          <th scope="col">Secrets</th>
          <th scope="col">Audit</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="row in rows" :key="row.sessionId">
          <td>
            <span class="view__state">
              <span
                :class="['view__dot', `view__dot--${row.state}`]"
                aria-hidden="true"
              ></span>
              <span class="view__state-label">{{ stateLabel(row.state) }}</span>
            </span>
          </td>
          <td>
            <code class="view__session-id">{{ row.sessionId }}</code>
          </td>
          <td>{{ profileLabel(row) }}</td>
          <td>{{ policyLabel(row) }}</td>
          <td>
            <span class="view__muted">
              pid {{ row.pid }} ·
              <time :datetime="row.processStartTime">{{ row.processStartTime }}</time>
            </span>
          </td>
          <td>
            <time :datetime="row.startedAt">{{ row.startedAt }}</time>
          </td>
          <td>
            <time v-if="row.endedAt" :datetime="row.endedAt">{{ row.endedAt }}</time>
            <span v-else class="view__muted">—</span>
          </td>
          <td>
            <span v-if="typeof row.exitStatus === 'number'" class="view__muted">
              {{ row.exitStatus }}
            </span>
            <span v-else class="view__muted">—</span>
          </td>
          <td>
            <span class="badge badge--count">{{ row.secretNameCount }} secrets</span>
          </td>
          <td>
            <span class="view__muted">{{ auditLabel(row) }}</span>
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
}

.view__header h2 {
  margin: 0;
  font-size: 1rem;
  letter-spacing: 0.04em;
  text-transform: uppercase;
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

.view__muted {
  color: #9aa3b2;
}

.view__state {
  display: inline-flex;
  align-items: center;
  gap: 0.375rem;
}

.view__dot {
  display: inline-block;
  width: 0.5rem;
  height: 0.5rem;
  border-radius: 50%;
  background: rgba(255, 255, 255, 0.16);
}

.view__dot--running {
  background: #6fe1a8;
}

.view__dot--completed {
  background: rgba(255, 255, 255, 0.32);
}

.view__dot--failed {
  background: #f08a8a;
}

.view__dot--stale {
  background: #f8d77a;
}

.view__state-label {
  text-transform: capitalize;
}

.view__session-id {
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
}

.badge--count {
  background: rgba(120, 170, 255, 0.1);
  border-color: rgba(120, 170, 255, 0.28);
  color: #a8c6ff;
}
</style>
