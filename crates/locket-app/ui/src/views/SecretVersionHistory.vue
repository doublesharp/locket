<script setup lang="ts">
import { computed, ref } from 'vue';

import type { VersionHistoryRow } from '../types/views';

interface Props {
  rows: VersionHistoryRow[];
  secretLabel: string;
}

const props = defineProps<Props>();

const isEmpty = computed<boolean>(() => props.rows.length === 0);

const expanded = ref<Set<number>>(new Set());

function toggle(version: number): void {
  const next = new Set(expanded.value);
  if (next.has(version)) {
    next.delete(version);
  } else {
    next.add(version);
  }
  expanded.value = next;
}

function isExpanded(version: number): boolean {
  return expanded.value.has(version);
}

function stateLabel(state: VersionHistoryRow['state']): string {
  switch (state) {
    case 'current':
      return 'current';
    case 'deprecated':
      return 'deprecated';
    case 'purged':
      return 'purged';
    default:
      return state;
  }
}
</script>

<template>
  <section class="view" aria-labelledby="secret-version-history-heading">
    <header class="view__header">
      <h2 id="secret-version-history-heading">Version history — {{ secretLabel }}</h2>
    </header>

    <p v-if="isEmpty" class="view__empty">No version history available.</p>

    <table v-else class="view__table" aria-describedby="secret-version-history-heading">
      <thead>
        <tr>
          <th scope="col">Version</th>
          <th scope="col">State</th>
          <th scope="col">Deprecated at</th>
          <th scope="col">Grace until</th>
          <th scope="col">Pinned eligible</th>
          <th scope="col">Scan inclusion</th>
          <th scope="col">Rotation audit</th>
        </tr>
      </thead>
      <tbody>
        <template v-for="row in rows" :key="row.version">
          <tr>
            <td>
              <span class="view__name">v{{ row.version }}</span>
            </td>
            <td>
              <span :class="['badge', `badge--state-${row.state}`]">
                {{ stateLabel(row.state) }}
              </span>
            </td>
            <td>
              <time v-if="row.deprecatedAt" :datetime="row.deprecatedAt">
                {{ row.deprecatedAt }}
              </time>
              <span v-else class="view__muted">—</span>
            </td>
            <td>
              <time v-if="row.graceUntil" :datetime="row.graceUntil">{{ row.graceUntil }}</time>
              <span v-else class="view__muted">—</span>
            </td>
            <td>
              <span
                v-if="row.pinnedReferenceEligible"
                class="view__check"
                aria-label="pinned references eligible"
              >
                ✓
              </span>
              <span
                v-else
                class="view__cross"
                aria-label="pinned references not eligible"
              >
                ✗
              </span>
            </td>
            <td>
              <span
                v-if="row.scanInclusion"
                class="view__check"
                aria-label="included in scans"
              >
                ✓
              </span>
              <span v-else class="view__cross" aria-label="not included in scans">✗</span>
            </td>
            <td>
              <button
                v-if="row.rotationAuditSummary"
                type="button"
                class="view__expand"
                :aria-expanded="isExpanded(row.version)"
                :aria-controls="`rotation-audit-v${row.version}`"
                :aria-label="`Toggle rotation audit summary for version ${row.version}`"
                @click="toggle(row.version)"
              >
                {{ isExpanded(row.version) ? 'Hide' : 'Show' }}
              </button>
              <span v-else class="view__muted">—</span>
            </td>
          </tr>
          <tr
            v-if="row.rotationAuditSummary && isExpanded(row.version)"
            :id="`rotation-audit-v${row.version}`"
            class="view__detail"
          >
            <td colspan="7">
              <p class="view__detail-text">{{ row.rotationAuditSummary }}</p>
            </td>
          </tr>
        </template>
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

.view__name {
  font-weight: 600;
}

.view__muted {
  color: #9aa3b2;
}

.view__check {
  color: #b8e6c8;
}

.view__cross {
  color: #9aa3b2;
}

.view__expand {
  background: rgba(255, 255, 255, 0.04);
  color: #e6e8ec;
  border: 1px solid rgba(255, 255, 255, 0.08);
  border-radius: 0.375rem;
  padding: 0.125rem 0.5rem;
  font-size: 0.75rem;
  cursor: pointer;
}

.view__expand:hover {
  background: rgba(255, 255, 255, 0.08);
}

.view__expand:focus-visible {
  outline: 2px solid #f8d77a;
  outline-offset: 2px;
}

.view__detail {
  background: rgba(255, 255, 255, 0.02);
}

.view__detail-text {
  margin: 0;
  font-size: 0.8125rem;
  color: #9aa3b2;
  white-space: pre-wrap;
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

.badge--state-current {
  background: rgba(170, 230, 200, 0.1);
  border-color: rgba(170, 230, 200, 0.28);
  color: #b8e6c8;
}

.badge--state-deprecated {
  background: rgba(248, 215, 122, 0.12);
  border-color: rgba(248, 215, 122, 0.32);
  color: #f8d77a;
}

.badge--state-purged {
  background: rgba(255, 255, 255, 0.04);
  color: #9aa3b2;
}
</style>
