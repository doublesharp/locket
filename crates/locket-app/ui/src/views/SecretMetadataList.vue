<script setup lang="ts">
import { computed } from 'vue';

import type { SecretRowMeta } from '../types/views';

interface Props {
  rows: SecretRowMeta[];
  privacyMode: boolean;
  loading: boolean;
}

const props = defineProps<Props>();

const emit = defineEmits<{
  (e: 'select', row: SecretRowMeta): void;
}>();

const isEmpty = computed<boolean>(() => !props.loading && props.rows.length === 0);

function displayName(row: SecretRowMeta): string {
  if (props.privacyMode) {
    return row.alias ?? row.name;
  }
  return row.name;
}

function sourceLabel(source: SecretRowMeta['source']): string {
  switch (source) {
    case 'team':
      return 'team';
    case 'user-local':
      return 'user-local';
    case 'machine-local':
      return 'machine-local';
    default:
      return source;
  }
}

function onActivate(row: SecretRowMeta): void {
  emit('select', row);
}

function onKey(event: KeyboardEvent, row: SecretRowMeta): void {
  if (event.key === 'Enter' || event.key === ' ') {
    event.preventDefault();
    emit('select', row);
  }
}
</script>

<template>
  <section class="view" aria-labelledby="secret-metadata-list-heading">
    <header class="view__header">
      <h2 id="secret-metadata-list-heading">Secrets</h2>
    </header>

    <p v-if="loading" class="view__loading" role="status">Loading secret metadata…</p>

    <p v-else-if="isEmpty" class="view__empty">
      No secrets in this profile yet. Run <code>locket set &lt;KEY&gt;</code> or
      <code>locket import &lt;file.env&gt;</code>.
    </p>

    <table v-else class="view__table" aria-describedby="secret-metadata-list-heading">
      <thead>
        <tr>
          <th scope="col">Name</th>
          <th scope="col">Source</th>
          <th scope="col">Required</th>
          <th scope="col">Owner</th>
          <th scope="col">Tags</th>
          <th scope="col">Created</th>
          <th scope="col">Rotated</th>
          <th scope="col">Version</th>
          <th scope="col">Status</th>
        </tr>
      </thead>
      <tbody>
        <tr
          v-for="row in rows"
          :key="row.id"
          class="view__row"
          tabindex="0"
          :aria-label="`Open metadata for ${displayName(row)}`"
          @click="onActivate(row)"
          @keydown="onKey($event, row)"
        >
          <td>
            <span class="view__name">{{ displayName(row) }}</span>
          </td>
          <td>
            <span :class="['badge', `badge--source-${row.source}`]">
              {{ sourceLabel(row.source) }}
            </span>
          </td>
          <td>
            <span v-if="row.required" class="badge badge--required">required</span>
            <span v-else-if="row.optional" class="badge badge--optional">optional</span>
            <span v-else class="badge badge--neutral">—</span>
          </td>
          <td>
            <span class="view__muted">{{ row.ownerLabel ?? '—' }}</span>
          </td>
          <td>
            <span v-if="row.tags && row.tags.length > 0" class="view__tags">
              <span v-for="tag in row.tags" :key="tag" class="badge badge--tag">{{ tag }}</span>
            </span>
            <span v-else class="view__muted">—</span>
          </td>
          <td>
            <time :datetime="row.createdAt">{{ row.createdAt }}</time>
          </td>
          <td>
            <time v-if="row.rotatedAt" :datetime="row.rotatedAt">{{ row.rotatedAt }}</time>
            <span v-else class="view__muted">—</span>
          </td>
          <td>
            <span class="view__muted">v{{ row.currentVersion }}</span>
          </td>
          <td>
            <span v-if="row.hasDeprecatedGrace" class="badge badge--warning" role="note">
              deprecated grace
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
}

.view__header h2 {
  margin: 0;
  font-size: 1rem;
  letter-spacing: 0.04em;
  text-transform: uppercase;
}

.view__loading,
.view__empty {
  margin: 0;
  font-size: 0.875rem;
  color: #9aa3b2;
}

.view__empty code {
  background: rgba(255, 255, 255, 0.06);
  padding: 0.125rem 0.25rem;
  border-radius: 0.25rem;
  font-size: 0.8125rem;
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

.view__row {
  cursor: pointer;
}

.view__row:hover {
  background: rgba(255, 255, 255, 0.03);
}

.view__row:focus {
  outline: 2px solid #f8d77a;
  outline-offset: -2px;
}

.view__name {
  font-weight: 600;
}

.view__muted {
  color: #9aa3b2;
}

.view__tags {
  display: inline-flex;
  flex-wrap: wrap;
  gap: 0.25rem;
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

.badge--source-team {
  background: rgba(120, 170, 255, 0.12);
  border-color: rgba(120, 170, 255, 0.32);
  color: #a8c6ff;
}

.badge--source-user-local {
  background: rgba(170, 230, 200, 0.1);
  border-color: rgba(170, 230, 200, 0.28);
  color: #b8e6c8;
}

.badge--source-machine-local {
  background: rgba(220, 200, 170, 0.1);
  border-color: rgba(220, 200, 170, 0.28);
  color: #e0cfa8;
}

.badge--required {
  background: rgba(248, 215, 122, 0.12);
  border-color: rgba(248, 215, 122, 0.32);
  color: #f8d77a;
}

.badge--optional {
  background: rgba(255, 255, 255, 0.04);
  color: #9aa3b2;
}

.badge--neutral {
  color: #9aa3b2;
}

.badge--tag {
  background: rgba(255, 255, 255, 0.04);
  color: #9aa3b2;
}

.badge--warning {
  background: rgba(248, 215, 122, 0.12);
  border-color: rgba(248, 215, 122, 0.32);
  color: #f8d77a;
}
</style>
