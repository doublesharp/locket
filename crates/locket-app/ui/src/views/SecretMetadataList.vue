<script setup lang="ts">
import { computed, ref } from 'vue';

import type { SecretRowMeta } from '../types/views';
import {
  defaultSecretFilter,
  filterSecretRows,
  isSecretFilterActive,
  type SecretDeprecationFilter,
  type SecretFilterState,
  type SecretRequiredFilter,
  type SecretSourceFilter,
} from '../secret/filter';

interface Props {
  rows: SecretRowMeta[];
  privacyMode: boolean;
  loading: boolean;
  errorMessage?: string | null;
  lastRefreshedAt?: string;
}

const props = defineProps<Props>();

const emit = defineEmits<{
  (e: 'select', row: SecretRowMeta): void;
  (e: 'refresh'): void;
}>();

const searchQuery = ref<string>('');
const filterState = ref<SecretFilterState>(defaultSecretFilter());

const metadataFilteredRows = computed<SecretRowMeta[]>(() =>
  filterSecretRows(props.rows, filterState.value),
);

const filteredRows = computed<SecretRowMeta[]>(() => {
  const query = searchQuery.value.trim().toLowerCase();
  if (query.length === 0) {
    return metadataFilteredRows.value;
  }
  return metadataFilteredRows.value.filter((row) => searchText(row).includes(query));
});

const filtersActive = computed<boolean>(() => isSecretFilterActive(filterState.value));

function setSourceFilter(value: SecretSourceFilter): void {
  filterState.value = { ...filterState.value, source: value };
}

function setRequiredFilter(value: SecretRequiredFilter): void {
  filterState.value = { ...filterState.value, required: value };
}

function setDeprecationFilter(value: SecretDeprecationFilter): void {
  filterState.value = { ...filterState.value, deprecation: value };
}

function clearFilters(): void {
  filterState.value = defaultSecretFilter();
  searchQuery.value = '';
}

const isEmpty = computed<boolean>(() => !props.loading && props.rows.length === 0);
const isFilteredEmpty = computed<boolean>(
  () => !props.loading && props.rows.length > 0 && filteredRows.value.length === 0,
);

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

function searchText(row: SecretRowMeta): string {
  return [
    displayName(row),
    row.source,
    row.required ? 'required' : '',
    row.optional ? 'optional' : '',
    row.ownerLabel ?? '',
    ...(row.tags ?? []),
    `v${row.currentVersion}`,
    row.hasDeprecatedGrace ? 'deprecated grace' : '',
    ...(row.deprecatedReferenceWarnings ?? []).map(warningSearchText),
  ]
    .join(' ')
    .toLowerCase();
}

function warningLabel(
  warning: NonNullable<SecretRowMeta['deprecatedReferenceWarnings']>[number],
): string {
  const status = warning.status === 'expired-grace' ? 'expired grace' : 'active grace';
  const surface = warning.surface === 'command-preview' ? 'command preview' : 'policy';
  const count = warning.referenceCount > 1 ? ` (${warning.referenceCount.toString()})` : '';
  return `v${warning.version.toString()} ${status} ${surface}${count}`;
}

function warningSearchText(
  warning: NonNullable<SecretRowMeta['deprecatedReferenceWarnings']>[number],
): string {
  return [
    `v${warning.version}`,
    warning.status,
    warning.surface,
    warning.referenceCount > 1 ? `${warning.referenceCount} references` : '1 reference',
  ].join(' ');
}

function onActivate(row: SecretRowMeta): void {
  emit('select', row);
}

function refresh(): void {
  emit('refresh');
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
      <div class="view__actions">
        <span v-if="lastRefreshedAt" class="view__muted">
          <time :datetime="lastRefreshedAt">{{ lastRefreshedAt }}</time>
        </span>
        <button type="button" class="view__button" :disabled="loading" @click="refresh">
          Refresh
        </button>
      </div>
      <label class="view__search">
        <span class="view__search-label">Search secrets</span>
        <input
          v-model="searchQuery"
          type="search"
          autocomplete="off"
          spellcheck="false"
          placeholder="Search metadata"
        />
      </label>
    </header>

    <fieldset class="view__filters" aria-labelledby="secret-filter-legend">
      <legend id="secret-filter-legend" class="view__filters-legend">Filters (metadata only)</legend>
      <div class="view__filter-group" role="group" aria-label="Filter by source">
        <span class="view__filter-label">Source</span>
        <button
          v-for="option in [
            { value: 'all', label: 'All' },
            { value: 'team', label: 'Team' },
            { value: 'user-local', label: 'User-local' },
            { value: 'machine-local', label: 'Machine-local' },
          ] as const"
          :key="option.value"
          type="button"
          :class="['view__filter-chip', { 'view__filter-chip--active': filterState.source === option.value }]"
          :aria-pressed="filterState.source === option.value"
          @click="setSourceFilter(option.value)"
        >
          {{ option.label }}
        </button>
      </div>
      <div class="view__filter-group" role="group" aria-label="Filter by required">
        <span class="view__filter-label">Required</span>
        <button
          v-for="option in [
            { value: 'all', label: 'All' },
            { value: 'required', label: 'Required' },
            { value: 'optional', label: 'Optional' },
          ] as const"
          :key="option.value"
          type="button"
          :class="['view__filter-chip', { 'view__filter-chip--active': filterState.required === option.value }]"
          :aria-pressed="filterState.required === option.value"
          @click="setRequiredFilter(option.value)"
        >
          {{ option.label }}
        </button>
      </div>
      <div class="view__filter-group" role="group" aria-label="Filter by deprecation">
        <span class="view__filter-label">Status</span>
        <button
          v-for="option in [
            { value: 'all', label: 'All' },
            { value: 'current', label: 'Current' },
            { value: 'deprecated', label: 'Deprecated grace' },
          ] as const"
          :key="option.value"
          type="button"
          :class="['view__filter-chip', { 'view__filter-chip--active': filterState.deprecation === option.value }]"
          :aria-pressed="filterState.deprecation === option.value"
          @click="setDeprecationFilter(option.value)"
        >
          {{ option.label }}
        </button>
      </div>
      <button
        v-if="filtersActive || searchQuery.length > 0"
        type="button"
        class="view__filter-clear"
        @click="clearFilters"
      >
        Clear filters
      </button>
    </fieldset>

    <p v-if="errorMessage" class="view__error">{{ errorMessage }}</p>

    <p v-else-if="loading" class="view__loading" role="status">Loading secret metadata…</p>

    <p v-else-if="isEmpty" class="view__empty">
      No secrets in this profile yet. Run <code>locket set &lt;KEY&gt;</code> or
      <code>locket import &lt;file.env&gt;</code>.
    </p>

    <p v-else-if="isFilteredEmpty" class="view__empty">No matching secrets.</p>

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
          v-for="row in filteredRows"
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
            <span
              v-if="row.deprecatedReferenceWarnings && row.deprecatedReferenceWarnings.length > 0"
              class="view__badges"
            >
              <span
                v-for="warning in row.deprecatedReferenceWarnings"
                :key="`${row.id}:v${warning.version}:${warning.status}:${warning.surface}`"
                class="badge badge--warning"
                role="note"
                :title="warning.graceUntil ? `Grace until ${warning.graceUntil}` : undefined"
              >
                {{ warningLabel(warning) }}
              </span>
            </span>
            <span v-else-if="row.hasDeprecatedGrace" class="badge badge--warning" role="note">
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
  flex-wrap: wrap;
  gap: 0.75rem;
  margin-bottom: 0.75rem;
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
  gap: 0.625rem;
  margin-left: auto;
}

.view__button {
  min-height: 2rem;
  border: 1px solid rgba(255, 255, 255, 0.14);
  border-radius: 0.375rem;
  background: rgba(255, 255, 255, 0.06);
  color: #e6e8ec;
  cursor: pointer;
  font: inherit;
  font-size: 0.8125rem;
  padding: 0.25rem 0.625rem;
}

.view__button:disabled {
  color: #667085;
  cursor: not-allowed;
}

.view__search {
  display: grid;
  gap: 0.25rem;
  min-width: min(18rem, 100%);
}

.view__search-label {
  color: #9aa3b2;
  font-size: 0.75rem;
  font-weight: 600;
  letter-spacing: 0.04em;
  text-transform: uppercase;
}

.view__search input {
  box-sizing: border-box;
  width: 100%;
  min-height: 2rem;
  border: 1px solid rgba(255, 255, 255, 0.12);
  border-radius: 0.375rem;
  background: rgba(255, 255, 255, 0.05);
  color: #e6e8ec;
  font: inherit;
  padding: 0.375rem 0.625rem;
}

.view__search input:focus {
  border-color: #f8d77a;
  outline: 2px solid rgba(248, 215, 122, 0.24);
  outline-offset: 1px;
}

.view__search input::placeholder {
  color: #667085;
}

.view__filters {
  margin: 0 0 0.75rem;
  padding: 0.625rem 0.75rem;
  border: 1px solid rgba(255, 255, 255, 0.06);
  border-radius: 0.375rem;
  background: rgba(255, 255, 255, 0.02);
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem 0.875rem;
  align-items: center;
}
.view__filters-legend {
  padding: 0 0.25rem;
  color: #9aa3b2;
  font-size: 0.7rem;
  letter-spacing: 0.04em;
  text-transform: uppercase;
}
.view__filter-group {
  display: inline-flex;
  align-items: center;
  gap: 0.25rem;
  flex-wrap: wrap;
}
.view__filter-label {
  font-size: 0.7rem;
  color: #9aa3b2;
  letter-spacing: 0.02em;
  text-transform: uppercase;
  margin-right: 0.25rem;
}
.view__filter-chip {
  border: 1px solid rgba(255, 255, 255, 0.12);
  background: rgba(255, 255, 255, 0.04);
  color: #c5cbd6;
  font: inherit;
  font-size: 0.75rem;
  padding: 0.125rem 0.5rem;
  border-radius: 999px;
  cursor: pointer;
}
.view__filter-chip--active {
  background: rgba(248, 215, 122, 0.16);
  color: #f8d77a;
  border-color: rgba(248, 215, 122, 0.5);
}
.view__filter-chip:focus-visible {
  outline: 2px solid #f8d77a;
  outline-offset: 1px;
}
.view__filter-clear {
  margin-left: auto;
  border: 0;
  background: transparent;
  color: #9aa3b2;
  font: inherit;
  font-size: 0.75rem;
  text-decoration: underline;
  cursor: pointer;
}

.view__loading,
.view__empty {
  margin: 0;
  font-size: 0.875rem;
  color: #9aa3b2;
}

.view__error {
  color: #ffb4a8;
  margin: 0;
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

.view__badges {
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
