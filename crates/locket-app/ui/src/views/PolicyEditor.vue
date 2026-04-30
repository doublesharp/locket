<script setup lang="ts">
import { computed, ref } from 'vue';

import type { CommandPolicyRow } from '../types/views';

defineOptions({ name: 'PolicyEditor' });

interface Props {
  rows: CommandPolicyRow[];
  privacyMode: boolean;
  loading: boolean;
}

const props = defineProps<Props>();

const selectedId = ref<string | null>(null);
const searchQuery = ref<string>('');

const sortedRows = computed<CommandPolicyRow[]>(() =>
  [...props.rows].sort((left, right) => left.name.localeCompare(right.name)),
);

const filteredRows = computed<CommandPolicyRow[]>(() => {
  const query = searchQuery.value.trim().toLowerCase();
  if (query.length === 0) {
    return sortedRows.value;
  }
  return sortedRows.value.filter((row) => searchText(row).includes(query));
});

const selectedPolicy = computed<CommandPolicyRow | null>(() => {
  if (filteredRows.value.length === 0) {
    return null;
  }
  return filteredRows.value.find((row) => row.id === selectedId.value) ?? filteredRows.value[0];
});

const isEmpty = computed<boolean>(() => !props.loading && sortedRows.value.length === 0);
const isFilteredEmpty = computed<boolean>(
  () => !props.loading && sortedRows.value.length > 0 && filteredRows.value.length === 0,
);

function policyLabel(row: CommandPolicyRow): string {
  if (props.privacyMode) {
    return row.alias ?? row.name;
  }
  return row.name;
}

function secretCount(row: CommandPolicyRow): number {
  return new Set([...row.requiredSecrets, ...row.optionalSecrets, ...row.allowedSecrets]).size;
}

function gateLabels(row: CommandPolicyRow): string[] {
  const labels: string[] = [];
  if (row.confirm) {
    labels.push('confirm');
  }
  if (row.requireUserVerification) {
    labels.push('verify user');
  }
  if (row.allowRemoteDocker) {
    labels.push('remote docker');
  }
  return labels;
}

function secretSearchLabels(row: CommandPolicyRow): string[] {
  if (props.privacyMode) {
    return [];
  }
  return [...row.requiredSecrets, ...row.optionalSecrets, ...row.allowedSecrets];
}

function searchText(row: CommandPolicyRow): string {
  return [
    policyLabel(row),
    row.commandKind,
    row.commandPreview,
    row.envMode,
    row.overrideMode,
    ...gateLabels(row),
    ...secretSearchLabels(row),
    `${secretCount(row)} secrets`,
    ttlLabel(row.ttlSeconds),
    row.updatedAt,
  ]
    .join(' ')
    .toLowerCase();
}

function ttlLabel(seconds: number): string {
  if (seconds <= 0) {
    return '0s';
  }
  const minutes = Math.floor(seconds / 60);
  const remainder = seconds % 60;
  if (minutes === 0) {
    return `${seconds}s`;
  }
  if (remainder === 0) {
    return `${minutes}m`;
  }
  return `${minutes}m ${remainder}s`;
}

function selectPolicy(row: CommandPolicyRow): void {
  selectedId.value = row.id;
}
</script>

<template>
  <section class="view" aria-labelledby="policy-editor-heading">
    <header class="view__header">
      <h2 id="policy-editor-heading">Policies</h2>
      <div class="view__actions">
        <label class="view__search">
          <span class="view__search-label">Search policies</span>
          <input
            v-model="searchQuery"
            type="search"
            autocomplete="off"
            spellcheck="false"
            placeholder="Search metadata"
          />
        </label>
        <span class="badge badge--neutral">read-only</span>
      </div>
    </header>

    <p v-if="loading" class="view__loading" role="status">Loading policy metadata...</p>

    <p v-else-if="isEmpty" class="view__empty">
      No saved command policies. Run <code>locket policy add dev -- &lt;cmd&gt;</code>.
    </p>

    <p v-else-if="isFilteredEmpty" class="view__empty">No matching policies.</p>

    <div v-else class="policy-layout">
      <table class="view__table" aria-describedby="policy-editor-heading">
        <thead>
          <tr>
            <th scope="col">Name</th>
            <th scope="col">Mode</th>
            <th scope="col">Secrets</th>
            <th scope="col">TTL</th>
            <th scope="col">Gates</th>
            <th scope="col">Updated</th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="row in filteredRows"
            :key="row.id"
            :class="['view__row', { 'view__row--selected': selectedPolicy?.id === row.id }]"
            tabindex="0"
            :aria-label="`Inspect policy ${policyLabel(row)}`"
            @click="selectPolicy(row)"
            @keydown.enter.prevent="selectPolicy(row)"
            @keydown.space.prevent="selectPolicy(row)"
          >
            <td>
              <span class="view__name">{{ policyLabel(row) }}</span>
            </td>
            <td>
              <span :class="['badge', row.commandKind === 'shell' ? 'badge--warning' : 'badge--ok']">
                {{ row.commandKind }}
              </span>
            </td>
            <td>{{ secretCount(row) }}</td>
            <td>{{ ttlLabel(row.ttlSeconds) }}</td>
            <td>
              <span v-if="gateLabels(row).length > 0" class="view__badges">
                <span v-for="gate in gateLabels(row)" :key="gate" class="badge badge--gate">
                  {{ gate }}
                </span>
              </span>
              <span v-else class="view__muted">none</span>
            </td>
            <td>
              <time :datetime="row.updatedAt">{{ row.updatedAt }}</time>
            </td>
          </tr>
        </tbody>
      </table>

      <aside v-if="selectedPolicy" class="policy-detail" aria-labelledby="policy-detail-heading">
        <h3 id="policy-detail-heading">{{ policyLabel(selectedPolicy) }}</h3>

        <dl class="policy-detail__grid">
          <div>
            <dt>Command kind</dt>
            <dd>{{ selectedPolicy.commandKind }}</dd>
          </div>
          <div>
            <dt>Environment</dt>
            <dd>{{ selectedPolicy.envMode }}</dd>
          </div>
          <div>
            <dt>Override</dt>
            <dd>{{ selectedPolicy.overrideMode }}</dd>
          </div>
          <div>
            <dt>TTL</dt>
            <dd>{{ ttlLabel(selectedPolicy.ttlSeconds) }}</dd>
          </div>
        </dl>

        <section class="policy-detail__section" aria-labelledby="policy-command-heading">
          <h4 id="policy-command-heading">Command</h4>
          <code class="policy-detail__command">{{ selectedPolicy.commandPreview }}</code>
        </section>

        <section class="policy-detail__section" aria-labelledby="policy-secret-heading">
          <h4 id="policy-secret-heading">Secret access</h4>
          <dl class="policy-detail__secrets">
            <div>
              <dt>Required</dt>
              <dd>{{ selectedPolicy.requiredSecrets.length }}</dd>
            </div>
            <div>
              <dt>Optional</dt>
              <dd>{{ selectedPolicy.optionalSecrets.length }}</dd>
            </div>
            <div>
              <dt>Allowed</dt>
              <dd>{{ selectedPolicy.allowedSecrets.length }}</dd>
            </div>
          </dl>
        </section>

        <section class="policy-detail__section" aria-labelledby="policy-gates-heading">
          <h4 id="policy-gates-heading">Gates</h4>
          <div class="view__badges">
            <span v-if="selectedPolicy.confirm" class="badge badge--gate">confirm</span>
            <span v-if="selectedPolicy.requireUserVerification" class="badge badge--gate">
              verify user
            </span>
            <span v-if="selectedPolicy.allowRemoteDocker" class="badge badge--warning">
              remote docker
            </span>
            <span
              v-if="
                !selectedPolicy.confirm &&
                !selectedPolicy.requireUserVerification &&
                !selectedPolicy.allowRemoteDocker
              "
              class="view__muted"
            >
              none
            </span>
          </div>
        </section>
      </aside>
    </div>
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
  flex-wrap: wrap;
  gap: 0.75rem;
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

.view__loading,
.view__empty {
  margin: 0;
  font-size: 0.875rem;
  color: #9aa3b2;
}

.view__empty code,
.policy-detail__command {
  background: rgba(255, 255, 255, 0.06);
  border-radius: 0.25rem;
  color: #e6e8ec;
  font-size: 0.8125rem;
}

.view__empty code {
  padding: 0.125rem 0.25rem;
}

.policy-layout {
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(18rem, 24rem);
  gap: 1rem;
  align-items: start;
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
  font-size: 0.75rem;
  font-weight: 600;
  letter-spacing: 0.04em;
  text-transform: uppercase;
  color: #9aa3b2;
}

.view__row {
  cursor: pointer;
}

.view__row:hover,
.view__row--selected {
  background: rgba(255, 255, 255, 0.04);
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
  white-space: nowrap;
}

.badge--ok {
  background: rgba(170, 230, 200, 0.1);
  border-color: rgba(170, 230, 200, 0.28);
  color: #b8e6c8;
}

.badge--warning {
  background: rgba(248, 215, 122, 0.12);
  border-color: rgba(248, 215, 122, 0.32);
  color: #f8d77a;
}

.badge--gate,
.badge--neutral {
  color: #9aa3b2;
}

.policy-detail {
  display: flex;
  flex-direction: column;
  gap: 0.875rem;
  padding: 0.875rem;
  border: 1px solid rgba(255, 255, 255, 0.08);
  border-radius: 0.5rem;
}

.policy-detail h3,
.policy-detail h4 {
  margin: 0;
}

.policy-detail h3 {
  font-size: 0.9375rem;
}

.policy-detail h4 {
  font-size: 0.75rem;
  letter-spacing: 0.04em;
  text-transform: uppercase;
  color: #9aa3b2;
}

.policy-detail__grid,
.policy-detail__secrets {
  margin: 0;
  display: grid;
  gap: 0.5rem;
}

.policy-detail__grid {
  grid-template-columns: repeat(2, minmax(0, 1fr));
}

.policy-detail__secrets {
  grid-template-columns: repeat(3, minmax(0, 1fr));
}

.policy-detail__grid div,
.policy-detail__secrets div {
  min-width: 0;
}

.policy-detail dt {
  color: #9aa3b2;
  font-size: 0.75rem;
}

.policy-detail dd {
  margin: 0.125rem 0 0;
  font-size: 0.875rem;
}

.policy-detail__section {
  display: flex;
  flex-direction: column;
  gap: 0.375rem;
}

.policy-detail__command {
  display: block;
  padding: 0.5rem;
  overflow-wrap: anywhere;
}

@media (max-width: 960px) {
  .policy-layout {
    grid-template-columns: 1fr;
  }
}
</style>
