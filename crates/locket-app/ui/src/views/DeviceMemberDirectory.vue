<script setup lang="ts">
import { computed, ref } from 'vue';

import type { DeviceMemberRow } from '../types/views';

interface Props {
  rows: DeviceMemberRow[];
  privacyMode: boolean;
}

type KindFilter = 'all' | DeviceMemberRow['kind'];
type StatusFilter = 'all' | DeviceMemberRow['status'];

const props = defineProps<Props>();

const searchTerm = ref<string>('');
const kindFilter = ref<KindFilter>('all');
const statusFilter = ref<StatusFilter>('all');

const filteredRows = computed<DeviceMemberRow[]>(() => {
  const needle = searchTerm.value.trim().toLocaleLowerCase();
  return props.rows.filter((row) => {
    if (kindFilter.value !== 'all' && row.kind !== kindFilter.value) {
      return false;
    }
    if (statusFilter.value !== 'all' && row.status !== statusFilter.value) {
      return false;
    }
    if (needle.length === 0) {
      return true;
    }
    const haystack = [
      displayName(row),
      fingerprintLabel(row),
      row.kind,
      row.role ?? '',
      row.status,
    ]
      .join(' ')
      .toLocaleLowerCase();
    return haystack.includes(needle);
  });
});

const emptyText = computed<string>(() => {
  if (props.rows.length === 0) {
    return 'No devices or members. Run locket device init.';
  }
  return 'No devices or members match the current search.';
});

function displayName(row: DeviceMemberRow): string {
  if (props.privacyMode) {
    return row.alias ?? row.name;
  }
  return row.name;
}

function fingerprintLabel(row: DeviceMemberRow): string {
  if (!row.fingerprint && !row.fingerprintAlias) {
    return '—';
  }
  if (props.privacyMode) {
    return row.fingerprintAlias ?? row.fingerprint ?? '—';
  }
  return row.fingerprint ?? '—';
}

function memberDeviceCount(row: DeviceMemberRow): string {
  if (row.kind !== 'member') {
    return row.localDevice ? 'local' : '—';
  }
  return `${row.trustedDeviceCount ?? 0}`;
}
</script>

<template>
  <section class="view" aria-labelledby="device-member-directory-heading">
    <header class="view__header">
      <h2 id="device-member-directory-heading">Devices &amp; members</h2>
    </header>

    <div class="view__controls" aria-label="Device and member filters">
      <label class="view__search">
        <span class="view__label">Search</span>
        <input v-model="searchTerm" type="search" autocomplete="off" />
      </label>

      <label class="view__select">
        <span class="view__label">Type</span>
        <select v-model="kindFilter">
          <option value="all">All</option>
          <option value="device">Devices</option>
          <option value="member">Members</option>
        </select>
      </label>

      <label class="view__select">
        <span class="view__label">Status</span>
        <select v-model="statusFilter">
          <option value="all">All</option>
          <option value="active">Active</option>
          <option value="pending">Pending</option>
          <option value="revoked">Revoked</option>
          <option value="removed">Removed</option>
        </select>
      </label>
    </div>

    <p v-if="filteredRows.length === 0" class="view__empty">{{ emptyText }}</p>

    <table v-else class="view__table" aria-describedby="device-member-directory-heading">
      <thead>
        <tr>
          <th scope="col">Name</th>
          <th scope="col">Type</th>
          <th scope="col">Role</th>
          <th scope="col">Fingerprint</th>
          <th scope="col">Devices</th>
          <th scope="col">Status</th>
          <th scope="col">Created</th>
          <th scope="col">Last seen</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="row in filteredRows" :key="`${row.kind}:${row.id}`">
          <td>
            <span class="view__name">{{ displayName(row) }}</span>
          </td>
          <td>
            <span class="badge">{{ row.kind }}</span>
          </td>
          <td>
            <span class="view__muted">{{ row.role ?? '—' }}</span>
          </td>
          <td>
            <code class="view__fingerprint">{{ fingerprintLabel(row) }}</code>
          </td>
          <td>
            <span class="view__muted">{{ memberDeviceCount(row) }}</span>
          </td>
          <td>
            <span :class="['badge', `badge--status-${row.status}`]">{{ row.status }}</span>
          </td>
          <td>
            <time :datetime="row.createdAt">{{ row.createdAt }}</time>
          </td>
          <td>
            <time v-if="row.lastSeenAt" :datetime="row.lastSeenAt">{{ row.lastSeenAt }}</time>
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

.view__controls {
  display: grid;
  grid-template-columns: minmax(14rem, 1fr) minmax(8rem, 10rem) minmax(8rem, 10rem);
  gap: 0.75rem;
  align-items: end;
  margin-bottom: 0.75rem;
}

.view__search,
.view__select {
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
}

.view__label {
  font-size: 0.75rem;
  color: #9aa3b2;
  text-transform: uppercase;
  letter-spacing: 0.04em;
}

.view__search input,
.view__select select {
  min-height: 2rem;
  border-radius: 0.375rem;
  border: 1px solid rgba(255, 255, 255, 0.08);
  background: rgba(255, 255, 255, 0.04);
  color: #e6e8ec;
  padding: 0.25rem 0.5rem;
  font: inherit;
}

.view__search input:focus-visible,
.view__select select:focus-visible {
  outline: 2px solid #f8d77a;
  outline-offset: 2px;
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

.view__fingerprint {
  color: #e6e8ec;
  background: rgba(255, 255, 255, 0.06);
  padding: 0.125rem 0.25rem;
  border-radius: 0.25rem;
  font-size: 0.8125rem;
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

.badge--status-active {
  background: rgba(170, 230, 200, 0.1);
  border-color: rgba(170, 230, 200, 0.28);
  color: #b8e6c8;
}

.badge--status-pending {
  background: rgba(120, 170, 255, 0.12);
  border-color: rgba(120, 170, 255, 0.32);
  color: #a8c6ff;
}

.badge--status-revoked,
.badge--status-removed {
  background: rgba(240, 138, 138, 0.12);
  border-color: rgba(240, 138, 138, 0.32);
  color: #f4b3b3;
}

@media (max-width: 760px) {
  .view__controls {
    grid-template-columns: 1fr;
  }
}
</style>
