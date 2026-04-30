<script setup lang="ts">
import { computed, ref } from 'vue';

import AgentUnavailableBanner from './components/AgentUnavailableBanner.vue';
import { useAgent } from './composables/useAgent';
import { useTray } from './composables/useTray';
import AuditLog from './views/AuditLog.vue';
import ExecutionMonitor from './views/ExecutionMonitor.vue';
import ProjectDashboard from './views/ProjectDashboard.vue';
import ScanResults from './views/ScanResults.vue';
import SecretMetadataList from './views/SecretMetadataList.vue';
import SecretVersionHistory from './views/SecretVersionHistory.vue';
import Settings from './views/Settings.vue';
import type {
  AuditLogRow,
  RuntimeSessionRow,
  ScanFindingRow,
  SecretRowMeta,
  SettingsState,
  VersionHistoryRow,
} from './types/views';

type ViewKey = 'dashboard' | 'secrets' | 'versions' | 'execution' | 'audit' | 'scan' | 'settings';

const { status, error, loading, refresh } = useAgent();
useTray(status, error);

const currentView = ref<ViewKey>('dashboard');

const navItems: ReadonlyArray<{ key: ViewKey; label: string }> = [
  { key: 'dashboard', label: 'Dashboard' },
  { key: 'secrets', label: 'Secrets' },
  { key: 'versions', label: 'Versions' },
  { key: 'execution', label: 'Execution' },
  { key: 'audit', label: 'Audit' },
  { key: 'scan', label: 'Scan' },
  { key: 'settings', label: 'Settings' },
];

const lockLabel = computed<string>(() => {
  if (loading.value && status.value === null && error.value === null) {
    return 'Connecting…';
  }
  if (status.value === null) {
    return 'Unavailable';
  }
  switch (status.value.lock_state) {
    case 'unlocked':
      return 'Unlocked';
    case 'locked':
      return 'Locked';
    case 'unknown':
      return 'Unknown';
    default:
      return 'Unknown';
  }
});

const projectLabel = computed<string>(() => status.value?.project_id ?? '—');
const profileLabel = computed<string>(() => status.value?.profile_name ?? '—');

// Slice 4-6/9-11 land real data sources. Today the views render with
// the empty arrays below so the navigation is exercisable end-to-end.
const secrets = ref<SecretRowMeta[]>([]);
const versions = ref<VersionHistoryRow[]>([]);
const sessions = ref<RuntimeSessionRow[]>([]);
const auditRows = ref<AuditLogRow[]>([]);
const findings = ref<ScanFindingRow[]>([]);
const scanning = ref<boolean>(false);
const auditChainOk = ref<boolean>(true);

const settings = ref<SettingsState>({
  privacyRedactNames: false,
  unlockTtlSeconds: 0,
  requireUserVerification: false,
  dangerousProfileFlag: false,
  agentVersion: status.value?.agent_version ?? 'unknown',
});

function applySettingsPatch(patch: Partial<SettingsState>): void {
  settings.value = { ...settings.value, ...patch };
}

function selectView(key: ViewKey): void {
  currentView.value = key;
}

function selectSecret(): void {
  currentView.value = 'versions';
}

function triggerVerify(): void {
  void refresh();
}

function triggerRescan(): void {
  scanning.value = true;
  setTimeout(() => {
    scanning.value = false;
  }, 250);
}
</script>

<template>
  <div class="shell">
    <aside class="shell__nav" aria-label="Primary navigation">
      <div class="shell__brand">
        <h1>Locket</h1>
        <dl class="shell__status">
          <dt>Vault</dt>
          <dd>{{ lockLabel }}</dd>
          <dt>Project</dt>
          <dd>{{ projectLabel }}</dd>
          <dt>Profile</dt>
          <dd>{{ profileLabel }}</dd>
        </dl>
      </div>

      <nav>
        <ul>
          <li v-for="item in navItems" :key="item.key">
            <button
              type="button"
              :class="['shell__nav-item', { 'shell__nav-item--active': currentView === item.key }]"
              :aria-current="currentView === item.key ? 'page' : undefined"
              @click="selectView(item.key)"
            >
              {{ item.label }}
            </button>
          </li>
        </ul>
      </nav>
    </aside>

    <main class="shell__main">
      <AgentUnavailableBanner v-if="error" :error="error" />

      <ProjectDashboard
        v-if="currentView === 'dashboard'"
        :lock-label="lockLabel"
        :project-label="projectLabel"
        :profile-label="profileLabel"
        :loading="loading"
        :secrets="secrets"
        :versions="versions"
        :sessions="sessions"
        :audit-rows="auditRows"
        :findings="findings"
        :settings="settings"
        :audit-chain-ok="auditChainOk"
        @navigate="selectView"
        @refresh="triggerVerify"
      />

      <SecretMetadataList
        v-else-if="currentView === 'secrets'"
        :rows="secrets"
        :privacy-mode="settings.privacyRedactNames"
        :loading="loading"
        @select="selectSecret"
      />

      <SecretVersionHistory
        v-else-if="currentView === 'versions'"
        :rows="versions"
        secret-label="—"
      />

      <ExecutionMonitor
        v-else-if="currentView === 'execution'"
        :rows="sessions"
        :privacy-mode="settings.privacyRedactNames"
      />

      <AuditLog
        v-else-if="currentView === 'audit'"
        :rows="auditRows"
        :privacy-mode="settings.privacyRedactNames"
        :chain-ok="auditChainOk"
        @verify="triggerVerify"
      />

      <ScanResults
        v-else-if="currentView === 'scan'"
        :findings="findings"
        :scanning="scanning"
        @rescan="triggerRescan"
      />

      <Settings
        v-else-if="currentView === 'settings'"
        :state="settings"
        @update="applySettingsPatch"
      />
    </main>
  </div>
</template>

<style>
:root {
  color-scheme: light dark;
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
}

body,
html,
#app {
  margin: 0;
  height: 100vh;
  background: #0f1115;
  color: #e6e8ec;
}

.shell {
  display: grid;
  grid-template-columns: 220px 1fr;
  min-height: 100vh;
}

.shell__nav {
  background: #0b0d11;
  border-right: 1px solid rgba(255, 255, 255, 0.06);
  padding: 1.25rem 0.875rem;
  display: flex;
  flex-direction: column;
  gap: 1.5rem;
}

.shell__brand h1 {
  margin: 0 0 0.875rem;
  font-size: 1rem;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  color: #f8d77a;
}

.shell__status {
  margin: 0;
  font-size: 0.75rem;
  display: grid;
  grid-template-columns: auto 1fr;
  column-gap: 0.5rem;
  row-gap: 0.25rem;
  color: #9aa3b2;
}

.shell__status dt {
  font-weight: 500;
}

.shell__status dd {
  margin: 0;
  color: #e6e8ec;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.shell__nav nav ul {
  list-style: none;
  margin: 0;
  padding: 0;
  display: flex;
  flex-direction: column;
  gap: 0.125rem;
}

.shell__nav-item {
  width: 100%;
  text-align: left;
  background: transparent;
  border: 0;
  padding: 0.5rem 0.625rem;
  border-radius: 0.375rem;
  font-size: 0.875rem;
  color: #c5cbd6;
  cursor: pointer;
}

.shell__nav-item:hover {
  background: rgba(255, 255, 255, 0.04);
  color: #e6e8ec;
}

.shell__nav-item:focus-visible {
  outline: 2px solid #f8d77a;
  outline-offset: 2px;
}

.shell__nav-item--active {
  background: rgba(248, 215, 122, 0.12);
  color: #f8d77a;
}

.shell__main {
  padding: 1.5rem 2rem;
  display: flex;
  flex-direction: column;
  gap: 1.5rem;
  overflow: auto;
}
</style>
