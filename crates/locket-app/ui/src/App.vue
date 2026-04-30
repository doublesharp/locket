<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from 'vue';
import { listen, type UnlistenFn } from '@tauri-apps/api/event';

import AgentUnavailableBanner from './components/AgentUnavailableBanner.vue';
import { listRuntimeSessions, lockVault, scan as scanKnownValues } from './agent/client';
import { runtimeSessionRow } from './agent/runtimeSessions';
import { useAgent } from './composables/useAgent';
import { useTray } from './composables/useTray';
import AuditLog from './views/AuditLog.vue';
import BackupRecovery from './views/BackupRecovery.vue';
import DeviceMemberDirectory from './views/DeviceMemberDirectory.vue';
import ExecutionMonitor from './views/ExecutionMonitor.vue';
import PolicyEditor from './views/PolicyEditor.vue';
import ProjectDashboard from './views/ProjectDashboard.vue';
import ScanResults from './views/ScanResults.vue';
import SecretMetadataList from './views/SecretMetadataList.vue';
import SecretVersionHistory from './views/SecretVersionHistory.vue';
import Settings from './views/Settings.vue';
import type {
  AuditLogRow,
  CommandPolicyRow,
  DeviceMemberRow,
  RuntimeSessionRow,
  ScanFindingRow,
  SecretRowMeta,
  SettingsState,
  VersionHistoryRow,
} from './types/views';
import type { AgentClientError, ListRuntimeSessionsRequest, ScanFinding } from './agent/types';
import { privacyAlias, privacyLabel } from './utils/privacy';

type ViewKey =
  | 'dashboard'
  | 'secrets'
  | 'versions'
  | 'execution'
  | 'devices'
  | 'audit'
  | 'scan'
  | 'policies'
  | 'recovery'
  | 'settings';

const { status, error, loading, refresh } = useAgent();
useTray(status, error);

const currentView = ref<ViewKey>('dashboard');
let unlistenTrayMenu: UnlistenFn | null = null;

type TrayMenuAction =
  | 'open-app'
  | 'lock-vault'
  | 'unlock-vault'
  | 'switch-profile'
  | 'run-policy'
  | 'start-scan';

const navItems: ReadonlyArray<{ key: ViewKey; label: string }> = [
  { key: 'dashboard', label: 'Dashboard' },
  { key: 'secrets', label: 'Secrets' },
  { key: 'versions', label: 'Versions' },
  { key: 'execution', label: 'Execution' },
  { key: 'devices', label: 'Devices' },
  { key: 'audit', label: 'Audit' },
  { key: 'scan', label: 'Scan' },
  { key: 'policies', label: 'Policies' },
  { key: 'recovery', label: 'Recovery' },
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

const projectAlias = ref<string | null>(null);
const profileAlias = ref<string | null>(null);

const projectLabel = computed<string>(() =>
  privacyLabel('project', status.value?.project_id, settings.value.privacyRedactNames, projectAlias.value),
);
const profileLabel = computed<string>(() =>
  privacyLabel('profile', status.value?.profile_name, settings.value.privacyRedactNames, profileAlias.value),
);

// Slice 4-5/9-11 land the remaining real data sources. The execution
// monitor is populated from the agent's metadata-only session RPC.
const secrets = ref<SecretRowMeta[]>([]);
const versions = ref<VersionHistoryRow[]>([]);
const sessions = ref<RuntimeSessionRow[]>([]);
const deviceMembers = ref<DeviceMemberRow[]>([]);
const auditRows = ref<AuditLogRow[]>([]);
const findings = ref<ScanFindingRow[]>([]);
const policies = ref<CommandPolicyRow[]>([]);
const sessionsLoading = ref<boolean>(false);
const sessionsError = ref<string | null>(null);
const sessionsLastRefreshed = ref<string | undefined>(undefined);
const scanning = ref<boolean>(false);
const scanLocked = ref<boolean>(false);
const scanError = ref<string | null>(null);
const lastScanAt = ref<string | undefined>(undefined);
const auditChainOk = ref<boolean>(true);

const settings = ref<SettingsState>({
  privacyRedactNames: false,
  unlockTtlSeconds: 0,
  requireUserVerification: false,
  dangerousProfileFlag: false,
  agentVersion: status.value?.agent_version ?? 'unknown',
});

watch(
  [status, () => settings.value.privacyRedactNames],
  ([nextStatus, redactNames]) => {
    const projectId = nextStatus?.project_id ?? null;
    const profileName = nextStatus?.profile_name ?? null;

    projectAlias.value = null;
    profileAlias.value = null;

    if (!redactNames) {
      return;
    }

    if (projectId !== null && projectId.length > 0) {
      void privacyAlias('project', projectId)
        .then((alias) => {
          if (settings.value.privacyRedactNames && status.value?.project_id === projectId) {
            projectAlias.value = alias;
          }
        })
        .catch(() => {});
    }
    if (profileName !== null && profileName.length > 0) {
      void privacyAlias('profile', profileName)
        .then((alias) => {
          if (settings.value.privacyRedactNames && status.value?.profile_name === profileName) {
            profileAlias.value = alias;
          }
        })
        .catch(() => {});
    }
  },
  { immediate: true },
);

function applySettingsPatch(patch: Partial<SettingsState>): void {
  settings.value = { ...settings.value, ...patch };
}

function selectView(key: ViewKey): void {
  currentView.value = key;
}

async function handleTrayMenuAction(action: TrayMenuAction): Promise<void> {
  switch (action) {
    case 'open-app':
      currentView.value = 'dashboard';
      break;
    case 'lock-vault':
      await lockVault();
      await refresh();
      break;
    case 'unlock-vault':
    case 'switch-profile':
      currentView.value = 'settings';
      break;
    case 'run-policy':
      currentView.value = 'policies';
      break;
    case 'start-scan':
      currentView.value = 'scan';
      await triggerRescan();
      break;
    default:
      break;
  }
}

function selectSecret(): void {
  currentView.value = 'versions';
}

function triggerVerify(): void {
  void refresh();
  void refreshRuntimeSessions();
}

const runtimeSessionRequest = computed<ListRuntimeSessionsRequest | null>(() => {
  const currentStatus = status.value;
  if (currentStatus?.project_id === null || currentStatus?.project_id === undefined) {
    return null;
  }
  if (currentStatus.profile_name === null || currentStatus.profile_name === undefined) {
    return null;
  }
  return {
    project_id: currentStatus.project_id,
    profile_id: currentStatus.profile_name,
    privacy_redact_names: settings.value.privacyRedactNames,
  };
});

function sessionErrorLabel(error: AgentClientError): string {
  switch (error.kind) {
    case 'unavailable':
      return 'Agent unavailable.';
    case 'protocol':
      return 'Session request failed.';
    case 'rejected':
      return error.code;
    default:
      return 'Session request failed.';
  }
}

let sessionRefreshSequence = 0;

async function refreshRuntimeSessions(): Promise<void> {
  const request = runtimeSessionRequest.value;
  const sequence = (sessionRefreshSequence += 1);
  if (request === null) {
    sessions.value = [];
    sessionsError.value = null;
    sessionsLoading.value = false;
    sessionsLastRefreshed.value = undefined;
    return;
  }

  sessionsLoading.value = true;
  sessionsError.value = null;
  const result = await listRuntimeSessions(request);
  if (sequence !== sessionRefreshSequence) {
    return;
  }
  if (result.ok) {
    sessions.value = result.value.rows.map(runtimeSessionRow);
    sessionsLastRefreshed.value = new Date().toISOString();
  } else {
    sessions.value = [];
    sessionsError.value = sessionErrorLabel(result.error);
  }
  sessionsLoading.value = false;
}

watch(runtimeSessionRequest, () => {
  void refreshRuntimeSessions();
});

function scanErrorLabel(error: AgentClientError): string {
  switch (error.kind) {
    case 'unavailable':
      return 'Agent unavailable.';
    case 'protocol':
      return 'Scan request failed.';
    case 'rejected':
      return error.code;
    default:
      return 'Scan request failed.';
  }
}

function normalizeSeverity(severity: string): ScanFindingRow['severity'] {
  switch (severity.toLowerCase()) {
    case 'critical':
      return 'critical';
    case 'high':
    case 'error':
      return 'high';
    case 'medium':
    case 'warn':
    case 'warning':
      return 'medium';
    default:
      return 'low';
  }
}

function scanFindingRow(finding: ScanFinding, index: number): ScanFindingRow {
  return {
    id: `${finding.path}:${finding.line}:${finding.column}:${finding.rule}:${index}`,
    rule: finding.rule,
    severity: normalizeSeverity(finding.severity),
    path: finding.path,
    line: finding.line,
    column: finding.column,
    redactedSummary: finding.redacted_summary,
    suppressedBy: finding.suppressed_by ?? undefined,
  };
}

async function triggerRescan(): Promise<void> {
  scanning.value = true;
  scanError.value = null;
  const result = await scanKnownValues({ paths: [], require_known: false });
  if (result.ok) {
    findings.value = result.value.findings.map(scanFindingRow);
    scanLocked.value = result.value.locked;
    lastScanAt.value = new Date().toISOString();
  } else {
    findings.value = [];
    scanLocked.value = false;
    scanError.value = scanErrorLabel(result.error);
  }
  scanning.value = false;
}

function triggerBackupAction(): void {
  void refresh();
}

onMounted(() => {
  void listen<TrayMenuAction>('tray-menu-action', (event) => {
    void handleTrayMenuAction(event.payload);
  })
    .then((unlisten) => {
      unlistenTrayMenu = unlisten;
    })
    .catch(() => {});
});

onUnmounted(() => {
  unlistenTrayMenu?.();
  unlistenTrayMenu = null;
});
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
        :loading="sessionsLoading"
        :error-message="sessionsError"
        :last-refreshed-at="sessionsLastRefreshed"
        @refresh="refreshRuntimeSessions"
      />

      <DeviceMemberDirectory
        v-else-if="currentView === 'devices'"
        :rows="deviceMembers"
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
        :locked="scanLocked"
        :error-message="scanError"
        :last-scan-at="lastScanAt"
        @rescan="triggerRescan"
      />

      <PolicyEditor
        v-else-if="currentView === 'policies'"
        :rows="policies"
        :privacy-mode="settings.privacyRedactNames"
        :loading="loading"
      />

      <BackupRecovery
        v-else-if="currentView === 'recovery'"
        @action="triggerBackupAction"
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
