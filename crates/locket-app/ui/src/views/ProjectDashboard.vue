<script setup lang="ts">
import { computed } from 'vue';

import type {
  AuditLogRow,
  RuntimeSessionRow,
  ScanFindingRow,
  SecretRowMeta,
  SettingsState,
  VersionHistoryRow,
} from '../types/views';

type DashboardTarget = 'secrets' | 'versions' | 'execution' | 'audit' | 'scan' | 'settings';

interface Props {
  lockLabel: string;
  projectLabel: string;
  profileLabel: string;
  loading: boolean;
  secrets: SecretRowMeta[];
  versions: VersionHistoryRow[];
  sessions: RuntimeSessionRow[];
  auditRows: AuditLogRow[];
  findings: ScanFindingRow[];
  settings: SettingsState;
  auditChainOk: boolean;
}

const props = defineProps<Props>();

const emit = defineEmits<{
  (e: 'navigate', target: DashboardTarget): void;
  (e: 'refresh'): void;
}>();

const secretCount = computed<number>(() => props.secrets.length);
const deprecatedCount = computed<number>(
  () => props.versions.filter((row) => row.state === 'deprecated').length,
);
const runningSessionCount = computed<number>(
  () => props.sessions.filter((row) => row.state === 'running').length,
);
const failedSessionCount = computed<number>(
  () => props.sessions.filter((row) => row.state === 'failed' || row.state === 'stale').length,
);
const scanWarningCount = computed<number>(
  () => props.findings.filter((row) => row.severity === 'high' || row.severity === 'critical').length,
);
const auditIssueCount = computed<number>(
  () => props.auditRows.filter((row) => row.status !== 'OK' || !row.hmacOk).length,
);

const statusClass = computed<string>(() => {
  switch (props.lockLabel) {
    case 'Unlocked':
      return 'dashboard__status--ok';
    case 'Locked':
      return 'dashboard__status--locked';
    case 'Connecting…':
      return 'dashboard__status--pending';
    default:
      return 'dashboard__status--error';
  }
});

const healthRows = computed(() => [
  {
    label: 'Audit chain',
    value: props.auditChainOk ? 'verified' : 'attention',
    tone: props.auditChainOk ? 'ok' : 'warn',
  },
  {
    label: 'Scan warnings',
    value: scanWarningCount.value.toString(),
    tone: scanWarningCount.value === 0 ? 'ok' : 'warn',
  },
  {
    label: 'Runtime failures',
    value: failedSessionCount.value.toString(),
    tone: failedSessionCount.value === 0 ? 'ok' : 'warn',
  },
  {
    label: 'Privacy mode',
    value: props.settings.privacyRedactNames ? 'aliases' : 'exact names',
    tone: props.settings.privacyRedactNames ? 'ok' : 'neutral',
  },
]);

function navigate(target: DashboardTarget): void {
  emit('navigate', target);
}

function refresh(): void {
  emit('refresh');
}
</script>

<template>
  <section class="dashboard" aria-labelledby="project-dashboard-heading">
    <header class="dashboard__header">
      <div>
        <h2 id="project-dashboard-heading">Project dashboard</h2>
        <p class="dashboard__context">
          <span>{{ projectLabel }}</span>
          <span aria-hidden="true">/</span>
          <span>{{ profileLabel }}</span>
        </p>
      </div>
      <button type="button" class="dashboard__refresh" :disabled="loading" @click="refresh">
        {{ loading ? 'Refreshing' : 'Refresh' }}
      </button>
    </header>

    <section class="dashboard__status" aria-label="Agent status">
      <div :class="['dashboard__lock', statusClass]">
        <span class="dashboard__lock-label">Vault</span>
        <strong>{{ lockLabel }}</strong>
      </div>
      <dl class="dashboard__facts">
        <div>
          <dt>Agent</dt>
          <dd>{{ settings.agentVersion }}</dd>
        </div>
        <div>
          <dt>Unlock TTL</dt>
          <dd>{{ settings.unlockTtlSeconds }}s</dd>
        </div>
        <div>
          <dt>User verification</dt>
          <dd>{{ settings.requireUserVerification ? 'required' : 'not required' }}</dd>
        </div>
      </dl>
    </section>

    <section class="dashboard__metrics" aria-label="Project summary">
      <button type="button" class="dashboard__metric" @click="navigate('secrets')">
        <span>Secrets</span>
        <strong>{{ secretCount }}</strong>
      </button>
      <button type="button" class="dashboard__metric" @click="navigate('versions')">
        <span>Deprecated versions</span>
        <strong>{{ deprecatedCount }}</strong>
      </button>
      <button type="button" class="dashboard__metric" @click="navigate('execution')">
        <span>Running sessions</span>
        <strong>{{ runningSessionCount }}</strong>
      </button>
      <button type="button" class="dashboard__metric" @click="navigate('audit')">
        <span>Audit issues</span>
        <strong>{{ auditIssueCount }}</strong>
      </button>
    </section>

    <section class="dashboard__health" aria-labelledby="dashboard-health-heading">
      <h3 id="dashboard-health-heading">Health</h3>
      <ul>
        <li v-for="row in healthRows" :key="row.label">
          <span>{{ row.label }}</span>
          <strong :class="`dashboard__health-${row.tone}`">{{ row.value }}</strong>
        </li>
      </ul>
    </section>
  </section>
</template>

<style scoped>
.dashboard {
  color: #e6e8ec;
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

.dashboard__header,
.dashboard__status,
.dashboard__health {
  background: #0f1115;
  border-radius: 0.5rem;
  padding: 1rem;
}

.dashboard__header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 1rem;
}

.dashboard__header h2,
.dashboard__health h3 {
  margin: 0;
  font-size: 1rem;
  letter-spacing: 0.04em;
  text-transform: uppercase;
}

.dashboard__context {
  margin: 0.35rem 0 0;
  color: #9aa3b2;
  display: flex;
  gap: 0.4rem;
  min-width: 0;
}

.dashboard__context span {
  overflow-wrap: anywhere;
}

.dashboard__refresh,
.dashboard__metric {
  border: 1px solid rgba(255, 255, 255, 0.1);
  background: rgba(255, 255, 255, 0.04);
  color: #e6e8ec;
  cursor: pointer;
}

.dashboard__refresh {
  border-radius: 0.375rem;
  min-height: 2.25rem;
  padding: 0 0.875rem;
}

.dashboard__refresh:disabled {
  color: #6f7785;
  cursor: default;
}

.dashboard__status {
  display: grid;
  grid-template-columns: minmax(12rem, 0.4fr) 1fr;
  gap: 1rem;
}

.dashboard__lock {
  border-radius: 0.5rem;
  padding: 1rem;
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
  background: rgba(255, 255, 255, 0.04);
}

.dashboard__lock-label,
.dashboard__facts dt,
.dashboard__metric span,
.dashboard__health li span {
  color: #9aa3b2;
  font-size: 0.78rem;
}

.dashboard__lock strong {
  font-size: 1.5rem;
}

.dashboard__status--ok {
  color: #78d69d;
}

.dashboard__status--locked,
.dashboard__status--pending {
  color: #f8d77a;
}

.dashboard__status--error {
  color: #ff8a8a;
}

.dashboard__facts {
  margin: 0;
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 0.75rem;
}

.dashboard__facts div {
  min-width: 0;
}

.dashboard__facts dd {
  margin: 0.25rem 0 0;
  overflow-wrap: anywhere;
}

.dashboard__metrics {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 0.75rem;
}

.dashboard__metric {
  border-radius: 0.5rem;
  min-height: 6rem;
  padding: 0.875rem;
  text-align: left;
  display: flex;
  flex-direction: column;
  justify-content: space-between;
}

.dashboard__metric:hover,
.dashboard__metric:focus-visible,
.dashboard__refresh:hover,
.dashboard__refresh:focus-visible {
  border-color: rgba(248, 215, 122, 0.55);
  outline: none;
}

.dashboard__metric strong {
  font-size: 2rem;
}

.dashboard__health ul {
  margin: 0.75rem 0 0;
  padding: 0;
  list-style: none;
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 0.75rem;
}

.dashboard__health li {
  min-width: 0;
}

.dashboard__health li strong {
  display: block;
  margin-top: 0.25rem;
  overflow-wrap: anywhere;
}

.dashboard__health-ok {
  color: #78d69d;
}

.dashboard__health-warn {
  color: #f8d77a;
}

.dashboard__health-neutral {
  color: #e6e8ec;
}

@media (max-width: 860px) {
  .dashboard__status,
  .dashboard__facts,
  .dashboard__metrics,
  .dashboard__health ul {
    grid-template-columns: 1fr;
  }

  .dashboard__header {
    align-items: stretch;
    flex-direction: column;
  }
}
</style>
