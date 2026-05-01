<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from 'vue';
import { invoke, isTauri } from '@tauri-apps/api/core';
import { listen, type UnlistenFn } from '@tauri-apps/api/event';

import AgentUnavailableBanner from './components/AgentUnavailableBanner.vue';
import PolicyEditorForm from './components/PolicyEditorForm.vue';
import ProfileSwitcherView from './views/ProfileSwitcherView.vue';
import RevealModal from './components/RevealModal.vue';
import {
  copySecret,
  listAudit,
  listDeviceMembers,
  listPolicies,
  listRuntimeSessions,
  listSecrets,
  listVersions,
  lockVault,
  readConfig,
  registerCommandPolicies,
  reveal as revealAgent,
  scan as scanKnownValues,
  setActiveProfile,
  writeConfig,
  verifyAudit,
} from './agent/client';
import {
  applyPolicyMutation,
  type PolicyFormMode,
} from './policy/form';
import {
  rememberTarget,
  type ProfileSwitchState,
} from './profile/switcher';
import type { CommandPolicySnapshotWire } from './agent/types';
import { deviceMemberRow } from './agent/deviceMembers';
import { commandPolicyRow } from './agent/policies';
import { runtimeSessionRow } from './agent/runtimeSessions';
import { secretRow } from './agent/secrets';
import { versionHistoryRow } from './agent/versions';
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
import TeamInviteView from './views/TeamInviteView.vue';
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
import type {
  AgentClientError,
  AgentConfigSettings,
  AuditChainStatus,
  AuditWireRow,
  ListAuditRequest,
  ListDeviceMembersRequest,
  ListPoliciesRequest,
  ListRuntimeSessionsRequest,
  ListSecretsRequest,
  ListVersionsRequest,
  ScanFinding,
  WriteConfigChanges,
} from './agent/types';
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
  | 'profiles'
  | 'team'
  | 'recovery'
  | 'settings';

const { status, error, loading, lastSeenAt, connected, refresh } = useAgent();
useTray(status, error);

const connectionLabel = computed<string>(() => {
  if (!connected.value) {
    return 'Reconnecting…';
  }
  if (lastSeenAt.value === null) {
    return 'Connected';
  }
  return `Live · ${formatLastSeen(lastSeenAt.value)}`;
});

const connectionTone = computed<'ok' | 'warn'>(() => (connected.value ? 'ok' : 'warn'));

function formatLastSeen(iso: string): string {
  const parsed = Date.parse(iso);
  if (Number.isNaN(parsed)) {
    return 'just now';
  }
  const seconds = Math.max(0, Math.round((Date.now() - parsed) / 1000));
  if (seconds < 5) {
    return 'just now';
  }
  if (seconds < 60) {
    return `${seconds.toString()}s ago`;
  }
  const minutes = Math.round(seconds / 60);
  return `${minutes.toString()}m ago`;
}

const currentView = ref<ViewKey>('dashboard');
const revealModal = ref<InstanceType<typeof RevealModal> | null>(null);
const copyError = ref<string | null>(null);
const revealError = ref<string | null>(null);
let unlistenTrayMenu: UnlistenFn | null = null;

type TrayMenuAction =
  | 'open-app'
  | 'lock-vault'
  | 'unlock-vault'
  | 'switch-profile'
  | 'run-policy'
  | 'start-scan'
  | 'reveal-secret'
  | 'copy-secret';

const navItems: ReadonlyArray<{ key: ViewKey; label: string }> = [
  { key: 'dashboard', label: 'Dashboard' },
  { key: 'secrets', label: 'Secrets' },
  { key: 'versions', label: 'Versions' },
  { key: 'execution', label: 'Execution' },
  { key: 'devices', label: 'Devices' },
  { key: 'audit', label: 'Audit' },
  { key: 'scan', label: 'Scan' },
  { key: 'policies', label: 'Policies' },
  { key: 'profiles', label: 'Profiles' },
  { key: 'team', label: 'Team' },
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
  privacyLabel(
    'project',
    status.value?.project_id,
    settings.value.privacyRedactNames,
    projectAlias.value,
  ),
);
const profileLabel = computed<string>(() =>
  privacyLabel(
    'profile',
    status.value?.profile_name,
    settings.value.privacyRedactNames,
    profileAlias.value,
  ),
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
const rawAuditRows = ref<AuditWireRow[]>([]);
const teamInviteNotice = ref<string | null>(null);
const secretsLoading = ref<boolean>(false);
const secretsError = ref<string | null>(null);
const secretsLastRefreshed = ref<string | undefined>(undefined);
const versionsLoading = ref<boolean>(false);
const versionsError = ref<string | null>(null);
const versionsLastRefreshed = ref<string | undefined>(undefined);
const sessionsLoading = ref<boolean>(false);
const sessionsError = ref<string | null>(null);
const sessionsLastRefreshed = ref<string | undefined>(undefined);
const deviceMembersLoading = ref<boolean>(false);
const deviceMembersError = ref<string | null>(null);
const deviceMembersLastRefreshed = ref<string | undefined>(undefined);
const policiesLoading = ref<boolean>(false);
const policiesError = ref<string | null>(null);
const settingsLoading = ref<boolean>(false);
const settingsError = ref<string | null>(null);
const auditLoading = ref<boolean>(false);
const auditError = ref<string | null>(null);
const auditLastRefreshed = ref<string | undefined>(undefined);
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

function durationSeconds(value: string | null): number {
  if (value === null) {
    return 0;
  }
  const match = /^(\d+)(ms|s|m|h)?$/.exec(value.trim());
  if (match === null) {
    return 0;
  }
  const amount = Number.parseInt(match[1] ?? '0', 10);
  switch (match[2] ?? 's') {
    case 'ms':
      return Math.ceil(amount / 1000);
    case 'm':
      return amount * 60;
    case 'h':
      return amount * 3600;
    default:
      return amount;
  }
}

function verificationRequired(settings: AgentConfigSettings): boolean {
  return Object.values(settings.user_verification_required_for).some((value) => value);
}

function applyAgentConfig(config: AgentConfigSettings): void {
  settings.value = {
    ...settings.value,
    privacyRedactNames: config.privacy_redact_names,
    unlockTtlSeconds: durationSeconds(config.agent_unlock_ttl),
    requireUserVerification: verificationRequired(config),
    dangerousProfileFlag: config.dangerous_profile?.dangerous ?? false,
    agentVersion: status.value?.agent_version ?? settings.value.agentVersion,
  };
}

function settingsErrorLabel(error: AgentClientError): string {
  switch (error.kind) {
    case 'unavailable':
      return 'Agent unavailable.';
    case 'protocol':
      return 'Settings request failed.';
    case 'rejected':
      return error.code;
    default:
      return 'Settings request failed.';
  }
}

async function refreshSettings(): Promise<void> {
  settingsLoading.value = true;
  settingsError.value = null;
  const currentStatus = status.value;
  const result = await readConfig({
    project_id: currentStatus?.project_id ?? null,
    profile_name: currentStatus?.profile_name ?? null,
  });
  if (result.ok) {
    applyAgentConfig(result.value);
  } else {
    settingsError.value = settingsErrorLabel(result.error);
  }
  settingsLoading.value = false;
}

async function handleSettingsPatch(patch: Partial<SettingsState>): Promise<void> {
  applySettingsPatch(patch);

  if (!('privacyRedactNames' in patch)) {
    return;
  }
  const projectId = status.value?.project_id;
  if (projectId === null || projectId === undefined) {
    return;
  }
  const changes: WriteConfigChanges = {
    privacy_redact_names: patch.privacyRedactNames ?? false,
  };
  settingsLoading.value = true;
  settingsError.value = null;
  const result = await writeConfig({
    project_id: projectId,
    profile_name: status.value?.profile_name ?? null,
    changes,
  });
  if (result.ok) {
    applyAgentConfig(result.value.settings);
  } else {
    settingsError.value = settingsErrorLabel(result.error);
  }
  settingsLoading.value = false;
}

const settingsContextKey = computed<string>(
  () => `${status.value?.project_id ?? ''}:${status.value?.profile_name ?? ''}`,
);

watch(
  status,
  () => {
    settings.value = {
      ...settings.value,
      agentVersion: status.value?.agent_version ?? 'unknown',
    };
  },
  { immediate: true },
);

watch(
  settingsContextKey,
  () => {
    void refreshSettings();
  },
  { immediate: true },
);

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
      currentView.value = 'settings';
      break;
    case 'switch-profile':
      currentView.value = 'profiles';
      break;
    case 'run-policy':
      currentView.value = 'policies';
      break;
    case 'start-scan':
      currentView.value = 'scan';
      await triggerRescan();
      break;
    case 'reveal-secret':
      currentView.value = 'secrets';
      await handleRevealSelectedSecret();
      break;
    case 'copy-secret':
      currentView.value = 'secrets';
      await handleCopySelectedSecret();
      break;
    default:
      break;
  }
}

const selectedSecret = ref<SecretRowMeta | null>(null);

function selectSecret(row?: SecretRowMeta): void {
  if (row !== undefined) {
    selectedSecret.value = row;
  }
  currentView.value = 'versions';
}

/** Generic, name-free label for the reveal modal heading. */
function secretLabel(row: SecretRowMeta | null, redactNames: boolean): string {
  if (row === null) {
    return 'Secret';
  }
  if (redactNames) {
    return row.alias ?? 'Secret';
  }
  return row.name;
}

async function pushTraySelection(): Promise<void> {
  if (!isTauri()) {
    return;
  }
  const selection = {
    vault_unlocked: status.value?.lock_state === 'unlocked',
    secret_selected: selectedSecret.value !== null,
  };
  try {
    await invoke<void>('tray_set_selection', { selection });
  } catch {
    // Tray refresh failures are local-only; the next change will retry.
  }
}

watch(
  [
    () => status.value?.lock_state,
    selectedSecret,
  ],
  () => {
    void pushTraySelection();
  },
  { immediate: true },
);

async function handleRevealSelectedSecret(): Promise<void> {
  revealError.value = null;
  const target = selectedSecret.value;
  if (target === null) {
    revealError.value = 'Select a secret in the list before revealing.';
    return;
  }
  const profileId = status.value?.profile_name;
  if (profileId === null || profileId === undefined) {
    revealError.value = 'Active profile unavailable.';
    return;
  }
  const result = await revealAgent({
    secret_name: target.name,
    profile_id: profileId,
  });
  if (!result.ok) {
    revealError.value = revealErrorLabel(result.error);
    return;
  }
  revealModal.value?.show({
    secretLabel: secretLabel(target, settings.value.privacyRedactNames),
    value: result.value.value,
    ttlSeconds: result.value.ttl_seconds,
  });
}

function revealErrorLabel(err: AgentClientError): string {
  switch (err.kind) {
    case 'unavailable':
      return 'Agent unavailable.';
    case 'protocol':
      return 'Reveal request failed.';
    case 'rejected':
      return err.code;
    default:
      return 'Reveal request failed.';
  }
}

async function handleCopySelectedSecret(): Promise<void> {
  copyError.value = null;
  const target = selectedSecret.value;
  if (target === null) {
    copyError.value = 'Select a secret in the list before copying.';
    return;
  }
  const profileId = status.value?.profile_name;
  if (profileId === null || profileId === undefined) {
    copyError.value = 'Active profile unavailable.';
    return;
  }
  const result = await copySecret({
    secret_name: target.name,
    profile_id: profileId,
    project_id: status.value?.project_id ?? undefined,
  });
  if (!result.ok) {
    copyError.value = revealErrorLabel(result.error);
    return;
  }
  if (result.value.kind === 'unsupported') {
    copyError.value = `Clipboard unavailable: ${result.value.unsupported_reason}.`;
  }
}

function triggerVerify(): void {
  void refresh();
  void refreshSecrets();
  void refreshVersions();
  void refreshRuntimeSessions();
  void refreshDeviceMembers();
  void refreshPolicies();
  void refreshAuditLog();
  void verifyAuditChain();
}

function nowUnixNanos(): number {
  return Date.now() * 1_000_000;
}

const secretsRequest = computed<ListSecretsRequest | null>(() => {
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
    redact_names: settings.value.privacyRedactNames,
  };
});

const versionsRequest = computed<ListVersionsRequest | null>(() => {
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
    now_unix_nanos: nowUnixNanos(),
    redact_names: settings.value.privacyRedactNames,
  };
});

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

const policiesRequest = computed<ListPoliciesRequest | null>(() => {
  const projectId = status.value?.project_id;
  if (projectId === null || projectId === undefined) {
    return null;
  }
  return {
    project_id: projectId,
    privacy_redact_names: settings.value.privacyRedactNames,
  };
});

const deviceMembersRequest = computed<ListDeviceMembersRequest | null>(() => {
  const projectId = status.value?.project_id;
  if (projectId === null || projectId === undefined) {
    return null;
  }
  return {
    project_id: projectId,
    redact_names: settings.value.privacyRedactNames,
    include_revoked_devices: true,
  };
});

function secretErrorLabel(error: AgentClientError): string {
  switch (error.kind) {
    case 'unavailable':
      return 'Agent unavailable.';
    case 'protocol':
      return 'Secret request failed.';
    case 'rejected':
      return error.code;
    default:
      return 'Secret request failed.';
  }
}

let secretRefreshSequence = 0;

async function refreshSecrets(): Promise<void> {
  const request = secretsRequest.value;
  const sequence = (secretRefreshSequence += 1);
  if (request === null) {
    secrets.value = [];
    secretsError.value = null;
    secretsLoading.value = false;
    secretsLastRefreshed.value = undefined;
    return;
  }

  secretsLoading.value = true;
  secretsError.value = null;
  const result = await listSecrets(request);
  if (sequence !== secretRefreshSequence) {
    return;
  }
  if (result.ok) {
    secrets.value = result.value.rows.map(secretRow);
    secretsLastRefreshed.value = new Date().toISOString();
  } else {
    secrets.value = [];
    secretsError.value = secretErrorLabel(result.error);
  }
  secretsLoading.value = false;
}

watch(secretsRequest, () => {
  selectedSecret.value = null;
  void refreshSecrets();
});

function versionErrorLabel(error: AgentClientError): string {
  switch (error.kind) {
    case 'unavailable':
      return 'Agent unavailable.';
    case 'protocol':
      return 'Version request failed.';
    case 'rejected':
      return error.code;
    default:
      return 'Version request failed.';
  }
}

let versionRefreshSequence = 0;

async function refreshVersions(): Promise<void> {
  const request = versionsRequest.value;
  const sequence = (versionRefreshSequence += 1);
  if (request === null) {
    versions.value = [];
    versionsError.value = null;
    versionsLoading.value = false;
    versionsLastRefreshed.value = undefined;
    return;
  }

  versionsLoading.value = true;
  versionsError.value = null;
  const result = await listVersions({ ...request, now_unix_nanos: nowUnixNanos() });
  if (sequence !== versionRefreshSequence) {
    return;
  }
  if (result.ok) {
    versions.value = result.value.rows.map(versionHistoryRow);
    versionsLastRefreshed.value = new Date().toISOString();
  } else {
    versions.value = [];
    versionsError.value = versionErrorLabel(result.error);
  }
  versionsLoading.value = false;
}

watch(versionsRequest, () => {
  void refreshVersions();
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

function policyErrorLabel(error: AgentClientError): string {
  switch (error.kind) {
    case 'unavailable':
      return 'Agent unavailable.';
    case 'protocol':
      return 'Policy request failed.';
    case 'rejected':
      return error.code;
    default:
      return 'Policy request failed.';
  }
}

let policyRefreshSequence = 0;

async function refreshPolicies(): Promise<void> {
  const request = policiesRequest.value;
  const sequence = (policyRefreshSequence += 1);
  if (request === null) {
    policies.value = [];
    policiesError.value = null;
    policiesLoading.value = false;
    return;
  }

  policiesLoading.value = true;
  policiesError.value = null;
  const result = await listPolicies(request);
  if (sequence !== policyRefreshSequence) {
    return;
  }
  if (result.ok) {
    policies.value = result.value.rows.map(commandPolicyRow);
  } else {
    policies.value = [];
    policiesError.value = policyErrorLabel(result.error);
  }
  policiesLoading.value = false;
}

watch(policiesRequest, () => {
  void refreshPolicies();
});

const profileSwitchState = ref<ProfileSwitchState>({
  activeProfile: null,
  activeDangerous: false,
  recentTargets: [],
});
const profileSwitchInProgress = ref<boolean>(false);
const profileSwitchError = ref<string | null>(null);
const profileSwitchLastAt = ref<string | undefined>(undefined);

watch(
  [
    () => status.value?.profile_name ?? null,
    () => settings.value.dangerousProfileFlag,
  ],
  ([nextProfile, nextDangerous]) => {
    profileSwitchState.value = {
      ...profileSwitchState.value,
      activeProfile: nextProfile,
      activeDangerous: nextDangerous,
    };
  },
  { immediate: true },
);

async function handleProfileSwitch(payload: {
  profileName: string;
  confirmation: string | undefined;
  dangerous: boolean;
}): Promise<void> {
  const projectId = status.value?.project_id;
  if (projectId === null || projectId === undefined) {
    profileSwitchError.value = 'Active project unavailable.';
    return;
  }
  profileSwitchInProgress.value = true;
  profileSwitchError.value = null;
  const result = await setActiveProfile({
    project_id: projectId,
    profile_name: payload.profileName,
    confirmation: payload.confirmation,
    privacy_redact_names: settings.value.privacyRedactNames,
  });
  profileSwitchInProgress.value = false;
  if (!result.ok) {
    profileSwitchError.value = profileSwitchErrorLabel(result.error);
    return;
  }
  profileSwitchState.value = rememberTarget(profileSwitchState.value, payload.profileName);
  profileSwitchLastAt.value = new Date().toISOString();
  await refresh();
}

function profileSwitchErrorLabel(err: AgentClientError): string {
  switch (err.kind) {
    case 'unavailable':
      return 'Agent unavailable.';
    case 'protocol':
      return 'Profile switch failed.';
    case 'rejected':
      return err.code;
    default:
      return 'Profile switch failed.';
  }
}

const policyFormMode = ref<PolicyFormMode | null>(null);
const policyFormRow = ref<CommandPolicyRow | null>(null);
const policyFormSubmitting = ref<boolean>(false);
const policyFormError = ref<string | null>(null);

function openPolicyCreate(): void {
  policyFormMode.value = 'create';
  policyFormRow.value = null;
  policyFormError.value = null;
}

function openPolicyEdit(row: CommandPolicyRow): void {
  policyFormMode.value = 'edit';
  policyFormRow.value = row;
  policyFormError.value = null;
}

function openPolicyDelete(row: CommandPolicyRow): void {
  policyFormMode.value = 'delete';
  policyFormRow.value = row;
  policyFormError.value = null;
}

function dismissPolicyForm(): void {
  policyFormMode.value = null;
  policyFormRow.value = null;
  policyFormError.value = null;
}

function snapshotsFromCurrentRows(): CommandPolicySnapshotWire[] {
  const projectId = status.value?.project_id ?? '';
  return policies.value.map<CommandPolicySnapshotWire>((row) => ({
    project_id: projectId,
    name: row.name,
    command_kind: row.commandKind,
    command_preview: row.commandPreview,
    required_secrets: row.requiredSecrets,
    optional_secrets: row.optionalSecrets,
    allowed_secrets: row.allowedSecrets,
    confirm: row.confirm,
    require_user_verification: row.requireUserVerification,
    require_agent: false,
    allow_remote_docker: row.allowRemoteDocker,
    ttl_seconds: row.ttlSeconds,
    env_mode: row.envMode,
    override_mode: row.overrideMode,
    updated_at_unix_nanos: Date.parse(row.updatedAt) * 1_000_000,
  }));
}

async function submitPolicyForm(payload: {
  mode: PolicyFormMode;
  snapshot: CommandPolicySnapshotWire;
  originalName: string;
}): Promise<void> {
  const projectId = status.value?.project_id;
  if (projectId === null || projectId === undefined) {
    policyFormError.value = 'Active project unavailable.';
    return;
  }
  policyFormSubmitting.value = true;
  policyFormError.value = null;
  const next = applyPolicyMutation(
    snapshotsFromCurrentRows(),
    payload.mode,
    payload.snapshot,
    payload.originalName,
  );
  const result = await registerCommandPolicies({
    project_id: projectId,
    policies: next,
    audit_profile_id: status.value?.profile_name ?? undefined,
  });
  policyFormSubmitting.value = false;
  if (!result.ok) {
    policyFormError.value = policyErrorLabel(result.error);
    return;
  }
  dismissPolicyForm();
  await refreshPolicies();
}

function deviceMemberErrorLabel(error: AgentClientError): string {
  switch (error.kind) {
    case 'unavailable':
      return 'Agent unavailable.';
    case 'protocol':
      return 'Device request failed.';
    case 'rejected':
      return error.code;
    default:
      return 'Device request failed.';
  }
}

let deviceMembersRefreshSequence = 0;

async function refreshDeviceMembers(): Promise<void> {
  const request = deviceMembersRequest.value;
  const sequence = (deviceMembersRefreshSequence += 1);
  if (request === null) {
    deviceMembers.value = [];
    deviceMembersError.value = null;
    deviceMembersLoading.value = false;
    deviceMembersLastRefreshed.value = undefined;
    return;
  }

  deviceMembersLoading.value = true;
  deviceMembersError.value = null;
  const result = await listDeviceMembers(request);
  if (sequence !== deviceMembersRefreshSequence) {
    return;
  }
  if (result.ok) {
    deviceMembers.value = result.value.rows.map(deviceMemberRow);
    deviceMembersLastRefreshed.value = new Date().toISOString();
  } else {
    deviceMembers.value = [];
    deviceMembersError.value = deviceMemberErrorLabel(result.error);
  }
  deviceMembersLoading.value = false;
}

watch(deviceMembersRequest, () => {
  void refreshDeviceMembers();
});

const auditRequest = computed<ListAuditRequest | null>(() => {
  const projectId = status.value?.project_id;
  if (projectId === null || projectId === undefined) {
    return null;
  }
  return {
    project_id: projectId,
    profile_id: null,
    action: null,
    status: null,
    limit: 100,
    redact_names: settings.value.privacyRedactNames,
  };
});

function auditErrorLabel(error: AgentClientError): string {
  switch (error.kind) {
    case 'unavailable':
      return 'Agent unavailable.';
    case 'protocol':
      return 'Audit request failed.';
    case 'rejected':
      return error.code;
    default:
      return 'Audit request failed.';
  }
}

function auditStatusLabel(status: string): AuditLogRow['status'] {
  switch (status.toUpperCase()) {
    case 'SUCCESS':
    case 'OK':
      return 'OK';
    case 'DENIED':
      return 'DENIED';
    default:
      return 'FAILED';
  }
}

function auditTimestamp(timestampUnixNanos: number): string {
  return new Date(Math.trunc(timestampUnixNanos / 1_000_000)).toISOString();
}

function auditRowHmacOk(row: AuditWireRow, chainStatus: AuditChainStatus): boolean {
  if (chainStatus.hmac_ok !== false || chainStatus.first_break_sequence === null) {
    return true;
  }
  return row.sequence < chainStatus.first_break_sequence;
}

function auditLogRow(row: AuditWireRow, chainStatus: AuditChainStatus): AuditLogRow {
  const statusLabel = auditStatusLabel(row.status);
  const metadata: Record<string, string | number> = {
    action: row.action,
    status: row.status,
  };
  if (row.command !== null) {
    metadata.command = row.command;
  }
  return {
    sequence: row.sequence,
    action: row.action,
    status: statusLabel,
    timestamp: auditTimestamp(row.timestamp),
    profile: row.profile_id ?? undefined,
    secretName: row.secret_name ?? undefined,
    metadataJson: JSON.stringify(metadata),
    denialReason: statusLabel === 'DENIED' ? row.status : undefined,
    hmacOk: auditRowHmacOk(row, chainStatus),
  };
}

let auditRefreshSequence = 0;

async function refreshAuditLog(): Promise<void> {
  const request = auditRequest.value;
  const sequence = (auditRefreshSequence += 1);
  if (request === null) {
    auditRows.value = [];
    auditChainOk.value = true;
    return;
  }

  auditLoading.value = true;
  auditError.value = null;
  const result = await listAudit(request);
  if (sequence !== auditRefreshSequence) {
    return;
  }
  if (result.ok) {
    const hmacOk = result.value.chain_status.hmac_ok !== false;
    auditRows.value = result.value.rows.map((row) => auditLogRow(row, result.value.chain_status));
    rawAuditRows.value = [...result.value.rows];
    auditChainOk.value = hmacOk;
    auditLastRefreshed.value = new Date().toISOString();
  } else {
    auditRows.value = [];
    rawAuditRows.value = [];
    auditError.value = auditErrorLabel(result.error);
    auditChainOk.value = true;
  }
  auditLoading.value = false;
}

const recentActivityRows = computed(() => {
  const okCount = auditRows.value.filter((row) => row.status === 'OK').length;
  const deniedCount = auditRows.value.filter((row) => row.status === 'DENIED').length;
  const failedCount = auditRows.value.filter(
    (row) => row.status === 'FAILED' || !row.hmacOk,
  ).length;
  return [
    { label: 'OK', value: okCount.toString(), tone: 'ok' },
    { label: 'Denied', value: deniedCount.toString(), tone: deniedCount === 0 ? 'ok' : 'warn' },
    { label: 'Failed', value: failedCount.toString(), tone: failedCount === 0 ? 'ok' : 'warn' },
    {
      label: 'Audit',
      value: auditChainOk.value ? 'safe' : 'check',
      tone: auditChainOk.value ? 'ok' : 'warn',
    },
  ];
});

async function verifyAuditChain(): Promise<void> {
  const request = auditRequest.value;
  if (request === null) {
    auditRows.value = [];
    auditChainOk.value = true;
    return;
  }
  const result = await verifyAudit({ project_id: request.project_id });
  if (result.ok) {
    auditChainOk.value = result.value.hmac_ok !== false;
  }
  await refreshAuditLog();
}

watch(auditRequest, () => {
  void refreshAuditLog();
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

const TEAM_INVITE_RPC_MISSING =
  'Agent does not yet expose ListTeamInvites/CreateTeamInvite/AcceptTeamInvite/RevokeTeamInvite. ' +
  'Form input validated; submit blocked until the agent ships those RPCs.';

function handleTeamInviteIssue(): void {
  teamInviteNotice.value = TEAM_INVITE_RPC_MISSING;
}

function handleTeamInviteAccept(): void {
  teamInviteNotice.value = TEAM_INVITE_RPC_MISSING;
}

function handleTeamInviteRevoke(): void {
  teamInviteNotice.value = TEAM_INVITE_RPC_MISSING;
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
          <dt>Agent</dt>
          <dd>
            <span
              :class="`shell__connection shell__connection--${connectionTone}`"
              :data-connected="connected ? 'true' : 'false'"
              role="status"
              aria-live="polite"
            >{{ connectionLabel }}</span>
          </dd>
        </dl>
        <section class="shell__activity" aria-label="Recent activity">
          <div class="shell__activity-head">
            <span>Recent</span>
            <span v-if="auditLoading">Loading</span>
            <span v-else-if="auditError">{{ auditError }}</span>
            <span v-else-if="auditLastRefreshed">Updated</span>
          </div>
          <dl>
            <div v-for="row in recentActivityRows" :key="row.label">
              <dt>{{ row.label }}</dt>
              <dd :class="`shell__activity-value shell__activity-value--${row.tone}`">
                {{ row.value }}
              </dd>
            </div>
          </dl>
        </section>
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
        :loading="secretsLoading"
        :error-message="secretsError"
        :last-refreshed-at="secretsLastRefreshed"
        @select="selectSecret"
        @refresh="refreshSecrets"
      />

      <SecretVersionHistory
        v-else-if="currentView === 'versions'"
        :rows="versions"
        secret-label="All secrets"
        :loading="versionsLoading"
        :error-message="versionsError"
        :last-refreshed-at="versionsLastRefreshed"
        @refresh="refreshVersions"
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
        :loading="deviceMembersLoading"
        :error-message="deviceMembersError"
        :last-refreshed-at="deviceMembersLastRefreshed"
        @refresh="refreshDeviceMembers"
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
        :loading="policiesLoading || loading"
        :error-message="policiesError"
        @refresh="refreshPolicies"
        @create="openPolicyCreate"
        @edit="openPolicyEdit"
        @delete="openPolicyDelete"
      />

      <ProfileSwitcherView
        v-else-if="currentView === 'profiles'"
        :state="profileSwitchState"
        :privacy-mode="settings.privacyRedactNames"
        :switching="profileSwitchInProgress"
        :error-message="profileSwitchError"
        :last-switched-at="profileSwitchLastAt"
        @switch="handleProfileSwitch"
      />

      <TeamInviteView
        v-else-if="currentView === 'team'"
        :audit-rows="rawAuditRows"
        :dangerous-profiles="settings.dangerousProfileFlag ? (status?.profile_name ?? '') : ''"
        :require-accept-user-verification="settings.requireUserVerification"
        :loading="auditLoading"
        :error-message="auditError ?? teamInviteNotice"
        :last-refreshed-at="auditLastRefreshed"
        @refresh="refreshAuditLog"
        @issue="handleTeamInviteIssue"
        @accept="handleTeamInviteAccept"
        @revoke="handleTeamInviteRevoke"
      />

      <BackupRecovery v-else-if="currentView === 'recovery'" @action="triggerBackupAction" />

      <Settings
        v-else-if="currentView === 'settings'"
        :state="settings"
        :loading="settingsLoading"
        :error-message="settingsError"
        @update="handleSettingsPatch"
      />

      <p v-if="revealError" role="alert" class="shell__notice">{{ revealError }}</p>
      <p v-if="copyError" role="alert" class="shell__notice">{{ copyError }}</p>
    </main>

    <RevealModal ref="revealModal" />
    <PolicyEditorForm
      v-if="policyFormMode !== null && status?.project_id"
      :mode="policyFormMode"
      :row="policyFormRow"
      :project-id="status?.project_id ?? ''"
      :dangerous-profile="settings.dangerousProfileFlag"
      :profile-label="status?.profile_name ?? profileLabel"
      :submitting="policyFormSubmitting"
      :error-message="policyFormError"
      @submit="submitPolicyForm"
      @dismiss="dismissPolicyForm"
    />
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

.shell__connection {
  display: inline-flex;
  align-items: center;
  gap: 0.375rem;
  padding: 0.0625rem 0.375rem;
  border-radius: 999px;
  font-size: 0.7rem;
  font-weight: 600;
  letter-spacing: 0.02em;
}

.shell__connection::before {
  content: '';
  width: 0.4rem;
  height: 0.4rem;
  border-radius: 50%;
  background: currentColor;
}

.shell__connection--ok {
  color: #8fd19e;
  background: rgba(143, 209, 158, 0.12);
}

.shell__connection--warn {
  color: #f2b879;
  background: rgba(242, 184, 121, 0.14);
}

.shell__activity {
  margin-top: 1rem;
  padding-top: 0.875rem;
  border-top: 1px solid rgba(255, 255, 255, 0.08);
}

.shell__activity-head {
  display: flex;
  justify-content: space-between;
  gap: 0.5rem;
  font-size: 0.7rem;
  color: #9aa3b2;
}

.shell__activity dl {
  margin: 0.625rem 0 0;
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 0.5rem;
}

.shell__activity div {
  min-width: 0;
}

.shell__activity dt {
  font-size: 0.68rem;
  color: #9aa3b2;
}

.shell__activity dd {
  margin: 0.125rem 0 0;
  font-size: 0.875rem;
  font-weight: 650;
}

.shell__activity-value--ok {
  color: #8fd19e;
}

.shell__activity-value--warn {
  color: #f2b879;
}

.shell__activity-value--neutral {
  color: #e6e8ec;
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

.shell__notice {
  margin: 0;
  padding: 0.5rem 0.75rem;
  border: 1px solid rgba(248, 215, 122, 0.32);
  background: rgba(248, 215, 122, 0.08);
  color: #f8d77a;
  border-radius: 0.375rem;
  font-size: 0.85rem;
}
</style>
