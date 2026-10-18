import { describe, expect, it } from 'vitest';
import app from '../App.vue?raw';
import unlock from '../components/UnlockModal.vue?raw';
import policy from '../views/PolicyEditor.vue?raw';
import dashboard from '../views/ProjectDashboard.vue?raw';
import scan from '../views/ScanResults.vue?raw';
import backup from '../views/BackupRecovery.vue?raw';
import variables from '../views/SecretMetadataList.vue?raw';
import team from '../views/TeamInviteView.vue?raw';
const sources: Record<string, string> = {
  '../App.vue': app,
  '../components/UnlockModal.vue': unlock,
  '../views/PolicyEditor.vue': policy,
  '../views/ProjectDashboard.vue': dashboard,
  '../views/ScanResults.vue': scan,
};
const source = (path: string) => sources[path]!;
describe('desktop component action wiring without a DOM runner', () => {
  it('mounts unlock and routes tray unlock through the same action', () => {
    const app = source('../App.vue');
    expect(app).toContain('<UnlockModal');
    expect(app).toContain('@submit="handleUnlock"');
    expect(app).toMatch(/case 'unlock-vault':[\s\S]*?openUnlock\(\)/);
    const modal = source('../components/UnlockModal.vue');
    expect(modal).toContain('Use system keychain');
    expect(modal).toContain('props.busy');
    expect(modal).toContain("passphrase.value = ''");
    expect(modal).toContain('props.errorMessage');
  });
  it('uses durable policy mutation and terminal launch', () => {
    const app = source('../App.vue');
    expect(app).toContain('await desktopSavePolicy(');
    expect(app).not.toContain('await registerCommandPolicies(');
    expect(app).toContain('await desktopRunPolicy(');
    expect(source('../views/PolicyEditor.vue')).toContain('Run in terminal');
  });
  it('offers project connection/init/import and removes two-row search', () => {
    const app = source('../App.vue');
    expect(app).toContain('await desktopOpenProject(');
    expect(app).toContain('await desktopInitializeProject(');
    expect(app).toContain('await desktopImportEnv(');
    expect(app).toContain('await desktopStartAgent(');
    expect(source('../views/ProjectDashboard.vue')).not.toContain('Project and profile search');
  });
  it('does not display an unattempted scan as no findings', () => {
    expect(source('../views/ScanResults.vue')).toContain('No scan has run');
  });
});

it('requires explicit personal/history export opt-ins and exposes preview', () => {
  expect(backup).toContain('includePersonal: false');
  expect(backup).toContain('includeHistory: false');
  expect(backup).toContain('Preview scope');
  expect(backup).toContain('Include my overrides and this machine');
  expect(app).toContain('preview_only: action.request.previewOnly');
});

it('never sends environment display names as profile IDs', () => {
  expect(app).not.toMatch(/profile_id:\s*(?:currentStatus|status\.value\??)\.profile_name/);
  expect(app).not.toContain(':profile-id="status?.profile_name"');
  expect(app).not.toContain('selectedProject.value?.profile_id ?? status.value?.profile_name');
  expect(app).toContain('profile_id: context.profile_id');
  expect(app).toContain(':profile-id="activeContext?.profile_id"');
});
it('disables disconnected actions and only claims empty after loading', () => {
  for (const component of [policy, variables, team]) {
    expect(component).toContain('actionGuidance');
    expect(component).toContain('metadataLoaded');
  }
  expect(policy).toContain(':disabled="!actionsEnabled');
  expect(app).toContain(':actions-enabled="policyAccess.enabled"');
  expect(app).toContain('if (!policyAccess.value.enabled) return;');
});

it('guards environment responses and refreshes the sole initial native context', () => {
  expect(app).toContain('await withCurrentSelection(');
  expect(app).toContain('captureSelection(selectedProject.value, selectionGeneration.value)');
  expect(app).toContain('initialProjectSelection(result.value, selectedProject.value)');
  expect(app).toContain('selectedProject.value = initial;');
  expect(dashboard).not.toContain('scan_warning_count');
});
