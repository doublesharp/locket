import type { DesktopProjectContext } from '../agent/types';
import { projectStatusMatches } from './health';
export function scopedProjectContext(
  status: { project_id: string | null; profile_name: string | null } | null,
  selected: DesktopProjectContext | null,
  connected: boolean,
): DesktopProjectContext | null {
  return selected?.profile_id.trim() && projectStatusMatches(status, selected, connected)
    ? selected
    : null;
}
export function actionAvailability(input: {
  projectSelected: boolean;
  connected: boolean;
  scoped: boolean;
  unlocked: boolean;
  loaded: boolean;
  loading: boolean;
  error?: string | null;
}): { enabled: boolean; guidance: string | null } {
  if (!input.projectSelected)
    return { enabled: false, guidance: 'Connect a project from Project to use this view.' };
  if (!input.connected)
    return { enabled: false, guidance: 'Start the local agent from Project, then retry.' };
  if (!input.scoped)
    return {
      enabled: false,
      guidance: 'Reconnect the selected project from Project to verify this environment.',
    };
  if (!input.unlocked)
    return { enabled: false, guidance: 'Unlock the selected project, then refresh this view.' };
  if (input.loading)
    return { enabled: false, guidance: 'Loading metadata for this project and environment…' };
  if (input.error) return { enabled: false, guidance: `${input.error} Retry loading metadata.` };
  if (!input.loaded)
    return {
      enabled: false,
      guidance: 'Load this project metadata with Refresh before using these actions.',
    };
  return { enabled: true, guidance: null };
}
