/** Metadata-only presentation of authenticated folder delivery. */
export interface PendingCollision {
  id: string;
  name: string;
}
export interface PendingProfileDetails {
  profile_id: string;
  profile_name: string;
  reason: string;
  colliding_profile: PendingCollision | null;
  colliding_secrets: PendingCollision[];
}
export interface TeamSyncStatus {
  epoch: number;
  state: string;
  conflicts: number;
  conflict_ids?: string[];
  pending_profiles?: Record<string, string>;
  pending_details?: PendingProfileDetails[];
  waiting: number;
  waiting_known?: boolean;
  last_error?: string | null;
  last_verified_at?: number | null;
  owner_fingerprint?: string | null;
  folder?: string | null;
  published: number;
  applied: number;
}
export function syncMessage(
  status: Pick<TeamSyncStatus, 'state' | 'conflicts' | 'waiting' | 'pending_profiles'>,
): string {
  if (['fork', 'rollback', 'stopped'].includes(status.state))
    return 'Stopped: conflicting update history. Contact the owner and verify the history before continuing.';
  if (status.state === 'delivery-error')
    return 'Delivery needs attention. Check the details below, then try again.';
  if (status.state === 'removed') return 'Your device was removed. Automatic updates have stopped.';
  if (status.state === 'locked') return 'Unlock to check and apply waiting team updates.';
  const profiles = Object.keys(status.pending_profiles ?? {}).length;
  if (profiles || status.conflicts) {
    const choices = [
      profiles
        ? `${profiles} ${profiles === 1 ? 'profile needs' : 'profiles need'} local consent or collision resolution`
        : '',
      status.conflicts
        ? `${status.conflicts} ${status.conflicts === 1 ? 'value needs' : 'values need'} your choice`
        : '',
    ]
      .filter(Boolean)
      .join('; ');
    return `${choices}. Other verified membership and key changes still apply.`;
  }
  if (status.state === 'unanchored')
    return 'Join using an independently verified owner fingerprint to establish trust.';
  return 'Showing the last verified update. Folder delivery cannot prove that this is the owner’s newest state.';
}
const quote = (value: string) => `'${value.replaceAll("'", `'"'"'`)}'`;
export function joinCommand(folder: string, ownerPin: string): string | null {
  if (!folder.trim() || !/^[a-fA-F0-9]{64}$/.test(ownerPin)) return null;
  return `locket team join --folder ${quote(folder.trim())} --owner ${quote(ownerPin.toLowerCase())}`;
}
