//! Explicit local reconciliation for an exact authenticated pending checkpoint.
use super::{CommitAuthorization, Result, identity, nanos, reject};
use locket_core::team_package::{DeviceIdentity, SignedStatement, VerifiedStatement};
use locket_crypto::KeyBytes;
use locket_store::Store;
use rusqlite::{OptionalExtension, params};

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PendingCollision {
    pub id: String,
    pub name: String,
}
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PendingProfileDetails {
    pub profile_id: String,
    pub profile_name: String,
    pub reason: String,
    pub colliding_profile: Option<PendingCollision>,
    pub colliding_secrets: Vec<PendingCollision>,
}
pub(super) fn current_checkpoint(
    store: &Store,
    project: &str,
    verified: &VerifiedStatement,
) -> Result<()> {
    let head: Option<(i64, String, String)> = store
        .connection()
        .query_row(
            "SELECT epoch,digest,state FROM team_sync_heads WHERE project_id=?1",
            [project],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    let pending: Option<(i64, String)> = store
        .connection()
        .query_row(
            "SELECT epoch,digest FROM team_sync_pending_packages WHERE project_id=?1",
            [project],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let epoch = i64::try_from(verified.statement.epoch).map_err(|_| reject("epoch overflow"))?;
    if head.as_ref().is_none_or(|head| {
        head.0 != epoch
            || head.1 != verified.digest
            || ["fork", "removed"].contains(&head.2.as_str())
    }) || pending
        .as_ref()
        .is_none_or(|pending| pending.0 != epoch || pending.1 != verified.digest)
    {
        return Err(reject("pending package is not the current authorized checkpoint"));
    }
    Ok(())
}
fn load_pending(
    store: &Store,
    project: &str,
    sealing: &KeyBytes,
    local: &DeviceIdentity,
    now: i64,
) -> Result<Option<VerifiedStatement>> {
    let active = store
        .get_active_local_device(project)?
        .ok_or_else(|| reject("active local device missing"))?;
    if identity(&active)? != *local {
        return Err(reject("recipient differs from active local device"));
    }
    let bytes: Option<Vec<u8>> = store
        .connection()
        .query_row(
            "SELECT encrypted_package FROM team_sync_pending_packages WHERE project_id=?1",
            [project],
            |row| row.get(0),
        )
        .optional()?;
    let Some(bytes) = bytes else {
        return Ok(None);
    };
    let (_, owner) =
        super::snapshot::anchor(store, project)?.ok_or_else(|| reject("owner pin missing"))?;
    let verified = SignedStatement::open(&bytes, sealing)?.verify_update(
        &owner.fingerprint,
        project,
        local,
        now,
    )?;
    current_checkpoint(store, project, &verified)?;
    Ok(Some(verified))
}
fn pending_reason(store: &Store, project: &str, profile: &str, expected: &str) -> Result<()> {
    let reason: Option<String> = store
        .connection()
        .query_row(
            "SELECT reason FROM team_sync_pending_profiles WHERE project_id=?1 AND profile_id=?2",
            (project, profile),
            |row| row.get(0),
        )
        .optional()?;
    if reason.as_deref() != Some(expected) {
        return Err(reject("pending profile requires a different reconciliation action"));
    }
    Ok(())
}
/// Returns authenticated names and exact collision IDs without values or keys.
/// # Errors
/// Rejects an inactive device, stale checkpoint or invalid encrypted package.
pub fn pending_profile_details(
    store: &Store,
    project: &str,
    sealing: &KeyBytes,
    local: &DeviceIdentity,
    now: i64,
) -> Result<Vec<PendingProfileDetails>> {
    let Some(verified) = load_pending(store, project, sealing, local, now)? else {
        return Ok(Vec::new());
    };
    let rows=store.connection().prepare("SELECT profile_id,reason FROM team_sync_pending_profiles WHERE project_id=?1 ORDER BY profile_id")?.query_map([project],|row|Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?)))?.collect::<std::result::Result<Vec<_>,_>>()?;
    let local_profiles = store.list_profiles(project)?;
    let mut details = Vec::new();
    for (id, reason) in rows {
        let profile = verified
            .statement
            .profiles
            .iter()
            .find(|profile| profile.id == id)
            .ok_or_else(|| reject("pending profile no longer granted"))?;
        let colliding_profile = local_profiles
            .iter()
            .find(|local| local.id != id && local.name == profile.name)
            .map(|local| PendingCollision { id: local.id.clone(), name: local.name.clone() });
        let mut colliding_secrets = Vec::new();
        for secret in &profile.secrets {
            if let Some(local) =
                store.get_secret_by_source(project, &id, &secret.name, "team-managed")?
                && local.id != secret.id
            {
                colliding_secrets.push(PendingCollision { id: local.id, name: local.name });
            }
        }
        details.push(PendingProfileDetails {
            profile_id: id,
            profile_name: profile.name.clone(),
            reason,
            colliding_profile,
            colliding_secrets,
        });
    }
    Ok(details)
}
/// Renames one explicitly selected local profile that blocks an incoming profile.
/// Preserves its ID, keys, secret history and dangerous marker.
/// # Errors
/// Rejects invalid names, ambiguity, occupied names, stale scope or denied authorization.
pub fn rename_local_profile_for_pending(
    store: &mut Store,
    project: &str,
    incoming_profile_id: &str,
    local_profile_id: &str,
    new_name: &str,
    master: &KeyBytes,
    sealing: &KeyBytes,
    local: &DeviceIdentity,
    now: i64,
    authorization: Option<&CommitAuthorization>,
) -> Result<()> {
    locket_core::ProfileName::new(new_name)
        .map_err(|_| reject("invalid new local profile name"))?;
    let verified = load_pending(store, project, sealing, local, now)?
        .ok_or_else(|| reject("no pending profile"))?;
    let incoming = verified
        .statement
        .profiles
        .iter()
        .find(|profile| profile.id == incoming_profile_id)
        .ok_or_else(|| reject("incoming profile outside current grant"))?;
    let _authorization = authorization.map(|authorize| authorize()).transpose()?;
    store.with_atomic_write(|store| {
        current_checkpoint(store,project,&verified)?;
        pending_reason(store,project,incoming_profile_id,"profile-name-collision")?;
        let profiles=store.list_profiles(project)?;
        let target=profiles.iter().find(|profile|profile.id==local_profile_id).ok_or_else(||reject("selected local profile outside project"))?;
        if target.id==incoming.id || target.name!=incoming.name || new_name==incoming.name || profiles.iter().any(|profile|profile.name==new_name) {return Err(reject("selected profile or new name does not resolve this collision"));}
        store.connection().execute("UPDATE profiles SET name=?3 WHERE project_id=?1 AND id=?2",params![project,local_profile_id,new_name])?;
        super::snapshot::audit_event(store,project,master,"TEAM_SYNC",now,&serde_json::json!({"reconcile":"rename-local-profile","incoming_profile_id":incoming_profile_id,"local_profile_id":local_profile_id,"old_name":target.name,"new_name":new_name}))?;
        Ok(())
    })
}
/// Preserves an explicitly selected colliding team row as a local override.
/// Ciphertext, IDs, versions and historical source provenance remain unchanged.
/// # Errors
/// Rejects stale scope, a mismatched collision or any existing user-local row.
pub fn preserve_collision_as_override(
    store: &mut Store,
    project: &str,
    incoming_profile_id: &str,
    local_secret_id: &str,
    master: &KeyBytes,
    sealing: &KeyBytes,
    local: &DeviceIdentity,
    now: i64,
    authorization: Option<&CommitAuthorization>,
) -> Result<()> {
    let verified = load_pending(store, project, sealing, local, now)?
        .ok_or_else(|| reject("no pending profile"))?;
    let incoming = verified
        .statement
        .profiles
        .iter()
        .find(|profile| profile.id == incoming_profile_id)
        .ok_or_else(|| reject("incoming profile outside current grant"))?;
    let _authorization = authorization.map(|authorize| authorize()).transpose()?;
    store.with_atomic_write(|store| {
        current_checkpoint(store,project,&verified)?;
        pending_reason(store,project,incoming_profile_id,"secret-name-collision")?;
        let target=store.list_secrets_by_profile(project,incoming_profile_id)?.into_iter().find(|secret|secret.id==local_secret_id && secret.source=="team-managed").ok_or_else(||reject("selected shared secret outside pending profile"))?;
        if !incoming.secrets.iter().any(|secret|secret.name==target.name && secret.id!=target.id) {return Err(reject("selected secret is not a current name collision"));}
        if store.get_secret_by_source(project,incoming_profile_id,&target.name,"user-local")?.is_some() {return Err(reject("existing user-local override preserved; choose a different explicit reconciliation"));}
        store.connection().execute("UPDATE secrets SET source='user-local',updated_at=?3 WHERE project_id=?1 AND id=?2",params![project,local_secret_id,nanos(now)?])?;
        store.connection().execute("DELETE FROM team_sync_values WHERE project_id=?1 AND secret_id=?2",(project,local_secret_id))?;
        store.connection().execute("DELETE FROM team_sync_conflicts WHERE project_id=?1 AND secret_id=?2",(project,local_secret_id))?;
        super::snapshot::audit_event(store,project,master,"TEAM_SYNC",now,&serde_json::json!({"reconcile":"preserve-local-override","profile_id":incoming_profile_id,"secret_id":local_secret_id,"history_preserved":true}))?;
        Ok(())
    })
}
