use std::io::Write;

use locket_core::TeamId;
use locket_crypto::KeyPurpose;
use locket_store::{AuditWrite, PendingTeamInviteRecord, TeamMemberListRecord, TeamRecord};
use serde_json::json;

use crate::{
    CliError, RuntimeContext, TeamCommand, TeamInitArgs, TeamRemoveArgs, TeamRevokeDeviceArgs,
    confirmation_failed_error, ensure_project_exists, invalid_reference_error, load_project_key,
    now_unix_nanos, open_store, privacy_alias, privacy_redact_names_enabled, require_project,
    secret_already_exists_error, secret_not_found_error, team_role_denied_error,
};

pub fn team_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    command: TeamCommand,
) -> Result<(), CliError> {
    match command {
        TeamCommand::Init(args) => team_init_command(context, output, &args),
        TeamCommand::Members => team_members_command(context, output),
        TeamCommand::Remove(args) => team_remove_command(context, output, &args),
        TeamCommand::RevokeDevice(args) => team_revoke_device_command(context, output, &args),
    }
}

fn team_init_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &TeamInitArgs,
) -> Result<(), CliError> {
    let resolved = require_project(context)?;
    let mut store = open_store(context)?;
    let project_id = resolved.config.project_id.as_str();
    ensure_project_exists(&store, project_id)?;

    if let Some(existing) = store.get_team_by_project(project_id)? {
        return Err(secret_already_exists_error(format!(
            "team already initialized: {} ({})",
            existing.name, existing.id
        )));
    }

    let team_id = TeamId::generate().map_err(|_| CliError::Time)?;
    let timestamp = now_unix_nanos()?;
    let record = TeamRecord {
        id: team_id.into_string(),
        project_id: project_id.to_owned(),
        name: args.name.clone(),
        created_at: timestamp,
        updated_at: timestamp,
    };
    store.insert_team(&record)?;

    let audit_key = load_project_key(context, &store, project_id, KeyPurpose::Audit)?;
    let metadata = json!({
        "schema_version": 1,
        "action": "TEAM_INIT",
        "status": "SUCCESS",
        "command": "team init",
        "project_id": project_id,
        "team_id": record.id,
        "team_name": record.name,
    });
    let audit = AuditWrite {
        project_id,
        profile_id: None,
        action: "TEAM_INIT",
        status: "SUCCESS",
        secret_name: None,
        command: Some("team init"),
        metadata_json: &metadata,
        timestamp,
    };
    store.append_audit(audit_key.as_ref(), &audit)?;

    writeln!(output, "team initialized: {} ({})", record.name, record.id)?;
    writeln!(output, "metadata_only: yes")?;
    Ok(())
}

fn team_remove_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &TeamRemoveArgs,
) -> Result<(), CliError> {
    let resolved = require_project(context)?;
    let mut store = open_store(context)?;
    let project_id = resolved.config.project_id.as_str();
    ensure_project_exists(&store, project_id)?;

    let Some(team) = store.get_team_by_project(project_id)? else {
        return Err(team_role_denied_error("no team initialized for this project"));
    };

    let Some(member) = store.get_team_member(&team.id, &args.member)? else {
        return Err(secret_not_found_error(format!("team member not found: {}", args.member)));
    };

    if member.removed_at.is_some() {
        return Err(secret_not_found_error(format!(
            "team member already removed: {}",
            member.display_name
        )));
    }

    // Last-owner guard: cannot remove the last remaining owner.
    if member.role == "owner" {
        let owner_count = store.count_active_owners(&team.id)?;
        if owner_count <= 1 {
            return Err(team_role_denied_error("cannot remove the last remaining owner"));
        }
    }

    // Show metadata summary before confirmation.
    writeln!(output, "remove member: {} ({})", member.display_name, member.role)?;
    writeln!(output, "trusted_devices: {}", member.trusted_device_count)?;
    writeln!(
        output,
        "note: a rotation checklist for accessible profiles and secrets is recommended"
    )?;

    // Typed confirmation: must type the display name exactly.
    let confirmation = context.confirmation_reader.read_confirmation(&member.display_name)?;
    if confirmation.trim() != member.display_name {
        return Err(confirmation_failed_error("confirmation did not match member display name"));
    }

    let timestamp = now_unix_nanos()?;
    store.remove_team_member(&member.id, timestamp)?;

    let audit_key = load_project_key(context, &store, project_id, KeyPurpose::Audit)?;
    let metadata = json!({
        "schema_version": 1,
        "action": "TEAM_REMOVE",
        "status": "SUCCESS",
        "command": "team remove",
        "project_id": project_id,
        "team_id": team.id,
        "member_id": member.id,
        "member_role": member.role,
    });
    let audit = AuditWrite {
        project_id,
        profile_id: None,
        action: "TEAM_REMOVE",
        status: "SUCCESS",
        secret_name: None,
        command: Some("team remove"),
        metadata_json: &metadata,
        timestamp,
    };
    store.append_audit(audit_key.as_ref(), &audit)?;

    writeln!(output, "team_remove: success")?;
    writeln!(output, "metadata_only: yes")?;
    Ok(())
}

fn team_revoke_device_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &TeamRevokeDeviceArgs,
) -> Result<(), CliError> {
    let resolved = require_project(context)?;
    let mut store = open_store(context)?;
    let project_id = resolved.config.project_id.as_str();
    ensure_project_exists(&store, project_id)?;

    if store.get_team_by_project(project_id)?.is_none() {
        return Err(team_role_denied_error("no team initialized for this project"));
    }

    let device = store
        .find_device(project_id, &args.device)?
        .ok_or_else(|| invalid_reference_error("device not found"))?;

    if device.revoked_at.is_some() {
        writeln!(output, "device: already revoked")?;
        writeln!(output, "device_id: {}", device.id)?;
        writeln!(output, "metadata_only: yes")?;
        return Ok(());
    }

    let timestamp = now_unix_nanos()?;
    store.revoke_device(project_id, &device.id, timestamp)?;

    let audit_key = load_project_key(context, &store, project_id, KeyPurpose::Audit)?;
    let metadata = json!({
        "schema_version": 1,
        "action": "DEVICE_REVOKE",
        "status": "SUCCESS",
        "command": "team revoke-device",
        "device_id": device.id,
        "device_name": device.name,
        "fingerprint": device.fingerprint,
        "local": device.local,
    });
    let audit = AuditWrite {
        project_id,
        profile_id: None,
        action: "DEVICE_REVOKE",
        status: "SUCCESS",
        secret_name: None,
        command: Some("team revoke-device"),
        metadata_json: &metadata,
        timestamp,
    };
    store.append_audit(audit_key.as_ref(), &audit)?;

    writeln!(output, "device: revoked")?;
    writeln!(output, "device_id: {}", device.id)?;
    writeln!(output, "fingerprint: {}", device.fingerprint)?;
    writeln!(
        output,
        "note: a rotation checklist for accessible profiles and secrets is recommended"
    )?;
    writeln!(output, "metadata_only: yes")?;
    Ok(())
}

fn team_members_command(context: &RuntimeContext, output: &mut impl Write) -> Result<(), CliError> {
    let resolved = require_project(context)?;
    let store = open_store(context)?;
    let project_id = resolved.config.project_id.as_str();
    ensure_project_exists(&store, project_id)?;
    let redact_names = privacy_redact_names_enabled(context, false)?;

    let Some(team) = store.get_team_by_project(project_id)? else {
        writeln!(output, "team: none")?;
        writeln!(output, "members: none")?;
        writeln!(output, "pending_invites: none")?;
        writeln!(output, "metadata_only: yes")?;
        return Ok(());
    };

    let members = store.list_team_members(&team.id)?;
    let pending_invites = store.list_pending_team_invites(&team.id, now_unix_nanos()?)?;

    writeln!(output, "team: {}", team_name_label(&team, redact_names))?;
    writeln!(output, "team_id: {}", team_id_label(&team, redact_names))?;
    write_members(output, &members, redact_names)?;
    write_pending_invites(output, &pending_invites, redact_names)?;
    writeln!(output, "metadata_only: yes")?;
    Ok(())
}

fn write_members(
    output: &mut impl Write,
    members: &[TeamMemberListRecord],
    redact_names: bool,
) -> Result<(), CliError> {
    if members.is_empty() {
        writeln!(output, "members: none")?;
        return Ok(());
    }
    writeln!(output, "members:")?;
    for member in members {
        writeln!(
            output,
            "- id={} display={} role={} trusted_devices={} joined_at={} removed_at={}",
            member_id_label(member, redact_names),
            member_display_label(member, redact_names),
            member.role,
            member.trusted_device_count,
            member.joined_at,
            optional_timestamp_label(member.removed_at),
        )?;
    }
    Ok(())
}

fn write_pending_invites(
    output: &mut impl Write,
    invites: &[PendingTeamInviteRecord],
    redact_names: bool,
) -> Result<(), CliError> {
    if invites.is_empty() {
        writeln!(output, "pending_invites: none")?;
        return Ok(());
    }
    writeln!(output, "pending_invites:")?;
    for invite in invites {
        writeln!(
            output,
            "- id={} status=pending role={} profiles={} recipient_device={} created_at={} expires_at={}",
            invite_id_label(invite, redact_names),
            invite.role,
            invite_profiles_label(invite, redact_names),
            invite_recipient_label(invite, redact_names),
            invite.created_at,
            invite.expires_at,
        )?;
    }
    Ok(())
}
