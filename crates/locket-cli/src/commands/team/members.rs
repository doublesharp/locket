use std::collections::BTreeSet;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use data_encoding::BASE64URL_NOPAD;
use ed25519_dalek::SigningKey;
use locket_core::{InviteId, InvitePayload, MemberId, ProjectId, SignedInvite, TeamId, TeamRole};
use locket_crypto::{KeyPurpose, generate_key};
use locket_store::{
    AuditContext, AuditWrite, DeviceRecord, PendingTeamInviteRecord, StoredTeamInviteRecord,
    TeamInviteRecord, TeamMemberListRecord, TeamRecord,
};
use serde_json::json;

use super::device;
use crate::support::time::NANOS_PER_SECOND;
use crate::{
    CliError, RuntimeContext, TeamCommand, TeamInitArgs, TeamInviteArgs, TeamRemoveArgs,
    TeamRevokeDeviceArgs, TeamRevokeInviteArgs, TeamRoleArg, confirmation_failed_error,
    ensure_project_exists, invalid_reference_error, load_project_key, metadata_invalid_error,
    now_unix_nanos, open_store, privacy_alias, privacy_redact_names_enabled,
    profile_not_found_error, require_project, secret_already_exists_error, secret_not_found_error,
    set_user_only_file_options, set_user_only_file_permissions, team_role_denied_error,
    unix_nanos_to_rfc3339,
};

const DEFAULT_INVITE_TTL_SECONDS: i64 = 7 * 24 * 60 * 60;

pub fn team_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    command: TeamCommand,
) -> Result<(), CliError> {
    match command {
        TeamCommand::Init(args) => team_init_command(context, output, &args),
        TeamCommand::Invite(args) => team_invite_command(context, output, &args),
        TeamCommand::RevokeInvite(args) => team_revoke_invite_command(context, output, &args),
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
    if let Some(local_device) = store.get_active_local_device(project_id)? {
        let member_id = MemberId::generate().map_err(|_| CliError::Time)?.into_string();
        store.insert_team_member(
            &member_id,
            &record.id,
            Some(&local_device.id),
            &local_device.name,
            "owner",
            timestamp,
        )?;
    }

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

fn team_invite_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &TeamInviteArgs,
) -> Result<(), CliError> {
    validate_invitee_name(&args.name)?;
    let resolved = require_project(context)?;
    let mut store = open_store(context)?;
    let project_id = resolved.config.project_id.as_str();
    ensure_project_exists(&store, project_id)?;

    let issuer = load_invite_issuer(&store, project_id)?;
    let invite_role = role_from_arg(args.role);
    let role_label = role_label(args.role);
    if !can_issue_role(&issuer.member.role, args.role) {
        return Err(team_role_denied_error("team role cannot issue this invite"));
    }

    let recipient = decode_recipient_device(&args.device)?;
    if recipient.fingerprint == issuer.local_device.fingerprint {
        return Err(metadata_invalid_error("recipient device must differ from issuer device"));
    }
    let profiles = validate_invite_profiles(&store, project_id, &args.profiles)?;
    confirm_dangerous_profiles(context, output, &store, project_id, &profiles)?;

    let created_at = now_unix_nanos()?;
    let expires_at = created_at
        .checked_add(
            DEFAULT_INVITE_TTL_SECONDS.checked_mul(NANOS_PER_SECOND).ok_or(CliError::Time)?,
        )
        .ok_or(CliError::Time)?;
    let built_invite = build_signed_invite(
        project_id,
        &issuer,
        &recipient,
        &profiles,
        invite_role,
        role_label,
        expires_at,
    )?;
    let output_path =
        args.output.clone().unwrap_or_else(|| default_invite_output_path(context, created_at));
    ensure_invite_output_available(&output_path)?;

    let invite_record = persist_invite(
        context,
        &mut store,
        project_id,
        &issuer,
        &built_invite,
        &output_path,
        created_at,
    )?;

    let redact_names = privacy_redact_names_enabled(context, false)?;
    write_invite_created_output(
        output,
        &invite_record,
        &built_invite.issuer_fingerprint,
        &output_path,
        redact_names,
    )
}

fn team_revoke_invite_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &TeamRevokeInviteArgs,
) -> Result<(), CliError> {
    let resolved = require_project(context)?;
    let mut store = open_store(context)?;
    let project_id = resolved.config.project_id.as_str();
    ensure_project_exists(&store, project_id)?;

    let issuer = load_invite_issuer(&store, project_id)?;
    let invite = store.get_team_invite(&issuer.team.id, &args.invite_id)?.ok_or_else(|| {
        secret_not_found_error(format!("team invite not found: {}", args.invite_id))
    })?;
    if invite.accepted_at.is_some() || invite.revoked_at.is_some() {
        return Err(locket_store::StoreError::InviteReplayDetected {
            invite_id: invite.id.clone(),
        }
        .into());
    }
    if !can_revoke_invite(&issuer.member.role, &issuer.member.id, &invite) {
        return Err(team_role_denied_error("team role cannot revoke this invite"));
    }

    let timestamp = now_unix_nanos()?;
    let audit_key = load_project_key(context, &store, project_id, KeyPurpose::Audit)?;
    let metadata = json!({
        "schema_version": 1,
        "action": "TEAM_INVITE",
        "status": "SUCCESS",
        "command": "team revoke-invite",
        "operation": "revoke",
        "project_id": project_id,
        "team_id": &issuer.team.id,
        "invite_id": &invite.id,
        "issuer_member_id": &invite.issuer_member_id,
        "revoker_member_id": &issuer.member.id,
        "recipient_device_fingerprint": &invite.recipient_device_fingerprint,
        "role": &invite.role,
        "profiles": &invite.profiles,
        "created_at": invite.created_at,
        "expires_at": invite.expires_at,
        "revoked_at": timestamp,
    });
    let audit = AuditWrite {
        project_id,
        profile_id: None,
        action: "TEAM_INVITE",
        status: "SUCCESS",
        secret_name: None,
        command: Some("team revoke-invite"),
        metadata_json: &metadata,
        timestamp,
    };
    store.revoke_team_invite(
        &args.invite_id,
        timestamp,
        Some(AuditContext { key: audit_key.as_ref(), write: &audit }),
    )?;

    let redact_names = privacy_redact_names_enabled(context, false)?;
    writeln!(output, "team_invite: revoked")?;
    writeln!(output, "invite_id: {}", invite_id_label_from_str(&args.invite_id, redact_names))?;
    writeln!(output, "role: {}", invite.role)?;
    writeln!(output, "profiles: {}", profiles_label(&invite.profiles, redact_names))?;
    writeln!(
        output,
        "recipient_fingerprint: {}",
        device_fingerprint_label(&invite.recipient_device_fingerprint, redact_names)
    )?;
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
    let caller = current_team_member_role(&store, project_id, &team.id)?;

    if member.removed_at.is_some() {
        return Err(secret_not_found_error(format!(
            "team member already removed: {}",
            member.display_name
        )));
    }

    authorize_team_remove(caller, &member)?;

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
    let redact_names = privacy_redact_names_enabled(context, false)?;
    write_rotation_checklist(output, &store, project_id, redact_names)?;

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

    let Some(team) = store.get_team_by_project(project_id)? else {
        return Err(team_role_denied_error("no team initialized for this project"));
    };

    let device = store
        .find_device(project_id, &args.device)?
        .ok_or_else(|| invalid_reference_error("device not found"))?;
    let caller = current_team_member_role(&store, project_id, &team.id)?;
    let target_member = store.get_active_team_member_by_device(&team.id, &device.id)?;
    authorize_team_device_revoke(caller, target_member.as_ref())?;

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
    let redact_names = privacy_redact_names_enabled(context, false)?;
    write_rotation_checklist(output, &store, project_id, redact_names)?;
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

struct InviteIssuer {
    team: TeamRecord,
    local_device: DeviceRecord,
    member: TeamMemberListRecord,
}

struct BuiltInvite {
    id: String,
    encoded_invite: String,
    issuer_fingerprint: String,
    recipient_fingerprint: String,
    role: &'static str,
    profiles: Vec<String>,
    nonce: [u8; 24],
    expires_at: i64,
}

fn load_invite_issuer(
    store: &locket_store::Store,
    project_id: &str,
) -> Result<InviteIssuer, CliError> {
    let team = store
        .get_team_by_project(project_id)?
        .ok_or_else(|| team_role_denied_error("no team initialized for this project"))?;
    let local_device = store
        .get_active_local_device(project_id)?
        .ok_or_else(|| invalid_reference_error("local device is not initialized"))?;
    let member = store
        .get_team_member_by_device(&team.id, &local_device.id)?
        .ok_or_else(|| team_role_denied_error("local device is not a team member"))?;
    Ok(InviteIssuer { team, local_device, member })
}

fn build_signed_invite(
    project_id: &str,
    issuer: &InviteIssuer,
    recipient: &RecipientDevice,
    profiles: &[String],
    invite_role: TeamRole,
    role_label: &'static str,
    expires_at: i64,
) -> Result<BuiltInvite, CliError> {
    let invite_id = InviteId::generate().map_err(|_| CliError::Time)?;
    let nonce = invite_nonce()?;
    let signing_key = signing_key_from_device(&issuer.local_device.signing_public_key)?;
    let issuer_signing_public_key = signing_key.verifying_key().to_bytes();
    let issuer_sealing_public_key = issuer
        .local_device
        .sealing_public_key
        .as_slice()
        .try_into()
        .map_err(|_| metadata_invalid_error("issuer sealing key must be 32 bytes"))?;
    let issuer_fingerprint =
        device::device_fingerprint_hex(&issuer_signing_public_key, &issuer_sealing_public_key);
    let payload = InvitePayload {
        v: 1,
        invite_id: invite_id.clone(),
        project_id: ProjectId::new(project_id.to_owned())
            .map_err(|_| metadata_invalid_error("project id is invalid"))?,
        issuer_member_id: MemberId::new(issuer.member.id.clone())
            .map_err(|_| metadata_invalid_error("issuer member id is invalid"))?,
        issuer_signing_public_key: BASE64URL_NOPAD.encode(&issuer_signing_public_key),
        issuer_sealing_public_key: BASE64URL_NOPAD.encode(&issuer_sealing_public_key),
        issuer_device_fingerprint: issuer_fingerprint.clone(),
        recipient_device_fingerprint: recipient.fingerprint.clone(),
        recipient_sealing_public_key: BASE64URL_NOPAD.encode(&recipient.sealing_public_key),
        role: invite_role,
        profiles: profiles.to_vec(),
        expires_at: expires_at / NANOS_PER_SECOND,
        nonce: BASE64URL_NOPAD.encode(&nonce),
    };
    let signed_invite = SignedInvite::sign(&signing_key, payload)
        .map_err(|error| metadata_invalid_error(format!("invite signing failed: {error}")))?;
    let encoded_invite = signed_invite
        .encode()
        .map_err(|error| metadata_invalid_error(format!("invite encoding failed: {error}")))?;
    Ok(BuiltInvite {
        id: invite_id.as_str().to_owned(),
        encoded_invite,
        issuer_fingerprint,
        recipient_fingerprint: recipient.fingerprint.clone(),
        role: role_label,
        profiles: profiles.to_vec(),
        nonce,
        expires_at,
    })
}

fn persist_invite(
    context: &RuntimeContext,
    store: &mut locket_store::Store,
    project_id: &str,
    issuer: &InviteIssuer,
    invite: &BuiltInvite,
    output_path: &Path,
    created_at: i64,
) -> Result<TeamInviteRecord, CliError> {
    let audit_key = load_project_key(context, store, project_id, KeyPurpose::Audit)?;
    write_invite_file(output_path, &invite.encoded_invite)?;
    let invite_record = TeamInviteRecord {
        id: invite.id.clone(),
        team_id: issuer.team.id.clone(),
        issuer_member_id: issuer.member.id.clone(),
        recipient_device_fingerprint: invite.recipient_fingerprint.clone(),
        role: invite.role.to_owned(),
        profiles: invite.profiles.clone(),
        nonce: invite.nonce.to_vec(),
        created_at,
        expires_at: invite.expires_at,
    };
    let metadata = json!({
        "schema_version": 1,
        "action": "TEAM_INVITE",
        "status": "SUCCESS",
        "command": "team invite",
        "project_id": project_id,
        "team_id": issuer.team.id,
        "invite_id": invite_record.id,
        "issuer_member_id": issuer.member.id,
        "issuer_device_id": issuer.local_device.id,
        "issuer_device_fingerprint": invite.issuer_fingerprint,
        "recipient_device_fingerprint": invite_record.recipient_device_fingerprint,
        "role": invite_record.role,
        "profiles": invite_record.profiles,
        "expires_at": invite_record.expires_at,
        "output_path_kind": output_path_kind(output_path, context),
    });
    let audit = AuditWrite {
        project_id,
        profile_id: None,
        action: "TEAM_INVITE",
        status: "SUCCESS",
        secret_name: None,
        command: Some("team invite"),
        metadata_json: &metadata,
        timestamp: created_at,
    };
    if let Err(error) = store.insert_team_invite(
        &invite_record,
        Some(AuditContext { key: audit_key.as_ref(), write: &audit }),
    ) {
        let _ignored = fs::remove_file(output_path);
        return Err(error.into());
    }
    Ok(invite_record)
}

fn write_invite_created_output(
    output: &mut impl Write,
    invite_record: &TeamInviteRecord,
    issuer_fingerprint: &str,
    output_path: &Path,
    redact_names: bool,
) -> Result<(), CliError> {
    writeln!(output, "team_invite: created")?;
    writeln!(output, "invite_id: {}", invite_id_label_from_str(&invite_record.id, redact_names))?;
    writeln!(
        output,
        "issuer_fingerprint: {}",
        device_fingerprint_label(issuer_fingerprint, redact_names)
    )?;
    writeln!(
        output,
        "recipient_fingerprint: {}",
        device_fingerprint_label(&invite_record.recipient_device_fingerprint, redact_names)
    )?;
    writeln!(output, "role: {}", invite_record.role)?;
    writeln!(output, "profiles: {}", profiles_label(&invite_record.profiles, redact_names))?;
    writeln!(output, "expires_at: {}", format_invite_expiry(invite_record.expires_at))?;
    writeln!(output, "output: {}", output_path.display())?;
    writeln!(output, "metadata_only: yes")?;
    Ok(())
}

struct RecipientDevice {
    fingerprint: String,
    sealing_public_key: [u8; 32],
}

fn decode_recipient_device(value: &str) -> Result<RecipientDevice, CliError> {
    let descriptor = device::decode_device_descriptor(value)?;
    let signing_public_key = device::decode_descriptor_key(&descriptor.signing_public_key_ed25519)?;
    let sealing_public_key = device::decode_descriptor_key(&descriptor.sealing_public_key_x25519)?;
    let fingerprint = device::device_fingerprint_hex(&signing_public_key, &sealing_public_key);
    if fingerprint != descriptor.fingerprint_sha256 {
        return Err(metadata_invalid_error("recipient device descriptor fingerprint mismatch"));
    }
    Ok(RecipientDevice { fingerprint, sealing_public_key })
}

fn validate_invite_profiles(
    store: &locket_store::Store,
    project_id: &str,
    profile_names: &[String],
) -> Result<Vec<String>, CliError> {
    let mut unique = BTreeSet::new();
    for name in profile_names {
        if name.trim().is_empty() || name.chars().any(char::is_control) {
            return Err(metadata_invalid_error("invalid invite profile name"));
        }
        let Some(profile) = store.get_profile_by_name(project_id, name)? else {
            return Err(profile_not_found_error(format!("profile not found: {name}")));
        };
        unique.insert(profile.name);
    }
    Ok(unique.into_iter().collect())
}

fn confirm_dangerous_profiles(
    context: &RuntimeContext,
    output: &mut impl Write,
    store: &locket_store::Store,
    project_id: &str,
    profiles: &[String],
) -> Result<(), CliError> {
    let mut dangerous = Vec::new();
    for profile_name in profiles {
        if let Some(profile) = store.get_profile_by_name(project_id, profile_name)?
            && profile.dangerous
        {
            dangerous.push(profile.name);
        }
    }
    if dangerous.is_empty() {
        return Ok(());
    }
    let names = dangerous.join(",");
    writeln!(output, "dangerous_profiles: {names}")?;
    writeln!(output, "metadata_only: yes")?;
    writeln!(output, "type 'team invite {names}' to confirm dangerous profile invite")?;
    let confirmation = context.confirmation_reader.read_confirmation("team invite")?;
    if confirmation.trim_end_matches(['\r', '\n']) != format!("team invite {names}") {
        return Err(confirmation_failed_error(
            "confirmation did not match dangerous profile invite scope",
        ));
    }
    Ok(())
}

fn validate_invitee_name(name: &str) -> Result<(), CliError> {
    if name.trim().is_empty() || name.len() > 80 || name.chars().any(char::is_control) {
        return Err(metadata_invalid_error("invalid invitee name"));
    }
    Ok(())
}

const fn role_from_arg(role: TeamRoleArg) -> TeamRole {
    match role {
        TeamRoleArg::Owner => TeamRole::Owner,
        TeamRoleArg::Maintainer => TeamRole::Maintainer,
        TeamRoleArg::Developer => TeamRole::Developer,
        TeamRoleArg::ReadOnly => TeamRole::ReadOnly,
    }
}

const fn role_label(role: TeamRoleArg) -> &'static str {
    match role {
        TeamRoleArg::Owner => "owner",
        TeamRoleArg::Maintainer => "maintainer",
        TeamRoleArg::Developer => "developer",
        TeamRoleArg::ReadOnly => "read-only",
    }
}

fn can_issue_role(issuer_role: &str, invite_role: TeamRoleArg) -> bool {
    match issuer_role {
        "owner" => true,
        "maintainer" => matches!(invite_role, TeamRoleArg::Developer | TeamRoleArg::ReadOnly),
        _ => false,
    }
}

fn can_revoke_invite(
    revoker_role: &str,
    revoker_member_id: &str,
    invite: &StoredTeamInviteRecord,
) -> bool {
    match revoker_role {
        "owner" => true,
        "maintainer" => invite.issuer_member_id == revoker_member_id || invite.role != "owner",
        _ => false,
    }
}

fn invite_nonce() -> Result<[u8; 24], CliError> {
    let random = generate_key()?;
    let mut nonce = [0_u8; 24];
    nonce.copy_from_slice(&random[..24]);
    Ok(nonce)
}

fn signing_key_from_device(bytes: &[u8]) -> Result<SigningKey, CliError> {
    let seed: [u8; 32] = bytes
        .try_into()
        .map_err(|_| metadata_invalid_error("issuer signing key must be 32 bytes"))?;
    Ok(SigningKey::from_bytes(&seed))
}

fn default_invite_output_path(context: &RuntimeContext, timestamp: i64) -> PathBuf {
    let rendered = unix_nanos_to_rfc3339(timestamp)
        .map_or_else(|| timestamp.to_string(), |value| value.replace(':', "-"));
    context.cwd.join(format!("locket-invite-{rendered}.locket-invite"))
}

fn ensure_invite_output_available(path: &Path) -> Result<(), CliError> {
    if path.exists() {
        return Err(invalid_reference_error("invite output already exists"));
    }
    Ok(())
}

fn write_invite_file(path: &Path, encoded_invite: &str) -> Result<(), CliError> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    set_user_only_file_options(&mut options);
    let mut file = options.open(path).map_err(|error| {
        if error.kind() == io::ErrorKind::AlreadyExists {
            invalid_reference_error("invite output already exists")
        } else {
            CliError::Io(error)
        }
    })?;
    file.write_all(encoded_invite.as_bytes())?;
    file.write_all(b"\n")?;
    set_user_only_file_permissions(path)?;
    Ok(())
}

fn output_path_kind(path: &Path, context: &RuntimeContext) -> &'static str {
    if path.parent().is_some_and(|parent| parent == context.cwd) {
        "current_directory"
    } else if path.is_absolute() {
        "absolute"
    } else {
        "relative"
    }
}

fn format_invite_expiry(timestamp: i64) -> String {
    unix_nanos_to_rfc3339(timestamp).unwrap_or_else(|| timestamp.to_string())
}

fn invite_id_label_from_str(invite_id: &str, redact_names: bool) -> String {
    if redact_names { privacy_alias("invite", invite_id) } else { invite_id.to_owned() }
}

fn device_fingerprint_label(fingerprint: &str, redact_names: bool) -> String {
    if redact_names { privacy_alias("device", fingerprint) } else { fingerprint.to_owned() }
}

fn profiles_label(profiles: &[String], redact_names: bool) -> String {
    if profiles.is_empty() {
        return "-".to_owned();
    }
    profiles
        .iter()
        .map(
            |profile| {
                if redact_names { privacy_alias("profile", profile) } else { profile.clone() }
            },
        )
        .collect::<Vec<_>>()
        .join(",")
}

fn team_name_label(team: &TeamRecord, redact_names: bool) -> String {
    if redact_names { privacy_alias("team", &team.name) } else { team.name.clone() }
}

fn team_id_label(team: &TeamRecord, redact_names: bool) -> String {
    if redact_names { privacy_alias("team", &team.id) } else { team.id.clone() }
}

fn member_id_label(member: &TeamMemberListRecord, redact_names: bool) -> String {
    if redact_names { privacy_alias("member", &member.id) } else { member.id.clone() }
}

fn member_display_label(member: &TeamMemberListRecord, redact_names: bool) -> String {
    if redact_names {
        privacy_alias("member", &member.display_name)
    } else {
        member.display_name.clone()
    }
}

fn invite_id_label(invite: &PendingTeamInviteRecord, redact_names: bool) -> String {
    if redact_names { privacy_alias("invite", &invite.id) } else { invite.id.clone() }
}

fn invite_recipient_label(invite: &PendingTeamInviteRecord, redact_names: bool) -> String {
    if redact_names {
        privacy_alias("device", &invite.recipient_device_fingerprint)
    } else {
        invite.recipient_device_fingerprint.clone()
    }
}

fn invite_profiles_label(invite: &PendingTeamInviteRecord, redact_names: bool) -> String {
    if invite.profiles.is_empty() {
        return "-".to_owned();
    }
    invite
        .profiles
        .iter()
        .map(
            |profile| {
                if redact_names { privacy_alias("profile", profile) } else { profile.clone() }
            },
        )
        .collect::<Vec<_>>()
        .join(",")
}

fn optional_timestamp_label(value: Option<i64>) -> String {
    value.map_or_else(|| "-".to_owned(), |timestamp| timestamp.to_string())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TeamMemberRole {
    Owner,
    Maintainer,
    Developer,
    ReadOnly,
}

impl TeamMemberRole {
    fn from_label(label: &str) -> Option<Self> {
        match label {
            "owner" => Some(Self::Owner),
            "maintainer" => Some(Self::Maintainer),
            "developer" => Some(Self::Developer),
            "read-only" => Some(Self::ReadOnly),
            _ => None,
        }
    }
}

fn current_team_member_role(
    store: &locket_store::Store,
    project_id: &str,
    team_id: &str,
) -> Result<TeamMemberRole, CliError> {
    let Some(local_device) = store.get_active_local_device(project_id)? else {
        return Err(team_role_denied_error("team action requires an active local team device"));
    };
    let Some(member) = store.get_active_team_member_by_device(team_id, &local_device.id)? else {
        return Err(team_role_denied_error("local device is not an active team member"));
    };
    TeamMemberRole::from_label(&member.role)
        .ok_or_else(|| team_role_denied_error("local team member has an unknown role"))
}

fn authorize_team_remove(
    caller: TeamMemberRole,
    target: &TeamMemberListRecord,
) -> Result<(), CliError> {
    match caller {
        TeamMemberRole::Owner => Ok(()),
        TeamMemberRole::Maintainer if matches!(target.role.as_str(), "developer" | "read-only") => {
            Ok(())
        }
        TeamMemberRole::Maintainer => Err(team_role_denied_error(
            "maintainers can remove only developer and read-only members",
        )),
        TeamMemberRole::Developer | TeamMemberRole::ReadOnly => {
            Err(team_role_denied_error("team role cannot remove members"))
        }
    }
}

fn authorize_team_device_revoke(
    caller: TeamMemberRole,
    target_member: Option<&TeamMemberListRecord>,
) -> Result<(), CliError> {
    match caller {
        TeamMemberRole::Owner => Ok(()),
        TeamMemberRole::Maintainer => {
            let Some(member) = target_member else {
                return Err(team_role_denied_error(
                    "maintainers can revoke only non-owner member devices",
                ));
            };
            if member.role == "owner" {
                return Err(team_role_denied_error(
                    "maintainers cannot revoke owner member devices",
                ));
            }
            Ok(())
        }
        TeamMemberRole::Developer | TeamMemberRole::ReadOnly => {
            Err(team_role_denied_error("team role cannot revoke team devices"))
        }
    }
}

/// Emits a metadata-only rotation checklist for every profile in the
/// project, listing the count of active secrets that an Owner-level
/// principal could have accessed. Member-to-profile scoping is
/// approximated as "all project profiles" until invite-issued profile
/// lists are persisted; the placeholder below tracks the gap.
///
/// Output shape (one block, never a value):
///
/// ```text
/// rotation_checklist:
///   profile <name>: rotate_active_secrets=N
///   ...
///   total_active_secrets=N
///   action: rotate listed secrets in each profile and `team revoke-device` any associated devices
///   scope_note: profile membership not yet persisted; checklist covers all project profiles
/// ```
fn write_rotation_checklist(
    output: &mut impl Write,
    store: &locket_store::Store,
    project_id: &str,
    redact_names: bool,
) -> Result<(), CliError> {
    let profiles = store.list_profiles(project_id)?;
    writeln!(output, "rotation_checklist:")?;
    if profiles.is_empty() {
        writeln!(output, "  (no profiles)")?;
        writeln!(output, "  total_active_secrets=0")?;
        return Ok(());
    }
    let mut total: usize = 0;
    for profile in &profiles {
        let secrets = store.list_active_secrets_by_profile(project_id, &profile.id)?;
        total = total.saturating_add(secrets.len());
        let label =
            if redact_names { privacy_alias("profile", &profile.id) } else { profile.name.clone() };
        writeln!(output, "  profile {label}: rotate_active_secrets={}", secrets.len())?;
    }
    writeln!(output, "  total_active_secrets={total}")?;
    writeln!(
        output,
        "  action: rotate listed secrets in each profile and `team revoke-device` any associated devices"
    )?;
    writeln!(
        output,
        "  scope_note: profile membership not yet persisted; checklist covers all project profiles"
    )?;
    Ok(())
}
