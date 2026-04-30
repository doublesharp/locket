use std::io::Write;

use locket_store::{PendingTeamInviteRecord, TeamMemberListRecord, TeamRecord};

use crate::{
    CliError, RuntimeContext, TeamCommand, ensure_project_exists, now_unix_nanos, open_store,
    privacy_alias, privacy_redact_names_enabled, require_project,
};

pub fn team_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    command: TeamCommand,
) -> Result<(), CliError> {
    match command {
        TeamCommand::Members => team_members_command(context, output),
    }
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
