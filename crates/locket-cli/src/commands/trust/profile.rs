//! Profile command implementations.

use std::io::Write;

use locket_core::{ProfileId, ProfileName};
use locket_crypto::KeyPurpose;
use locket_store::{AuditWrite, ProfileRecord, Store};
use serde_json::{Value, json};

use crate::{
    CliError, LOCKET_TOML, ProfileCommand, ProfileNameArgs, RuntimeContext,
    initialize_profile_keys, load_project_key, now_unix_nanos, open_store, require_project,
    write_project_config,
};

pub fn profile_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    command: ProfileCommand,
) -> Result<(), CliError> {
    match command {
        ProfileCommand::List => list_profiles(context, output),
        ProfileCommand::Create(args) => create_profile(context, output, args),
        ProfileCommand::MarkDangerous(args) => set_profile_dangerous(context, output, args, true),
        ProfileCommand::ClearDangerous(args) => set_profile_dangerous(context, output, args, false),
    }
}

fn list_profiles(context: &RuntimeContext, output: &mut impl Write) -> Result<(), CliError> {
    let resolved = require_project(context)?;
    let store = open_store(context)?;
    let profiles = store.list_profiles(resolved.config.project_id.as_str())?;

    if profiles.is_empty() {
        writeln!(output, "no profiles")?;
        return Ok(());
    }

    for profile in profiles {
        let marker =
            if profile.name == resolved.config.default_profile.as_str() { "*" } else { " " };
        let dangerous = if profile.dangerous { " dangerous" } else { "" };
        writeln!(output, "{marker} {} ({}){dangerous}", profile.name, profile.id)?;
    }

    Ok(())
}

fn create_profile(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: ProfileNameArgs,
) -> Result<(), CliError> {
    let resolved = require_project(context)?;
    let profile_name = ProfileName::new(args.profile)
        .map_err(|_| CliError::Config("invalid profile name".to_owned()))?;
    let store = open_store(context)?;

    if store
        .get_profile_by_name(resolved.config.project_id.as_str(), profile_name.as_str())?
        .is_some()
    {
        return Err(CliError::Config("profile already exists".to_owned()));
    }

    let profile_id = ProfileId::generate().map_err(|_| CliError::Time)?;
    let inserted = store.insert_profile_if_absent(
        profile_id.as_str(),
        resolved.config.project_id.as_str(),
        profile_name.as_str(),
        false,
        now_unix_nanos()?,
    )?;
    if !inserted {
        return Err(CliError::Config("profile already exists".to_owned()));
    }
    initialize_profile_keys(
        context,
        &store,
        &resolved.config,
        profile_id.as_str(),
        now_unix_nanos()?,
    )?;

    writeln!(output, "created profile {profile_name} ({profile_id})")?;
    Ok(())
}

fn set_profile_dangerous(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: ProfileNameArgs,
    dangerous: bool,
) -> Result<(), CliError> {
    let resolved = require_project(context)?;
    let profile_name = ProfileName::new(args.profile)
        .map_err(|_| CliError::Config("invalid profile name".to_owned()))?;
    let mut store = open_store(context)?;
    let project_id = resolved.config.project_id.as_str();
    let Some(profile) = store.get_profile_by_name(project_id, profile_name.as_str())? else {
        return Err(CliError::Config("profile not found".to_owned()));
    };

    let prior_dangerous = profile.dangerous;
    let new_state = dangerous_state_label(dangerous);
    let prior_state = dangerous_state_label(prior_dangerous);

    print_profile_dangerous_summary(&store, output, project_id, &profile, dangerous)?;

    if prior_dangerous == dangerous {
        writeln!(
            output,
            "profile {} ({}) dangerous={new_state} unchanged metadata_only=yes",
            profile.name, profile.id
        )?;
        return Ok(());
    }

    confirm_profile_dangerous_change(context, output, &profile, dangerous)?;

    store.set_profile_dangerous(project_id, profile_name.as_str(), dangerous)?;

    let timestamp = now_unix_nanos()?;
    let metadata = profile_dangerous_audit_metadata(&profile, prior_dangerous, dangerous);
    let audit_key = load_project_key(context, &store, project_id, KeyPurpose::Audit)?;
    let audit = AuditWrite {
        project_id,
        profile_id: Some(&profile.id),
        action: "PROFILE_CHANGE",
        status: "SUCCESS",
        secret_name: None,
        command: Some(if dangerous { "profile mark-dangerous" } else { "profile clear-dangerous" }),
        metadata_json: &metadata,
        timestamp,
    };
    store.append_audit(audit_key.as_ref(), &audit)?;

    writeln!(
        output,
        "profile {} ({}) dangerous={new_state} prior={prior_state} metadata_only=yes",
        profile.name, profile.id
    )?;
    Ok(())
}

fn print_profile_dangerous_summary(
    store: &Store,
    output: &mut impl Write,
    project_id: &str,
    profile: &ProfileRecord,
    target_dangerous: bool,
) -> Result<(), CliError> {
    let secret_count = store.list_active_secrets_by_profile(project_id, &profile.id)?.len();
    let grant_count = store.count_directory_grants_for_profile(project_id, &profile.id)?;
    writeln!(output, "profile: {}", profile.name)?;
    writeln!(output, "profile_id: {}", profile.id)?;
    writeln!(output, "current_dangerous: {}", dangerous_state_label(profile.dangerous))?;
    writeln!(output, "target_dangerous: {}", dangerous_state_label(target_dangerous))?;
    writeln!(output, "active_secrets: {secret_count}")?;
    writeln!(output, "directory_grants: {grant_count}")?;
    writeln!(output, "metadata_only: yes")?;
    Ok(())
}

fn confirm_profile_dangerous_change(
    context: &RuntimeContext,
    output: &mut impl Write,
    profile: &ProfileRecord,
    dangerous: bool,
) -> Result<(), CliError> {
    let (prompt_label, expected) = if dangerous {
        ("mark-dangerous", profile.name.clone())
    } else {
        ("clear-dangerous", format!("clear {}", profile.name))
    };
    writeln!(output, "type '{expected}' to confirm {prompt_label}")?;
    let confirmation =
        context.confirmation_reader.read_confirmation(&format!("profile {prompt_label}"))?;
    if confirmation.trim_end_matches(['\r', '\n']) != expected {
        return Err(CliError::Config("confirmation did not match".to_owned()));
    }
    Ok(())
}

fn profile_dangerous_audit_metadata(profile: &ProfileRecord, prior: bool, new: bool) -> Value {
    json!({
        "schema_version": 1,
        "action": "PROFILE_CHANGE",
        "status": "SUCCESS",
        "operation": "set_dangerous",
        "profile_id": profile.id,
        "profile_name": profile.name,
        "prior_dangerous": prior,
        "new_dangerous": new,
    })
}

const fn dangerous_state_label(dangerous: bool) -> &'static str {
    if dangerous { "dangerous" } else { "not-dangerous" }
}

pub fn use_profile_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: ProfileNameArgs,
) -> Result<(), CliError> {
    let profile_name = ProfileName::new(args.profile)
        .map_err(|_| CliError::Config("invalid profile name".to_owned()))?;
    let mut resolved = require_project(context)?;
    let store = open_store(context)?;
    let profile = store
        .get_profile_by_name(resolved.config.project_id.as_str(), profile_name.as_str())?
        .ok_or_else(|| CliError::Config("profile not found".to_owned()))?;
    resolved.config.default_profile = profile_name;
    write_project_config(&resolved.root.join(LOCKET_TOML), &resolved.config)?;
    writeln!(output, "active profile: {} ({})", profile.name, profile.id)?;
    Ok(())
}
