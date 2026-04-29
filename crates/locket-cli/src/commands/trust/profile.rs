//! Profile command implementations.

use std::io::Write;

use locket_core::{ProfileId, ProfileName};
use locket_crypto::KeyPurpose;
use locket_store::{AuditWrite, ProfileRecord, Store};
use serde_json::{Value, json};

use crate::{
    CliError, LOCKET_TOML, ProfileCommand, ProfileNameArgs, RuntimeContext,
    confirmation_failed_error, format_hex, initialize_profile_keys, invalid_profile_name_error,
    load_project_key, now_unix_nanos, open_store, profile_not_found_error, require_project,
    root_hash, secret_already_exists_error, write_project_config,
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
        .map_err(|_| invalid_profile_name_error("invalid profile name"))?;
    let mut store = open_store(context)?;
    let project_id = resolved.config.project_id.as_str();

    if store.get_profile_by_name(project_id, profile_name.as_str())?.is_some() {
        return Err(secret_already_exists_error("profile already exists"));
    }

    let profile_id = ProfileId::generate().map_err(|_| CliError::Time)?;
    let timestamp = now_unix_nanos()?;
    let inserted = store.insert_profile_if_absent(
        profile_id.as_str(),
        project_id,
        profile_name.as_str(),
        false,
        timestamp,
    )?;
    if !inserted {
        return Err(secret_already_exists_error("profile already exists"));
    }
    initialize_profile_keys(context, &store, &resolved.config, profile_id.as_str(), timestamp)?;
    let metadata =
        profile_create_audit_metadata(project_id, profile_id.as_str(), profile_name.as_str());
    let audit_key = load_project_key(context, &store, project_id, KeyPurpose::Audit)?;
    let audit = AuditWrite {
        project_id,
        profile_id: Some(profile_id.as_str()),
        action: "PROFILE_CREATE",
        status: "SUCCESS",
        secret_name: None,
        command: None,
        metadata_json: &metadata,
        timestamp,
    };
    store.append_audit(audit_key.as_ref(), &audit)?;

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
        .map_err(|_| invalid_profile_name_error("invalid profile name"))?;
    let mut store = open_store(context)?;
    let project_id = resolved.config.project_id.as_str();
    let Some(profile) = store.get_profile_by_name(project_id, profile_name.as_str())? else {
        return Err(profile_not_found_error("profile not found"));
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
        return Err(confirmation_failed_error("confirmation did not match"));
    }
    Ok(())
}

fn profile_create_audit_metadata(project_id: &str, profile_id: &str, profile_name: &str) -> Value {
    json!({
        "schema_version": 1,
        "action": "PROFILE_CREATE",
        "status": "SUCCESS",
        "project_id": project_id,
        "profile_id": profile_id,
        "profile_name": profile_name,
        "dangerous": false,
        "key_purposes_initialized": ["profile-secret", "profile-fingerprint"],
    })
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
        .map_err(|_| invalid_profile_name_error("invalid profile name"))?;
    let mut resolved = require_project(context)?;
    let mut store = open_store(context)?;
    let project_id = resolved.config.project_id.as_str().to_owned();
    let new_profile = store
        .get_profile_by_name(&project_id, profile_name.as_str())?
        .ok_or_else(|| profile_not_found_error("profile not found"))?;
    let prior_profile_name = resolved.config.default_profile.as_str().to_owned();
    if prior_profile_name == profile_name.as_str() {
        writeln!(output, "active profile: {} ({}) unchanged", new_profile.name, new_profile.id)?;
        return Ok(());
    }
    let prior_profile = store
        .get_profile_by_name(&project_id, &prior_profile_name)?
        .ok_or_else(|| profile_not_found_error("current default profile not found"))?;

    let timestamp = now_unix_nanos()?;
    let root_hash = format_hex(&root_hash(&resolved.root)?);
    let audit_key = load_project_key(context, &store, &project_id, KeyPurpose::Audit)?;
    let metadata =
        profile_use_audit_metadata(&project_id, &prior_profile, &new_profile, root_hash.as_str());
    resolved.config.default_profile = profile_name;
    write_project_config(&resolved.root.join(LOCKET_TOML), &resolved.config)?;

    let audit = AuditWrite {
        project_id: &project_id,
        profile_id: Some(&new_profile.id),
        action: "PROFILE_CHANGE",
        status: "SUCCESS",
        secret_name: None,
        command: Some("use"),
        metadata_json: &metadata,
        timestamp,
    };
    store.append_audit(audit_key.as_ref(), &audit)?;

    writeln!(output, "active profile: {} ({})", new_profile.name, new_profile.id)?;
    Ok(())
}

fn profile_use_audit_metadata(
    project_id: &str,
    prior_profile: &ProfileRecord,
    new_profile: &ProfileRecord,
    root_hash: &str,
) -> Value {
    json!({
        "schema_version": 1,
        "action": "PROFILE_CHANGE",
        "status": "SUCCESS",
        "operation": "use",
        "command": "use",
        "project_id": project_id,
        "prior_profile_id": prior_profile.id,
        "prior_profile_name": prior_profile.name,
        "new_profile_id": new_profile.id,
        "new_profile_name": new_profile.name,
        "root_hash": root_hash,
    })
}
