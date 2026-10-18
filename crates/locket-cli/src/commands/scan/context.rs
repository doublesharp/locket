//! `locket context` command and privacy/redaction helpers.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;

use locket_core::{CommandPolicy, PolicyDocument, SecretName};
use locket_store::{ProfileRecord, SecretRecord, Store};

use crate::commands::config::spec::{config_get_value, read_user_config};
use crate::{
    CliError, LOCKET_TOML, RedactNamesArgs, ResolvedProject, RuntimeContext, command_type,
    metadata_invalid_error, open_store, privacy_alias, read_policy_document, require_project,
    yes_no,
};

/// Emits real local identity without scanning, decrypting, initializing, or starting an agent.
pub fn context_json_command(
    context: &RuntimeContext,
    output: &mut impl Write,
) -> Result<(), CliError> {
    use rusqlite::OptionalExtension;
    let resolved = require_project(context)?;
    if !context.store_path.is_file() {
        return Err(crate::runtime::error::corrupt_db_error("local store is missing"));
    }
    let store_path = context.store_path.canonicalize()?;
    let connection = rusqlite::Connection::open_with_flags(
        &store_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .map_err(locket_store::StoreError::from)?;
    let profile: Option<(String,String)> = connection.query_row(
        "SELECT profiles.id, profiles.name FROM profiles JOIN projects ON projects.id = profiles.project_id WHERE projects.id = ?1 AND profiles.name = ?2",
        (resolved.config.project_id.as_str(), resolved.config.default_profile.as_str()),
        |row| Ok((row.get(0)?,row.get(1)?)),
    ).optional().map_err(locket_store::StoreError::from)?;
    let (profile_id, profile_name) = profile.ok_or_else(|| {
        crate::runtime::error::profile_not_found_error(
            "project or default profile is missing from the local store",
        )
    })?;
    serde_json::to_writer(
        &mut *output,
        &serde_json::json!({
            "root": resolved.root,
            "project_id": resolved.config.project_id.as_str(),
            "project_name": resolved.config.name,
            "profile_id": profile_id,
            "profile_name": profile_name,
            "store_path": store_path,
        }),
    )?;
    writeln!(output)?;
    Ok(())
}

pub fn context_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &RedactNamesArgs,
) -> Result<(), CliError> {
    let resolved = require_project(context)?;
    let store = open_store(context)?;
    let redact_names = privacy_redact_names_enabled(context, args.redact_names)?;
    let profiles = store.list_profiles(resolved.config.project_id.as_str())?;
    let policy_document = read_policy_document(&resolved.root.join(LOCKET_TOML))?;
    let active_profile =
        profiles.iter().find(|profile| profile.name == resolved.config.default_profile.as_str());
    let active_profile_label = active_profile.map_or_else(
        || {
            if redact_names {
                privacy_alias("profile", resolved.config.default_profile.as_str())
            } else {
                resolved.config.default_profile.to_string()
            }
        },
        |profile| context_profile_label(profile, redact_names),
    );

    writeln!(output, "Project: {}", context_project_label(&resolved, redact_names))?;
    writeln!(output, "Profile: {active_profile_label}")?;
    writeln!(output, "Profiles:")?;
    if profiles.is_empty() {
        writeln!(output, "- none")?;
    }
    for profile in &profiles {
        let label = context_profile_label(profile, redact_names);
        let active = profile.name == resolved.config.default_profile.as_str();
        let secret_count = store
            .list_active_secrets_by_profile(resolved.config.project_id.as_str(), &profile.id)?
            .len();
        writeln!(
            output,
            "- {label} active={} dangerous={} secrets={secret_count}",
            yes_no(active),
            yes_no(profile.dangerous)
        )?;
    }

    let secret_summaries =
        context_secret_summaries(&store, &resolved, &profiles, &policy_document, redact_names)?;
    writeln!(output, "Secrets referenced:")?;
    if secret_summaries.is_empty() {
        writeln!(output, "- none")?;
    }
    for summary in secret_summaries {
        writeln!(
            output,
            "- {} profiles={} sources={}",
            summary.name,
            format_display_list(&summary.profiles),
            format_display_list(&summary.sources)
        )?;
    }

    writeln!(output, "Policies:")?;
    if policy_document.commands.is_empty() {
        writeln!(output, "- none")?;
    }
    for policy in policy_document.commands.values() {
        writeln!(
            output,
            "- {} type={} required={} optional={} confirm={} verify_user={}",
            context_policy_label(policy, redact_names),
            command_type(&policy.command),
            format_policy_secret_list(&policy.required_secrets, redact_names),
            format_policy_secret_list(&policy.optional_secrets, redact_names),
            yes_no(policy.confirm),
            yes_no(policy.require_user_verification)
        )?;
    }
    writeln!(output, "No secret values included.")?;
    writeln!(output, "metadata_only: yes")?;
    Ok(())
}

struct ContextSecretSummary {
    name: String,
    profiles: BTreeSet<String>,
    sources: BTreeSet<String>,
}

pub fn privacy_redact_names_enabled(
    context: &RuntimeContext,
    explicit: bool,
) -> Result<bool, CliError> {
    if explicit {
        return Ok(true);
    }
    let config = read_user_config(context)?;
    let Some(value) = config_get_value(&config, "privacy.redact_names") else {
        return Ok(false);
    };
    value.as_bool().ok_or_else(|| metadata_invalid_error("privacy.redact_names must be boolean"))
}

fn context_project_label(resolved: &ResolvedProject, redact_names: bool) -> String {
    if redact_names {
        privacy_alias("project", resolved.config.project_id.as_str())
    } else {
        resolved.config.name.clone()
    }
}

fn context_profile_label(profile: &ProfileRecord, redact_names: bool) -> String {
    if redact_names { privacy_alias("profile", &profile.id) } else { profile.name.clone() }
}

fn context_secret_label(secret: &SecretRecord, redact_names: bool) -> String {
    if redact_names { privacy_alias("secret", &secret.name) } else { secret.name.clone() }
}

fn context_policy_label(policy: &CommandPolicy, redact_names: bool) -> String {
    if redact_names { privacy_alias("policy", &policy.name) } else { policy.name.clone() }
}

fn context_secret_summaries(
    store: &Store,
    resolved: &ResolvedProject,
    profiles: &[ProfileRecord],
    policy_document: &PolicyDocument,
    redact_names: bool,
) -> Result<Vec<ContextSecretSummary>, CliError> {
    let mut summaries = BTreeMap::<String, ContextSecretSummary>::new();
    for profile in profiles {
        let profile_label = context_profile_label(profile, redact_names);
        for secret in store
            .list_active_secrets_by_profile(resolved.config.project_id.as_str(), &profile.id)?
        {
            let label = context_secret_label(&secret, redact_names);
            let summary = summaries.entry(label.clone()).or_insert_with(|| ContextSecretSummary {
                name: label,
                profiles: BTreeSet::new(),
                sources: BTreeSet::new(),
            });
            summary.profiles.insert(profile_label.clone());
            summary.sources.insert(secret.source);
        }
    }
    for policy in policy_document.commands.values() {
        let policy_label = context_policy_label(policy, redact_names);
        for secret in &policy.required_secrets {
            let label = context_secret_name_label(secret, redact_names);
            let summary = summaries.entry(label.clone()).or_insert_with(|| ContextSecretSummary {
                name: label,
                profiles: BTreeSet::new(),
                sources: BTreeSet::new(),
            });
            summary.profiles.insert(format!("policy:{policy_label}"));
            summary.sources.insert("policy-required".to_owned());
        }
        for secret in &policy.optional_secrets {
            let label = context_secret_name_label(secret, redact_names);
            let summary = summaries.entry(label.clone()).or_insert_with(|| ContextSecretSummary {
                name: label,
                profiles: BTreeSet::new(),
                sources: BTreeSet::new(),
            });
            summary.profiles.insert(format!("policy:{policy_label}"));
            summary.sources.insert("policy-optional".to_owned());
        }
    }
    Ok(summaries.into_values().collect())
}

fn context_secret_name_label(secret: &SecretName, redact_names: bool) -> String {
    if redact_names { privacy_alias("secret", secret.as_str()) } else { secret.as_str().to_owned() }
}

fn format_policy_secret_list(secrets: &[SecretName], redact_names: bool) -> String {
    if secrets.is_empty() {
        return "none".to_owned();
    }
    let values = secrets
        .iter()
        .map(|secret| context_secret_name_label(secret, redact_names))
        .collect::<BTreeSet<_>>();
    format_display_list(&values)
}

fn format_display_list(values: &BTreeSet<String>) -> String {
    if values.is_empty() {
        "none".to_owned()
    } else {
        values.iter().cloned().collect::<Vec<_>>().join(",")
    }
}
