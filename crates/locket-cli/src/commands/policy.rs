use clap::{Args, Subcommand};
use locket_core::{PolicyDocument, SecretName};
use locket_crypto::KeyPurpose;
use locket_scan::EntropyRule;
use locket_store::AuditWrite;
use serde_json::json;
use std::fs;
use std::io::Write;

use crate::commands::scan::scanner::{ScanPolicy, read_scan_policy};
use crate::{
    CliError, LOCKET_TOML, RuntimeContext, confirmation_failed_error, invalid_reference_error,
    invalid_secret_name_error, load_project_key, metadata_invalid_error, now_unix_nanos,
    open_store, policy_not_found_error, require_project, secret_already_exists_error,
};

#[derive(Debug, Subcommand)]
pub enum PolicyCommand {
    /// Add an argv command policy.
    Add(PolicyAddArgs),
    /// Append optional secret names to a policy.
    Allow(PolicySecretsArgs),
    /// Append required secret names to a policy.
    Require(PolicySecretsArgs),
    /// Delete a command policy.
    Delete(PolicyDeleteArgs),
    /// Validate policy metadata in locket.toml.
    Doctor,
}

#[derive(Debug, Args)]
pub struct PolicyAddArgs {
    /// Command policy name.
    name: String,
    /// Command and arguments after `--`.
    #[arg(last = true, required = true)]
    command: Vec<String>,
}

#[derive(Debug, Args)]
pub struct PolicySecretsArgs {
    /// Command policy name.
    name: String,
    /// Secret names to add.
    #[arg(required = true)]
    keys: Vec<String>,
}

#[derive(Debug, Args)]
pub struct PolicyDeleteArgs {
    /// Command policy name.
    name: String,
    /// Confirm deletion without an interactive prompt.
    #[arg(long)]
    yes: bool,
}

pub fn command(
    context: &RuntimeContext,
    output: &mut impl Write,
    command: PolicyCommand,
) -> Result<(), CliError> {
    match command {
        PolicyCommand::Add(args) => add(context, output, args),
        PolicyCommand::Allow(args) => allow(context, output, args),
        PolicyCommand::Require(args) => require(context, output, args),
        PolicyCommand::Delete(args) => delete(context, output, args),
        PolicyCommand::Doctor => doctor(context, output),
    }
}

fn add(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: PolicyAddArgs,
) -> Result<(), CliError> {
    validate_policy_name(&args.name)?;
    let resolved = require_project(context)?;
    let path = resolved.root.join(LOCKET_TOML);
    let mut document = read_locket_toml(&path)?;
    let commands = commands_table_mut(&mut document)?;
    if commands.contains_key(&args.name) {
        return Err(secret_already_exists_error(format!(
            "command policy already exists: {}",
            args.name
        )));
    }

    let mut policy = toml::map::Map::new();
    policy.insert("argv".to_owned(), string_array(args.command));
    commands.insert(args.name.clone(), toml::Value::Table(policy));
    write_validated_locket_toml(&path, &document)?;
    write_policy_update_audit_if_available(context, "add", &args.name)?;
    write_policy_update(output, &args.name, "add")
}

fn allow(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: PolicySecretsArgs,
) -> Result<(), CliError> {
    let resolved = require_project(context)?;
    let path = resolved.root.join(LOCKET_TOML);
    let mut document = read_locket_toml(&path)?;
    let policy = policy_table_mut(&mut document, &args.name)?;
    let keys = validate_secret_names(args.keys)?;
    append_without_duplicates(policy, "optional_secrets", &keys)?;
    write_validated_locket_toml(&path, &document)?;
    write_policy_update_audit_if_available(context, "allow", &args.name)?;
    write_policy_update(output, &args.name, "allow")
}

fn require(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: PolicySecretsArgs,
) -> Result<(), CliError> {
    let resolved = require_project(context)?;
    let path = resolved.root.join(LOCKET_TOML);
    let mut document = read_locket_toml(&path)?;
    let policy = policy_table_mut(&mut document, &args.name)?;
    let keys = validate_secret_names(args.keys)?;
    append_without_duplicates(policy, "required_secrets", &keys)?;
    remove_values(policy, "optional_secrets", &keys)?;
    write_validated_locket_toml(&path, &document)?;
    write_policy_update_audit_if_available(context, "require", &args.name)?;
    write_policy_update(output, &args.name, "require")
}

fn delete(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: PolicyDeleteArgs,
) -> Result<(), CliError> {
    let PolicyDeleteArgs { name, yes } = args;
    if !yes {
        return Err(confirmation_failed_error("policy delete requires --yes"));
    }
    let resolved = require_project(context)?;
    let path = resolved.root.join(LOCKET_TOML);
    let mut document = read_locket_toml(&path)?;
    let commands = commands_table_mut(&mut document)?;
    if commands.remove(&name).is_none() {
        return Err(policy_not_found_error(format!("command policy not found: {name}")));
    }
    write_validated_locket_toml(&path, &document)?;
    write_policy_update_audit_if_available(context, "delete", &name)?;
    write_policy_update(output, &name, "delete")
}

fn doctor(context: &RuntimeContext, output: &mut impl Write) -> Result<(), CliError> {
    let resolved = require_project(context)?;
    let path = resolved.root.join(LOCKET_TOML);
    let policy_text = fs::read_to_string(&path)?;
    let document = PolicyDocument::from_toml_str(&policy_text)
        .map_err(|error| metadata_invalid_error(error.to_string()))?;

    let has_lk_references = policy_text.contains("lk://");
    writeln!(output, "policy_doctor: {}", if has_lk_references { "incomplete" } else { "ok" })?;
    writeln!(output, "policies: {}", document.commands.len())?;
    writeln!(output, "metadata_only: yes")?;
    writeln!(output, "minimal_env_allowlist: {}", locket_exec::DEFAULT_SAFE_ALLOWLIST.join(" "))?;
    let scan_policy = read_scan_policy(&path)?;
    let entropy_rule = scan_policy.entropy_rule;
    if entropy_rule != EntropyRule::default() {
        writeln!(
            output,
            "warning: non-default scanner thresholds high_entropy min_length={} entropy_threshold={}",
            entropy_rule.min_len, entropy_rule.threshold
        )?;
    }
    let default_scan_policy = ScanPolicy::default();
    if scan_policy.provider_token_severity() != default_scan_policy.provider_token_severity()
        || scan_policy.env_file_severity() != default_scan_policy.env_file_severity()
    {
        writeln!(
            output,
            "warning: non-default scanner severity provider_token={} env_file={}",
            scan_policy.provider_token_severity().as_str(),
            scan_policy.env_file_severity().as_str()
        )?;
    }
    for policy in document.commands.values().filter(|policy| !policy.override_explicit()) {
        writeln!(
            output,
            "warning: policy {} uses implicit override=locket; set override explicitly",
            policy.name
        )?;
    }
    if has_lk_references {
        writeln!(output, "warning: lk:// validation skipped because agent is unavailable")?;
        writeln!(output, "unvalidated_lk_references: present")?;
        return Err(CliError::Typed {
            kind: locket_core::LocketError::AgentUnavailable,
            message: "AgentUnavailable: policy doctor could not validate lk:// references"
                .to_owned(),
        });
    }
    Ok(())
}

fn read_locket_toml(path: &std::path::Path) -> Result<toml::Value, CliError> {
    let content = fs::read_to_string(path)?;
    toml::from_str::<toml::Value>(&content).map_err(CliError::from)
}

fn write_validated_locket_toml(
    path: &std::path::Path,
    document: &toml::Value,
) -> Result<(), CliError> {
    let content = toml::to_string_pretty(document)?;
    PolicyDocument::from_toml_str(&content)
        .map_err(|error| metadata_invalid_error(error.to_string()))?;
    fs::write(path, content)?;
    Ok(())
}

fn commands_table_mut(
    document: &mut toml::Value,
) -> Result<&mut toml::map::Map<String, toml::Value>, CliError> {
    let Some(root) = document.as_table_mut() else {
        return Err(metadata_invalid_error("locket.toml root must be a table"));
    };
    let commands = root
        .entry("commands".to_owned())
        .or_insert_with(|| toml::Value::Table(toml::map::Map::new()));
    commands.as_table_mut().ok_or_else(|| metadata_invalid_error("commands must be a table"))
}

fn policy_table_mut<'a>(
    document: &'a mut toml::Value,
    name: &str,
) -> Result<&'a mut toml::map::Map<String, toml::Value>, CliError> {
    let commands = commands_table_mut(document)?;
    commands
        .get_mut(name)
        .and_then(toml::Value::as_table_mut)
        .ok_or_else(|| policy_not_found_error(format!("command policy not found: {name}")))
}

fn validate_policy_name(name: &str) -> Result<(), CliError> {
    if name.is_empty() {
        return Err(invalid_reference_error("policy name must not be empty"));
    }
    Ok(())
}

fn validate_secret_names(keys: Vec<String>) -> Result<Vec<String>, CliError> {
    keys.into_iter()
        .map(|key| {
            if SecretName::new(key.clone()).is_err() {
                return Err(invalid_secret_name_error(format!("invalid secret name: {key}")));
            }
            Ok(key)
        })
        .collect()
}

fn append_without_duplicates(
    policy: &mut toml::map::Map<String, toml::Value>,
    field: &str,
    keys: &[String],
) -> Result<(), CliError> {
    let array = string_array_mut(policy, field)?;
    for key in keys {
        if !array.iter().any(|value| value.as_str() == Some(key.as_str())) {
            array.push(toml::Value::String(key.clone()));
        }
    }
    Ok(())
}

fn remove_values(
    policy: &mut toml::map::Map<String, toml::Value>,
    field: &str,
    keys: &[String],
) -> Result<(), CliError> {
    let Some(value) = policy.get_mut(field) else {
        return Ok(());
    };
    let Some(array) = value.as_array_mut() else {
        return Err(metadata_invalid_error(format!("{field} must be an array")));
    };
    array.retain(|value| !value.as_str().is_some_and(|name| keys.iter().any(|key| key == name)));
    Ok(())
}

fn string_array_mut<'a>(
    policy: &'a mut toml::map::Map<String, toml::Value>,
    field: &str,
) -> Result<&'a mut Vec<toml::Value>, CliError> {
    let value = policy.entry(field.to_owned()).or_insert_with(|| toml::Value::Array(Vec::new()));
    value.as_array_mut().ok_or_else(|| metadata_invalid_error(format!("{field} must be an array")))
}

fn string_array(values: Vec<String>) -> toml::Value {
    toml::Value::Array(values.into_iter().map(toml::Value::String).collect())
}

fn write_policy_update(
    output: &mut impl Write,
    name: &str,
    operation: &str,
) -> Result<(), CliError> {
    writeln!(output, "policy: {name}")?;
    writeln!(output, "operation: {operation}")?;
    writeln!(output, "metadata_only: yes")?;
    Ok(())
}

fn write_policy_update_audit_if_available(
    context: &RuntimeContext,
    operation: &str,
    policy: &str,
) -> Result<(), CliError> {
    let Ok(resolved) = require_project(context) else {
        return Ok(());
    };
    let mut store = open_store(context)?;
    if store.get_project(resolved.config.project_id.as_str())?.is_none() {
        return Ok(());
    }
    let audit_key =
        load_project_key(context, &store, resolved.config.project_id.as_str(), KeyPurpose::Audit)?;
    let metadata = json!({
        "schema_version": 1,
        "action": "POLICY_UPDATE",
        "status": "SUCCESS",
        "operation": operation,
        "policy": policy,
        "metadata_only": true,
    });
    let audit = AuditWrite {
        project_id: resolved.config.project_id.as_str(),
        profile_id: None,
        action: "POLICY_UPDATE",
        status: "SUCCESS",
        secret_name: None,
        command: Some("policy"),
        metadata_json: &metadata,
        timestamp: now_unix_nanos()?,
    };
    store.append_audit(audit_key.as_ref(), &audit)?;
    Ok(())
}
