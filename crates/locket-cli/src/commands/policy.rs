use clap::{Args, Subcommand};
use locket_core::{CommandPolicy, CommandSpec, ExternalEnvSource, PolicyDocument, SecretName};
use locket_crypto::KeyPurpose;
use locket_scan::EntropyRule;
use locket_store::{AuditContext, AuditWrite};
use serde_json::json;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;

use crate::commands::config::spec::{
    config_get_value, read_user_config, validate_config_key, validate_stored_config_value,
};
use crate::commands::scan::scanner::{ScanPolicy, read_scan_policy};
use crate::{
    CliError, LOCKET_TOML, RuntimeContext, confirmation_failed_error, invalid_policy_error,
    invalid_reference_error, invalid_secret_name_error, load_project_key, metadata_invalid_error,
    now_unix_nanos, open_store, policy_not_found_error, require_project,
    secret_already_exists_error, set_user_only_file_options, set_user_only_file_permissions,
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
    /// Edit a command policy in the configured editor.
    Edit(PolicyEditArgs),
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
}

#[derive(Debug, Args)]
pub struct PolicyEditArgs {
    /// Command policy name.
    name: String,
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
        PolicyCommand::Edit(args) => edit(context, output, args),
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
    let policy_document = write_validated_locket_toml(&path, &document)?;
    write_policy_index_update_if_available(
        context,
        resolved.config.project_id.as_str(),
        &document,
        &policy_document,
        &args.name,
        "add",
    )?;
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
    let policy_document = write_validated_locket_toml(&path, &document)?;
    write_policy_index_update_if_available(
        context,
        resolved.config.project_id.as_str(),
        &document,
        &policy_document,
        &args.name,
        "allow",
    )?;
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
    let policy_document = write_validated_locket_toml(&path, &document)?;
    write_policy_index_update_if_available(
        context,
        resolved.config.project_id.as_str(),
        &document,
        &policy_document,
        &args.name,
        "require",
    )?;
    write_policy_update(output, &args.name, "require")
}

fn delete(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: PolicyDeleteArgs,
) -> Result<(), CliError> {
    let PolicyDeleteArgs { name } = args;
    let resolved = require_project(context)?;
    let path = resolved.root.join(LOCKET_TOML);
    let mut document = read_locket_toml(&path)?;
    let commands = commands_table_mut(&mut document)?;
    if !commands.contains_key(&name) {
        return Err(policy_not_found_error(format!("command policy not found: {name}")));
    }
    write_policy_delete_confirmation(output, &name)?;
    let confirmation = context.confirmation_reader.read_confirmation("policy delete")?;
    if confirmation.trim_end_matches(['\r', '\n']) != name {
        return Err(confirmation_failed_error("confirmation did not match policy name"));
    }
    commands.remove(&name);
    let _policy_document = write_validated_locket_toml(&path, &document)?;
    write_policy_index_delete_if_available(context, resolved.config.project_id.as_str(), &name)?;
    write_policy_update(output, &name, "delete")
}

fn edit(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: PolicyEditArgs,
) -> Result<(), CliError> {
    let resolved = require_project(context)?;
    let path = resolved.root.join(LOCKET_TOML);
    let document = read_locket_toml(&path)?;
    ensure_policy_exists(&document, &args.name)?;
    let editor = configured_editor(context)?;
    let edit_path = write_edit_copy(&path, &document)?;
    let edit_result = run_policy_editor(&editor, &edit_path)
        .and_then(|()| apply_edited_policy(&path, &edit_path, &args.name));
    let cleanup_result = fs::remove_file(&edit_path);
    if let Err(error) = cleanup_result
        && error.kind() != io::ErrorKind::NotFound
        && edit_result.is_ok()
    {
        return Err(error.into());
    }
    edit_result?;
    let updated_document = read_locket_toml(&path)?;
    let policy_text = toml::to_string_pretty(&updated_document)?;
    let policy_document = PolicyDocument::from_toml_str(&policy_text)
        .map_err(|error| metadata_invalid_error(error.to_string()))?;
    write_policy_index_update_if_available(
        context,
        resolved.config.project_id.as_str(),
        &updated_document,
        &policy_document,
        &args.name,
        "edit",
    )?;
    write_policy_update(output, &args.name, "edit")
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

fn read_locket_toml(path: &Path) -> Result<toml::Value, CliError> {
    let content = fs::read_to_string(path)?;
    toml::from_str::<toml::Value>(&content).map_err(CliError::from)
}

fn write_validated_locket_toml(path: &Path, document: &toml::Value) -> Result<PolicyDocument, CliError> {
    let content = toml::to_string_pretty(document)?;
    let policy_document = PolicyDocument::from_toml_str(&content)
        .map_err(|error| metadata_invalid_error(error.to_string()))?;
    fs::write(path, content)?;
    Ok(policy_document)
}

fn ensure_policy_exists(document: &toml::Value, name: &str) -> Result<(), CliError> {
    let exists = document
        .get("commands")
        .and_then(toml::Value::as_table)
        .and_then(|commands| commands.get(name))
        .and_then(toml::Value::as_table)
        .is_some();
    if exists {
        Ok(())
    } else {
        Err(policy_not_found_error(format!("command policy not found: {name}")))
    }
}

fn configured_editor(context: &RuntimeContext) -> Result<String, CliError> {
    let config = read_user_config(context)?;
    let spec = validate_config_key("editor.default")?;
    if let Some(value) = config_get_value(&config, "editor.default") {
        validate_stored_config_value(spec, value)?;
        let Some(editor) = value.as_str() else {
            return Err(metadata_invalid_error("invalid stored config value for editor.default"));
        };
        return Ok(editor.to_owned());
    }
    std::env::var("VISUAL")
        .or_else(|_| std::env::var("EDITOR"))
        .map_err(|_| {
            metadata_invalid_error("policy edit requires editor.default, VISUAL, or EDITOR")
        })
        .and_then(|editor| validate_editor_command(&editor).map(|()| editor))
}

fn validate_editor_command(editor: &str) -> Result<(), CliError> {
    if editor.is_empty()
        || editor.chars().any(char::is_control)
        || editor.chars().any(char::is_whitespace)
    {
        return Err(metadata_invalid_error(
            "policy editor must be a command name or absolute path without arguments",
        ));
    }
    if editor.starts_with('~') || editor.contains('$') || editor.contains('`') {
        return Err(metadata_invalid_error("policy editor must not use shell expansion"));
    }
    Ok(())
}

fn write_edit_copy(path: &Path, document: &toml::Value) -> Result<PathBuf, CliError> {
    let edit_path = path.with_file_name(format!(
        ".locket-policy-edit-{}-{}.toml",
        std::process::id(),
        now_unix_nanos()?
    ));
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    set_user_only_file_options(&mut options);
    let mut file = options.open(&edit_path)?;
    file.write_all(toml::to_string_pretty(document)?.as_bytes())?;
    set_user_only_file_permissions(&edit_path)?;
    Ok(edit_path)
}

fn run_policy_editor(editor: &str, edit_path: &Path) -> Result<(), CliError> {
    let status = ProcessCommand::new(editor).arg(edit_path).status().map_err(CliError::from)?;
    if status.success() {
        Ok(())
    } else {
        Err(invalid_policy_error("policy editor exited unsuccessfully"))
    }
}

fn apply_edited_policy(path: &Path, edit_path: &Path, name: &str) -> Result<(), CliError> {
    let edited_text = fs::read_to_string(edit_path)?;
    let edited = toml::from_str::<toml::Value>(&edited_text)
        .map_err(|error| invalid_policy_error(format!("invalid edited policy TOML: {error}")))?;
    ensure_policy_exists(&edited, name)?;
    let content = toml::to_string_pretty(&edited)?;
    PolicyDocument::from_toml_str(&content)
        .map_err(|error| invalid_policy_error(format!("invalid edited policy: {error}")))?;
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

fn write_policy_delete_confirmation(output: &mut impl Write, name: &str) -> Result<(), CliError> {
    writeln!(output, "policy_delete: {name}")?;
    writeln!(output, "metadata_only: yes")?;
    writeln!(output, "affected_shell_hooks: live grants revoked when available")?;
    writeln!(output, "affected_tray_actions: policy shortcuts removed")?;
    writeln!(output, "affected_automation_clients: policy grants revoked when available")?;
    writeln!(output, "affected_vscode_tasks: policy tasks removed")?;
    writeln!(output, "type '{name}' to confirm policy delete")?;
    Ok(())
}

fn write_policy_index_update_if_available(
    context: &RuntimeContext,
    project_id: &str,
    raw_document: &toml::Value,
    policy_document: &PolicyDocument,
    policy_name: &str,
    operation: &str,
) -> Result<(), CliError> {
    let mut store = open_store(context)?;
    if store.get_project(project_id)?.is_none() {
        return Ok(());
    }
    let raw_policy_json = policy_json(raw_document, policy_name)?;
    let policy = policy_document.commands.get(policy_name).ok_or_else(|| {
        metadata_invalid_error(format!("command policy missing after validation: {policy_name}"))
    })?;
    let normalized_json = normalized_policy_json(policy);
    let audit_key = load_project_key(context, &store, project_id, KeyPurpose::Audit)?;
    let timestamp = now_unix_nanos()?;
    let metadata = policy_update_metadata(operation, policy_name);
    let audit = AuditWrite {
        project_id,
        profile_id: None,
        action: "POLICY_UPDATE",
        status: "SUCCESS",
        secret_name: None,
        command: Some("policy"),
        metadata_json: &metadata,
        timestamp,
    };
    store.upsert_command_policy_index(
        project_id,
        policy_name,
        &raw_policy_json,
        &normalized_json,
        timestamp,
        Some(AuditContext { key: audit_key.as_ref(), write: &audit }),
    )?;
    Ok(())
}

fn write_policy_index_delete_if_available(
    context: &RuntimeContext,
    project_id: &str,
    policy_name: &str,
) -> Result<(), CliError> {
    let mut store = open_store(context)?;
    if store.get_project(project_id)?.is_none() {
        return Ok(());
    }
    let audit_key = load_project_key(context, &store, project_id, KeyPurpose::Audit)?;
    let timestamp = now_unix_nanos()?;
    let metadata = policy_update_metadata("delete", policy_name);
    let audit = AuditWrite {
        project_id,
        profile_id: None,
        action: "POLICY_UPDATE",
        status: "SUCCESS",
        secret_name: None,
        command: Some("policy"),
        metadata_json: &metadata,
        timestamp,
    };
    store.delete_command_policy_index(
        project_id,
        policy_name,
        Some(AuditContext { key: audit_key.as_ref(), write: &audit }),
    )?;
    Ok(())
}

fn policy_update_metadata(operation: &str, policy: &str) -> serde_json::Value {
    json!({
        "schema_version": 1,
        "action": "POLICY_UPDATE",
        "status": "SUCCESS",
        "command": "policy",
        "operation": operation,
        "policy": policy,
        "metadata_only": true,
    })
}

fn policy_json(document: &toml::Value, policy_name: &str) -> Result<serde_json::Value, CliError> {
    let policy = document
        .get("commands")
        .and_then(toml::Value::as_table)
        .and_then(|commands| commands.get(policy_name))
        .ok_or_else(|| metadata_invalid_error(format!("command policy missing: {policy_name}")))?;
    serde_json::to_value(policy).map_err(CliError::from)
}

fn normalized_policy_json(policy: &CommandPolicy) -> serde_json::Value {
    json!({
        "schema_version": 1,
        "name": policy.name,
        "command": command_json(&policy.command),
        "allowed_secrets": secret_name_strings(&policy.allowed_secrets),
        "required_secrets": secret_name_strings(&policy.required_secrets),
        "optional_secrets": secret_name_strings(&policy.optional_secrets),
        "inherit_env": policy.inherit_env,
        "env_mode": policy.env_mode.as_str(),
        "override": policy.override_behavior.as_str(),
        "override_explicit": policy.override_explicit(),
        "external_env_sources": policy
            .external_env_sources
            .iter()
            .map(external_env_source_json)
            .collect::<Vec<_>>(),
        "allow_remote_docker": policy.allow_remote_docker,
        "confirm": policy.confirm,
        "require_user_verification": policy.require_user_verification,
        "ttl_seconds": policy.ttl.as_secs(),
    })
}

fn command_json(command: &CommandSpec) -> serde_json::Value {
    match command {
        CommandSpec::Argv(argv) => json!({ "type": "argv", "argv": argv }),
        CommandSpec::Shell(shell) => json!({ "type": "shell", "shell": shell }),
    }
}

fn secret_name_strings(names: &[SecretName]) -> Vec<&str> {
    names.iter().map(SecretName::as_str).collect()
}

fn external_env_source_json(source: &ExternalEnvSource) -> serde_json::Value {
    match source {
        ExternalEnvSource::Parent => json!({ "type": "parent" }),
        ExternalEnvSource::File(path) => {
            json!({ "type": "file", "path": path.display().to_string() })
        }
        ExternalEnvSource::Compose => json!({ "type": "compose" }),
        ExternalEnvSource::Ide => json!({ "type": "ide" }),
    }
}
