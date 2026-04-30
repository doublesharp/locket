//! Implementation of the `locket run` command and runtime session helpers
//! shared with the `exec` command.

use std::collections::BTreeSet;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command as ProcessCommand, ExitStatus};
use std::str::FromStr;

use locket_core::{CommandPolicy, CommandSpec, ExternalEnvSource, SecretName, SessionId};
use locket_platform::{LocalUserVerificationRequest, PlatformError};
use locket_store::{ProfileRecord, RuntimeSessionRecord, RuntimeSessionSecretNameRetention, Store};
use serde_json::Value;

use crate::commands::agent::ensure_agent_running_for_execution;
use crate::commands::config::spec::{config_get_value, read_user_config};
use crate::commands::secrets::import::{EnvImportEntry, parse_env_import};
use crate::runtime::RuntimeContext;
use crate::runtime::error::{
    CliError, child_exit_error, confirmation_failed_error, corrupt_db_error, exec_prepare_error,
    external_source_unavailable_error, invalid_policy_error, metadata_invalid_error,
    unimplemented_in_build_error, user_verification_failed_error,
};
use crate::runtime::key_access::default_profile;
use crate::support::secret_helpers::{
    PolicySecretSelection, decrypt_secret_version, policy_secret_selections,
};
use crate::{
    ResolvedProject, RunArgs, ensure_trusted_project_root, load_command_policy, now_unix_nanos,
    open_store, require_project, write_runtime_policy_audit_if_available,
};

/// Inputs needed to run a prepared command under a runtime session record.
pub struct RuntimeExecutionRequest<'a> {
    /// The opened backing store used to track the runtime session.
    pub store: &'a Store,
    /// Project resolved for the active working directory.
    pub resolved: &'a ResolvedProject,
    /// Profile whose secrets are being injected.
    pub profile: &'a ProfileRecord,
    /// Optional policy name when the execution is policy-driven.
    pub policy_name: Option<&'a str>,
    /// Sorted, deduplicated secret names that were injected.
    pub secret_names: &'a [String],
    /// Prepared execution plan ready to spawn.
    pub prepared: &'a locket_exec::PreparedExecution,
    /// Optional working directory to apply when spawning.
    pub current_dir: Option<&'a Path>,
}

struct PreparedPolicyExecution {
    selections: Vec<PolicySecretSelection>,
    secret_names: Vec<String>,
    prepared: locket_exec::PreparedExecution,
}

pub fn run_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    run_args: &RunArgs,
) -> Result<(), CliError> {
    let resolved = require_project(context)?;
    let policy = load_command_policy(&resolved, &run_args.policy)?;

    let confirmation_source = if policy.confirm {
        let expected = format!("run {}", policy.name);
        writeln!(output, "type '{expected}' to confirm run")?;
        let confirmation = context.confirmation_reader.read_confirmation("run")?;
        if confirmation.trim_end_matches(['\r', '\n']) != expected {
            return Err(confirmation_failed_error("confirmation did not match run scope"));
        }
        Some("interactive")
    } else {
        None
    };
    let user_verification = if policy.require_user_verification {
        let request =
            LocalUserVerificationRequest::new("run", format!("authorize policy {}", policy.name));
        match context.user_verifier.verify_user(&request) {
            Ok(verified) => Some(verified),
            Err(
                PlatformError::LocalUserVerificationFailed
                | PlatformError::LocalUserVerificationUnavailable,
            ) => {
                return Err(user_verification_failed_error(
                    "policy requires local user verification",
                ));
            }
            Err(error) => return Err(error.into()),
        }
    } else {
        None
    };
    let mut store = open_store(context)?;
    ensure_trusted_project_root(&store, &resolved)?;
    let profile = default_profile(&store, &resolved.config)?;
    ensure_agent_running_for_execution(context)?;
    let prepared_policy =
        prepare_policy_execution(context, output, &store, &resolved, &profile, &policy)?;
    let status = execute_prepared_with_runtime_session(
        context,
        &RuntimeExecutionRequest {
            store: &store,
            resolved: &resolved,
            profile: &profile,
            policy_name: Some(&policy.name),
            secret_names: &prepared_policy.secret_names,
            prepared: &prepared_policy.prepared,
            current_dir: Some(&context.cwd),
        },
    )?;
    let audit_status = if status.success() { "SUCCESS" } else { "FAILED" };
    write_runtime_policy_audit_if_available(
        context,
        &mut store,
        &resolved,
        &profile,
        &policy,
        audit_status,
        &prepared_policy.selections,
        status.code(),
        confirmation_source,
        user_verification.as_ref(),
    )?;
    if status.success() {
        return Ok(());
    }

    writeln!(output, "child exited with status {status}")?;
    Err(child_exit_error(status))
}

fn prepare_policy_execution(
    context: &RuntimeContext,
    output: &mut impl Write,
    store: &Store,
    resolved: &ResolvedProject,
    profile: &ProfileRecord,
    policy: &CommandPolicy,
) -> Result<PreparedPolicyExecution, CliError> {
    let selections = policy_secret_selections(store, resolved, profile, policy)?;
    let parent_env = std::env::vars()
        .map(|(name, value)| (name, locket_exec::env_value(value)))
        .collect::<locket_exec::EnvMap>();
    let external_env = resolve_policy_external_env(policy, &parent_env, &resolved.root)?;
    let missing_required = missing_required_secret_names(&selections, &external_env);
    if !missing_required.is_empty() {
        return Err(invalid_policy_error(format!(
            "required secret(s) missing: {}",
            missing_required.join(",")
        )));
    }

    let locket_env = policy_locket_env(context, store, resolved, profile, &selections)?;
    warn_implicit_locket_override_conflicts(
        output,
        policy,
        &parent_env,
        &external_env,
        &locket_env,
    )?;
    let request = locket_exec::ExecutionRequest {
        argv: policy_argv(policy),
        parent_env,
        inherit_env: policy.inherit_env.clone(),
        external_env: external_env.clone(),
        locket_env,
        env_mode: policy.env_mode,
        override_mode: policy.override_behavior,
    };
    let prepared = locket_exec::prepare_execution(&request).map_err(exec_prepare_error)?;
    let external_env_names = external_env.keys().map(ToOwned::to_owned).collect::<Vec<_>>();
    let secret_names = unique_secret_names(
        selections
            .iter()
            .filter_map(|selection| selection.selected.as_ref().map(|secret| secret.name.as_str()))
            .chain(external_env_names.iter().map(String::as_str)),
    );

    Ok(PreparedPolicyExecution { selections, secret_names, prepared })
}

pub fn resolve_policy_external_env(
    policy: &CommandPolicy,
    parent_env: &locket_exec::EnvMap,
    project_root: &Path,
) -> Result<locket_exec::EnvMap, CliError> {
    resolve_policy_external_env_with_compose_config_command(
        policy,
        parent_env,
        project_root,
        &ComposeConfigCommand::docker(),
    )
}

#[allow(clippy::redundant_pub_crate)]
pub(crate) struct ComposeConfigCommand<'a> {
    program: &'a Path,
    args: &'a [&'a str],
}

#[allow(clippy::elidable_lifetime_names)]
impl<'a> ComposeConfigCommand<'a> {
    #[cfg(test)]
    pub(crate) const fn new(program: &'a Path, args: &'a [&'a str]) -> Self {
        Self { program, args }
    }

    fn docker() -> Self {
        Self { program: Path::new("docker"), args: &["compose", "config", "--format", "json"] }
    }
}

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn resolve_policy_external_env_with_compose_config_command(
    policy: &CommandPolicy,
    parent_env: &locket_exec::EnvMap,
    project_root: &Path,
    compose_config_command: &ComposeConfigCommand<'_>,
) -> Result<locket_exec::EnvMap, CliError> {
    let mut external_env = locket_exec::EnvMap::new();
    for source in &policy.external_env_sources {
        match source {
            ExternalEnvSource::Parent => {
                external_env.extend(locket_exec::resolve_parent_external_env(
                    parent_env,
                    policy.allowed_secrets.iter().map(SecretName::as_str),
                ));
            }
            ExternalEnvSource::File(path) => {
                external_env.extend(resolve_external_env_file(path, project_root, policy)?);
            }
            ExternalEnvSource::Compose => {
                external_env.extend(resolve_external_env_compose(
                    compose_config_command,
                    parent_env,
                    project_root,
                    policy,
                )?);
            }
            ExternalEnvSource::Ide => {
                return Err(unimplemented_in_build_error(
                    "external env source is not wired in this build",
                ));
            }
        }
    }
    Ok(external_env)
}

fn resolve_external_env_compose(
    compose_config_command: &ComposeConfigCommand<'_>,
    parent_env: &locket_exec::EnvMap,
    project_root: &Path,
    policy: &CommandPolicy,
) -> Result<locket_exec::EnvMap, CliError> {
    let output = ProcessCommand::new(compose_config_command.program)
        .args(compose_config_command.args)
        .current_dir(project_root)
        .env_clear()
        .envs(parent_env.iter().map(|(name, value)| (name, value.as_str())))
        .output()
        .map_err(|error| {
            external_source_unavailable_error(format!(
                "ExternalSourceUnavailable: docker compose config could not be started: {error}"
            ))
        })?;
    if !output.status.success() {
        return Err(external_source_unavailable_error(format!(
            "ExternalSourceUnavailable: docker compose config failed with status {}",
            output.status
        )));
    }
    resolve_external_env_compose_json(policy, &output.stdout)
}

fn warn_implicit_locket_override_conflicts(
    output: &mut impl Write,
    policy: &CommandPolicy,
    parent_env: &locket_exec::EnvMap,
    external_env: &locket_exec::EnvMap,
    locket_env: &locket_exec::EnvMap,
) -> Result<(), CliError> {
    if policy.override_explicit() {
        return Ok(());
    }
    let inherit_env = policy.inherit_env.iter().map(String::as_str).collect::<Vec<_>>();
    let base_env = locket_exec::merge_environment(
        parent_env,
        locket_exec::DEFAULT_SAFE_ALLOWLIST,
        &inherit_env,
        external_env,
        &locket_exec::EnvMap::new(),
        policy.env_mode,
        policy.override_behavior,
    )
    .map_err(|error| exec_prepare_error(locket_exec::ExecError::Environment(error)))?;
    let conflicts = locket_env
        .keys()
        .filter(|name| base_env.contains_key(*name))
        .cloned()
        .collect::<BTreeSet<_>>();
    if conflicts.is_empty() {
        return Ok(());
    }
    writeln!(
        output,
        "warning: implicit override=locket will replace existing env name(s): {}",
        conflicts.into_iter().collect::<Vec<_>>().join(", ")
    )?;
    Ok(())
}

fn resolve_external_env_file(
    declared_path: &Path,
    project_root: &Path,
    policy: &CommandPolicy,
) -> Result<locket_exec::EnvMap, CliError> {
    if declared_path.is_absolute() {
        return Err(metadata_invalid_error(format!(
            "external env file {} must be a project-relative path",
            declared_path.display()
        )));
    }

    let canonical_root = project_root.canonicalize().map_err(|error| {
        metadata_invalid_error(format!(
            "could not canonicalize project root {}: {error}",
            project_root.display()
        ))
    })?;
    let candidate = project_root.join(declared_path);
    let canonical_candidate = candidate.canonicalize().map_err(|error| {
        metadata_invalid_error(format!(
            "external env file {} could not be opened: {error}",
            declared_path.display()
        ))
    })?;
    if !canonical_candidate.starts_with(&canonical_root) {
        return Err(metadata_invalid_error(format!(
            "external env file {} resolves outside the project root",
            declared_path.display()
        )));
    }

    let allowed_names =
        policy.allowed_secrets.iter().map(|name| name.as_str().to_owned()).collect::<BTreeSet<_>>();
    let contents = fs::read_to_string(&canonical_candidate)?;
    let mut env = locket_exec::EnvMap::new();
    for entry in parse_env_import(&contents) {
        if let EnvImportEntry::Secret { key, value } = entry
            && allowed_names.contains(&key)
        {
            env.insert(key, locket_exec::env_value(value));
        }
    }
    Ok(env)
}

fn resolve_external_env_compose_json(
    policy: &CommandPolicy,
    stdout: &[u8],
) -> Result<locket_exec::EnvMap, CliError> {
    let config: Value = serde_json::from_slice(stdout).map_err(|error| {
        external_source_unavailable_error(format!(
            "ExternalSourceUnavailable: docker compose config returned invalid JSON: {error}"
        ))
    })?;
    let allowed_names =
        policy.allowed_secrets.iter().map(|name| name.as_str().to_owned()).collect::<BTreeSet<_>>();
    let mut env = locket_exec::EnvMap::new();
    if let Some(environment) = config.get("environment") {
        extend_env_from_compose_environment(&mut env, &allowed_names, environment);
    }
    if let Some(services) = config.get("services").and_then(Value::as_object) {
        for service in services.values() {
            if let Some(environment) = service.get("environment") {
                extend_env_from_compose_environment(&mut env, &allowed_names, environment);
            }
        }
    }
    Ok(env)
}

fn extend_env_from_compose_environment(
    env: &mut locket_exec::EnvMap,
    allowed_names: &BTreeSet<String>,
    environment: &Value,
) {
    match environment {
        Value::Object(entries) => {
            for (name, value) in entries {
                if allowed_names.contains(name)
                    && let Some(value) = compose_env_value_as_string(value)
                {
                    env.insert(name.clone(), locket_exec::env_value(value));
                }
            }
        }
        Value::Array(entries) => {
            for entry in entries {
                let Some(entry) = entry.as_str() else {
                    continue;
                };
                let Some((name, value)) = entry.split_once('=') else {
                    continue;
                };
                if allowed_names.contains(name) {
                    env.insert(name.to_owned(), locket_exec::env_value(value.to_owned()));
                }
            }
        }
        _ => {}
    }
}

fn compose_env_value_as_string(value: &serde_json::Value) -> Option<String> {
    match value {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        Value::Null | Value::Array(_) | Value::Object(_) => None,
    }
}

fn missing_required_secret_names<'a>(
    selections: &'a [PolicySecretSelection],
    external_env: &locket_exec::EnvMap,
) -> Vec<&'a str> {
    selections
        .iter()
        .filter(|selection| {
            selection.required
                && selection.selected.is_none()
                && !external_env.contains_key(&selection.name)
        })
        .map(|selection| selection.name.as_str())
        .collect()
}

fn policy_locket_env(
    context: &RuntimeContext,
    store: &Store,
    resolved: &ResolvedProject,
    profile: &ProfileRecord,
    selections: &[PolicySecretSelection],
) -> Result<locket_exec::EnvMap, CliError> {
    let mut locket_env = locket_exec::EnvMap::new();
    for selection in selections {
        if let Some(secret) = &selection.selected {
            let value = decrypt_secret_version(
                context,
                store,
                resolved.config.project_id.as_str(),
                &profile.id,
                secret,
                secret.current_version,
            )?;
            locket_env.insert(secret.name.clone(), value);
        }
    }
    Ok(locket_env)
}

fn policy_argv(policy: &CommandPolicy) -> Vec<String> {
    match &policy.command {
        CommandSpec::Argv(arguments) => arguments.clone(),
        CommandSpec::Shell(script) => shell_argv(script),
    }
}

#[cfg(unix)]
fn shell_argv(script: &str) -> Vec<String> {
    vec!["/bin/sh".to_owned(), "-c".to_owned(), script.to_owned()]
}

#[cfg(windows)]
fn shell_argv(script: &str) -> Vec<String> {
    vec!["cmd.exe".to_owned(), "/C".to_owned(), script.to_owned()]
}

pub fn execute_prepared_with_runtime_session(
    context: &RuntimeContext,
    request: &RuntimeExecutionRequest<'_>,
) -> Result<ExitStatus, CliError> {
    let started_at = now_unix_nanos()?;
    let mut command = request.prepared.command();
    if let Some(current_dir) = request.current_dir {
        command.current_dir(current_dir);
    }
    let mut child = command.spawn()?;
    let process_id = child.id();
    let session = RuntimeSessionRecord {
        id: SessionId::generate()
            .map_err(|_| corrupt_db_error("runtime session id generation failed"))?
            .into_string(),
        project_id: request.resolved.config.project_id.to_string(),
        profile_id: request.profile.id.clone(),
        policy_name: request.policy_name.map(ToOwned::to_owned),
        process_id,
        process_start_time: started_at,
        started_at,
        ended_at: None,
        exit_status: None,
        secret_names: runtime_session_retention(context)?
            .secret_names_for_storage(request.secret_names),
        spawn_audit_sequence: None,
        completion_audit_sequence: None,
    };

    if let Err(error) = request.store.insert_runtime_session(&session) {
        let _ignored = child.kill();
        let _ignored = child.wait();
        return Err(error.into());
    }

    let status = child.wait()?;
    request.store.mark_runtime_session_completed(
        &session.id,
        now_unix_nanos()?,
        status.code(),
        None,
    )?;
    Ok(status)
}

fn runtime_session_retention(
    context: &RuntimeContext,
) -> Result<RuntimeSessionSecretNameRetention, CliError> {
    let config = read_user_config(context)?;
    let Some(value) = config_get_value(&config, "runtime.session_secret_name_retention") else {
        return Ok(RuntimeSessionSecretNameRetention::default());
    };
    let Some(value) = value.as_str() else {
        return Err(metadata_invalid_error(
            "runtime.session_secret_name_retention must be a duration or off",
        ));
    };
    RuntimeSessionSecretNameRetention::from_str(value).map_err(|_| {
        metadata_invalid_error("runtime.session_secret_name_retention must be a duration or off")
    })
}

pub fn unique_secret_names<'a>(names: impl Iterator<Item = &'a str>) -> Vec<String> {
    names.map(ToOwned::to_owned).collect::<BTreeSet<_>>().into_iter().collect()
}
