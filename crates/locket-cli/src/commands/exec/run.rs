//! Implementation of the `locket run` command and runtime session helpers
//! shared with the `exec` command.

use std::collections::BTreeSet;
use std::io::Write;
use std::path::Path;
use std::process::ExitStatus;
use std::str::FromStr;

use locket_core::{CommandPolicy, CommandSpec, ExternalEnvSource, SessionId};
use locket_platform::{LocalUserVerificationRequest, PlatformError};
use locket_store::{ProfileRecord, RuntimeSessionRecord, RuntimeSessionSecretNameRetention, Store};

use crate::commands::config::spec::{config_get_value, read_user_config};
use crate::runtime::RuntimeContext;
use crate::runtime::error::{
    CliError, child_exit_error, confirmation_failed_error, corrupt_db_error, exec_prepare_error,
    metadata_invalid_error, secret_not_found_error, unimplemented_in_build_error,
    user_verification_failed_error,
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

    if matches!(policy.command, CommandSpec::Shell(_)) {
        writeln!(output, "policy {}: shell execution is not implemented", policy.name)?;
        return Err(unimplemented_in_build_error(
            "shell policy execution is not wired in this build",
        ));
    }
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
    let external_env = resolve_policy_external_env(policy, &parent_env)?;
    let missing_required = missing_required_secret_names(&selections, &external_env);
    if !missing_required.is_empty() {
        return Err(secret_not_found_error(format!(
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
) -> Result<locket_exec::EnvMap, CliError> {
    let mut external_env = locket_exec::EnvMap::new();
    for source in &policy.external_env_sources {
        match source {
            ExternalEnvSource::Parent => {
                external_env.extend(locket_exec::resolve_parent_external_env(
                    parent_env,
                    policy.allowed_secrets.iter().map(locket_core::SecretName::as_str),
                ));
            }
            ExternalEnvSource::File(_) | ExternalEnvSource::Compose | ExternalEnvSource::Ide => {
                return Err(unimplemented_in_build_error(
                    "external env source is not wired in this build",
                ));
            }
        }
    }
    Ok(external_env)
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
        CommandSpec::Shell(_) => unreachable!("shell policies are rejected before decryption"),
    }
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
