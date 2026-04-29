//! Implementation of the `locket run` command and runtime session helpers
//! shared with the `exec` command.

use std::collections::BTreeSet;
use std::io::Write;
use std::path::Path;
use std::process::ExitStatus;
use std::str::FromStr;

use locket_core::{CommandSpec, SessionId};
use locket_store::{ProfileRecord, RuntimeSessionRecord, RuntimeSessionSecretNameRetention, Store};

use crate::cli_error::{
    CliError, child_exit_error, exec_prepare_error, unimplemented_in_build_error,
};
use crate::config_validation::{config_get_value, read_user_config};
use crate::key_access::default_profile;
use crate::runtime::RuntimeContext;
use crate::secret_helpers::{decrypt_secret_version, policy_secret_selections};
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
    if policy.confirm {
        return Err(unimplemented_in_build_error("policy confirmation is not wired in this build"));
    }
    if policy.require_user_verification {
        return Err(unimplemented_in_build_error(
            "policy user verification is not wired in this build",
        ));
    }
    if !policy.external_env_sources.is_empty() {
        return Err(unimplemented_in_build_error(
            "policy external environment sources are not wired in this build",
        ));
    }

    let store = open_store(context)?;
    ensure_trusted_project_root(&store, &resolved)?;
    let profile = default_profile(&store, &resolved.config)?;
    let selections = policy_secret_selections(&store, &resolved, &profile, &policy)?;
    let missing_required = selections
        .iter()
        .filter(|selection| selection.required && selection.selected.is_none())
        .map(|selection| selection.name.as_str())
        .collect::<Vec<_>>();
    if !missing_required.is_empty() {
        return Err(CliError::Config(format!(
            "required secret(s) missing: {}",
            missing_required.join(",")
        )));
    }

    let mut locket_env = locket_exec::EnvMap::new();
    for selection in &selections {
        if let Some(secret) = &selection.selected {
            let value = decrypt_secret_version(
                context,
                &store,
                resolved.config.project_id.as_str(),
                &profile.id,
                secret,
                secret.current_version,
            )?;
            locket_env.insert(secret.name.clone(), value.as_str().to_owned());
        }
    }

    let command_argv = match &policy.command {
        CommandSpec::Argv(arguments) => arguments.clone(),
        CommandSpec::Shell(_) => unreachable!("shell policies are rejected before decryption"),
    };
    let request = locket_exec::ExecutionRequest {
        argv: command_argv,
        parent_env: std::env::vars().collect(),
        inherit_env: policy.inherit_env.clone(),
        external_env: locket_exec::EnvMap::new(),
        locket_env,
        env_mode: policy.env_mode,
        override_mode: policy.override_behavior,
    };
    let prepared = locket_exec::prepare_execution(&request).map_err(exec_prepare_error)?;
    let secret_names =
        unique_secret_names(selections.iter().filter_map(|selection| {
            selection.selected.as_ref().map(|secret| secret.name.as_str())
        }));
    let status = execute_prepared_with_runtime_session(
        context,
        &RuntimeExecutionRequest {
            store: &store,
            resolved: &resolved,
            profile: &profile,
            policy_name: Some(&policy.name),
            secret_names: &secret_names,
            prepared: &prepared,
            current_dir: Some(&context.cwd),
        },
    )?;
    let audit_status = if status.success() { "SUCCESS" } else { "FAILED" };
    write_runtime_policy_audit_if_available(
        context,
        &resolved,
        &profile,
        &policy,
        audit_status,
        &selections,
    )?;
    if status.success() {
        return Ok(());
    }

    writeln!(output, "child exited with status {status}")?;
    Err(child_exit_error(status))
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
            .map_err(|_| CliError::Config("runtime session id generation failed".to_owned()))?
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
        return Err(CliError::Config(
            "runtime.session_secret_name_retention must be a duration or off".to_owned(),
        ));
    };
    RuntimeSessionSecretNameRetention::from_str(value).map_err(|_| {
        CliError::Config(
            "runtime.session_secret_name_retention must be a duration or off".to_owned(),
        )
    })
}

pub fn unique_secret_names<'a>(names: impl Iterator<Item = &'a str>) -> Vec<String> {
    names.map(ToOwned::to_owned).collect::<BTreeSet<_>>().into_iter().collect()
}
