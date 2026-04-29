//! Implementation of the `locket exec` command and its private helpers.

use std::io::Write;

use locket_crypto::KeyPurpose;
use locket_store::{AuditWrite, ProfileRecord};
use serde_json::json;

use crate::cli_error::{CliError, child_exit_error, exec_prepare_error};
use crate::key_access::{default_profile, load_project_key};
use crate::runtime::RuntimeContext;
use crate::secret_helpers::{decrypt_current_secret, resolve_active_secret};
use crate::{
    ExecArgs, ResolvedProject, RuntimeExecutionRequest, active_profile_secret_names,
    execute_prepared_with_runtime_session, now_unix_nanos, open_store, require_project,
    unique_secret_names,
};

pub fn exec_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &ExecArgs,
) -> Result<(), CliError> {
    if !args.all && args.secrets.is_empty() {
        return Err(CliError::Config("exec requires --all or at least one --secret".to_owned()));
    }

    let resolved_project = require_project(context)?;
    let store = open_store(context)?;
    let profile = default_profile(&store, &resolved_project.config)?;

    let secret_names = if args.all {
        let mut names = active_profile_secret_names(
            &store,
            resolved_project.config.project_id.as_str(),
            &profile.id,
        )?
        .into_iter()
        .collect::<Vec<_>>();
        names.sort();
        names
    } else {
        args.secrets.clone()
    };

    if args.all && !args.force {
        confirm_exec_all_scope(context, output, &profile, &args.command, &secret_names)?;
    }

    let mut resolved_secrets = Vec::with_capacity(args.secrets.len());
    let mut locket_env = locket_exec::EnvMap::new();
    let mut injected_names = Vec::with_capacity(secret_names.len());
    for key in &secret_names {
        let resolved = resolve_active_secret(context, key)?;
        let value = decrypt_current_secret(context, &resolved)?;
        injected_names.push(resolved.secret.name.clone());
        locket_env.insert(resolved.secret.name.clone(), value.as_str().to_owned());
        resolved_secrets.push(resolved);
    }
    injected_names.sort();
    injected_names.dedup();
    let unique_names = unique_secret_names(injected_names.iter().map(String::as_str));
    let first_secret = resolved_secrets.first();

    let argv_program = args.command.first().cloned().unwrap_or_default();
    let arg_count = args.command.len();
    let request = locket_exec::ExecutionRequest {
        argv: args.command.clone(),
        parent_env: std::env::vars().collect(),
        inherit_env: vec!["PATH".to_owned()],
        external_env: locket_exec::EnvMap::new(),
        locket_env,
        env_mode: locket_exec::EnvMode::Strict,
        override_mode: locket_exec::EnvOverrideMode::Locket,
    };
    let prepared = locket_exec::prepare_execution(&request).map_err(exec_prepare_error)?;
    let _ = first_secret;
    let status = if unique_names.is_empty() {
        prepared.command().status()?
    } else {
        execute_prepared_with_runtime_session(
            context,
            &RuntimeExecutionRequest {
                store: &store,
                resolved: &resolved_project,
                profile: &profile,
                policy_name: None,
                secret_names: &unique_names,
                prepared: &prepared,
                current_dir: None,
            },
        )?
    };
    let exit_code = status.code();

    write_exec_audit_if_available(
        context,
        &resolved_project,
        &profile,
        &argv_program,
        arg_count,
        &injected_names,
        args.all,
        exit_code,
        if status.success() { "SUCCESS" } else { "FAILED" },
    )?;

    if status.success() {
        return Ok(());
    }
    writeln!(output, "child exited with status {status}")?;
    Err(child_exit_error(status))
}

fn confirm_exec_all_scope(
    context: &RuntimeContext,
    output: &mut impl Write,
    profile: &ProfileRecord,
    command: &[String],
    secret_names: &[String],
) -> Result<(), CliError> {
    let argv_program = command.first().map_or("", String::as_str);
    writeln!(output, "exec_profile: {}", profile.name)?;
    writeln!(output, "exec_argv_program: {argv_program}")?;
    writeln!(output, "exec_arg_count: {}", command.len())?;
    writeln!(output, "exec_secret_count: {}", secret_names.len())?;
    writeln!(output, "exec_secret_names: {}", join_or_none(secret_names))?;
    writeln!(output, "metadata_only: yes")?;
    let expected = format!("exec --all {}", profile.name);
    writeln!(output, "type '{expected}' to confirm injection")?;
    let confirmation = context.confirmation_reader.read_confirmation("exec --all")?;
    if confirmation.trim_end_matches(['\r', '\n']) != expected {
        return Err(CliError::Config("confirmation did not match exec --all scope".to_owned()));
    }
    Ok(())
}

fn join_or_none(names: &[String]) -> String {
    if names.is_empty() { "none".to_owned() } else { names.join(",") }
}

#[allow(clippy::too_many_arguments)]
fn write_exec_audit_if_available(
    context: &RuntimeContext,
    resolved: &ResolvedProject,
    profile: &ProfileRecord,
    argv_program: &str,
    arg_count: usize,
    injected_names: &[String],
    all_mode: bool,
    exit_code: Option<i32>,
    status: &str,
) -> Result<(), CliError> {
    let mut store = open_store(context)?;
    if store.get_project(resolved.config.project_id.as_str())?.is_none() {
        return Ok(());
    }
    let Ok(audit_key) =
        load_project_key(context, &store, resolved.config.project_id.as_str(), KeyPurpose::Audit)
    else {
        return Ok(());
    };
    let metadata = json!({
        "schema_version": 1,
        "action": "EXEC",
        "status": status,
        "profile_id": profile.id,
        "argv_program": argv_program,
        "arg_count": arg_count,
        "secret_names": injected_names,
        "all_mode": all_mode,
        "exit_code": exit_code,
    });
    let audit = AuditWrite {
        project_id: resolved.config.project_id.as_str(),
        profile_id: Some(&profile.id),
        action: "EXEC",
        status,
        secret_name: None,
        command: Some("exec"),
        metadata_json: &metadata,
        timestamp: now_unix_nanos()?,
    };
    store.append_audit(audit_key.as_ref(), &audit)?;
    Ok(())
}
