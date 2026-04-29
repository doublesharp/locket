//! Implementation of the `locket compose` command.

use std::io::Write;

use super::docker::{
    compose_argv_with_options, prepare_compose_policy_execution,
    write_docker_policy_audit_if_available,
};
use crate::runtime::RuntimeContext;
use crate::runtime::error::{CliError, child_exit_error};
use crate::{ComposeCommand, ComposeRunArgs};

pub fn compose_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    command: ComposeCommand,
) -> Result<(), CliError> {
    match command {
        ComposeCommand::Run(args) => compose_run_command(context, output, &args),
    }
}

pub fn compose_run_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &ComposeRunArgs,
) -> Result<(), CliError> {
    let parent_env = std::env::vars()
        .map(|(name, value)| (name, locket_exec::env_value(value)))
        .collect::<locket_exec::EnvMap>();
    let compose_args = compose_argv_with_options(
        args.command.clone(),
        args.project_directory.as_deref(),
        &args.profile,
    )?;
    let mut prepared =
        prepare_compose_policy_execution(context, &args.policy, &compose_args, parent_env)?;
    let status = prepared.execution.command().current_dir(&context.cwd).status()?;
    let audit_status = if status.success() { "SUCCESS" } else { "FAILED" };
    write_docker_policy_audit_if_available(context, &mut prepared, audit_status)?;
    if status.success() {
        return Ok(());
    }

    writeln!(output, "child exited with status {status}")?;
    Err(child_exit_error(status))
}
