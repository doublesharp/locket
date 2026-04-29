//! Process execution and environment injection for Locket.

use std::process::Command;

pub use locket_core::{EnvMap, EnvMergeError, EnvMode, EnvOverrideMode, merge_environment};
use thiserror::Error;

/// Parent environment names considered safe in [`EnvMode::Minimal`].
pub const DEFAULT_SAFE_ALLOWLIST: &[&str] =
    &["PATH", "HOME", "USER", "LOGNAME", "SHELL", "TMPDIR", "TEMP", "TMP"];

/// Execution request before a child process is built.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ExecutionRequest {
    /// Command argv. The first item is the program name.
    pub argv: Vec<String>,
    /// Parent process environment snapshot.
    pub parent_env: EnvMap,
    /// Explicit inherited parent environment names.
    pub inherit_env: Vec<String>,
    /// External environment sources already resolved by the caller.
    pub external_env: EnvMap,
    /// Authorized Locket secret values for this process only.
    pub locket_env: EnvMap,
    /// Base environment mode.
    pub env_mode: EnvMode,
    /// Conflict behavior for Locket values.
    pub override_mode: EnvOverrideMode,
}

impl ExecutionRequest {
    /// Creates a request with strict isolation and no environment layers.
    #[must_use]
    pub const fn strict(argv: Vec<String>) -> Self {
        Self {
            argv,
            parent_env: EnvMap::new(),
            inherit_env: Vec::new(),
            external_env: EnvMap::new(),
            locket_env: EnvMap::new(),
            env_mode: EnvMode::Strict,
            override_mode: EnvOverrideMode::Locket,
        }
    }
}

/// Child process details after environment policy is applied.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PreparedExecution {
    /// Program to execute.
    pub program: String,
    /// Arguments passed after the program.
    pub args: Vec<String>,
    /// Complete child environment. It is intended to be applied after
    /// `Command::env_clear`.
    pub env: EnvMap,
}

impl PreparedExecution {
    /// Builds a [`Command`] with `env_clear` already applied.
    #[must_use]
    pub fn command(&self) -> Command {
        let mut command = Command::new(&self.program);
        command.args(&self.args).env_clear().envs(&self.env);
        command
    }
}

/// Error returned while preparing process execution.
#[derive(Debug, Clone, Eq, Error, PartialEq)]
pub enum ExecError {
    /// No program was supplied.
    #[error("empty command")]
    EmptyCommand,
    /// Environment construction failed before process spawn.
    #[error(transparent)]
    Environment(#[from] EnvMergeError),
}

/// Applies Locket environment policy and returns a spawn-ready plan.
///
/// # Errors
///
/// Returns [`ExecError::EmptyCommand`] when `request.argv` has no program.
/// Returns [`ExecError::Environment`] when environment merge policy rejects a
/// conflict before spawn.
pub fn prepare_execution(request: &ExecutionRequest) -> Result<PreparedExecution, ExecError> {
    let Some((program, args)) = request.argv.split_first() else {
        return Err(ExecError::EmptyCommand);
    };
    let inherit_env = request.inherit_env.iter().map(String::as_str).collect::<Vec<_>>();
    let env = merge_environment(
        &request.parent_env,
        DEFAULT_SAFE_ALLOWLIST,
        &inherit_env,
        &request.external_env,
        &request.locket_env,
        request.env_mode,
        request.override_mode,
    )?;

    Ok(PreparedExecution { program: program.clone(), args: args.to_vec(), env })
}

#[cfg(test)]
mod tests {
    use super::{ExecError, ExecutionRequest, prepare_execution};
    use crate::{EnvMap, EnvMode, EnvOverrideMode};

    fn env(values: &[(&str, &str)]) -> EnvMap {
        values.iter().map(|(name, value)| ((*name).to_owned(), (*value).to_owned())).collect()
    }

    #[test]
    fn prepares_strict_child_environment_without_parent_leakage() -> Result<(), ExecError> {
        let mut request = ExecutionRequest::strict(vec!["node".to_owned(), "server.js".to_owned()]);
        request.parent_env = env(&[("PATH", "/bin"), ("SECRET", "parent")]);
        request.locket_env = env(&[("DATABASE_URL", "postgres://local")]);

        let prepared = prepare_execution(&request)?;

        assert_eq!(prepared.program, "node");
        assert_eq!(prepared.args, ["server.js"]);
        assert_eq!(prepared.env.len(), 1);
        assert_eq!(prepared.env.get("DATABASE_URL").map(String::as_str), Some("postgres://local"));
        assert!(!prepared.env.contains_key("SECRET"));
        assert!(!prepared.env.contains_key("PATH"));
        Ok(())
    }

    #[test]
    fn minimal_mode_inherits_safe_allowlist() -> Result<(), ExecError> {
        let mut request = ExecutionRequest::strict(vec!["tool".to_owned()]);
        request.parent_env = env(&[("PATH", "/bin"), ("SECRET", "parent")]);
        request.env_mode = EnvMode::Minimal;

        let prepared = prepare_execution(&request)?;

        assert_eq!(prepared.env.get("PATH").map(String::as_str), Some("/bin"));
        assert!(!prepared.env.contains_key("SECRET"));
        Ok(())
    }

    #[test]
    fn explicit_inherit_augments_strict_mode() -> Result<(), ExecError> {
        let mut request = ExecutionRequest::strict(vec!["tool".to_owned()]);
        request.parent_env = env(&[("NODE_ENV", "development"), ("SECRET", "parent")]);
        request.inherit_env = vec!["NODE_ENV".to_owned()];

        let prepared = prepare_execution(&request)?;

        assert_eq!(prepared.env.get("NODE_ENV").map(String::as_str), Some("development"));
        assert!(!prepared.env.contains_key("SECRET"));
        Ok(())
    }

    #[test]
    fn override_error_rejects_conflict_before_spawn() {
        let mut request = ExecutionRequest::strict(vec!["tool".to_owned()]);
        request.external_env = env(&[("DATABASE_URL", "external")]);
        request.locket_env = env(&[("DATABASE_URL", "locket")]);
        request.override_mode = EnvOverrideMode::Error;

        let result = prepare_execution(&request);

        assert!(matches!(result, Err(ExecError::Environment(_))));
    }

    #[test]
    fn rejects_empty_command() {
        let request = ExecutionRequest::strict(Vec::new());

        assert_eq!(prepare_execution(&request), Err(ExecError::EmptyCommand));
    }
}
