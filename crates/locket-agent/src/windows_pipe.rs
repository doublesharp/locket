//! Windows named-pipe transport helpers for the local agent.
//!
//! This module owns the Tokio named-pipe construction points. The full
//! Windows daemon dispatch path is intentionally layered in the CLI so
//! Unix socket behavior remains untouched.

use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use tokio::net::windows::named_pipe::{
    ClientOptions, NamedPipeClient, NamedPipeServer, ServerOptions,
};
use tokio::time::sleep;

/// Windows error code returned when all pipe instances are busy.
const ERROR_PIPE_BUSY: i32 = 231;

/// Configuration for the Windows agent named pipe.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentPipeConfig {
    /// Full pipe name, e.g. `\\.\pipe\locket-agent-S-...`.
    pub pipe_name: PathBuf,
}

impl AgentPipeConfig {
    /// Convenience constructor for callers that already resolved the pipe name.
    #[must_use]
    pub fn new(pipe_name: PathBuf) -> Self {
        Self { pipe_name }
    }
}

/// Creates a first named-pipe server instance for the agent.
///
/// This is the Windows transport skeleton: byte-mode, local-only, and
/// first-instance guarded. The current milestone intentionally uses the
/// platform default security attributes; wiring the current-user DACL
/// descriptor into creation remains tracked in the app task document.
///
/// # Errors
///
/// Returns any OS error from Tokio's named-pipe creation.
pub fn bind_named_pipe_listener(config: &AgentPipeConfig) -> io::Result<NamedPipeServer> {
    named_pipe_server_options(true).create(config.pipe_name.as_os_str())
}

/// Creates an additional server instance for the same named pipe.
///
/// # Errors
///
/// Returns any OS error from Tokio's named-pipe creation.
pub fn bind_named_pipe_instance(config: &AgentPipeConfig) -> io::Result<NamedPipeServer> {
    named_pipe_server_options(false).create(config.pipe_name.as_os_str())
}

fn named_pipe_server_options(first_instance: bool) -> ServerOptions {
    let mut options = ServerOptions::new();
    options.first_pipe_instance(first_instance).reject_remote_clients(true);
    options
}

/// Opens a client connection to the agent pipe, retrying while all
/// server instances are busy.
///
/// # Errors
///
/// Returns the first non-busy OS error from Tokio's named-pipe client.
pub async fn connect_named_pipe_client(pipe_name: &Path) -> io::Result<NamedPipeClient> {
    loop {
        match ClientOptions::new().open(pipe_name.as_os_str()) {
            Ok(client) => return Ok(client),
            Err(error) if error.raw_os_error() == Some(ERROR_PIPE_BUSY) => {
                sleep(Duration::from_millis(25)).await;
            }
            Err(error) => return Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{AgentPipeConfig, ERROR_PIPE_BUSY};
    use std::path::PathBuf;

    #[test]
    fn pipe_config_preserves_resolved_pipe_name() {
        let pipe_name = PathBuf::from(r"\\.\pipe\locket-agent-S-1-5-21-1000");
        assert_eq!(AgentPipeConfig::new(pipe_name.clone()).pipe_name, pipe_name);
    }

    #[test]
    fn busy_error_code_matches_windows_pipe_busy() {
        assert_eq!(ERROR_PIPE_BUSY, 231);
    }
}
