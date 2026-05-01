//! Windows named-pipe transport helpers for the local agent.
//!
//! This module owns the Tokio named-pipe construction and request
//! handling points. It reuses the shared agent dispatcher so Windows
//! and Unix transports expose the same unary RPC surface.

use std::ffi::c_void;
use std::io;
use std::path::{Path, PathBuf};
use std::ptr::{NonNull, null_mut};
use std::time::Duration;

use tokio::net::windows::named_pipe::{
    ClientOptions, NamedPipeClient, NamedPipeServer, ServerOptions,
};
use tokio::time::sleep;
use windows_sys::Win32::Foundation::{HLOCAL, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};

/// Windows error code returned when all pipe instances are busy.
const ERROR_PIPE_BUSY: i32 = 231;

/// Configuration for the Windows agent named pipe.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentPipeConfig {
    /// Full pipe name, e.g. `\\.\pipe\locket-agent-S-...`.
    pub pipe_name: PathBuf,
    /// Security descriptor string used for the pipe's protected DACL.
    pub security_descriptor_sddl: Option<String>,
}

impl AgentPipeConfig {
    /// Convenience constructor for callers that already resolved the pipe name.
    #[must_use]
    pub fn new(pipe_name: PathBuf) -> Self {
        Self { pipe_name, security_descriptor_sddl: None }
    }

    /// Constructor for the production current-user-only pipe contract.
    ///
    /// # Errors
    ///
    /// Returns a platform error when the current Windows user SID
    /// cannot be read or converted into the pipe DACL SDDL.
    pub fn current_user(pipe_name: PathBuf) -> Result<Self, locket_platform::PlatformError> {
        let sid = locket_platform::current_user_sid_string()?;
        let security_descriptor_sddl = locket_platform::agent_pipe_dacl_sddl_for_sid(&sid)?;
        Ok(Self { pipe_name, security_descriptor_sddl: Some(security_descriptor_sddl) })
    }

    /// Applies a caller-supplied SDDL string. Tests use this to assert
    /// pass-through without depending on the host's SID.
    #[must_use]
    pub fn with_security_descriptor_sddl(mut self, sddl: impl Into<String>) -> Self {
        self.security_descriptor_sddl = Some(sddl.into());
        self
    }
}

/// Creates a first named-pipe server instance for the agent.
///
/// Creates the Windows transport: byte-mode, local-only,
/// first-instance guarded, and optionally protected by the caller's
/// current-user DACL security descriptor.
///
/// # Errors
///
/// Returns any OS error from Tokio's named-pipe creation.
pub fn bind_named_pipe_listener(config: &AgentPipeConfig) -> io::Result<NamedPipeServer> {
    create_named_pipe_server(config, true)
}

/// Creates an additional server instance for the same named pipe.
///
/// # Errors
///
/// Returns any OS error from Tokio's named-pipe creation.
pub fn bind_named_pipe_instance(config: &AgentPipeConfig) -> io::Result<NamedPipeServer> {
    create_named_pipe_server(config, false)
}

fn create_named_pipe_server(
    config: &AgentPipeConfig,
    first_instance: bool,
) -> io::Result<NamedPipeServer> {
    let options = named_pipe_server_options(first_instance);
    if let Some(sddl) = config.security_descriptor_sddl.as_deref() {
        let mut attributes = SecurityAttributes::from_sddl(sddl)?;
        // SAFETY: `attributes.as_mut_ptr()` points at a live
        // SECURITY_ATTRIBUTES whose security descriptor remains owned
        // by `attributes` for the duration of this synchronous create call.
        unsafe {
            options.create_with_security_attributes_raw(
                config.pipe_name.as_os_str(),
                attributes.as_mut_ptr(),
            )
        }
    } else {
        options.create(config.pipe_name.as_os_str())
    }
}

fn named_pipe_server_options(first_instance: bool) -> ServerOptions {
    let mut options = ServerOptions::new();
    options.first_pipe_instance(first_instance).reject_remote_clients(true);
    options
}

struct SecurityAttributes {
    descriptor: NonNull<c_void>,
    attributes: SECURITY_ATTRIBUTES,
}

impl SecurityAttributes {
    fn from_sddl(sddl: &str) -> io::Result<Self> {
        let wide = sddl.encode_utf16().chain(std::iter::once(0)).collect::<Vec<_>>();
        let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
        // SAFETY: `wide` is NUL-terminated UTF-16, `descriptor`
        // points to writable storage for the allocated descriptor, and
        // Windows owns the allocation until released with `LocalFree`.
        let converted = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                null_mut(),
            )
        };
        if converted == 0 {
            return Err(io::Error::last_os_error());
        }
        let descriptor =
            NonNull::new(descriptor.cast::<c_void>()).ok_or_else(io::Error::last_os_error)?;
        let attributes = SECURITY_ATTRIBUTES {
            nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(u32::MAX),
            lpSecurityDescriptor: descriptor.as_ptr(),
            bInheritHandle: 0,
        };
        Ok(Self { descriptor, attributes })
    }

    fn as_mut_ptr(&mut self) -> *mut c_void {
        (&mut self.attributes as *mut SECURITY_ATTRIBUTES).cast::<c_void>()
    }
}

impl Drop for SecurityAttributes {
    fn drop(&mut self) {
        // SAFETY: `descriptor` was allocated by
        // `ConvertStringSecurityDescriptorToSecurityDescriptorW`.
        unsafe {
            LocalFree(self.descriptor.as_ptr() as HLOCAL);
        }
    }
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

/// Handles one connected named-pipe client with the shared unary
/// request dispatcher.
///
/// `SubscribeStatus` streaming remains Unix-socket-only for now; the
/// dispatcher returns a typed protocol error for that method on this
/// transport.
///
/// # Errors
///
/// Returns I/O errors from pipe reads/writes or frame encoding.
pub async fn handle_named_pipe_connection(
    mut stream: NamedPipeServer,
    state: crate::server::AgentSocketState,
) -> io::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut buffer = Vec::with_capacity(4 * 1024);
    loop {
        let request = match read_one_frame(&mut stream, &mut buffer).await? {
            Some(request) => request,
            None => return Ok(()),
        };
        let response = crate::server::dispatch(&request, &state).await;
        let frame = crate::framing::encode_frame(&response, crate::DEFAULT_MAX_MESSAGE_SIZE)
            .map_err(|error| io::Error::other(error.to_string()))?;
        stream.write_all(&frame).await?;
        stream.flush().await?;
    }
}

async fn read_one_frame(
    stream: &mut NamedPipeServer,
    buffer: &mut Vec<u8>,
) -> io::Result<Option<crate::envelope::RequestEnvelope>> {
    use tokio::io::AsyncReadExt;

    loop {
        if let Ok((envelope, consumed)) =
            crate::framing::decode_request_frame(buffer, crate::DEFAULT_MAX_MESSAGE_SIZE)
        {
            buffer.drain(..consumed);
            return Ok(Some(envelope));
        }
        let mut chunk = [0_u8; 1024];
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            return Ok(None);
        }
        buffer.extend_from_slice(&chunk[..read]);
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
    fn pipe_config_preserves_security_descriptor_sddl() {
        let config = AgentPipeConfig::new(PathBuf::from(r"\\.\pipe\locket-agent-test"))
            .with_security_descriptor_sddl("D:P(A;;GA;;;S-1-5-21-1000)");
        assert_eq!(config.security_descriptor_sddl.as_deref(), Some("D:P(A;;GA;;;S-1-5-21-1000)"));
    }

    #[test]
    fn busy_error_code_matches_windows_pipe_busy() {
        assert_eq!(ERROR_PIPE_BUSY, 231);
    }
}
