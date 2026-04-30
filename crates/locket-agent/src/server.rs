//! Unix-domain-socket server for the Locket agent.
//!
//! This is the foundation slice (`agent-socket-server`) — it binds the
//! per-user agent socket, accepts connections in a loop, decodes the
//! v1 length-prefixed framing, and dispatches a stub handler that
//! answers `Status` and rejects every other RPC with a redacted
//! `ProtocolError`-shaped error response. Later slices add peer
//! validation, the unlock cache, the grant table, and
//! `SubscribeStatus`.
//!
//! Windows named-pipe support stays a separate `[ ]` follow-up.

use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;

use crate::DEFAULT_MAX_MESSAGE_SIZE;
use crate::envelope::{ErrorEnvelope, RequestEnvelope, ResponseEnvelope, SuccessEnvelope};
use crate::framing::{decode_request_frame, encode_frame};
use crate::method::AgentMethod;
use crate::status::{LockState, StatusPayload};

/// Permissions for a freshly bound agent socket — owner-only.
const SOCKET_PERMISSIONS_MODE: u32 = 0o600;
/// Permissions for the parent directory that holds the socket — also
/// owner-only so peers can't list/probe it.
const SOCKET_PARENT_PERMISSIONS_MODE: u32 = 0o700;

/// Outcome of a single accepted connection's handle loop.
#[derive(Debug)]
pub enum ConnectionOutcome {
    /// Client closed the stream cleanly.
    PeerClosed,
    /// We answered one or more requests, then hit an error reading.
    Errored,
    /// The connection was rejected at accept time without a response,
    /// most commonly because the peer's UID did not match the
    /// daemon's.
    Rejected {
        /// Why the connection was dropped.
        reason: SocketServerError,
    },
}

impl PartialEq for ConnectionOutcome {
    fn eq(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (Self::PeerClosed, Self::PeerClosed)
                | (Self::Errored, Self::Errored)
                | (Self::Rejected { .. }, Self::Rejected { .. })
        )
    }
}

impl Eq for ConnectionOutcome {}

/// Errors returned by the agent socket server.
#[derive(Debug, thiserror::Error)]
pub enum SocketServerError {
    /// The configured socket path is already in use by a live owner.
    /// Maps to `LocketError::AgentSocketInUse` (exit 81) at the CLI
    /// boundary.
    #[error("agent socket already bound: {path}")]
    AgentSocketInUse {
        /// Path the second daemon attempted to bind.
        path: PathBuf,
    },
    /// An existing path on the bind chain has wider Unix permissions
    /// than the agent allows. We refuse to silently tighten user
    /// directories because that could mask hostile creation by another
    /// principal; the operator has to fix the perms first.
    #[error("agent socket path {path} has mode {mode:#o}; expected at most {expected:#o}")]
    SocketPathTooWide {
        /// Path whose mode bits are too permissive.
        path: PathBuf,
        /// Mode bits found on disk (lower 9 bits).
        mode: u32,
        /// Maximum allowed mode bits (e.g., `0o700` for parents).
        expected: u32,
    },
    /// The connecting peer's effective UID did not match the daemon's
    /// UID. Maps to [`locket_core::LocketError::AccessDenied`] (exit
    /// 70) at the CLI boundary.
    #[error(
        "agent peer UID {peer_uid} does not match daemon UID {daemon_uid}; refusing cross-user connection"
    )]
    PeerCredentialDenied {
        /// UID reported by the kernel for the connecting peer.
        peer_uid: u32,
        /// UID of the running daemon process.
        daemon_uid: u32,
    },
    /// `bind`/`accept`/permission tweak failed for an OS reason.
    #[error("agent socket I/O error: {0}")]
    Io(#[from] io::Error),
}

/// Configuration for [`bind_socket_listener`].
#[derive(Clone, Debug)]
pub struct AgentSocketConfig {
    /// Filesystem path the listener should bind. Parent directory is
    /// created with `0o700` if missing.
    pub path: PathBuf,
    /// Agent version reported on `Status` responses.
    pub agent_version: String,
}

impl AgentSocketConfig {
    /// Convenience constructor for tests and direct callers.
    #[must_use]
    pub fn new(path: PathBuf, agent_version: impl Into<String>) -> Self {
        Self { path, agent_version: agent_version.into() }
    }
}

/// Binds the agent's Unix domain socket and tightens permissions.
///
/// Returns [`SocketServerError::AgentSocketInUse`] when a previous
/// listener still owns the path. The caller (the spec-described
/// `locket agent start`) reaps stale sockets and retries; the bare
/// helper here treats `EADDRINUSE` as an in-use error so the caller
/// can decide what to do. This slice does not yet implement the
/// stale-socket cleanup; that lives in the upcoming agent CLI work.
///
/// If the parent directory already exists with mode bits wider than
/// `0o700`, this function refuses to bind with
/// [`SocketServerError::SocketPathTooWide`] rather than silently
/// tightening another principal's directory.
///
/// # Errors
///
/// Returns [`SocketServerError`] when binding, parent-directory
/// creation, or permission tightening fails, or when the parent
/// directory's existing permissions are wider than the agent allows.
pub fn bind_socket_listener(config: &AgentSocketConfig) -> Result<UnixListener, SocketServerError> {
    if let Some(parent) = config.path.parent()
        && !parent.as_os_str().is_empty()
    {
        prepare_parent_directory(parent)?;
    }

    let listener = match UnixListener::bind(&config.path) {
        Ok(listener) => listener,
        Err(error) if error.kind() == io::ErrorKind::AddrInUse => {
            return Err(SocketServerError::AgentSocketInUse { path: config.path.clone() });
        }
        Err(error) => return Err(error.into()),
    };
    std::fs::set_permissions(
        &config.path,
        std::fs::Permissions::from_mode(SOCKET_PERMISSIONS_MODE),
    )?;
    let socket_mode = std::fs::metadata(&config.path)?.permissions().mode() & 0o777;
    if socket_mode & !SOCKET_PERMISSIONS_MODE != 0 {
        return Err(SocketServerError::SocketPathTooWide {
            path: config.path.clone(),
            mode: socket_mode,
            expected: SOCKET_PERMISSIONS_MODE,
        });
    }
    Ok(listener)
}

/// Ensures the socket's parent directory exists and is owner-only.
///
/// If the directory does not exist, it is created with `0o700`. If it
/// already exists with mode bits beyond `0o700`, the bind is refused
/// rather than silently tightened — that prevents an agent start from
/// quietly clamping down a user-owned directory whose wider mode might
/// be intentional (or hostile).
fn prepare_parent_directory(parent: &Path) -> Result<(), SocketServerError> {
    match std::fs::metadata(parent) {
        Ok(metadata) => {
            let mode = metadata.permissions().mode() & 0o777;
            if mode & !SOCKET_PARENT_PERMISSIONS_MODE != 0 {
                return Err(SocketServerError::SocketPathTooWide {
                    path: parent.to_path_buf(),
                    mode,
                    expected: SOCKET_PARENT_PERMISSIONS_MODE,
                });
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            std::fs::create_dir_all(parent)?;
            std::fs::set_permissions(
                parent,
                std::fs::Permissions::from_mode(SOCKET_PARENT_PERMISSIONS_MODE),
            )?;
        }
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

/// State shared across every accepted connection.
#[derive(Clone)]
pub struct AgentSocketState {
    /// Source of `Status` responses for this slice's stub handlers.
    pub status_source: Arc<Mutex<StubStatusSource>>,
    /// UID of the running daemon process, used to validate peer
    /// credentials on every accept.
    pub daemon_uid: u32,
}

impl AgentSocketState {
    /// Builds an initial state with a locked status payload. Future
    /// slices replace this with a real key-cache-backed source.
    ///
    /// The daemon UID is captured from the live process when the
    /// state is constructed, which matches how `locket agent start`
    /// will boot the listener.
    #[must_use]
    pub fn locked(agent_version: impl Into<String>) -> Self {
        Self::with_daemon_uid(agent_version, crate::peer_cred::current_process_uid())
    }

    /// Builds an initial state with an explicit daemon UID. Tests use
    /// this to drive the peer-validation rejection path without
    /// running as a different user.
    #[must_use]
    pub fn with_daemon_uid(agent_version: impl Into<String>, daemon_uid: u32) -> Self {
        Self {
            status_source: Arc::new(Mutex::new(StubStatusSource::new(StatusPayload::locked(
                agent_version,
            )))),
            daemon_uid,
        }
    }
}

/// Provides metadata-only `Status` payloads. Stubbed for this slice;
/// later slices replace it with the unlock-cache-driven view.
pub struct StubStatusSource {
    current: StatusPayload,
}

impl StubStatusSource {
    /// Creates a status source that reports the supplied payload.
    #[must_use]
    pub const fn new(initial: StatusPayload) -> Self {
        Self { current: initial }
    }

    /// Returns the current status snapshot.
    #[must_use]
    pub fn snapshot(&self) -> StatusPayload {
        self.current.clone()
    }

    /// Replaces the current snapshot.
    pub const fn set_lock_state(&mut self, lock_state: LockState) {
        self.current.lock_state = lock_state;
    }
}

/// Handles a single accepted connection.
///
/// Validates peer credentials, reads framed requests, dispatches the
/// stub handler, and writes framed responses until the peer closes or
/// a read error occurs.
///
/// A peer whose effective UID does not match the daemon's UID is
/// dropped immediately without any response, so the existence and
/// state of the daemon are not exposed to other principals on the
/// host. Same-user connections are allowed through; the rejection is
/// surfaced through [`ConnectionOutcome::Rejected`] for tests and
/// future audit wiring.
pub async fn handle_connection(
    mut stream: UnixStream,
    state: AgentSocketState,
) -> ConnectionOutcome {
    if let Err(error) = crate::peer_cred::validate_peer_stream(&stream, state.daemon_uid) {
        return ConnectionOutcome::Rejected { reason: error };
    }
    let mut buffer = Vec::with_capacity(4 * 1024);
    loop {
        match read_one_frame(&mut stream, &mut buffer).await {
            Ok(None) => return ConnectionOutcome::PeerClosed,
            Ok(Some(envelope)) => {
                let response = dispatch(&envelope, &state).await;
                if !write_response(&mut stream, &response).await {
                    return ConnectionOutcome::Errored;
                }
            }
            Err(_) => return ConnectionOutcome::Errored,
        }
    }
}

async fn read_one_frame(
    stream: &mut UnixStream,
    buffer: &mut Vec<u8>,
) -> Result<Option<RequestEnvelope>, io::Error> {
    loop {
        if let Ok((envelope, consumed)) = decode_request_frame(buffer, DEFAULT_MAX_MESSAGE_SIZE) {
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

async fn dispatch(envelope: &RequestEnvelope, state: &AgentSocketState) -> ResponseEnvelope {
    match envelope.method() {
        Ok(AgentMethod::Status) => {
            let snapshot = state.status_source.lock().await.snapshot();
            let payload = serde_json::to_value(snapshot).unwrap_or(serde_json::Value::Null);
            ResponseEnvelope::Success(SuccessEnvelope::new(envelope.id.clone(), payload))
        }
        Ok(method) => ResponseEnvelope::Error(ErrorEnvelope::new(
            envelope.id.clone(),
            "ProtocolError",
            format!("method {} is not implemented in this build", method.as_str()),
            false,
        )),
        Err(_) => ResponseEnvelope::Error(ErrorEnvelope::new(
            envelope.id.clone(),
            "ProtocolError",
            "unknown agent method",
            false,
        )),
    }
}

async fn write_response(stream: &mut UnixStream, response: &ResponseEnvelope) -> bool {
    let Ok(frame) = encode_frame(response, DEFAULT_MAX_MESSAGE_SIZE) else {
        return false;
    };
    stream.write_all(&frame).await.is_ok() && stream.flush().await.is_ok()
}

/// Returns the bound socket's filesystem permission bits.
///
/// Returns `None` when the path does not exist or `metadata` fails.
/// Surfaced as a public helper for tests and `locket doctor`.
#[must_use]
pub fn socket_permission_mode(path: &Path) -> Option<u32> {
    std::fs::metadata(path).ok().map(|metadata| metadata.permissions().mode() & 0o777)
}
