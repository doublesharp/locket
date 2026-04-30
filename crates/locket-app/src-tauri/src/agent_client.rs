//! Minimal client for the locket agent's v1 framed JSON protocol.
//!
//! Connects to the agent's Unix domain socket, exchanges a single
//! `Status` request/response, and surfaces a typed error so the
//! desktop UI can render a precise `AgentUnavailable` banner instead
//! of swallowing every failure into a generic timeout.

use std::path::{Path, PathBuf};
use std::time::Duration;

use locket_agent::{
    AgentMethod, DEFAULT_MAX_MESSAGE_SIZE, ProtocolError, RequestEnvelope, ResponseEnvelope,
    StatusPayload, decode_response_frame, encode_frame,
};
use serde::Serialize;
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

/// Default subdirectory under the user's data dir for agent sockets.
const DEFAULT_DATA_DIR: &str = ".locket";

/// Default socket file name relative to [`DEFAULT_DATA_DIR`].
const DEFAULT_SOCKET_FILE: &str = "agent.sock";

/// Environment variable that overrides the agent socket path.
const SOCKET_PATH_ENV: &str = "LOCKET_AGENT_SOCKET";

/// Connect timeout for the agent socket.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

/// Round-trip request timeout once a connection is established.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(3);

/// Typed errors surfaced by the desktop agent client.
///
/// Variants distinguish the daemon being absent (the common case the
/// `AgentUnavailable` banner is for) from wire-protocol faults so the
/// UI can keep them separate per the spec.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, thiserror::Error)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum AgentClientError {
    /// The agent daemon is not running or its socket is missing.
    #[error("agent unavailable: {reason}")]
    Unavailable {
        /// Short reason — daemon offline, socket missing, refused, timed-out.
        reason: String,
        /// Path that was attempted, for diagnostics.
        socket_path: String,
    },
    /// The wire protocol failed: framing, JSON, version, or unknown method.
    #[error("agent protocol error: {reason}")]
    Protocol {
        /// Human-readable summary of the protocol failure.
        reason: String,
    },
    /// The agent answered with an error envelope.
    #[error("agent rejected request: {code}")]
    Rejected {
        /// Stable typed-error code from the agent.
        code: String,
        /// Redacted safe message.
        message: String,
        /// Whether the client may retry the request unchanged.
        retryable: bool,
    },
}

impl AgentClientError {
    fn unavailable(reason: impl Into<String>, socket_path: &Path) -> Self {
        Self::Unavailable { reason: reason.into(), socket_path: socket_path.display().to_string() }
    }
}

impl From<ProtocolError> for AgentClientError {
    fn from(value: ProtocolError) -> Self {
        Self::Protocol { reason: value.to_string() }
    }
}

/// Resolve the path the desktop should try to connect to.
///
/// Honors `LOCKET_AGENT_SOCKET` first; otherwise falls back to
/// `<HOME>/.locket/agent.sock`. The default lines up with the CLI's
/// own `agent_data_dir`/`agent_socket_path` derivation when the user
/// has not overridden the store directory.
#[must_use]
pub fn resolve_socket_path() -> PathBuf {
    if let Ok(path) = std::env::var(SOCKET_PATH_ENV)
        && !path.is_empty()
    {
        return PathBuf::from(path);
    }
    let home = home_dir().unwrap_or_else(|| PathBuf::from("."));
    home.join(DEFAULT_DATA_DIR).join(DEFAULT_SOCKET_FILE)
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

/// Issue a single `Status` request to the agent.
///
/// Returns the metadata-only payload on success. Maps every failure
/// mode (no socket, refused connection, framing fault, error envelope)
/// onto [`AgentClientError`] without ever surfacing raw I/O errors to
/// the UI.
///
/// # Errors
///
/// Returns [`AgentClientError`] when the socket can't be reached, the
/// request times out, the wire protocol fails, or the agent replies
/// with an error envelope.
pub async fn fetch_status(socket_path: &Path) -> Result<StatusPayload, AgentClientError> {
    let stream = connect(socket_path).await?;
    let request = RequestEnvelope::new(new_request_id(), AgentMethod::Status, Value::Null);
    let response = round_trip(stream, &request).await?;
    payload_from_response(response)
}

async fn connect(socket_path: &Path) -> Result<UnixStream, AgentClientError> {
    if !socket_path.exists() {
        return Err(AgentClientError::unavailable("agent socket not found", socket_path));
    }
    match tokio::time::timeout(CONNECT_TIMEOUT, UnixStream::connect(socket_path)).await {
        Ok(Ok(stream)) => Ok(stream),
        Ok(Err(error)) => {
            Err(AgentClientError::unavailable(format!("connect failed: {error}"), socket_path))
        }
        Err(_) => Err(AgentClientError::unavailable("connect timed out", socket_path)),
    }
}

async fn round_trip(
    mut stream: UnixStream,
    request: &RequestEnvelope,
) -> Result<ResponseEnvelope, AgentClientError> {
    let frame = encode_frame(request, DEFAULT_MAX_MESSAGE_SIZE)?;

    let result = tokio::time::timeout(REQUEST_TIMEOUT, exchange_frame(&mut stream, &frame)).await;
    match result {
        Ok(Ok(envelope)) => Ok(envelope),
        Ok(Err(error)) => Err(error),
        Err(_) => Err(AgentClientError::Protocol { reason: "request timed out".to_owned() }),
    }
}

async fn exchange_frame(
    stream: &mut UnixStream,
    frame: &[u8],
) -> Result<ResponseEnvelope, AgentClientError> {
    stream
        .write_all(frame)
        .await
        .map_err(|error| AgentClientError::Protocol { reason: format!("write failed: {error}") })?;
    stream
        .flush()
        .await
        .map_err(|error| AgentClientError::Protocol { reason: format!("flush failed: {error}") })?;
    read_response_frame(stream).await
}

async fn read_response_frame(
    stream: &mut UnixStream,
) -> Result<ResponseEnvelope, AgentClientError> {
    let mut buffer: Vec<u8> = Vec::with_capacity(4096);
    let mut chunk = [0_u8; 4096];
    loop {
        match decode_response_frame(&buffer, DEFAULT_MAX_MESSAGE_SIZE) {
            Ok((envelope, _consumed)) => return Ok(envelope),
            Err(ProtocolError::IncompleteFrame) => {}
            Err(error) => return Err(error.into()),
        }
        let read = stream.read(&mut chunk).await.map_err(|error| AgentClientError::Protocol {
            reason: format!("read failed: {error}"),
        })?;
        if read == 0 {
            return Err(AgentClientError::Protocol {
                reason: "agent closed connection before response".to_owned(),
            });
        }
        buffer.extend_from_slice(&chunk[..read]);
    }
}

fn payload_from_response(response: ResponseEnvelope) -> Result<StatusPayload, AgentClientError> {
    match response {
        ResponseEnvelope::Success(success) => {
            serde_json::from_value::<StatusPayload>(success.payload).map_err(|error| {
                AgentClientError::Protocol { reason: format!("malformed status payload: {error}") }
            })
        }
        ResponseEnvelope::Error(error) => Err(AgentClientError::Rejected {
            code: error.error,
            message: error.message,
            retryable: error.retryable,
        }),
    }
}

fn new_request_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let next = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("desktop-{next}")
}

// Unit-level coverage of `resolve_socket_path` requires mutating
// process environment, which races with other tests under cargo's
// test runner. The integration tests in `tests/agent_client.rs`
// exercise the live socket path end-to-end and cover the
// daemon-offline failure mode.
