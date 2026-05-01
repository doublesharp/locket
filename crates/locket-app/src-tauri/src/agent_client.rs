//! Minimal client for the locket agent's v1 framed JSON protocol.
//!
//! Connects to the agent's Unix domain socket, exchanges framed
//! request/response RPCs, and subscribes to the metadata-only status
//! stream used by the system tray.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use locket_agent::{
    AgentMethod, DEFAULT_MAX_MESSAGE_SIZE, ProtocolError, RequestEnvelope, ResponseEnvelope,
    StatusEvent, StatusPayload, decode_response_frame, encode_frame,
};
use locket_core::{ErrorDisplayCopy, LocketError};
use serde::{Serialize, de::DeserializeOwned};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::{Notify, mpsc};

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

/// Initial reconnect backoff after the status stream drops.
pub const RECONNECT_INITIAL_BACKOFF: Duration = Duration::from_secs(1);

/// Maximum reconnect backoff between attempts. The desktop spec caps
/// the wait at 30 seconds so a long-stopped agent still surfaces a
/// reconnect within a UX-acceptable window once it comes back.
pub const RECONNECT_MAX_BACKOFF: Duration = Duration::from_secs(30);

/// Pure mapping from a previous attempt delay to the next delay. The
/// schedule doubles starting at [`RECONNECT_INITIAL_BACKOFF`] until it
/// hits [`RECONNECT_MAX_BACKOFF`]. Exposed as a `pub` helper so tests
/// and the Tauri reconnect loop share the same source of truth.
#[must_use]
pub fn next_reconnect_delay(previous: Option<Duration>) -> Duration {
    let Some(previous) = previous else {
        return RECONNECT_INITIAL_BACKOFF;
    };
    let doubled = previous.saturating_mul(2);
    if doubled >= RECONNECT_MAX_BACKOFF {
        RECONNECT_MAX_BACKOFF
    } else {
        doubled
    }
}

/// Cancellation token shared between the desktop shell and the
/// streaming client task.
///
/// The Tauri layer flips this on app shutdown so the long-lived
/// `SubscribeStatus` reader exits cleanly without leaving a half-open
/// socket behind.
#[derive(Clone, Debug, Default)]
pub struct CancelToken {
    notify: Arc<Notify>,
    flag: Arc<std::sync::atomic::AtomicBool>,
}

impl CancelToken {
    /// Creates a fresh, unflagged cancel token.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Marks the token as cancelled and wakes every waiter.
    pub fn cancel(&self) {
        self.flag.store(true, std::sync::atomic::Ordering::SeqCst);
        self.notify.notify_waiters();
    }

    /// Reports whether the token has been cancelled.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.flag.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Future resolves the moment [`CancelToken::cancel`] is called.
    pub async fn cancelled(&self) {
        if self.is_cancelled() {
            return;
        }
        let notified = self.notify.notified();
        if self.is_cancelled() {
            return;
        }
        notified.await;
    }
}

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
        /// Shared typed-error reason shown across UI surfaces.
        display_reason: String,
        /// Shared typed-error recovery action shown across UI surfaces.
        next_action: String,
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
        /// Shared typed-error reason when the code maps to `LocketError`.
        display_reason: String,
        /// Shared typed-error recovery action when the code maps to `LocketError`.
        next_action: String,
        /// Whether the client may retry the request unchanged.
        retryable: bool,
    },
}

impl AgentClientError {
    fn unavailable(reason: impl Into<String>, socket_path: &Path) -> Self {
        let copy = LocketError::AgentUnavailable.display_copy();
        Self::Unavailable {
            reason: reason.into(),
            display_reason: copy.reason.to_owned(),
            next_action: copy.next_action.to_owned(),
            socket_path: socket_path.display().to_string(),
        }
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
    invoke_method::<(), StatusPayload>(socket_path, AgentMethod::Status, &()).await
}

/// Invoke any agent RPC end-to-end.
///
/// Serializes `payload` to JSON, exchanges a single request frame, and
/// deserializes the success payload as `R`. Error envelopes flow back
/// as [`AgentClientError::Rejected`].
///
/// # Errors
///
/// Returns [`AgentClientError`] for unreachable sockets, timeouts,
/// framing/JSON faults, and agent-side rejections.
pub async fn invoke_method<P: Serialize, R: DeserializeOwned>(
    socket_path: &Path,
    method: AgentMethod,
    payload: &P,
) -> Result<R, AgentClientError> {
    let payload_value = serde_json::to_value(payload).map_err(|error| {
        AgentClientError::Protocol { reason: format!("payload serialization failed: {error}") }
    })?;
    let stream = connect(socket_path).await?;
    let request = RequestEnvelope::new(new_request_id(), method, payload_value);
    let response = round_trip(stream, &request).await?;
    decode_payload(response)
}

/// Subscribe to metadata-only agent status events.
///
/// Opens a dedicated `SubscribeStatus` connection and forwards decoded
/// [`StatusEvent`] values into `sender` until the socket closes or the
/// receiver is dropped. No per-read timeout is applied because the
/// server is allowed to idle until its heartbeat interval.
///
/// # Errors
///
/// Returns [`AgentClientError`] when the socket can't be reached, the
/// initial request can't be written, the wire protocol fails, or the
/// agent replies with an error envelope.
pub async fn stream_status_events(
    socket_path: &Path,
    sender: mpsc::Sender<StatusEvent>,
) -> Result<(), AgentClientError> {
    stream_status_events_with_cancel(socket_path, sender, &CancelToken::new()).await
}

/// Cancellable variant of [`stream_status_events`].
///
/// The reader stops as soon as `cancel` is flipped, sending one final
/// `CancelSubscription` envelope upstream so the agent can release the
/// subscriber slot cleanly. Used by the long-lived Tauri command so app
/// shutdown can join the reader without dangling tasks.
///
/// # Errors
///
/// Returns [`AgentClientError`] for unreachable sockets, write/flush
/// failures, framing/JSON faults, and agent-side error envelopes.
pub async fn stream_status_events_with_cancel(
    socket_path: &Path,
    sender: mpsc::Sender<StatusEvent>,
    cancel: &CancelToken,
) -> Result<(), AgentClientError> {
    let mut stream = connect(socket_path).await?;
    let subscribe_id = new_request_id();
    let request = RequestEnvelope::new(
        subscribe_id.clone(),
        AgentMethod::SubscribeStatus,
        serde_json::Value::Null,
    );
    let frame = encode_frame(&request, DEFAULT_MAX_MESSAGE_SIZE)?;
    stream
        .write_all(&frame)
        .await
        .map_err(|error| AgentClientError::Protocol { reason: format!("write failed: {error}") })?;
    stream
        .flush()
        .await
        .map_err(|error| AgentClientError::Protocol { reason: format!("flush failed: {error}") })?;
    let result = read_status_stream(&mut stream, sender, cancel).await;
    if cancel.is_cancelled() {
        // Best-effort `CancelSubscription` so the agent doesn't have to
        // observe the close to free the subscriber. The cancellation
        // path returns `Ok(())` regardless of whether the agent saw the
        // envelope before the socket closed.
        let cancel_request = RequestEnvelope::new(
            new_request_id(),
            AgentMethod::CancelSubscription,
            serde_json::json!({ "subscription_id": subscribe_id }),
        );
        if let Ok(frame) = encode_frame(&cancel_request, DEFAULT_MAX_MESSAGE_SIZE) {
            let _ = stream.write_all(&frame).await;
            let _ = stream.flush().await;
        }
        return Ok(());
    }
    result
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

async fn read_status_stream(
    stream: &mut UnixStream,
    sender: mpsc::Sender<StatusEvent>,
    cancel: &CancelToken,
) -> Result<(), AgentClientError> {
    let mut buffer: Vec<u8> = Vec::with_capacity(4096);
    let mut chunk = [0_u8; 4096];
    loop {
        match decode_response_frame(&buffer, DEFAULT_MAX_MESSAGE_SIZE) {
            Ok((response, consumed)) => {
                buffer.drain(..consumed);
                let event = decode_payload::<StatusEvent>(response)?;
                if sender.send(event).await.is_err() {
                    return Ok(());
                }
                continue;
            }
            Err(ProtocolError::IncompleteFrame) => {}
            Err(error) => return Err(error.into()),
        }
        if cancel.is_cancelled() {
            return Ok(());
        }
        let read = tokio::select! {
            biased;
            () = cancel.cancelled() => return Ok(()),
            result = stream.read(&mut chunk) => result.map_err(|error| AgentClientError::Protocol {
                reason: format!("read failed: {error}"),
            })?,
        };
        if read == 0 {
            return Err(AgentClientError::Protocol {
                reason: "agent closed status stream".to_owned(),
            });
        }
        buffer.extend_from_slice(&chunk[..read]);
    }
}

fn decode_payload<R: DeserializeOwned>(response: ResponseEnvelope) -> Result<R, AgentClientError> {
    match response {
        ResponseEnvelope::Success(success) => {
            serde_json::from_value::<R>(success.payload).map_err(|error| {
                AgentClientError::Protocol {
                    reason: format!("malformed response payload: {error}"),
                }
            })
        }
        ResponseEnvelope::Error(error) => {
            let copy = display_copy_for_agent_code(&error.error).unwrap_or(ErrorDisplayCopy {
                reason: "The agent rejected the request.",
                next_action: "See the agent logs for details.",
            });
            Err(AgentClientError::Rejected {
                code: error.error,
                message: error.message,
                display_reason: copy.reason.to_owned(),
                next_action: copy.next_action.to_owned(),
                retryable: error.retryable,
            })
        }
    }
}

fn display_copy_for_agent_code(code: &str) -> Option<ErrorDisplayCopy> {
    LocketError::from_code_name(code).map(|error| error.display_copy())
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

#[cfg(test)]
mod tests {
    use super::{
        CancelToken, RECONNECT_INITIAL_BACKOFF, RECONNECT_MAX_BACKOFF, display_copy_for_agent_code,
        next_reconnect_delay,
    };
    use std::time::Duration;

    #[test]
    fn agent_error_codes_use_shared_locket_error_copy() -> Result<(), Box<dyn std::error::Error>> {
        let copy = display_copy_for_agent_code("UnlockRequired").ok_or("known typed error")?;
        assert_eq!(copy.reason, "The vault is locked.");
        assert_eq!(copy.next_action, "Run locket unlock or approve an agent unlock prompt.");
        assert!(display_copy_for_agent_code("ProtocolError").is_none());
        Ok(())
    }

    #[test]
    fn reconnect_schedule_doubles_until_capped_at_30_seconds() {
        // Spec: start at 1 second, double on each failure, cap at 30
        // seconds. The schedule must always start from
        // `RECONNECT_INITIAL_BACKOFF` and never exceed
        // `RECONNECT_MAX_BACKOFF`.
        let mut delays = Vec::new();
        let mut current: Option<Duration> = None;
        for _ in 0..10 {
            let next = next_reconnect_delay(current);
            delays.push(next);
            current = Some(next);
        }

        assert_eq!(delays[0], RECONNECT_INITIAL_BACKOFF);
        assert_eq!(delays[0], Duration::from_secs(1));
        assert_eq!(delays[1], Duration::from_secs(2));
        assert_eq!(delays[2], Duration::from_secs(4));
        assert_eq!(delays[3], Duration::from_secs(8));
        assert_eq!(delays[4], Duration::from_secs(16));
        for delay in &delays[5..] {
            assert_eq!(*delay, RECONNECT_MAX_BACKOFF);
            assert_eq!(*delay, Duration::from_secs(30));
        }
    }

    #[tokio::test(flavor = "current_thread")]
    #[allow(clippy::expect_used)]
    async fn cancel_token_wakes_waiters_once_cancelled() {
        let token = CancelToken::new();
        assert!(!token.is_cancelled());
        let waiter = {
            let token = token.clone();
            tokio::spawn(async move { token.cancelled().await })
        };
        token.cancel();
        waiter.await.expect("waiter must complete");
        assert!(token.is_cancelled());
        // Subsequent waits resolve immediately.
        token.cancelled().await;
    }
}
