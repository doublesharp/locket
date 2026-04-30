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
use crate::status_stream::StatusHub;

#[cfg(test)]
type PeerCredentialValidator =
    dyn Fn(&UnixStream, u32) -> Result<(), SocketServerError> + Send + Sync;

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
    /// Agent version string reported on `Status` responses.
    pub agent_version: String,
    /// UID of the running daemon process, used to validate peer
    /// credentials on every accept.
    pub daemon_uid: u32,
    /// Per-project unlock-key cache populated by `Unlock` and cleared
    /// by `Lock`. Status responses derive `lock_state` and
    /// `unlock_ttl_seconds` from the live entries here.
    pub unlock_cache: Arc<Mutex<crate::unlock_cache::UnlockCache>>,
    /// Live process-bound grant records. `RequestGrant` inserts new
    /// rows, `RevokeGrant` and `ExpireGrant` remove them, and
    /// `Status` responses surface `live_grant_count` from this table.
    pub grants: Arc<Mutex<crate::grant::GrantTable>>,
    /// Metadata-only runtime session snapshots used by desktop views.
    pub runtime_sessions: Arc<Mutex<Vec<crate::runtime_sessions::RuntimeSessionSnapshot>>>,
    /// Metadata-only saved command policy snapshots used by desktop views.
    pub command_policies: Arc<Mutex<Vec<crate::policies::CommandPolicySnapshot>>>,
    /// Server-side fan-out hub for `SubscribeStatus` streams.
    pub status_hub: StatusHub,
    /// Test hook overriding the heartbeat cadence so unit tests can run
    /// with millisecond cadence rather than 30-second waits.
    #[cfg(test)]
    pub test_heartbeat_interval: Arc<Mutex<Option<std::time::Duration>>>,
    /// Test hook that lets socket tests inject spoofed peer UIDs
    /// without requiring root or a second local user.
    #[cfg(test)]
    peer_credential_validator: Arc<PeerCredentialValidator>,
}

impl AgentSocketState {
    /// Builds an initial state with an empty unlock cache.
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
        let agent_version = agent_version.into();
        let status_hub = StatusHub::new(StatusPayload::locked(agent_version.clone()));
        Self {
            agent_version,
            daemon_uid,
            unlock_cache: Arc::new(Mutex::new(crate::unlock_cache::UnlockCache::default())),
            grants: Arc::new(Mutex::new(crate::grant::GrantTable::default())),
            runtime_sessions: Arc::new(Mutex::new(Vec::new())),
            command_policies: Arc::new(Mutex::new(Vec::new())),
            status_hub,
            #[cfg(test)]
            test_heartbeat_interval: Arc::new(Mutex::new(None)),
            #[cfg(test)]
            peer_credential_validator: Arc::new(crate::peer_cred::validate_peer_stream),
        }
    }

    /// Test-only constructor that lets tests inject a shared unlock
    /// cache so they can pre-populate entries before driving the
    /// dispatcher.
    #[cfg(test)]
    pub fn for_tests(
        agent_version: impl Into<String>,
        daemon_uid: u32,
        cache: Arc<Mutex<crate::unlock_cache::UnlockCache>>,
    ) -> Self {
        let agent_version = agent_version.into();
        let status_hub = StatusHub::new(StatusPayload::locked(agent_version.clone()));
        Self {
            agent_version,
            daemon_uid,
            unlock_cache: cache,
            grants: Arc::new(Mutex::new(crate::grant::GrantTable::default())),
            runtime_sessions: Arc::new(Mutex::new(Vec::new())),
            command_policies: Arc::new(Mutex::new(Vec::new())),
            status_hub,
            test_heartbeat_interval: Arc::new(Mutex::new(None)),
            peer_credential_validator: Arc::new(crate::peer_cred::validate_peer_stream),
        }
    }

    /// Test-only override for peer credential validation. The live
    /// socket is still used, but the peer UID passed into the policy is
    /// supplied by the test so cross-user outcomes are deterministic.
    #[cfg(test)]
    #[must_use]
    pub fn with_test_peer_uid(mut self, peer_uid: u32) -> Self {
        self.peer_credential_validator = Arc::new(move |_stream, daemon_uid| {
            crate::peer_cred::validate_peer_uid(peer_uid, daemon_uid)
        });
        self
    }

    /// Test-only override for the heartbeat cadence. Setting this
    /// before a `SubscribeStatus` connection is accepted lets unit
    /// tests run with millisecond cadence rather than 30-second waits.
    #[cfg(test)]
    pub async fn set_test_heartbeat_interval(&self, interval: std::time::Duration) {
        *self.test_heartbeat_interval.lock().await = Some(interval);
    }

    /// Test-only seed for metadata-only runtime session snapshots.
    #[cfg(test)]
    pub async fn set_runtime_sessions_for_tests(
        &self,
        sessions: Vec<crate::runtime_sessions::RuntimeSessionSnapshot>,
    ) {
        *self.runtime_sessions.lock().await = sessions;
    }

    /// Test-only seed for metadata-only command policy snapshots.
    #[cfg(test)]
    pub async fn set_command_policies_for_tests(
        &self,
        policies: Vec<crate::policies::CommandPolicySnapshot>,
    ) {
        *self.command_policies.lock().await = policies;
    }

    /// Builds the metadata-only `Status` payload from the current
    /// unlock-cache state. The reported `unlock_ttl_seconds` is the
    /// longest remaining TTL across live entries; the agent reports
    /// `Locked` whenever no live entry remains.
    pub async fn status_snapshot(&self, now_unix_nanos: i128) -> StatusPayload {
        {
            let mut cache = self.unlock_cache.lock().await;
            cache.evict_expired(now_unix_nanos);
        }
        let summary = collect_live_summary(&self.unlock_cache, now_unix_nanos).await;
        let grant_count = {
            let grants = self.grants.lock().await;
            grants.len()
        };
        StatusPayload {
            lock_state: if summary.any_live { LockState::Unlocked } else { LockState::Locked },
            project_id: None,
            profile_name: None,
            live_grant_count: u32::try_from(grant_count).unwrap_or(u32::MAX),
            agent_version: self.agent_version.clone(),
            unlock_ttl_seconds: summary.max_remaining_seconds,
        }
    }

    async fn publish_status_snapshot(&self, now_unix_nanos: i128) -> StatusPayload {
        let snapshot = self.status_snapshot(now_unix_nanos).await;
        self.status_hub.publish(snapshot.clone()).await;
        snapshot
    }
}

/// Snapshot of live unlock-cache state used to fill a `StatusPayload`.
struct LiveCacheSummary {
    any_live: bool,
    max_remaining_seconds: Option<u64>,
}

async fn collect_live_summary(
    unlock_cache: &Arc<Mutex<crate::unlock_cache::UnlockCache>>,
    now_unix_nanos: i128,
) -> LiveCacheSummary {
    let live_expiries: Vec<i128> = {
        let cache = unlock_cache.lock().await;
        cache
            .entries_for_status()
            .filter(|entry| !entry.is_expired(now_unix_nanos))
            .map(crate::unlock_cache::UnlockEntry::expires_at_unix_nanos)
            .collect()
    };
    let any_live = !live_expiries.is_empty();
    let max_remaining_seconds = live_expiries
        .into_iter()
        .map(|expires_at| u64::try_from((expires_at - now_unix_nanos) / 1_000_000_000).unwrap_or(0))
        .max();
    LiveCacheSummary { any_live, max_remaining_seconds }
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
    if let Err(error) = validate_connection_peer(&stream, &state) {
        return ConnectionOutcome::Rejected { reason: error };
    }
    let mut buffer = Vec::with_capacity(4 * 1024);
    loop {
        match read_one_frame(&mut stream, &mut buffer).await {
            Ok(None) => return ConnectionOutcome::PeerClosed,
            Ok(Some(envelope)) => {
                if matches!(envelope.method(), Ok(AgentMethod::SubscribeStatus)) {
                    return stream_status(stream, state, envelope.id.clone(), buffer).await;
                }
                let response = dispatch(&envelope, &state).await;
                if !write_response(&mut stream, &response).await {
                    return ConnectionOutcome::Errored;
                }
            }
            Err(_) => return ConnectionOutcome::Errored,
        }
    }
}

fn validate_connection_peer(
    stream: &UnixStream,
    state: &AgentSocketState,
) -> Result<(), SocketServerError> {
    #[cfg(test)]
    {
        (state.peer_credential_validator)(stream, state.daemon_uid)
    }
    #[cfg(not(test))]
    {
        crate::peer_cred::validate_peer_stream(stream, state.daemon_uid)
    }
}

/// Streams metadata-only status events for the lifetime of a
/// `SubscribeStatus` request.
///
/// Reads from the peer in parallel with the hub: the only request
/// allowed mid-stream is `CancelSubscription`, which closes the
/// connection cleanly. Any other framed request is answered with a
/// redacted `ProtocolError` and then the connection is dropped.
async fn stream_status(
    mut stream: UnixStream,
    state: AgentSocketState,
    request_id: String,
    initial_buffer: Vec<u8>,
) -> ConnectionOutcome {
    let mut subscriber = state.status_hub.subscribe().await;
    #[cfg(test)]
    let heartbeat =
        state.test_heartbeat_interval.lock().await.unwrap_or(std::time::Duration::from_secs(
            crate::status::STATUS_HEARTBEAT_INTERVAL_SECS,
        ));
    #[cfg(not(test))]
    let heartbeat = std::time::Duration::from_secs(crate::status::STATUS_HEARTBEAT_INTERVAL_SECS);

    let mut buffer = initial_buffer;
    loop {
        // Drain any already-buffered frames before blocking on the
        // socket. A peer can send `CancelSubscription` immediately
        // after `SubscribeStatus`, in which case it would already be
        // sitting in `buffer`.
        if let Ok((envelope, consumed)) = decode_request_frame(&buffer, DEFAULT_MAX_MESSAGE_SIZE) {
            buffer.drain(..consumed);
            if matches!(envelope.method(), Ok(AgentMethod::CancelSubscription)) {
                return ConnectionOutcome::PeerClosed;
            }
            let response = error_response(
                &envelope,
                "ProtocolError",
                "only CancelSubscription is allowed mid-stream",
            );
            let _ = write_response(&mut stream, &response).await;
            return ConnectionOutcome::Errored;
        }

        tokio::select! {
            event = subscriber.next_event_with_heartbeat(heartbeat) => {
                let Some(event) = event else { return ConnectionOutcome::Errored; };
                let Ok(payload) = serde_json::to_value(&event) else {
                    return ConnectionOutcome::Errored;
                };
                let response = ResponseEnvelope::Success(SuccessEnvelope::new(
                    request_id.clone(),
                    payload,
                ));
                if !write_response(&mut stream, &response).await {
                    return ConnectionOutcome::Errored;
                }
            }
            read = stream.read_buf(&mut buffer) => {
                match read {
                    Ok(0) => return ConnectionOutcome::PeerClosed,
                    Ok(_) => {
                        // Loop will attempt decode at the top.
                    }
                    Err(_) => return ConnectionOutcome::Errored,
                }
            }
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

/// Wire payload for the `Unlock` RPC. The `key` field is bytes-as-array
/// per the v1 spec; `serde_bytes` lets serde accept JSON byte arrays
/// without forcing the client to base64-encode the unwrapped key.
// TODO(task-agent-real-unlock): Replace the client-supplied `key` field
// with an OS-keychain / passphrase / recovery-envelope unwrap performed
// inside the agent. See docs/specs/agent.md:84.
#[derive(serde::Deserialize)]
struct UnlockPayload {
    project_id: String,
    #[serde(with = "serde_bytes")]
    key: Vec<u8>,
    ttl_seconds: u64,
    method: crate::unlock_cache::UnlockMethod,
}

/// Returns the current Unix wall-clock time in nanoseconds, clamped to
/// the positive `i64` range so downstream arithmetic stays in `i128`.
pub fn current_unix_nanos() -> i128 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| {
            let max = u128::from(u64::try_from(i64::MAX).unwrap_or(0));
            let clamped = d.as_nanos().min(max);
            i128::from(i64::try_from(clamped).unwrap_or(0))
        })
        .unwrap_or(0)
}

fn error_response(envelope: &RequestEnvelope, error: &str, message: &str) -> ResponseEnvelope {
    ResponseEnvelope::Error(ErrorEnvelope::new(envelope.id.clone(), error, message, false))
}

pub async fn dispatch(envelope: &RequestEnvelope, state: &AgentSocketState) -> ResponseEnvelope {
    match envelope.method() {
        Ok(AgentMethod::Status) => {
            let snapshot = state.status_snapshot(current_unix_nanos()).await;
            let payload = serde_json::to_value(snapshot).unwrap_or(serde_json::Value::Null);
            ResponseEnvelope::Success(SuccessEnvelope::new(envelope.id.clone(), payload))
        }
        // TODO(task-agent-real-unlock): see UnlockPayload above — this arm
        // trusts the client's key bytes; once the agent owns the unwrap path,
        // the wire payload changes from `key` to e.g. `passphrase` /
        // `keychain_token` and this arm performs the unwrap.
        Ok(AgentMethod::Unlock) => {
            let now = current_unix_nanos();
            let payload: UnlockPayload = match serde_json::from_value(envelope.payload.clone()) {
                Ok(payload) => payload,
                Err(_) => {
                    return error_response(envelope, "ProtocolError", "invalid Unlock payload");
                }
            };
            let entry = crate::unlock_cache::UnlockEntry::new(
                payload.key,
                now,
                std::time::Duration::from_secs(payload.ttl_seconds),
                payload.method,
            );
            state.unlock_cache.lock().await.insert(payload.project_id, entry);
            state.publish_status_snapshot(now).await;
            ResponseEnvelope::Success(SuccessEnvelope::new(
                envelope.id.clone(),
                serde_json::Value::Null,
            ))
        }
        Ok(AgentMethod::Lock) => {
            state.unlock_cache.lock().await.clear();
            state.grants.lock().await.clear();
            state.publish_status_snapshot(current_unix_nanos()).await;
            ResponseEnvelope::Success(SuccessEnvelope::new(
                envelope.id.clone(),
                serde_json::Value::Null,
            ))
        }
        Ok(AgentMethod::RequestGrant) => handle_request_grant(envelope, state).await,
        Ok(AgentMethod::RevokeGrant) => handle_revoke_grant(envelope, state).await,
        Ok(AgentMethod::ExpireGrant) => handle_expire_grant(envelope, state).await,
        Ok(AgentMethod::Reveal) => crate::reveal::handle_reveal(envelope),
        Ok(AgentMethod::Copy) => crate::reveal::handle_copy(envelope),
        Ok(AgentMethod::ScanKnownValues) => crate::scan::handle_scan(envelope),
        Ok(AgentMethod::ListRuntimeSessions) => handle_list_runtime_sessions(envelope, state).await,
        Ok(AgentMethod::ListPolicies) => handle_list_policies(envelope, state).await,
        Ok(AgentMethod::ResolveReference) => crate::resolve::handle_resolve(envelope),
        Ok(AgentMethod::PrepareExec) => crate::prepare_exec::handle_prepare_exec(envelope),
        Ok(AgentMethod::ListSecrets) => handle_list_secrets(envelope),
        Ok(AgentMethod::ListVersions) => handle_list_versions(envelope),
        Ok(AgentMethod::VerifyAudit) => handle_verify_audit(envelope, state).await,
        Ok(AgentMethod::ListAudit) => handle_list_audit(envelope, state).await,
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

async fn handle_list_policies(
    envelope: &RequestEnvelope,
    state: &AgentSocketState,
) -> ResponseEnvelope {
    let request: crate::policies::ListPoliciesRequest =
        match serde_json::from_value(envelope.payload.clone()) {
            Ok(request) => request,
            Err(_) => return crate::policies::invalid_payload_response(envelope),
        };
    let response = {
        let policies = state.command_policies.lock().await;
        crate::policies::list_policies_response(&request, &policies)
    };
    crate::policies::success_response(envelope, response)
}

async fn handle_list_runtime_sessions(
    envelope: &RequestEnvelope,
    state: &AgentSocketState,
) -> ResponseEnvelope {
    let request: crate::runtime_sessions::ListRuntimeSessionsRequest =
        match serde_json::from_value(envelope.payload.clone()) {
            Ok(request) => request,
            Err(_) => return crate::runtime_sessions::invalid_payload_response(envelope),
        };
    let response = {
        let sessions = state.runtime_sessions.lock().await;
        crate::runtime_sessions::list_runtime_sessions_response(&request, &sessions)
    };
    crate::runtime_sessions::success_response(envelope, response)
}

fn handle_list_secrets(envelope: &RequestEnvelope) -> ResponseEnvelope {
    let payload: crate::secrets::ListSecretsRequest =
        match serde_json::from_value(envelope.payload.clone()) {
            Ok(payload) => payload,
            Err(_) => {
                return error_response(envelope, "ProtocolError", "invalid ListSecrets payload");
            }
        };
    match crate::secrets::list_secrets(&payload) {
        Ok(response) => {
            let payload = serde_json::to_value(response).unwrap_or(serde_json::Value::Null);
            ResponseEnvelope::Success(SuccessEnvelope::new(envelope.id.clone(), payload))
        }
        Err(error) => {
            let locket_error = error.locket_error();
            ResponseEnvelope::Error(ErrorEnvelope::new(
                envelope.id.clone(),
                format!("{locket_error:?}"),
                error.to_string(),
                false,
            ))
        }
    }
}

fn handle_list_versions(envelope: &RequestEnvelope) -> ResponseEnvelope {
    let payload: crate::versions::ListVersionsRequest =
        match serde_json::from_value(envelope.payload.clone()) {
            Ok(payload) => payload,
            Err(_) => {
                return error_response(envelope, "ProtocolError", "invalid ListVersions payload");
            }
        };
    match crate::versions::list_versions(&payload) {
        Ok(response) => {
            let payload = serde_json::to_value(response).unwrap_or(serde_json::Value::Null);
            ResponseEnvelope::Success(SuccessEnvelope::new(envelope.id.clone(), payload))
        }
        Err(error) => {
            let locket_error = error.locket_error();
            ResponseEnvelope::Error(ErrorEnvelope::new(
                envelope.id.clone(),
                format!("{locket_error:?}"),
                error.to_string(),
                false,
            ))
        }
    }
}

async fn handle_verify_audit(
    envelope: &RequestEnvelope,
    state: &AgentSocketState,
) -> ResponseEnvelope {
    let payload: crate::audit_verify::VerifyAuditRequest =
        match serde_json::from_value(envelope.payload.clone()) {
            Ok(payload) => payload,
            Err(_) => {
                return error_response(envelope, "ProtocolError", "invalid VerifyAudit payload");
            }
        };
    let audit_key = {
        let cache = state.unlock_cache.lock().await;
        cache
            .lookup(&payload.project_id, current_unix_nanos())
            .map(|entry| entry.key_bytes().to_vec())
    };
    let response = audit_key.map_or_else(
        || Ok(crate::audit_verify::VerifyAuditResponse::locked()),
        |key| crate::audit_verify::verify_audit(&payload, &key),
    );
    match response {
        Ok(response) => {
            let payload = serde_json::to_value(response).unwrap_or(serde_json::Value::Null);
            ResponseEnvelope::Success(SuccessEnvelope::new(envelope.id.clone(), payload))
        }
        Err(error) => {
            let locket_error = error.locket_error();
            ResponseEnvelope::Error(ErrorEnvelope::new(
                envelope.id.clone(),
                format!("{locket_error:?}"),
                error.to_string(),
                false,
            ))
        }
    }
}

async fn handle_list_audit(envelope: &RequestEnvelope, state: &AgentSocketState) -> ResponseEnvelope {
    let payload: crate::audit::ListAuditRequest =
        match serde_json::from_value(envelope.payload.clone()) {
            Ok(payload) => payload,
            Err(_) => {
                return error_response(envelope, "ProtocolError", "invalid ListAudit payload");
            }
        };
    let audit_key = {
        let cache = state.unlock_cache.lock().await;
        cache
            .lookup(&payload.project_id, current_unix_nanos())
            .map(|entry| entry.key_bytes().to_vec())
    };
    match crate::audit::list_audit(&payload, audit_key.as_deref()) {
        Ok(response) => {
            let payload = serde_json::to_value(response).unwrap_or(serde_json::Value::Null);
            ResponseEnvelope::Success(SuccessEnvelope::new(envelope.id.clone(), payload))
        }
        Err(error) => {
            let locket_error = error.locket_error();
            ResponseEnvelope::Error(ErrorEnvelope::new(
                envelope.id.clone(),
                format!("{locket_error:?}"),
                error.to_string(),
                false,
            ))
        }
    }
}

async fn handle_request_grant(
    envelope: &RequestEnvelope,
    state: &AgentSocketState,
) -> ResponseEnvelope {
    let payload: crate::grant::RequestGrantPayload =
        match serde_json::from_value(envelope.payload.clone()) {
            Ok(payload) => payload,
            Err(_) => {
                return error_response(envelope, "ProtocolError", "invalid RequestGrant payload");
            }
        };
    let now = current_unix_nanos();
    let ttl_nanos = i128::from(payload.ttl_seconds).saturating_mul(1_000_000_000);
    let record = {
        let mut grants = state.grants.lock().await;
        match grants.issue(payload, now, now.saturating_add(ttl_nanos)) {
            Ok(record) => record,
            Err(_) => {
                return error_response(envelope, "ProtocolError", "failed to allocate grant id");
            }
        }
    };
    let response_payload = serde_json::json!({
        "grant_id": record.grant_id,
        "expires_at_unix_nanos": record.expires_at_unix_nanos.to_string(),
    });
    ResponseEnvelope::Success(SuccessEnvelope::new(envelope.id.clone(), response_payload))
}

async fn handle_revoke_grant(
    envelope: &RequestEnvelope,
    state: &AgentSocketState,
) -> ResponseEnvelope {
    let payload: crate::grant::GrantIdPayload =
        match serde_json::from_value(envelope.payload.clone()) {
            Ok(payload) => payload,
            Err(_) => {
                return error_response(envelope, "ProtocolError", "invalid RevokeGrant payload");
            }
        };
    let removed = {
        let mut grants = state.grants.lock().await;
        grants.revoke(&payload.grant_id)
    };
    if removed.is_some() {
        ResponseEnvelope::Success(SuccessEnvelope::new(
            envelope.id.clone(),
            serde_json::Value::Null,
        ))
    } else {
        error_response(envelope, "GrantRequired", "grant not found")
    }
}

async fn handle_expire_grant(
    envelope: &RequestEnvelope,
    state: &AgentSocketState,
) -> ResponseEnvelope {
    let payload: crate::grant::GrantIdPayload =
        match serde_json::from_value(envelope.payload.clone()) {
            Ok(payload) => payload,
            Err(_) => {
                return error_response(envelope, "ProtocolError", "invalid ExpireGrant payload");
            }
        };
    let outcome = {
        let mut grants = state.grants.lock().await;
        let now = current_unix_nanos();
        match grants.get(&payload.grant_id) {
            None => ExpireOutcome::Unknown,
            Some(record) if now >= record.expires_at_unix_nanos => {
                grants.revoke(&payload.grant_id);
                ExpireOutcome::DroppedExpired
            }
            Some(_) => ExpireOutcome::StillLive,
        }
    };
    match outcome {
        ExpireOutcome::DroppedExpired | ExpireOutcome::Unknown => ResponseEnvelope::Success(
            SuccessEnvelope::new(envelope.id.clone(), serde_json::Value::Null),
        ),
        ExpireOutcome::StillLive => {
            error_response(envelope, "ProtocolError", "grant is still live")
        }
    }
}

#[derive(Clone, Copy)]
enum ExpireOutcome {
    DroppedExpired,
    Unknown,
    StillLive,
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

#[cfg(test)]
mod cache_status_tests {
    use std::sync::Arc;
    use std::time::Duration;

    use super::*;
    use crate::unlock_cache::{UnlockCache, UnlockEntry, UnlockMethod};
    use tokio::sync::Mutex;

    #[tokio::test(flavor = "current_thread")]
    async fn status_reports_unlocked_when_cache_has_live_entry() {
        let cache = Arc::new(Mutex::new(UnlockCache::default()));
        cache.lock().await.insert(
            "proj-1".to_owned(),
            UnlockEntry::new(
                b"k".to_vec(),
                1_000_000_000,
                Duration::from_secs(60),
                UnlockMethod::Passphrase,
            ),
        );
        let state = AgentSocketState::for_tests(
            "test-version",
            crate::peer_cred::current_process_uid(),
            cache.clone(),
        );

        let snapshot = state.status_snapshot(1_500_000_000).await;

        assert_eq!(snapshot.lock_state, LockState::Unlocked);
        assert_eq!(snapshot.unlock_ttl_seconds, Some(59));
    }
}
