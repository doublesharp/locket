//! End-to-end tests for the desktop agent client.
//!
//! Spins up the locket-agent socket server in-process and drives the
//! desktop client against it. Covers the daemon-offline failure path,
//! a successful round-trip, and reconnection after the daemon drops.
#![allow(
    clippy::missing_docs_in_private_items,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc
)]

// Pull all dev-deps in so `unused_crate_dependencies` stays quiet for
// crates the rest of the test references via paths/macros only.
use directories as _;
use locket_app as _;
use locket_core as _;
use serde as _;
use serde_json as _;
use tauri as _;
use thiserror as _;

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use locket_agent::{
    AgentMethod, AgentSocketConfig, AgentSocketState, DEFAULT_MAX_MESSAGE_SIZE,
    ListRuntimeSessionsRequest, LockState, ResponseEnvelope, StatusEvent, StatusPayload,
    SuccessEnvelope, bind_socket_listener, decode_request_frame, encode_frame, handle_connection,
};
use locket_desktop_lib::{
    AgentClientError, fetch_status, invoke_method, resolve_socket_path, stream_status_events,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;
use tokio::sync::Notify;

const AGENT_VERSION: &str = "0.0.0-test";

#[tokio::test]
async fn fetch_status_returns_unavailable_when_socket_missing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let socket_path = dir.path().join("never-bound.sock");

    let result = fetch_status(&socket_path).await;
    let err = result.expect_err("missing socket must fail");
    match err {
        AgentClientError::Unavailable {
            reason,
            display_reason,
            next_action,
            socket_path: returned,
        } => {
            assert!(reason.contains("not found"), "reason was {reason}");
            assert_eq!(display_reason, "The local agent is unavailable.");
            assert_eq!(next_action, "Run locket agent start, then retry.");
            assert_eq!(returned, socket_path.display().to_string());
        }
        other => panic!("expected Unavailable, got {other:?}"),
    }
}

#[tokio::test]
async fn fetch_status_round_trips_against_a_live_agent() {
    let dir = tempdir_user_only();
    let socket_path = dir.path().join("agent.sock");

    let server = TestServer::start_at(&socket_path).await;
    let payload = fetch_status(&server.socket_path).await.expect("status round-trip");
    assert_eq!(payload.agent_version, AGENT_VERSION);
    server.stop().await;
}

#[tokio::test]
async fn fetch_status_recovers_after_daemon_restart() {
    let dir = tempdir_user_only();
    let socket_path = dir.path().join("agent.sock");

    let first = TestServer::start_at(&socket_path).await;
    let payload = fetch_status(&first.socket_path).await.expect("first round-trip");
    assert_eq!(payload.agent_version, AGENT_VERSION);
    first.stop().await;

    // After the daemon stops the path may linger or vanish depending on
    // OS cleanup; both states must surface as Unavailable, not as a
    // protocol error.
    let result = fetch_status(&socket_path).await;
    match result {
        Err(AgentClientError::Unavailable { .. }) => {}
        other => panic!("expected Unavailable after stop, got {other:?}"),
    }

    let second = TestServer::start_at(&socket_path).await;
    let payload = fetch_status(&second.socket_path).await.expect("second round-trip");
    assert_eq!(payload.agent_version, AGENT_VERSION);
    second.stop().await;
}

#[tokio::test]
async fn list_runtime_sessions_round_trips_against_a_live_agent() {
    let dir = tempdir_user_only();
    let socket_path = dir.path().join("agent.sock");

    let server = TestServer::start_at(&socket_path).await;
    let request = ListRuntimeSessionsRequest {
        project_id: "project-main".to_owned(),
        profile_id: "profile-prod".to_owned(),
        privacy_redact_names: true,
    };
    let response: locket_agent::ListRuntimeSessionsResponse =
        invoke_method(&server.socket_path, AgentMethod::ListRuntimeSessions, &request)
            .await
            .expect("runtime sessions round-trip");
    assert!(response.rows.is_empty());
    server.stop().await;
}

#[tokio::test]
async fn stream_status_events_decodes_subscribe_status_frames() {
    let dir = tempdir_user_only();
    let socket_path = dir.path().join("status-stream.sock");
    let listener = UnixListener::bind(&socket_path).expect("bind stream listener");

    let server = tokio::spawn(async move {
        let (mut stream, _addr) = listener.accept().await.expect("accept status client");
        let mut buffer = Vec::new();
        let mut chunk = [0_u8; 1024];
        loop {
            let read = stream.read(&mut chunk).await.expect("read subscribe request");
            assert_ne!(read, 0, "client closed before SubscribeStatus");
            buffer.extend_from_slice(&chunk[..read]);
            if let Ok((request, _consumed)) =
                decode_request_frame(&buffer, DEFAULT_MAX_MESSAGE_SIZE)
            {
                assert_eq!(request.method().ok(), Some(AgentMethod::SubscribeStatus));
                break;
            }
        }

        let locked = StatusEvent::status(1, StatusPayload::locked(AGENT_VERSION));
        write_status_event(&mut stream, &locked).await;
        let mut unlocked = StatusPayload::locked(AGENT_VERSION);
        unlocked.lock_state = LockState::Unlocked;
        write_status_event(&mut stream, &StatusEvent::status(2, unlocked)).await;
    });

    let (sender, mut receiver) = tokio::sync::mpsc::channel(4);
    let client_path = socket_path.clone();
    let client = tokio::spawn(async move { stream_status_events(&client_path, sender).await });

    let first = receiver.recv().await.expect("initial status event");
    assert!(first.is_state_change());
    assert_eq!(first.sequence, 1);
    assert_eq!(first.status.lock_state, LockState::Locked);

    let second = receiver.recv().await.expect("updated status event");
    assert!(second.is_state_change());
    assert_eq!(second.sequence, 2);
    assert_eq!(second.status.lock_state, LockState::Unlocked);

    let result = client.await.expect("client task");
    assert!(matches!(result, Err(AgentClientError::Protocol { .. })));
    server.await.expect("server task");
}

#[tokio::test]
async fn config_settings_round_trip_and_locked_write_rejection() {
    let dir = tempdir_user_only();
    let socket_path = dir.path().join("agent.sock");
    let config_path = dir.path().join("config.toml");
    let store_path = dir.path().join("store.db");

    let server = TestServer::start_at(&socket_path).await;
    let read_request = locket_agent::ReadConfigRequest {
        config_path: config_path.clone(),
        store_path: None,
        project_id: None,
        profile_name: None,
    };
    let response: locket_agent::AgentConfigSettings =
        invoke_method(&server.socket_path, AgentMethod::ReadConfig, &read_request)
            .await
            .expect("read config round-trip");
    assert!(!response.privacy_redact_names);
    assert_eq!(response.agent_unlock_ttl, None);

    let write_request = locket_agent::WriteConfigRequest {
        config_path,
        store_path,
        project_id: "project-main".to_owned(),
        profile_name: None,
        changes: locket_agent::WriteConfigChanges {
            privacy_redact_names: Some(true),
            ..locket_agent::WriteConfigChanges::default()
        },
    };
    let result: Result<locket_agent::WriteConfigResponse, AgentClientError> =
        invoke_method(&server.socket_path, AgentMethod::WriteConfig, &write_request).await;
    let err = result.expect_err("locked config writes require unlock");
    match err {
        AgentClientError::Rejected { code, .. } => assert_eq!(code, "UnlockRequired"),
        other => panic!("expected UnlockRequired rejection, got {other:?}"),
    }
    server.stop().await;
}

#[test]
fn resolve_socket_path_returns_a_value() {
    // Sanity check: the helper must produce a path even when no env
    // override is set. The integration tests above exercise the live
    // socket directly without depending on this helper.
    let path = resolve_socket_path();
    assert!(!path.as_os_str().is_empty());
}

async fn write_status_event(stream: &mut tokio::net::UnixStream, event: &StatusEvent) {
    let payload = serde_json::to_value(event).expect("status event JSON");
    let response = ResponseEnvelope::Success(SuccessEnvelope::new("desktop-test", payload));
    let frame = encode_frame(&response, DEFAULT_MAX_MESSAGE_SIZE).expect("status frame");
    stream.write_all(&frame).await.expect("write status frame");
    stream.flush().await.expect("flush status frame");
}

struct TestServer {
    socket_path: PathBuf,
    shutdown: Arc<Notify>,
    handle: tokio::task::JoinHandle<()>,
}

impl TestServer {
    async fn start_at(path: &Path) -> Self {
        let config = AgentSocketConfig::new(path.to_path_buf(), AGENT_VERSION.to_owned());
        let listener = bind_socket_listener(&config).expect("bind listener");
        let state = AgentSocketState::locked(AGENT_VERSION);
        let shutdown = Arc::new(Notify::new());

        let socket_path = path.to_path_buf();
        let shutdown_signal = shutdown.clone();
        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    () = shutdown_signal.notified() => return,
                    accept = listener.accept() => {
                        let Ok((stream, _addr)) = accept else { return };
                        let connection_state = state.clone();
                        tokio::spawn(async move {
                            let _outcome = handle_connection(stream, connection_state).await;
                        });
                    }
                }
            }
        });

        // Give the spawn a moment to enter accept().
        tokio::time::sleep(Duration::from_millis(20)).await;
        Self { socket_path, shutdown, handle }
    }

    async fn stop(self) {
        self.shutdown.notify_waiters();
        let _ = self.handle.await;
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

/// Returns a tempdir with mode 0o700 so `bind_socket_listener` accepts it.
fn tempdir_user_only() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    let perms = std::fs::Permissions::from_mode(0o700);
    std::fs::set_permissions(dir.path(), perms).expect("chmod tempdir");
    dir
}
