//! Unit tests for the locket-agent protocol surface.
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]

use super::{
    AgentMethod, DEFAULT_MAX_MESSAGE_SIZE, ErrorEnvelope, LockState, PROTOCOL_VERSION,
    ProtocolError, RequestEnvelope, ResponseEnvelope, STATUS_HEARTBEAT_INTERVAL_SECS, StatusEvent,
    StatusEventKind, StatusEventSequence, StatusPayload, SuccessEnvelope, UnknownMethod,
    decode_request_frame, decode_response_frame, encode_frame,
};
use serde_json::json;

#[test]
fn agent_methods_round_trip_through_wire_names() -> Result<(), UnknownMethod> {
    let methods = [
        AgentMethod::Status,
        AgentMethod::Unlock,
        AgentMethod::Lock,
        AgentMethod::RegisterClient,
        AgentMethod::RevokeClient,
        AgentMethod::RequestGrant,
        AgentMethod::RevokeGrant,
        AgentMethod::ExpireGrant,
        AgentMethod::ResolveReference,
        AgentMethod::PrepareExec,
        AgentMethod::ScanKnownValues,
        AgentMethod::Reveal,
        AgentMethod::Copy,
        AgentMethod::SubscribeStatus,
        AgentMethod::CancelSubscription,
        AgentMethod::ClientHello,
    ];

    for method in methods {
        assert_eq!(method.as_str().parse::<AgentMethod>()?, method);
    }

    Ok(())
}

#[test]
fn encodes_and_decodes_length_prefixed_request() -> Result<(), ProtocolError> {
    let request = RequestEnvelope::new("req-1", AgentMethod::Status, json!({"client_kind": "cli"}));

    let frame = encode_frame(&request, DEFAULT_MAX_MESSAGE_SIZE)?;
    assert_eq!(
        u32::from_le_bytes([frame[0], frame[1], frame[2], frame[3]]) as usize,
        frame.len() - 4
    );

    let (decoded, consumed) = decode_request_frame(&frame, DEFAULT_MAX_MESSAGE_SIZE)?;

    assert_eq!(decoded, request);
    assert_eq!(consumed, frame.len());
    Ok(())
}

#[test]
fn decodes_first_frame_and_reports_consumed_bytes() -> Result<(), ProtocolError> {
    let request = RequestEnvelope::new("req-1", AgentMethod::Status, json!({}));
    let mut bytes = encode_frame(&request, DEFAULT_MAX_MESSAGE_SIZE)?;
    bytes.extend_from_slice(b"trailing bytes");

    let (decoded, consumed) = decode_request_frame(&bytes, DEFAULT_MAX_MESSAGE_SIZE)?;

    assert_eq!(decoded, request);
    assert!(consumed < bytes.len());
    Ok(())
}

#[test]
fn rejects_incomplete_prefix_and_payload() -> Result<(), ProtocolError> {
    assert!(matches!(
        decode_request_frame(&[1, 2], DEFAULT_MAX_MESSAGE_SIZE),
        Err(ProtocolError::IncompleteFrame)
    ));

    let request = RequestEnvelope::new("req-1", AgentMethod::Status, json!({}));
    let frame = encode_frame(&request, DEFAULT_MAX_MESSAGE_SIZE)?;
    let partial = &frame[..frame.len() - 1];

    assert!(matches!(
        decode_request_frame(partial, DEFAULT_MAX_MESSAGE_SIZE),
        Err(ProtocolError::IncompleteFrame)
    ));
    Ok(())
}

#[test]
fn rejects_oversized_frames_before_json_decode() {
    let mut frame = Vec::new();
    frame.extend_from_slice(&10_u32.to_le_bytes());
    frame.extend_from_slice(b"0123456789");

    assert!(matches!(
        decode_request_frame(&frame, 9),
        Err(ProtocolError::MessageTooLarge { length: 10, maximum: 9 })
    ));
}

#[test]
fn encode_rejects_payloads_over_configured_maximum() {
    let request = RequestEnvelope::new("req-1", AgentMethod::Status, json!({"data": "x"}));

    assert!(matches!(
        encode_frame(&request, 1),
        Err(ProtocolError::MessageTooLarge { maximum: 1, .. })
    ));
}

#[test]
fn rejects_unknown_protocol_version() -> Result<(), ProtocolError> {
    let request = RequestEnvelope {
        v: 99,
        id: "req-1".to_owned(),
        kind: AgentMethod::Status.as_str().to_owned(),
        payload: json!({}),
    };
    let frame = encode_frame(&request, DEFAULT_MAX_MESSAGE_SIZE)?;

    assert!(matches!(
        decode_request_frame(&frame, DEFAULT_MAX_MESSAGE_SIZE),
        Err(ProtocolError::UnsupportedVersion { version: 99 })
    ));
    Ok(())
}

#[test]
fn rejects_unknown_request_methods() -> Result<(), ProtocolError> {
    let request = RequestEnvelope {
        v: PROTOCOL_VERSION,
        id: "req-1".to_owned(),
        kind: "Nope".to_owned(),
        payload: json!({}),
    };
    let frame = encode_frame(&request, DEFAULT_MAX_MESSAGE_SIZE)?;

    assert!(matches!(
        decode_request_frame(&frame, DEFAULT_MAX_MESSAGE_SIZE),
        Err(ProtocolError::UnknownMethod(error)) if error.method == "Nope"
    ));
    Ok(())
}

#[test]
fn constructors_emit_spec_envelope_shapes() {
    let success = SuccessEnvelope::new("req-1", json!({"ok": "payload"}));
    assert_eq!(success.v, PROTOCOL_VERSION);
    assert!(success.ok);
    assert_eq!(success.id, "req-1");

    let error = ErrorEnvelope::new("req-2", "AccessDenied", "access denied", false);
    assert_eq!(error.v, PROTOCOL_VERSION);
    assert!(!error.ok);
    assert!(!error.retryable);
    assert_eq!(error.error, "AccessDenied");
}

#[test]
fn response_envelope_deserializes_by_success_marker_shape() -> Result<(), serde_json::Error> {
    let success_value = json!({
        "v": PROTOCOL_VERSION,
        "id": "req-1",
        "ok": true,
        "payload": {"ready": true}
    });
    let error_value = json!({
        "v": PROTOCOL_VERSION,
        "id": "req-2",
        "ok": false,
        "error": "AccessDenied",
        "message": "access denied",
        "retryable": false
    });

    let success: ResponseEnvelope = serde_json::from_value(success_value)?;
    let error: ResponseEnvelope = serde_json::from_value(error_value)?;

    assert!(matches!(success, ResponseEnvelope::Success(envelope) if envelope.ok));
    assert!(matches!(error, ResponseEnvelope::Error(envelope) if !envelope.ok));
    Ok(())
}

#[test]
fn status_payload_is_metadata_only() {
    let payload = StatusPayload::locked("0.1.0");

    assert_eq!(payload.lock_state, LockState::Locked);
    assert_eq!(payload.live_grant_count, 0);
    assert!(payload.project_id.is_none());
    assert!(payload.profile_name.is_none());
}

#[test]
fn heartbeat_status_event_uses_spec_wire_shape() -> Result<(), serde_json::Error> {
    let payload = StatusPayload::locked("0.1.0");
    let event = StatusEvent::heartbeat(7, payload);
    let value = serde_json::to_value(&event)?;

    assert_eq!(STATUS_HEARTBEAT_INTERVAL_SECS, 30);
    assert_eq!(event.kind, StatusEventKind::Heartbeat);
    assert!(event.is_heartbeat());
    assert!(!event.is_state_change());
    assert_eq!(
        value,
        json!({
            "kind": "heartbeat",
            "sequence": 7,
            "lock_state": "locked",
            "project_id": null,
            "profile_name": null,
            "live_grant_count": 0,
            "agent_version": "0.1.0",
            "unlock_ttl_seconds": null
        })
    );
    Ok(())
}

#[test]
fn status_event_sequence_is_monotonic_and_marks_heartbeat_as_keepalive() {
    let mut sequence = StatusEventSequence::new();
    let first = sequence.status(StatusPayload::locked("0.1.0"));
    let heartbeat = sequence.heartbeat(StatusPayload::locked("0.1.0"));
    let third = sequence.status(StatusPayload::locked("0.1.0"));

    assert_eq!(first.sequence, 1);
    assert_eq!(heartbeat.sequence, 2);
    assert_eq!(third.sequence, 3);
    assert!(first.is_state_change());
    assert!(!heartbeat.is_state_change());
}

#[test]
fn status_event_success_envelope_decodes_for_stream_clients() -> Result<(), ProtocolError> {
    let event = StatusEvent::heartbeat(9, StatusPayload::locked("0.1.0"));
    let response = SuccessEnvelope::new("sub-1", serde_json::to_value(&event)?);
    let frame = encode_frame(&response, DEFAULT_MAX_MESSAGE_SIZE)?;

    let (decoded, consumed) = decode_response_frame(&frame, DEFAULT_MAX_MESSAGE_SIZE)?;
    assert_eq!(consumed, frame.len());
    assert!(matches!(decoded, ResponseEnvelope::Success(_)));
    let ResponseEnvelope::Success(success) = decoded else {
        return Ok(());
    };
    let decoded_event: StatusEvent = serde_json::from_value(success.payload)?;

    assert!(decoded_event.is_heartbeat());
    assert_eq!(decoded_event.sequence, 9);
    assert_eq!(decoded_event.status.lock_state, LockState::Locked);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn unlock_then_lock_round_trip() {
    use crate::envelope::{RequestEnvelope, ResponseEnvelope};
    use crate::method::AgentMethod;
    use crate::server::{AgentSocketState, dispatch};
    use serde_json::json;

    let state = AgentSocketState::locked("test-version");

    let unlock = RequestEnvelope::new(
        "req-1",
        AgentMethod::Unlock,
        json!({
            "project_id": "p-1",
            "key": [9, 9, 9, 9],
            "ttl_seconds": 30,
            "method": "Passphrase"
        }),
    );
    let response = dispatch(&unlock, &state).await;
    assert!(matches!(response, ResponseEnvelope::Success(_)));
    let populated = !state.unlock_cache.lock().await.is_empty();
    assert!(populated, "Unlock should populate the cache");

    let lock = RequestEnvelope::new("req-2", AgentMethod::Lock, json!({}));
    let response = dispatch(&lock, &state).await;
    assert!(matches!(response, ResponseEnvelope::Success(_)));
    let cleared = state.unlock_cache.lock().await.is_empty();
    assert!(cleared, "Lock must clear every cache entry");
}

#[tokio::test(flavor = "current_thread")]
async fn request_grant_returns_id_bound_to_caller_process() {
    use crate::envelope::{RequestEnvelope, ResponseEnvelope};
    use crate::method::AgentMethod;
    use crate::server::{AgentSocketState, dispatch};
    use serde_json::json;

    let state = AgentSocketState::locked("test-version");
    let request = RequestEnvelope::new(
        "req-1",
        AgentMethod::RequestGrant,
        json!({
            "project_id": "p-1",
            "profile_id": "prof-1",
            "action": "RunPolicy",
            "ttl_seconds": 30,
            "binding": {
                "pid": std::process::id(),
                "process_start_time": "0"
            }
        }),
    );
    let response = dispatch(&request, &state).await;

    let ResponseEnvelope::Success(success) = response else {
        unreachable!("expected success envelope");
    };
    let grant_id = success.payload.get("grant_id").and_then(|v| v.as_str()).unwrap_or_default();
    assert!(!grant_id.is_empty(), "grant id must not be empty");
    assert_eq!(state.grants.lock().await.len(), 1);
}

#[tokio::test(flavor = "current_thread")]
async fn revoke_grant_drops_record_and_unknown_returns_grant_required() {
    use crate::envelope::{RequestEnvelope, ResponseEnvelope};
    use crate::grant::{GrantBinding, GrantRecord};
    use crate::method::AgentMethod;
    use crate::server::{AgentSocketState, dispatch};
    use serde_json::json;

    let state = AgentSocketState::locked("test-version");
    state.grants.lock().await.insert(GrantRecord::new(
        "g-1",
        GrantBinding::new(std::process::id(), "0"),
        i128::MAX,
    ));

    let revoke =
        RequestEnvelope::new("r-1", AgentMethod::RevokeGrant, json!({ "grant_id": "g-1" }));
    let response = dispatch(&revoke, &state).await;
    assert!(matches!(response, ResponseEnvelope::Success(_)));
    assert!(state.grants.lock().await.is_empty());

    let revoke_missing =
        RequestEnvelope::new("r-2", AgentMethod::RevokeGrant, json!({ "grant_id": "missing" }));
    let response = dispatch(&revoke_missing, &state).await;
    let ResponseEnvelope::Error(error) = response else {
        unreachable!("expected error envelope for unknown grant");
    };
    assert_eq!(error.error, "GrantRequired");
}

#[tokio::test(flavor = "current_thread")]
async fn expire_grant_drops_already_expired_record() {
    use crate::envelope::{RequestEnvelope, ResponseEnvelope};
    use crate::grant::{GrantBinding, GrantRecord};
    use crate::method::AgentMethod;
    use crate::server::{AgentSocketState, dispatch};
    use serde_json::json;

    let state = AgentSocketState::locked("test-version");
    state.grants.lock().await.insert(GrantRecord::new(
        "g-2",
        GrantBinding::new(std::process::id(), "0"),
        1,
    ));

    let request =
        RequestEnvelope::new("r-1", AgentMethod::ExpireGrant, json!({ "grant_id": "g-2" }));
    let response = dispatch(&request, &state).await;
    assert!(matches!(response, ResponseEnvelope::Success(_)));
    assert!(state.grants.lock().await.is_empty());
}

#[cfg(unix)]
mod server_tests {
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    use super::*;
    use crate::{
        AgentMethod, AgentSocketConfig, AgentSocketState, ConnectionOutcome, RequestEnvelope,
        ResponseEnvelope, SocketServerError, bind_socket_listener, decode_response_frame,
        encode_frame, handle_connection, socket_permission_mode,
    };
    use serde_json::Value;
    use tempfile::tempdir;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixStream;

    /// Tempfile's `tempdir()` may inherit `0o755` from the system temp
    /// root on macOS/Linux. The agent rejects parent directories with
    /// any group/other bits set, so test setup must explicitly tighten
    /// the directory to `0o700` before binding.
    fn tighten_directory(path: &Path) -> std::io::Result<()> {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
    }

    #[tokio::test]
    async fn binds_socket_with_owner_only_permissions() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        tighten_directory(directory.path())?;
        let socket_path = directory.path().join("agent.sock");
        let config = AgentSocketConfig::new(socket_path.clone(), "0.0.0-test");
        let _listener = bind_socket_listener(&config)?;

        let Some(mode) = socket_permission_mode(&socket_path) else {
            return Err("agent socket must exist after bind".into());
        };
        assert_eq!(mode, 0o600, "agent socket must be user-only");

        let parent_mode = std::fs::metadata(directory.path())?.permissions().mode() & 0o777;
        assert_eq!(parent_mode, 0o700, "agent socket parent must be user-only");
        Ok(())
    }

    #[tokio::test]
    async fn second_listener_on_same_path_fails_with_socket_in_use()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        tighten_directory(directory.path())?;
        let socket_path = directory.path().join("agent.sock");
        let config = AgentSocketConfig::new(socket_path.clone(), "0.0.0-test");
        let _first = bind_socket_listener(&config)?;

        let second = bind_socket_listener(&config);
        let Err(SocketServerError::AgentSocketInUse { path }) = second else {
            return Err(
                format!("second bind should fail with AgentSocketInUse, got {second:?}").into()
            );
        };
        assert_eq!(path, socket_path);
        Ok(())
    }

    #[tokio::test]
    async fn status_request_round_trips_through_handler() -> Result<(), Box<dyn std::error::Error>>
    {
        let directory = tempdir()?;
        tighten_directory(directory.path())?;
        let socket_path = directory.path().join("agent.sock");
        let config = AgentSocketConfig::new(socket_path.clone(), "0.0.0-test");
        let listener = bind_socket_listener(&config)?;
        let state = AgentSocketState::locked(config.agent_version.clone());

        let server_state = state.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = match listener.accept().await {
                Ok(pair) => pair,
                Err(error) => return Err(error),
            };
            Ok(handle_connection(stream, server_state).await)
        });

        let mut client = UnixStream::connect(&socket_path).await?;
        let request = RequestEnvelope::new("req-1", AgentMethod::Status, Value::Null);
        let frame = encode_frame(&request, DEFAULT_MAX_MESSAGE_SIZE)?;
        client.write_all(&frame).await?;
        client.flush().await?;

        let mut buffer = Vec::new();
        let mut chunk = [0_u8; 1024];
        let response = loop {
            let read = client.read(&mut chunk).await?;
            buffer.extend_from_slice(&chunk[..read]);
            if let Ok((response, _)) = decode_response_frame(&buffer, DEFAULT_MAX_MESSAGE_SIZE) {
                break response;
            }
            if read == 0 {
                return Err("server closed before sending a response".into());
            }
        };
        let ResponseEnvelope::Success(success) = response else {
            return Err(format!("expected Status success, got {response:?}").into());
        };
        assert_eq!(success.id, "req-1");
        assert_eq!(success.payload["lock_state"], "locked");
        assert_eq!(success.payload["agent_version"], "0.0.0-test");

        // Closing the client lets the connection loop return and the
        // server task finish cleanly.
        drop(client);
        let outcome = server.await??;
        assert_eq!(outcome, ConnectionOutcome::PeerClosed);
        Ok(())
    }

    #[tokio::test]
    async fn unimplemented_methods_return_protocol_error_envelopes()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        tighten_directory(directory.path())?;
        let socket_path = directory.path().join("agent.sock");
        let config = AgentSocketConfig::new(socket_path.clone(), "0.0.0-test");
        let listener = bind_socket_listener(&config)?;
        let state = AgentSocketState::locked(config.agent_version.clone());

        let server_state = state.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = match listener.accept().await {
                Ok(pair) => pair,
                Err(error) => return Err(error),
            };
            Ok(handle_connection(stream, server_state).await)
        });

        let mut client = UnixStream::connect(&socket_path).await?;
        // `Unlock` is one of the methods that still has no dispatch
        // arm, so it exercises the catch-all `ProtocolError` branch.
        let request = RequestEnvelope::new("req-2", AgentMethod::Unlock, Value::Null);
        let frame = encode_frame(&request, DEFAULT_MAX_MESSAGE_SIZE)?;
        client.write_all(&frame).await?;
        client.flush().await?;

        let mut buffer = Vec::new();
        let mut chunk = [0_u8; 1024];
        let response = loop {
            let read = client.read(&mut chunk).await?;
            buffer.extend_from_slice(&chunk[..read]);
            if let Ok((response, _)) = decode_response_frame(&buffer, DEFAULT_MAX_MESSAGE_SIZE) {
                break response;
            }
            if read == 0 {
                return Err("server closed before sending a response".into());
            }
        };
        let ResponseEnvelope::Error(error) = response else {
            return Err(format!("expected ProtocolError envelope, got {response:?}").into());
        };
        assert_eq!(error.id, "req-2");
        assert_eq!(error.error, "ProtocolError");
        assert!(error.message.contains("Unlock"));
        assert!(!error.retryable);

        drop(client);
        server.await??;
        Ok(())
    }

    #[tokio::test]
    async fn bind_refuses_when_parent_directory_has_group_or_other_bits()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        // Pre-existing parent with `0o755` — explicitly wider than the
        // agent allows. The bind must refuse rather than silently
        // tighten another principal's directory.
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o755))?;
        let socket_path = directory.path().join("agent.sock");
        let config = AgentSocketConfig::new(socket_path.clone(), "0.0.0-test");

        let result = bind_socket_listener(&config);
        let Err(SocketServerError::SocketPathTooWide { path, mode, expected }) = result else {
            return Err(format!("expected SocketPathTooWide, got {result:?}").into());
        };
        assert_eq!(path, directory.path());
        assert_eq!(mode, 0o755);
        assert_eq!(expected, 0o700);
        // Nothing should have been bound.
        assert!(!socket_path.exists(), "socket must not be created when parent is too wide");
        Ok(())
    }

    #[tokio::test]
    async fn bind_succeeds_when_parent_already_owner_only() -> Result<(), Box<dyn std::error::Error>>
    {
        let directory = tempdir()?;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
        let socket_path = directory.path().join("agent.sock");
        let config = AgentSocketConfig::new(socket_path.clone(), "0.0.0-test");
        let _listener = bind_socket_listener(&config)?;

        let parent_mode = std::fs::metadata(directory.path())?.permissions().mode() & 0o777;
        assert_eq!(parent_mode, 0o700);
        assert_eq!(socket_permission_mode(&socket_path), Some(0o600));
        Ok(())
    }

    #[tokio::test]
    async fn bind_creates_missing_parent_with_owner_only_permissions()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
        let nested = directory.path().join("agent");
        let socket_path = nested.join("agent.sock");
        let config = AgentSocketConfig::new(socket_path, "0.0.0-test");

        let _listener = bind_socket_listener(&config)?;
        let nested_mode = std::fs::metadata(&nested)?.permissions().mode() & 0o777;
        assert_eq!(nested_mode, 0o700, "freshly created parent must be owner-only");
        Ok(())
    }

    #[tokio::test]
    async fn handle_connection_rejects_cross_user_peer() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        tighten_directory(directory.path())?;
        let socket_path = directory.path().join("agent.sock");
        let config = AgentSocketConfig::new(socket_path.clone(), "0.0.0-test");
        let listener = bind_socket_listener(&config)?;
        // Spoof a daemon UID that cannot match the live test process
        // UID so the live UnixStream::peer_cred() lookup yields a
        // mismatch. This drives the rejection path without needing
        // sudo or a second user account.
        let phantom_daemon_uid =
            crate::peer_cred::current_process_uid().wrapping_add(1).wrapping_add(0xDEAD);
        let state = AgentSocketState::with_daemon_uid("0.0.0-test", phantom_daemon_uid);

        let server_state = state.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = match listener.accept().await {
                Ok(pair) => pair,
                Err(error) => return Err(error),
            };
            Ok(handle_connection(stream, server_state).await)
        });

        let mut client = UnixStream::connect(&socket_path).await?;
        let request = RequestEnvelope::new("req-1", AgentMethod::Status, Value::Null);
        let frame = encode_frame(&request, DEFAULT_MAX_MESSAGE_SIZE)?;
        // The server should drop the stream before reading any frame
        // — write may succeed into the kernel buffer, but the read
        // attempt below must observe EOF without ever producing a
        // response envelope.
        let _ = client.write_all(&frame).await;
        let mut buffer = Vec::new();
        let mut chunk = [0_u8; 1024];
        loop {
            let read = client.read(&mut chunk).await?;
            if read == 0 {
                break;
            }
            buffer.extend_from_slice(&chunk[..read]);
        }
        assert!(
            buffer.is_empty(),
            "rejected peer must not receive any response bytes, got {buffer:?}"
        );

        let outcome = server.await??;
        assert!(
            matches!(
                &outcome,
                ConnectionOutcome::Rejected {
                    reason: SocketServerError::PeerCredentialDenied { .. },
                }
            ),
            "expected ConnectionOutcome::Rejected with PeerCredentialDenied, got {outcome:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn handle_connection_accepts_same_uid_peer() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        tighten_directory(directory.path())?;
        let socket_path = directory.path().join("agent.sock");
        let config = AgentSocketConfig::new(socket_path.clone(), "0.0.0-test");
        let listener = bind_socket_listener(&config)?;
        // The default constructor captures the live process UID, so
        // a same-process UnixStream::connect() satisfies the peer
        // check.
        let state = AgentSocketState::locked(config.agent_version.clone());

        let server_state = state.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = match listener.accept().await {
                Ok(pair) => pair,
                Err(error) => return Err(error),
            };
            Ok(handle_connection(stream, server_state).await)
        });

        let mut client = UnixStream::connect(&socket_path).await?;
        let request = RequestEnvelope::new("req-1", AgentMethod::Status, Value::Null);
        let frame = encode_frame(&request, DEFAULT_MAX_MESSAGE_SIZE)?;
        client.write_all(&frame).await?;
        client.flush().await?;

        let mut buffer = Vec::new();
        let mut chunk = [0_u8; 1024];
        let response = loop {
            let read = client.read(&mut chunk).await?;
            buffer.extend_from_slice(&chunk[..read]);
            if let Ok((response, _)) = decode_response_frame(&buffer, DEFAULT_MAX_MESSAGE_SIZE) {
                break response;
            }
            if read == 0 {
                return Err("server closed before sending a response".into());
            }
        };
        let ResponseEnvelope::Success(success) = response else {
            return Err(format!("expected Status success, got {response:?}").into());
        };
        assert_eq!(success.id, "req-1");

        drop(client);
        let outcome = server.await??;
        assert_eq!(outcome, ConnectionOutcome::PeerClosed);
        Ok(())
    }
}
