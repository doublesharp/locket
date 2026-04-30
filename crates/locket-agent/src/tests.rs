//! Unit tests for the locket-agent protocol surface.
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::panic)]

use super::{
    AgentMethod, DEFAULT_MAX_MESSAGE_SIZE, ErrorEnvelope, ListSecretsResponse, LockState,
    PROTOCOL_VERSION, ProtocolError, RequestEnvelope, ResponseEnvelope,
    STATUS_HEARTBEAT_INTERVAL_SECS, StatusEvent, StatusEventKind, StatusEventSequence,
    StatusPayload, SuccessEnvelope, UnknownMethod, decode_request_frame, decode_response_frame,
    encode_frame,
};
use serde_json::json;

fn test_grant_record(grant_id: &str, expires_at_unix_nanos: i128) -> crate::grant::GrantRecord {
    crate::grant::GrantRecord::new(crate::grant::GrantRecordFields {
        grant_id: grant_id.to_owned(),
        project_id: "p-1".to_owned(),
        profile_id: "prof-1".to_owned(),
        action: crate::grant::GrantAction::RunPolicy,
        binding: crate::grant::GrantBinding::new(std::process::id(), "0"),
        issued_at_unix_nanos: 0,
        ttl_seconds: 30,
        expires_at_unix_nanos,
    })
}

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
        AgentMethod::ListRuntimeSessions,
        AgentMethod::ListPolicies,
        AgentMethod::Reveal,
        AgentMethod::Copy,
        AgentMethod::SubscribeStatus,
        AgentMethod::CancelSubscription,
        AgentMethod::ClientHello,
        AgentMethod::ListSecrets,
    ];

    for method in methods {
        assert_eq!(method.as_str().parse::<AgentMethod>()?, method);
    }

    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn list_secrets_returns_metadata_ordered_by_source_precedence()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::envelope::{RequestEnvelope, ResponseEnvelope};
    use crate::method::AgentMethod;
    use crate::server::{AgentSocketState, dispatch};
    use locket_store::Store;
    use serde_json::json;

    let directory = tempfile::tempdir()?;
    let store_path = directory.path().join("store.db");
    let mut store = Store::open(&store_path)?;
    store.initialize_schema()?;
    store.connection().execute(
        "INSERT INTO projects(id, name, created_at) VALUES ('lk_proj_test', 'test', 1)",
        [],
    )?;
    store.connection().execute(
        "INSERT INTO profiles(id, project_id, name, dangerous, created_at)
         VALUES ('lk_prof_test', 'lk_proj_test', 'default', 0, 1)",
        [],
    )?;
    for (id, name, source, required, version) in [
        ("lk_sec_team", "DATABASE_URL", "team-managed", true, 1),
        ("lk_sec_machine", "DATABASE_URL", "machine-local", false, 3),
        ("lk_sec_user", "DATABASE_URL", "user-local", false, 2),
        ("lk_sec_api", "API_TOKEN", "user-local", true, 1),
    ] {
        store.connection().execute(
            "INSERT INTO secrets(
               id, project_id, profile_id, name, source, origin, required,
               current_version, state, created_at, updated_at, last_rotated_at, deleted_at
             )
             VALUES (?1, 'lk_proj_test', 'lk_prof_test', ?2, ?3, 'manual', ?4, ?5, 'active', 100, 200, NULL, NULL)",
            (id, name, source, required, version),
        )?;
    }

    let state = AgentSocketState::locked("test-version");
    let request = RequestEnvelope::new(
        "secrets",
        AgentMethod::ListSecrets,
        json!({
            "store_path": store_path,
            "project_id": "lk_proj_test",
            "profile_id": "lk_prof_test",
            "redact_names": false
        }),
    );
    let response = dispatch(&request, &state).await;
    let ResponseEnvelope::Success(success) = response else {
        panic!("ListSecrets should succeed");
    };
    let payload: ListSecretsResponse = serde_json::from_value(success.payload)?;

    let ordered = payload
        .rows
        .iter()
        .map(|row| (row.name.as_str(), row.source.as_str(), row.source_precedence))
        .collect::<Vec<_>>();
    assert_eq!(
        ordered,
        vec![
            ("API_TOKEN", "user-local", 2),
            ("DATABASE_URL", "machine-local", 3),
            ("DATABASE_URL", "user-local", 2),
            ("DATABASE_URL", "team-managed", 1),
        ]
    );
    assert_eq!(payload.rows[0].required, true);
    assert_eq!(payload.rows[1].current_version, 3);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn list_secrets_applies_privacy_aliases_and_remains_locked_safe()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::envelope::{RequestEnvelope, ResponseEnvelope};
    use crate::method::AgentMethod;
    use crate::server::{AgentSocketState, dispatch};
    use locket_store::Store;
    use serde_json::json;

    let directory = tempfile::tempdir()?;
    let store_path = directory.path().join("store.db");
    let mut store = Store::open(&store_path)?;
    store.initialize_schema()?;
    store.connection().execute(
        "INSERT INTO projects(id, name, created_at) VALUES ('lk_proj_test', 'test', 1)",
        [],
    )?;
    store.connection().execute(
        "INSERT INTO profiles(id, project_id, name, dangerous, created_at)
         VALUES ('lk_prof_test', 'lk_proj_test', 'default', 0, 1)",
        [],
    )?;
    store.connection().execute(
        "INSERT INTO secrets(
           id, project_id, profile_id, name, source, origin, required,
           current_version, state, created_at, updated_at, last_rotated_at, deleted_at
         )
         VALUES ('lk_sec_test', 'lk_proj_test', 'lk_prof_test', 'DATABASE_URL', 'user-local',
                 'manual', 1, 1, 'active', 100, 200, NULL, NULL)",
        [],
    )?;

    let state = AgentSocketState::locked("test-version");
    let request = RequestEnvelope::new(
        "secrets",
        AgentMethod::ListSecrets,
        json!({
            "store_path": store_path,
            "project_id": "lk_proj_test",
            "profile_id": "lk_prof_test",
            "redact_names": true
        }),
    );
    let response = dispatch(&request, &state).await;
    let ResponseEnvelope::Success(success) = response else {
        panic!("ListSecrets should succeed while locked");
    };
    let payload: ListSecretsResponse = serde_json::from_value(success.payload)?;

    assert_eq!(payload.rows.len(), 1);
    assert_ne!(payload.rows[0].name, "DATABASE_URL");
    assert_ne!(payload.rows[0].profile_id, "lk_prof_test");
    assert!(payload.rows[0].name.starts_with("secret-"));
    assert!(payload.rows[0].profile_id.starts_with("profile-"));
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
    state.grants.lock().await.insert(test_grant_record("g-live", i128::MAX));

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
    assert!(state.grants.lock().await.is_empty(), "Lock must clear live grants");
}

#[tokio::test(flavor = "current_thread")]
async fn unlock_and_lock_publish_status_changes() {
    use crate::envelope::{RequestEnvelope, ResponseEnvelope};
    use crate::method::AgentMethod;
    use crate::server::{AgentSocketState, dispatch};
    use serde_json::json;

    let state = AgentSocketState::locked("test-version");
    let mut subscriber = state.status_hub.subscribe().await;
    let initial = subscriber.next_event().await.expect("initial status event");
    assert_eq!(initial.status.lock_state, LockState::Locked);

    let unlock = RequestEnvelope::new(
        "req-1",
        AgentMethod::Unlock,
        json!({
            "project_id": "p-1",
            "key": [1, 2, 3, 4],
            "ttl_seconds": 30,
            "method": "Passphrase"
        }),
    );
    assert!(matches!(dispatch(&unlock, &state).await, ResponseEnvelope::Success(_)));

    let unlocked = subscriber.next_event().await.expect("unlock status event");
    assert!(unlocked.is_state_change());
    assert_eq!(unlocked.status.lock_state, LockState::Unlocked);
    assert_eq!(unlocked.status.unlock_ttl_seconds, Some(30));

    let lock = RequestEnvelope::new("req-2", AgentMethod::Lock, json!({}));
    assert!(matches!(dispatch(&lock, &state).await, ResponseEnvelope::Success(_)));

    let locked = subscriber.next_event().await.expect("lock status event");
    assert!(locked.is_state_change());
    assert_eq!(locked.status.lock_state, LockState::Locked);
    assert_eq!(locked.status.unlock_ttl_seconds, None);
}

#[tokio::test(flavor = "current_thread")]
async fn malformed_unlock_payload_returns_protocol_error() {
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
            "ttl_seconds": 30,
            "method": "Passphrase"
        }),
    );

    let ResponseEnvelope::Error(error) = dispatch(&unlock, &state).await else {
        unreachable!("malformed Unlock payload must fail");
    };
    assert_eq!(error.error, "ProtocolError");
    assert!(state.unlock_cache.lock().await.is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn list_runtime_sessions_filters_profile_and_applies_aliases() {
    use crate::RuntimeSessionSnapshot;
    use crate::envelope::{RequestEnvelope, ResponseEnvelope};
    use crate::method::AgentMethod;
    use crate::server::{AgentSocketState, dispatch};
    use serde_json::json;

    let state = AgentSocketState::locked("test-version");
    state
        .set_runtime_sessions_for_tests(vec![
            RuntimeSessionSnapshot {
                session_id: "sess-old".to_owned(),
                project_id: "project-main".to_owned(),
                profile_id: "profile-prod".to_owned(),
                policy_name: Some("deploy-prod".to_owned()),
                process_id: 101,
                process_start_time: 1_700_000_000,
                started_at: 1_700_000_100,
                ended_at: Some(1_700_000_500),
                exit_status: Some(0),
                secret_name_count: 2,
                spawn_audit_sequence: Some(7),
                completion_audit_sequence: Some(8),
            },
            RuntimeSessionSnapshot {
                session_id: "sess-new".to_owned(),
                project_id: "project-main".to_owned(),
                profile_id: "profile-prod".to_owned(),
                policy_name: Some("deploy-prod".to_owned()),
                process_id: 202,
                process_start_time: 1_700_001_000,
                started_at: 1_700_001_100,
                ended_at: None,
                exit_status: None,
                secret_name_count: 1,
                spawn_audit_sequence: Some(9),
                completion_audit_sequence: None,
            },
            RuntimeSessionSnapshot {
                session_id: "sess-other-profile".to_owned(),
                project_id: "project-main".to_owned(),
                profile_id: "profile-dev".to_owned(),
                policy_name: Some("deploy-prod".to_owned()),
                process_id: 303,
                process_start_time: 1_700_002_000,
                started_at: 1_700_002_100,
                ended_at: None,
                exit_status: None,
                secret_name_count: 3,
                spawn_audit_sequence: Some(10),
                completion_audit_sequence: None,
            },
        ])
        .await;

    let request = RequestEnvelope::new(
        "req-runtime",
        AgentMethod::ListRuntimeSessions,
        json!({
            "project_id": "project-main",
            "profile_id": "profile-prod",
            "privacy_redact_names": true,
        }),
    );
    let ResponseEnvelope::Success(success) = dispatch(&request, &state).await else {
        unreachable!("valid ListRuntimeSessions payload must succeed");
    };
    let rendered = success.payload().to_string();
    assert!(!rendered.contains("profile-prod"));
    assert!(!rendered.contains("deploy-prod"));
    assert!(!rendered.contains("sess-other-profile"));

    let rows = success.payload().get("rows").and_then(serde_json::Value::as_array).unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0]["session_id"], "sess-new");
    assert_eq!(rows[0]["state"], "running");
    assert_eq!(rows[0]["secret_name_count"], 1);
    assert!(rows[0]["profile"].as_str().unwrap().starts_with("profile-"));
    assert!(rows[0]["policy"].as_str().unwrap().starts_with("policy-"));
    assert_eq!(rows[1]["session_id"], "sess-old");
    assert_eq!(rows[1]["state"], "completed");
}

#[tokio::test(flavor = "current_thread")]
async fn malformed_list_runtime_sessions_payload_returns_protocol_error() {
    use crate::envelope::{RequestEnvelope, ResponseEnvelope};
    use crate::method::AgentMethod;
    use crate::server::{AgentSocketState, dispatch};
    use serde_json::json;

    let state = AgentSocketState::locked("test-version");
    let request = RequestEnvelope::new(
        "req-runtime",
        AgentMethod::ListRuntimeSessions,
        json!({
            "project_id": "project-main",
        }),
    );

    let ResponseEnvelope::Error(error) = dispatch(&request, &state).await else {
        unreachable!("malformed ListRuntimeSessions payload must fail");
    };
    assert_eq!(error.error, "ProtocolError");
    assert!(state.runtime_sessions.lock().await.is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn list_policies_filters_project_and_applies_aliases() {
    use crate::CommandPolicySnapshot;
    use crate::envelope::{RequestEnvelope, ResponseEnvelope};
    use crate::method::AgentMethod;
    use crate::server::{AgentSocketState, dispatch};
    use serde_json::json;

    let state = AgentSocketState::locked("test-version");
    state
        .set_command_policies_for_tests(vec![
            CommandPolicySnapshot {
                project_id: "project-main".to_owned(),
                name: "deploy-prod".to_owned(),
                command_kind: "argv".to_owned(),
                command_preview: "pnpm deploy".to_owned(),
                required_secrets: vec!["DATABASE_URL".to_owned()],
                optional_secrets: vec!["OPENAI_API_KEY".to_owned()],
                allowed_secrets: vec!["DATABASE_URL".to_owned(), "OPENAI_API_KEY".to_owned()],
                confirm: true,
                require_user_verification: true,
                allow_remote_docker: false,
                ttl_seconds: 300,
                env_mode: "minimal".to_owned(),
                override_mode: "locket".to_owned(),
                updated_at_unix_nanos: 1_700_000_000,
            },
            CommandPolicySnapshot {
                project_id: "project-main".to_owned(),
                name: "build".to_owned(),
                command_kind: "shell".to_owned(),
                command_preview: "pnpm build".to_owned(),
                required_secrets: Vec::new(),
                optional_secrets: Vec::new(),
                allowed_secrets: Vec::new(),
                confirm: false,
                require_user_verification: false,
                allow_remote_docker: false,
                ttl_seconds: 900,
                env_mode: "strict".to_owned(),
                override_mode: "preserve".to_owned(),
                updated_at_unix_nanos: 1_700_000_100,
            },
            CommandPolicySnapshot {
                project_id: "project-other".to_owned(),
                name: "other-project-policy".to_owned(),
                command_kind: "argv".to_owned(),
                command_preview: "ignored".to_owned(),
                required_secrets: vec!["OTHER_SECRET".to_owned()],
                optional_secrets: Vec::new(),
                allowed_secrets: vec!["OTHER_SECRET".to_owned()],
                confirm: false,
                require_user_verification: false,
                allow_remote_docker: false,
                ttl_seconds: 900,
                env_mode: "minimal".to_owned(),
                override_mode: "locket".to_owned(),
                updated_at_unix_nanos: 1_700_000_200,
            },
        ])
        .await;

    let request = RequestEnvelope::new(
        "req-policies",
        AgentMethod::ListPolicies,
        json!({
            "project_id": "project-main",
            "privacy_redact_names": true,
        }),
    );
    let ResponseEnvelope::Success(success) = dispatch(&request, &state).await else {
        unreachable!("valid ListPolicies payload must succeed");
    };
    let rendered = success.payload().to_string();
    assert!(!rendered.contains("deploy-prod"));
    assert!(!rendered.contains("DATABASE_URL"));
    assert!(!rendered.contains("OPENAI_API_KEY"));
    assert!(!rendered.contains("other-project-policy"));

    let rows = success.payload().get("rows").and_then(serde_json::Value::as_array).unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0]["command_kind"], "shell");
    assert!(rows[0]["name"].as_str().unwrap().starts_with("policy-"));
    assert_eq!(rows[1]["command_kind"], "argv");
    assert_eq!(rows[1]["ttl_seconds"], 300);
    assert_eq!(rows[1]["confirm"], true);
    assert!(rows[1]["required_secrets"][0].as_str().unwrap().starts_with("secret-"));
}

#[tokio::test(flavor = "current_thread")]
async fn malformed_list_policies_payload_returns_protocol_error() {
    use crate::envelope::{RequestEnvelope, ResponseEnvelope};
    use crate::method::AgentMethod;
    use crate::server::{AgentSocketState, dispatch};
    use serde_json::json;

    let state = AgentSocketState::locked("test-version");
    let request = RequestEnvelope::new(
        "req-policies",
        AgentMethod::ListPolicies,
        json!({
            "project_id": "project-main",
        }),
    );

    let ResponseEnvelope::Error(error) = dispatch(&request, &state).await else {
        unreachable!("malformed ListPolicies payload must fail");
    };
    assert_eq!(error.error, "ProtocolError");
    assert!(state.command_policies.lock().await.is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn status_lazily_evicts_expired_unlock_entries() {
    use crate::server::AgentSocketState;
    use crate::unlock_cache::{UnlockEntry, UnlockMethod};
    use std::time::Duration;

    let state = AgentSocketState::locked("test-version");
    state.unlock_cache.lock().await.insert(
        "p-1".to_owned(),
        UnlockEntry::new(b"k".to_vec(), 0, Duration::from_secs(1), UnlockMethod::Passphrase),
    );

    let snapshot = state.status_snapshot(2_000_000_000).await;

    assert_eq!(snapshot.lock_state, LockState::Locked);
    assert_eq!(snapshot.unlock_ttl_seconds, None);
    assert!(state.unlock_cache.lock().await.is_empty());
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
    let record = {
        let grants = state.grants.lock().await;
        assert_eq!(grants.len(), 1);
        grants.get(grant_id).cloned().unwrap_or_else(|| unreachable!("issued grant is stored"))
    };
    assert_eq!(record.project_id, "p-1");
    assert_eq!(record.profile_id, "prof-1");
    assert_eq!(record.action, crate::grant::GrantAction::RunPolicy);
    assert_eq!(record.ttl_seconds, 30);
    assert_eq!(record.binding.process_start_time, "0");
}

#[tokio::test(flavor = "current_thread")]
async fn revoke_grant_drops_record_and_unknown_returns_grant_required() {
    use crate::envelope::{RequestEnvelope, ResponseEnvelope};
    use crate::method::AgentMethod;
    use crate::server::{AgentSocketState, dispatch};
    use serde_json::json;

    let state = AgentSocketState::locked("test-version");
    state.grants.lock().await.insert(test_grant_record("g-1", i128::MAX));

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
    use crate::method::AgentMethod;
    use crate::server::{AgentSocketState, dispatch};
    use serde_json::json;

    let state = AgentSocketState::locked("test-version");
    state.grants.lock().await.insert(test_grant_record("g-2", 1));

    let request =
        RequestEnvelope::new("r-1", AgentMethod::ExpireGrant, json!({ "grant_id": "g-2" }));
    let response = dispatch(&request, &state).await;
    assert!(matches!(response, ResponseEnvelope::Success(_)));
    assert!(state.grants.lock().await.is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn expire_grant_leaves_live_grant_intact() {
    use crate::envelope::{RequestEnvelope, ResponseEnvelope};
    use crate::method::AgentMethod;
    use crate::server::{AgentSocketState, dispatch};
    use serde_json::json;

    let state = AgentSocketState::locked("test-version");
    state.grants.lock().await.insert(test_grant_record("g-live", i128::MAX));

    let request =
        RequestEnvelope::new("r-1", AgentMethod::ExpireGrant, json!({ "grant_id": "g-live" }));
    let response = dispatch(&request, &state).await;

    let ResponseEnvelope::Error(error) = response else {
        unreachable!("ExpireGrant on a live grant must return an error envelope");
    };
    assert_eq!(error.error, "ProtocolError");
    assert!(
        state.grants.lock().await.get("g-live").is_some(),
        "live grant must not be revoked by ExpireGrant"
    );
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
        // `RegisterClient` is one of the methods that still has no dispatch
        // arm, so it exercises the catch-all `ProtocolError` branch.
        let request = RequestEnvelope::new("req-2", AgentMethod::RegisterClient, Value::Null);
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
        assert!(error.message.contains("RegisterClient"));
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
        let state = AgentSocketState::with_daemon_uid("0.0.0-test", 1000).with_test_peer_uid(1001);

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
    async fn handle_connection_accepts_spoofed_same_user_peer()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        tighten_directory(directory.path())?;
        let socket_path = directory.path().join("agent.sock");
        let config = AgentSocketConfig::new(socket_path.clone(), "0.0.0-test");
        let listener = bind_socket_listener(&config)?;
        let state = AgentSocketState::with_daemon_uid(config.agent_version.clone(), 1000)
            .with_test_peer_uid(1000);

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

    /// Reads a single response frame from the client socket, growing
    /// `buffer` as needed. Returns `None` when the server closes the
    /// connection without sending a frame.
    async fn read_one_response_frame(
        client: &mut UnixStream,
        buffer: &mut Vec<u8>,
    ) -> Result<Option<ResponseEnvelope>, Box<dyn std::error::Error>> {
        loop {
            if let Ok((response, consumed)) =
                decode_response_frame(buffer, DEFAULT_MAX_MESSAGE_SIZE)
            {
                buffer.drain(..consumed);
                return Ok(Some(response));
            }
            let mut chunk = [0_u8; 256];
            let read = client.read(&mut chunk).await?;
            if read == 0 {
                return Ok(None);
            }
            buffer.extend_from_slice(&chunk[..read]);
        }
    }

    #[tokio::test]
    async fn subscribe_status_writes_initial_event_then_heartbeat_over_socket()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::time::Duration;

        let directory = tempdir()?;
        tighten_directory(directory.path())?;
        let socket_path = directory.path().join("agent.sock");
        let config = AgentSocketConfig::new(socket_path.clone(), "test-version");
        let listener = bind_socket_listener(&config)?;
        let state = AgentSocketState::locked(config.agent_version.clone());
        state.set_test_heartbeat_interval(Duration::from_millis(20)).await;

        let server_state = state.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = match listener.accept().await {
                Ok(pair) => pair,
                Err(error) => return Err(error),
            };
            Ok(handle_connection(stream, server_state).await)
        });

        let mut client = UnixStream::connect(&socket_path).await?;
        let request =
            RequestEnvelope::new("sub-1", AgentMethod::SubscribeStatus, serde_json::json!({}));
        let frame = encode_frame(&request, DEFAULT_MAX_MESSAGE_SIZE)?;
        client.write_all(&frame).await?;
        client.flush().await?;

        let mut buffer = Vec::new();
        let Some(initial) = read_one_response_frame(&mut client, &mut buffer).await? else {
            return Err("server closed before sending the initial status event".into());
        };
        let ResponseEnvelope::Success(initial_success) = initial else {
            return Err(format!("expected initial Success, got {initial:?}").into());
        };
        assert_eq!(initial_success.id, "sub-1");
        let initial_kind =
            initial_success.payload().get("kind").and_then(Value::as_str).unwrap_or_default();
        assert_eq!(initial_kind, "status");

        let Some(heartbeat) = read_one_response_frame(&mut client, &mut buffer).await? else {
            return Err("server closed before sending a heartbeat".into());
        };
        let ResponseEnvelope::Success(heartbeat_success) = heartbeat else {
            return Err(format!("expected heartbeat Success, got {heartbeat:?}").into());
        };
        let heartbeat_kind =
            heartbeat_success.payload().get("kind").and_then(Value::as_str).unwrap_or_default();
        assert_eq!(heartbeat_kind, "heartbeat");

        drop(client);
        let _ = server.await?;
        Ok(())
    }

    #[tokio::test]
    async fn cancel_subscription_closes_stream_cleanly() -> Result<(), Box<dyn std::error::Error>> {
        use std::time::Duration;

        let directory = tempdir()?;
        tighten_directory(directory.path())?;
        let socket_path = directory.path().join("agent.sock");
        let config = AgentSocketConfig::new(socket_path.clone(), "v");
        let listener = bind_socket_listener(&config)?;
        let state = AgentSocketState::locked(config.agent_version.clone());
        // Long heartbeat so the test does not race a heartbeat against
        // the cancel response — we want the cancel itself to drive the
        // close.
        state.set_test_heartbeat_interval(Duration::from_secs(60)).await;

        let server_state = state.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = match listener.accept().await {
                Ok(pair) => pair,
                Err(error) => return Err(error),
            };
            Ok(handle_connection(stream, server_state).await)
        });

        let mut client = UnixStream::connect(&socket_path).await?;
        let subscribe = encode_frame(
            &RequestEnvelope::new("s-1", AgentMethod::SubscribeStatus, serde_json::json!({})),
            DEFAULT_MAX_MESSAGE_SIZE,
        )?;
        client.write_all(&subscribe).await?;
        client.flush().await?;

        let mut buffer = Vec::new();
        let Some(_initial) = read_one_response_frame(&mut client, &mut buffer).await? else {
            return Err("server closed before sending the initial status event".into());
        };

        let cancel = encode_frame(
            &RequestEnvelope::new("s-1", AgentMethod::CancelSubscription, serde_json::json!({})),
            DEFAULT_MAX_MESSAGE_SIZE,
        )?;
        client.write_all(&cancel).await?;
        client.flush().await?;
        drop(client);

        let outcome = server.await??;
        assert_eq!(outcome, ConnectionOutcome::PeerClosed);
        Ok(())
    }
}
