//! Unit tests for the locket-agent protocol surface.

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
            "agent_version": "0.1.0"
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
