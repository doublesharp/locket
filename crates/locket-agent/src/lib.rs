//! Local agent and protocol types for Locket.

use std::str::FromStr;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

/// Maximum v1 protocol message size in bytes.
pub const DEFAULT_MAX_MESSAGE_SIZE: usize = 1024 * 1024;

/// Agent protocol version supported by this crate.
pub const PROTOCOL_VERSION: u16 = 1;

/// V1 agent RPC method names.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentMethod {
    /// Return metadata-only agent status.
    Status,
    /// Unlock local key material.
    Unlock,
    /// Clear local key material and live grants.
    Lock,
    /// Register an automation client.
    RegisterClient,
    /// Revoke an automation client.
    RevokeClient,
    /// Request a live TTL grant.
    RequestGrant,
    /// Revoke a live TTL grant.
    RevokeGrant,
    /// Lazily record an expired grant.
    ExpireGrant,
    /// Resolve an authorized `lk://` reference.
    ResolveReference,
    /// Prepare a command policy for execution.
    PrepareExec,
    /// Provide known-value scan matching.
    ScanKnownValues,
    /// Reveal one secret value through a gated path.
    Reveal,
    /// Copy one secret value through a gated path.
    Copy,
    /// Subscribe to metadata-only status events.
    SubscribeStatus,
    /// Cancel a status subscription.
    CancelSubscription,
    /// Automation client challenge handshake.
    ClientHello,
}

impl AgentMethod {
    /// Returns the exact v1 wire method name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Status => "Status",
            Self::Unlock => "Unlock",
            Self::Lock => "Lock",
            Self::RegisterClient => "RegisterClient",
            Self::RevokeClient => "RevokeClient",
            Self::RequestGrant => "RequestGrant",
            Self::RevokeGrant => "RevokeGrant",
            Self::ExpireGrant => "ExpireGrant",
            Self::ResolveReference => "ResolveReference",
            Self::PrepareExec => "PrepareExec",
            Self::ScanKnownValues => "ScanKnownValues",
            Self::Reveal => "Reveal",
            Self::Copy => "Copy",
            Self::SubscribeStatus => "SubscribeStatus",
            Self::CancelSubscription => "CancelSubscription",
            Self::ClientHello => "ClientHello",
        }
    }
}

impl FromStr for AgentMethod {
    type Err = UnknownMethod;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "Status" => Ok(Self::Status),
            "Unlock" => Ok(Self::Unlock),
            "Lock" => Ok(Self::Lock),
            "RegisterClient" => Ok(Self::RegisterClient),
            "RevokeClient" => Ok(Self::RevokeClient),
            "RequestGrant" => Ok(Self::RequestGrant),
            "RevokeGrant" => Ok(Self::RevokeGrant),
            "ExpireGrant" => Ok(Self::ExpireGrant),
            "ResolveReference" => Ok(Self::ResolveReference),
            "PrepareExec" => Ok(Self::PrepareExec),
            "ScanKnownValues" => Ok(Self::ScanKnownValues),
            "Reveal" => Ok(Self::Reveal),
            "Copy" => Ok(Self::Copy),
            "SubscribeStatus" => Ok(Self::SubscribeStatus),
            "CancelSubscription" => Ok(Self::CancelSubscription),
            "ClientHello" => Ok(Self::ClientHello),
            other => Err(UnknownMethod { method: other.to_owned() }),
        }
    }
}

/// Unknown v1 agent method name.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("unknown agent method: {method}")]
pub struct UnknownMethod {
    /// Method string found in the envelope.
    pub method: String,
}

/// JSON request envelope sent after the v1 length prefix.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RequestEnvelope {
    /// Protocol version.
    pub v: u16,
    /// Client-generated request id.
    pub id: String,
    /// Method name.
    pub kind: String,
    /// Method payload.
    pub payload: Value,
}

impl RequestEnvelope {
    /// Creates a v1 request envelope for a typed method.
    #[must_use]
    pub fn new(id: impl Into<String>, method: AgentMethod, payload: Value) -> Self {
        Self { v: PROTOCOL_VERSION, id: id.into(), kind: method.as_str().to_owned(), payload }
    }

    /// Returns the validated typed method.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::UnknownMethod`] when `kind` is not a supported
    /// v1 method name.
    pub fn method(&self) -> Result<AgentMethod, ProtocolError> {
        self.kind.parse().map_err(ProtocolError::UnknownMethod)
    }
}

/// JSON response envelope sent after the v1 length prefix.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(untagged)]
pub enum ResponseEnvelope {
    /// Successful response.
    Success(SuccessEnvelope),
    /// Error response.
    Error(ErrorEnvelope),
}

/// Successful response envelope.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SuccessEnvelope {
    /// Protocol version.
    pub v: u16,
    /// Request id being answered.
    pub id: String,
    /// Success marker.
    pub ok: bool,
    /// Response payload.
    pub payload: Value,
}

impl SuccessEnvelope {
    /// Creates a successful v1 response.
    #[must_use]
    pub fn new(id: impl Into<String>, payload: Value) -> Self {
        Self { v: PROTOCOL_VERSION, id: id.into(), ok: true, payload }
    }
}

/// Error response envelope.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ErrorEnvelope {
    /// Protocol version.
    pub v: u16,
    /// Request id being answered.
    pub id: String,
    /// Success marker. Always false for this variant.
    pub ok: bool,
    /// Typed Locket error name.
    pub error: String,
    /// Redacted safe message.
    pub message: String,
    /// Whether the client may retry the request unchanged.
    pub retryable: bool,
}

impl ErrorEnvelope {
    /// Creates a redacted v1 error response.
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        error: impl Into<String>,
        message: impl Into<String>,
        retryable: bool,
    ) -> Self {
        Self {
            v: PROTOCOL_VERSION,
            id: id.into(),
            ok: false,
            error: error.into(),
            message: message.into(),
            retryable,
        }
    }
}

/// Metadata-only lock state reported by status calls.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum LockState {
    /// Agent is not holding unwrapped keys.
    Locked,
    /// Agent has unwrapped keys for the current user/session.
    Unlocked,
    /// Agent is unavailable or cannot determine lock state.
    Unknown,
}

/// Metadata-only status payload shared by `Status` and status events.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StatusPayload {
    /// Lock state.
    pub lock_state: LockState,
    /// Optional active project id or privacy alias.
    pub project_id: Option<String>,
    /// Optional active profile name or privacy alias.
    pub profile_name: Option<String>,
    /// Count of live grants, never grant tokens.
    pub live_grant_count: u32,
    /// Agent version string.
    pub agent_version: String,
}

impl StatusPayload {
    /// Creates a locked status payload with no active project context.
    #[must_use]
    pub fn locked(agent_version: impl Into<String>) -> Self {
        Self {
            lock_state: LockState::Locked,
            project_id: None,
            profile_name: None,
            live_grant_count: 0,
            agent_version: agent_version.into(),
        }
    }
}

/// Error returned while encoding or decoding agent protocol frames.
#[derive(Debug, Error)]
pub enum ProtocolError {
    /// Frame length is larger than the configured maximum.
    #[error("agent protocol message exceeds maximum size: {length} > {maximum}")]
    MessageTooLarge {
        /// Encoded payload length.
        length: usize,
        /// Maximum allowed payload length.
        maximum: usize,
    },
    /// The byte stream does not contain a complete frame yet.
    #[error("incomplete agent protocol frame")]
    IncompleteFrame,
    /// JSON serialization or deserialization failed.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    /// The frame length cannot be represented by the v1 32-bit prefix.
    #[error("agent protocol message is too large for v1 framing")]
    LengthPrefixOverflow,
    /// The protocol version is not supported.
    #[error("unsupported agent protocol version: {version}")]
    UnsupportedVersion {
        /// Version found in the envelope.
        version: u16,
    },
    /// Request kind is not a supported v1 method.
    #[error(transparent)]
    UnknownMethod(#[from] UnknownMethod),
}

/// Serializes an envelope payload into a length-prefixed v1 frame.
///
/// The first four bytes are the little-endian payload length. The length
/// excludes the prefix itself and the payload is UTF-8 JSON.
///
/// # Errors
///
/// Returns [`ProtocolError::Json`] when serialization fails, and
/// [`ProtocolError::MessageTooLarge`] or [`ProtocolError::LengthPrefixOverflow`]
/// when the JSON payload is too large for the configured v1 frame.
pub fn encode_frame<T: Serialize>(
    envelope: &T,
    maximum_size: usize,
) -> Result<Vec<u8>, ProtocolError> {
    let payload = serde_json::to_vec(envelope)?;
    if payload.len() > maximum_size {
        return Err(ProtocolError::MessageTooLarge {
            length: payload.len(),
            maximum: maximum_size,
        });
    }
    let length = u32::try_from(payload.len()).map_err(|_| ProtocolError::LengthPrefixOverflow)?;
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&length.to_le_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

/// Decodes one v1 request frame from `bytes`.
///
/// # Errors
///
/// Returns [`ProtocolError::IncompleteFrame`] when fewer than one complete
/// frame is available, [`ProtocolError::MessageTooLarge`] when the frame
/// declares an oversized payload, [`ProtocolError::Json`] for malformed JSON,
/// and [`ProtocolError::UnsupportedVersion`] for non-v1 requests.
pub fn decode_request_frame(
    bytes: &[u8],
    maximum_size: usize,
) -> Result<(RequestEnvelope, usize), ProtocolError> {
    let (payload, consumed) = frame_payload(bytes, maximum_size)?;
    let envelope: RequestEnvelope = serde_json::from_slice(payload)?;
    if envelope.v != PROTOCOL_VERSION {
        return Err(ProtocolError::UnsupportedVersion { version: envelope.v });
    }
    envelope.method()?;
    Ok((envelope, consumed))
}

fn frame_payload(bytes: &[u8], maximum_size: usize) -> Result<(&[u8], usize), ProtocolError> {
    if bytes.len() < 4 {
        return Err(ProtocolError::IncompleteFrame);
    }
    let length_bytes = [bytes[0], bytes[1], bytes[2], bytes[3]];
    let length = u32::from_le_bytes(length_bytes) as usize;
    if length > maximum_size {
        return Err(ProtocolError::MessageTooLarge { length, maximum: maximum_size });
    }
    let consumed = 4 + length;
    if bytes.len() < consumed {
        return Err(ProtocolError::IncompleteFrame);
    }
    Ok((&bytes[4..consumed], consumed))
}

#[cfg(test)]
mod tests {
    use super::{
        AgentMethod, DEFAULT_MAX_MESSAGE_SIZE, ErrorEnvelope, LockState, PROTOCOL_VERSION,
        ProtocolError, RequestEnvelope, StatusPayload, SuccessEnvelope, decode_request_frame,
        encode_frame,
    };
    use serde_json::json;

    #[test]
    fn encodes_and_decodes_length_prefixed_request() -> Result<(), ProtocolError> {
        let request =
            RequestEnvelope::new("req-1", AgentMethod::Status, json!({"client_kind": "cli"}));

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
    fn status_payload_is_metadata_only() {
        let payload = StatusPayload::locked("0.1.0");

        assert_eq!(payload.lock_state, LockState::Locked);
        assert_eq!(payload.live_grant_count, 0);
        assert!(payload.project_id.is_none());
        assert!(payload.profile_name.is_none());
    }
}
