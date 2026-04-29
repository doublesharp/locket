//! Local agent and protocol types for Locket.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

/// Maximum v1 protocol message size in bytes.
pub const DEFAULT_MAX_MESSAGE_SIZE: usize = 1024 * 1024;

/// Agent protocol version supported by this crate.
pub const PROTOCOL_VERSION: u16 = 1;

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
        DEFAULT_MAX_MESSAGE_SIZE, PROTOCOL_VERSION, ProtocolError, RequestEnvelope,
        decode_request_frame, encode_frame,
    };
    use serde_json::json;

    #[test]
    fn encodes_and_decodes_length_prefixed_request() -> Result<(), ProtocolError> {
        let request = RequestEnvelope {
            v: PROTOCOL_VERSION,
            id: "req-1".to_owned(),
            kind: "Status".to_owned(),
            payload: json!({"client_kind": "cli"}),
        };

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

        let request = RequestEnvelope {
            v: PROTOCOL_VERSION,
            id: "req-1".to_owned(),
            kind: "Status".to_owned(),
            payload: json!({}),
        };
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
            kind: "Status".to_owned(),
            payload: json!({}),
        };
        let frame = encode_frame(&request, DEFAULT_MAX_MESSAGE_SIZE)?;

        assert!(matches!(
            decode_request_frame(&frame, DEFAULT_MAX_MESSAGE_SIZE),
            Err(ProtocolError::UnsupportedVersion { version: 99 })
        ));
        Ok(())
    }
}
