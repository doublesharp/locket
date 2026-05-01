//! Typed errors for encoding and decoding agent protocol frames.

use thiserror::Error;

use crate::method::UnknownMethod;

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
