//! Local agent and protocol types for Locket.

mod envelope;
mod error;
mod framing;
mod method;
mod status;

pub use envelope::{ErrorEnvelope, RequestEnvelope, ResponseEnvelope, SuccessEnvelope};
pub use error::ProtocolError;
pub use framing::{decode_request_frame, encode_frame};
pub use method::{AgentMethod, UnknownMethod};
pub use status::{LockState, StatusPayload};

/// Maximum v1 protocol message size in bytes.
pub const DEFAULT_MAX_MESSAGE_SIZE: usize = 1024 * 1024;

/// Agent protocol version supported by this crate.
pub const PROTOCOL_VERSION: u16 = 1;

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
