//! Local agent and protocol types for Locket.

mod envelope;
mod error;
mod framing;
mod grant;
mod method;
#[cfg(unix)]
mod peer_cred;
mod prepare_exec;
mod resolve;
mod reveal;
mod scan;
#[cfg(unix)]
mod server;
mod status;

pub use envelope::{ErrorEnvelope, RequestEnvelope, ResponseEnvelope, SuccessEnvelope};
pub use error::ProtocolError;
pub use framing::{decode_request_frame, decode_response_frame, encode_frame};
pub use grant::{GrantBinding, GrantRecord, GrantTable, GrantValidation};
pub use method::{AgentMethod, UnknownMethod};
pub use prepare_exec::{PrepareExecRequest, PrepareExecResponse};
pub use resolve::{ResolveRequest, ResolveResponse};
pub use reveal::{CopyRequest, CopyResponse, RevealRequest, RevealResponse};
pub use scan::{ScanFinding, ScanRequest, ScanResponse};
#[cfg(unix)]
pub use peer_cred::{current_process_uid, validate_peer_stream, validate_peer_uid};
#[cfg(unix)]
pub use server::{
    AgentSocketConfig, AgentSocketState, ConnectionOutcome, SocketServerError, StubStatusSource,
    bind_socket_listener, handle_connection, socket_permission_mode,
};
pub use status::{
    LockState, STATUS_HEARTBEAT_INTERVAL_SECS, StatusEvent, StatusEventKind, StatusEventSequence,
    StatusPayload,
};

/// Maximum v1 protocol message size in bytes.
pub const DEFAULT_MAX_MESSAGE_SIZE: usize = 1024 * 1024;

/// Agent protocol version supported by this crate.
pub const PROTOCOL_VERSION: u16 = 1;

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
