//! Local agent and protocol types for Locket.

// age 0.11 enters through locket-core and carries older transitive crates
// alongside workspace versions. The sealed-bundle dependency owns that skew.
#![allow(clippy::multiple_crate_versions)]

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
mod runtime_sessions;
mod scan;
#[cfg(unix)]
mod server;
mod status;
mod status_stream;
mod unlock_cache;

pub use envelope::{ErrorEnvelope, RequestEnvelope, ResponseEnvelope, SuccessEnvelope};
pub use error::ProtocolError;
pub use framing::{decode_request_frame, decode_response_frame, encode_frame};
pub use grant::{
    GrantAction, GrantBinding, GrantIdPayload, GrantRecord, GrantRecordFields, GrantTable,
    GrantValidation, RequestGrantPayload,
};
pub use method::{AgentMethod, UnknownMethod};
#[cfg(unix)]
pub use peer_cred::{current_process_uid, validate_peer_stream, validate_peer_uid};
pub use prepare_exec::{PrepareExecRequest, PrepareExecResponse};
pub use resolve::{ResolveRequest, ResolveResponse};
pub use reveal::{CopyRequest, CopyResponse, RevealRequest, RevealResponse};
pub use runtime_sessions::{
    ListRuntimeSessionsRequest, ListRuntimeSessionsResponse, RuntimeSessionRow,
    RuntimeSessionSnapshot, RuntimeSessionState,
};
pub use scan::{ScanFinding, ScanRequest, ScanResponse};
#[cfg(unix)]
pub use server::{
    AgentSocketConfig, AgentSocketState, ConnectionOutcome, SocketServerError,
    bind_socket_listener, handle_connection, socket_permission_mode,
};
pub use status::{
    LockState, STATUS_HEARTBEAT_INTERVAL_SECS, StatusEvent, StatusEventKind, StatusEventSequence,
    StatusPayload,
};
pub use status_stream::{StatusHub, StatusSubscriber};
pub use unlock_cache::{UnlockCache, UnlockEntry, UnlockMethod};

/// Maximum v1 protocol message size in bytes.
pub const DEFAULT_MAX_MESSAGE_SIZE: usize = 1024 * 1024;

/// Agent protocol version supported by this crate.
pub const PROTOCOL_VERSION: u16 = 1;

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
