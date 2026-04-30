//! Typed payloads for the `Reveal` and `Copy` agent RPCs.
//!
//! Both methods provide gated single-value access to a secret. They
//! share request and response shapes because the only operational
//! difference is the audit row written by the agent and the redaction
//! policy applied to the returned value at the client boundary. The
//! handlers here are stubs: the unlock cache, grant table, and audit
//! pipeline are not wired yet, so every call returns a typed
//! `UnlockRequired` error envelope. The desktop UI treats this as the
//! canonical "vault is locked, prompt the user to unlock" denial.
//!
//! See `docs/specs/agent.md` for the gated-value-access contract and
//! `docs/specs/errors.md` for the `UnlockRequired` error semantics.
//!
//! When the unlock cache and grant table are wired in a later slice,
//! the dispatch arms will replace the unconditional denial with a real
//! lookup that may return [`RevealResponse`] / [`CopyResponse`] success
//! envelopes carrying the value and a TTL hint. The shapes defined here
//! are stable for that future code path.

use serde::{Deserialize, Serialize};

use crate::envelope::{ErrorEnvelope, RequestEnvelope, ResponseEnvelope};

/// Wire `error` value used when the vault is locked.
const ERROR_UNLOCK_REQUIRED: &str = "UnlockRequired";

/// Redacted denial message returned to clients.
///
/// The string is intentionally generic. The desktop UI promotes the
/// typed `error` field rather than this human-readable text.
const UNLOCK_REQUIRED_MESSAGE: &str = "vault is locked; unlock required before revealing values";

/// Request payload for `Reveal`.
///
/// `secret_name` is the canonical key name within the active project,
/// not an `lk://` URI; references go through `ResolveReference`.
/// `profile_id` selects which profile's value to read so the agent can
/// audit the request against the correct profile scope.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RevealRequest {
    /// Canonical secret name within the active project.
    pub secret_name: String,
    /// Profile id whose value should be read.
    pub profile_id: String,
}

/// Response payload for `Reveal` once the unlock cache is wired.
///
/// The stub handler never produces this shape today, but the type is
/// part of the public API so future success paths and the desktop UI
/// can rely on a stable shape.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RevealResponse {
    /// Resolved secret value. Treated as a redacted token by the UI.
    pub value: String,
    /// Time-to-live hint for any caller-side caching, in seconds.
    pub ttl_seconds: u32,
}

/// Request payload for `Copy`.
///
/// Identical shape to [`RevealRequest`]; defined separately so the
/// methods retain distinct typed surfaces and so audit wiring can
/// distinguish them without sniffing the variant.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CopyRequest {
    /// Canonical secret name within the active project.
    pub secret_name: String,
    /// Profile id whose value should be copied.
    pub profile_id: String,
}

/// Response payload for `Copy` once the unlock cache is wired.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CopyResponse {
    /// Resolved secret value. Treated as a redacted token by the UI.
    pub value: String,
    /// Time-to-live hint for any caller-side caching, in seconds.
    pub ttl_seconds: u32,
}

/// Stub handler for `Reveal`.
///
/// Always returns an [`ErrorEnvelope`] with `error = "UnlockRequired"`
/// and `retryable = false`. The deserialization step is performed so
/// the wire shape is validated even while the value path is stubbed
/// out; future slices will replace this with a real handler that
/// inspects the unlock cache and grant table.
pub fn handle_reveal(request: &RequestEnvelope) -> ResponseEnvelope {
    serde_json::from_value::<RevealRequest>(request.payload.clone()).map_or_else(
        |_| {
            ResponseEnvelope::Error(ErrorEnvelope::new(
                request.id.clone(),
                "ProtocolError",
                "invalid Reveal payload",
                false,
            ))
        },
        |_typed| {
            ResponseEnvelope::Error(ErrorEnvelope::new(
                request.id.clone(),
                ERROR_UNLOCK_REQUIRED,
                UNLOCK_REQUIRED_MESSAGE,
                false,
            ))
        },
    )
}

/// Stub handler for `Copy`.
///
/// Mirrors [`handle_reveal`]; see that function for the rationale.
pub fn handle_copy(request: &RequestEnvelope) -> ResponseEnvelope {
    serde_json::from_value::<CopyRequest>(request.payload.clone()).map_or_else(
        |_| {
            ResponseEnvelope::Error(ErrorEnvelope::new(
                request.id.clone(),
                "ProtocolError",
                "invalid Copy payload",
                false,
            ))
        },
        |_typed| {
            ResponseEnvelope::Error(ErrorEnvelope::new(
                request.id.clone(),
                ERROR_UNLOCK_REQUIRED,
                UNLOCK_REQUIRED_MESSAGE,
                false,
            ))
        },
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::panic)]

    use super::{
        CopyRequest, CopyResponse, ERROR_UNLOCK_REQUIRED, RevealRequest, RevealResponse,
        handle_copy, handle_reveal,
    };
    use crate::PROTOCOL_VERSION;
    use crate::envelope::{RequestEnvelope, ResponseEnvelope};
    use crate::method::AgentMethod;
    use serde_json::json;

    #[test]
    fn reveal_request_round_trips_through_json() -> Result<(), serde_json::Error> {
        let request = RevealRequest {
            secret_name: "DATABASE_URL".to_owned(),
            profile_id: "profile-dev".to_owned(),
        };

        let value = serde_json::to_value(&request)?;
        let decoded: RevealRequest = serde_json::from_value(value.clone())?;

        assert_eq!(decoded, request);
        assert_eq!(value["secret_name"], "DATABASE_URL");
        assert_eq!(value["profile_id"], "profile-dev");
        Ok(())
    }

    #[test]
    fn reveal_response_round_trips_through_json() -> Result<(), serde_json::Error> {
        let response = RevealResponse { value: "hunter2".to_owned(), ttl_seconds: 30 };

        let value = serde_json::to_value(&response)?;
        let decoded: RevealResponse = serde_json::from_value(value.clone())?;

        assert_eq!(decoded, response);
        assert_eq!(value["value"], "hunter2");
        assert_eq!(value["ttl_seconds"], 30);
        Ok(())
    }

    #[test]
    fn copy_request_round_trips_through_json() -> Result<(), serde_json::Error> {
        let request = CopyRequest {
            secret_name: "API_TOKEN".to_owned(),
            profile_id: "profile-prod".to_owned(),
        };

        let value = serde_json::to_value(&request)?;
        let decoded: CopyRequest = serde_json::from_value(value)?;

        assert_eq!(decoded, request);
        Ok(())
    }

    #[test]
    fn copy_response_round_trips_through_json() -> Result<(), serde_json::Error> {
        let response = CopyResponse { value: "k".to_owned(), ttl_seconds: 0 };

        let decoded: CopyResponse = serde_json::from_value(serde_json::to_value(&response)?)?;
        assert_eq!(decoded, response);
        Ok(())
    }

    #[test]
    fn handle_reveal_returns_unlock_required_error() {
        let envelope = RequestEnvelope::new(
            "req-reveal",
            AgentMethod::Reveal,
            json!({ "secret_name": "DATABASE_URL", "profile_id": "profile-dev" }),
        );

        let response = handle_reveal(&envelope);

        let ResponseEnvelope::Error(error) = response else {
            panic!("expected error envelope, got success");
        };
        assert_eq!(error.v, PROTOCOL_VERSION);
        assert_eq!(error.id, "req-reveal");
        assert!(!error.ok);
        assert_eq!(error.error, ERROR_UNLOCK_REQUIRED);
        assert!(!error.retryable);
        assert!(!error.message.is_empty());
    }

    #[test]
    fn handle_copy_returns_unlock_required_error() {
        let envelope = RequestEnvelope::new(
            "req-copy",
            AgentMethod::Copy,
            json!({ "secret_name": "API_TOKEN", "profile_id": "profile-prod" }),
        );

        let response = handle_copy(&envelope);

        let ResponseEnvelope::Error(error) = response else {
            panic!("expected error envelope, got success");
        };
        assert_eq!(error.id, "req-copy");
        assert_eq!(error.error, ERROR_UNLOCK_REQUIRED);
        assert!(!error.retryable);
    }

    #[test]
    fn handle_reveal_rejects_malformed_payload_with_protocol_error() {
        let envelope = RequestEnvelope::new("req-bad", AgentMethod::Reveal, json!({"oops": 1}));

        let response = handle_reveal(&envelope);
        let ResponseEnvelope::Error(error) = response else {
            panic!("expected error envelope, got success");
        };
        assert_eq!(error.error, "ProtocolError");
    }
}
