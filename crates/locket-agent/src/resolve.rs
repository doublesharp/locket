//! Typed payloads for the `ResolveReference` agent RPC.
//!
//! `ResolveReference` resolves an authorized `lk://` reference into a
//! plaintext value plus metadata. The reference resolver enforces the
//! deprecated-version grace contract, so pinned `lk://...@vN` URIs may
//! return graced versions while unpinned references must not. See
//! `docs/specs/agent.md` and `docs/specs/runtime.md`.
//!
//! The handler here is a stub: the resolver requires a live grant to
//! produce values, and the grant table is not yet wired through the
//! socket dispatch path. Every call returns a typed `GrantRequired`
//! error envelope. The desktop UI uses that as the canonical
//! "agent is unlocked but the caller needs an explicit grant" denial.

use serde::{Deserialize, Serialize};

use crate::envelope::{ErrorEnvelope, RequestEnvelope, ResponseEnvelope};

/// Wire `error` value used when the caller lacks a grant.
const ERROR_GRANT_REQUIRED: &str = "GrantRequired";

/// Redacted denial message returned to clients.
const GRANT_REQUIRED_MESSAGE: &str =
    "live grant required to resolve lk:// references; request a grant before retrying";

/// Request payload for `ResolveReference`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ResolveRequest {
    /// `lk://` reference to resolve. The agent re-parses this string;
    /// no client-side parsing is trusted.
    pub reference: String,
}

/// Response payload for `ResolveReference` once the grant table is
/// wired.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ResolveResponse {
    /// Plaintext value for the resolved reference.
    pub value: String,
    /// Version selected by the resolver. Stable for the duration of
    /// the caller's grant.
    pub version: u32,
    /// Profile id whose value was selected.
    pub profile_id: String,
}

/// Stub handler for `ResolveReference`.
///
/// Always returns an [`ErrorEnvelope`] with `error = "GrantRequired"`
/// and `retryable = false`. The payload is deserialized first so the
/// wire shape is validated even while the resolver is stubbed out.
pub fn handle_resolve(request: &RequestEnvelope) -> ResponseEnvelope {
    serde_json::from_value::<ResolveRequest>(request.payload.clone()).map_or_else(
        |_| {
            ResponseEnvelope::Error(ErrorEnvelope::new(
                request.id.clone(),
                "ProtocolError",
                "invalid ResolveReference payload",
                false,
            ))
        },
        |_typed| {
            ResponseEnvelope::Error(ErrorEnvelope::new(
                request.id.clone(),
                ERROR_GRANT_REQUIRED,
                GRANT_REQUIRED_MESSAGE,
                false,
            ))
        },
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::panic)]

    use super::{ERROR_GRANT_REQUIRED, ResolveRequest, ResolveResponse, handle_resolve};
    use crate::PROTOCOL_VERSION;
    use crate::envelope::{RequestEnvelope, ResponseEnvelope};
    use crate::method::AgentMethod;
    use serde_json::json;

    #[test]
    fn resolve_request_round_trips_through_json() -> Result<(), serde_json::Error> {
        let request =
            ResolveRequest { reference: "lk://team/project/profile/SECRET@v3".to_owned() };

        let value = serde_json::to_value(&request)?;
        let decoded: ResolveRequest = serde_json::from_value(value.clone())?;

        assert_eq!(decoded, request);
        assert_eq!(value["reference"], "lk://team/project/profile/SECRET@v3");
        Ok(())
    }

    #[test]
    fn resolve_response_round_trips_through_json() -> Result<(), serde_json::Error> {
        let response = ResolveResponse {
            value: "secret-value".to_owned(),
            version: 7,
            profile_id: "profile-prod".to_owned(),
        };

        let value = serde_json::to_value(&response)?;
        let decoded: ResolveResponse = serde_json::from_value(value)?;

        assert_eq!(decoded, response);
        Ok(())
    }

    #[test]
    fn handle_resolve_returns_grant_required_error() {
        let envelope = RequestEnvelope::new(
            "req-resolve",
            AgentMethod::ResolveReference,
            json!({ "reference": "lk://team/project/profile/SECRET" }),
        );

        let response = handle_resolve(&envelope);
        let ResponseEnvelope::Error(error) = response else {
            panic!("expected error envelope");
        };
        assert_eq!(error.v, PROTOCOL_VERSION);
        assert_eq!(error.id, "req-resolve");
        assert_eq!(error.error, ERROR_GRANT_REQUIRED);
        assert!(!error.retryable);
        assert!(!error.message.is_empty());
    }

    #[test]
    fn handle_resolve_rejects_malformed_payload_with_protocol_error() {
        let envelope = RequestEnvelope::new(
            "req-bad",
            AgentMethod::ResolveReference,
            json!({"reference": 1234}),
        );

        let response = handle_resolve(&envelope);
        let ResponseEnvelope::Error(error) = response else {
            panic!("expected error envelope");
        };
        assert_eq!(error.error, "ProtocolError");
    }
}
