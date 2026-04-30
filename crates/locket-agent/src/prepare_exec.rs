//! Typed payloads for the `PrepareExec` agent RPC.
//!
//! `PrepareExec` resolves a saved command policy into the precise set of
//! environment variable names the trusted CLI execution path is
//! authorized to inject, plus a TTL hint for the resulting grant. See
//! `docs/specs/agent.md` and `docs/specs/runtime.md`.
//!
//! The handler here is a stub. The policy registry, command-kind
//! classifier, and grant issuer are not yet wired through the socket
//! dispatch path, so every call returns a successful but empty
//! response: no env vars allowed, `command_kind = "argv"` (the default
//! shape used by saved policies), and `ttl_seconds = 0`. The desktop
//! policy editor uses this stub to render a "no env vars yet" preview
//! without erroring while the rest of the pipeline catches up.

use serde::{Deserialize, Serialize};

use crate::envelope::{ErrorEnvelope, RequestEnvelope, ResponseEnvelope, SuccessEnvelope};

/// Default `command_kind` value emitted by the stub handler.
///
/// Saved policies always describe an argv-style invocation today; the
/// other supported value is `"shell"` and is reserved for future slices
/// that wrap the command in a shell pipeline.
const DEFAULT_COMMAND_KIND: &str = "argv";

/// Request payload for `PrepareExec`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrepareExecRequest {
    /// Name of the saved command policy to prepare.
    pub policy_name: String,
    /// Profile id whose secrets the policy should resolve against.
    pub profile_id: String,
}

/// Response payload for `PrepareExec`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrepareExecResponse {
    /// Environment variable names the executor is authorized to inject.
    /// The list is metadata only: no values are exposed here.
    pub allowed_env_names: Vec<String>,
    /// Shape of the command invocation, e.g. `"argv"` or `"shell"`.
    pub command_kind: String,
    /// Time-to-live hint, in seconds, for the prepared invocation.
    pub ttl_seconds: u32,
}

/// Stub handler for `PrepareExec`.
///
/// Always returns a successful response with an empty allow-list, an
/// `argv` command kind, and a zero TTL. Future slices will replace the
/// body with a real policy lookup that emits the actual env names and
/// a non-zero TTL based on the policy spec.
pub fn handle_prepare_exec(request: &RequestEnvelope) -> ResponseEnvelope {
    let Ok(typed) = serde_json::from_value::<PrepareExecRequest>(request.payload.clone()) else {
        return ResponseEnvelope::Error(ErrorEnvelope::new(
            request.id.clone(),
            "ProtocolError",
            "invalid PrepareExec payload",
            false,
        ));
    };
    // The typed payload is intentionally not consulted yet; binding it
    // ensures the wire fields are recognized so the future handler does
    // not silently break older clients.
    let _ = typed;

    let response = PrepareExecResponse {
        allowed_env_names: Vec::new(),
        command_kind: DEFAULT_COMMAND_KIND.to_owned(),
        ttl_seconds: 0,
    };
    serde_json::to_value(&response).map_or_else(
        |_| {
            ResponseEnvelope::Error(ErrorEnvelope::new(
                request.id.clone(),
                "ProtocolError",
                "failed to serialize PrepareExec response",
                false,
            ))
        },
        |payload| ResponseEnvelope::Success(SuccessEnvelope::new(request.id.clone(), payload)),
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::panic)]

    use super::{
        DEFAULT_COMMAND_KIND, PrepareExecRequest, PrepareExecResponse, handle_prepare_exec,
    };
    use crate::envelope::{RequestEnvelope, ResponseEnvelope};
    use crate::method::AgentMethod;
    use serde_json::json;

    #[test]
    fn prepare_exec_request_round_trips_through_json() -> Result<(), serde_json::Error> {
        let request = PrepareExecRequest {
            policy_name: "deploy-staging".to_owned(),
            profile_id: "profile-staging".to_owned(),
        };

        let value = serde_json::to_value(&request)?;
        let decoded: PrepareExecRequest = serde_json::from_value(value.clone())?;

        assert_eq!(decoded, request);
        assert_eq!(value["policy_name"], "deploy-staging");
        assert_eq!(value["profile_id"], "profile-staging");
        Ok(())
    }

    #[test]
    fn prepare_exec_response_round_trips_through_json() -> Result<(), serde_json::Error> {
        let response = PrepareExecResponse {
            allowed_env_names: vec!["DATABASE_URL".to_owned(), "API_TOKEN".to_owned()],
            command_kind: "argv".to_owned(),
            ttl_seconds: 60,
        };

        let value = serde_json::to_value(&response)?;
        let decoded: PrepareExecResponse = serde_json::from_value(value.clone())?;

        assert_eq!(decoded, response);
        assert_eq!(value["command_kind"], "argv");
        assert_eq!(value["ttl_seconds"], 60);
        Ok(())
    }

    #[test]
    fn handle_prepare_exec_returns_empty_success_response() -> Result<(), serde_json::Error> {
        let envelope = RequestEnvelope::new(
            "req-prepare",
            AgentMethod::PrepareExec,
            json!({"policy_name": "deploy-staging", "profile_id": "profile-staging"}),
        );

        let response = handle_prepare_exec(&envelope);
        let ResponseEnvelope::Success(success) = response else {
            panic!("expected success envelope");
        };
        assert_eq!(success.id, "req-prepare");
        let decoded: PrepareExecResponse = serde_json::from_value(success.payload)?;
        assert!(decoded.allowed_env_names.is_empty());
        assert_eq!(decoded.command_kind, DEFAULT_COMMAND_KIND);
        assert_eq!(decoded.ttl_seconds, 0);
        Ok(())
    }

    #[test]
    fn handle_prepare_exec_rejects_malformed_payload_with_protocol_error() {
        let envelope = RequestEnvelope::new(
            "req-bad",
            AgentMethod::PrepareExec,
            json!({"policy_name": 1, "profile_id": null}),
        );

        let response = handle_prepare_exec(&envelope);
        let ResponseEnvelope::Error(error) = response else {
            panic!("expected error envelope");
        };
        assert_eq!(error.error, "ProtocolError");
    }
}
