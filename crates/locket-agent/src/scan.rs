//! Typed payloads for the `ScanKnownValues` agent RPC.
//!
//! `ScanKnownValues` provides in-memory matching against the agent's
//! known-secret-value map for scanner integrations that must avoid
//! persisting plaintext values. Pattern, entropy, and `.env` heuristics
//! live in `locket-scan` and run client-side without an unlock; this
//! RPC adds the known-value match path that requires unwrapped key
//! material.
//!
//! See `docs/specs/agent.md` and `docs/specs/scan-redaction.md` for
//! semantics. The handler here is a stub: the locked-vault contract
//! says known-value matching cannot run when the vault is locked, so
//! we return an empty findings list with `locked = true`. Callers that
//! pass `require_known = true` are expected to inspect `locked` and
//! surface `UnlockRequired` themselves; once the unlock cache is wired
//! the dispatch arm here will return that error directly.

use serde::{Deserialize, Serialize};

use crate::envelope::{ErrorEnvelope, RequestEnvelope, ResponseEnvelope, SuccessEnvelope};

/// Request payload for `ScanKnownValues`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ScanRequest {
    /// Filesystem paths the caller has already read into memory and now
    /// wants matched against known values. The agent never opens these
    /// files itself; the path is metadata for finding records.
    pub paths: Vec<String>,
    /// When true, the caller is in a "fail closed" mode and wants the
    /// agent to refuse with an explicit unlock-required error if the
    /// vault is locked. The stub handler does not honor this flag yet
    /// because the unlock cache is not wired; the field is preserved on
    /// the wire so the future handler can read it.
    pub require_known: bool,
}

/// Single scan finding emitted by `ScanKnownValues`.
///
/// Findings are metadata only: `redacted_summary` is a short, redaction-
/// safe excerpt the UI can render without exposing the matched value.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ScanFinding {
    /// Name of the rule or known-value source that produced the match.
    pub rule: String,
    /// Path the match originated from, echoed from the request.
    pub path: String,
    /// One-based line number within `path`.
    pub line: u32,
    /// One-based column number within the matched line.
    pub column: u32,
    /// Severity classification (`info`, `warn`, `error`, ...).
    pub severity: String,
    /// Short redacted excerpt safe to display in logs and UIs.
    pub redacted_summary: String,
    /// Optional rule id that suppressed this finding, when applicable.
    pub suppressed_by: Option<String>,
}

/// Response payload for `ScanKnownValues`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ScanResponse {
    /// All matches discovered. Empty when the vault is locked because
    /// known-value matching needs unwrapped keys.
    pub findings: Vec<ScanFinding>,
    /// Whether the agent was locked at the time of the call. Callers
    /// that requested `require_known = true` should treat `locked =
    /// true` as a coverage gap.
    pub locked: bool,
}

/// Stub handler for `ScanKnownValues`.
///
/// Always reports `locked = true` with an empty findings list, mirroring
/// the locked-vault behavior described in `scan-redaction.md`. The
/// request is still deserialized so the wire shape is validated.
pub fn handle_scan(request: &RequestEnvelope) -> ResponseEnvelope {
    let Ok(typed) = serde_json::from_value::<ScanRequest>(request.payload.clone()) else {
        return ResponseEnvelope::Error(ErrorEnvelope::new(
            request.id.clone(),
            "ProtocolError",
            "invalid ScanKnownValues payload",
            false,
        ));
    };
    // Touch the typed value so future handlers and the compiler agree
    // on the field set without warning about unused destructuring.
    let _ = typed;

    let response = ScanResponse { findings: Vec::new(), locked: true };
    serde_json::to_value(&response).map_or_else(
        |_| {
            ResponseEnvelope::Error(ErrorEnvelope::new(
                request.id.clone(),
                "ProtocolError",
                "failed to serialize ScanKnownValues response",
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

    use super::{ScanFinding, ScanRequest, ScanResponse, handle_scan};
    use crate::envelope::{RequestEnvelope, ResponseEnvelope};
    use crate::method::AgentMethod;
    use serde_json::json;

    #[test]
    fn scan_request_round_trips_through_json() -> Result<(), serde_json::Error> {
        let request = ScanRequest {
            paths: vec!["src/main.rs".to_owned(), ".env".to_owned()],
            require_known: true,
        };

        let value = serde_json::to_value(&request)?;
        let decoded: ScanRequest = serde_json::from_value(value.clone())?;

        assert_eq!(decoded, request);
        assert_eq!(value["require_known"], true);
        assert_eq!(value["paths"][0], "src/main.rs");
        Ok(())
    }

    #[test]
    fn scan_finding_preserves_optional_suppressed_by() -> Result<(), serde_json::Error> {
        let finding = ScanFinding {
            rule: "known-value/db".to_owned(),
            path: "src/main.rs".to_owned(),
            line: 12,
            column: 5,
            severity: "warn".to_owned(),
            redacted_summary: "let token = \"***\";".to_owned(),
            suppressed_by: Some("locket-ignore/line".to_owned()),
        };

        let value = serde_json::to_value(&finding)?;
        let decoded: ScanFinding = serde_json::from_value(value.clone())?;

        assert_eq!(decoded, finding);
        assert_eq!(value["suppressed_by"], "locket-ignore/line");
        Ok(())
    }

    #[test]
    fn scan_response_round_trips_through_json() -> Result<(), serde_json::Error> {
        let response = ScanResponse { findings: vec![], locked: true };

        let value = serde_json::to_value(&response)?;
        let decoded: ScanResponse = serde_json::from_value(value.clone())?;

        assert_eq!(decoded, response);
        assert_eq!(value["locked"], true);
        assert!(value["findings"].as_array().is_some_and(Vec::is_empty));
        Ok(())
    }

    #[test]
    fn handle_scan_returns_locked_empty_response() -> Result<(), serde_json::Error> {
        let envelope = RequestEnvelope::new(
            "req-scan",
            AgentMethod::ScanKnownValues,
            json!({"paths": ["src/main.rs"], "require_known": false}),
        );

        let response = handle_scan(&envelope);
        let ResponseEnvelope::Success(success) = response else {
            panic!("expected success envelope");
        };
        assert_eq!(success.id, "req-scan");
        let decoded: ScanResponse = serde_json::from_value(success.payload)?;
        assert!(decoded.locked);
        assert!(decoded.findings.is_empty());
        Ok(())
    }

    #[test]
    fn handle_scan_rejects_malformed_payload_with_protocol_error() {
        let envelope =
            RequestEnvelope::new("req-bad", AgentMethod::ScanKnownValues, json!({"paths": 5}));

        let response = handle_scan(&envelope);
        let ResponseEnvelope::Error(error) = response else {
            panic!("expected error envelope");
        };
        assert_eq!(error.error, "ProtocolError");
    }
}
