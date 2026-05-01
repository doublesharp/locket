//! Metadata-only runtime session listing for desktop execution views.

use locket_core::privacy_alias;
use serde::{Deserialize, Serialize};

use crate::envelope::{ErrorEnvelope, RequestEnvelope, ResponseEnvelope, SuccessEnvelope};

/// Request for active-profile runtime sessions.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ListRuntimeSessionsRequest {
    /// Active project identifier.
    pub project_id: String,
    /// Active profile identifier.
    pub profile_id: String,
    /// Whether exact profile/policy labels should be replaced with privacy aliases.
    pub privacy_redact_names: bool,
}

/// Response containing metadata-only runtime session rows.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ListRuntimeSessionsResponse {
    /// Rows scoped to the active project/profile.
    pub rows: Vec<RuntimeSessionRow>,
}

/// Agent-held runtime session metadata. Never contains secret values or names.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RuntimeSessionSnapshot {
    /// Runtime session identifier.
    pub session_id: String,
    /// Parent project identifier.
    pub project_id: String,
    /// Parent profile identifier.
    pub profile_id: String,
    /// Optional policy name used to authorize the session.
    pub policy_name: Option<String>,
    /// Runtime process id.
    pub process_id: u32,
    /// Process start timestamp in nanoseconds since the Unix epoch.
    pub process_start_time: i64,
    /// Session start timestamp in nanoseconds since the Unix epoch.
    pub started_at: i64,
    /// Session end timestamp in nanoseconds since the Unix epoch.
    pub ended_at: Option<i64>,
    /// Process exit status when known.
    pub exit_status: Option<i32>,
    /// Count of retained secret names; values and names are not held here.
    pub secret_name_count: u32,
    /// Optional project-scoped audit sequence for the spawn event.
    pub spawn_audit_sequence: Option<u64>,
    /// Optional project-scoped audit sequence for the completion event.
    pub completion_audit_sequence: Option<u64>,
}

/// Wire row consumed by the desktop execution monitor.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RuntimeSessionRow {
    /// Runtime session identifier.
    pub session_id: String,
    /// Exact profile id when privacy is off; alias when privacy is on.
    pub profile: String,
    /// Profile alias when privacy is on.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile_alias: Option<String>,
    /// Exact policy name when privacy is off; alias when privacy is on.
    pub policy: String,
    /// Policy alias when privacy is on.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_alias: Option<String>,
    /// Runtime process id.
    pub pid: u32,
    /// Process start timestamp in nanoseconds since the Unix epoch.
    pub process_start_time: i64,
    /// Session start timestamp in nanoseconds since the Unix epoch.
    pub started_at: i64,
    /// Session end timestamp in nanoseconds since the Unix epoch.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ended_at: Option<i64>,
    /// Process exit status when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_status: Option<i32>,
    /// Metadata-only state derived from completion data.
    pub state: RuntimeSessionState,
    /// Count of retained secret names; never the names or values.
    pub secret_name_count: u32,
    /// Project-scoped audit sequence for the spawn event, if available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spawn_audit_sequence: Option<u64>,
    /// Project-scoped audit sequence for the completion event, if available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completion_audit_sequence: Option<u64>,
}

/// Metadata-only runtime session state.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeSessionState {
    /// No completion metadata has arrived.
    Running,
    /// Completion metadata has zero exit status.
    Completed,
    /// Completion metadata has non-zero or unknown exit status.
    Failed,
}

/// Builds the socket response for the runtime-session list request.
#[must_use]
pub fn list_runtime_sessions_response(
    request: &ListRuntimeSessionsRequest,
    sessions: &[RuntimeSessionSnapshot],
) -> ListRuntimeSessionsResponse {
    let mut rows = sessions
        .iter()
        .filter(|session| {
            session.project_id == request.project_id && session.profile_id == request.profile_id
        })
        .map(|session| runtime_session_row(request, session))
        .collect::<Vec<_>>();
    rows.sort_by(|left, right| {
        right.started_at.cmp(&left.started_at).then_with(|| left.session_id.cmp(&right.session_id))
    });
    ListRuntimeSessionsResponse { rows }
}

fn runtime_session_row(
    request: &ListRuntimeSessionsRequest,
    session: &RuntimeSessionSnapshot,
) -> RuntimeSessionRow {
    let policy_name = session.policy_name.as_deref().unwrap_or("direct");
    let profile_alias =
        request.privacy_redact_names.then(|| privacy_alias("profile", &session.profile_id));
    let policy_alias = request.privacy_redact_names.then(|| privacy_alias("policy", policy_name));
    RuntimeSessionRow {
        session_id: session.session_id.clone(),
        profile: profile_alias.clone().unwrap_or_else(|| session.profile_id.clone()),
        profile_alias,
        policy: policy_alias.clone().unwrap_or_else(|| policy_name.to_owned()),
        policy_alias,
        pid: session.process_id,
        process_start_time: session.process_start_time,
        started_at: session.started_at,
        ended_at: session.ended_at,
        exit_status: session.exit_status,
        state: runtime_session_state(session),
        secret_name_count: session.secret_name_count,
        spawn_audit_sequence: session.spawn_audit_sequence,
        completion_audit_sequence: session.completion_audit_sequence,
    }
}

const fn runtime_session_state(session: &RuntimeSessionSnapshot) -> RuntimeSessionState {
    match (session.ended_at, session.exit_status) {
        (None, _) => RuntimeSessionState::Running,
        (Some(_), Some(0)) => RuntimeSessionState::Completed,
        (Some(_), _) => RuntimeSessionState::Failed,
    }
}

/// Handles invalid-payload conversion for the dispatcher.
#[must_use]
pub fn invalid_payload_response(envelope: &RequestEnvelope) -> ResponseEnvelope {
    ResponseEnvelope::Error(ErrorEnvelope::new(
        envelope.id.clone(),
        "ProtocolError",
        "invalid ListRuntimeSessions payload",
        false,
    ))
}

/// Encodes a successful runtime-session list response.
#[must_use]
pub fn success_response(
    envelope: &RequestEnvelope,
    response: ListRuntimeSessionsResponse,
) -> ResponseEnvelope {
    let payload = serde_json::to_value(response).unwrap_or(serde_json::Value::Null);
    ResponseEnvelope::Success(SuccessEnvelope::new(envelope.id.clone(), payload))
}
