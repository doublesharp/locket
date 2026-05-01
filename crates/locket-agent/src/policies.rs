//! Metadata-only saved command policy listing for desktop policy views.

use locket_core::{CommandPolicy, CommandSpec, privacy_alias};
use serde::{Deserialize, Serialize};

use crate::envelope::{ErrorEnvelope, RequestEnvelope, ResponseEnvelope, SuccessEnvelope};

/// Request for saved command policy metadata.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ListPoliciesRequest {
    /// Active project identifier.
    pub project_id: String,
    /// Whether exact policy and secret names should be replaced with privacy aliases.
    pub privacy_redact_names: bool,
}

/// Response containing metadata-only saved command policy rows.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ListPoliciesResponse {
    /// Rows scoped to the requested project.
    pub rows: Vec<CommandPolicyRow>,
}

/// Agent-held saved policy metadata. Never contains secret values.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct CommandPolicySnapshot {
    /// Parent project identifier.
    pub project_id: String,
    /// Saved command policy name.
    pub name: String,
    /// Command representation: `argv` or `shell`.
    pub command_kind: String,
    /// Metadata-only command preview for UI display.
    pub command_preview: String,
    /// Required secret names.
    pub required_secrets: Vec<String>,
    /// Optional secret names.
    pub optional_secrets: Vec<String>,
    /// Union of required and optional secret names.
    pub allowed_secrets: Vec<String>,
    /// Whether execution requires typed confirmation.
    pub confirm: bool,
    /// Whether execution requires local user verification.
    pub require_user_verification: bool,
    /// Whether execution must go through the local agent.
    pub require_agent: bool,
    /// Whether Docker helpers may target remote contexts.
    pub allow_remote_docker: bool,
    /// Grant TTL in seconds.
    pub ttl_seconds: u64,
    /// Base child environment policy.
    pub env_mode: String,
    /// Conflict behavior for injected Locket names.
    pub override_mode: String,
    /// Updated timestamp in nanoseconds since the Unix epoch.
    pub updated_at_unix_nanos: i64,
}

impl CommandPolicySnapshot {
    /// Build metadata for a parsed policy and project-local update timestamp.
    #[must_use]
    pub fn from_policy(
        project_id: impl Into<String>,
        policy: &CommandPolicy,
        updated_at_unix_nanos: i64,
    ) -> Self {
        Self {
            project_id: project_id.into(),
            name: policy.name.clone(),
            command_kind: command_kind(&policy.command).to_owned(),
            command_preview: command_preview(&policy.command),
            required_secrets: policy.required_secrets.iter().map(ToString::to_string).collect(),
            optional_secrets: policy.optional_secrets.iter().map(ToString::to_string).collect(),
            allowed_secrets: policy.allowed_secrets.iter().map(ToString::to_string).collect(),
            confirm: policy.confirm,
            require_user_verification: policy.require_user_verification,
            require_agent: policy.require_agent,
            allow_remote_docker: policy.allow_remote_docker,
            ttl_seconds: policy.ttl.as_secs(),
            env_mode: policy.env_mode.as_str().to_owned(),
            override_mode: policy.override_behavior.as_str().to_owned(),
            updated_at_unix_nanos,
        }
    }
}

/// Wire row consumed by desktop policy surfaces.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct CommandPolicyRow {
    /// Stable row identifier. Alias when privacy mode is enabled.
    pub id: String,
    /// Exact policy name when privacy is off; alias when privacy is on.
    pub name: String,
    /// Policy alias when privacy is on.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,
    /// Command representation: `argv` or `shell`.
    pub command_kind: String,
    /// Metadata-only command preview.
    pub command_preview: String,
    /// Required secret names, or aliases in privacy mode.
    pub required_secrets: Vec<String>,
    /// Optional secret names, or aliases in privacy mode.
    pub optional_secrets: Vec<String>,
    /// Union of policy-visible names, or aliases in privacy mode.
    pub allowed_secrets: Vec<String>,
    /// Whether execution requires typed confirmation.
    pub confirm: bool,
    /// Whether execution requires local user verification.
    pub require_user_verification: bool,
    /// Whether execution must go through the local agent.
    pub require_agent: bool,
    /// Whether Docker helpers may target remote contexts.
    pub allow_remote_docker: bool,
    /// Grant TTL in seconds.
    pub ttl_seconds: u64,
    /// Base child environment policy.
    pub env_mode: String,
    /// Conflict behavior for injected Locket names.
    pub override_mode: String,
    /// Updated timestamp in nanoseconds since the Unix epoch.
    pub updated_at_unix_nanos: i64,
}

/// Builds the socket response for the saved policy list request.
#[must_use]
pub fn list_policies_response(
    request: &ListPoliciesRequest,
    policies: &[CommandPolicySnapshot],
) -> ListPoliciesResponse {
    let mut rows = policies
        .iter()
        .filter(|policy| policy.project_id == request.project_id)
        .map(|policy| command_policy_row(request, policy))
        .collect::<Vec<_>>();
    rows.sort_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then_with(|| right.updated_at_unix_nanos.cmp(&left.updated_at_unix_nanos))
    });
    ListPoliciesResponse { rows }
}

fn command_policy_row(
    request: &ListPoliciesRequest,
    policy: &CommandPolicySnapshot,
) -> CommandPolicyRow {
    let alias = request.privacy_redact_names.then(|| privacy_alias("policy", &policy.name));
    CommandPolicyRow {
        id: alias.clone().unwrap_or_else(|| policy.name.clone()),
        name: alias.clone().unwrap_or_else(|| policy.name.clone()),
        alias,
        command_kind: policy.command_kind.clone(),
        command_preview: policy.command_preview.clone(),
        required_secrets: secret_labels(&policy.required_secrets, request.privacy_redact_names),
        optional_secrets: secret_labels(&policy.optional_secrets, request.privacy_redact_names),
        allowed_secrets: secret_labels(&policy.allowed_secrets, request.privacy_redact_names),
        confirm: policy.confirm,
        require_user_verification: policy.require_user_verification,
        require_agent: policy.require_agent,
        allow_remote_docker: policy.allow_remote_docker,
        ttl_seconds: policy.ttl_seconds,
        env_mode: policy.env_mode.clone(),
        override_mode: policy.override_mode.clone(),
        updated_at_unix_nanos: policy.updated_at_unix_nanos,
    }
}

fn secret_labels(names: &[String], privacy_redact_names: bool) -> Vec<String> {
    names
        .iter()
        .map(|name| if privacy_redact_names { privacy_alias("secret", name) } else { name.clone() })
        .collect()
}

const fn command_kind(command: &CommandSpec) -> &'static str {
    match command {
        CommandSpec::Argv(_) => "argv",
        CommandSpec::Shell(_) => "shell",
    }
}

fn command_preview(command: &CommandSpec) -> String {
    match command {
        CommandSpec::Argv(argv) => argv.join(" "),
        CommandSpec::Shell(shell) => shell.clone(),
    }
}

/// Handles invalid-payload conversion for the dispatcher.
#[must_use]
pub fn invalid_payload_response(envelope: &RequestEnvelope) -> ResponseEnvelope {
    ResponseEnvelope::Error(ErrorEnvelope::new(
        envelope.id.clone(),
        "ProtocolError",
        "invalid ListPolicies payload",
        false,
    ))
}

/// Encodes a successful saved policy list response.
#[must_use]
pub fn success_response(
    envelope: &RequestEnvelope,
    response: ListPoliciesResponse,
) -> ResponseEnvelope {
    let payload = serde_json::to_value(response).unwrap_or(serde_json::Value::Null);
    ResponseEnvelope::Success(SuccessEnvelope::new(envelope.id.clone(), payload))
}
