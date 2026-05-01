//! Metadata-only saved command policy listing for desktop policy views.

use std::path::PathBuf;

use locket_core::{CommandPolicy, CommandSpec, privacy_alias};
use locket_store::{AuditWrite, Store};
use serde::{Deserialize, Serialize};
use serde_json::json;

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

/// Request payload for `RegisterCommandPolicies`.
///
/// The CLI emits this RPC after every `policy add/allow/require/edit/delete`
/// write to `locket.toml`, so the running agent's in-memory snapshot stays
/// in sync with the on-disk policy set without requiring a desktop client
/// to pump the snapshots.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RegisterCommandPoliciesRequest {
    /// Active project identifier whose snapshot should be replaced.
    pub project_id: String,
    /// Replacement snapshots for `project_id`. The agent retains
    /// snapshots for other projects unchanged.
    pub policies: Vec<CommandPolicySnapshot>,
    /// Path to the user-scoped `store.db` used to append the
    /// metadata-only `POLICY_UPDATE` audit row.
    pub store_path: PathBuf,
    /// Optional active profile id recorded on the audit row.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_profile_id: Option<String>,
}

/// Replaces the in-memory snapshots for a single project.
///
/// All entries previously stored for `project_id` are removed; entries
/// for other project ids are preserved. The replacement is in-place to
/// keep the snapshot vector flat, matching the existing `ListPolicies`
/// path which filters by `project_id` on read.
pub fn replace_project_snapshots(
    snapshots: &mut Vec<CommandPolicySnapshot>,
    project_id: &str,
    replacements: Vec<CommandPolicySnapshot>,
) {
    snapshots.retain(|snapshot| snapshot.project_id != project_id);
    for replacement in replacements {
        if replacement.project_id == project_id {
            snapshots.push(replacement);
        }
    }
}

/// Handler for `RegisterCommandPolicies`.
///
/// The agent must have a live unlock-cache entry for `project_id` so
/// callers cannot mutate snapshots for projects they have not unlocked.
/// On success a metadata-only `POLICY_UPDATE` audit row with
/// `operation: "snapshot"` is appended to the project audit chain.
#[cfg(unix)]
pub async fn handle_register_command_policies(
    request: &RequestEnvelope,
    state: &crate::server::AgentSocketState,
    now_unix_nanos: i128,
) -> ResponseEnvelope {
    let typed: RegisterCommandPoliciesRequest =
        match serde_json::from_value(request.payload.clone()) {
            Ok(value) => value,
            Err(_) => {
                return ResponseEnvelope::Error(ErrorEnvelope::new(
                    request.id.clone(),
                    "ProtocolError",
                    "invalid RegisterCommandPolicies payload",
                    false,
                ));
            }
        };

    let audit_key = {
        let cache = state.unlock_cache.lock().await;
        cache.lookup(&typed.project_id, now_unix_nanos).map(|entry| entry.key_bytes().to_vec())
    };
    let Some(audit_key) = audit_key else {
        return ResponseEnvelope::Error(ErrorEnvelope::new(
            request.id.clone(),
            "UnlockRequired",
            "unlock required to register command policies",
            false,
        ));
    };

    let policy_count = typed.policies.len();
    {
        let mut snapshots = state.command_policies.lock().await;
        replace_project_snapshots(&mut snapshots, &typed.project_id, typed.policies);
    }

    let metadata = json!({
        "schema_version": 1,
        "action": "POLICY_UPDATE",
        "status": "SUCCESS",
        "command": "policy",
        "operation": "snapshot",
        "change_kind": "snapshot",
        "policy": "*",
        "policy_name": "*",
        "command_policy_count": policy_count,
        "metadata_only": true,
    });
    let timestamp = i64::try_from(now_unix_nanos).unwrap_or(i64::MAX);
    let audit = AuditWrite {
        project_id: &typed.project_id,
        profile_id: typed.audit_profile_id.as_deref(),
        action: "POLICY_UPDATE",
        status: "SUCCESS",
        secret_name: None,
        command: Some("policy"),
        metadata_json: &metadata,
        timestamp,
    };
    let mut store = match Store::open(&typed.store_path) {
        Ok(store) => store,
        Err(error) => {
            return ResponseEnvelope::Error(ErrorEnvelope::new(
                request.id.clone(),
                "CorruptDb",
                format!("failed to open store: {error}"),
                false,
            ));
        }
    };
    if let Err(error) = store.append_audit(&audit_key, &audit) {
        return ResponseEnvelope::Error(ErrorEnvelope::new(
            request.id.clone(),
            "CorruptDb",
            format!("failed to append POLICY_UPDATE audit row: {error}"),
            false,
        ));
    }

    ResponseEnvelope::Success(SuccessEnvelope::new(request.id.clone(), serde_json::Value::Null))
}
