//! Agent RPC for switching the active project profile.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use locket_core::{PROJECT_CONFIG_SCHEMA_VERSION, ProfileName, ProjectConfig};
use locket_store::{AuditWrite, ProfileRecord, Store};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::envelope::{ErrorEnvelope, RequestEnvelope, ResponseEnvelope, SuccessEnvelope};

/// Request payload for `SetActiveProfile`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SetActiveProfileRequest {
    /// Project `locket.toml` path to update.
    pub config_path: PathBuf,
    /// Store path used to validate profiles and write audit metadata.
    pub store_path: PathBuf,
    /// Project id whose active profile is changing.
    pub project_id: String,
    /// Requested profile name.
    pub profile_name: String,
    /// Typed confirmation for dangerous-profile switches.
    #[serde(default)]
    pub confirmation: Option<String>,
    /// Privacy mode for response labels.
    #[serde(default)]
    pub privacy_redact_names: bool,
    /// Optional trusted-root hash for audit parity with CLI `use`.
    #[serde(default)]
    pub root_hash: Option<String>,
}

/// Response payload for `SetActiveProfile`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SetActiveProfileResponse {
    /// Whether `locket.toml` changed.
    pub changed: bool,
    /// Newly active profile id.
    pub profile_id: String,
    /// Newly active profile name.
    pub profile_name: String,
    /// Privacy-aware label for the newly active profile.
    pub profile_label: String,
    /// Whether the newly active profile is marked dangerous.
    pub dangerous: bool,
    /// Prior active profile id.
    pub prior_profile_id: String,
    /// Prior active profile name.
    pub prior_profile_name: String,
    /// Privacy-aware label for the prior active profile.
    pub prior_profile_label: String,
    /// Number of live project grants revoked after a successful switch.
    pub live_grants_revoked: u32,
}

#[derive(Debug, thiserror::Error)]
enum SetActiveProfileError {
    #[error("invalid profile name")]
    InvalidProfileName,
    #[error("profile not found")]
    ProfileNotFound,
    #[error("confirmation did not match")]
    ConfirmationFailed,
    #[error("unlock required")]
    UnlockRequired,
    #[error("{0}")]
    MetadataInvalid(String),
    #[error(transparent)]
    Store(#[from] locket_store::StoreError),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    TomlDeserialize(#[from] toml::de::Error),
    #[error(transparent)]
    TomlSerialize(#[from] toml::ser::Error),
}

impl SetActiveProfileError {
    fn error_name(&self) -> &'static str {
        match self {
            Self::InvalidProfileName => "InvalidProfileName",
            Self::ProfileNotFound => "ProfileNotFound",
            Self::ConfirmationFailed => "ConfirmationFailed",
            Self::UnlockRequired => "UnlockRequired",
            Self::MetadataInvalid(_)
            | Self::Io(_)
            | Self::TomlDeserialize(_)
            | Self::TomlSerialize(_) => "MetadataInvalid",
            Self::Store(error) => match error.locket_error() {
                locket_core::LocketError::StorageBusy => "StorageBusy",
                locket_core::LocketError::SchemaNewerThanBinary => "SchemaNewerThanBinary",
                locket_core::LocketError::AuditIntegrityFailed => "AuditIntegrityFailed",
                locket_core::LocketError::MetadataInvalid => "MetadataInvalid",
                _ => "CorruptDb",
            },
        }
    }
}

/// Handles a `SetActiveProfile` request.
pub async fn handle_set_active_profile(
    request: &RequestEnvelope,
    state: &crate::server::AgentSocketState,
    now_unix_nanos: i128,
) -> ResponseEnvelope {
    let payload: SetActiveProfileRequest = match serde_json::from_value(request.payload.clone()) {
        Ok(payload) => payload,
        Err(_) => {
            return error_response(request, "ProtocolError", "invalid SetActiveProfile payload");
        }
    };
    match set_active_profile(&payload, state, now_unix_nanos).await {
        Ok(response) => success_response(request, response),
        Err(error) => error_response(request, error.error_name(), error.to_string()),
    }
}

async fn set_active_profile(
    request: &SetActiveProfileRequest,
    state: &crate::server::AgentSocketState,
    now_unix_nanos: i128,
) -> Result<SetActiveProfileResponse, SetActiveProfileError> {
    let profile_name = ProfileName::new(request.profile_name.clone())
        .map_err(|_| SetActiveProfileError::InvalidProfileName)?;
    let audit_key = audit_key_for_project(state, &request.project_id, now_unix_nanos).await?;
    let mut project_config = read_project_config(&request.config_path)?;
    if project_config.project_id.as_str() != request.project_id {
        return Err(SetActiveProfileError::MetadataInvalid(
            "project_id does not match locket.toml".to_owned(),
        ));
    }

    let mut store = Store::open(&request.store_path)?;
    let new_profile = store
        .get_profile_by_name(&request.project_id, profile_name.as_str())?
        .ok_or(SetActiveProfileError::ProfileNotFound)?;
    let prior_profile = store
        .get_profile_by_name(&request.project_id, project_config.default_profile.as_str())?
        .ok_or(SetActiveProfileError::ProfileNotFound)?;

    if prior_profile.name == new_profile.name {
        return Ok(response_payload(
            false,
            &prior_profile,
            &new_profile,
            request.privacy_redact_names,
            0,
        ));
    }

    if new_profile.dangerous {
        let confirmed = request
            .confirmation
            .as_deref()
            .is_some_and(|value| value.trim_end_matches(['\r', '\n']) == new_profile.name.as_str());
        if !confirmed {
            return Err(SetActiveProfileError::ConfirmationFailed);
        }
    }

    let live_grants_to_revoke = {
        let grants = state.grants.lock().await;
        grants.count_for_project(&request.project_id)
    };
    project_config.default_profile = profile_name;
    write_project_config(&request.config_path, &project_config)?;
    append_profile_change_audit(
        &mut store,
        request,
        &prior_profile,
        &new_profile,
        u32::try_from(live_grants_to_revoke).unwrap_or(u32::MAX),
        &audit_key,
        i64::try_from(now_unix_nanos).unwrap_or(i64::MAX),
    )?;
    let revoked = {
        let mut grants = state.grants.lock().await;
        grants.revoke_for_project(&request.project_id)
    };
    state.publish_status_snapshot(now_unix_nanos).await;
    Ok(response_payload(
        true,
        &prior_profile,
        &new_profile,
        request.privacy_redact_names,
        u32::try_from(revoked).unwrap_or(u32::MAX),
    ))
}

async fn audit_key_for_project(
    state: &crate::server::AgentSocketState,
    project_id: &str,
    now_unix_nanos: i128,
) -> Result<Vec<u8>, SetActiveProfileError> {
    state
        .unlock_cache
        .lock()
        .await
        .lookup(project_id, now_unix_nanos)
        .map(|entry| entry.key_bytes().to_vec())
        .ok_or(SetActiveProfileError::UnlockRequired)
}

fn read_project_config(path: &Path) -> Result<ProjectConfig, SetActiveProfileError> {
    let text = fs::read_to_string(path)?;
    let config = toml::from_str::<ProjectConfig>(&text)?;
    if config.schema_version != PROJECT_CONFIG_SCHEMA_VERSION {
        return Err(SetActiveProfileError::MetadataInvalid(format!(
            "unsupported locket.toml schema_version {}; supported {}",
            config.schema_version, PROJECT_CONFIG_SCHEMA_VERSION
        )));
    }
    Ok(config)
}

fn write_project_config(path: &Path, config: &ProjectConfig) -> Result<(), SetActiveProfileError> {
    let text = toml::to_string_pretty(config)?;
    fs::write(path, text)?;
    Ok(())
}

fn append_profile_change_audit(
    store: &mut Store,
    request: &SetActiveProfileRequest,
    prior_profile: &ProfileRecord,
    new_profile: &ProfileRecord,
    live_grants_revoked: u32,
    audit_key: &[u8],
    timestamp: i64,
) -> Result<(), SetActiveProfileError> {
    let confirmation_source = new_profile.dangerous.then_some("typed");
    let mut metadata = json!({
        "schema_version": 1,
        "action": "PROFILE_CHANGE",
        "status": "SUCCESS",
        "operation": "use",
        "command": "agent set-active-profile",
        "project_id": request.project_id,
        "prior_profile_id": prior_profile.id,
        "prior_profile_name": prior_profile.name,
        "new_profile_id": new_profile.id,
        "new_profile_name": new_profile.name,
        "new_profile_dangerous": new_profile.dangerous,
        "live_grants_revoked": live_grants_revoked,
    });
    if let Some(root_hash) = request.root_hash.as_deref() {
        metadata["root_hash"] = json!(root_hash);
    }
    if let Some(source) = confirmation_source {
        metadata["confirmation_source"] = json!(source);
    }
    let audit = AuditWrite {
        project_id: &request.project_id,
        profile_id: Some(new_profile.id.as_str()),
        action: "PROFILE_CHANGE",
        status: "SUCCESS",
        secret_name: None,
        command: Some("agent set-active-profile"),
        metadata_json: &metadata,
        timestamp,
    };
    store.append_audit(audit_key, &audit)?;
    Ok(())
}

fn response_payload(
    changed: bool,
    prior_profile: &ProfileRecord,
    new_profile: &ProfileRecord,
    redact_names: bool,
    live_grants_revoked: u32,
) -> SetActiveProfileResponse {
    SetActiveProfileResponse {
        changed,
        profile_id: new_profile.id.clone(),
        profile_name: new_profile.name.clone(),
        profile_label: profile_label(new_profile, redact_names),
        dangerous: new_profile.dangerous,
        prior_profile_id: prior_profile.id.clone(),
        prior_profile_name: prior_profile.name.clone(),
        prior_profile_label: profile_label(prior_profile, redact_names),
        live_grants_revoked,
    }
}

fn profile_label(profile: &ProfileRecord, redact_names: bool) -> String {
    if redact_names { privacy_alias("profile", &profile.id) } else { profile.name.clone() }
}

fn privacy_alias(kind: &str, id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"locket-privacy-alias-v1");
    hasher.update(format!("kind:{kind};id:{id}").as_bytes());
    let digest = hasher.finalize();
    format!("{kind}-{:02x}{:02x}{:02x}{:02x}", digest[0], digest[1], digest[2], digest[3])
}

fn success_response<T: Serialize>(request: &RequestEnvelope, payload: T) -> ResponseEnvelope {
    let payload = serde_json::to_value(payload).unwrap_or(serde_json::Value::Null);
    ResponseEnvelope::Success(SuccessEnvelope::new(request.id.clone(), payload))
}

fn error_response(
    request: &RequestEnvelope,
    error: &str,
    message: impl Into<String>,
) -> ResponseEnvelope {
    ResponseEnvelope::Error(ErrorEnvelope::new(request.id.clone(), error, message, false))
}
