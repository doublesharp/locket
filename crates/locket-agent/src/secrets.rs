//! Metadata-only secret listing RPC payloads and helpers.

use std::path::PathBuf;

use locket_store::{Store, StoreError};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Wire payload for the `ListSecrets` RPC.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ListSecretsRequest {
    /// `SQLite` store path to read.
    pub store_path: PathBuf,
    /// Project id whose active-profile rows are listed.
    pub project_id: String,
    /// Active profile id.
    pub profile_id: String,
    /// Whether profile and secret names should be aliased.
    #[serde(default)]
    pub redact_names: bool,
}

/// Metadata-only `ListSecrets` response.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ListSecretsResponse {
    /// Active secret metadata rows ordered by name and source precedence.
    pub rows: Vec<ListSecretsRow>,
}

/// Metadata-only active secret row for agent clients.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ListSecretsRow {
    /// Secret row id.
    pub id: String,
    /// Profile id or privacy alias.
    pub profile_id: String,
    /// Secret name or privacy alias.
    pub name: String,
    /// Runtime source.
    pub source: String,
    /// Numeric source precedence, with larger values winning runtime resolution.
    pub source_precedence: u8,
    /// Metadata origin.
    pub origin: String,
    /// Current version number.
    pub current_version: u32,
    /// Secret state.
    pub state: String,
    /// Whether command policies should treat the secret as required.
    pub required: bool,
    /// Creation timestamp in nanoseconds since the Unix epoch.
    pub created_at: i64,
    /// Last metadata update timestamp in nanoseconds since the Unix epoch.
    pub updated_at: i64,
    /// Last rotation timestamp in nanoseconds since the Unix epoch.
    pub last_rotated_at: Option<i64>,
}

/// Lists active-profile secret metadata. This never reads encrypted values.
///
/// # Errors
///
/// Returns [`StoreError`] when the store cannot be opened or queried.
pub fn list_secrets(request: &ListSecretsRequest) -> Result<ListSecretsResponse, StoreError> {
    let store = Store::open(&request.store_path)?;
    let rows = store
        .list_active_secret_metadata_by_profile(&request.project_id, &request.profile_id)?
        .into_iter()
        .map(|row| ListSecretsRow {
            id: row.id,
            profile_id: profile_label(&row.profile_id, request.redact_names),
            name: secret_label(&row.name, request.redact_names),
            source: row.source,
            source_precedence: row.source_precedence,
            origin: row.origin,
            current_version: row.current_version,
            state: row.state,
            required: row.required,
            created_at: row.created_at,
            updated_at: row.updated_at,
            last_rotated_at: row.last_rotated_at,
        })
        .collect();
    Ok(ListSecretsResponse { rows })
}

fn profile_label(value: &str, redact_names: bool) -> String {
    if redact_names { privacy_alias("profile", value) } else { value.to_owned() }
}

fn secret_label(value: &str, redact_names: bool) -> String {
    if redact_names { privacy_alias("secret", value) } else { value.to_owned() }
}

fn privacy_alias(kind: &str, id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"locket-privacy-alias-v1");
    hasher.update(format!("kind:{kind};id:{id}").as_bytes());
    let digest = hasher.finalize();
    format!("{kind}-{:02x}{:02x}{:02x}{:02x}", digest[0], digest[1], digest[2], digest[3])
}
