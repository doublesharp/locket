//! Metadata-only secret version listing RPC payloads and helpers.

use std::path::PathBuf;

use locket_core::privacy_alias;
use locket_store::{Store, StoreError};
use serde::{Deserialize, Serialize};

/// Wire payload for the `ListVersions` RPC.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ListVersionsRequest {
    /// `SQLite` store path to read.
    pub store_path: PathBuf,
    /// Project id whose active-profile rows are listed.
    pub project_id: String,
    /// Active profile id.
    pub profile_id: String,
    /// Optional secret-name filter.
    pub secret_name: Option<String>,
    /// Optional source filter.
    pub source: Option<String>,
    /// Timestamp used for grace-window derived fields.
    pub now_unix_nanos: i64,
    /// Whether profile and secret names should be aliased.
    #[serde(default)]
    pub redact_names: bool,
}

/// Metadata-only `ListVersions` response.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ListVersionsResponse {
    /// Version metadata rows ordered by name, source precedence, and version.
    pub rows: Vec<ListVersionsRow>,
}

/// Metadata-only secret version row for agent clients.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ListVersionsRow {
    /// Secret row id.
    pub secret_id: String,
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
    /// Whole-secret state.
    pub secret_state: String,
    /// Current version pointer on the parent secret.
    pub current_version: u32,
    /// Last rotation timestamp on the parent secret.
    pub last_rotated_at: Option<i64>,
    /// Version number.
    pub version: u32,
    /// Version state.
    pub version_state: String,
    /// Version creation timestamp.
    pub created_at: i64,
    /// Deprecation timestamp.
    pub deprecated_at: Option<i64>,
    /// Grace-window expiration timestamp.
    pub grace_until: Option<i64>,
    /// Purge timestamp.
    pub purged_at: Option<i64>,
    /// Whether a pinned `lk://...@vN` reference may resolve this version at `now`.
    pub pinned_reference_eligible: bool,
    /// Whether known-value scanning should include this version at `now`.
    pub scan_included: bool,
}

/// Lists version metadata. This never reads encrypted values.
///
/// # Errors
///
/// Returns [`StoreError`] when the store cannot be opened or queried.
pub fn list_versions(request: &ListVersionsRequest) -> Result<ListVersionsResponse, StoreError> {
    let store = Store::open(&request.store_path)?;
    let rows = store
        .list_secret_version_metadata_by_profile(&request.project_id, &request.profile_id)?
        .into_iter()
        .filter(|row| request.secret_name.as_ref().is_none_or(|name| row.name == *name))
        .filter(|row| request.source.as_ref().is_none_or(|source| row.source == *source))
        .map(|row| {
            let eligible = version_resolves_at(
                &row.version_state,
                row.secret_state.as_str(),
                row.current_version,
                row.version,
                row.grace_until,
                request.now_unix_nanos,
            );
            ListVersionsRow {
                secret_id: row.secret_id,
                profile_id: profile_label(&row.profile_id, request.redact_names),
                name: secret_label(&row.name, request.redact_names),
                source: row.source,
                source_precedence: row.source_precedence,
                origin: row.origin,
                secret_state: row.secret_state,
                current_version: row.current_version,
                last_rotated_at: row.last_rotated_at,
                version: row.version,
                version_state: row.version_state,
                created_at: row.created_at,
                deprecated_at: row.deprecated_at,
                grace_until: row.grace_until,
                purged_at: row.purged_at,
                pinned_reference_eligible: eligible,
                scan_included: eligible,
            }
        })
        .collect();
    Ok(ListVersionsResponse { rows })
}

fn version_resolves_at(
    version_state: &str,
    secret_state: &str,
    current_version: u32,
    version: u32,
    grace_until: Option<i64>,
    now_unix_nanos: i64,
) -> bool {
    match version_state {
        "current" => secret_state == "active" && version == current_version,
        "deprecated" => grace_until.is_some_and(|grace_until| grace_until > now_unix_nanos),
        _ => false,
    }
}

fn profile_label(value: &str, redact_names: bool) -> String {
    if redact_names { privacy_alias("profile", value) } else { value.to_owned() }
}

fn secret_label(value: &str, redact_names: bool) -> String {
    if redact_names { privacy_alias("secret", value) } else { value.to_owned() }
}

