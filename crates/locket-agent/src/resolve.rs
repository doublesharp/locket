//! Typed payloads for the `ResolveReference` agent RPC.
//!
//! `ResolveReference` resolves an authorized `lk://` reference into a
//! plaintext value plus metadata. The reference resolver enforces the
//! deprecated-version grace contract, so pinned `lk://...@vN` URIs may
//! return graced versions while unpinned references must not. See
//! `docs/specs/agent.md` and `docs/specs/runtime.md`.
//!
//! The handler requires a live grant and a live unlock-cache entry
//! before it touches the store. It returns only typed envelopes and
//! never includes secret values in error metadata.

use std::path::Path;

use locket_core::{LkReferenceUri, LocketError, SecretVersion};
use locket_crypto::{
    EncryptedSecretValue, HkdfWrapInfo, KeyPurpose, KeyWrapAad, KeyWrapPurpose, WrappedKeyMaterial,
    decrypt_secret_value_v1, derive_wrapping_key_v1, key_wrap_aad_v1, secret_blob_aad_v1,
    unwrap_key_material_v1,
};
use locket_store::{AuditWrite, SecretRecord, SecretVersionRecord, Store};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::envelope::{ErrorEnvelope, RequestEnvelope, ResponseEnvelope};
use crate::grant::{GrantAction, GrantBinding, GrantValidation};

/// Wire `error` value used when the caller lacks a grant.
const ERROR_GRANT_REQUIRED: &str = "GrantRequired";
const ERROR_UNLOCK_REQUIRED: &str = "UnlockRequired";
const ERROR_INVALID_REFERENCE: &str = "InvalidReference";
const ERROR_PROFILE_NOT_FOUND: &str = "ProfileNotFound";
const ERROR_SECRET_NOT_FOUND: &str = "SecretNotFound";
const ERROR_SECRET_DELETED: &str = "SecretDeleted";
const ERROR_SECRET_VERSION_EXPIRED: &str = "SecretVersionExpired";
const ERROR_POLICY_NOT_FOUND: &str = "PolicyNotFound";
const ERROR_ACCESS_DENIED: &str = "AccessDenied";
const ERROR_CORRUPT_DB: &str = "CorruptDb";

/// Redacted denial message returned to clients.
const GRANT_REQUIRED_MESSAGE: &str =
    "live grant required to resolve lk:// references; request a grant before retrying";
const UNLOCK_REQUIRED_MESSAGE: &str =
    "unlock required to resolve lk:// references; unlock the project before retrying";

/// Request payload for `ResolveReference`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ResolveRequest {
    /// `lk://` reference to resolve. The agent re-parses this string;
    /// no client-side parsing is trusted.
    pub reference: String,
    /// Project id whose unlock-cache entry and store rows are used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_id: Option<String>,
    /// Profile id authorized by the live grant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_id: Option<String>,
    /// Command policy whose allow-list authorizes this reference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_name: Option<String>,
    /// Path to the user-scoped `store.db`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub store_path: Option<String>,
    /// Live grant id authorizing reference resolution.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<String>,
    /// Current process binding for the grant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding: Option<GrantBinding>,
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

/// Handler for `ResolveReference`.
#[cfg(unix)]
#[allow(clippy::too_many_lines)]
pub async fn handle_resolve(
    request: &RequestEnvelope,
    state: &crate::server::AgentSocketState,
    now_unix_nanos: i128,
) -> ResponseEnvelope {
    let Ok(typed) = serde_json::from_value::<ResolveRequest>(request.payload.clone()) else {
        return protocol_error(request, "invalid ResolveReference payload");
    };
    if LkReferenceUri::parse(&typed.reference).is_err() {
        return typed_error(
            request,
            ERROR_INVALID_REFERENCE,
            "invalid lk:// reference",
            LocketError::InvalidReference,
        );
    }
    let Some(project_id) = typed.project_id.as_deref() else {
        return protocol_error(request, "ResolveReference requires project_id");
    };
    let Some(profile_id) = typed.profile_id.as_deref() else {
        return protocol_error(request, "ResolveReference requires profile_id");
    };
    let Some(policy_name) = typed.policy_name.as_deref() else {
        return protocol_error(request, "ResolveReference requires policy_name");
    };
    let Some(store_path) = typed.store_path.as_deref() else {
        return protocol_error(request, "ResolveReference requires store_path");
    };

    let cached_master_key_for_denial = || async {
        let cache = state.unlock_cache.lock().await;
        cache.lookup(project_id, now_unix_nanos).map(|entry| entry.key_bytes().to_vec())
    };
    let grant_validation = {
        let Some(grant_id) = typed.grant_id.as_deref() else {
            let key = cached_master_key_for_denial().await;
            crate::audit_deny::try_append_grant_denial(
                project_id,
                profile_id,
                Some(Path::new(store_path)),
                key.as_deref(),
                GrantAction::ResolveReference,
                0,
                now_unix_nanos,
                "agent",
            );
            return grant_required(request);
        };
        let grants = state.grants.lock().await;
        grants.validate(
            grant_id,
            project_id,
            profile_id,
            GrantAction::ResolveReference,
            now_unix_nanos,
            typed.binding.as_ref(),
        )
    };
    if !matches!(grant_validation, GrantValidation::Valid) {
        let key = cached_master_key_for_denial().await;
        crate::audit_deny::try_append_grant_denial(
            project_id,
            profile_id,
            Some(Path::new(store_path)),
            key.as_deref(),
            GrantAction::ResolveReference,
            0,
            now_unix_nanos,
            "agent",
        );
        return grant_required(request);
    }

    let master_key = {
        let cache = state.unlock_cache.lock().await;
        cache.lookup(project_id, now_unix_nanos).map(|entry| entry.key_bytes().to_vec())
    };
    let Some(master_key) = master_key else {
        crate::degraded_audit::record_locked_refusal(
            "RESOLVE_REFERENCE",
            Some(project_id),
            "agent.ResolveReference",
            Some(Path::new(store_path)),
            now_unix_nanos,
        );
        return typed_error(
            request,
            ERROR_UNLOCK_REQUIRED,
            UNLOCK_REQUIRED_MESSAGE,
            LocketError::UnlockRequired,
        );
    };

    match resolve_reference(
        &typed.reference,
        project_id,
        profile_id,
        policy_name,
        Path::new(store_path),
        &master_key,
        now_unix_nanos,
    ) {
        Ok(response) => {
            let payload = serde_json::to_value(response).unwrap_or(serde_json::Value::Null);
            ResponseEnvelope::Success(crate::envelope::SuccessEnvelope::new(
                request.id.clone(),
                payload,
            ))
        }
        Err(error) => typed_error(request, error.error, error.message, error.kind),
    }
}

fn protocol_error(request: &RequestEnvelope, message: &str) -> ResponseEnvelope {
    ResponseEnvelope::Error(ErrorEnvelope::new(request.id.clone(), "ProtocolError", message, false))
}

fn grant_required(request: &RequestEnvelope) -> ResponseEnvelope {
    typed_error(request, ERROR_GRANT_REQUIRED, GRANT_REQUIRED_MESSAGE, LocketError::GrantRequired)
}

fn typed_error(
    request: &RequestEnvelope,
    error: &'static str,
    message: impl Into<String>,
    _kind: LocketError,
) -> ResponseEnvelope {
    ResponseEnvelope::Error(ErrorEnvelope::new(request.id.clone(), error, message, false))
}

#[derive(Debug)]
struct ResolveFailure {
    error: &'static str,
    message: &'static str,
    kind: LocketError,
}

impl ResolveFailure {
    const fn new(error: &'static str, message: &'static str, kind: LocketError) -> Self {
        Self { error, message, kind }
    }
}

fn resolve_reference(
    reference: &str,
    project_id: &str,
    authorized_profile_id: &str,
    policy_name: &str,
    store_path: &Path,
    master_key: &[u8],
    now_unix_nanos: i128,
) -> Result<ResolveResponse, ResolveFailure> {
    let parsed = LkReferenceUri::parse(reference).map_err(|_| {
        ResolveFailure::new(
            ERROR_INVALID_REFERENCE,
            "invalid lk:// reference",
            LocketError::InvalidReference,
        )
    })?;
    let master_key = key_array(master_key).ok_or_else(corrupt_db)?;
    let mut store = Store::open(store_path).map_err(|_| corrupt_db())?;
    match resolve_reference_inner(
        &store,
        project_id,
        authorized_profile_id,
        policy_name,
        &parsed,
        &master_key,
        now_unix_nanos,
    ) {
        Ok(resolved) => {
            append_resolve_reference_audit(
                &mut store,
                project_id,
                policy_name,
                &parsed,
                &master_key,
                now_unix_nanos,
                ResolveAuditOutcome::Success(&resolved.audit),
            )?;
            Ok(resolved.response)
        }
        Err(error) => {
            append_resolve_reference_audit(
                &mut store,
                project_id,
                policy_name,
                &parsed,
                &master_key,
                now_unix_nanos,
                ResolveAuditOutcome::Failure(&error),
            )?;
            Err(error)
        }
    }
}

fn resolve_reference_inner(
    store: &Store,
    project_id: &str,
    authorized_profile_id: &str,
    policy_name: &str,
    parsed: &LkReferenceUri,
    master_key: &locket_crypto::KeyBytes,
    now_unix_nanos: i128,
) -> Result<ResolvedReference, ResolveFailure> {
    authorize_policy_reference(store, project_id, policy_name, parsed.key().as_str())?;
    let profile = store
        .get_profile_by_name(project_id, parsed.profile().as_str())
        .map_err(|_| corrupt_db())?
        .ok_or_else(|| {
            ResolveFailure::new(
                ERROR_PROFILE_NOT_FOUND,
                "profile not found",
                LocketError::ProfileNotFound,
            )
        })?;
    if profile.id != authorized_profile_id {
        return Err(ResolveFailure::new(
            ERROR_ACCESS_DENIED,
            "live grant does not authorize the referenced profile",
            LocketError::AccessDenied,
        ));
    }
    let secret = select_secret(store, project_id, &profile.id, parsed)?;
    let version_number = parsed.version().map_or(secret.current_version, SecretVersion::get);
    let version = store
        .get_secret_version(&secret.id, version_number)
        .map_err(|_| corrupt_db())?
        .ok_or_else(|| {
        ResolveFailure::new(
            ERROR_SECRET_NOT_FOUND,
            "secret version not found",
            LocketError::SecretNotFound,
        )
    })?;
    validate_version(&secret, &version, parsed.version().is_some(), now_unix_nanos)?;
    let value =
        decrypt_secret(store, project_id, &profile.id, &secret, version.version, master_key)
            .map_err(|_| corrupt_db())?;
    let audit = ResolveAuditDetails {
        profile_id: profile.id.clone(),
        source: secret.source,
        version: version.version,
        grace_until: version.grace_until,
    };
    Ok(ResolvedReference {
        response: ResolveResponse {
            value: value.to_string(),
            version: version.version,
            profile_id: profile.id,
        },
        audit,
    })
}

struct ResolvedReference {
    response: ResolveResponse,
    audit: ResolveAuditDetails,
}

struct ResolveAuditDetails {
    profile_id: String,
    source: String,
    version: u32,
    grace_until: Option<i64>,
}

#[derive(Clone, Copy)]
enum ResolveAuditOutcome<'a> {
    Success(&'a ResolveAuditDetails),
    Failure(&'a ResolveFailure),
}

fn append_resolve_reference_audit(
    store: &mut Store,
    project_id: &str,
    policy_name: &str,
    parsed: &LkReferenceUri,
    master_key: &locket_crypto::KeyBytes,
    timestamp: i128,
    outcome: ResolveAuditOutcome<'_>,
) -> Result<(), ResolveFailure> {
    let audit_key = load_project_key_with_master(store, project_id, KeyPurpose::Audit, master_key)
        .map_err(|_| corrupt_db())?;
    let timestamp = i64::try_from(timestamp).map_err(|_| corrupt_db())?;
    let mut metadata = Map::from_iter([
        ("schema_version".to_owned(), json!(1)),
        ("action".to_owned(), json!("RESOLVE_REFERENCE")),
        ("project_id".to_owned(), json!(project_id)),
        ("policy".to_owned(), json!(policy_name)),
        ("profile_name".to_owned(), json!(parsed.profile().as_str())),
        ("secret_name".to_owned(), json!(parsed.key().as_str())),
    ]);
    if let Some(source) = parsed.source() {
        metadata.insert("source".to_owned(), json!(source.as_str()));
    }
    if let Some(version) = parsed.version() {
        metadata.insert("selected_version".to_owned(), json!(version.get()));
    }
    let (status, profile_id) = match outcome {
        ResolveAuditOutcome::Success(details) => {
            metadata.insert("status".to_owned(), json!("SUCCESS"));
            metadata.insert("profile_id".to_owned(), json!(details.profile_id));
            metadata.insert("source".to_owned(), json!(details.source));
            metadata.insert("selected_version".to_owned(), json!(details.version));
            if let Some(grace_until) = details.grace_until {
                metadata.insert("grace_until".to_owned(), json!(grace_until));
            }
            ("SUCCESS", Some(details.profile_id.as_str()))
        }
        ResolveAuditOutcome::Failure(error) => {
            metadata.insert("status".to_owned(), json!("FAILURE"));
            metadata.insert("failure_reason".to_owned(), json!(error.error));
            metadata.insert("exit_code".to_owned(), json!(error.kind.exit_code()));
            ("FAILURE", None)
        }
    };
    let metadata = Value::Object(metadata);
    let audit = AuditWrite {
        project_id,
        profile_id,
        action: "RESOLVE_REFERENCE",
        status,
        secret_name: Some(parsed.key().as_str()),
        command: None,
        metadata_json: &metadata,
        timestamp,
    };
    store.append_audit(audit_key.as_ref(), &audit).map_err(|_| corrupt_db())?;
    Ok(())
}

fn authorize_policy_reference(
    store: &Store,
    project_id: &str,
    policy_name: &str,
    secret_name: &str,
) -> Result<(), ResolveFailure> {
    let Some(policy) =
        store.get_command_policy_index(project_id, policy_name).map_err(|_| corrupt_db())?
    else {
        return Err(ResolveFailure::new(
            ERROR_POLICY_NOT_FOUND,
            "command policy not found",
            LocketError::PolicyNotFound,
        ));
    };
    let Some(allowed_secrets) =
        policy.normalized_json.get("allowed_secrets").and_then(serde_json::Value::as_array)
    else {
        return Err(corrupt_db());
    };
    let authorized = allowed_secrets
        .iter()
        .filter_map(serde_json::Value::as_str)
        .any(|allowed| allowed == secret_name);
    if authorized {
        Ok(())
    } else {
        Err(ResolveFailure::new(
            ERROR_ACCESS_DENIED,
            "command policy does not authorize the reference",
            LocketError::AccessDenied,
        ))
    }
}

fn select_secret(
    store: &Store,
    project_id: &str,
    profile_id: &str,
    parsed: &LkReferenceUri,
) -> Result<SecretRecord, ResolveFailure> {
    if let Some(source) = parsed.source() {
        let secret = store
            .get_secret_by_source(project_id, profile_id, parsed.key().as_str(), source.as_str())
            .map_err(|_| corrupt_db())?
            .ok_or_else(|| {
                ResolveFailure::new(
                    ERROR_SECRET_NOT_FOUND,
                    "secret not found",
                    LocketError::SecretNotFound,
                )
            })?;
        if secret.state == "deleted" {
            return Err(ResolveFailure::new(
                ERROR_SECRET_DELETED,
                "secret source is deleted",
                LocketError::SecretDeleted,
            ));
        }
        return Ok(secret);
    }

    let active = store
        .list_secrets_by_name(project_id, profile_id, parsed.key().as_str())
        .map_err(|_| corrupt_db())?
        .into_iter()
        .filter(|secret| secret.state == "active")
        .collect::<Vec<_>>();
    let highest =
        active.iter().map(|secret| source_precedence(&secret.source)).max().ok_or_else(|| {
            ResolveFailure::new(
                ERROR_SECRET_NOT_FOUND,
                "secret not found",
                LocketError::SecretNotFound,
            )
        })?;
    active.into_iter().find(|secret| source_precedence(&secret.source) == highest).ok_or_else(
        || {
            ResolveFailure::new(
                ERROR_SECRET_NOT_FOUND,
                "secret not found",
                LocketError::SecretNotFound,
            )
        },
    )
}

fn validate_version(
    secret: &SecretRecord,
    version: &SecretVersionRecord,
    pinned: bool,
    now_unix_nanos: i128,
) -> Result<(), ResolveFailure> {
    if secret.state == "deleted" {
        return Err(ResolveFailure::new(
            ERROR_SECRET_DELETED,
            "secret source is deleted",
            LocketError::SecretDeleted,
        ));
    }
    if !pinned && version.state == "current" {
        return Ok(());
    }
    if pinned && version.state == "current" {
        return Ok(());
    }
    if pinned
        && version.state == "deprecated"
        && version.grace_until.is_some_and(|grace_until| i128::from(grace_until) > now_unix_nanos)
    {
        return Ok(());
    }
    Err(ResolveFailure::new(
        ERROR_SECRET_VERSION_EXPIRED,
        "secret version is expired",
        LocketError::SecretVersionExpired,
    ))
}

fn decrypt_secret(
    store: &Store,
    project_id: &str,
    profile_id: &str,
    secret: &SecretRecord,
    version: u32,
    master_key: &locket_crypto::KeyBytes,
) -> Result<zeroize::Zeroizing<String>, locket_crypto::CryptoError> {
    let profile_secret_key = load_profile_key_with_master(
        store,
        project_id,
        profile_id,
        KeyPurpose::ProfileSecret,
        master_key,
    )?;
    let blob = store
        .get_blob(&secret.id, version)
        .map_err(|_| locket_crypto::CryptoError::DecryptionFailed)?
        .ok_or(locket_crypto::CryptoError::DecryptionFailed)?;
    let value_aad = secret_blob_aad_v1(&locket_crypto::SecretBlobAad::new(
        project_id,
        profile_id,
        &secret.id,
        &secret.name,
        version,
    ))?;
    let wrap_aad = key_wrap_aad_v1(&KeyWrapAad::new(
        project_id,
        &secret.id,
        Some(profile_id),
        version,
        KeyWrapPurpose::SecretDek,
    ))?;
    let encrypted = EncryptedSecretValue {
        encrypted_dek: blob.encrypted_dek,
        ciphertext: blob.ciphertext,
        value_nonce: blob.value_nonce,
        aad_schema_version: blob.aad_schema_version,
    };
    decrypt_secret_value_v1(&profile_secret_key, &encrypted, &value_aad, &wrap_aad)
}

fn load_profile_key_with_master(
    store: &Store,
    project_id: &str,
    profile_id: &str,
    purpose: KeyPurpose,
    master_key: &locket_crypto::KeyBytes,
) -> Result<zeroize::Zeroizing<locket_crypto::KeyBytes>, locket_crypto::CryptoError> {
    let record = store
        .get_key_by_scope(project_id, Some(profile_id), purpose.as_str())
        .map_err(|_| locket_crypto::CryptoError::DecryptionFailed)?
        .ok_or(locket_crypto::CryptoError::DecryptionFailed)?;
    let wrapping_key = derive_wrapping_key_v1(
        master_key,
        &HkdfWrapInfo::new(project_id, Some(profile_id), purpose),
    )?;
    let aad = key_wrap_aad_v1(&KeyWrapAad::new(
        project_id,
        &record.id,
        Some(profile_id),
        0,
        KeyWrapPurpose::from(purpose),
    ))?;
    let wrapped = WrappedKeyMaterial { ciphertext: record.wrapped_material, nonce: record.nonce };
    unwrap_key_material_v1(&wrapping_key, &wrapped, &aad)
}

fn load_project_key_with_master(
    store: &Store,
    project_id: &str,
    purpose: KeyPurpose,
    master_key: &locket_crypto::KeyBytes,
) -> Result<zeroize::Zeroizing<locket_crypto::KeyBytes>, locket_crypto::CryptoError> {
    let record = store
        .get_key_by_scope(project_id, None, purpose.as_str())
        .map_err(|_| locket_crypto::CryptoError::DecryptionFailed)?
        .ok_or(locket_crypto::CryptoError::DecryptionFailed)?;
    let wrapping_key =
        derive_wrapping_key_v1(master_key, &HkdfWrapInfo::new(project_id, None, purpose))?;
    let aad = key_wrap_aad_v1(&KeyWrapAad::new(
        project_id,
        &record.id,
        None,
        0,
        KeyWrapPurpose::from(purpose),
    ))?;
    let wrapped = WrappedKeyMaterial { ciphertext: record.wrapped_material, nonce: record.nonce };
    unwrap_key_material_v1(&wrapping_key, &wrapped, &aad)
}

fn key_array(bytes: &[u8]) -> Option<locket_crypto::KeyBytes> {
    bytes.try_into().ok()
}

const fn source_precedence(source: &str) -> u8 {
    match source.as_bytes() {
        b"team-managed" => 1,
        b"user-local" => 2,
        b"machine-local" => 3,
        _ => 0,
    }
}

const fn corrupt_db() -> ResolveFailure {
    ResolveFailure::new(ERROR_CORRUPT_DB, "reference resolution failed", LocketError::CorruptDb)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::panic)]

    use super::{ERROR_GRANT_REQUIRED, ResolveRequest, ResolveResponse, handle_resolve};
    use crate::PROTOCOL_VERSION;
    use crate::envelope::{RequestEnvelope, ResponseEnvelope};
    use crate::grant::{GrantAction, GrantBinding, GrantRecord, GrantRecordFields};
    use crate::method::AgentMethod;
    use crate::server::AgentSocketState;
    use crate::unlock_cache::{UnlockEntry, UnlockMethod};
    use locket_core::LocketError;
    use locket_crypto::{
        HkdfWrapInfo, KeyPurpose, KeyWrapAad, KeyWrapPurpose, SecretBlobAad,
        derive_wrapping_key_v1, encrypt_secret_value_v1, key_wrap_aad_v1, secret_blob_aad_v1,
        secret_fingerprint_v1, wrap_key_material_v1,
    };
    use locket_store::{
        KeyRecord, SecretBlobRecord, SecretFingerprintRecord, SecretRecord, SecretVersionRecord,
        Store,
    };
    use serde_json::json;
    use std::path::PathBuf;
    use std::time::Duration;
    use tempfile::{TempDir, tempdir};

    const PROJECT_ID: &str = "lk_proj_resolve";
    const PROFILE_ID: &str = "lk_prof_dev";
    const PROFILE_NAME: &str = "dev";
    const SECRET_ID: &str = "lk_sec_resolve";
    const SECRET_NAME: &str = "DATABASE_URL";
    const GRANT_ID: &str = "lk_grant_resolve";
    const POLICY_NAME: &str = "deploy";

    struct ResolveFixture {
        _directory: TempDir,
        store_path: PathBuf,
        master_key: locket_crypto::KeyBytes,
        profile_secret_key: locket_crypto::KeyBytes,
        profile_fingerprint_key: locket_crypto::KeyBytes,
        expected_value: String,
    }

    fn resolve_request(fixture: &ResolveFixture) -> ResolveRequest {
        ResolveRequest {
            reference: format!("lk://{PROFILE_NAME}/{SECRET_NAME}"),
            project_id: Some(PROJECT_ID.to_owned()),
            profile_id: Some(PROFILE_ID.to_owned()),
            policy_name: Some(POLICY_NAME.to_owned()),
            store_path: Some(fixture.store_path.display().to_string()),
            grant_id: Some(GRANT_ID.to_owned()),
            binding: Some(GrantBinding::new(std::process::id(), "0")),
        }
    }

    fn test_grant_record(expires_at_unix_nanos: i128) -> GrantRecord {
        GrantRecord::new(GrantRecordFields {
            grant_id: GRANT_ID.to_owned(),
            project_id: PROJECT_ID.to_owned(),
            profile_id: PROFILE_ID.to_owned(),
            action: GrantAction::ResolveReference,
            binding: GrantBinding::new(std::process::id(), "0"),
            issued_at_unix_nanos: 0,
            ttl_seconds: 30,
            expires_at_unix_nanos,
        })
    }

    fn build_fixture() -> Result<ResolveFixture, Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let store_path = directory.path().join("store.db");
        let mut store = Store::open(&store_path)?;
        store.initialize_schema()?;
        store.insert_project_if_absent(PROJECT_ID, "resolve-test", 1)?;
        store.insert_profile_if_absent(PROFILE_ID, PROJECT_ID, PROFILE_NAME, false, 1)?;
        insert_policy_index(&mut store, POLICY_NAME, &[SECRET_NAME])?;

        let master_key = [7_u8; 32];
        let audit_key = [10_u8; 32];
        let profile_secret_key = [8_u8; 32];
        let profile_fingerprint_key = [9_u8; 32];
        insert_wrapped_project_key(
            &store,
            "lk_key_project_audit",
            KeyPurpose::Audit,
            &master_key,
            &audit_key,
        )?;
        insert_wrapped_profile_key(
            &store,
            "lk_key_profile_secret",
            KeyPurpose::ProfileSecret,
            &master_key,
            &profile_secret_key,
        )?;
        insert_wrapped_profile_key(
            &store,
            "lk_key_profile_fingerprint",
            KeyPurpose::ProfileFingerprint,
            &master_key,
            &profile_fingerprint_key,
        )?;

        let expected_value = "resolved test value".to_owned();
        insert_encrypted_secret(
            &mut store,
            SECRET_ID,
            "user-local",
            &profile_secret_key,
            &profile_fingerprint_key,
            &expected_value,
        )?;
        Ok(ResolveFixture {
            _directory: directory,
            store_path,
            master_key,
            profile_secret_key,
            profile_fingerprint_key,
            expected_value,
        })
    }

    fn insert_policy_index(
        store: &mut Store,
        policy_name: &str,
        allowed_secrets: &[&str],
    ) -> Result<(), Box<dyn std::error::Error>> {
        store.upsert_command_policy_index(
            PROJECT_ID,
            policy_name,
            &json!({ "argv": ["pnpm", "deploy"] }),
            &json!({
                "schema_version": 1,
                "name": policy_name,
                "allowed_secrets": allowed_secrets,
            }),
            1,
            None,
        )?;
        Ok(())
    }

    fn insert_wrapped_project_key(
        store: &Store,
        key_id: &str,
        purpose: KeyPurpose,
        master_key: &locket_crypto::KeyBytes,
        key_material: &locket_crypto::KeyBytes,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let wrapping_key =
            derive_wrapping_key_v1(master_key, &HkdfWrapInfo::new(PROJECT_ID, None, purpose))?;
        let aad = key_wrap_aad_v1(&KeyWrapAad::new(
            PROJECT_ID,
            key_id,
            None,
            0,
            KeyWrapPurpose::from(purpose),
        ))?;
        let wrapped = wrap_key_material_v1(&wrapping_key, key_material, &aad)?;
        store.insert_key(&KeyRecord {
            id: key_id.to_owned(),
            project_id: PROJECT_ID.to_owned(),
            profile_id: None,
            purpose: purpose.as_str().to_owned(),
            wrapped_material: wrapped.ciphertext,
            nonce: wrapped.nonce,
            created_at: 1,
        })?;
        Ok(())
    }

    fn insert_wrapped_profile_key(
        store: &Store,
        key_id: &str,
        purpose: KeyPurpose,
        master_key: &locket_crypto::KeyBytes,
        key_material: &locket_crypto::KeyBytes,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let wrapping_key = derive_wrapping_key_v1(
            master_key,
            &HkdfWrapInfo::new(PROJECT_ID, Some(PROFILE_ID), purpose),
        )?;
        let aad = key_wrap_aad_v1(&KeyWrapAad::new(
            PROJECT_ID,
            key_id,
            Some(PROFILE_ID),
            0,
            KeyWrapPurpose::from(purpose),
        ))?;
        let wrapped = wrap_key_material_v1(&wrapping_key, key_material, &aad)?;
        store.insert_key(&KeyRecord {
            id: key_id.to_owned(),
            project_id: PROJECT_ID.to_owned(),
            profile_id: Some(PROFILE_ID.to_owned()),
            purpose: purpose.as_str().to_owned(),
            wrapped_material: wrapped.ciphertext,
            nonce: wrapped.nonce,
            created_at: 1,
        })?;
        Ok(())
    }

    fn insert_encrypted_secret(
        store: &mut Store,
        secret_id: &str,
        source: &str,
        profile_secret_key: &locket_crypto::KeyBytes,
        profile_fingerprint_key: &locket_crypto::KeyBytes,
        value: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let value_aad = secret_blob_aad_v1(&SecretBlobAad::new(
            PROJECT_ID,
            PROFILE_ID,
            secret_id,
            SECRET_NAME,
            1,
        ))?;
        let wrap_aad = key_wrap_aad_v1(&KeyWrapAad::new(
            PROJECT_ID,
            secret_id,
            Some(PROFILE_ID),
            1,
            KeyWrapPurpose::SecretDek,
        ))?;
        let encrypted = encrypt_secret_value_v1(profile_secret_key, value, &value_aad, &wrap_aad)?;
        let fingerprint = secret_fingerprint_v1(profile_fingerprint_key, value)?;
        let secret = SecretRecord {
            id: secret_id.to_owned(),
            project_id: PROJECT_ID.to_owned(),
            profile_id: PROFILE_ID.to_owned(),
            name: SECRET_NAME.to_owned(),
            source: source.to_owned(),
            origin: "manual".to_owned(),
            current_version: 1,
            state: "active".to_owned(),
            created_at: 1,
            updated_at: 1,
            last_rotated_at: None,
            deleted_at: None,
        };
        let version = SecretVersionRecord {
            secret_id: secret_id.to_owned(),
            version: 1,
            source: source.to_owned(),
            origin: "manual".to_owned(),
            state: "current".to_owned(),
            created_at: 1,
            deprecated_at: None,
            grace_until: None,
            purged_at: None,
        };
        let blob = SecretBlobRecord {
            secret_id: secret_id.to_owned(),
            version: 1,
            encrypted_dek: encrypted.encrypted_dek,
            ciphertext: encrypted.ciphertext,
            value_nonce: encrypted.value_nonce,
            aad_schema_version: 1,
            created_at: 1,
        };
        let fingerprint = SecretFingerprintRecord {
            secret_id: secret_id.to_owned(),
            version: 1,
            fingerprint: fingerprint.to_vec(),
            created_at: 1,
        };
        store.create_active_secret(&secret, &version, &blob, &fingerprint)?;
        Ok(())
    }

    fn rotate_encrypted_secret(
        store: &mut Store,
        version_number: u32,
        value: &str,
        grace_until: Option<i64>,
        profile_secret_key: &locket_crypto::KeyBytes,
        profile_fingerprint_key: &locket_crypto::KeyBytes,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let secret = store
            .get_secret_by_source(PROJECT_ID, PROFILE_ID, SECRET_NAME, "user-local")?
            .ok_or("missing secret to rotate")?;
        let value_aad = secret_blob_aad_v1(&SecretBlobAad::new(
            PROJECT_ID,
            PROFILE_ID,
            &secret.id,
            SECRET_NAME,
            version_number,
        ))?;
        let wrap_aad = key_wrap_aad_v1(&KeyWrapAad::new(
            PROJECT_ID,
            &secret.id,
            Some(PROFILE_ID),
            version_number,
            KeyWrapPurpose::SecretDek,
        ))?;
        let encrypted = encrypt_secret_value_v1(profile_secret_key, value, &value_aad, &wrap_aad)?;
        let fingerprint = secret_fingerprint_v1(profile_fingerprint_key, value)?;
        let version = SecretVersionRecord {
            secret_id: secret.id.clone(),
            version: version_number,
            source: secret.source.clone(),
            origin: "manual".to_owned(),
            state: "current".to_owned(),
            created_at: 2,
            deprecated_at: None,
            grace_until: None,
            purged_at: None,
        };
        let blob = SecretBlobRecord {
            secret_id: secret.id.clone(),
            version: version_number,
            encrypted_dek: encrypted.encrypted_dek,
            ciphertext: encrypted.ciphertext,
            value_nonce: encrypted.value_nonce,
            aad_schema_version: 1,
            created_at: 2,
        };
        let fingerprint = SecretFingerprintRecord {
            secret_id: secret.id.clone(),
            version: version_number,
            fingerprint: fingerprint.to_vec(),
            created_at: 2,
        };
        store.rotate_secret(&secret, &version, &blob, &fingerprint, 2, grace_until)?;
        Ok(())
    }

    async fn unlocked_state(fixture: &ResolveFixture) -> AgentSocketState {
        let state = AgentSocketState::locked("test-version");
        state.grants.lock().await.insert(test_grant_record(i128::MAX));
        state.unlock_cache.lock().await.insert(
            PROJECT_ID.to_owned(),
            UnlockEntry::new(
                fixture.master_key.to_vec(),
                0,
                Duration::from_secs(60),
                UnlockMethod::Passphrase,
            ),
        );
        state
    }

    async fn resolve_with_fixture(
        fixture: &ResolveFixture,
        reference: impl Into<String>,
        now_unix_nanos: i128,
    ) -> Result<ResponseEnvelope, Box<dyn std::error::Error>> {
        let state = unlocked_state(fixture).await;
        let mut request = resolve_request(fixture);
        request.reference = reference.into();
        let envelope = RequestEnvelope::new(
            "req-resolve-fixture",
            AgentMethod::ResolveReference,
            serde_json::to_value(request)?,
        );
        Ok(handle_resolve(&envelope, &state, now_unix_nanos).await)
    }

    fn error_code(response: ResponseEnvelope) -> Result<String, Box<dyn std::error::Error>> {
        let ResponseEnvelope::Error(error) = response else {
            return Err("expected error envelope".into());
        };
        Ok(error.error)
    }

    fn resolve_payload(
        response: ResponseEnvelope,
    ) -> Result<ResolveResponse, Box<dyn std::error::Error>> {
        let ResponseEnvelope::Success(success) = response else {
            return Err(format!("expected success envelope, got {response:?}").into());
        };
        Ok(serde_json::from_value(success.payload)?)
    }

    fn resolve_audit_metadata(
        fixture: &ResolveFixture,
    ) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
        let store = Store::open(&fixture.store_path)?;
        let mut statement = store.connection().prepare(
            "SELECT action, status, secret_name, command, metadata_json
             FROM audit_log
             WHERE project_id = ?1
             ORDER BY sequence",
        )?;
        let rows = statement
            .query_map([PROJECT_ID], |row| {
                let action: String = row.get(0)?;
                let status: String = row.get(1)?;
                let secret_name: Option<String> = row.get(2)?;
                let command: Option<String> = row.get(3)?;
                let metadata: String = row.get(4)?;
                Ok((action, status, secret_name, command, metadata))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        rows.into_iter()
            .map(|(action, status, secret_name, command, metadata)| {
                let metadata: serde_json::Value = serde_json::from_str(&metadata)?;
                assert_eq!(action, "RESOLVE_REFERENCE");
                assert_eq!(metadata["action"], "RESOLVE_REFERENCE");
                assert_eq!(metadata["status"], status);
                assert_eq!(secret_name.as_deref(), Some(SECRET_NAME));
                assert!(command.is_none());
                Ok(metadata)
            })
            .collect()
    }

    #[test]
    fn resolve_request_round_trips_through_json() -> Result<(), serde_json::Error> {
        let request = ResolveRequest {
            reference: "lk://dev/DATABASE_URL@v3".to_owned(),
            project_id: Some(PROJECT_ID.to_owned()),
            profile_id: Some(PROFILE_ID.to_owned()),
            policy_name: Some(POLICY_NAME.to_owned()),
            store_path: Some("/tmp/store.db".to_owned()),
            grant_id: Some(GRANT_ID.to_owned()),
            binding: Some(GrantBinding::new(123, "start")),
        };

        let value = serde_json::to_value(&request)?;
        let decoded: ResolveRequest = serde_json::from_value(value.clone())?;

        assert_eq!(decoded, request);
        assert_eq!(value["reference"], "lk://dev/DATABASE_URL@v3");
        assert_eq!(value["policy_name"], POLICY_NAME);
        Ok(())
    }

    #[test]
    fn resolve_response_round_trips_through_json() -> Result<(), serde_json::Error> {
        let response = ResolveResponse {
            value: "resolved test value".to_owned(),
            version: 7,
            profile_id: "profile-prod".to_owned(),
        };

        let value = serde_json::to_value(&response)?;
        let decoded: ResolveResponse = serde_json::from_value(value)?;

        assert_eq!(decoded, response);
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn handle_resolve_returns_grant_required_error() -> Result<(), Box<dyn std::error::Error>>
    {
        let fixture = build_fixture()?;
        let state = AgentSocketState::locked("test-version");
        let envelope = RequestEnvelope::new(
            "req-resolve",
            AgentMethod::ResolveReference,
            serde_json::to_value(resolve_request(&fixture))?,
        );

        let response = handle_resolve(&envelope, &state, 1).await;
        let ResponseEnvelope::Error(error) = response else {
            panic!("expected error envelope");
        };
        assert_eq!(error.v, PROTOCOL_VERSION);
        assert_eq!(error.id, "req-resolve");
        assert_eq!(error.error, ERROR_GRANT_REQUIRED);
        assert!(!error.retryable);
        assert!(!error.message.is_empty());
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn handle_resolve_rejects_malformed_payload_with_protocol_error() {
        let state = AgentSocketState::locked("test-version");
        let envelope = RequestEnvelope::new(
            "req-bad",
            AgentMethod::ResolveReference,
            json!({"reference": 1234}),
        );

        let response = handle_resolve(&envelope, &state, 1).await;
        let ResponseEnvelope::Error(error) = response else {
            panic!("expected error envelope");
        };
        assert_eq!(error.error, "ProtocolError");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn handle_resolve_returns_value_with_live_grant_and_unlock()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = build_fixture()?;
        let state = unlocked_state(&fixture).await;
        let envelope = RequestEnvelope::new(
            "req-ok",
            AgentMethod::ResolveReference,
            serde_json::to_value(resolve_request(&fixture))?,
        );

        let response = handle_resolve(&envelope, &state, 1).await;
        let payload = resolve_payload(response)?;
        assert!(payload.value == fixture.expected_value, "resolved value mismatch");
        assert_eq!(payload.version, 1);
        assert_eq!(payload.profile_id, PROFILE_ID);
        let audits = resolve_audit_metadata(&fixture)?;
        assert_eq!(audits.len(), 1);
        assert_eq!(audits[0]["status"], "SUCCESS");
        assert_eq!(audits[0]["policy"], POLICY_NAME);
        assert_eq!(audits[0]["profile_id"], PROFILE_ID);
        assert_eq!(audits[0]["profile_name"], PROFILE_NAME);
        assert_eq!(audits[0]["secret_name"], SECRET_NAME);
        assert_eq!(audits[0]["source"], "user-local");
        assert_eq!(audits[0]["selected_version"], 1);
        assert!(audits[0].get("value").is_none());
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn handle_resolve_requires_caller_policy_name() -> Result<(), Box<dyn std::error::Error>>
    {
        let fixture = build_fixture()?;
        let state = unlocked_state(&fixture).await;
        let mut request = resolve_request(&fixture);
        request.policy_name = None;
        let envelope = RequestEnvelope::new(
            "req-missing-policy-name",
            AgentMethod::ResolveReference,
            serde_json::to_value(request)?,
        );

        let response = handle_resolve(&envelope, &state, 1).await;
        assert_eq!(error_code(response)?, "ProtocolError");
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn handle_resolve_returns_policy_not_found_for_unknown_policy()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = build_fixture()?;
        let state = unlocked_state(&fixture).await;
        let mut request = resolve_request(&fixture);
        request.policy_name = Some("missing-policy".to_owned());
        let envelope = RequestEnvelope::new(
            "req-missing-policy",
            AgentMethod::ResolveReference,
            serde_json::to_value(request)?,
        );

        let response = handle_resolve(&envelope, &state, 1).await;
        assert_eq!(error_code(response)?, "PolicyNotFound");
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn handle_resolve_denies_secret_not_allowed_by_policy()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = build_fixture()?;
        let mut store = Store::open(&fixture.store_path)?;
        insert_policy_index(&mut store, "deny-database", &["OTHER_SECRET"])?;
        let state = unlocked_state(&fixture).await;
        let mut request = resolve_request(&fixture);
        request.policy_name = Some("deny-database".to_owned());
        let envelope = RequestEnvelope::new(
            "req-policy-denied",
            AgentMethod::ResolveReference,
            serde_json::to_value(request)?,
        );

        let response = handle_resolve(&envelope, &state, 1).await;
        assert_eq!(error_code(response)?, "AccessDenied");
        let audits = resolve_audit_metadata(&fixture)?;
        assert_eq!(audits.len(), 1);
        assert_eq!(audits[0]["status"], "FAILURE");
        assert_eq!(audits[0]["failure_reason"], "AccessDenied");
        assert_eq!(audits[0]["exit_code"], LocketError::AccessDenied.exit_code());
        assert_eq!(audits[0]["policy"], "deny-database");
        assert_eq!(audits[0]["secret_name"], SECRET_NAME);
        assert!(audits[0].get("value").is_none());
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn handle_resolve_honors_pinned_current_version() -> Result<(), Box<dyn std::error::Error>>
    {
        let fixture = build_fixture()?;
        let version_two_value = "resolved test value v2";
        let mut store = Store::open(&fixture.store_path)?;
        rotate_encrypted_secret(
            &mut store,
            2,
            version_two_value,
            None,
            &fixture.profile_secret_key,
            &fixture.profile_fingerprint_key,
        )?;

        let unpinned = resolve_with_fixture(&fixture, "lk://dev/DATABASE_URL", 1).await?;
        let unpinned = resolve_payload(unpinned)?;
        assert_eq!(unpinned.version, 2);
        assert_eq!(unpinned.value, version_two_value);

        let pinned = resolve_with_fixture(&fixture, "lk://dev/DATABASE_URL@v2", 1).await?;
        let pinned = resolve_payload(pinned)?;
        assert_eq!(pinned.version, 2);
        assert_eq!(pinned.value, version_two_value);
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn handle_resolve_pinned_missing_version_does_not_fallback()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = build_fixture()?;
        let response = resolve_with_fixture(&fixture, "lk://dev/DATABASE_URL@v99", 1).await?;

        assert_eq!(error_code(response)?, "SecretNotFound");
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn handle_resolve_denies_profile_outside_live_grant()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = build_fixture()?;
        let store = Store::open(&fixture.store_path)?;
        store.insert_profile_if_absent("lk_prof_prod", PROJECT_ID, "prod", false, 1)?;
        let state = unlocked_state(&fixture).await;
        let mut request = resolve_request(&fixture);
        request.reference = "lk://prod/DATABASE_URL".to_owned();
        let envelope = RequestEnvelope::new(
            "req-profile-denied",
            AgentMethod::ResolveReference,
            serde_json::to_value(request)?,
        );

        let response = handle_resolve(&envelope, &state, 1).await;
        assert_eq!(error_code(response)?, "AccessDenied");
        let audits = resolve_audit_metadata(&fixture)?;
        assert_eq!(audits.len(), 1);
        assert_eq!(audits[0]["status"], "FAILURE");
        assert_eq!(audits[0]["failure_reason"], "AccessDenied");
        assert_eq!(audits[0]["profile_name"], "prod");
        assert!(audits[0].get("value").is_none());
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn handle_resolve_uses_precedence_unless_source_is_explicit()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = build_fixture()?;
        let machine_value = "resolved machine-local test value";
        let mut store = Store::open(&fixture.store_path)?;
        insert_encrypted_secret(
            &mut store,
            "lk_sec_resolve_machine",
            "machine-local",
            &fixture.profile_secret_key,
            &fixture.profile_fingerprint_key,
            machine_value,
        )?;

        let implicit = resolve_with_fixture(&fixture, "lk://dev/DATABASE_URL", 1).await?;
        assert_eq!(resolve_payload(implicit)?.value, machine_value);

        let explicit =
            resolve_with_fixture(&fixture, "lk://dev/DATABASE_URL?source=user-local", 1).await?;
        assert_eq!(resolve_payload(explicit)?.value, fixture.expected_value);
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn handle_resolve_requires_unlock_after_grant() -> Result<(), Box<dyn std::error::Error>>
    {
        let fixture = build_fixture()?;
        let state = AgentSocketState::locked("test-version");
        state.grants.lock().await.insert(test_grant_record(i128::MAX));
        let envelope = RequestEnvelope::new(
            "req-locked",
            AgentMethod::ResolveReference,
            serde_json::to_value(resolve_request(&fixture))?,
        );

        let response = handle_resolve(&envelope, &state, 1).await;
        let ResponseEnvelope::Error(error) = response else {
            return Err("expected unlock-required error".into());
        };
        assert_eq!(error.error, "UnlockRequired");

        let degraded_log = fixture
            .store_path
            .parent()
            .ok_or("store path should have parent")?
            .join(locket_platform::DEGRADED_AUDIT_LOG_FILENAME);
        let body = std::fs::read_to_string(&degraded_log)?;
        let row: serde_json::Value =
            serde_json::from_str(body.lines().next().ok_or("expected degraded audit row")?)?;
        assert_eq!(row["action"], "RESOLVE_REFERENCE");
        assert_eq!(row["status"], "DENIED_LOCKED");
        assert_eq!(row["command"], "agent.ResolveReference");
        assert_eq!(row["project_id"], PROJECT_ID);
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn handle_resolve_rejects_invalid_lk_reference() {
        let state = AgentSocketState::locked("test-version");
        let envelope = RequestEnvelope::new(
            "req-invalid",
            AgentMethod::ResolveReference,
            json!({ "reference": "not-a-reference" }),
        );

        let response = handle_resolve(&envelope, &state, 1).await;
        let ResponseEnvelope::Error(error) = response else {
            panic!("expected error envelope");
        };
        assert_eq!(error.error, "InvalidReference");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn handle_resolve_rejects_missing_profile() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = build_fixture()?;
        let response = resolve_with_fixture(&fixture, "lk://missing/DATABASE_URL", 1).await?;

        assert_eq!(error_code(response)?, "ProfileNotFound");
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn handle_resolve_rejects_missing_secret() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = build_fixture()?;
        let mut store = Store::open(&fixture.store_path)?;
        insert_policy_index(&mut store, "allow-missing", &["MISSING_KEY"])?;
        let state = unlocked_state(&fixture).await;
        let mut request = resolve_request(&fixture);
        request.reference = "lk://dev/MISSING_KEY".to_owned();
        request.policy_name = Some("allow-missing".to_owned());
        let envelope = RequestEnvelope::new(
            "req-missing-secret",
            AgentMethod::ResolveReference,
            serde_json::to_value(request)?,
        );

        let response = handle_resolve(&envelope, &state, 1).await;
        assert_eq!(error_code(response)?, "SecretNotFound");
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn handle_resolve_rejects_deleted_secret() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = build_fixture()?;
        let store = Store::open(&fixture.store_path)?;
        store
            .connection()
            .execute("UPDATE secrets SET state = 'deleted' WHERE id = ?1", [&SECRET_ID])?;
        let response =
            resolve_with_fixture(&fixture, "lk://dev/DATABASE_URL?source=user-local", 1).await?;

        assert_eq!(error_code(response)?, "SecretDeleted");
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn handle_resolve_rejects_expired_secret_version()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = build_fixture()?;
        let store = Store::open(&fixture.store_path)?;
        store.connection().execute(
            "UPDATE secret_versions SET state = 'deprecated', grace_until = 0 WHERE secret_id = ?1 AND version = 1",
            [&SECRET_ID],
        )?;
        let response = resolve_with_fixture(&fixture, "lk://dev/DATABASE_URL@v1", 1).await?;

        assert_eq!(error_code(response)?, "SecretVersionExpired");
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn handle_resolve_maps_store_open_failure_to_corrupt_db()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = build_fixture()?;
        let state = unlocked_state(&fixture).await;
        let mut request = resolve_request(&fixture);
        request.store_path = Some(
            fixture
                .store_path
                .parent()
                .ok_or("fixture store path missing parent")?
                .display()
                .to_string(),
        );
        let envelope = RequestEnvelope::new(
            "req-corrupt",
            AgentMethod::ResolveReference,
            serde_json::to_value(request)?,
        );

        let response = handle_resolve(&envelope, &state, 1).await;
        assert_eq!(error_code(response)?, "CorruptDb");
        Ok(())
    }
}
