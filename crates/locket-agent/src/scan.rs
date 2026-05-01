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
//! semantics. The handler accepts already-read text buffers, decrypts
//! known values only from a live unlock-cache entry, and returns
//! redacted match metadata without persisting or returning values.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use locket_core::{LocketError, privacy_alias};
use locket_crypto::{
    EncryptedSecretValue, HkdfWrapInfo, KeyPurpose, KeyWrapAad, KeyWrapPurpose, WrappedKeyMaterial,
    decrypt_secret_value_v1, derive_wrapping_key_v1, key_wrap_aad_v1, secret_blob_aad_v1,
    unwrap_key_material_v1,
};
use locket_store::{AuditWrite, SecretRecord, SecretVersionRecord, Store};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use zeroize::Zeroizing;

use crate::envelope::{ErrorEnvelope, RequestEnvelope, ResponseEnvelope, SuccessEnvelope};
use crate::grant::{GrantAction, GrantBinding, GrantValidation};

const ERROR_GRANT_REQUIRED: &str = "GrantRequired";
const ERROR_UNLOCK_REQUIRED: &str = "UnlockRequired";
const ERROR_PROFILE_NOT_FOUND: &str = "ProfileNotFound";
const ERROR_CORRUPT_DB: &str = "CorruptDb";

const GRANT_REQUIRED_MESSAGE: &str =
    "live grant required to scan known values; request a grant before retrying";
const UNLOCK_REQUIRED_MESSAGE: &str =
    "unlock required to scan known values; unlock the project before retrying";
const AGENT_SCAN_COMMAND: &str = "agent-scan-known-values";

/// Request payload for `ScanKnownValues`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ScanRequest {
    /// Legacy path-only labels. Real scans should populate `inputs`
    /// so the agent never opens files on behalf of UI/editor callers.
    #[serde(default)]
    pub paths: Vec<String>,
    /// Already-read text buffers to match against known values.
    #[serde(default)]
    pub inputs: Vec<ScanInput>,
    /// Project id whose unlock-cache entry and store rows are used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_id: Option<String>,
    /// Profile id authorized by the live grant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_id: Option<String>,
    /// Path to the user-scoped `store.db`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub store_path: Option<PathBuf>,
    /// Live grant id authorizing known-value scanning.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<String>,
    /// Current process binding for the grant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding: Option<GrantBinding>,
    /// When true, the caller is in a "fail closed" mode and wants the
    /// agent to refuse with an explicit unlock-required error when
    /// known-value coverage is unavailable.
    pub require_known: bool,
    /// Whether profile and secret labels should be privacy aliases in
    /// returned findings. Audit metadata keeps exact names only.
    #[serde(default)]
    pub redact_names: bool,
}

/// Already-read text buffer to scan.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ScanInput {
    /// Metadata-only path label supplied by the caller.
    pub path: String,
    /// Text content already held in caller memory.
    pub text: String,
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

/// Handler for `ScanKnownValues`.
///
/// Legacy calls that provide no project/store context still receive
/// the original locked/empty shape so shipped UI stubs remain
/// compatible. Covered scans require a live grant and unlock-cache
/// entry before any store decryption occurs.
#[allow(clippy::too_many_lines)]
pub async fn handle_scan(
    request: &RequestEnvelope,
    state: &crate::server::AgentSocketState,
    now_unix_nanos: i128,
) -> ResponseEnvelope {
    let Ok(typed) = serde_json::from_value::<ScanRequest>(request.payload.clone()) else {
        return ResponseEnvelope::Error(ErrorEnvelope::new(
            request.id.clone(),
            "ProtocolError",
            "invalid ScanKnownValues payload",
            false,
        ));
    };
    if typed.project_id.is_none()
        && typed.profile_id.is_none()
        && typed.store_path.is_none()
        && typed.grant_id.is_none()
        && typed.inputs.is_empty()
    {
        return if typed.require_known {
            crate::degraded_audit::record_locked_refusal(
                "SCAN",
                None,
                "agent.ScanKnownValues",
                None,
                now_unix_nanos,
            );
            unlock_required(request)
        } else {
            success_response(request, &ScanResponse { findings: Vec::new(), locked: true })
        };
    }
    let Some(project_id) = typed.project_id.as_deref() else {
        return protocol_error(request, "ScanKnownValues requires project_id");
    };
    let Some(profile_id) = typed.profile_id.as_deref() else {
        return protocol_error(request, "ScanKnownValues requires profile_id");
    };
    let Some(store_path) = typed.store_path.as_deref() else {
        return protocol_error(request, "ScanKnownValues requires store_path");
    };

    let cached_master_key_for_denial = || async {
        let cache = state.unlock_cache.lock().await;
        cache.lookup(project_id, now_unix_nanos).map(|entry| entry.key_bytes().to_vec())
    };
    let Some(grant_id) = typed.grant_id.as_deref() else {
        let key = cached_master_key_for_denial().await;
        crate::audit_deny::try_append_grant_denial(
            project_id,
            profile_id,
            Some(store_path),
            key.as_deref(),
            GrantAction::ScanKnownValues,
            0,
            now_unix_nanos,
            "agent",
        );
        return grant_required(request);
    };
    let grant_validation = {
        let grants = state.grants.lock().await;
        grants.validate(
            grant_id,
            project_id,
            profile_id,
            GrantAction::ScanKnownValues,
            now_unix_nanos,
            typed.binding.as_ref(),
        )
    };
    if !matches!(grant_validation, GrantValidation::Valid) {
        let key = cached_master_key_for_denial().await;
        crate::audit_deny::try_append_grant_denial(
            project_id,
            profile_id,
            Some(store_path),
            key.as_deref(),
            GrantAction::ScanKnownValues,
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
        return if typed.require_known {
            crate::degraded_audit::record_locked_refusal(
                "SCAN",
                Some(project_id),
                "agent.ScanKnownValues",
                Some(store_path),
                now_unix_nanos,
            );
            unlock_required(request)
        } else {
            success_response(request, &ScanResponse { findings: Vec::new(), locked: true })
        };
    };

    match scan_known_values(&typed, project_id, profile_id, store_path, &master_key, now_unix_nanos)
    {
        Ok(response) => success_response(request, &response),
        Err(error) => typed_failure(request, &error),
    }
}

fn success_response(request: &RequestEnvelope, response: &ScanResponse) -> ResponseEnvelope {
    serde_json::to_value(response).map_or_else(
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

fn protocol_error(request: &RequestEnvelope, message: &str) -> ResponseEnvelope {
    ResponseEnvelope::Error(ErrorEnvelope::new(request.id.clone(), "ProtocolError", message, false))
}

fn grant_required(request: &RequestEnvelope) -> ResponseEnvelope {
    typed_locket_error(
        request,
        ERROR_GRANT_REQUIRED,
        GRANT_REQUIRED_MESSAGE,
        LocketError::GrantRequired,
    )
}

fn unlock_required(request: &RequestEnvelope) -> ResponseEnvelope {
    typed_locket_error(
        request,
        ERROR_UNLOCK_REQUIRED,
        UNLOCK_REQUIRED_MESSAGE,
        LocketError::UnlockRequired,
    )
}

fn typed_locket_error(
    request: &RequestEnvelope,
    error: &'static str,
    message: &'static str,
    kind: LocketError,
) -> ResponseEnvelope {
    debug_assert!(kind.exit_code() > 0);
    typed_error(request, error, message)
}

fn typed_error(
    request: &RequestEnvelope,
    error: &'static str,
    message: &'static str,
) -> ResponseEnvelope {
    ResponseEnvelope::Error(ErrorEnvelope::new(request.id.clone(), error, message, false))
}

fn typed_failure(request: &RequestEnvelope, error: &ScanFailure) -> ResponseEnvelope {
    debug_assert!(error.kind.exit_code() > 0);
    typed_error(request, error.error, error.message)
}

#[derive(Debug)]
struct ScanFailure {
    error: &'static str,
    message: &'static str,
    kind: LocketError,
}

impl ScanFailure {
    const fn new(error: &'static str, message: &'static str, kind: LocketError) -> Self {
        Self { error, message, kind }
    }
}

struct KnownSecret {
    value: Zeroizing<String>,
    secret_name: String,
    rule_label: String,
}

struct ScanMatches {
    findings: Vec<ScanFinding>,
    matched_secret_names: BTreeSet<String>,
}

fn scan_known_values(
    request: &ScanRequest,
    project_id: &str,
    profile_id: &str,
    store_path: &Path,
    master_key: &[u8],
    now_unix_nanos: i128,
) -> Result<ScanResponse, ScanFailure> {
    let master_key = key_array(master_key).ok_or_else(corrupt_db)?;
    let mut store = Store::open(store_path).map_err(|_| corrupt_db())?;
    ensure_profile_exists(&store, project_id, profile_id)?;
    let known_values =
        collect_known_values(&store, project_id, profile_id, &master_key, now_unix_nanos, request)?;
    let mut matches = ScanMatches { findings: Vec::new(), matched_secret_names: BTreeSet::new() };
    for input in &request.inputs {
        append_input_matches(input, &known_values, &mut matches);
    }
    append_scan_audit(&mut store, project_id, profile_id, &master_key, &matches, now_unix_nanos)?;
    Ok(ScanResponse { findings: matches.findings, locked: false })
}

fn ensure_profile_exists(
    store: &Store,
    project_id: &str,
    profile_id: &str,
) -> Result<(), ScanFailure> {
    let exists = store
        .list_profiles(project_id)
        .map_err(|_| corrupt_db())?
        .iter()
        .any(|profile| profile.id == profile_id);
    if exists {
        Ok(())
    } else {
        Err(ScanFailure::new(
            ERROR_PROFILE_NOT_FOUND,
            "profile not found",
            LocketError::ProfileNotFound,
        ))
    }
}

fn collect_known_values(
    store: &Store,
    project_id: &str,
    profile_id: &str,
    master_key: &locket_crypto::KeyBytes,
    now_unix_nanos: i128,
    request: &ScanRequest,
) -> Result<Vec<KnownSecret>, ScanFailure> {
    let mut known = Vec::new();
    let timestamp = i64::try_from(now_unix_nanos).map_err(|_| corrupt_db())?;
    for secret in store.list_secrets_by_profile(project_id, profile_id).map_err(|_| corrupt_db())? {
        for version in store.list_secret_versions(&secret.id).map_err(|_| corrupt_db())? {
            if should_scan_known_version(&secret, &version, timestamp)
                && store.get_blob(&secret.id, version.version).map_err(|_| corrupt_db())?.is_some()
            {
                let value = decrypt_secret(
                    store,
                    project_id,
                    profile_id,
                    &secret,
                    version.version,
                    master_key,
                )
                .map_err(|_| corrupt_db())?;
                let label = if request.redact_names {
                    privacy_alias("secret", &secret.id)
                } else {
                    secret.name.clone()
                };
                known.push(KnownSecret {
                    value,
                    secret_name: secret.name.clone(),
                    rule_label: format!("known-value/{label}"),
                });
            }
        }
    }
    Ok(known)
}

fn append_input_matches(
    input: &ScanInput,
    known_values: &[KnownSecret],
    matches: &mut ScanMatches,
) {
    for known in known_values {
        if known.value.is_empty() {
            continue;
        }
        let mut cursor = 0;
        while let Some(relative) = input.text[cursor..].find(known.value.as_str()) {
            let start = cursor + relative;
            let (line, column) = line_column_for_byte(&input.text, start);
            matches.findings.push(ScanFinding {
                rule: known.rule_label.clone(),
                path: input.path.clone(),
                line,
                column,
                severity: "error".to_owned(),
                redacted_summary: "known secret value match".to_owned(),
                suppressed_by: None,
            });
            matches.matched_secret_names.insert(known.secret_name.clone());
            cursor = start + known.value.len();
        }
    }
}

fn line_column_for_byte(text: &str, byte_index: usize) -> (u32, u32) {
    let mut line = 1;
    let mut column = 1;
    for (index, character) in text.char_indices() {
        if index >= byte_index {
            break;
        }
        if character == '\n' {
            line += 1;
            column = 1;
        } else {
            column += 1;
        }
    }
    (line, column)
}

fn append_scan_audit(
    store: &mut Store,
    project_id: &str,
    profile_id: &str,
    master_key: &locket_crypto::KeyBytes,
    matches: &ScanMatches,
    timestamp: i128,
) -> Result<(), ScanFailure> {
    let audit_key = load_project_key_with_master(store, project_id, KeyPurpose::Audit, master_key)
        .map_err(|_| corrupt_db())?;
    let timestamp = i64::try_from(timestamp).map_err(|_| corrupt_db())?;
    let mut metadata = Map::from_iter([
        ("schema_version".to_owned(), json!(1)),
        ("action".to_owned(), json!("SCAN")),
        ("status".to_owned(), json!("SUCCESS")),
        ("command".to_owned(), json!(AGENT_SCAN_COMMAND)),
        ("scope".to_owned(), json!("agent")),
        ("profile_id".to_owned(), json!(profile_id)),
        ("known_value_coverage".to_owned(), json!(true)),
        ("pattern_only".to_owned(), json!(false)),
        ("finding_counts".to_owned(), json!({ "known_secret_value": matches.findings.len() })),
    ]);
    if !matches.matched_secret_names.is_empty() {
        metadata.insert(
            "redacted_secret_names".to_owned(),
            json!(matches.matched_secret_names.iter().collect::<Vec<_>>()),
        );
    }
    let metadata = Value::Object(metadata);
    let audit = AuditWrite {
        project_id,
        profile_id: Some(profile_id),
        action: "SCAN",
        status: "SUCCESS",
        secret_name: None,
        command: Some(AGENT_SCAN_COMMAND),
        metadata_json: &metadata,
        timestamp,
    };
    store.append_audit(audit_key.as_ref(), &audit).map_err(|_| corrupt_db())?;
    Ok(())
}

fn should_scan_known_version(
    secret: &SecretRecord,
    version: &SecretVersionRecord,
    timestamp: i64,
) -> bool {
    match version.state.as_str() {
        "current" => secret.state == "active" || version.version == secret.current_version,
        "deprecated" => version.grace_until.is_some_and(|grace_until| grace_until > timestamp),
        _ => false,
    }
}

fn decrypt_secret(
    store: &Store,
    project_id: &str,
    profile_id: &str,
    secret: &SecretRecord,
    version: u32,
    master_key: &locket_crypto::KeyBytes,
) -> Result<Zeroizing<String>, locket_crypto::CryptoError> {
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
) -> Result<Zeroizing<locket_crypto::KeyBytes>, locket_crypto::CryptoError> {
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
) -> Result<Zeroizing<locket_crypto::KeyBytes>, locket_crypto::CryptoError> {
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

const fn corrupt_db() -> ScanFailure {
    ScanFailure::new(ERROR_CORRUPT_DB, "known-value scan failed", LocketError::CorruptDb)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::panic)]

    use super::{ScanFinding, ScanInput, ScanRequest, ScanResponse, handle_scan};
    use crate::envelope::{RequestEnvelope, ResponseEnvelope};
    use crate::grant::{GrantAction, GrantBinding, GrantRecord, GrantRecordFields};
    use crate::method::AgentMethod;
    use crate::server::AgentSocketState;
    use crate::unlock_cache::{UnlockEntry, UnlockMethod};
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

    const PROJECT_ID: &str = "lk_proj_scan";
    const PROFILE_ID: &str = "lk_prof_dev";
    const PROFILE_NAME: &str = "dev";
    const SECRET_ID: &str = "lk_sec_current";
    const SECRET_NAME: &str = "DATABASE_URL";
    const GRACE_SECRET_ID: &str = "lk_sec_grace";
    const GRACE_SECRET_NAME: &str = "API_TOKEN";
    const GRANT_ID: &str = "lk_grant_scan";

    struct ScanFixture {
        _directory: TempDir,
        store_path: PathBuf,
        master_key: locket_crypto::KeyBytes,
        current_value: String,
        grace_value: String,
    }

    #[test]
    fn scan_request_round_trips_through_json() -> Result<(), serde_json::Error> {
        let request = ScanRequest {
            paths: vec!["src/main.rs".to_owned(), ".env".to_owned()],
            inputs: vec![ScanInput { path: "src/main.rs".to_owned(), text: "text".to_owned() }],
            project_id: Some(PROJECT_ID.to_owned()),
            profile_id: Some(PROFILE_ID.to_owned()),
            store_path: Some(PathBuf::from("/tmp/store.db")),
            grant_id: Some(GRANT_ID.to_owned()),
            binding: Some(GrantBinding::new(123, "start")),
            require_known: true,
            redact_names: true,
        };

        let value = serde_json::to_value(&request)?;
        let decoded: ScanRequest = serde_json::from_value(value.clone())?;

        assert_eq!(decoded, request);
        assert_eq!(value["require_known"], true);
        assert_eq!(value["paths"][0], "src/main.rs");
        assert_eq!(value["inputs"][0]["path"], "src/main.rs");
        assert_eq!(value["project_id"], PROJECT_ID);
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

    #[tokio::test(flavor = "current_thread")]
    async fn handle_scan_returns_locked_empty_response_for_legacy_request()
    -> Result<(), serde_json::Error> {
        let state = AgentSocketState::locked("test-version");
        let envelope = RequestEnvelope::new(
            "req-scan",
            AgentMethod::ScanKnownValues,
            json!({"paths": ["src/main.rs"], "require_known": false}),
        );

        let response = handle_scan(&envelope, &state, 1).await;
        let ResponseEnvelope::Success(success) = response else {
            panic!("expected success envelope");
        };
        assert_eq!(success.id, "req-scan");
        let decoded: ScanResponse = serde_json::from_value(success.payload)?;
        assert!(decoded.locked);
        assert!(decoded.findings.is_empty());
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn handle_scan_rejects_malformed_payload_with_protocol_error() {
        let state = AgentSocketState::locked("test-version");
        let envelope =
            RequestEnvelope::new("req-bad", AgentMethod::ScanKnownValues, json!({"paths": 5}));

        let response = handle_scan(&envelope, &state, 1).await;
        let ResponseEnvelope::Error(error) = response else {
            panic!("expected error envelope");
        };
        assert_eq!(error.error, "ProtocolError");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn handle_scan_requires_live_grant() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = build_fixture()?;
        let state = unlocked_state(&fixture, false).await;
        let envelope = scan_envelope(&scan_request(&fixture, true, false));

        let response = handle_scan(&envelope, &state, 1).await;
        assert_eq!(error_code(response)?, "GrantRequired");
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn handle_scan_requires_unlock_when_fail_closed() -> Result<(), Box<dyn std::error::Error>>
    {
        let fixture = build_fixture()?;
        let state = granted_state(true).await;
        let envelope = scan_envelope(&scan_request(&fixture, true, false));

        let response = handle_scan(&envelope, &state, 1).await;
        assert_eq!(error_code(response)?, "UnlockRequired");

        // The scan refusal must mirror into the degraded-audit log when
        // a store path was supplied so its parent is the LOCKET_HOME.
        let degraded_log = fixture
            .store_path
            .parent()
            .ok_or("store path should have parent")?
            .join(locket_platform::DEGRADED_AUDIT_LOG_FILENAME);
        let body = std::fs::read_to_string(&degraded_log)?;
        let row: serde_json::Value =
            serde_json::from_str(body.lines().next().ok_or("expected degraded audit row")?)?;
        assert_eq!(row["action"], "SCAN");
        assert_eq!(row["status"], "DENIED_LOCKED");
        assert_eq!(row["command"], "agent.ScanKnownValues");
        assert_eq!(row["project_id"], PROJECT_ID);
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn handle_scan_returns_locked_gap_when_not_fail_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = build_fixture()?;
        let state = granted_state(true).await;
        let envelope = scan_envelope(&scan_request(&fixture, false, false));

        let response = handle_scan(&envelope, &state, 1).await;
        let payload = scan_payload(response)?;
        assert!(payload.locked);
        assert!(payload.findings.is_empty());
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn handle_scan_matches_known_values_without_leaking_values()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = build_fixture()?;
        let state = unlocked_state(&fixture, true).await;
        let envelope = scan_envelope(&scan_request(&fixture, true, false));

        let response = handle_scan(&envelope, &state, 1).await;
        let response_json = serde_json::to_string(&response)?;
        assert!(!response_json.contains(&fixture.current_value));
        assert!(!response_json.contains(&fixture.grace_value));
        let payload = scan_payload(response)?;
        assert!(!payload.locked);
        assert_eq!(payload.findings.len(), 2);
        let current = payload
            .findings
            .iter()
            .find(|finding| finding.rule == "known-value/DATABASE_URL")
            .ok_or("missing current secret finding")?;
        assert_eq!(current.path, "src/main.rs");
        assert_eq!(current.line, 2);
        assert_eq!(current.column, 1);
        assert_eq!(current.severity, "error");
        assert_eq!(current.redacted_summary, "known secret value match");
        assert!(payload.findings.iter().any(|finding| finding.rule == "known-value/DATABASE_URL"));
        assert!(payload.findings.iter().any(|finding| finding.rule == "known-value/API_TOKEN"));

        let audit = scan_audit_metadata(&fixture)?;
        assert_eq!(audit["status"], "SUCCESS");
        assert_eq!(audit["command"], "agent-scan-known-values");
        assert_eq!(audit["profile_id"], PROFILE_ID);
        assert_eq!(audit["known_value_coverage"], true);
        assert_eq!(audit["pattern_only"], false);
        assert_eq!(audit["finding_counts"]["known_secret_value"], 2);
        assert_eq!(audit["redacted_secret_names"][0], GRACE_SECRET_NAME);
        assert_eq!(audit["redacted_secret_names"][1], SECRET_NAME);
        let audit_json = serde_json::to_string(&audit)?;
        assert!(!audit_json.contains(&fixture.current_value));
        assert!(!audit_json.contains(&fixture.grace_value));
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn handle_scan_uses_privacy_aliases_for_finding_rules()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = build_fixture()?;
        let state = unlocked_state(&fixture, true).await;
        let envelope = scan_envelope(&scan_request(&fixture, true, true));

        let payload = scan_payload(handle_scan(&envelope, &state, 1).await)?;

        assert!(
            payload.findings.iter().all(|finding| finding.rule.starts_with("known-value/secret-"))
        );
        assert!(payload.findings.iter().all(|finding| !finding.rule.contains(SECRET_NAME)));
        assert!(payload.findings.iter().all(|finding| !finding.rule.contains(GRACE_SECRET_NAME)));
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn handle_scan_excludes_deprecated_values_after_grace()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = build_fixture()?;
        let state = unlocked_state(&fixture, true).await;
        let envelope = scan_envelope(&scan_request(&fixture, true, false));

        let payload = scan_payload(handle_scan(&envelope, &state, 100).await)?;

        assert_eq!(payload.findings.len(), 1);
        assert_eq!(payload.findings[0].rule, "known-value/DATABASE_URL");
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn handle_scan_returns_profile_not_found() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = build_fixture()?;
        let state = AgentSocketState::locked("test-version");
        state.grants.lock().await.insert(test_grant_record_for_profile("lk_prof_missing"));
        state.unlock_cache.lock().await.insert(
            PROJECT_ID.to_owned(),
            UnlockEntry::new(
                fixture.master_key.to_vec(),
                0,
                Duration::from_secs(60),
                UnlockMethod::Passphrase,
            ),
        );
        let mut request = scan_request(&fixture, true, false);
        request.profile_id = Some("lk_prof_missing".to_owned());
        let envelope = scan_envelope(&request);

        let response = handle_scan(&envelope, &state, 1).await;

        assert_eq!(error_code(response)?, "ProfileNotFound");
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn handle_scan_maps_store_open_failure_to_corrupt_db()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = build_fixture()?;
        let state = unlocked_state(&fixture, true).await;
        let mut request = scan_request(&fixture, true, false);
        request.store_path = Some(fixture.store_path.with_file_name("missing-store.db"));
        let envelope = scan_envelope(&request);

        let response = handle_scan(&envelope, &state, 1).await;

        assert_eq!(error_code(response)?, "CorruptDb");
        Ok(())
    }

    fn scan_request(fixture: &ScanFixture, require_known: bool, redact_names: bool) -> ScanRequest {
        ScanRequest {
            paths: Vec::new(),
            inputs: vec![ScanInput {
                path: "src/main.rs".to_owned(),
                text: format!("prefix\n{} then {}", fixture.current_value, fixture.grace_value),
            }],
            project_id: Some(PROJECT_ID.to_owned()),
            profile_id: Some(PROFILE_ID.to_owned()),
            store_path: Some(fixture.store_path.clone()),
            grant_id: Some(GRANT_ID.to_owned()),
            binding: Some(GrantBinding::new(std::process::id(), "0")),
            require_known,
            redact_names,
        }
    }

    fn scan_envelope(request: &ScanRequest) -> RequestEnvelope {
        RequestEnvelope::new(
            "req-scan",
            AgentMethod::ScanKnownValues,
            serde_json::to_value(request).unwrap(),
        )
    }

    async fn unlocked_state(fixture: &ScanFixture, grant: bool) -> AgentSocketState {
        let state = granted_state(grant).await;
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

    async fn granted_state(grant: bool) -> AgentSocketState {
        let state = AgentSocketState::locked("test-version");
        if grant {
            state.grants.lock().await.insert(test_grant_record());
        }
        state
    }

    fn test_grant_record() -> GrantRecord {
        test_grant_record_for_profile(PROFILE_ID)
    }

    fn test_grant_record_for_profile(profile_id: &str) -> GrantRecord {
        GrantRecord::new(GrantRecordFields {
            grant_id: GRANT_ID.to_owned(),
            project_id: PROJECT_ID.to_owned(),
            profile_id: profile_id.to_owned(),
            action: GrantAction::ScanKnownValues,
            binding: GrantBinding::new(std::process::id(), "0"),
            issued_at_unix_nanos: 0,
            ttl_seconds: 30,
            expires_at_unix_nanos: 1_000,
        })
    }

    fn scan_payload(
        response: ResponseEnvelope,
    ) -> Result<ScanResponse, Box<dyn std::error::Error>> {
        let ResponseEnvelope::Success(success) = response else {
            return Err(format!("expected success envelope, got {response:?}").into());
        };
        Ok(serde_json::from_value(success.payload)?)
    }

    fn error_code(response: ResponseEnvelope) -> Result<String, Box<dyn std::error::Error>> {
        let ResponseEnvelope::Error(error) = response else {
            return Err("expected error envelope".into());
        };
        Ok(error.error)
    }

    fn scan_audit_metadata(
        fixture: &ScanFixture,
    ) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        let store = Store::open(&fixture.store_path)?;
        let row = store.connection().query_row(
            "SELECT action, status, profile_id, command, metadata_json
             FROM audit_log
             WHERE project_id = ?1 AND action = 'SCAN'
             ORDER BY sequence DESC
             LIMIT 1",
            [PROJECT_ID],
            |row| {
                let action: String = row.get(0)?;
                let status: String = row.get(1)?;
                let profile_id: Option<String> = row.get(2)?;
                let command: Option<String> = row.get(3)?;
                let metadata: String = row.get(4)?;
                Ok((action, status, profile_id, command, metadata))
            },
        )?;
        assert_eq!(row.0, "SCAN");
        assert_eq!(row.1, "SUCCESS");
        assert_eq!(row.2.as_deref(), Some(PROFILE_ID));
        assert_eq!(row.3.as_deref(), Some("agent-scan-known-values"));
        Ok(serde_json::from_str(&row.4)?)
    }

    fn build_fixture() -> Result<ScanFixture, Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let store_path = directory.path().join("store.db");
        let mut store = Store::open(&store_path)?;
        store.initialize_schema()?;
        store.insert_project_if_absent(PROJECT_ID, "scan-test", 1)?;
        store.insert_profile_if_absent(PROFILE_ID, PROJECT_ID, PROFILE_NAME, false, 1)?;

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

        let current_value = "fixture-current-value".to_owned();
        let grace_value = "fixture-grace-value".to_owned();
        insert_encrypted_secret(
            &mut store,
            SecretInsert {
                secret_id: SECRET_ID,
                secret_name: SECRET_NAME,
                current_version: 1,
                version: 1,
                version_state: "current",
                grace_until: None,
                value: &current_value,
            },
            &profile_secret_key,
            &profile_fingerprint_key,
        )?;
        insert_encrypted_secret(
            &mut store,
            SecretInsert {
                secret_id: GRACE_SECRET_ID,
                secret_name: GRACE_SECRET_NAME,
                current_version: 2,
                version: 1,
                version_state: "deprecated",
                grace_until: Some(50),
                value: &grace_value,
            },
            &profile_secret_key,
            &profile_fingerprint_key,
        )?;

        Ok(ScanFixture {
            _directory: directory,
            store_path,
            master_key,
            current_value,
            grace_value,
        })
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

    #[derive(Clone, Copy)]
    struct SecretInsert<'a> {
        secret_id: &'a str,
        secret_name: &'a str,
        current_version: u32,
        version: u32,
        version_state: &'a str,
        grace_until: Option<i64>,
        value: &'a str,
    }

    fn insert_encrypted_secret(
        store: &mut Store,
        insert: SecretInsert<'_>,
        profile_secret_key: &locket_crypto::KeyBytes,
        profile_fingerprint_key: &locket_crypto::KeyBytes,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let value_aad = secret_blob_aad_v1(&SecretBlobAad::new(
            PROJECT_ID,
            PROFILE_ID,
            insert.secret_id,
            insert.secret_name,
            insert.version,
        ))?;
        let wrap_aad = key_wrap_aad_v1(&KeyWrapAad::new(
            PROJECT_ID,
            insert.secret_id,
            Some(PROFILE_ID),
            insert.version,
            KeyWrapPurpose::SecretDek,
        ))?;
        let encrypted =
            encrypt_secret_value_v1(profile_secret_key, insert.value, &value_aad, &wrap_aad)?;
        let fingerprint = secret_fingerprint_v1(profile_fingerprint_key, insert.value)?;
        let secret = SecretRecord {
            id: insert.secret_id.to_owned(),
            project_id: PROJECT_ID.to_owned(),
            profile_id: PROFILE_ID.to_owned(),
            name: insert.secret_name.to_owned(),
            source: "user-local".to_owned(),
            origin: "manual".to_owned(),
            current_version: insert.current_version,
            state: "active".to_owned(),
            created_at: 1,
            updated_at: 1,
            last_rotated_at: None,
            deleted_at: None,
        };
        let version = SecretVersionRecord {
            secret_id: insert.secret_id.to_owned(),
            version: insert.version,
            source: "user-local".to_owned(),
            origin: "manual".to_owned(),
            state: insert.version_state.to_owned(),
            created_at: 1,
            deprecated_at: if insert.version_state == "deprecated" { Some(1) } else { None },
            grace_until: insert.grace_until,
            purged_at: None,
        };
        let blob = SecretBlobRecord {
            secret_id: insert.secret_id.to_owned(),
            version: insert.version,
            encrypted_dek: encrypted.encrypted_dek,
            ciphertext: encrypted.ciphertext,
            value_nonce: encrypted.value_nonce,
            aad_schema_version: 1,
            created_at: 1,
        };
        let fingerprint = SecretFingerprintRecord {
            secret_id: insert.secret_id.to_owned(),
            version: insert.version,
            fingerprint: fingerprint.to_vec(),
            created_at: 1,
        };
        store.create_active_secret(&secret, &version, &blob, &fingerprint)?;
        Ok(())
    }
}
