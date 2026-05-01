//! Desktop backup/recovery RPC request and response types.

use std::path::PathBuf;

use locket_core::bundle::{BundleContainer, verify_age_payload_structure};
use serde::{Deserialize, Serialize};

use crate::envelope::{ErrorEnvelope, RequestEnvelope, ResponseEnvelope, SuccessEnvelope};
use crate::server::{AgentSocketState, current_unix_nanos};

/// Bundle export profile scope.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum BundleExportScope {
    /// Export only the active profile.
    ActiveProfile,
    /// Export every profile in the project.
    AllProfiles,
}

/// Desktop request for sealed bundle export.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExportBundleRequest {
    /// Project id being exported.
    pub project_id: String,
    /// Active profile id/name supplied by desktop status.
    pub profile_id: Option<String>,
    /// Device descriptor for the recipient.
    pub recipient_descriptor: String,
    /// Profile selection.
    pub scope: BundleExportScope,
    /// Whether remote audit rows should be included.
    pub include_audit: bool,
    /// Optional output path.
    pub output_path: Option<PathBuf>,
}

/// Import conflict behavior.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum BundleConflictMode {
    /// Review conflicts without applying divergent rows.
    Review,
    /// Prefer incoming bundle rows when conflicts occur.
    AcceptIncoming,
    /// Keep local rows when conflicts occur.
    AcceptLocal,
}

/// Desktop request for sealed bundle import.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ImportBundleRequest {
    /// Project id receiving the bundle.
    pub project_id: String,
    /// Bundle file path.
    pub bundle_path: PathBuf,
    /// Import remote audit rows when present.
    pub include_audit: bool,
    /// Conflict policy.
    pub conflict_mode: BundleConflictMode,
}

/// Desktop request for non-destructive bundle verification.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VerifyBundleRequest {
    /// Bundle file path.
    pub bundle_path: PathBuf,
    /// Whether the UI requires the bundle to be decryptable locally.
    #[serde(default)]
    pub require_decryptable: bool,
}

/// Recovery-rotation verification factor requested by the UI.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RecoveryVerification {
    /// Fresh platform prompt / hardware-backed verification.
    Platform,
    /// Current recovery-code prompt.
    CurrentCode,
}

/// Desktop request for recovery-code rotation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RecoveryRotateRequest {
    /// Project id whose recovery envelope would be rotated.
    pub project_id: String,
    /// Requested fresh verification factor.
    pub verification: RecoveryVerification,
    /// User confirmed one-time display semantics in the UI.
    pub acknowledged_one_time_display: bool,
    /// Whether the UI should clear the visible code after display.
    pub clear_after_display: bool,
}

/// Common metadata-only backup action response.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BackupActionResponse {
    /// Stable action label.
    pub action: String,
    /// User-facing, metadata-only status.
    pub status: String,
    /// User-facing, metadata-only next step.
    pub message: String,
}

/// Non-destructive bundle verification response.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VerifyBundleResponse {
    /// Whether the outer container and age payload are structurally valid.
    pub structural_valid: bool,
    /// Bundle schema version.
    pub schema_version: u16,
    /// Project id from the plaintext manifest.
    pub project_id: String,
    /// Profile count from the plaintext manifest.
    pub profile_count: u32,
    /// Recipient count from the plaintext manifest.
    pub recipient_count: u32,
    /// Payload digest from the plaintext manifest.
    pub payload_digest: String,
    /// Whether local decryptability was checked by this RPC.
    pub decryptable_by_this_device: Option<bool>,
    /// Metadata-only status.
    pub message: String,
}

/// Handle desktop bundle export.
pub async fn handle_export_bundle(
    envelope: &RequestEnvelope,
    state: &AgentSocketState,
) -> ResponseEnvelope {
    let request: ExportBundleRequest = match serde_json::from_value(envelope.payload.clone()) {
        Ok(request) => request,
        Err(_) => return error_response(envelope, "ProtocolError", "invalid ExportBundle payload"),
    };
    if let Some(response) = require_unlocked(envelope, state, &request.project_id).await {
        return response;
    }
    if request.recipient_descriptor.trim().is_empty() {
        return error_response(envelope, "InvalidReference", "bundle export requires a recipient");
    }
    not_implemented(
        envelope,
        "export-bundle",
        "Bundle export reached the typed agent path; applying it requires the sealed-bundle core to be shared with the agent.",
    )
}

/// Handle desktop bundle import.
pub async fn handle_import_bundle(
    envelope: &RequestEnvelope,
    state: &AgentSocketState,
) -> ResponseEnvelope {
    let request: ImportBundleRequest = match serde_json::from_value(envelope.payload.clone()) {
        Ok(request) => request,
        Err(_) => return error_response(envelope, "ProtocolError", "invalid ImportBundle payload"),
    };
    if let Some(response) = require_unlocked(envelope, state, &request.project_id).await {
        return response;
    }
    if !request.bundle_path.exists() {
        return error_response(envelope, "BundleVerificationFailed", "bundle file was not found");
    }
    not_implemented(
        envelope,
        "import-bundle",
        "Bundle import reached the typed agent path; applying rows requires the sealed-bundle core to be shared with the agent.",
    )
}

/// Handle desktop bundle verification.
pub fn handle_verify_bundle(envelope: &RequestEnvelope) -> ResponseEnvelope {
    let request: VerifyBundleRequest = match serde_json::from_value(envelope.payload.clone()) {
        Ok(request) => request,
        Err(_) => return error_response(envelope, "ProtocolError", "invalid VerifyBundle payload"),
    };
    let bytes = match std::fs::read(&request.bundle_path) {
        Ok(bytes) => bytes,
        Err(_) => {
            return error_response(
                envelope,
                "BundleVerificationFailed",
                "bundle file was not found",
            );
        }
    };
    let bundle = match BundleContainer::deserialize(&bytes) {
        Ok(bundle) => bundle,
        Err(error) => {
            return error_response(
                envelope,
                "BundleVerificationFailed",
                &format!("bundle verification failed: {error}"),
            );
        }
    };
    if let Err(error) = verify_age_payload_structure(&bundle.encrypted_payload) {
        return error_response(
            envelope,
            "BundleVerificationFailed",
            &format!("bundle verification failed: {error}"),
        );
    }
    let decryptable_by_this_device = request.require_decryptable.then_some(false);
    let response = VerifyBundleResponse {
        structural_valid: true,
        schema_version: bundle.manifest.schema_version,
        project_id: bundle.manifest.project_id,
        profile_count: bundle.manifest.profile_count,
        recipient_count: u32::try_from(bundle.manifest.recipient_fingerprints.len())
            .unwrap_or(u32::MAX),
        payload_digest: bundle.manifest.payload_digest,
        decryptable_by_this_device,
        message: if request.require_decryptable {
            "Bundle is structurally valid; local decryptability requires the CLI bundle core."
                .to_owned()
        } else {
            "Bundle is structurally valid.".to_owned()
        },
    };
    success_response(envelope, response)
}

/// Handle desktop recovery-code rotation.
pub async fn handle_recovery_rotate(
    envelope: &RequestEnvelope,
    state: &AgentSocketState,
) -> ResponseEnvelope {
    let request: RecoveryRotateRequest = match serde_json::from_value(envelope.payload.clone()) {
        Ok(request) => request,
        Err(_) => {
            return error_response(envelope, "ProtocolError", "invalid RecoveryRotate payload");
        }
    };
    if !request.acknowledged_one_time_display {
        return error_response(
            envelope,
            "ConfirmationFailed",
            "one-time recovery-code display must be acknowledged",
        );
    }
    if let Some(response) = require_unlocked(envelope, state, &request.project_id).await {
        return response;
    }
    not_implemented(
        envelope,
        "recovery-rotate",
        "Recovery rotation reached the typed agent path; fresh verification and envelope rewrite still require CLI-core extraction.",
    )
}

async fn require_unlocked(
    envelope: &RequestEnvelope,
    state: &AgentSocketState,
    project_id: &str,
) -> Option<ResponseEnvelope> {
    let unlocked = {
        let cache = state.unlock_cache.lock().await;
        cache.lookup(project_id, current_unix_nanos()).is_some()
    };
    (!unlocked).then(|| error_response(envelope, "UnlockRequired", "unlock the vault first"))
}

fn not_implemented(
    envelope: &RequestEnvelope,
    action: &'static str,
    message: impl Into<String>,
) -> ResponseEnvelope {
    success_response(
        envelope,
        BackupActionResponse {
            action: action.to_owned(),
            status: "not-implemented".to_owned(),
            message: message.into(),
        },
    )
}

fn success_response<T: Serialize>(envelope: &RequestEnvelope, payload: T) -> ResponseEnvelope {
    let payload = serde_json::to_value(payload).unwrap_or(serde_json::Value::Null);
    ResponseEnvelope::Success(SuccessEnvelope::new(envelope.id.clone(), payload))
}

fn error_response(envelope: &RequestEnvelope, error: &str, message: &str) -> ResponseEnvelope {
    ResponseEnvelope::Error(ErrorEnvelope::new(envelope.id.clone(), error, message, false))
}
