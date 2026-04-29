//! Offline validation for signed update manifests.

use data_encoding::BASE64URL_NOPAD;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::{LocketError, canonical_json};

const MANIFEST_SCHEMA_VERSION: u8 = 1;
const SIGNATURE_ALGORITHM: &str = "Ed25519";
const SIGNATURE_DOMAIN: &[u8] = b"locket-update-manifest-v1\0";
const SHA256_HEX_LEN: usize = 64;
const ED25519_PUBLIC_KEY_LEN: usize = 32;
const ED25519_SIGNATURE_LEN: usize = 64;

/// A signed update manifest envelope.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SignedUpdateManifest {
    /// Manifest schema version. v1 signs only the `signed` payload.
    pub v: u8,
    /// Privacy-safe update metadata covered by the release signature.
    pub signed: UpdateManifestPayload,
    /// Detached signatures over the canonical v1 payload.
    pub signatures: Vec<UpdateManifestSignature>,
}

/// Update metadata covered by the offline release signature.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UpdateManifestPayload {
    /// Release channel this manifest applies to.
    pub channel: UpdateChannel,
    /// Release version string.
    pub version: String,
    /// UTC publication timestamp supplied by release tooling.
    pub published_at: String,
    /// Per-platform artifacts.
    pub artifacts: Vec<UpdateArtifact>,
}

/// Supported update channels for signed manifests.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum UpdateChannel {
    /// Stable public release channel.
    Stable,
    /// Beta prerelease channel.
    Beta,
}

/// Metadata for one downloadable release artifact.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UpdateArtifact {
    /// Operating-system target, for example `macos`, `windows`, or `linux`.
    pub platform: String,
    /// CPU architecture target, for example `aarch64` or `x86_64`.
    pub arch: String,
    /// HTTPS download URL for the artifact.
    pub url: String,
    /// Lowercase hex SHA-256 digest of the artifact bytes.
    pub sha256: String,
    /// Artifact length in bytes.
    pub size_bytes: u64,
}

/// A detached signature entry for a signed manifest payload.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UpdateManifestSignature {
    /// Stable release-key identifier.
    pub key_id: String,
    /// Signature algorithm. v1 accepts only `Ed25519`.
    pub algorithm: String,
    /// Unpadded base64url Ed25519 signature.
    pub signature: String,
}

/// A manifest whose schema, metadata, and release signature have been verified.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedUpdateManifest {
    /// Verified metadata payload.
    pub payload: UpdateManifestPayload,
    /// Key id of the pinned release key that verified the payload.
    pub key_id: String,
}

/// Failure reasons for update manifest validation.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum UpdateManifestError {
    /// Manifest JSON could not be parsed.
    #[error("manifest JSON is invalid")]
    InvalidJson,
    /// Manifest schema version is unsupported.
    #[error("manifest schema version is unsupported")]
    UnsupportedSchema,
    /// Required signed metadata is missing or malformed.
    #[error("manifest metadata is invalid")]
    InvalidMetadata,
    /// Pinned release public key is malformed.
    #[error("release public key is invalid")]
    InvalidPublicKey,
    /// No signature matches the pinned release key id.
    #[error("manifest signature is missing")]
    MissingSignature,
    /// Manifest signature is malformed.
    #[error("manifest signature is invalid")]
    InvalidSignature,
    /// Manifest signature does not verify against the pinned key.
    #[error("manifest signature verification failed")]
    SignatureVerificationFailed,
}

impl From<UpdateManifestError> for LocketError {
    fn from(_: UpdateManifestError) -> Self {
        Self::UpdateManifestInvalid
    }
}

/// Parses and verifies a signed update manifest with a pinned Ed25519 release key.
///
/// The verifier performs no network I/O. Callers fetch the manifest only after
/// the user opts into update checks, then pass the bytes here with the pinned
/// release key compiled into the binary.
///
/// # Errors
///
/// Returns [`UpdateManifestError`] when JSON parsing, schema validation,
/// privacy-safe URL validation, or Ed25519 verification fails.
pub fn verify_update_manifest(
    manifest_bytes: &[u8],
    pinned_key_id: &str,
    pinned_public_key_base64url: &str,
) -> Result<VerifiedUpdateManifest, UpdateManifestError> {
    let manifest: SignedUpdateManifest =
        serde_json::from_slice(manifest_bytes).map_err(|_| UpdateManifestError::InvalidJson)?;
    if manifest.v != MANIFEST_SCHEMA_VERSION {
        return Err(UpdateManifestError::UnsupportedSchema);
    }
    validate_payload(&manifest.signed)?;
    let verifying_key = decode_verifying_key(pinned_public_key_base64url)?;
    let signature = manifest
        .signatures
        .iter()
        .find(|signature| {
            signature.key_id == pinned_key_id && signature.algorithm == SIGNATURE_ALGORITHM
        })
        .ok_or(UpdateManifestError::MissingSignature)?;
    let signature = decode_signature(&signature.signature)?;
    verifying_key
        .verify(&signed_payload_bytes(&manifest.signed)?, &signature)
        .map_err(|_| UpdateManifestError::SignatureVerificationFailed)?;
    Ok(VerifiedUpdateManifest { payload: manifest.signed, key_id: pinned_key_id.to_owned() })
}

fn validate_payload(payload: &UpdateManifestPayload) -> Result<(), UpdateManifestError> {
    validate_nonempty_token(&payload.version)?;
    validate_nonempty_token(&payload.published_at)?;
    if payload.artifacts.is_empty() {
        return Err(UpdateManifestError::InvalidMetadata);
    }
    for artifact in &payload.artifacts {
        validate_nonempty_token(&artifact.platform)?;
        validate_nonempty_token(&artifact.arch)?;
        validate_https_static_url(&artifact.url)?;
        validate_sha256_hex(&artifact.sha256)?;
        if artifact.size_bytes == 0 {
            return Err(UpdateManifestError::InvalidMetadata);
        }
    }
    Ok(())
}

fn validate_nonempty_token(value: &str) -> Result<(), UpdateManifestError> {
    if value.is_empty() || value.chars().any(char::is_control) {
        return Err(UpdateManifestError::InvalidMetadata);
    }
    Ok(())
}

fn validate_https_static_url(url: &str) -> Result<(), UpdateManifestError> {
    let Some(rest) = url.strip_prefix("https://") else {
        return Err(UpdateManifestError::InvalidMetadata);
    };
    if rest.is_empty()
        || url.chars().any(char::is_control)
        || url.contains('?')
        || url.contains('#')
    {
        return Err(UpdateManifestError::InvalidMetadata);
    }
    let host = rest.split('/').next().unwrap_or_default();
    if host.is_empty() || host.contains('@') || host.contains(':') {
        return Err(UpdateManifestError::InvalidMetadata);
    }
    Ok(())
}

fn validate_sha256_hex(value: &str) -> Result<(), UpdateManifestError> {
    if value.len() != SHA256_HEX_LEN
        || !value.bytes().all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(UpdateManifestError::InvalidMetadata);
    }
    Ok(())
}

fn decode_verifying_key(encoded: &str) -> Result<VerifyingKey, UpdateManifestError> {
    let bytes = BASE64URL_NOPAD
        .decode(encoded.as_bytes())
        .map_err(|_| UpdateManifestError::InvalidPublicKey)?;
    let key_bytes: [u8; ED25519_PUBLIC_KEY_LEN] =
        bytes.try_into().map_err(|_| UpdateManifestError::InvalidPublicKey)?;
    VerifyingKey::from_bytes(&key_bytes).map_err(|_| UpdateManifestError::InvalidPublicKey)
}

fn decode_signature(encoded: &str) -> Result<Signature, UpdateManifestError> {
    let bytes = BASE64URL_NOPAD
        .decode(encoded.as_bytes())
        .map_err(|_| UpdateManifestError::InvalidSignature)?;
    let signature_bytes: [u8; ED25519_SIGNATURE_LEN] =
        bytes.try_into().map_err(|_| UpdateManifestError::InvalidSignature)?;
    Ok(Signature::from_bytes(&signature_bytes))
}

fn signed_payload_bytes(payload: &UpdateManifestPayload) -> Result<Vec<u8>, UpdateManifestError> {
    let value: Value =
        serde_json::to_value(payload).map_err(|_| UpdateManifestError::InvalidMetadata)?;
    let mut bytes = Vec::from(SIGNATURE_DOMAIN);
    bytes.extend_from_slice(canonical_json(&value).as_bytes());
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use data_encoding::BASE64URL_NOPAD;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;

    use super::{
        SignedUpdateManifest, UpdateArtifact, UpdateChannel, UpdateManifestError,
        UpdateManifestPayload, UpdateManifestSignature, verify_update_manifest,
    };
    use crate::LocketError;

    #[test]
    fn verifies_signed_manifest_and_returns_payload() -> Result<(), Box<dyn std::error::Error>> {
        let (manifest, key_id, public_key) = signed_manifest()?;

        let verified = verify_update_manifest(&manifest, &key_id, &public_key)?;

        assert_eq!(verified.key_id, key_id);
        assert_eq!(verified.payload.version, "0.2.0");
        assert_eq!(verified.payload.artifacts[0].platform, "macos");
        Ok(())
    }

    #[test]
    fn rejects_unsigned_or_mismatched_key_id() -> Result<(), Box<dyn std::error::Error>> {
        let (manifest, _, public_key) = signed_manifest()?;

        let Err(error) = verify_update_manifest(&manifest, "release-key-other", &public_key) else {
            return Err("manifest should require the pinned key id".into());
        };

        assert_eq!(error, UpdateManifestError::MissingSignature);
        assert_eq!(LocketError::from(error).exit_code(), 89);
        Ok(())
    }

    #[test]
    fn rejects_invalid_json() -> Result<(), Box<dyn std::error::Error>> {
        let Err(error) = verify_update_manifest(b"{not json", "release-key-v1", "not-a-key") else {
            return Err("invalid JSON should fail before key parsing".into());
        };

        assert_eq!(error, UpdateManifestError::InvalidJson);
        Ok(())
    }

    #[test]
    fn rejects_unsupported_schema() -> Result<(), Box<dyn std::error::Error>> {
        let (manifest, key_id, public_key) = signed_manifest()?;
        let mut manifest: serde_json::Value = serde_json::from_slice(&manifest)?;
        manifest["v"] = json!(2);
        let manifest = serde_json::to_vec(&manifest)?;

        let Err(error) = verify_update_manifest(&manifest, &key_id, &public_key) else {
            return Err("unsupported schema should fail before trusting manifest".into());
        };

        assert_eq!(error, UpdateManifestError::UnsupportedSchema);
        Ok(())
    }

    #[test]
    fn rejects_invalid_pinned_release_key() -> Result<(), Box<dyn std::error::Error>> {
        let (manifest, key_id, _) = signed_manifest()?;

        let Err(error) = verify_update_manifest(&manifest, &key_id, "not-a-release-key") else {
            return Err("invalid pinned release key should fail".into());
        };

        assert_eq!(error, UpdateManifestError::InvalidPublicKey);
        Ok(())
    }

    #[test]
    fn rejects_malformed_signature() -> Result<(), Box<dyn std::error::Error>> {
        let (manifest, key_id, public_key) = signed_manifest()?;
        let mut manifest: serde_json::Value = serde_json::from_slice(&manifest)?;
        manifest["signatures"][0]["signature"] = json!("not-a-signature");
        let manifest = serde_json::to_vec(&manifest)?;

        let Err(error) = verify_update_manifest(&manifest, &key_id, &public_key) else {
            return Err("malformed signature should fail".into());
        };

        assert_eq!(error, UpdateManifestError::InvalidSignature);
        Ok(())
    }

    #[test]
    fn rejects_tampered_signed_payload() -> Result<(), Box<dyn std::error::Error>> {
        let (manifest, key_id, public_key) = signed_manifest()?;
        let mut manifest: serde_json::Value = serde_json::from_slice(&manifest)?;
        manifest["signed"]["version"] = json!("0.2.1");
        let manifest = serde_json::to_vec(&manifest)?;

        let Err(error) = verify_update_manifest(&manifest, &key_id, &public_key) else {
            return Err("tampered manifest should not verify".into());
        };

        assert_eq!(error, UpdateManifestError::SignatureVerificationFailed);
        Ok(())
    }

    #[test]
    fn rejects_non_static_or_non_https_urls() -> Result<(), Box<dyn std::error::Error>> {
        let (manifest, key_id, public_key) = signed_manifest_with_url(
            "https://updates.example.test/locket.pkg?project_id=lk_proj_secret",
        )?;

        let Err(error) = verify_update_manifest(&manifest, &key_id, &public_key) else {
            return Err("tracking query strings should be rejected".into());
        };

        assert_eq!(error, UpdateManifestError::InvalidMetadata);
        Ok(())
    }

    #[test]
    fn rejects_invalid_artifact_digest_shape() -> Result<(), Box<dyn std::error::Error>> {
        let (manifest, key_id, public_key) = signed_manifest_with_digest("ABC")?;

        let Err(error) = verify_update_manifest(&manifest, &key_id, &public_key) else {
            return Err("invalid digest should be rejected before trusting manifest".into());
        };

        assert_eq!(error, UpdateManifestError::InvalidMetadata);
        Ok(())
    }

    fn signed_manifest() -> Result<(Vec<u8>, String, String), Box<dyn std::error::Error>> {
        signed_manifest_with_url("https://updates.example.test/releases/locket-0.2.0-aarch64.pkg")
    }

    fn signed_manifest_with_url(
        url: &str,
    ) -> Result<(Vec<u8>, String, String), Box<dyn std::error::Error>> {
        signed_manifest_with_artifact(UpdateArtifact {
            platform: "macos".to_owned(),
            arch: "aarch64".to_owned(),
            url: url.to_owned(),
            sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_owned(),
            size_bytes: 42,
        })
    }

    fn signed_manifest_with_digest(
        sha256: &str,
    ) -> Result<(Vec<u8>, String, String), Box<dyn std::error::Error>> {
        signed_manifest_with_artifact(UpdateArtifact {
            platform: "macos".to_owned(),
            arch: "aarch64".to_owned(),
            url: "https://updates.example.test/releases/locket-0.2.0-aarch64.pkg".to_owned(),
            sha256: sha256.to_owned(),
            size_bytes: 42,
        })
    }

    fn signed_manifest_with_artifact(
        artifact: UpdateArtifact,
    ) -> Result<(Vec<u8>, String, String), Box<dyn std::error::Error>> {
        let key_id = "release-key-v1".to_owned();
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let payload = UpdateManifestPayload {
            channel: UpdateChannel::Stable,
            version: "0.2.0".to_owned(),
            published_at: "2026-04-29T00:00:00Z".to_owned(),
            artifacts: vec![artifact],
        };
        let signature = signing_key.sign(&super::signed_payload_bytes(&payload)?);
        let envelope = SignedUpdateManifest {
            v: 1,
            signed: payload,
            signatures: vec![UpdateManifestSignature {
                key_id: key_id.clone(),
                algorithm: "Ed25519".to_owned(),
                signature: BASE64URL_NOPAD.encode(&signature.to_bytes()),
            }],
        };
        Ok((
            serde_json::to_vec(&envelope)?,
            key_id,
            BASE64URL_NOPAD.encode(signing_key.verifying_key().as_bytes()),
        ))
    }
}
