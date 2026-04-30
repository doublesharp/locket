//! Core policy and validation primitives for Locket.

pub mod audit;
pub mod bundle;
pub mod env;
pub mod error;
pub mod id;
pub mod invite;
pub mod metadata;
pub mod policy;
pub mod profile_name;
pub mod project;
pub mod reference_uri;
pub mod secret_name;
pub mod time;
pub mod update_manifest;

pub use audit::{
    AUDIT_HMAC_LEN, AuditCanonicalizationError, AuditHmacInput, audit_hmac_v1_bytes, bytes,
    canonical_json, canonical_json_bytes, canonical_json_string, field,
    insert_convenience_metadata,
};
pub use bundle::{
    BUNDLE_MAGIC, BUNDLE_MANIFEST_ALLOWED_FIELDS, BUNDLE_MAX_MANIFEST_LEN, BUNDLE_MAX_PAYLOAD_LEN,
    BUNDLE_SCHEMA_V1, BundleContainer, BundleContainerError, BundleContainerResult,
    BundleEncryptionError, BundleEncryptionResult, BundleManifest,
    decrypt_bundle_payload_with_age_identity, encrypt_bundle_payload_for_age_recipients,
    verify_age_payload_structure,
};
pub use env::{
    EnvMap, EnvMergeError, EnvMode, EnvOverrideMode, EnvValue, InvalidEnvMode,
    InvalidEnvOverrideMode, env_value, merge_environment,
};
pub use error::{ExitCode, LocketError};
pub use id::{
    ClientId, DeviceId, IdGenerationError, InvalidId, InviteId, KdfProfileId, KeyId, MemberId,
    PasskeyId, ProfileId, ProjectId, SecretId, SessionId, TeamId,
};
pub use invite::{
    INVITE_PREFIX, InviteDecodeError, InviteEncodeError, InvitePayload, InviteVerifyError,
    SignedInvite, TeamRole, device_fingerprint_v1, fingerprint_hex,
};
pub use metadata::{MetadataPrivacyFinding, MetadataValidationError, validate_metadata_field};
pub use policy::{
    CommandPolicy, CommandSpec, ExternalEnvSource, MAX_COMMAND_POLICY_TTL_SECONDS, PolicyDocument,
    PolicyParseError,
};
pub use profile_name::{InvalidProfileName, MAX_PROFILE_NAME_LEN, ProfileName};
pub use project::{PROJECT_CONFIG_SCHEMA_VERSION, ProjectConfig};
pub use reference_uri::{
    InvalidReferenceUri, InvalidSecretSource, LkReferenceUri, SecretSource, SecretVersion,
};
pub use secret_name::{InvalidSecretName, SecretName};
pub use time::{Duration, InvalidDuration, Timestamp};
pub use update_manifest::{
    ReleaseKey, UpdateArtifact, UpdateChannel, UpdateManifestError, UpdateManifestFetchRequest,
    UpdateManifestPayload, UpdateManifestSignature, VerifiedUpdateManifest,
    build_update_manifest_fetch_request, verify_update_manifest,
    verify_update_manifest_key_rotation,
};
