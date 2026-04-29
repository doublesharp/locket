//! Core policy and validation primitives for Locket.

pub mod audit;
pub mod env;
pub mod error;
pub mod id;
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
pub use env::{
    EnvMap, EnvMergeError, EnvMode, EnvOverrideMode, EnvValue, InvalidEnvMode,
    InvalidEnvOverrideMode, env_value, merge_environment,
};
pub use error::{ExitCode, LocketError};
pub use id::{
    ClientId, DeviceId, IdGenerationError, InvalidId, KdfProfileId, KeyId, PasskeyId, ProfileId,
    ProjectId, SecretId, SessionId,
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
    UpdateArtifact, UpdateChannel, UpdateManifestError, UpdateManifestPayload,
    UpdateManifestSignature, VerifiedUpdateManifest, verify_update_manifest,
};
