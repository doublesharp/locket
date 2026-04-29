//! Key purpose enums used by AAD construction and key wrapping.

const SECRET_DEK_PURPOSE: &str = "secret-dek";

/// Persisted key purpose strings from the `keys.purpose` column.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub enum KeyPurpose {
    /// Project metadata key.
    ProjectMetadata,
    /// Project audit key, serialized as `project-audit`.
    Audit,
    /// Profile secret key.
    ProfileSecret,
    /// Profile fingerprint key.
    ProfileFingerprint,
}

impl KeyPurpose {
    /// Returns the canonical persisted purpose string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProjectMetadata => "project-metadata",
            Self::Audit => "project-audit",
            Self::ProfileSecret => "profile-secret",
            Self::ProfileFingerprint => "profile-fingerprint",
        }
    }
}

/// Purpose strings accepted by `key_wrap_aad_v1`.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub enum KeyWrapPurpose {
    /// Project metadata key.
    ProjectMetadata,
    /// Project audit key.
    Audit,
    /// Profile secret key.
    ProfileSecret,
    /// Profile fingerprint key.
    ProfileFingerprint,
    /// Per-version secret DEK.
    SecretDek,
}

impl KeyWrapPurpose {
    /// Returns the canonical key-wrap purpose string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProjectMetadata => KeyPurpose::ProjectMetadata.as_str(),
            Self::Audit => KeyPurpose::Audit.as_str(),
            Self::ProfileSecret => KeyPurpose::ProfileSecret.as_str(),
            Self::ProfileFingerprint => KeyPurpose::ProfileFingerprint.as_str(),
            Self::SecretDek => SECRET_DEK_PURPOSE,
        }
    }
}

impl From<KeyPurpose> for KeyWrapPurpose {
    fn from(value: KeyPurpose) -> Self {
        match value {
            KeyPurpose::ProjectMetadata => Self::ProjectMetadata,
            KeyPurpose::Audit => Self::Audit,
            KeyPurpose::ProfileSecret => Self::ProfileSecret,
            KeyPurpose::ProfileFingerprint => Self::ProfileFingerprint,
        }
    }
}
