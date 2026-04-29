//! Centralized Locket errors and stable process exit codes.

use thiserror::Error;

/// A process exit code reserved by the Locket failure-mode specification.
pub type ExitCode = u8;

/// Typed Locket failure modes.
#[derive(Debug, Clone, Eq, Error, PartialEq)]
pub enum LocketError {
    /// Invalid `lk://` reference syntax or target.
    #[error("invalid locket reference")]
    InvalidReference,
    /// A Git worktree was required but not found.
    #[error("git worktree required")]
    GitWorktreeRequired,
    /// User-supplied secret name failed `SecretName` validation.
    #[error("invalid secret name")]
    InvalidSecretName,
    /// User-supplied profile name failed `ProfileName` validation.
    #[error("invalid profile name")]
    InvalidProfileName,
    /// Policy validation could not complete without an agent or unlocked vault.
    #[error("policy validation incomplete")]
    PolicyValidationIncomplete,
    /// Referenced command policy or automation-client policy binding was not found.
    #[error("policy not found")]
    PolicyNotFound,
    /// Environment variable conflict under `override = \"error\"`.
    #[error("environment conflict")]
    EnvironmentConflict,
    /// Metadata contains invalid display characters.
    #[error("metadata invalid")]
    MetadataInvalid,
    /// Metadata looks like secret material.
    #[error("metadata looks like secret")]
    MetadataLooksLikeSecret,
    /// Typed-string confirmation prompt rejected by the user input.
    #[error("confirmation did not match")]
    ConfirmationFailed,
    /// Interactive terminal input was required but unavailable.
    #[error("interactive TTY required")]
    TtyRequired,
    /// `locket scan` found one or more blocking findings.
    #[error("scan blocked by findings")]
    ScanFindingBlocked,
    /// Secret, profile, policy, or key material already exists.
    #[error("secret already exists")]
    SecretAlreadyExists,
    /// Policy, role, profile, or command scope explicitly denied the action.
    #[error("access denied")]
    AccessDenied,
    /// Project root is not trusted.
    #[error("project root untrusted")]
    ProjectRootUntrusted,
    /// No Locket project could be resolved from the current directory.
    #[error("project not found")]
    ProjectNotFound,
    /// Vault or required key is locked.
    #[error("unlock required")]
    UnlockRequired,
    /// No live grant covers this action or context.
    #[error("grant required")]
    GrantRequired,
    /// Local user verification failed.
    #[error("local user verification failed")]
    UserVerificationFailed,
    /// Pinned deprecated secret version has no active grace window.
    #[error("secret version expired")]
    SecretVersionExpired,
    /// Selected secret source is tombstoned.
    #[error("secret deleted")]
    SecretDeleted,
    /// Selected secret could not be found by name/source/profile.
    #[error("secret not found")]
    SecretNotFound,
    /// Selected profile could not be found by name.
    #[error("profile not found")]
    ProfileNotFound,
    /// Required agent is unavailable.
    #[error("agent unavailable")]
    AgentUnavailable,
    /// Agent socket is in use by a peer that is not the active trusted agent.
    #[error("agent socket in use")]
    AgentSocketInUse,
    /// Automation client is not trusted.
    #[error("automation client not trusted")]
    AutomationClientNotTrusted,
    /// Automation client replay was detected.
    #[error("automation client replay detected")]
    AutomationClientReplayDetected,
    /// Update manifest signature, schema, or metadata validation failed.
    #[error("update manifest invalid")]
    UpdateManifestInvalid,
    /// Secret version counter cannot be advanced.
    #[error("secret version overflow")]
    SecretVersionOverflow,
    /// Database contents are corrupt.
    #[error("corrupt database")]
    CorruptDb,
    /// Another Locket process is currently writing.
    #[error("storage busy")]
    StorageBusy,
    /// Store schema is newer than this binary supports.
    #[error("schema newer than binary")]
    SchemaNewerThanBinary,
    /// Audit chain verification failed.
    #[error("audit integrity failed")]
    AuditIntegrityFailed,
    /// Keychain is unavailable.
    #[error("keychain unavailable")]
    KeychainUnavailable,
    /// Recovery code is lost.
    #[error("lost recovery code")]
    LostRecoveryCode,
    /// Keychain entry is lost.
    #[error("lost keychain entry")]
    LostKeychainEntry,
    /// Recovery code and keychain entry are both lost.
    #[error("vault unrecoverable")]
    UnrecoverableVault,
    /// Sealed bundle verification failed.
    #[error("bundle verification failed")]
    BundleVerificationFailed,
    /// Invite has expired.
    #[error("invite expired")]
    InviteExpired,
    /// Team bundle conflicts with local state.
    #[error("team bundle conflict")]
    TeamBundleConflict,
    /// Device has been revoked.
    #[error("device revoked")]
    DeviceRevoked,
}

impl LocketError {
    /// Returns the stable process exit code for this failure.
    #[must_use]
    pub const fn exit_code(&self) -> ExitCode {
        match self {
            Self::InvalidReference
            | Self::GitWorktreeRequired
            | Self::MetadataInvalid
            | Self::InvalidSecretName
            | Self::InvalidProfileName
            | Self::PolicyNotFound
            | Self::ProjectNotFound => 64,
            Self::PolicyValidationIncomplete => 65,
            Self::EnvironmentConflict | Self::MetadataLooksLikeSecret => 66,
            Self::SecretAlreadyExists => 67,
            Self::ConfirmationFailed | Self::TtyRequired => 68,
            Self::ScanFindingBlocked => 69,
            Self::AccessDenied => 70,
            Self::ProjectRootUntrusted => 71,
            Self::UnlockRequired => 72,
            Self::GrantRequired => 73,
            Self::UserVerificationFailed => 74,
            Self::SecretVersionExpired => 75,
            Self::SecretDeleted => 76,
            Self::SecretNotFound => 77,
            Self::ProfileNotFound => 78,
            Self::AgentUnavailable => 80,
            Self::AgentSocketInUse => 81,
            Self::AutomationClientNotTrusted => 82,
            Self::AutomationClientReplayDetected => 83,
            Self::UpdateManifestInvalid => 89,
            Self::SecretVersionOverflow | Self::CorruptDb => 90,
            Self::StorageBusy => 91,
            Self::SchemaNewerThanBinary => 92,
            Self::AuditIntegrityFailed => 93,
            Self::KeychainUnavailable => 100,
            Self::LostRecoveryCode => 101,
            Self::LostKeychainEntry => 102,
            Self::UnrecoverableVault => 103,
            Self::BundleVerificationFailed => 110,
            Self::InviteExpired => 111,
            Self::TeamBundleConflict => 112,
            Self::DeviceRevoked => 113,
        }
    }
}

impl From<&LocketError> for ExitCode {
    fn from(value: &LocketError) -> Self {
        value.exit_code()
    }
}

#[cfg(test)]
mod tests {
    use super::LocketError;

    #[test]
    fn maps_input_exit_codes() {
        assert_eq!(LocketError::InvalidReference.exit_code(), 64);
        assert_eq!(LocketError::GitWorktreeRequired.exit_code(), 64);
        assert_eq!(LocketError::InvalidSecretName.exit_code(), 64);
        assert_eq!(LocketError::InvalidProfileName.exit_code(), 64);
        assert_eq!(LocketError::PolicyNotFound.exit_code(), 64);
        assert_eq!(LocketError::ProjectNotFound.exit_code(), 64);
        assert_eq!(LocketError::PolicyValidationIncomplete.exit_code(), 65);
        assert_eq!(LocketError::EnvironmentConflict.exit_code(), 66);
        assert_eq!(LocketError::MetadataInvalid.exit_code(), 64);
        assert_eq!(LocketError::MetadataLooksLikeSecret.exit_code(), 66);
        assert_eq!(LocketError::SecretAlreadyExists.exit_code(), 67);
        assert_eq!(LocketError::ConfirmationFailed.exit_code(), 68);
        assert_eq!(LocketError::TtyRequired.exit_code(), 68);
        assert_eq!(LocketError::ScanFindingBlocked.exit_code(), 69);
    }

    #[test]
    fn maps_authorization_exit_codes() {
        assert_eq!(LocketError::AccessDenied.exit_code(), 70);
        assert_eq!(LocketError::ProjectRootUntrusted.exit_code(), 71);
        assert_eq!(LocketError::UnlockRequired.exit_code(), 72);
        assert_eq!(LocketError::GrantRequired.exit_code(), 73);
        assert_eq!(LocketError::UserVerificationFailed.exit_code(), 74);
        assert_eq!(LocketError::SecretVersionExpired.exit_code(), 75);
        assert_eq!(LocketError::SecretDeleted.exit_code(), 76);
        assert_eq!(LocketError::SecretNotFound.exit_code(), 77);
        assert_eq!(LocketError::ProfileNotFound.exit_code(), 78);
    }

    #[test]
    fn maps_storage_and_later_exit_codes_below_reserved_shell_codes() {
        let cases = [
            (LocketError::AgentUnavailable, 80),
            (LocketError::AgentSocketInUse, 81),
            (LocketError::AutomationClientNotTrusted, 82),
            (LocketError::AutomationClientReplayDetected, 83),
            (LocketError::UpdateManifestInvalid, 89),
            (LocketError::SecretVersionOverflow, 90),
            (LocketError::CorruptDb, 90),
            (LocketError::StorageBusy, 91),
            (LocketError::SchemaNewerThanBinary, 92),
            (LocketError::AuditIntegrityFailed, 93),
            (LocketError::KeychainUnavailable, 100),
            (LocketError::LostRecoveryCode, 101),
            (LocketError::LostKeychainEntry, 102),
            (LocketError::UnrecoverableVault, 103),
            (LocketError::BundleVerificationFailed, 110),
            (LocketError::InviteExpired, 111),
            (LocketError::TeamBundleConflict, 112),
            (LocketError::DeviceRevoked, 113),
            (LocketError::TtyRequired, 68),
        ];

        for (error, code) in cases {
            assert_eq!(error.exit_code(), code);
            assert!(error.exit_code() < 126);
        }
    }

    #[test]
    fn converts_error_references_to_exit_codes() {
        assert_eq!(super::ExitCode::from(&LocketError::GrantRequired), 73);
    }

    #[test]
    fn displays_stable_error_messages() {
        let cases = [
            (LocketError::InvalidReference, "invalid locket reference"),
            (LocketError::EnvironmentConflict, "environment conflict"),
            (LocketError::MetadataInvalid, "metadata invalid"),
            (LocketError::MetadataLooksLikeSecret, "metadata looks like secret"),
            (LocketError::SecretAlreadyExists, "secret already exists"),
            (LocketError::UnrecoverableVault, "vault unrecoverable"),
            (LocketError::DeviceRevoked, "device revoked"),
            (LocketError::ConfirmationFailed, "confirmation did not match"),
            (LocketError::TtyRequired, "interactive TTY required"),
            (LocketError::SecretNotFound, "secret not found"),
            (LocketError::ProfileNotFound, "profile not found"),
            (LocketError::SecretVersionOverflow, "secret version overflow"),
            (LocketError::ProjectNotFound, "project not found"),
            (LocketError::InvalidSecretName, "invalid secret name"),
            (LocketError::InvalidProfileName, "invalid profile name"),
        ];

        for (error, message) in cases {
            assert_eq!(error.to_string(), message);
        }
    }
}
