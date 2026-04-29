//! CLI error type, error conversions, and helpers for typed error construction.

use std::error::Error;
use std::fmt::{self, Display};
use std::io;

use locket_core::LocketError;
use locket_store::StoreError;

#[derive(Debug)]
pub enum CliError {
    Config(String),
    Typed { kind: LocketError, message: String },
    ChildExit(u8),
    Io(io::Error),
    Store(StoreError),
    Json(serde_json::Error),
    TomlDe(toml::de::Error),
    TomlSer(toml::ser::Error),
    Crypto(locket_crypto::CryptoError),
    Platform(locket_platform::PlatformError),
    Time,
}

impl CliError {
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::Config(_) | Self::Json(_) | Self::TomlDe(_) | Self::TomlSer(_) => {
                LocketError::InvalidReference.exit_code()
            }
            Self::Typed { kind, .. } => kind.exit_code(),
            Self::ChildExit(code) => *code,
            Self::Io(_) | Self::Time => LocketError::CorruptDb.exit_code(),
            Self::Store(error) => error.locket_error().exit_code(),
            Self::Crypto(error) => crypto_error_exit_code(*error),
            Self::Platform(error) => platform_error_exit_code(error),
        }
    }
}

const fn crypto_error_exit_code(error: locket_crypto::CryptoError) -> u8 {
    match error {
        locket_crypto::CryptoError::InvalidSecretValue => LocketError::InvalidReference.exit_code(),
        _ => LocketError::CorruptDb.exit_code(),
    }
}

const fn platform_error_exit_code(error: &locket_platform::PlatformError) -> u8 {
    match error {
        locket_platform::PlatformError::MasterKeyNotFound
        | locket_platform::PlatformError::InvalidPassphrase => {
            LocketError::UnlockRequired.exit_code()
        }
        locket_platform::PlatformError::LocalUserVerificationFailed
        | locket_platform::PlatformError::LocalUserVerificationUnavailable => {
            LocketError::UserVerificationFailed.exit_code()
        }
        locket_platform::PlatformError::RecoveryEnvelopeSchemaUnsupported(_)
        | locket_platform::PlatformError::InvalidRecoveryEnvelope(_)
        | locket_platform::PlatformError::InvalidPassphraseFallback
        | locket_platform::PlatformError::InvalidMasterKey
        | locket_platform::PlatformError::InvalidProjectId
        | locket_platform::PlatformError::Keyring(_)
        | locket_platform::PlatformError::Io(_)
        | locket_platform::PlatformError::TomlDe(_)
        | locket_platform::PlatformError::TomlSer(_)
        | locket_platform::PlatformError::Crypto(_)
        | locket_platform::PlatformError::MemoryPoisoned => {
            LocketError::KeychainUnavailable.exit_code()
        }
    }
}

pub fn typed_cli_error(kind: LocketError, message: impl Into<String>) -> CliError {
    CliError::Typed { kind, message: message.into() }
}

pub fn project_root_untrusted_error() -> CliError {
    typed_cli_error(
        LocketError::ProjectRootUntrusted,
        "ProjectRootNotTrusted: current project root is not trusted; run locket project trust-root",
    )
}

pub fn secret_deleted_error(message: impl Into<String>) -> CliError {
    typed_cli_error(LocketError::SecretDeleted, message)
}

pub fn bundle_verification_error(message: impl Into<String>) -> CliError {
    typed_cli_error(LocketError::BundleVerificationFailed, message)
}

pub fn unimplemented_in_build_error(message: impl Into<String>) -> CliError {
    typed_cli_error(LocketError::PolicyValidationIncomplete, message)
}

pub fn exec_prepare_error(error: locket_exec::ExecError) -> CliError {
    match error {
        locket_exec::ExecError::Environment(error) => {
            typed_cli_error(LocketError::EnvironmentConflict, error.to_string())
        }
        locket_exec::ExecError::EmptyCommand => CliError::Config("empty command".to_owned()),
    }
}

pub fn child_exit_error(status: std::process::ExitStatus) -> CliError {
    CliError::ChildExit(status.code().and_then(|code| u8::try_from(code).ok()).unwrap_or(1))
}

impl Display for CliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(message) | Self::Typed { message, .. } => formatter.write_str(message),
            Self::ChildExit(code) => write!(formatter, "child process exited with code {code}"),
            Self::Io(error) => error.fmt(formatter),
            Self::Store(error) => error.fmt(formatter),
            Self::Json(error) => error.fmt(formatter),
            Self::TomlDe(error) => error.fmt(formatter),
            Self::TomlSer(error) => error.fmt(formatter),
            Self::Crypto(error) => error.fmt(formatter),
            Self::Platform(error) => error.fmt(formatter),
            Self::Time => formatter.write_str("system time is before the Unix epoch"),
        }
    }
}

impl Error for CliError {}

impl From<io::Error> for CliError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<StoreError> for CliError {
    fn from(value: StoreError) -> Self {
        Self::Store(value)
    }
}

impl From<serde_json::Error> for CliError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

impl From<toml::de::Error> for CliError {
    fn from(value: toml::de::Error) -> Self {
        Self::TomlDe(value)
    }
}

impl From<toml::ser::Error> for CliError {
    fn from(value: toml::ser::Error) -> Self {
        Self::TomlSer(value)
    }
}

impl From<locket_crypto::CryptoError> for CliError {
    fn from(value: locket_crypto::CryptoError) -> Self {
        Self::Crypto(value)
    }
}

impl From<locket_platform::PlatformError> for CliError {
    fn from(value: locket_platform::PlatformError) -> Self {
        Self::Platform(value)
    }
}
