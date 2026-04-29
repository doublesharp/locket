//! Error and result types for `locket-crypto`.

use thiserror::Error;

/// Result type used by this crate.
pub type CryptoResult<T> = Result<T, CryptoError>;

/// Error returned by Locket crypto helpers.
#[derive(Debug, Clone, Copy, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum CryptoError {
    /// A canonical field name is too large for the v1 encoding.
    #[error("canonical field name is too long")]
    FieldNameTooLong,
    /// A canonical field value is too large for the v1 encoding.
    #[error("canonical field value is too long")]
    FieldValueTooLong,
    /// Secret values must be UTF-8 and must not contain NUL bytes.
    #[error("invalid secret value")]
    InvalidSecretValue,
    /// The operating system random number generator failed.
    #[error("random generation failed")]
    RandomFailed,
    /// HKDF expansion failed.
    #[error("key derivation failed")]
    KeyDerivationFailed,
    /// Stored passphrase KDF parameters are unsupported or malformed.
    #[error("invalid kdf parameters")]
    InvalidKdfParameters,
    /// Encryption failed.
    #[error("encryption failed")]
    EncryptionFailed,
    /// Decryption failed.
    #[error("decryption failed")]
    DecryptionFailed,
    /// A wrapped DEK did not use the canonical embedded nonce layout.
    #[error("invalid wrapped key layout")]
    InvalidWrappedKey,
}
