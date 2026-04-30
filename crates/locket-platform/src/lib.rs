//! Platform integration layer for Locket.

// rand 0.9 transitively brings rand_core 0.6 and 0.9 via other deps,
// triggering this lint. Cannot be fixed without upgrading all crates.
#![allow(clippy::multiple_crate_versions)]

mod error;
mod fs_helpers;
mod master_key;
mod passphrase;
mod process;
mod recovery;
mod user_verification;

pub use error::PlatformError;
pub use master_key::{
    KeyringMasterKeyStore, MasterKeyStore, MemoryMasterKeyStore, MockMasterKeyStore,
    MockMasterKeyStoreFailure,
};
pub use passphrase::PassphraseFallbackMasterKeyStore;
pub use process::{
    ProcessBinding, current_process_binding, process_binding_for_pid,
    process_binding_matches_live_process,
};
pub use recovery::{
    RECOVERY_KDF_TOML_VERSION, RecoveryEnvelope, RecoveryEnvelopeEntry, RecoveryKdfToml,
    load_recovery_envelope, load_recovery_kdf_toml, save_recovery_envelope, save_recovery_kdf_toml,
};
pub use user_verification::{
    LocalUserVerification, LocalUserVerificationMethod, LocalUserVerificationRequest,
    LocalUserVerifier, MemoryLocalUserVerifier, UnavailableLocalUserVerifier,
};

// Re-exports of crate-private helpers used by `tests.rs`.
#[cfg(test)]
pub(crate) use master_key::{decode_key, encode_key, master_key_account};

/// Returns the current platform name used in diagnostics.
#[must_use]
pub const fn platform_name() -> &'static str {
    std::env::consts::OS
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
