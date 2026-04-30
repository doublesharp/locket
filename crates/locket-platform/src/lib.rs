//! Platform integration layer for Locket.

// rand 0.9 transitively brings rand_core 0.6 and 0.9 via other deps,
// triggering this lint. Cannot be fixed without upgrading all crates.
#![allow(clippy::multiple_crate_versions)]

mod core_dumps;
mod error;
mod fs_helpers;
mod master_key;
mod memory_lock;
mod passphrase;
mod process;
mod recovery;
mod user_verification;

pub use core_dumps::{CoreDumpHardening, core_dump_hardening_state, disable_core_dumps};
pub use error::PlatformError;
pub use master_key::{
    KeyringMasterKeyStore, MasterKeyStore, MemoryMasterKeyStore, MockMasterKeyStore,
    MockMasterKeyStoreFailure,
};
pub use memory_lock::{MemoryLockHardening, lock_process_memory, memory_lock_hardening_state};
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
