//! Platform integration layer for Locket.

// rand 0.9 transitively brings rand_core 0.6 and 0.9 via other deps,
// triggering this lint. Cannot be fixed without upgrading all crates.
#![allow(clippy::multiple_crate_versions)]

mod error;
mod hardening;
mod ipc;
mod storage;
mod verification;

pub(crate) use hardening::{core_dumps, memory_lock};
pub(crate) use ipc::{agent_pipe, process};
pub(crate) use storage::{
    automation_client_key, device_private_key, fs_helpers, locked_vault_audit, master_key,
    passphrase, recovery,
};
#[cfg(target_os = "linux")]
pub(crate) use verification::{linux_local_authentication, linux_user_verifier};
#[cfg(target_os = "macos")]
pub(crate) use verification::{macos_local_authentication, macos_user_verifier};
pub(crate) use verification::{passkey, user_verification};
#[cfg(target_os = "windows")]
pub(crate) use verification::{windows_local_authentication, windows_user_verifier};

pub use agent_pipe::{AGENT_PIPE_PREFIX, agent_pipe_dacl_sddl_for_sid, agent_pipe_name_for_sid};
pub use automation_client_key::{
    AutomationClientKeyStore, AutomationClientKeychainRef, KeyringAutomationClientKeyStore,
    MemoryAutomationClientKeyStore,
};
pub use core_dumps::{CoreDumpHardening, core_dump_hardening_state, disable_core_dumps};
pub use device_private_key::{
    DEVICE_PRIVATE_KEY_SCHEMA_VERSION, LocalDevicePrivateKeyStorage, MemoryDevicePrivateKeyStorage,
    PrivateKeyBytes, WrappedLocalFileDevicePrivateKeyStorage,
};
pub use error::PlatformError;
pub use fs_helpers::{secure_directory, write_user_only_file};
pub use locked_vault_audit::{
    DEGRADED_AUDIT_LOG_FILENAME, DEGRADED_AUDIT_LOG_MAX_ROTATIONS, DEGRADED_AUDIT_LOG_ROTATE_BYTES,
    DEGRADED_AUDIT_LOG_SCHEMA_VERSION, LockedVaultAuditLogger, LockedVaultDenialRow,
    permission_mode as locked_vault_audit_permission_mode,
};
pub use master_key::{
    KeyringMasterKeyStore, MasterKeyStore, MemoryMasterKeyStore, MockMasterKeyStore,
    MockMasterKeyStoreFailure,
};
pub use memory_lock::{MemoryLockHardening, lock_process_memory, memory_lock_hardening_state};
pub use passkey::{
    KeyringPlatformPasskeyRegistrar, MemoryPlatformPasskeyOutcome, MemoryPlatformPasskeyRegistrar,
    PasskeyRegistration, PlatformPasskeyRegistrar, UnavailablePlatformPasskeyRegistrar,
    default_platform_passkey_registrar,
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

#[cfg(target_os = "linux")]
pub use linux_local_authentication::{
    LocalAuthError as LinuxLocalAuthError, evaluate_local_user as linux_evaluate_local_user,
};
#[cfg(target_os = "linux")]
pub use linux_user_verifier::LinuxLocalUserVerifier;

#[cfg(target_os = "macos")]
pub use macos_local_authentication::{LocalAuthError, evaluate_local_user};
#[cfg(target_os = "macos")]
pub use macos_user_verifier::MacosLocalUserVerifier;

#[cfg(target_os = "windows")]
pub use agent_pipe::{current_user_sid_string, default_agent_pipe_name};
#[cfg(target_os = "windows")]
pub use windows_local_authentication::{
    LocalAuthError as WindowsLocalAuthError, evaluate_local_user as windows_evaluate_local_user,
};
#[cfg(target_os = "windows")]
pub use windows_user_verifier::WindowsLocalUserVerifier;

// Re-exports of crate-private helpers used by `tests.rs`.
#[cfg(test)]
pub(crate) use master_key::{decode_key, encode_key, master_key_account};

/// Returns the current platform name used in diagnostics.
#[must_use]
pub const fn platform_name() -> &'static str {
    std::env::consts::OS
}

/// Returns the default [`LocalUserVerifier`] for the current target.
///
/// On macOS this returns [`MacosLocalUserVerifier`], which delegates to
/// `LocalAuthentication.framework` (`docs/specs/crypto.md:192-218`).
/// On Linux this returns [`LinuxLocalUserVerifier`], which delegates to
/// Secret Service through the platform keyring
/// (`linux_local_authentication.rs`).
/// On Windows this returns [`WindowsLocalUserVerifier`], which delegates
/// to Windows Hello `UserConsentVerifier`
/// (`windows_local_authentication.rs`).
/// On every other target this returns [`UnavailableLocalUserVerifier`]
/// so callers fail closed until a platform backend ships.
#[must_use]
pub fn default_local_user_verifier() -> std::sync::Arc<dyn LocalUserVerifier + Send + Sync> {
    #[cfg(target_os = "macos")]
    {
        std::sync::Arc::new(MacosLocalUserVerifier::new())
    }
    #[cfg(target_os = "linux")]
    {
        std::sync::Arc::new(LinuxLocalUserVerifier::new())
    }
    #[cfg(target_os = "windows")]
    {
        std::sync::Arc::new(WindowsLocalUserVerifier::new())
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        std::sync::Arc::new(UnavailableLocalUserVerifier)
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
