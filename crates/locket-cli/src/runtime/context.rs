//! Runtime context shared across CLI commands.

use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use directories::{BaseDirs, ProjectDirs};
use locket_platform::{
    AutomationClientKeyStore, KeyringAutomationClientKeyStore, KeyringMasterKeyStore,
    LocalUserVerifier, MasterKeyStore, PassphraseFallbackMasterKeyStore, PlatformPasskeyRegistrar,
    default_local_user_verifier, default_platform_passkey_registrar,
};

use crate::CONFIG_TOML;
use crate::runtime::error::{CliError, corrupt_db_error};
use crate::runtime::prompts::{
    ConfirmationReader, EnvOrPromptPassphraseReader, PassphraseReader, RecoveryCodeReader,
    SecretValueReader, StdinConfirmationReader, StdinOrPromptSecretValueReader,
    TtyRecoveryCodeReader,
};

#[derive(Clone)]
pub struct RuntimeContext {
    pub cwd: PathBuf,
    pub store_path: PathBuf,
    pub config_path: PathBuf,
    pub template_dir: PathBuf,
    /// Optional override for the agent data directory. When set, the
    /// `agent_socket_path` / `agent_pid_path` / `agent_log_path` helpers
    /// resolve against this path. When `None`, the helpers fall back to
    /// `store_path.parent()` so existing test contexts that drop their
    /// store into a tempdir continue to derive a tempdir-local socket.
    /// Production startup populates this with the spec-mandated
    /// platform path (Linux: `$XDG_RUNTIME_DIR/locket`, macOS:
    /// `~/Library/Application Support/locket`, Windows: stub).
    pub agent_data_dir: Option<PathBuf>,
    pub key_store: Arc<dyn MasterKeyStore + Send + Sync>,
    pub automation_client_key_store: Arc<dyn AutomationClientKeyStore + Send + Sync>,
    pub passphrase_store: PassphraseFallbackMasterKeyStore,
    pub passphrase_reader: Arc<dyn PassphraseReader + Send + Sync>,
    pub recovery_code_reader: Arc<dyn RecoveryCodeReader + Send + Sync>,
    pub confirmation_reader: Arc<dyn ConfirmationReader + Send + Sync>,
    pub secret_value_reader: Arc<dyn SecretValueReader + Send + Sync>,
    pub user_verifier: Arc<dyn LocalUserVerifier + Send + Sync>,
    pub passkey_registrar: Arc<dyn PlatformPasskeyRegistrar + Send + Sync>,
}

impl RuntimeContext {
    pub fn default() -> Result<Self, CliError> {
        let cwd = std::env::current_dir()?;
        let Some(project_dirs) = ProjectDirs::from("dev", "0xdoublesharp", "Locket") else {
            return Err(corrupt_db_error("could not resolve a local data directory"));
        };
        let Some(base_dirs) = BaseDirs::new() else {
            return Err(corrupt_db_error("could not resolve a local home directory"));
        };
        let data_dir = project_dirs.data_dir();
        let config_dir = project_dirs.config_dir();
        fs::create_dir_all(data_dir)?;
        fs::create_dir_all(config_dir)?;
        Ok(Self {
            cwd,
            store_path: data_dir.join("store.db"),
            config_path: config_dir.join(CONFIG_TOML),
            template_dir: base_dirs.home_dir().join(".locket").join("templates"),
            agent_data_dir: resolve_default_agent_data_dir(base_dirs.home_dir()),
            key_store: Arc::new(KeyringMasterKeyStore),
            automation_client_key_store: Arc::new(KeyringAutomationClientKeyStore),
            passphrase_store: PassphraseFallbackMasterKeyStore::new(
                data_dir.join("passphrase-fallback"),
            ),
            passphrase_reader: Arc::new(EnvOrPromptPassphraseReader),
            recovery_code_reader: Arc::new(TtyRecoveryCodeReader),
            confirmation_reader: Arc::new(StdinConfirmationReader),
            secret_value_reader: Arc::new(StdinOrPromptSecretValueReader),
            user_verifier: default_local_user_verifier(),
            passkey_registrar: Arc::new(default_platform_passkey_registrar()),
        })
    }
}

/// Resolves the spec-mandated default agent data directory for the
/// current platform. Honors `docs/specs/agent.md:18-21`:
///
/// - Linux: `$XDG_RUNTIME_DIR/locket` when set, falling back to
///   `<HOME>/.locket`. The runtime-dir path is the agent's preferred
///   location because it is per-user, ephemeral, and `0o700` by default
///   on systemd installs.
/// - macOS: `<HOME>/Library/Application Support/locket`.
/// - Windows: today this returns `<HOME>/.locket` as a documented stub.
///   The spec calls for `\\.\pipe\locket-agent-<sid>`; resolving the
///   user's SID requires the `windows`/`windows-sys` crate which the
///   CLI does not yet depend on. The Windows pipe wiring is a separate
///   follow-up; until then, callers fall back to a HOME-relative
///   directory and the existing direct-CLI flows still work.
#[must_use]
pub fn resolve_default_agent_data_dir(home: &std::path::Path) -> Option<PathBuf> {
    resolve_agent_data_dir_for_platform(home, std::env::var_os("XDG_RUNTIME_DIR"))
}

fn resolve_agent_data_dir_for_platform(
    home: &std::path::Path,
    _xdg_runtime_dir: Option<std::ffi::OsString>,
) -> Option<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        if let Some(value) = _xdg_runtime_dir {
            let path = PathBuf::from(value);
            if !path.as_os_str().is_empty() {
                return Some(path.join("locket"));
            }
        }
        Some(home.join(".locket"))
    }
    #[cfg(target_os = "macos")]
    {
        Some(home.join("Library").join("Application Support").join("locket"))
    }
    #[cfg(all(not(target_os = "linux"), not(target_os = "macos")))]
    {
        // Windows and other platforms fall back to a HOME-relative
        // directory until the named-pipe path resolution lands. See
        // `docs/specs/agent.md:18-21`.
        Some(home.join(".locket"))
    }
}

#[cfg(test)]
mod tests {
    use super::resolve_agent_data_dir_for_platform;
    use std::path::Path;

    #[test]
    #[cfg(target_os = "linux")]
    fn agent_data_dir_prefers_xdg_runtime_dir_on_linux() {
        assert_eq!(
            resolve_agent_data_dir_for_platform(
                Path::new("/home/alice"),
                Some("/run/user/1000".into())
            ),
            Some(Path::new("/run/user/1000").join("locket"))
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn agent_data_dir_falls_back_to_home_on_linux_without_xdg_runtime_dir() {
        assert_eq!(
            resolve_agent_data_dir_for_platform(Path::new("/home/alice"), None),
            Some(Path::new("/home/alice").join(".locket"))
        );
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn agent_data_dir_uses_application_support_on_macos() {
        assert_eq!(
            resolve_agent_data_dir_for_platform(Path::new("/Users/alice"), None),
            Some(
                Path::new("/Users/alice")
                    .join("Library")
                    .join("Application Support")
                    .join("locket")
            )
        );
    }
}
