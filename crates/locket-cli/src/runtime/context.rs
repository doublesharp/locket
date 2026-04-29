//! Runtime context shared across CLI commands.

use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use directories::{BaseDirs, ProjectDirs};
use locket_platform::{KeyringMasterKeyStore, MasterKeyStore, PassphraseFallbackMasterKeyStore};

use crate::CONFIG_TOML;
use crate::cli_error::CliError;
use crate::prompts::{
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
    pub key_store: Arc<dyn MasterKeyStore + Send + Sync>,
    pub passphrase_store: PassphraseFallbackMasterKeyStore,
    pub passphrase_reader: Arc<dyn PassphraseReader + Send + Sync>,
    pub recovery_code_reader: Arc<dyn RecoveryCodeReader + Send + Sync>,
    pub confirmation_reader: Arc<dyn ConfirmationReader + Send + Sync>,
    pub secret_value_reader: Arc<dyn SecretValueReader + Send + Sync>,
}

impl RuntimeContext {
    pub fn default() -> Result<Self, CliError> {
        let cwd = std::env::current_dir()?;
        let Some(project_dirs) = ProjectDirs::from("dev", "0xdoublesharp", "Locket") else {
            return Err(CliError::Config("could not resolve a local data directory".to_owned()));
        };
        let Some(base_dirs) = BaseDirs::new() else {
            return Err(CliError::Config("could not resolve a local home directory".to_owned()));
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
            key_store: Arc::new(KeyringMasterKeyStore),
            passphrase_store: PassphraseFallbackMasterKeyStore::new(
                data_dir.join("passphrase-fallback"),
            ),
            passphrase_reader: Arc::new(EnvOrPromptPassphraseReader),
            recovery_code_reader: Arc::new(TtyRecoveryCodeReader),
            confirmation_reader: Arc::new(StdinConfirmationReader),
            secret_value_reader: Arc::new(StdinOrPromptSecretValueReader),
        })
    }
}
