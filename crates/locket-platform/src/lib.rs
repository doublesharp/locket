//! Platform integration layer for Locket.

use std::sync::Mutex;

use data_encoding::BASE64URL_NOPAD;
use keyring::Entry;
use locket_crypto::{KEY_LEN, KeyBytes};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

const KEYRING_SERVICE: &str = "dev.0xdoublesharp.locket";
const MASTER_KEY_ACCOUNT_PREFIX: &str = "master:";

/// Returns the current platform name used in diagnostics.
#[must_use]
pub const fn platform_name() -> &'static str {
    std::env::consts::OS
}

/// Interface for local master-key storage.
pub trait MasterKeyStore {
    /// Stores a master key for `project_id`.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError`] when the platform storage backend rejects the
    /// write.
    fn store_master_key(
        &self,
        project_id: &str,
        master_key: &KeyBytes,
    ) -> Result<(), PlatformError>;

    /// Loads a master key for `project_id`.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::MasterKeyNotFound`] when no key exists and
    /// [`PlatformError`] for backend failures or invalid key material.
    fn load_master_key(&self, project_id: &str) -> Result<Zeroizing<KeyBytes>, PlatformError>;

    /// Deletes a master key for `project_id`.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError`] when the backend rejects deletion.
    fn delete_master_key(&self, project_id: &str) -> Result<(), PlatformError>;
}

/// OS keychain-backed master-key store.
#[derive(Debug, Clone, Copy, Default)]
pub struct KeyringMasterKeyStore;

impl MasterKeyStore for KeyringMasterKeyStore {
    fn store_master_key(
        &self,
        project_id: &str,
        master_key: &KeyBytes,
    ) -> Result<(), PlatformError> {
        let entry = master_key_entry(project_id)?;
        entry.set_password(&encode_key(master_key)).map_err(PlatformError::Keyring)
    }

    #[allow(clippy::significant_drop_tightening)]
    fn load_master_key(&self, project_id: &str) -> Result<Zeroizing<KeyBytes>, PlatformError> {
        let entry = master_key_entry(project_id)?;
        let encoded = entry.get_password().map_err(map_keyring_get_error)?;
        decode_key(&encoded)
    }

    fn delete_master_key(&self, project_id: &str) -> Result<(), PlatformError> {
        let entry = master_key_entry(project_id)?;
        entry.delete_credential().map_err(PlatformError::Keyring)
    }
}

/// In-memory master-key store for tests and deterministic integration harnesses.
#[derive(Debug, Default)]
pub struct MemoryMasterKeyStore {
    key: Mutex<Option<(String, KeyBytes)>>,
}

impl MasterKeyStore for MemoryMasterKeyStore {
    fn store_master_key(
        &self,
        project_id: &str,
        master_key: &KeyBytes,
    ) -> Result<(), PlatformError> {
        {
            let mut guard = self.key.lock().map_err(|_| PlatformError::MemoryPoisoned)?;
            if let Some((_, old_key)) = guard.as_mut() {
                old_key.zeroize();
            }
            *guard = Some((project_id.to_owned(), *master_key));
        }
        Ok(())
    }

    fn load_master_key(&self, project_id: &str) -> Result<Zeroizing<KeyBytes>, PlatformError> {
        let loaded = {
            let guard = self.key.lock().map_err(|_| PlatformError::MemoryPoisoned)?;
            let Some((stored_project_id, key)) = guard.as_ref() else {
                return Err(PlatformError::MasterKeyNotFound);
            };
            let loaded = if stored_project_id == project_id { Some(*key) } else { None };
            drop(guard);
            loaded
        };

        loaded.map(Zeroizing::new).ok_or(PlatformError::MasterKeyNotFound)
    }

    fn delete_master_key(&self, project_id: &str) -> Result<(), PlatformError> {
        {
            let mut guard = self.key.lock().map_err(|_| PlatformError::MemoryPoisoned)?;
            if guard.as_ref().is_some_and(|(stored_project_id, _)| stored_project_id == project_id)
                && let Some((_, mut key)) = guard.take()
            {
                key.zeroize();
            }
        }
        Ok(())
    }
}

/// Error returned by platform integration.
#[derive(Debug, Error)]
pub enum PlatformError {
    /// OS keyring returned an error.
    #[error(transparent)]
    Keyring(#[from] keyring::Error),
    /// No master key exists for the requested project.
    #[error("master key not found")]
    MasterKeyNotFound,
    /// Stored key material was malformed.
    #[error("invalid stored master key")]
    InvalidMasterKey,
    /// In-memory test store mutex was poisoned.
    #[error("memory key store poisoned")]
    MemoryPoisoned,
}

fn master_key_entry(project_id: &str) -> Result<Entry, PlatformError> {
    Entry::new(KEYRING_SERVICE, &master_key_account(project_id)).map_err(PlatformError::Keyring)
}

fn master_key_account(project_id: &str) -> String {
    format!("{MASTER_KEY_ACCOUNT_PREFIX}{project_id}")
}

fn encode_key(master_key: &KeyBytes) -> String {
    BASE64URL_NOPAD.encode(master_key)
}

fn decode_key(encoded: &str) -> Result<Zeroizing<KeyBytes>, PlatformError> {
    let mut decoded = Zeroizing::new(
        BASE64URL_NOPAD.decode(encoded.as_bytes()).map_err(|_| PlatformError::InvalidMasterKey)?,
    );
    if decoded.len() != KEY_LEN {
        decoded.zeroize();
        return Err(PlatformError::InvalidMasterKey);
    }

    let mut key = Zeroizing::new([0_u8; KEY_LEN]);
    key.copy_from_slice(&decoded);
    Ok(key)
}

fn map_keyring_get_error(error: keyring::Error) -> PlatformError {
    match error {
        keyring::Error::NoEntry => PlatformError::MasterKeyNotFound,
        other => PlatformError::Keyring(other),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        KEY_LEN, MasterKeyStore, MemoryMasterKeyStore, PlatformError, decode_key, encode_key,
        master_key_account,
    };

    const PROJECT_ID: &str = "lk_proj_test";
    const MASTER_KEY: [u8; KEY_LEN] = [42; KEY_LEN];

    #[test]
    fn encodes_master_key_without_padding() -> Result<(), PlatformError> {
        let encoded = encode_key(&MASTER_KEY);

        assert!(!encoded.contains('='));
        assert_eq!(&*decode_key(&encoded)?, &MASTER_KEY);
        Ok(())
    }

    #[test]
    fn rejects_invalid_encoded_key_length() {
        assert!(matches!(decode_key("AA"), Err(PlatformError::InvalidMasterKey)));
    }

    #[test]
    fn memory_store_round_trips_and_deletes_master_key() -> Result<(), PlatformError> {
        let store = MemoryMasterKeyStore::default();

        store.store_master_key(PROJECT_ID, &MASTER_KEY)?;
        assert_eq!(&*store.load_master_key(PROJECT_ID)?, &MASTER_KEY);

        store.delete_master_key(PROJECT_ID)?;
        assert!(matches!(store.load_master_key(PROJECT_ID), Err(PlatformError::MasterKeyNotFound)));
        Ok(())
    }

    #[test]
    fn memory_store_is_project_scoped() -> Result<(), PlatformError> {
        let store = MemoryMasterKeyStore::default();

        store.store_master_key(PROJECT_ID, &MASTER_KEY)?;

        assert!(matches!(
            store.load_master_key("lk_proj_other"),
            Err(PlatformError::MasterKeyNotFound)
        ));
        Ok(())
    }

    #[test]
    fn keyring_account_is_project_scoped() {
        assert_eq!(master_key_account(PROJECT_ID), "master:lk_proj_test");
    }
}
