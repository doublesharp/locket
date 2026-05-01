//! Master-key store trait and OS keyring / in-memory implementations.

use std::sync::Mutex;

use data_encoding::BASE64URL_NOPAD;
use keyring::Entry;
use locket_crypto::{KEY_LEN, KeyBytes};
use zeroize::{Zeroize, Zeroizing};

use crate::error::PlatformError;

const KEYRING_SERVICE: &str = "dev.0xdoublesharp.locket";
const MASTER_KEY_ACCOUNT_PREFIX: &str = "master:";

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

/// Deterministic master-key store mock with per-operation failure injection.
#[derive(Debug, Default)]
pub struct MockMasterKeyStore {
    key: Mutex<Option<(String, KeyBytes)>>,
    failures: Mutex<MockMasterKeyStoreFailures>,
}

/// Failure mode returned by [`MockMasterKeyStore`] operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MockMasterKeyStoreFailure {
    /// Return [`PlatformError::MasterKeyNotFound`].
    MasterKeyNotFound,
    /// Return [`PlatformError::InvalidMasterKey`].
    InvalidMasterKey,
    /// Return [`PlatformError::MemoryPoisoned`].
    MemoryPoisoned,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct MockMasterKeyStoreFailures {
    store: Option<MockMasterKeyStoreFailure>,
    load: Option<MockMasterKeyStoreFailure>,
    delete: Option<MockMasterKeyStoreFailure>,
}

impl MockMasterKeyStoreFailure {
    const fn into_platform_error(self) -> PlatformError {
        match self {
            Self::MasterKeyNotFound => PlatformError::MasterKeyNotFound,
            Self::InvalidMasterKey => PlatformError::InvalidMasterKey,
            Self::MemoryPoisoned => PlatformError::MemoryPoisoned,
        }
    }
}

impl MockMasterKeyStore {
    /// Configures the next and future store operations to return `failure`.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::MemoryPoisoned`] if the mock's failure state is poisoned.
    pub fn set_store_failure(
        &self,
        failure: Option<MockMasterKeyStoreFailure>,
    ) -> Result<(), PlatformError> {
        self.failures.lock().map_err(|_| PlatformError::MemoryPoisoned)?.store = failure;
        Ok(())
    }

    /// Configures the next and future load operations to return `failure`.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::MemoryPoisoned`] if the mock's failure state is poisoned.
    pub fn set_load_failure(
        &self,
        failure: Option<MockMasterKeyStoreFailure>,
    ) -> Result<(), PlatformError> {
        self.failures.lock().map_err(|_| PlatformError::MemoryPoisoned)?.load = failure;
        Ok(())
    }

    /// Configures the next and future delete operations to return `failure`.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::MemoryPoisoned`] if the mock's failure state is poisoned.
    pub fn set_delete_failure(
        &self,
        failure: Option<MockMasterKeyStoreFailure>,
    ) -> Result<(), PlatformError> {
        self.failures.lock().map_err(|_| PlatformError::MemoryPoisoned)?.delete = failure;
        Ok(())
    }

    fn configured_failure(
        &self,
        operation: impl FnOnce(&MockMasterKeyStoreFailures) -> Option<MockMasterKeyStoreFailure>,
    ) -> Result<Option<PlatformError>, PlatformError> {
        let failures = self.failures.lock().map_err(|_| PlatformError::MemoryPoisoned)?;
        Ok(operation(&failures).map(MockMasterKeyStoreFailure::into_platform_error))
    }
}

impl MasterKeyStore for MockMasterKeyStore {
    fn store_master_key(
        &self,
        project_id: &str,
        master_key: &KeyBytes,
    ) -> Result<(), PlatformError> {
        if let Some(error) = self.configured_failure(|failures| failures.store)? {
            return Err(error);
        }
        let mut guard = self.key.lock().map_err(|_| PlatformError::MemoryPoisoned)?;
        if let Some((_, old_key)) = guard.as_mut() {
            old_key.zeroize();
        }
        *guard = Some((project_id.to_owned(), *master_key));
        drop(guard);
        Ok(())
    }

    fn load_master_key(&self, project_id: &str) -> Result<Zeroizing<KeyBytes>, PlatformError> {
        if let Some(error) = self.configured_failure(|failures| failures.load)? {
            return Err(error);
        }
        let loaded = {
            let guard = self.key.lock().map_err(|_| PlatformError::MemoryPoisoned)?;
            let Some((stored_project_id, key)) = guard.as_ref() else {
                return Err(PlatformError::MasterKeyNotFound);
            };
            if stored_project_id != project_id {
                return Err(PlatformError::MasterKeyNotFound);
            }
            let loaded = *key;
            drop(guard);
            loaded
        };
        Ok(Zeroizing::new(loaded))
    }

    fn delete_master_key(&self, project_id: &str) -> Result<(), PlatformError> {
        if let Some(error) = self.configured_failure(|failures| failures.delete)? {
            return Err(error);
        }
        let mut guard = self.key.lock().map_err(|_| PlatformError::MemoryPoisoned)?;
        if guard.as_ref().is_some_and(|(stored_project_id, _)| stored_project_id == project_id)
            && let Some((_, mut key)) = guard.take()
        {
            key.zeroize();
        }
        drop(guard);
        Ok(())
    }
}

pub fn master_key_entry(project_id: &str) -> Result<Entry, PlatformError> {
    Entry::new(KEYRING_SERVICE, &master_key_account(project_id)).map_err(PlatformError::Keyring)
}

pub fn master_key_account(project_id: &str) -> String {
    format!("{MASTER_KEY_ACCOUNT_PREFIX}{project_id}")
}

pub fn encode_key(master_key: &KeyBytes) -> String {
    BASE64URL_NOPAD.encode(master_key)
}

pub fn decode_key(encoded: &str) -> Result<Zeroizing<KeyBytes>, PlatformError> {
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

pub fn map_keyring_get_error(error: keyring::Error) -> PlatformError {
    match error {
        keyring::Error::NoEntry => PlatformError::MasterKeyNotFound,
        other => PlatformError::Keyring(other),
    }
}
