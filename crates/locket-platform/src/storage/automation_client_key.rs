//! Automation-client private-key storage helpers.

use std::collections::BTreeMap;
use std::sync::Mutex;

use data_encoding::BASE64URL_NOPAD;
use keyring_core::Entry;
use locket_crypto::{KEY_LEN, KeyBytes};
use zeroize::{Zeroize, Zeroizing};

use crate::error::PlatformError;

pub const AUTOMATION_CLIENT_KEYRING_SERVICE: &str = "dev.0xdoublesharp.locket";
const AUTOMATION_CLIENT_ACCOUNT_PREFIX: &str = "automation-client:";

/// OS-keychain reference for a stored automation-client private key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AutomationClientKeychainRef {
    /// Keychain service name.
    pub service: String,
    /// Keychain account name.
    pub account: String,
}

/// Storage backend for Locket-managed automation-client private keys.
pub trait AutomationClientKeyStore {
    /// Stores a private signing seed and returns the metadata-only keychain ref.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError`] when the platform storage backend rejects the
    /// write.
    fn store_client_key(
        &self,
        client_id: &str,
        private_key: &KeyBytes,
    ) -> Result<AutomationClientKeychainRef, PlatformError>;

    /// Deletes a stored private signing seed if present.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError`] when the platform storage backend rejects the
    /// deletion.
    fn delete_client_key(&self, client_id: &str) -> Result<(), PlatformError>;
}

/// OS keychain-backed automation-client private-key store.
#[derive(Debug, Clone, Copy, Default)]
pub struct KeyringAutomationClientKeyStore;

impl AutomationClientKeyStore for KeyringAutomationClientKeyStore {
    fn store_client_key(
        &self,
        client_id: &str,
        private_key: &KeyBytes,
    ) -> Result<AutomationClientKeychainRef, PlatformError> {
        let reference = automation_client_keychain_ref(client_id);
        let entry = automation_client_key_entry(client_id)?;
        entry.set_password(&encode_client_key(private_key)).map_err(PlatformError::Keyring)?;
        Ok(reference)
    }

    fn delete_client_key(&self, client_id: &str) -> Result<(), PlatformError> {
        let entry = automation_client_key_entry(client_id)?;
        match entry.delete_credential() {
            Ok(()) | Err(keyring_core::Error::NoEntry) => Ok(()),
            Err(error) => Err(PlatformError::Keyring(error)),
        }
    }
}

/// In-memory automation-client private-key store for tests.
#[derive(Debug, Default)]
pub struct MemoryAutomationClientKeyStore {
    keys: Mutex<BTreeMap<String, KeyBytes>>,
}

impl MemoryAutomationClientKeyStore {
    /// Returns a copy of a stored seed for assertions.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::MemoryPoisoned`] if the test store lock is poisoned.
    pub fn load_client_key(
        &self,
        client_id: &str,
    ) -> Result<Option<Zeroizing<KeyBytes>>, PlatformError> {
        let keys = self.keys.lock().map_err(|_| PlatformError::MemoryPoisoned)?;
        Ok(keys.get(client_id).copied().map(Zeroizing::new))
    }
}

impl AutomationClientKeyStore for MemoryAutomationClientKeyStore {
    fn store_client_key(
        &self,
        client_id: &str,
        private_key: &KeyBytes,
    ) -> Result<AutomationClientKeychainRef, PlatformError> {
        let mut keys = self.keys.lock().map_err(|_| PlatformError::MemoryPoisoned)?;
        if let Some(old_key) = keys.get_mut(client_id) {
            old_key.zeroize();
        }
        keys.insert(client_id.to_owned(), *private_key);
        drop(keys);
        Ok(automation_client_keychain_ref(client_id))
    }

    fn delete_client_key(&self, client_id: &str) -> Result<(), PlatformError> {
        let mut keys = self.keys.lock().map_err(|_| PlatformError::MemoryPoisoned)?;
        if let Some(mut key) = keys.remove(client_id) {
            key.zeroize();
        }
        drop(keys);
        Ok(())
    }
}

#[must_use]
pub fn automation_client_keychain_ref(client_id: &str) -> AutomationClientKeychainRef {
    AutomationClientKeychainRef {
        service: AUTOMATION_CLIENT_KEYRING_SERVICE.to_owned(),
        account: automation_client_key_account(client_id),
    }
}

fn automation_client_key_entry(client_id: &str) -> Result<Entry, PlatformError> {
    let reference = automation_client_keychain_ref(client_id);
    Entry::new(&reference.service, &reference.account).map_err(PlatformError::Keyring)
}

fn automation_client_key_account(client_id: &str) -> String {
    format!("{AUTOMATION_CLIENT_ACCOUNT_PREFIX}{client_id}")
}

fn encode_client_key(private_key: &KeyBytes) -> String {
    BASE64URL_NOPAD.encode(private_key)
}

#[allow(dead_code)]
fn decode_client_key(encoded: &str) -> Result<Zeroizing<KeyBytes>, PlatformError> {
    let decoded = Zeroizing::new(
        BASE64URL_NOPAD.decode(encoded.as_bytes()).map_err(|_| PlatformError::InvalidMasterKey)?,
    );
    if decoded.len() != KEY_LEN {
        return Err(PlatformError::InvalidMasterKey);
    }
    let mut key = Zeroizing::new([0_u8; KEY_LEN]);
    key.copy_from_slice(&decoded);
    Ok(key)
}
