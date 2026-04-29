//! Platform integration layer for Locket.

// rand 0.9 transitively brings rand_core 0.6 and 0.9 via other deps,
// triggering this lint. Cannot be fixed without upgrading all crates.
#![allow(clippy::multiple_crate_versions)]

use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use std::{fs, io, path::Path};

use data_encoding::BASE64URL_NOPAD;
use keyring::Entry;
use locket_crypto::{KEY_LEN, KeyBytes, NONCE_LEN};
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
    /// I/O error during recovery file operations.
    #[error("recovery io error: {0}")]
    Io(#[from] io::Error),
    /// Recovery envelope binary data is corrupt or uses an unsupported format.
    #[error("invalid recovery envelope: {0}")]
    InvalidRecoveryEnvelope(String),
    /// Recovery envelope uses a schema version newer than this binary supports.
    #[error("recovery envelope schema version {0} is not supported; upgrade locket")]
    RecoveryEnvelopeSchemaUnsupported(u16),
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

/// Schema version for recovery KDF TOML files.
pub const RECOVERY_KDF_TOML_VERSION: u32 = 1;

/// Persisted KDF parameters for the recovery envelope (stored in `recovery/kdf.toml`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryKdfToml {
    /// Unique identifier for this KDF parameter set.
    pub kdf_profile_id: String,
    /// Algorithm name (always `"argon2id"`).
    pub algorithm: String,
    /// Schema version.
    pub version: u32,
    /// Base64URL-nopad encoded salt.
    pub salt: String,
    /// Argon2id memory cost in KiB.
    pub m_cost: u32,
    /// Argon2id iteration count.
    pub t_cost: u32,
    /// Argon2id parallelism.
    pub p_cost: u32,
    /// Output length in bytes.
    pub output_len: u32,
    /// Creation timestamp in Unix nanoseconds.
    pub created_at: i64,
}

impl RecoveryKdfToml {
    /// Creates a new v1 `RecoveryKdfToml` from a profile ID, salt bytes, and creation timestamp.
    #[must_use]
    pub fn new_v1(kdf_profile_id: String, salt_bytes: &[u8], created_at_nanos: i64) -> Self {
        use locket_crypto::{KEY_LEN, RECOVERY_M_COST, RECOVERY_P_COST, RECOVERY_T_COST};
        // KEY_LEN is 32, well within u32 range.
        #[allow(clippy::cast_possible_truncation)]
        let output_len = KEY_LEN as u32;
        Self {
            kdf_profile_id,
            algorithm: "argon2id".to_owned(),
            version: RECOVERY_KDF_TOML_VERSION,
            salt: BASE64URL_NOPAD.encode(salt_bytes),
            m_cost: RECOVERY_M_COST,
            t_cost: RECOVERY_T_COST,
            p_cost: RECOVERY_P_COST,
            output_len,
            created_at: created_at_nanos,
        }
    }

    /// Decodes the base64url-nopad salt field back to bytes.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::InvalidRecoveryEnvelope`] if the salt is not valid base64url.
    pub fn decode_salt(&self) -> Result<Vec<u8>, PlatformError> {
        BASE64URL_NOPAD
            .decode(self.salt.as_bytes())
            .map_err(|_| PlatformError::InvalidRecoveryEnvelope("invalid kdf salt encoding".into()))
    }

    /// Converts the stored parameters to a [`locket_crypto::RecoveryKdfParams`].
    #[must_use]
    pub const fn to_crypto_params(&self) -> locket_crypto::RecoveryKdfParams {
        locket_crypto::RecoveryKdfParams {
            m_cost: self.m_cost,
            t_cost: self.t_cost,
            p_cost: self.p_cost,
            output_len: self.output_len,
        }
    }
}

/// A single entry in the recovery envelope (plaintext kind/id + encrypted payload).
#[derive(Debug, Clone)]
pub struct RecoveryEnvelopeEntry {
    /// Entry kind, e.g. `"master_key"`.
    pub entry_kind: String,
    /// Entry identifier, e.g. the project ID.
    pub entry_id: String,
    /// Nonce used for the AEAD encryption of this entry.
    pub nonce: locket_crypto::NonceBytes,
    /// AEAD ciphertext (plaintext + tag).
    pub ciphertext: Vec<u8>,
}

/// Recovery envelope binary container.
///
/// Stored at `recovery/envelope.bin`. All integers are little-endian.
#[derive(Debug, Clone)]
pub struct RecoveryEnvelope {
    /// KDF profile identifier matching the `kdf.toml` file.
    pub kdf_profile_id: String,
    /// Creation timestamp in Unix nanoseconds (i128 LE).
    pub created_at_unix_nanos: i128,
    /// Encrypted entries within this envelope.
    pub entries: Vec<RecoveryEnvelopeEntry>,
}

impl RecoveryEnvelope {
    /// Serializes the envelope to its canonical binary format.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::InvalidRecoveryEnvelope`] if entry counts overflow.
    pub fn serialize(&self) -> Result<Vec<u8>, PlatformError> {
        use locket_crypto::{RECOVERY_ENVELOPE_SCHEMA_V1, RECOVERY_MAGIC};
        let mut buf = Vec::new();
        buf.extend_from_slice(RECOVERY_MAGIC);
        buf.extend_from_slice(&RECOVERY_ENVELOPE_SCHEMA_V1.to_le_bytes());
        write_field(&mut buf, "kdf_profile_id", self.kdf_profile_id.as_bytes())?;
        buf.extend_from_slice(&self.created_at_unix_nanos.to_le_bytes());
        let entry_count = u32::try_from(self.entries.len())
            .map_err(|_| PlatformError::InvalidRecoveryEnvelope("too many entries".into()))?;
        buf.extend_from_slice(&entry_count.to_le_bytes());
        for entry in &self.entries {
            write_field(&mut buf, "entry_kind", entry.entry_kind.as_bytes())?;
            write_field(&mut buf, "entry_id", entry.entry_id.as_bytes())?;
            buf.extend_from_slice(&entry.nonce);
            let ct_len = u32::try_from(entry.ciphertext.len())
                .map_err(|_| PlatformError::InvalidRecoveryEnvelope("ciphertext too large".into()))?;
            buf.extend_from_slice(&ct_len.to_le_bytes());
            buf.extend_from_slice(&entry.ciphertext);
        }
        Ok(buf)
    }

    /// Deserializes an envelope from its canonical binary format.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::InvalidRecoveryEnvelope`] if the data is truncated or corrupt,
    /// or [`PlatformError::RecoveryEnvelopeSchemaUnsupported`] for unknown schema versions.
    pub fn deserialize(data: &[u8]) -> Result<Self, PlatformError> {
        use locket_crypto::{RECOVERY_ENVELOPE_SCHEMA_V1, RECOVERY_MAGIC};
        let mut cur = 0usize;

        // Magic
        let magic = read_exact(&mut cur, 16, data)?;
        if magic != RECOVERY_MAGIC.as_slice() {
            return Err(PlatformError::InvalidRecoveryEnvelope("bad magic bytes".into()));
        }
        // Schema version
        let ver_bytes = read_exact(&mut cur, 2, data)?;
        let schema_version = u16::from_le_bytes([ver_bytes[0], ver_bytes[1]]);
        if schema_version != RECOVERY_ENVELOPE_SCHEMA_V1 {
            return Err(PlatformError::RecoveryEnvelopeSchemaUnsupported(schema_version));
        }
        // kdf_profile_id field
        let kdf_profile_id = read_field_string(&mut cur, data)?;
        // created_at (i128 LE = 16 bytes)
        let created_bytes = read_exact(&mut cur, 16, data)?;
        let created_at_unix_nanos = i128::from_le_bytes(
            created_bytes.try_into().map_err(|_| {
                PlatformError::InvalidRecoveryEnvelope("truncated timestamp".into())
            })?,
        );
        // entry_count
        let count_bytes = read_exact(&mut cur, 4, data)?;
        let entry_count =
            u32::from_le_bytes([count_bytes[0], count_bytes[1], count_bytes[2], count_bytes[3]]);
        // Entries
        let mut entries = Vec::with_capacity(entry_count as usize);
        for _ in 0..entry_count {
            let entry_kind = read_field_string(&mut cur, data)?;
            let entry_id = read_field_string(&mut cur, data)?;
            let nonce_bytes = read_exact(&mut cur, NONCE_LEN, data)?;
            let mut nonce = [0u8; NONCE_LEN];
            nonce.copy_from_slice(nonce_bytes);
            let ct_len_bytes = read_exact(&mut cur, 4, data)?;
            let ct_len = u32::from_le_bytes([
                ct_len_bytes[0],
                ct_len_bytes[1],
                ct_len_bytes[2],
                ct_len_bytes[3],
            ]) as usize;
            let ciphertext = read_exact(&mut cur, ct_len, data)?.to_vec();
            entries.push(RecoveryEnvelopeEntry { entry_kind, entry_id, nonce, ciphertext });
        }
        Ok(Self { kdf_profile_id, created_at_unix_nanos, entries })
    }
}

fn write_field(buf: &mut Vec<u8>, name: &str, value: &[u8]) -> Result<(), PlatformError> {
    let name_len = u16::try_from(name.len())
        .map_err(|_| PlatformError::InvalidRecoveryEnvelope("field name too long".into()))?;
    let value_len = u32::try_from(value.len())
        .map_err(|_| PlatformError::InvalidRecoveryEnvelope("field value too long".into()))?;
    buf.extend_from_slice(&name_len.to_le_bytes());
    buf.extend_from_slice(name.as_bytes());
    buf.extend_from_slice(&value_len.to_le_bytes());
    buf.extend_from_slice(value);
    Ok(())
}

fn read_exact<'a>(cur: &mut usize, n: usize, data: &'a [u8]) -> Result<&'a [u8], PlatformError> {
    if *cur + n > data.len() {
        return Err(PlatformError::InvalidRecoveryEnvelope("truncated".into()));
    }
    let slice = &data[*cur..*cur + n];
    *cur += n;
    Ok(slice)
}

fn read_field_string(cur: &mut usize, data: &[u8]) -> Result<String, PlatformError> {
    let err = || PlatformError::InvalidRecoveryEnvelope("truncated field".into());
    if *cur + 2 > data.len() {
        return Err(err());
    }
    let name_len = u16::from_le_bytes([data[*cur], data[*cur + 1]]) as usize;
    *cur += 2;
    if *cur + name_len > data.len() {
        return Err(err());
    }
    *cur += name_len; // skip name bytes (we do not validate them here)
    if *cur + 4 > data.len() {
        return Err(err());
    }
    let value_len =
        u32::from_le_bytes([data[*cur], data[*cur + 1], data[*cur + 2], data[*cur + 3]]) as usize;
    *cur += 4;
    if *cur + value_len > data.len() {
        return Err(err());
    }
    let s = std::str::from_utf8(&data[*cur..*cur + value_len])
        .map_err(|_| PlatformError::InvalidRecoveryEnvelope("non-utf8 field value".into()))?
        .to_owned();
    *cur += value_len;
    Ok(s)
}

/// Loads and parses `kdf.toml` from a recovery directory.
///
/// # Errors
///
/// Returns [`PlatformError::Io`] if the file cannot be read, or
/// [`PlatformError::InvalidRecoveryEnvelope`] if the TOML is malformed.
pub fn load_recovery_kdf_toml(recovery_dir: &Path) -> Result<RecoveryKdfToml, PlatformError> {
    let path = recovery_dir.join("kdf.toml");
    let text = fs::read_to_string(&path).map_err(PlatformError::Io)?;
    toml::from_str(&text).map_err(|e| PlatformError::InvalidRecoveryEnvelope(e.to_string()))
}

/// Saves `kdf.toml` to a recovery directory (creates the directory if absent).
///
/// # Errors
///
/// Returns [`PlatformError::Io`] on filesystem errors, or
/// [`PlatformError::InvalidRecoveryEnvelope`] if TOML serialization fails.
pub fn save_recovery_kdf_toml(
    recovery_dir: &Path,
    kdf: &RecoveryKdfToml,
) -> Result<(), PlatformError> {
    fs::create_dir_all(recovery_dir).map_err(PlatformError::Io)?;
    let path = recovery_dir.join("kdf.toml");
    let text =
        toml::to_string(kdf).map_err(|e| PlatformError::InvalidRecoveryEnvelope(e.to_string()))?;
    fs::write(path, text).map_err(PlatformError::Io)
}

/// Loads and deserializes `envelope.bin` from a recovery directory.
///
/// # Errors
///
/// Returns [`PlatformError::Io`] if the file cannot be read, or propagates
/// [`RecoveryEnvelope::deserialize`] errors.
pub fn load_recovery_envelope(recovery_dir: &Path) -> Result<RecoveryEnvelope, PlatformError> {
    let path = recovery_dir.join("envelope.bin");
    let data = fs::read(&path).map_err(PlatformError::Io)?;
    RecoveryEnvelope::deserialize(&data)
}

/// Atomically writes `envelope.bin` to a recovery directory.
///
/// # Errors
///
/// Returns [`PlatformError::Io`] on filesystem errors or propagates
/// [`RecoveryEnvelope::serialize`] errors.
pub fn save_recovery_envelope(
    recovery_dir: &Path,
    envelope: &RecoveryEnvelope,
) -> Result<(), PlatformError> {
    fs::create_dir_all(recovery_dir).map_err(PlatformError::Io)?;
    let path = recovery_dir.join("envelope.bin");
    let tmp = recovery_dir.join("envelope.bin.tmp");
    let data = envelope.serialize()?;
    fs::write(&tmp, &data).map_err(PlatformError::Io)?;
    fs::rename(&tmp, &path).map_err(PlatformError::Io)
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
    fn rejects_invalid_encoded_key_alphabet() {
        assert!(matches!(decode_key("not valid base64"), Err(PlatformError::InvalidMasterKey)));
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
    fn memory_store_replaces_existing_project_key() -> Result<(), PlatformError> {
        let store = MemoryMasterKeyStore::default();
        let replacement = [7; KEY_LEN];

        store.store_master_key(PROJECT_ID, &MASTER_KEY)?;
        store.store_master_key("lk_proj_other", &replacement)?;

        assert!(matches!(store.load_master_key(PROJECT_ID), Err(PlatformError::MasterKeyNotFound)));
        assert_eq!(&*store.load_master_key("lk_proj_other")?, &replacement);
        Ok(())
    }

    #[test]
    fn keyring_account_is_project_scoped() {
        assert_eq!(master_key_account(PROJECT_ID), "master:lk_proj_test");
    }
}
