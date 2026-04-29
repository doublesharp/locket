//! Platform integration layer for Locket.

use std::fs;
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use data_encoding::{BASE64URL_NOPAD, HEXLOWER};
use keyring::Entry;
use locket_crypto::{
    CryptoError, KEY_LEN, KeyBytes, PASSPHRASE_FALLBACK_SALT_LEN, PassphraseKdfParams, TAG_LEN,
    WrappedKeyMaterial, derive_passphrase_fallback_key_v1, generate_passphrase_salt,
    passphrase_fallback_aad_v1, unwrap_key_material_v1, wrap_key_material_v1,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

const KEYRING_SERVICE: &str = "dev.0xdoublesharp.locket";
const MASTER_KEY_ACCOUNT_PREFIX: &str = "master:";
const PASSPHRASE_FALLBACK_SCHEMA_VERSION: u16 = 1;
const PASSPHRASE_FALLBACK_ALGORITHM: &str = "argon2id";

/// Returns the current platform name used in diagnostics.
#[must_use]
pub const fn platform_name() -> &'static str {
    std::env::consts::OS
}

/// Request metadata for a local user-verification ceremony.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalUserVerificationRequest {
    /// Metadata-only action name, such as `unlock`, `reveal`, or `team_accept`.
    pub action: String,
    /// Metadata-only reason shown to the user by platform prompts when supported.
    pub reason: String,
}

impl LocalUserVerificationRequest {
    /// Creates a metadata-only user-verification request.
    #[must_use]
    pub fn new(action: impl Into<String>, reason: impl Into<String>) -> Self {
        Self { action: action.into(), reason: reason.into() }
    }
}

/// Platform or fallback mechanism that satisfied a local user-verification gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LocalUserVerificationMethod {
    /// OS-native user-presence prompt such as Touch ID or Windows Hello.
    PlatformPrompt,
    /// Direct CTAP2/FIDO2 user-presence or user-verification ceremony.
    HardwareKey,
    /// Explicitly configured passphrase fallback.
    PassphraseFallback,
    /// In-memory test-only verifier.
    Test,
}

/// Successful local user-verification result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalUserVerification {
    /// Mechanism that satisfied the gate.
    pub method: LocalUserVerificationMethod,
    /// Metadata-only platform label for diagnostics.
    pub platform: String,
}

impl LocalUserVerification {
    /// Creates a verified result with metadata-only platform context.
    #[must_use]
    pub fn new(method: LocalUserVerificationMethod, platform: impl Into<String>) -> Self {
        Self { method, platform: platform.into() }
    }
}

/// Interface for local user verification used by sensitive CLI, UI, and agent gates.
pub trait LocalUserVerifier {
    /// Performs a local user-verification ceremony.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::LocalUserVerificationUnavailable`] when the
    /// current build has no platform verifier, and
    /// [`PlatformError::LocalUserVerificationFailed`] when a configured
    /// verifier rejects or cannot complete the ceremony.
    fn verify_user(
        &self,
        request: &LocalUserVerificationRequest,
    ) -> Result<LocalUserVerification, PlatformError>;
}

/// Default verifier for builds where platform presence APIs are not yet wired.
#[derive(Debug, Clone, Copy, Default)]
pub struct UnavailableLocalUserVerifier;

impl LocalUserVerifier for UnavailableLocalUserVerifier {
    fn verify_user(
        &self,
        _request: &LocalUserVerificationRequest,
    ) -> Result<LocalUserVerification, PlatformError> {
        Err(PlatformError::LocalUserVerificationUnavailable)
    }
}

/// Deterministic in-memory verifier for tests and integration harnesses.
#[derive(Debug, Clone)]
pub struct MemoryLocalUserVerifier {
    allow: bool,
}

impl MemoryLocalUserVerifier {
    /// Creates a verifier that always succeeds with a test-only method.
    #[must_use]
    pub const fn allowing() -> Self {
        Self { allow: true }
    }

    /// Creates a verifier that always fails local user verification.
    #[must_use]
    pub const fn denying() -> Self {
        Self { allow: false }
    }
}

impl LocalUserVerifier for MemoryLocalUserVerifier {
    fn verify_user(
        &self,
        _request: &LocalUserVerificationRequest,
    ) -> Result<LocalUserVerification, PlatformError> {
        if self.allow {
            Ok(LocalUserVerification::new(LocalUserVerificationMethod::Test, platform_name()))
        } else {
            Err(PlatformError::LocalUserVerificationFailed)
        }
    }
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

/// File-backed passphrase fallback for local master-key storage.
#[derive(Debug, Clone)]
pub struct PassphraseFallbackMasterKeyStore {
    directory: PathBuf,
}

impl PassphraseFallbackMasterKeyStore {
    /// Creates a passphrase fallback store rooted at `directory`.
    #[must_use]
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        Self { directory: directory.into() }
    }

    /// Returns whether a fallback envelope exists for `project_id`.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError`] if `project_id` is invalid for local path use.
    pub fn contains_project(&self, project_id: &str) -> Result<bool, PlatformError> {
        Ok(self.envelope_path(project_id)?.exists())
    }

    /// Stores `master_key` encrypted by an Argon2id key derived from `passphrase`.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError`] when KDF derivation, encryption, serialization,
    /// or filesystem writes fail.
    pub fn store_master_key(
        &self,
        project_id: &str,
        master_key: &KeyBytes,
        passphrase: &[u8],
        created_at: i64,
    ) -> Result<(), PlatformError> {
        let salt = generate_passphrase_salt()?;
        let kdf_profile_id = kdf_profile_id_from_salt(&salt);
        let params = PassphraseKdfParams::fallback_v1();
        let wrapping_key = derive_passphrase_fallback_key_v1(passphrase, &salt, params)?;
        let aad = passphrase_fallback_aad_v1(project_id, &kdf_profile_id)?;
        let wrapped = wrap_key_material_v1(&wrapping_key, master_key, &aad)?;
        let envelope = PassphraseFallbackEnvelope {
            version: PASSPHRASE_FALLBACK_SCHEMA_VERSION,
            algorithm: PASSPHRASE_FALLBACK_ALGORITHM.to_owned(),
            kdf_profile_id,
            salt: encode_bytes(&salt),
            m_cost: params.m_cost,
            t_cost: params.t_cost,
            p_cost: params.p_cost,
            output_len: params.output_len,
            nonce: encode_bytes(&wrapped.nonce),
            wrapped_master_key: encode_bytes(&wrapped.ciphertext),
            created_at,
        };

        secure_directory(&self.directory)?;
        let path = self.envelope_path(project_id)?;
        let temp_path = self.temp_envelope_path(project_id)?;
        let rendered = toml::to_string_pretty(&envelope)?;
        write_user_only_file(&temp_path, rendered.as_bytes())?;
        fs::rename(temp_path, path)?;
        Ok(())
    }

    /// Loads a master key from the passphrase fallback envelope for `project_id`.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::MasterKeyNotFound`] when no envelope exists,
    /// [`PlatformError::InvalidPassphrase`] when authentication fails, and
    /// [`PlatformError`] for malformed envelopes or filesystem failures.
    pub fn load_master_key(
        &self,
        project_id: &str,
        passphrase: &[u8],
    ) -> Result<Zeroizing<KeyBytes>, PlatformError> {
        let path = self.envelope_path(project_id)?;
        let text = match fs::read_to_string(path) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(PlatformError::MasterKeyNotFound);
            }
            Err(error) => return Err(error.into()),
        };
        let envelope: PassphraseFallbackEnvelope = toml::from_str(&text)?;
        envelope.validate()?;
        let salt = decode_bytes(&envelope.salt)?;
        if salt.len() != PASSPHRASE_FALLBACK_SALT_LEN {
            return Err(PlatformError::InvalidPassphraseFallback);
        }
        let nonce = decode_nonce(&envelope.nonce)?;
        let ciphertext = decode_bytes(&envelope.wrapped_master_key)?;
        if ciphertext.len() != KEY_LEN + TAG_LEN {
            return Err(PlatformError::InvalidPassphraseFallback);
        }
        let params = PassphraseKdfParams {
            m_cost: envelope.m_cost,
            t_cost: envelope.t_cost,
            p_cost: envelope.p_cost,
            output_len: envelope.output_len,
        };
        let wrapping_key = derive_passphrase_fallback_key_v1(passphrase, &salt, params)?;
        let aad = passphrase_fallback_aad_v1(project_id, &envelope.kdf_profile_id)?;
        let wrapped = WrappedKeyMaterial { ciphertext, nonce };

        unwrap_key_material_v1(&wrapping_key, &wrapped, &aad).map_err(|error| match error {
            CryptoError::DecryptionFailed => PlatformError::InvalidPassphrase,
            other => PlatformError::Crypto(other),
        })
    }

    /// Deletes the fallback envelope for `project_id` when present.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError`] for filesystem failures other than a missing file.
    pub fn delete_master_key(&self, project_id: &str) -> Result<(), PlatformError> {
        let path = self.envelope_path(project_id)?;
        match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    fn envelope_path(&self, project_id: &str) -> Result<PathBuf, PlatformError> {
        validate_path_component(project_id)?;
        Ok(self.directory.join(format!("{project_id}.toml")))
    }

    fn temp_envelope_path(&self, project_id: &str) -> Result<PathBuf, PlatformError> {
        validate_path_component(project_id)?;
        Ok(self.directory.join(format!("{project_id}.tmp")))
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct PassphraseFallbackEnvelope {
    version: u16,
    algorithm: String,
    kdf_profile_id: String,
    salt: String,
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
    output_len: u32,
    nonce: String,
    wrapped_master_key: String,
    created_at: i64,
}

impl PassphraseFallbackEnvelope {
    fn validate(&self) -> Result<(), PlatformError> {
        let expected = PassphraseKdfParams::fallback_v1();
        if self.version != PASSPHRASE_FALLBACK_SCHEMA_VERSION
            || self.algorithm != PASSPHRASE_FALLBACK_ALGORITHM
            || !self.kdf_profile_id.starts_with("lk_kdf_")
            || self.m_cost != expected.m_cost
            || self.t_cost != expected.t_cost
            || self.p_cost != expected.p_cost
            || self.output_len != expected.output_len
        {
            return Err(PlatformError::InvalidPassphraseFallback);
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
    /// Passphrase authentication failed.
    #[error("invalid passphrase")]
    InvalidPassphrase,
    /// Passphrase fallback metadata was malformed or unsupported.
    #[error("invalid passphrase fallback metadata")]
    InvalidPassphraseFallback,
    /// Project id cannot be used as a local fallback-envelope filename.
    #[error("invalid project id for local path")]
    InvalidProjectId,
    /// Local user verification is not available in this build or platform.
    #[error("local user verification unavailable")]
    LocalUserVerificationUnavailable,
    /// Local user verification was rejected or failed.
    #[error("local user verification failed")]
    LocalUserVerificationFailed,
    /// Local filesystem operation failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// Passphrase fallback TOML decoding failed.
    #[error(transparent)]
    TomlDe(#[from] toml::de::Error),
    /// Passphrase fallback TOML encoding failed.
    #[error(transparent)]
    TomlSer(#[from] toml::ser::Error),
    /// Crypto operation failed.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
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

fn encode_bytes(bytes: &[u8]) -> String {
    BASE64URL_NOPAD.encode(bytes)
}

fn decode_bytes(encoded: &str) -> Result<Vec<u8>, PlatformError> {
    BASE64URL_NOPAD.decode(encoded.as_bytes()).map_err(|_| PlatformError::InvalidPassphraseFallback)
}

fn decode_nonce(encoded: &str) -> Result<[u8; 24], PlatformError> {
    let decoded = decode_bytes(encoded)?;
    decoded.try_into().map_err(|_| PlatformError::InvalidPassphraseFallback)
}

fn kdf_profile_id_from_salt(salt: &[u8]) -> String {
    let prefix_len = salt.len().min(16);
    format!("lk_kdf_{}", HEXLOWER.encode(&salt[..prefix_len]))
}

fn validate_path_component(value: &str) -> Result<(), PlatformError> {
    if value.is_empty()
        || !value.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(PlatformError::InvalidProjectId);
    }
    Ok(())
}

fn secure_directory(path: &Path) -> Result<(), PlatformError> {
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn write_user_only_file(path: &Path, contents: &[u8]) -> Result<(), PlatformError> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(contents)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        KEY_LEN, LocalUserVerificationMethod, LocalUserVerificationRequest, LocalUserVerifier,
        MasterKeyStore, MemoryLocalUserVerifier, MemoryMasterKeyStore,
        PassphraseFallbackMasterKeyStore, PlatformError, UnavailableLocalUserVerifier, decode_key,
        encode_key, master_key_account,
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

    #[test]
    fn unavailable_user_verifier_fails_closed() {
        let verifier = UnavailableLocalUserVerifier;
        let request = LocalUserVerificationRequest::new("reveal", "Reveal DATABASE_URL");

        let result = verifier.verify_user(&request);

        assert!(matches!(result, Err(PlatformError::LocalUserVerificationUnavailable)));
    }

    #[test]
    fn memory_user_verifier_supports_success_and_failure() -> Result<(), PlatformError> {
        let request = LocalUserVerificationRequest::new("unlock", "Unlock local vault");
        let success = MemoryLocalUserVerifier::allowing().verify_user(&request)?;

        assert_eq!(success.method, LocalUserVerificationMethod::Test);
        assert_eq!(success.platform, super::platform_name());
        assert!(matches!(
            MemoryLocalUserVerifier::denying().verify_user(&request),
            Err(PlatformError::LocalUserVerificationFailed)
        ));
        Ok(())
    }

    #[test]
    fn passphrase_fallback_round_trips_master_key() -> Result<(), PlatformError> {
        let directory = tempfile::tempdir()?;
        let store = PassphraseFallbackMasterKeyStore::new(directory.path());

        store.store_master_key(PROJECT_ID, &MASTER_KEY, b"fallback passphrase", 123)?;

        assert!(store.contains_project(PROJECT_ID)?);
        let loaded = store.load_master_key(PROJECT_ID, b"fallback passphrase")?;
        assert_eq!(&*loaded, &MASTER_KEY);

        let envelope =
            std::fs::read_to_string(directory.path().join(format!("{PROJECT_ID}.toml")))?;
        assert!(!envelope.contains("fallback passphrase"));
        assert!(!envelope.contains(&encode_key(&MASTER_KEY)));
        assert!(envelope.contains("algorithm = \"argon2id\""));
        assert!(envelope.contains("m_cost = 32768"));
        Ok(())
    }

    #[test]
    fn passphrase_fallback_rejects_wrong_passphrase() -> Result<(), PlatformError> {
        let directory = tempfile::tempdir()?;
        let store = PassphraseFallbackMasterKeyStore::new(directory.path());

        store.store_master_key(PROJECT_ID, &MASTER_KEY, b"fallback passphrase", 123)?;
        let result = store.load_master_key(PROJECT_ID, b"wrong passphrase");

        assert!(matches!(result, Err(PlatformError::InvalidPassphrase)));
        Ok(())
    }

    #[test]
    fn passphrase_fallback_rejects_tampered_kdf_params() -> Result<(), PlatformError> {
        let cases = [
            ("m_cost", "m_cost = 32768", "m_cost = 1048576"),
            ("t_cost", "t_cost = 2", "t_cost = 100"),
            ("p_cost", "p_cost = 4", "p_cost = 128"),
            ("output_len", "output_len = 32", "output_len = 64"),
            ("salt", "salt = ", "salt = \"AA\""),
            ("wrapped_master_key", "wrapped_master_key = ", "wrapped_master_key = \"AA\""),
        ];

        for (case, from, to) in cases {
            let directory = tempfile::tempdir()?;
            let store = PassphraseFallbackMasterKeyStore::new(directory.path());

            store.store_master_key(PROJECT_ID, &MASTER_KEY, b"fallback passphrase", 123)?;
            let envelope_path = directory.path().join(format!("{PROJECT_ID}.toml"));
            let envelope = std::fs::read_to_string(&envelope_path)?;
            let tampered = if from.ends_with("= ") {
                replace_toml_assignment(&envelope, from, to)
            } else {
                envelope.replace(from, to)
            };
            assert_ne!(tampered, envelope, "case {case} did not tamper the envelope");
            std::fs::write(&envelope_path, tampered)?;

            let result = store.load_master_key(PROJECT_ID, b"fallback passphrase");

            assert!(
                matches!(result, Err(PlatformError::InvalidPassphraseFallback)),
                "case {case} should reject before derivation/decrypt"
            );
        }
        Ok(())
    }

    fn replace_toml_assignment(text: &str, prefix: &str, replacement: &str) -> String {
        text.lines()
            .map(|line| if line.starts_with(prefix) { replacement } else { line })
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn passphrase_fallback_delete_is_idempotent() -> Result<(), PlatformError> {
        let directory = tempfile::tempdir()?;
        let store = PassphraseFallbackMasterKeyStore::new(directory.path());

        store.store_master_key(PROJECT_ID, &MASTER_KEY, b"fallback passphrase", 123)?;
        store.delete_master_key(PROJECT_ID)?;
        store.delete_master_key(PROJECT_ID)?;

        assert!(!store.contains_project(PROJECT_ID)?);
        assert!(matches!(
            store.load_master_key(PROJECT_ID, b"fallback passphrase"),
            Err(PlatformError::MasterKeyNotFound)
        ));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn passphrase_fallback_uses_user_only_permissions() -> Result<(), PlatformError> {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir()?;
        let store = PassphraseFallbackMasterKeyStore::new(directory.path());

        store.store_master_key(PROJECT_ID, &MASTER_KEY, b"fallback passphrase", 123)?;

        let dir_mode = std::fs::metadata(directory.path())?.permissions().mode() & 0o777;
        let file_mode = std::fs::metadata(directory.path().join(format!("{PROJECT_ID}.toml")))?
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o700);
        assert_eq!(file_mode, 0o600);
        Ok(())
    }
}
