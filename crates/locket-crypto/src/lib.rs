//! Cryptographic primitives for Locket.

use chacha20poly1305::{
    Key, XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, OsRng, Payload, rand_core::RngCore},
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

/// Current deterministic AAD schema version for encrypted secret values.
pub const AAD_SCHEMA_V1: u16 = 1;

/// Current key-wrap schema version.
pub const KEY_WRAP_SCHEMA_V1: u16 = 1;

/// Current HKDF wrap-info schema version.
pub const HKDF_WRAP_INFO_SCHEMA_V1: u16 = 1;

/// Size in bytes of Locket symmetric keys.
pub const KEY_LEN: usize = 32;

/// Size in bytes of `XChaCha20-Poly1305` nonces.
pub const NONCE_LEN: usize = 24;

/// Size in bytes of `Poly1305` authentication tags.
pub const TAG_LEN: usize = 16;

/// Size in bytes of keyed secret fingerprints.
pub const FINGERPRINT_LEN: usize = 32;

const AAD_V1_PREFIX: &[u8] = b"locket-aad-v1";
const KEY_WRAP_V1_PREFIX: &[u8] = b"locket-key-wrap-v1";
const HKDF_WRAP_INFO_V1_PREFIX: &[u8] = b"locket-wrap-v1";
const SECRET_DEK_PURPOSE: &str = "secret-dek";

/// Fixed-size symmetric key bytes.
pub type KeyBytes = [u8; KEY_LEN];

/// Fixed-size `XChaCha20-Poly1305` nonce bytes.
pub type NonceBytes = [u8; NONCE_LEN];

/// Fixed-size keyed fingerprint bytes.
pub type FingerprintBytes = [u8; FINGERPRINT_LEN];

/// Result type used by this crate.
pub type CryptoResult<T> = Result<T, CryptoError>;

/// Error returned by Locket crypto helpers.
#[derive(Debug, Clone, Copy, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum CryptoError {
    /// A canonical field name is too large for the v1 encoding.
    #[error("canonical field name is too long")]
    FieldNameTooLong,
    /// A canonical field value is too large for the v1 encoding.
    #[error("canonical field value is too long")]
    FieldValueTooLong,
    /// Secret values must be UTF-8 and must not contain NUL bytes.
    #[error("invalid secret value")]
    InvalidSecretValue,
    /// The operating system random number generator failed.
    #[error("random generation failed")]
    RandomFailed,
    /// HKDF expansion failed.
    #[error("key derivation failed")]
    KeyDerivationFailed,
    /// Encryption failed.
    #[error("encryption failed")]
    EncryptionFailed,
    /// Decryption failed.
    #[error("decryption failed")]
    DecryptionFailed,
    /// A wrapped DEK did not use the canonical embedded nonce layout.
    #[error("invalid wrapped key layout")]
    InvalidWrappedKey,
}

/// Persisted key purpose strings from the `keys.purpose` column.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub enum KeyPurpose {
    /// Project metadata key.
    ProjectMetadata,
    /// Project audit key, serialized as `project-audit`.
    Audit,
    /// Profile secret key.
    ProfileSecret,
    /// Profile fingerprint key.
    ProfileFingerprint,
}

impl KeyPurpose {
    /// Returns the canonical persisted purpose string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProjectMetadata => "project-metadata",
            Self::Audit => "project-audit",
            Self::ProfileSecret => "profile-secret",
            Self::ProfileFingerprint => "profile-fingerprint",
        }
    }
}

/// Purpose strings accepted by `key_wrap_aad_v1`.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub enum KeyWrapPurpose {
    /// Project metadata key.
    ProjectMetadata,
    /// Project audit key.
    Audit,
    /// Profile secret key.
    ProfileSecret,
    /// Profile fingerprint key.
    ProfileFingerprint,
    /// Per-version secret DEK.
    SecretDek,
}

impl KeyWrapPurpose {
    /// Returns the canonical key-wrap purpose string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProjectMetadata => KeyPurpose::ProjectMetadata.as_str(),
            Self::Audit => KeyPurpose::Audit.as_str(),
            Self::ProfileSecret => KeyPurpose::ProfileSecret.as_str(),
            Self::ProfileFingerprint => KeyPurpose::ProfileFingerprint.as_str(),
            Self::SecretDek => SECRET_DEK_PURPOSE,
        }
    }
}

impl From<KeyPurpose> for KeyWrapPurpose {
    fn from(value: KeyPurpose) -> Self {
        match value {
            KeyPurpose::ProjectMetadata => Self::ProjectMetadata,
            KeyPurpose::Audit => Self::Audit,
            KeyPurpose::ProfileSecret => Self::ProfileSecret,
            KeyPurpose::ProfileFingerprint => Self::ProfileFingerprint,
        }
    }
}

/// Metadata used to derive canonical AAD for a secret blob.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct SecretBlobAad<'a> {
    project_id: &'a str,
    profile_id: &'a str,
    secret_id: &'a str,
    secret_name: &'a str,
    version: u32,
}

impl<'a> SecretBlobAad<'a> {
    /// Creates secret blob AAD metadata.
    #[must_use]
    pub const fn new(
        project_id: &'a str,
        profile_id: &'a str,
        secret_id: &'a str,
        secret_name: &'a str,
        version: u32,
    ) -> Self {
        Self { project_id, profile_id, secret_id, secret_name, version }
    }
}

/// Metadata used to derive canonical AAD for a key wrap.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct KeyWrapAad<'a> {
    project_id: &'a str,
    key_id: &'a str,
    profile_id: Option<&'a str>,
    version: u32,
    purpose: KeyWrapPurpose,
}

impl<'a> KeyWrapAad<'a> {
    /// Creates key-wrap AAD metadata.
    ///
    /// Use `None` for `profile_id` when wrapping project-scoped keys.
    #[must_use]
    pub const fn new(
        project_id: &'a str,
        key_id: &'a str,
        profile_id: Option<&'a str>,
        version: u32,
        purpose: KeyWrapPurpose,
    ) -> Self {
        Self { project_id, key_id, profile_id, version, purpose }
    }
}

/// Metadata used to construct HKDF wrap info.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct HkdfWrapInfo<'a> {
    project_id: &'a str,
    profile_id: Option<&'a str>,
    purpose: KeyPurpose,
}

impl<'a> HkdfWrapInfo<'a> {
    /// Creates HKDF wrap-info metadata.
    ///
    /// Use `None` for `profile_id` when deriving project-scoped wrapping keys.
    #[must_use]
    pub const fn new(
        project_id: &'a str,
        profile_id: Option<&'a str>,
        purpose: KeyPurpose,
    ) -> Self {
        Self { project_id, profile_id, purpose }
    }
}

/// Encrypted secret value material for a `SecretBlob` row.
#[derive(Clone, Eq, PartialEq)]
pub struct EncryptedSecretValue {
    /// Wrapped DEK bytes in `wrap_nonce || wrap_ciphertext` layout.
    pub encrypted_dek: Vec<u8>,
    /// Secret value ciphertext encrypted with the per-version DEK.
    pub ciphertext: Vec<u8>,
    /// Nonce used only for secret value encryption.
    pub value_nonce: NonceBytes,
    /// AAD schema version used to derive the value AAD.
    pub aad_schema_version: u16,
}

/// Encrypted stored key material for a `keys` row.
#[derive(Clone, Eq, PartialEq)]
pub struct WrappedKeyMaterial {
    /// Wrapped key ciphertext without the nonce.
    pub ciphertext: Vec<u8>,
    /// Nonce used for key-wrap encryption.
    pub nonce: NonceBytes,
}

/// Appends a little-endian `u16` to an output buffer.
pub fn append_u16_le(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_le_bytes());
}

/// Appends a little-endian `u32` to an output buffer.
pub fn append_u32_le(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_le_bytes());
}

/// Appends a canonical v1 UTF-8 field to an output buffer.
///
/// # Errors
///
/// Returns [`CryptoError::FieldNameTooLong`] or [`CryptoError::FieldValueTooLong`]
/// if either component cannot be represented by the v1 length prefixes.
pub fn append_canonical_field(output: &mut Vec<u8>, name: &str, value: &str) -> CryptoResult<()> {
    let name_len = u16::try_from(name.len()).map_err(|_| CryptoError::FieldNameTooLong)?;
    let value_len = u32::try_from(value.len()).map_err(|_| CryptoError::FieldValueTooLong)?;

    append_u16_le(output, name_len);
    output.extend_from_slice(name.as_bytes());
    append_u32_le(output, value_len);
    output.extend_from_slice(value.as_bytes());
    Ok(())
}

/// Returns the canonical v1 UTF-8 field encoding.
///
/// # Errors
///
/// Returns [`CryptoError::FieldNameTooLong`] or [`CryptoError::FieldValueTooLong`]
/// if either component cannot be represented by the v1 length prefixes.
pub fn canonical_field(name: &str, value: &str) -> CryptoResult<Vec<u8>> {
    let mut output = Vec::new();
    append_canonical_field(&mut output, name, value)?;
    Ok(output)
}

/// Constructs canonical secret blob AAD v1.
///
/// # Errors
///
/// Returns an error if any field cannot be represented by the canonical v1
/// length prefixes.
pub fn secret_blob_aad_v1(metadata: &SecretBlobAad<'_>) -> CryptoResult<Vec<u8>> {
    let mut aad = Vec::new();
    aad.extend_from_slice(AAD_V1_PREFIX);
    append_u16_le(&mut aad, AAD_SCHEMA_V1);
    append_canonical_field(&mut aad, "project_id", metadata.project_id)?;
    append_canonical_field(&mut aad, "profile_id", metadata.profile_id)?;
    append_canonical_field(&mut aad, "secret_id", metadata.secret_id)?;
    append_canonical_field(&mut aad, "secret_name", metadata.secret_name)?;
    append_u32_le(&mut aad, metadata.version);
    Ok(aad)
}

/// Constructs canonical key-wrap AAD v1.
///
/// # Errors
///
/// Returns an error if any field cannot be represented by the canonical v1
/// length prefixes.
pub fn key_wrap_aad_v1(metadata: &KeyWrapAad<'_>) -> CryptoResult<Vec<u8>> {
    let mut aad = Vec::new();
    aad.extend_from_slice(KEY_WRAP_V1_PREFIX);
    append_canonical_field(&mut aad, "project_id", metadata.project_id)?;
    append_canonical_field(&mut aad, "key_id", metadata.key_id)?;
    append_canonical_field(&mut aad, "profile_id", metadata.profile_id.unwrap_or(""))?;
    append_u32_le(&mut aad, metadata.version);
    append_canonical_field(&mut aad, "purpose", metadata.purpose.as_str())?;
    append_u16_le(&mut aad, KEY_WRAP_SCHEMA_V1);
    Ok(aad)
}

/// Constructs canonical HKDF wrap info v1.
///
/// # Errors
///
/// Returns an error if any field cannot be represented by the canonical v1
/// length prefixes.
pub fn hkdf_wrap_info_v1(metadata: &HkdfWrapInfo<'_>) -> CryptoResult<Vec<u8>> {
    let mut info = Vec::new();
    info.extend_from_slice(HKDF_WRAP_INFO_V1_PREFIX);
    append_u16_le(&mut info, HKDF_WRAP_INFO_SCHEMA_V1);
    append_canonical_field(&mut info, "project_id", metadata.project_id)?;
    append_canonical_field(&mut info, "profile_id", metadata.profile_id.unwrap_or(""))?;
    append_canonical_field(&mut info, "purpose", metadata.purpose.as_str())?;
    Ok(info)
}

/// Derives a 32-byte wrapping key from a master key and canonical HKDF wrap info.
///
/// # Errors
///
/// Returns an error if wrap-info construction or HKDF expansion fails.
pub fn derive_wrapping_key_v1(
    master_key: &KeyBytes,
    metadata: &HkdfWrapInfo<'_>,
) -> CryptoResult<Zeroizing<KeyBytes>> {
    let info = hkdf_wrap_info_v1(metadata)?;
    let hkdf = Hkdf::<Sha256>::new(None, master_key);
    let mut key = Zeroizing::new([0_u8; KEY_LEN]);
    hkdf.expand(&info, &mut *key).map_err(|_| CryptoError::KeyDerivationFailed)?;
    Ok(key)
}

/// Generates a random 32-byte symmetric key.
///
/// # Errors
///
/// Returns [`CryptoError::RandomFailed`] when operating-system randomness is
/// unavailable.
pub fn generate_key() -> CryptoResult<Zeroizing<KeyBytes>> {
    Ok(Zeroizing::new(random_bytes::<KEY_LEN>()?))
}

/// Wraps stored project/profile key material using separate nonce storage.
///
/// # Errors
///
/// Returns an error if random generation or encryption fails.
pub fn wrap_key_material_v1(
    wrapping_key: &KeyBytes,
    key_material: &KeyBytes,
    aad: &[u8],
) -> CryptoResult<WrappedKeyMaterial> {
    let nonce = random_bytes::<NONCE_LEN>()?;
    let ciphertext = aead_encrypt(wrapping_key, &nonce, key_material, aad)?;
    Ok(WrappedKeyMaterial { ciphertext, nonce })
}

/// Unwraps stored project/profile key material using separate nonce storage.
///
/// # Errors
///
/// Returns an error if authentication fails or plaintext length is invalid.
pub fn unwrap_key_material_v1(
    wrapping_key: &KeyBytes,
    wrapped: &WrappedKeyMaterial,
    aad: &[u8],
) -> CryptoResult<Zeroizing<KeyBytes>> {
    let plaintext =
        Zeroizing::new(aead_decrypt(wrapping_key, &wrapped.nonce, &wrapped.ciphertext, aad)?);
    if plaintext.len() != KEY_LEN {
        return Err(CryptoError::InvalidWrappedKey);
    }

    let mut key = Zeroizing::new([0_u8; KEY_LEN]);
    key.copy_from_slice(&plaintext);
    Ok(key)
}

/// Computes a profile-scoped keyed fingerprint for known-value scan matching.
///
/// # Errors
///
/// Returns an error if `value` is not valid secret value text.
pub fn secret_fingerprint_v1(
    profile_fingerprint_key: &KeyBytes,
    value: &str,
) -> CryptoResult<FingerprintBytes> {
    validate_secret_value(value)?;
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(profile_fingerprint_key)
        .map_err(|_| CryptoError::KeyDerivationFailed)?;
    mac.update(b"locket-secret-fingerprint-v1");
    mac.update(value.as_bytes());
    Ok(mac.finalize().into_bytes().into())
}

/// Encrypts a UTF-8 secret value and wraps its generated DEK.
///
/// The returned `encrypted_dek` embeds its own wrap nonce. The returned
/// `value_nonce` is used only for the value ciphertext.
///
/// # Errors
///
/// Returns an error if the value contains a NUL byte, random generation fails,
/// or encryption fails.
pub fn encrypt_secret_value_v1(
    profile_secret_key: &KeyBytes,
    value: &str,
    value_aad: &[u8],
    dek_wrap_aad: &[u8],
) -> CryptoResult<EncryptedSecretValue> {
    validate_secret_value(value)?;

    let dek = Zeroizing::new(random_bytes::<KEY_LEN>()?);
    let value_nonce = random_bytes::<NONCE_LEN>()?;
    let ciphertext = aead_encrypt(&dek, &value_nonce, value.as_bytes(), value_aad)?;
    let encrypted_dek = wrap_dek_v1(profile_secret_key, &dek, dek_wrap_aad)?;

    Ok(EncryptedSecretValue {
        encrypted_dek,
        ciphertext,
        value_nonce,
        aad_schema_version: AAD_SCHEMA_V1,
    })
}

/// Decrypts a secret value after unwrapping its embedded DEK.
///
/// # Errors
///
/// Returns an error if the wrapped DEK layout is invalid, authentication fails,
/// or decrypted bytes are not a valid secret value.
pub fn decrypt_secret_value_v1(
    profile_secret_key: &KeyBytes,
    encrypted: &EncryptedSecretValue,
    value_aad: &[u8],
    dek_wrap_aad: &[u8],
) -> CryptoResult<Zeroizing<String>> {
    let dek = unwrap_dek_v1(profile_secret_key, &encrypted.encrypted_dek, dek_wrap_aad)?;
    let mut plaintext = Zeroizing::new(aead_decrypt(
        &dek,
        &encrypted.value_nonce,
        &encrypted.ciphertext,
        value_aad,
    )?);

    let value = match String::from_utf8(std::mem::take(&mut *plaintext)) {
        Ok(value) => value,
        Err(error) => {
            let mut bytes = Zeroizing::new(error.into_bytes());
            bytes.zeroize();
            return Err(CryptoError::DecryptionFailed);
        }
    };

    validate_secret_value(&value)?;
    Ok(Zeroizing::new(value))
}

/// Wraps a 32-byte DEK using key-wrap v1 embedded nonce layout.
///
/// The returned bytes are `wrap_nonce || wrap_ciphertext`.
///
/// # Errors
///
/// Returns an error if random generation or encryption fails.
pub fn wrap_dek_v1(wrapping_key: &KeyBytes, dek: &KeyBytes, aad: &[u8]) -> CryptoResult<Vec<u8>> {
    let wrap_nonce = random_bytes::<NONCE_LEN>()?;
    let wrap_ciphertext = aead_encrypt(wrapping_key, &wrap_nonce, dek, aad)?;

    let mut wrapped = Vec::with_capacity(NONCE_LEN + wrap_ciphertext.len());
    wrapped.extend_from_slice(&wrap_nonce);
    wrapped.extend_from_slice(&wrap_ciphertext);
    Ok(wrapped)
}

/// Unwraps a 32-byte DEK using key-wrap v1 embedded nonce layout.
///
/// # Errors
///
/// Returns an error if the embedded layout is invalid or authentication fails.
pub fn unwrap_dek_v1(
    wrapping_key: &KeyBytes,
    encrypted_dek: &[u8],
    aad: &[u8],
) -> CryptoResult<Zeroizing<KeyBytes>> {
    let expected_len = NONCE_LEN + KEY_LEN + TAG_LEN;
    if encrypted_dek.len() != expected_len {
        return Err(CryptoError::InvalidWrappedKey);
    }

    let (wrap_nonce, wrap_ciphertext) = encrypted_dek.split_at(NONCE_LEN);
    let wrap_nonce: &NonceBytes =
        wrap_nonce.try_into().map_err(|_| CryptoError::InvalidWrappedKey)?;
    let plaintext = Zeroizing::new(aead_decrypt(wrapping_key, wrap_nonce, wrap_ciphertext, aad)?);
    if plaintext.len() != KEY_LEN {
        return Err(CryptoError::InvalidWrappedKey);
    }

    let mut dek = Zeroizing::new([0_u8; KEY_LEN]);
    dek.copy_from_slice(&plaintext);
    Ok(dek)
}

fn validate_secret_value(value: &str) -> CryptoResult<()> {
    if value.as_bytes().contains(&0) { Err(CryptoError::InvalidSecretValue) } else { Ok(()) }
}

fn random_bytes<const N: usize>() -> CryptoResult<[u8; N]> {
    let mut bytes = [0_u8; N];
    OsRng.try_fill_bytes(&mut bytes).map_err(|_| CryptoError::RandomFailed)?;
    Ok(bytes)
}

fn aead_encrypt(
    key: &KeyBytes,
    nonce: &NonceBytes,
    plaintext: &[u8],
    aad: &[u8],
) -> CryptoResult<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .encrypt(XNonce::from_slice(nonce), Payload { msg: plaintext, aad })
        .map_err(|_| CryptoError::EncryptionFailed)
}

fn aead_decrypt(
    key: &KeyBytes,
    nonce: &NonceBytes,
    ciphertext: &[u8],
    aad: &[u8],
) -> CryptoResult<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(XNonce::from_slice(nonce), Payload { msg: ciphertext, aad })
        .map_err(|_| CryptoError::DecryptionFailed)
}

#[cfg(test)]
mod tests {
    use super::{
        AAD_SCHEMA_V1, CryptoError, HkdfWrapInfo, KEY_LEN, KEY_WRAP_SCHEMA_V1, KeyPurpose,
        KeyWrapAad, KeyWrapPurpose, NONCE_LEN, SecretBlobAad, TAG_LEN, decrypt_secret_value_v1,
        derive_wrapping_key_v1, key_wrap_aad_v1, secret_blob_aad_v1, secret_fingerprint_v1,
        unwrap_dek_v1, unwrap_key_material_v1, wrap_dek_v1, wrap_key_material_v1,
    };

    const PROFILE_SECRET_KEY: [u8; KEY_LEN] = [7; KEY_LEN];
    const MASTER_KEY: [u8; KEY_LEN] = [11; KEY_LEN];

    #[test]
    fn secret_blob_aad_bytes_are_stable() -> Result<(), CryptoError> {
        let metadata =
            SecretBlobAad::new("lk_proj_123", "lk_prof_dev", "lk_sec_db", "DATABASE_URL", 7);

        let aad = secret_blob_aad_v1(&metadata)?;
        let expected = [
            b"locket-aad-v1".as_slice(),
            &AAD_SCHEMA_V1.to_le_bytes(),
            &[10, 0],
            b"project_id",
            &[11, 0, 0, 0],
            b"lk_proj_123",
            &[10, 0],
            b"profile_id",
            &[11, 0, 0, 0],
            b"lk_prof_dev",
            &[9, 0],
            b"secret_id",
            &[9, 0, 0, 0],
            b"lk_sec_db",
            &[11, 0],
            b"secret_name",
            &[12, 0, 0, 0],
            b"DATABASE_URL",
            &[7, 0, 0, 0],
        ]
        .concat();

        assert_eq!(aad, expected);
        Ok(())
    }

    #[test]
    fn key_wrap_aad_bytes_are_stable() -> Result<(), CryptoError> {
        let metadata = KeyWrapAad::new(
            "lk_proj_123",
            "lk_sec_db",
            Some("lk_prof_dev"),
            7,
            KeyWrapPurpose::SecretDek,
        );

        let aad = key_wrap_aad_v1(&metadata)?;
        let expected = [
            b"locket-key-wrap-v1".as_slice(),
            &[10, 0],
            b"project_id",
            &[11, 0, 0, 0],
            b"lk_proj_123",
            &[6, 0],
            b"key_id",
            &[9, 0, 0, 0],
            b"lk_sec_db",
            &[10, 0],
            b"profile_id",
            &[11, 0, 0, 0],
            b"lk_prof_dev",
            &[7, 0, 0, 0],
            &[7, 0],
            b"purpose",
            &[10, 0, 0, 0],
            b"secret-dek",
            &KEY_WRAP_SCHEMA_V1.to_le_bytes(),
        ]
        .concat();

        assert_eq!(aad, expected);
        Ok(())
    }

    #[test]
    fn secret_value_uses_separate_value_and_wrap_nonces() -> Result<(), CryptoError> {
        let value_aad = secret_blob_aad_v1(&SecretBlobAad::new(
            "lk_proj_123",
            "lk_prof_dev",
            "lk_sec_db",
            "DATABASE_URL",
            1,
        ))?;
        let wrap_aad = key_wrap_aad_v1(&KeyWrapAad::new(
            "lk_proj_123",
            "lk_sec_db",
            Some("lk_prof_dev"),
            1,
            KeyWrapPurpose::SecretDek,
        ))?;

        let encrypted = super::encrypt_secret_value_v1(
            &PROFILE_SECRET_KEY,
            "postgres://localhost/app",
            &value_aad,
            &wrap_aad,
        )?;

        assert_eq!(encrypted.value_nonce.len(), NONCE_LEN);
        assert_eq!(encrypted.encrypted_dek.len(), NONCE_LEN + KEY_LEN + TAG_LEN);
        assert_ne!(&encrypted.encrypted_dek[..NONCE_LEN], encrypted.value_nonce.as_slice());
        assert_eq!(encrypted.aad_schema_version, AAD_SCHEMA_V1);
        Ok(())
    }

    #[test]
    fn changed_aad_fails_secret_decryption() -> Result<(), CryptoError> {
        let value_aad = secret_blob_aad_v1(&SecretBlobAad::new(
            "lk_proj_123",
            "lk_prof_dev",
            "lk_sec_db",
            "DATABASE_URL",
            1,
        ))?;
        let changed_value_aad = secret_blob_aad_v1(&SecretBlobAad::new(
            "lk_proj_123",
            "lk_prof_prod",
            "lk_sec_db",
            "DATABASE_URL",
            1,
        ))?;
        let wrap_aad = key_wrap_aad_v1(&KeyWrapAad::new(
            "lk_proj_123",
            "lk_sec_db",
            Some("lk_prof_dev"),
            1,
            KeyWrapPurpose::SecretDek,
        ))?;

        let encrypted = super::encrypt_secret_value_v1(
            &PROFILE_SECRET_KEY,
            "secret-value",
            &value_aad,
            &wrap_aad,
        )?;
        let result =
            decrypt_secret_value_v1(&PROFILE_SECRET_KEY, &encrypted, &changed_value_aad, &wrap_aad);

        assert!(matches!(result, Err(CryptoError::DecryptionFailed)));
        Ok(())
    }

    #[test]
    fn wrap_and_unwrap_dek_round_trip() -> Result<(), CryptoError> {
        let dek = [19; KEY_LEN];
        let aad = key_wrap_aad_v1(&KeyWrapAad::new(
            "lk_proj_123",
            "lk_sec_db",
            Some("lk_prof_dev"),
            3,
            KeyWrapPurpose::SecretDek,
        ))?;

        let wrapped = wrap_dek_v1(&PROFILE_SECRET_KEY, &dek, &aad)?;
        let unwrapped = unwrap_dek_v1(&PROFILE_SECRET_KEY, &wrapped, &aad)?;

        assert_eq!(&*unwrapped, &dek);
        Ok(())
    }

    #[test]
    fn hkdf_wrap_info_uses_canonical_purpose_strings() -> Result<(), CryptoError> {
        let project_key = derive_wrapping_key_v1(
            &MASTER_KEY,
            &HkdfWrapInfo::new("lk_proj_123", None, KeyPurpose::Audit),
        )?;
        let profile_key = derive_wrapping_key_v1(
            &MASTER_KEY,
            &HkdfWrapInfo::new("lk_proj_123", Some("lk_prof_dev"), KeyPurpose::ProfileSecret),
        )?;

        assert_ne!(&*project_key, &*profile_key);
        Ok(())
    }

    #[test]
    fn stored_key_wrap_round_trips_with_separate_nonce() -> Result<(), CryptoError> {
        let key_material = [23; KEY_LEN];
        let aad = key_wrap_aad_v1(&KeyWrapAad::new(
            "lk_proj_123",
            "lk_key_profile",
            Some("lk_prof_dev"),
            0,
            KeyWrapPurpose::ProfileSecret,
        ))?;

        let wrapped = wrap_key_material_v1(&PROFILE_SECRET_KEY, &key_material, &aad)?;
        let unwrapped = unwrap_key_material_v1(&PROFILE_SECRET_KEY, &wrapped, &aad)?;

        assert_eq!(wrapped.nonce.len(), NONCE_LEN);
        assert_eq!(&*unwrapped, &key_material);
        Ok(())
    }

    #[test]
    fn secret_fingerprint_is_keyed_and_stable() -> Result<(), CryptoError> {
        let first = secret_fingerprint_v1(&PROFILE_SECRET_KEY, "secret-value")?;
        let second = secret_fingerprint_v1(&PROFILE_SECRET_KEY, "secret-value")?;
        let other_key = secret_fingerprint_v1(&MASTER_KEY, "secret-value")?;

        assert_eq!(first, second);
        assert_ne!(first, other_key);
        Ok(())
    }
}
