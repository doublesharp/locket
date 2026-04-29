//! Cryptographic primitives for Locket.

// rand 0.9 transitively brings rand_core 0.6 (via chacha20poly1305) and 0.9,
// which triggers this lint. This cannot be fixed without upgrading all crates.
#![allow(clippy::multiple_crate_versions)]

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    Key, XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, OsRng, Payload, rand_core::RngCore},
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::TryRngCore as _;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

mod error;
mod purpose;

pub use error::{CryptoError, CryptoResult};
pub use purpose::{KeyPurpose, KeyWrapPurpose};

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

/// Recovery envelope magic bytes.
pub const RECOVERY_MAGIC: &[u8; 16] = b"LOCKET-RECOVERY\0";

/// Recovery envelope schema version.
pub const RECOVERY_ENVELOPE_SCHEMA_V1: u16 = 1;

/// Argon2id memory cost in KiB for recovery envelopes (m=65536).
pub const RECOVERY_M_COST: u32 = 65_536;

/// Argon2id iteration count for recovery envelopes (t=3).
pub const RECOVERY_T_COST: u32 = 3;

/// Argon2id parallelism for recovery envelopes (p=4).
pub const RECOVERY_P_COST: u32 = 4;

/// Recovery code random byte length (160 bits).
pub const RECOVERY_CODE_BYTES: usize = 20;

/// Recovery code data character count (32 Crockford Base32 chars).
pub const RECOVERY_CODE_DATA_CHARS: usize = 32;

/// Recovery code total character count including checksum (34 chars).
pub const RECOVERY_CODE_TOTAL_CHARS: usize = 34;

/// Salt length in bytes for new recovery envelopes.
pub const RECOVERY_SALT_LEN: usize = 32;

const AAD_V1_PREFIX: &[u8] = b"locket-aad-v1";
const KEY_WRAP_V1_PREFIX: &[u8] = b"locket-key-wrap-v1";
const HKDF_WRAP_INFO_V1_PREFIX: &[u8] = b"locket-wrap-v1";
const PASSPHRASE_FALLBACK_AAD_V1_PREFIX: &[u8] = b"locket-passphrase-fallback-v1";
const RECOVERY_ENTRY_AAD_V1_PREFIX: &[u8] = b"locket-recovery-envelope-v1";
const RECOVERY_ENTRY_HKDF_V1_PREFIX: &[u8] = b"locket-recovery-entry-v1";

/// Argon2id memory cost in KiB for passphrase fallback envelopes.
pub const PASSPHRASE_FALLBACK_M_COST: u32 = 32_768;

/// Argon2id iteration count for passphrase fallback envelopes.
pub const PASSPHRASE_FALLBACK_T_COST: u32 = 2;

/// Argon2id parallelism for passphrase fallback envelopes.
pub const PASSPHRASE_FALLBACK_P_COST: u32 = 4;

/// Argon2id output length for passphrase fallback envelopes.
pub const PASSPHRASE_FALLBACK_OUTPUT_LEN: u32 = 32;

/// Salt length in bytes for new passphrase fallback envelopes.
pub const PASSPHRASE_FALLBACK_SALT_LEN: usize = 32;

/// Fixed-size symmetric key bytes.
pub type KeyBytes = [u8; KEY_LEN];

/// Fixed-size `XChaCha20-Poly1305` nonce bytes.
pub type NonceBytes = [u8; NONCE_LEN];

/// Fixed-size keyed fingerprint bytes.
pub type FingerprintBytes = [u8; FINGERPRINT_LEN];

/// Argon2id parameters for recovery envelope key derivation.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct RecoveryKdfParams {
    /// Memory cost in KiB.
    pub m_cost: u32,
    /// Iteration count.
    pub t_cost: u32,
    /// Parallelism degree.
    pub p_cost: u32,
    /// Output length in bytes.
    pub output_len: u32,
}

impl RecoveryKdfParams {
    /// Returns the v1 default recovery KDF parameters.
    #[must_use]
    pub const fn recovery_v1() -> Self {
        // KEY_LEN is 32, well within u32 range.
        #[allow(clippy::cast_possible_truncation)]
        let output_len = KEY_LEN as u32;
        Self {
            m_cost: RECOVERY_M_COST,
            t_cost: RECOVERY_T_COST,
            p_cost: RECOVERY_P_COST,
            output_len,
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

/// Argon2id parameters for passphrase fallback key derivation.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct PassphraseKdfParams {
    /// Memory cost in KiB.
    pub m_cost: u32,
    /// Iteration count.
    pub t_cost: u32,
    /// Parallelism.
    pub p_cost: u32,
    /// Derived output length in bytes.
    pub output_len: u32,
}

impl PassphraseKdfParams {
    /// Returns the v1 default passphrase fallback KDF parameters.
    #[must_use]
    pub const fn fallback_v1() -> Self {
        Self {
            m_cost: PASSPHRASE_FALLBACK_M_COST,
            t_cost: PASSPHRASE_FALLBACK_T_COST,
            p_cost: PASSPHRASE_FALLBACK_P_COST,
            output_len: PASSPHRASE_FALLBACK_OUTPUT_LEN,
        }
    }
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

/// Constructs canonical AAD for passphrase fallback master-key envelopes.
///
/// # Errors
///
/// Returns an error if either field cannot be represented by the canonical v1
/// length prefixes.
pub fn passphrase_fallback_aad_v1(project_id: &str, kdf_profile_id: &str) -> CryptoResult<Vec<u8>> {
    let mut aad = Vec::new();
    aad.extend_from_slice(PASSPHRASE_FALLBACK_AAD_V1_PREFIX);
    append_u16_le(&mut aad, KEY_WRAP_SCHEMA_V1);
    append_canonical_field(&mut aad, "project_id", project_id)?;
    append_canonical_field(&mut aad, "kdf_profile_id", kdf_profile_id)?;
    Ok(aad)
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

/// Generates a random salt for passphrase fallback KDF profiles.
///
/// # Errors
///
/// Returns [`CryptoError::RandomFailed`] when operating-system randomness is
/// unavailable.
pub fn generate_passphrase_salt() -> CryptoResult<[u8; PASSPHRASE_FALLBACK_SALT_LEN]> {
    random_bytes::<PASSPHRASE_FALLBACK_SALT_LEN>()
}

/// Derives a passphrase fallback wrapping key using Argon2id.
///
/// # Errors
///
/// Returns [`CryptoError::InvalidKdfParameters`] when stored parameters are not
/// valid for v1 fallback, and [`CryptoError::KeyDerivationFailed`] when Argon2id
/// derivation fails.
pub fn derive_passphrase_fallback_key_v1(
    passphrase: &[u8],
    salt: &[u8],
    params: PassphraseKdfParams,
) -> CryptoResult<Zeroizing<KeyBytes>> {
    if passphrase.is_empty()
        || salt.is_empty()
        || params.output_len != PASSPHRASE_FALLBACK_OUTPUT_LEN
    {
        return Err(CryptoError::InvalidKdfParameters);
    }

    let argon_params = Params::new(params.m_cost, params.t_cost, params.p_cost, Some(KEY_LEN))
        .map_err(|_| CryptoError::InvalidKdfParameters)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);
    let mut key = Zeroizing::new([0_u8; KEY_LEN]);
    argon2
        .hash_password_into(passphrase, salt, &mut *key)
        .map_err(|_| CryptoError::KeyDerivationFailed)?;
    Ok(key)
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

/// Crockford Base32 symbol alphabet (32 data symbols).
const CROCKFORD_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Crockford Base32 checksum symbols (37 symbols for mod-37 checksum).
const CROCKFORD_CHECK: &[u8; 37] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ*~$=U";

/// Encodes 20 raw bytes as 32 Crockford Base32 data chars + 2 checksum chars.
///
/// The output is 34 characters: 32 data + 2 checksum, suitable for grouping.
#[must_use]
pub fn recovery_code_encode(bytes: &[u8; RECOVERY_CODE_BYTES]) -> [u8; RECOVERY_CODE_TOTAL_CHARS] {
    let mut out = [0u8; RECOVERY_CODE_TOTAL_CHARS];
    // Encode 160 bits as 32 x 5-bit Crockford Base32 symbols.
    // acc is always < 32, usize cast is safe.
    #[allow(clippy::cast_possible_truncation)]
    for (i, slot) in out[..RECOVERY_CODE_DATA_CHARS].iter_mut().enumerate() {
        let bit_offset = i * 5;
        let byte_idx = bit_offset / 8;
        let bit_shift = bit_offset % 8;
        let bits = if bit_shift <= 3 {
            (bytes[byte_idx] >> (3 - bit_shift)) & 0x1F
        } else {
            let lo = (bytes[byte_idx] << (bit_shift - 3)) & 0x1F;
            let hi = if byte_idx + 1 < RECOVERY_CODE_BYTES {
                bytes[byte_idx + 1] >> (11 - bit_shift)
            } else {
                0
            };
            lo | hi
        };
        *slot = CROCKFORD_ALPHABET[bits as usize];
    }
    // Crockford checksum: treat bytes as a big-endian integer mod 37.
    // For 160-bit values, accumulate mod 37 byte by byte.
    let mut acc: u64 = 0;
    for &b in bytes {
        // acc = (acc * 256 + b) mod 37
        acc = (acc * 256 + u64::from(b)) % 37;
    }
    // The checksum is one symbol for (acc mod 37). We store two checksum chars
    // for forward compatibility: char 33 is the primary checksum, char 34 is 0-padded.
    // acc is always < 37 after mod, usize cast is safe.
    #[allow(clippy::cast_possible_truncation)]
    {
        out[RECOVERY_CODE_DATA_CHARS] = CROCKFORD_CHECK[acc as usize];
    }
    out[RECOVERY_CODE_DATA_CHARS + 1] = CROCKFORD_CHECK[0]; // reserved, always '0'
    out
}

/// Decodes 32 or 34 Crockford Base32 characters back into 20 raw bytes.
///
/// Accepts uppercase and lowercase input. Ignores hyphens (grouping separators).
/// Returns `Err(CryptoError::InvalidSecretValue)` on invalid characters or checksum mismatch.
///
/// # Errors
///
/// Returns [`CryptoError::InvalidSecretValue`] if the input is too short, contains
/// invalid characters, or the checksum does not match.
pub fn recovery_code_decode(input: &str) -> CryptoResult<[u8; RECOVERY_CODE_BYTES]> {
    // Strip grouping separators, normalize to uppercase.
    let chars: Vec<u8> =
        input.bytes().filter(|&b| b != b'-' && b != b' ').map(|b| b.to_ascii_uppercase()).collect();

    if !matches!(chars.len(), RECOVERY_CODE_DATA_CHARS | RECOVERY_CODE_TOTAL_CHARS) {
        return Err(CryptoError::InvalidSecretValue);
    }

    // Decode 32 data characters into 160 bits.
    let mut bits = [0u8; RECOVERY_CODE_DATA_CHARS];
    for (i, &c) in chars[..RECOVERY_CODE_DATA_CHARS].iter().enumerate() {
        let val = crockford_decode_char(c)?;
        bits[i] = val;
    }

    // Pack 32 x 5-bit values into 20 bytes.
    let mut bytes = [0u8; RECOVERY_CODE_BYTES];
    for (i, &val) in bits.iter().enumerate().take(RECOVERY_CODE_DATA_CHARS) {
        let bit_offset = i * 5;
        let byte_idx = bit_offset / 8;
        let bit_shift = bit_offset % 8;
        if bit_shift <= 3 {
            bytes[byte_idx] |= val << (3 - bit_shift);
        } else {
            bytes[byte_idx] |= val >> (bit_shift - 3);
            if byte_idx + 1 < RECOVERY_CODE_BYTES {
                bytes[byte_idx + 1] |= val << (11 - bit_shift);
            }
        }
    }

    // Verify checksum if provided.
    if chars.len() == RECOVERY_CODE_TOTAL_CHARS {
        let expected_check = chars[RECOVERY_CODE_DATA_CHARS];
        let mut acc: u64 = 0;
        for &b in &bytes {
            acc = (acc * 256 + u64::from(b)) % 37;
        }
        // acc is always < 37 after mod, usize cast is safe.
        #[allow(clippy::cast_possible_truncation)]
        let computed_symbol = CROCKFORD_CHECK[acc as usize];
        if expected_check != computed_symbol || chars[RECOVERY_CODE_DATA_CHARS + 1] != b'0' {
            return Err(CryptoError::InvalidSecretValue);
        }
    }

    Ok(bytes)
}

const fn crockford_decode_char(c: u8) -> CryptoResult<u8> {
    match c {
        b'0' | b'O' => Ok(0),
        b'1' | b'I' | b'L' => Ok(1),
        b'2' => Ok(2),
        b'3' => Ok(3),
        b'4' => Ok(4),
        b'5' => Ok(5),
        b'6' => Ok(6),
        b'7' => Ok(7),
        b'8' => Ok(8),
        b'9' => Ok(9),
        b'A' => Ok(10),
        b'B' => Ok(11),
        b'C' => Ok(12),
        b'D' => Ok(13),
        b'E' => Ok(14),
        b'F' => Ok(15),
        b'G' => Ok(16),
        b'H' => Ok(17),
        b'J' => Ok(18),
        b'K' => Ok(19),
        b'M' => Ok(20),
        b'N' => Ok(21),
        b'P' => Ok(22),
        b'Q' => Ok(23),
        b'R' => Ok(24),
        b'S' => Ok(25),
        b'T' => Ok(26),
        b'V' => Ok(27),
        b'W' => Ok(28),
        b'X' => Ok(29),
        b'Y' => Ok(30),
        b'Z' => Ok(31),
        _ => Err(CryptoError::InvalidSecretValue),
    }
}

/// Generates a fresh 20-byte random recovery code.
///
/// # Errors
///
/// Returns `CryptoError::RandomFailed` if the OS RNG fails.
pub fn generate_recovery_code_bytes() -> CryptoResult<[u8; RECOVERY_CODE_BYTES]> {
    let mut bytes = [0u8; RECOVERY_CODE_BYTES];
    rand::rngs::OsRng.try_fill_bytes(&mut bytes).map_err(|_| CryptoError::RandomFailed)?;
    Ok(bytes)
}

/// Generates a fresh random recovery salt.
///
/// # Errors
///
/// Returns `CryptoError::RandomFailed` if the OS RNG fails.
pub fn generate_recovery_salt() -> CryptoResult<[u8; RECOVERY_SALT_LEN]> {
    let mut salt = [0u8; RECOVERY_SALT_LEN];
    rand::rngs::OsRng.try_fill_bytes(&mut salt).map_err(|_| CryptoError::RandomFailed)?;
    Ok(salt)
}

/// Derives the recovery unwrap root key from a raw recovery code and stored KDF params.
///
/// Uses Argon2id with the stored parameters. Returns a zeroizing 32-byte key.
///
/// # Errors
///
/// Returns `CryptoError::InvalidKdfParameters` if params are zero or unsupported,
/// or `CryptoError::KeyDerivationFailed` on Argon2id failure.
pub fn derive_recovery_key_v1(
    recovery_code_bytes: &[u8; RECOVERY_CODE_BYTES],
    salt: &[u8],
    params: RecoveryKdfParams,
) -> CryptoResult<Zeroizing<KeyBytes>> {
    if salt.is_empty() || params.m_cost == 0 || params.t_cost == 0 || params.p_cost == 0 {
        return Err(CryptoError::InvalidKdfParameters);
    }
    let argon_params =
        Params::new(params.m_cost, params.t_cost, params.p_cost, Some(params.output_len as usize))
            .map_err(|_| CryptoError::InvalidKdfParameters)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    argon
        .hash_password_into(recovery_code_bytes, salt, &mut *key)
        .map_err(|_| CryptoError::KeyDerivationFailed)?;
    Ok(key)
}

/// Derives the per-entry HKDF key for a recovery envelope entry.
///
/// `info = b"locket-recovery-entry-v1" || field("entry_kind", entry_kind) || field("entry_id", entry_id) || field("kdf_profile_id", kdf_profile_id)`
///
/// # Errors
///
/// Returns `CryptoError` if field encoding or HKDF expansion fails.
pub fn recovery_entry_key_v1(
    unwrap_root: &KeyBytes,
    entry_kind: &str,
    entry_id: &str,
    kdf_profile_id: &str,
) -> CryptoResult<Zeroizing<KeyBytes>> {
    let mut info = Vec::new();
    info.extend_from_slice(RECOVERY_ENTRY_HKDF_V1_PREFIX);
    append_canonical_field(&mut info, "entry_kind", entry_kind)?;
    append_canonical_field(&mut info, "entry_id", entry_id)?;
    append_canonical_field(&mut info, "kdf_profile_id", kdf_profile_id)?;
    let hkdf = Hkdf::<Sha256>::new(None, unwrap_root);
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    hkdf.expand(&info, &mut *key).map_err(|_| CryptoError::KeyDerivationFailed)?;
    Ok(key)
}

/// Constructs canonical AAD for a recovery envelope entry.
///
/// `aad = b"locket-recovery-envelope-v1" || u16_le(schema_version) || field("kdf_profile_id", kdf_profile_id) || field("entry_kind", entry_kind) || field("entry_id", entry_id)`
///
/// # Errors
///
/// Returns `CryptoError` if any field is too long.
pub fn recovery_entry_aad_v1(
    kdf_profile_id: &str,
    entry_kind: &str,
    entry_id: &str,
) -> CryptoResult<Vec<u8>> {
    let mut aad = Vec::new();
    aad.extend_from_slice(RECOVERY_ENTRY_AAD_V1_PREFIX);
    append_u16_le(&mut aad, RECOVERY_ENVELOPE_SCHEMA_V1);
    append_canonical_field(&mut aad, "kdf_profile_id", kdf_profile_id)?;
    append_canonical_field(&mut aad, "entry_kind", entry_kind)?;
    append_canonical_field(&mut aad, "entry_id", entry_id)?;
    Ok(aad)
}

/// Encrypts a recovery envelope entry payload using the v1 per-entry key schedule.
///
/// # Errors
///
/// Returns an error if key derivation, nonce generation, or encryption fails.
pub fn seal_recovery_entry_v1(
    unwrap_root: &KeyBytes,
    kdf_profile_id: &str,
    entry_kind: &str,
    entry_id: &str,
    plaintext: &[u8],
) -> CryptoResult<(NonceBytes, Vec<u8>)> {
    let entry_key = recovery_entry_key_v1(unwrap_root, entry_kind, entry_id, kdf_profile_id)?;
    let aad = recovery_entry_aad_v1(kdf_profile_id, entry_kind, entry_id)?;
    let nonce = random_bytes::<NONCE_LEN>()?;
    let ciphertext = aead_encrypt(&entry_key, &nonce, plaintext, &aad)?;
    Ok((nonce, ciphertext))
}

/// Decrypts a recovery envelope entry payload using the v1 per-entry key schedule.
///
/// # Errors
///
/// Returns an error if key derivation fails or ciphertext authentication fails.
pub fn open_recovery_entry_v1(
    unwrap_root: &KeyBytes,
    kdf_profile_id: &str,
    entry_kind: &str,
    entry_id: &str,
    nonce: &NonceBytes,
    ciphertext: &[u8],
) -> CryptoResult<Vec<u8>> {
    let entry_key = recovery_entry_key_v1(unwrap_root, entry_kind, entry_id, kdf_profile_id)?;
    let aad = recovery_entry_aad_v1(kdf_profile_id, entry_kind, entry_id)?;
    aead_decrypt(&entry_key, nonce, ciphertext, &aad)
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
#[path = "tests.rs"]
mod tests;
