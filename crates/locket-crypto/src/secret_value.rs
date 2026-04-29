//! Secret value encryption, decryption, and keyed fingerprinting.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use crate::aad::AAD_SCHEMA_V1;
use crate::aead::{aead_decrypt, aead_encrypt, validate_secret_value};
use crate::error::{CryptoError, CryptoResult};
use crate::key_wrap::{unwrap_dek_v1, wrap_dek_v1};
use crate::random::random_bytes;
use crate::{FingerprintBytes, KEY_LEN, KeyBytes, NONCE_LEN, NonceBytes};

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
