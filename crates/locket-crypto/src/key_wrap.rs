//! Key wrap, unwrap, and HKDF wrapping-key derivation helpers.

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::aad::{HkdfWrapInfo, hkdf_wrap_info_v1};
use crate::aead::{aead_decrypt, aead_encrypt};
use crate::error::{CryptoError, CryptoResult};
use crate::random::random_bytes;
use crate::{KEY_LEN, KeyBytes, NONCE_LEN, NonceBytes, TAG_LEN};

/// Encrypted stored key material for a `keys` row.
#[derive(Clone, Eq, PartialEq)]
pub struct WrappedKeyMaterial {
    /// Wrapped key ciphertext without the nonce.
    pub ciphertext: Vec<u8>,
    /// Nonce used for key-wrap encryption.
    pub nonce: NonceBytes,
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
