//! Internal AEAD encrypt/decrypt helpers and shared input validation.

use chacha20poly1305::{
    Key, XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};

use crate::error::{CryptoError, CryptoResult};
use crate::{KeyBytes, NonceBytes};

pub fn validate_secret_value(value: &str) -> CryptoResult<()> {
    if value.as_bytes().contains(&0) { Err(CryptoError::InvalidSecretValue) } else { Ok(()) }
}

pub fn aead_encrypt(
    key: &KeyBytes,
    nonce: &NonceBytes,
    plaintext: &[u8],
    aad: &[u8],
) -> CryptoResult<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(&Key::from(*key));
    cipher
        .encrypt(&XNonce::from(*nonce), Payload { msg: plaintext, aad })
        .map_err(|_| CryptoError::EncryptionFailed)
}

pub fn aead_decrypt(
    key: &KeyBytes,
    nonce: &NonceBytes,
    ciphertext: &[u8],
    aad: &[u8],
) -> CryptoResult<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(&Key::from(*key));
    cipher
        .decrypt(&XNonce::from(*nonce), Payload { msg: ciphertext, aad })
        .map_err(|_| CryptoError::DecryptionFailed)
}
