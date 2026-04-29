//! Passphrase fallback KDF parameters and Argon2id derivation.

use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::Zeroizing;

use crate::error::{CryptoError, CryptoResult};
use crate::{
    KEY_LEN, KeyBytes, PASSPHRASE_FALLBACK_M_COST, PASSPHRASE_FALLBACK_OUTPUT_LEN,
    PASSPHRASE_FALLBACK_P_COST, PASSPHRASE_FALLBACK_T_COST,
};

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
