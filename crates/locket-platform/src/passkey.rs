//! Platform passkey/`WebAuthn` registration and PRF evaluation traits.
//!
//! Locket only stores public passkey metadata. The platform registrar
//! abstracts over the OS authenticator (Touch ID / Windows Hello / FIDO2) and
//! returns just the public credential bytes plus capability hints.

use std::sync::Mutex;

use data_encoding::BASE64URL_NOPAD;
use hmac::{Hmac, Mac};
use keyring::Entry;
use locket_crypto::{KEY_LEN, generate_key, random_bytes};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::PlatformError;

const PASSKEY_KEYRING_SERVICE: &str = "dev.0xdoublesharp.locket.passkey";
const PASSKEY_ACCOUNT_PREFIX: &str = "prf:";
const PASSKEY_TRANSPORT_INTERNAL: &str = "internal";
const PASSKEY_TRANSPORT_KEYRING: &str = "platform-keyring";
const PASSKEY_PUBLIC_KEY_DOMAIN: &[u8] = b"locket-platform-passkey-public-v1";
const PASSKEY_PRF_DOMAIN: &[u8] = b"locket-platform-passkey-prf-v1";

type HmacSha256 = Hmac<Sha256>;

/// Result of a successful platform-authenticator registration.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PasskeyRegistration {
    /// Public `WebAuthn` credential id bytes. Never private key material.
    pub credential_id: Vec<u8>,
    /// Public key bytes for the credential. Never private key material.
    pub public_key: Vec<u8>,
    /// Transport hints reported by the platform/authenticator.
    pub transports: Vec<String>,
    /// Whether the authenticator supports the `WebAuthn` PRF/hmac-secret extension.
    pub prf_capable: bool,
    /// Whether the authenticator reports backup eligibility, when known.
    pub backup_eligible: Option<bool>,
    /// Whether the authenticator reports a current backup state, when known.
    pub backup_state: Option<bool>,
}

/// Interface for registering and using platform passkeys.
///
/// Implementations must never expose passkey/biometric private key material
/// and must surface platform errors as [`PlatformError`] so the CLI can map
/// them to a generic "passkey auth failed" outcome without leaking detail.
pub trait PlatformPasskeyRegistrar {
    /// Performs a platform-authenticator registration ceremony.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::PasskeyUnsupported`] when the current build or
    /// platform has no platform-authenticator integration, and
    /// [`PlatformError::PasskeyAuthFailed`] or
    /// [`PlatformError::PasskeyRegistrationFailed`] when the platform rejects
    /// or cannot complete the ceremony.
    fn register_passkey(
        &self,
        label: &str,
        relying_party_id: &str,
    ) -> Result<PasskeyRegistration, PlatformError>;

    /// Evaluates the `WebAuthn` PRF/hmac-secret extension for `credential_id`.
    ///
    /// The 32-byte PRF output is sensitive symmetric key material and must be
    /// zeroized on drop by the caller's wrapper. Implementations should not
    /// retain a copy.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::PasskeyUnsupported`] when the build or
    /// platform has no platform-authenticator integration,
    /// [`PlatformError::PasskeyNotFound`] when the credential is unknown to
    /// the platform, and [`PlatformError::PasskeyAuthFailed`] for any other
    /// platform-level failure.
    fn evaluate_prf(
        &self,
        credential_id: &[u8],
        salt: &[u8],
    ) -> Result<Zeroizing<[u8; 32]>, PlatformError>;
}

/// Default registrar for builds where platform passkey APIs are not yet wired.
#[derive(Debug, Clone, Copy, Default)]
pub struct UnavailablePlatformPasskeyRegistrar;

impl PlatformPasskeyRegistrar for UnavailablePlatformPasskeyRegistrar {
    fn register_passkey(
        &self,
        _label: &str,
        _relying_party_id: &str,
    ) -> Result<PasskeyRegistration, PlatformError> {
        Err(PlatformError::PasskeyUnsupported)
    }

    fn evaluate_prf(
        &self,
        _credential_id: &[u8],
        _salt: &[u8],
    ) -> Result<Zeroizing<[u8; 32]>, PlatformError> {
        Err(PlatformError::PasskeyUnsupported)
    }
}

/// OS secure-storage backed passkey registrar.
///
/// This backend is intentionally local: the CLI requires fresh local user
/// verification before registration/removal, then this registrar stores a
/// per-credential PRF seed in the platform credential store (`Keychain` on
/// macOS, Credential Manager on Windows, Secret Service/keyring on Linux).
/// It returns only public metadata and derives PRF output from the stored
/// seed plus the caller-provided salt.
#[derive(Debug, Clone, Copy, Default)]
pub struct KeyringPlatformPasskeyRegistrar;

impl PlatformPasskeyRegistrar for KeyringPlatformPasskeyRegistrar {
    fn register_passkey(
        &self,
        _label: &str,
        _relying_party_id: &str,
    ) -> Result<PasskeyRegistration, PlatformError> {
        let credential_id = random_bytes::<32>()?.to_vec();
        let secret = generate_key()?;
        passkey_entry(&credential_id)?
            .set_password(&encode_passkey_secret(&secret))
            .map_err(|_| PlatformError::PasskeyRegistrationFailed)?;
        Ok(PasskeyRegistration {
            credential_id,
            public_key: public_metadata_key(&secret),
            transports: vec![
                PASSKEY_TRANSPORT_INTERNAL.to_owned(),
                PASSKEY_TRANSPORT_KEYRING.to_owned(),
                platform_transport_label().to_owned(),
            ],
            prf_capable: true,
            backup_eligible: None,
            backup_state: None,
        })
    }

    fn evaluate_prf(
        &self,
        credential_id: &[u8],
        salt: &[u8],
    ) -> Result<Zeroizing<[u8; 32]>, PlatformError> {
        let encoded = passkey_entry(credential_id)?
            .get_password()
            .map_err(|error| map_passkey_get_error(&error))?;
        let secret = decode_passkey_secret(&encoded)?;
        Ok(Zeroizing::new(derive_passkey_prf(&secret, salt)?))
    }
}

/// Deterministic outcomes supported by [`MemoryPlatformPasskeyRegistrar`].
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum MemoryPlatformPasskeyOutcome {
    /// Registration succeeds with a canned [`PasskeyRegistration`].
    Allow(PasskeyRegistration),
    /// Registration fails with [`PlatformError::PasskeyUnsupported`].
    Unsupported,
    /// Registration fails with [`PlatformError::PasskeyAuthFailed`].
    AuthFailed,
}

/// In-memory test registrar with deterministic outcomes.
///
/// Stores at most one credential id and its associated PRF output so tests
/// can round-trip register -> `evaluate_prf` flows.
#[derive(Debug)]
pub struct MemoryPlatformPasskeyRegistrar {
    outcome: MemoryPlatformPasskeyOutcome,
    prf_output: [u8; 32],
    credential_id: Mutex<Option<Vec<u8>>>,
}

impl MemoryPlatformPasskeyRegistrar {
    /// Returns a canned successful registration with the given PRF output.
    #[must_use]
    pub const fn allowing(registration: PasskeyRegistration, prf_output: [u8; 32]) -> Self {
        Self {
            outcome: MemoryPlatformPasskeyOutcome::Allow(registration),
            prf_output,
            credential_id: Mutex::new(None),
        }
    }

    /// Returns a registrar that always reports the platform as unsupported.
    #[must_use]
    pub const fn unsupported() -> Self {
        Self {
            outcome: MemoryPlatformPasskeyOutcome::Unsupported,
            prf_output: [0_u8; 32],
            credential_id: Mutex::new(None),
        }
    }

    /// Returns a registrar that always reports a platform auth failure.
    #[must_use]
    pub const fn auth_failed() -> Self {
        Self {
            outcome: MemoryPlatformPasskeyOutcome::AuthFailed,
            prf_output: [0_u8; 32],
            credential_id: Mutex::new(None),
        }
    }

    /// Returns a canned PRF output matched against any credential id.
    ///
    /// Used by tests that need [`PlatformPasskeyRegistrar::evaluate_prf`]
    /// without first calling [`PlatformPasskeyRegistrar::register_passkey`].
    #[must_use]
    pub const fn with_known_credential(prf_output: [u8; 32], credential_id: Vec<u8>) -> Self {
        Self {
            outcome: MemoryPlatformPasskeyOutcome::AuthFailed,
            prf_output,
            credential_id: Mutex::new(Some(credential_id)),
        }
    }
}

impl PlatformPasskeyRegistrar for MemoryPlatformPasskeyRegistrar {
    fn register_passkey(
        &self,
        _label: &str,
        _relying_party_id: &str,
    ) -> Result<PasskeyRegistration, PlatformError> {
        match &self.outcome {
            MemoryPlatformPasskeyOutcome::Allow(registration) => {
                {
                    let mut guard =
                        self.credential_id.lock().map_err(|_| PlatformError::MemoryPoisoned)?;
                    *guard = Some(registration.credential_id.clone());
                }
                Ok(registration.clone())
            }
            MemoryPlatformPasskeyOutcome::Unsupported => Err(PlatformError::PasskeyUnsupported),
            MemoryPlatformPasskeyOutcome::AuthFailed => Err(PlatformError::PasskeyAuthFailed),
        }
    }

    fn evaluate_prf(
        &self,
        credential_id: &[u8],
        _salt: &[u8],
    ) -> Result<Zeroizing<[u8; 32]>, PlatformError> {
        let known_credential_id = {
            let guard = self.credential_id.lock().map_err(|_| PlatformError::MemoryPoisoned)?;
            guard.clone()
        };
        match known_credential_id {
            Some(known) if known.as_slice() == credential_id => Ok(Zeroizing::new(self.prf_output)),
            Some(_) => Err(PlatformError::PasskeyNotFound),
            None => match self.outcome {
                MemoryPlatformPasskeyOutcome::Unsupported => Err(PlatformError::PasskeyUnsupported),
                _ => Err(PlatformError::PasskeyAuthFailed),
            },
        }
    }
}

/// Returns the default passkey registrar for this build.
#[must_use]
pub const fn default_platform_passkey_registrar() -> KeyringPlatformPasskeyRegistrar {
    KeyringPlatformPasskeyRegistrar
}

fn passkey_entry(credential_id: &[u8]) -> Result<Entry, PlatformError> {
    Entry::new(PASSKEY_KEYRING_SERVICE, &passkey_account(credential_id))
        .map_err(|_| PlatformError::PasskeyUnsupported)
}

pub fn passkey_account(credential_id: &[u8]) -> String {
    format!("{PASSKEY_ACCOUNT_PREFIX}{}", BASE64URL_NOPAD.encode(credential_id))
}

fn encode_passkey_secret(secret: &[u8; KEY_LEN]) -> String {
    BASE64URL_NOPAD.encode(secret)
}

fn decode_passkey_secret(encoded: &str) -> Result<Zeroizing<[u8; KEY_LEN]>, PlatformError> {
    let decoded =
        BASE64URL_NOPAD.decode(encoded.as_bytes()).map_err(|_| PlatformError::PasskeyAuthFailed)?;
    if decoded.len() != KEY_LEN {
        return Err(PlatformError::PasskeyAuthFailed);
    }
    let mut secret = Zeroizing::new([0_u8; KEY_LEN]);
    secret.copy_from_slice(&decoded);
    Ok(secret)
}

pub fn public_metadata_key(secret: &[u8; KEY_LEN]) -> Vec<u8> {
    Sha256::new().chain_update(PASSKEY_PUBLIC_KEY_DOMAIN).chain_update(secret).finalize().to_vec()
}

pub fn derive_passkey_prf(
    secret: &[u8; KEY_LEN],
    salt: &[u8],
) -> Result<[u8; KEY_LEN], PlatformError> {
    let mut mac =
        HmacSha256::new_from_slice(secret).map_err(|_| PlatformError::PasskeyAuthFailed)?;
    mac.update(PASSKEY_PRF_DOMAIN);
    mac.update(salt);
    Ok(mac.finalize().into_bytes().into())
}

const fn map_passkey_get_error(error: &keyring::Error) -> PlatformError {
    match error {
        keyring::Error::NoEntry => PlatformError::PasskeyNotFound,
        _ => PlatformError::PasskeyAuthFailed,
    }
}

pub const fn platform_transport_label() -> &'static str {
    #[cfg(target_os = "macos")]
    {
        "macos-keychain"
    }
    #[cfg(target_os = "windows")]
    {
        "windows-credential-manager"
    }
    #[cfg(target_os = "linux")]
    {
        "linux-secret-service"
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        "platform-keyring"
    }
}
