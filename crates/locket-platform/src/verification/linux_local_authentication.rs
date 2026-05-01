//! Linux LocalUserVerifier backend.
//!
//! Mirrors the structure of [`crate::macos_local_authentication`] and
//! keeps the platform-facing implementation behind a single safe entry
//! point. The current backend is:
//!
//!   1. Try a Secret Service (`libsecret` / D-Bus) presence challenge
//!      through the workspace's `keyring` dependency with the Linux
//!      Secret Service feature enabled. A locked keyring should trigger
//!      the desktop unlock prompt; a headless or missing D-Bus service
//!      reports [`LocalAuthError::Unavailable`].
//!   2. If Secret Service is unavailable, fall through to the
//!      `linux-fido2` feature-gated FIDO2 user-presence scaffold. The
//!      feature is intentionally dependency-free until the real
//!      `libfido2-sys` ceremony is validated on a Linux host with a
//!      physical key.
//!
//! This file contains no `unsafe`. The `unsafe_code = "deny"` lint at
//! the crate level is therefore upheld here without any local exception.
//!
//! Tests honor the
//! `LOCKET_TEST_LOCAL_AUTH=allow|deny|unavailable|fido2-allow|fido2-deny|fido2-unavailable`
//! environment variable so callers can drive the wrapper
//! deterministically without invoking Secret Service or a hardware key.

use std::sync::mpsc;
use std::time::Duration;

use data_encoding::BASE64URL_NOPAD;
use keyring::{Entry, Error as KeyringError};
use locket_crypto::random_bytes;
use thiserror::Error;

/// Maximum time we will block waiting for the Secret Service/keyring
/// backend. The keyring crate documents that Secret Service calls can
/// wedge if driven on the wrong thread; this guard prevents callers from
/// blocking indefinitely.
const EVALUATE_TIMEOUT: Duration = Duration::from_secs(120);
const SERVICE: &str = "dev.0xdoublesharp.locket.local-auth";
const ACCOUNT_PREFIX: &str = "presence:";

/// Environment variable consulted by tests so they can drive the wrapper
/// deterministically without invoking a real Linux backend.
const TEST_OVERRIDE_ENV: &str = "LOCKET_TEST_LOCAL_AUTH";

/// Errors returned by [`evaluate_local_user`].
///
/// The variants mirror [`crate::macos_local_authentication::LocalAuthError`]
/// so the outer [`LocalUserVerifier`](crate::user_verification::LocalUserVerifier)
/// implementation can treat both backends interchangeably.
#[derive(Debug, Error)]
pub enum LocalAuthError {
    /// Secret Service is unavailable on this host, the desktop session
    /// cannot expose it to this process, or no FIDO2 fallback is built.
    #[error("Linux local authentication unavailable: {0}")]
    Unavailable(String),
    /// The user dismissed, cancelled, or otherwise refused the prompt.
    #[error("Linux local authentication ceremony rejected: {0}")]
    Rejected(String),
    /// The platform binding returned a low-level error before a reply
    /// could be observed.
    #[error("Linux local authentication backend error: {0}")]
    Framework(String),
    /// The platform never delivered a reply within the configured
    /// timeout.
    #[error("Linux local authentication evaluation timed out")]
    Timeout,
    /// The supplied localized reason was empty.
    #[error("Linux local authentication requires a non-empty localized reason")]
    EmptyReason,
}

/// Test-only override applied before any backend call.
fn test_override() -> Option<Result<bool, LocalAuthError>> {
    let value = std::env::var(TEST_OVERRIDE_ENV).ok()?;
    match value.as_str() {
        "allow" => Some(Ok(true)),
        "deny" => Some(Ok(false)),
        "unavailable" => Some(Err(LocalAuthError::Unavailable("test override".to_owned()))),
        "timeout" => Some(Err(LocalAuthError::Timeout)),
        "fido2-allow" | "fido2-deny" | "fido2-unavailable" => None,
        other => Some(Err(LocalAuthError::Framework(format!(
            "unrecognized {TEST_OVERRIDE_ENV} override: {other}"
        )))),
    }
}

fn secret_service_test_override() -> Option<Result<bool, LocalAuthError>> {
    let value = std::env::var(TEST_OVERRIDE_ENV).ok()?;
    match value.as_str() {
        "fido2-allow" | "fido2-deny" | "fido2-unavailable" => {
            Some(Err(LocalAuthError::Unavailable("test Secret Service override".to_owned())))
        }
        _ => None,
    }
}

fn fido2_test_override() -> Option<Result<bool, LocalAuthError>> {
    let value = std::env::var(TEST_OVERRIDE_ENV).ok()?;
    match value.as_str() {
        "fido2-allow" => Some(Ok(true)),
        "fido2-deny" => Some(Ok(false)),
        "fido2-unavailable" => {
            Some(Err(LocalAuthError::Unavailable("test FIDO2 override".to_owned())))
        }
        _ => None,
    }
}

/// Evaluate a local user-verification ceremony on Linux.
///
/// This first performs a Secret Service challenge through the platform
/// keyring. It creates a short-lived random credential, reads it back,
/// and deletes it. If Secret Service is locked, the desktop environment
/// may prompt the user to unlock it before the read/write completes.
/// If Secret Service is unavailable, the FIDO2 fallback path is tried.
///
/// # Errors
///
/// Returns [`LocalAuthError::EmptyReason`] when `reason` is blank, and
/// [`LocalAuthError::Unavailable`] when neither Secret Service nor the
/// FIDO2 fallback is available to this process.
pub fn evaluate_local_user(reason: &str) -> Result<bool, LocalAuthError> {
    if reason.trim().is_empty() {
        return Err(LocalAuthError::EmptyReason);
    }

    if let Some(outcome) = test_override() {
        return outcome;
    }

    match evaluate_local_user_via_secret_service() {
        Err(LocalAuthError::Unavailable(secret_service_reason)) => {
            evaluate_local_user_via_fido2(reason).map_err(|error| match error {
                LocalAuthError::Unavailable(fido2_reason) => LocalAuthError::Unavailable(format!(
                    "Secret Service unavailable ({secret_service_reason}); \
                     FIDO2 fallback unavailable ({fido2_reason})"
                )),
                other => other,
            })
        }
        result => result,
    }
}

fn evaluate_local_user_via_secret_service() -> Result<bool, LocalAuthError> {
    if let Some(outcome) = secret_service_test_override() {
        return outcome;
    }

    let (tx, rx) = mpsc::channel();
    let _join = std::thread::Builder::new()
        .name("locket-linux-local-auth".to_owned())
        .spawn(move || {
            let _ = tx.send(run_secret_service_challenge());
        })
        .map_err(|error| {
            LocalAuthError::Framework(format!("failed to spawn Secret Service worker: {error}"))
        })?;

    match rx.recv_timeout(EVALUATE_TIMEOUT) {
        Ok(result) => result,
        Err(mpsc::RecvTimeoutError::Timeout) => Err(LocalAuthError::Timeout),
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(LocalAuthError::Framework(
            "Secret Service worker exited without a result".to_owned(),
        )),
    }
}

fn run_secret_service_challenge() -> Result<bool, LocalAuthError> {
    let nonce = random_bytes::<32>()
        .map_err(|error| LocalAuthError::Framework(format!("challenge entropy failed: {error}")))?;
    let challenge = BASE64URL_NOPAD.encode(&nonce);
    let account = format!("{ACCOUNT_PREFIX}{challenge}");
    let entry = Entry::new(SERVICE, &account).map_err(map_keyring_entry_error)?;

    entry.set_password(&challenge).map_err(map_keyring_write_error)?;
    let read_back = entry.get_password().map_err(map_keyring_read_error)?;
    let delete_result = entry.delete_credential();
    if let Err(error) = delete_result {
        return Err(map_keyring_delete_error(error));
    }

    Ok(read_back == challenge)
}

fn evaluate_local_user_via_fido2(reason: &str) -> Result<bool, LocalAuthError> {
    if let Some(outcome) = fido2_test_override() {
        return outcome;
    }

    evaluate_local_user_via_libfido2(reason)
}

#[cfg(feature = "linux-fido2")]
fn evaluate_local_user_via_libfido2(reason: &str) -> Result<bool, LocalAuthError> {
    let _ = reason;
    Err(LocalAuthError::Unavailable(
        "linux-fido2 feature is scaffold-only until the libfido2-sys ceremony \
         is validated on a Linux host with a physical security key"
            .to_owned(),
    ))
}

#[cfg(not(feature = "linux-fido2"))]
fn evaluate_local_user_via_libfido2(reason: &str) -> Result<bool, LocalAuthError> {
    let _ = reason;
    Err(LocalAuthError::Unavailable("linux-fido2 feature is not enabled in this build".to_owned()))
}

fn map_keyring_entry_error(error: KeyringError) -> LocalAuthError {
    match error {
        KeyringError::NoStorageAccess(inner) => LocalAuthError::Rejected(inner.to_string()),
        KeyringError::PlatformFailure(inner) => LocalAuthError::Unavailable(inner.to_string()),
        other => LocalAuthError::Framework(other.to_string()),
    }
}

fn map_keyring_write_error(error: KeyringError) -> LocalAuthError {
    match error {
        KeyringError::NoStorageAccess(inner) => LocalAuthError::Rejected(inner.to_string()),
        KeyringError::PlatformFailure(inner) => LocalAuthError::Unavailable(inner.to_string()),
        other => LocalAuthError::Framework(other.to_string()),
    }
}

fn map_keyring_read_error(error: KeyringError) -> LocalAuthError {
    match error {
        KeyringError::NoEntry => LocalAuthError::Framework(
            "Secret Service challenge disappeared before verification".to_owned(),
        ),
        KeyringError::NoStorageAccess(inner) => LocalAuthError::Rejected(inner.to_string()),
        KeyringError::PlatformFailure(inner) => LocalAuthError::Unavailable(inner.to_string()),
        other => LocalAuthError::Framework(other.to_string()),
    }
}

fn map_keyring_delete_error(error: KeyringError) -> LocalAuthError {
    match error {
        KeyringError::NoEntry => LocalAuthError::Framework(
            "Secret Service challenge disappeared before cleanup".to_owned(),
        ),
        KeyringError::NoStorageAccess(inner) => LocalAuthError::Rejected(inner.to_string()),
        KeyringError::PlatformFailure(inner) => LocalAuthError::Unavailable(inner.to_string()),
        other => LocalAuthError::Framework(other.to_string()),
    }
}

/// Serializes tests that mutate the shared `LOCKET_TEST_LOCAL_AUTH`
/// environment variable so they cannot race across the test binary.
///
/// Lives in this module so the entire `unsafe { env::set_var(..) }`
/// mechanic stays inside the authorized backend module, mirroring the
/// macOS layout. Callers in sibling modules
/// (`linux_user_verifier.rs`) drive their tests through
/// [`with_test_override`].
#[cfg(test)]
#[allow(unsafe_code, clippy::redundant_pub_crate, clippy::expect_used)]
pub(crate) fn with_test_override<F: FnOnce()>(value: Option<&str>, f: F) {
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    let _guard = ENV_LOCK.lock().expect("env lock poisoned");
    let previous = std::env::var(TEST_OVERRIDE_ENV).ok();
    if let Some(v) = value {
        // SAFETY: the lock above gives us exclusive access for the
        // duration of the test. `set_var` is safe when no other thread
        // is reading the environment concurrently.
        unsafe { std::env::set_var(TEST_OVERRIDE_ENV, v) };
    } else {
        // SAFETY: see above.
        unsafe { std::env::remove_var(TEST_OVERRIDE_ENV) };
    }

    f();

    if let Some(prev) = previous {
        // SAFETY: see above.
        unsafe { std::env::set_var(TEST_OVERRIDE_ENV, prev) };
    } else {
        // SAFETY: see above.
        unsafe { std::env::remove_var(TEST_OVERRIDE_ENV) };
    }
}

#[cfg(test)]
mod tests {
    use super::{LocalAuthError, evaluate_local_user, with_test_override};

    #[test]
    fn allow_override_returns_true() {
        with_test_override(Some("allow"), || {
            assert!(matches!(evaluate_local_user("Unlock vault"), Ok(true)));
        });
    }

    #[test]
    fn deny_override_returns_false() {
        with_test_override(Some("deny"), || {
            assert!(matches!(evaluate_local_user("Unlock vault"), Ok(false)));
        });
    }

    #[test]
    fn unavailable_override_maps_to_unavailable_error() {
        with_test_override(Some("unavailable"), || {
            assert!(matches!(
                evaluate_local_user("Unlock vault"),
                Err(LocalAuthError::Unavailable(_))
            ));
        });
    }

    #[test]
    fn fido2_fallback_allow_runs_after_secret_service_unavailable() {
        with_test_override(Some("fido2-allow"), || {
            assert!(matches!(evaluate_local_user("Unlock vault"), Ok(true)));
        });
    }

    #[test]
    fn fido2_fallback_deny_runs_after_secret_service_unavailable() {
        with_test_override(Some("fido2-deny"), || {
            assert!(matches!(evaluate_local_user("Unlock vault"), Ok(false)));
        });
    }

    #[test]
    fn fido2_fallback_unavailable_preserves_both_backend_reasons() {
        with_test_override(Some("fido2-unavailable"), || {
            let result = evaluate_local_user("Unlock vault");
            assert!(matches!(
                result,
                Err(LocalAuthError::Unavailable(reason))
                    if reason.contains("Secret Service unavailable")
                        && reason.contains("FIDO2 fallback unavailable")
            ));
        });
    }

    #[test]
    fn blank_reason_is_rejected_before_backend() {
        with_test_override(None, || {
            assert!(matches!(evaluate_local_user("   "), Err(LocalAuthError::EmptyReason)));
        });
    }

    #[test]
    #[ignore = "requires a Linux desktop session with Secret Service and a user prompt"]
    fn real_host_secret_service_presence_challenge() {
        with_test_override(None, || {
            assert!(matches!(evaluate_local_user("Validate Locket Secret Service"), Ok(true)));
        });
    }
}
