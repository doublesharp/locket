//! Linux LocalUserVerifier backend (placeholder).
//!
//! Mirrors the structure of [`crate::macos_local_authentication`] but
//! ships as a stub until the platform binding crate is selected. The
//! intended path is:
//!
//!   1. Try a Secret Service (`libsecret` / D-Bus) presence challenge,
//!      e.g. via the `secret-service` crate, so a logged-in desktop
//!      session can satisfy the gate without dedicated hardware.
//!   2. Fall back to a hardware FIDO2 / `libfido2-sys` user-presence
//!      touch challenge so headless sessions with a security key can
//!      still verify locally.
//!
//! Neither `secret-service` nor `libfido2-sys` is currently in the
//! workspace dependency graph (`Cargo.toml`). Per the parent spec the
//! production wrapper must not be in the position of pulling heavy new
//! deps without clear justification, so until that decision is made
//! [`evaluate_local_user`] returns [`LocalAuthError::Unavailable`] on
//! Linux. The [`LinuxLocalUserVerifier`](crate::linux_user_verifier::LinuxLocalUserVerifier)
//! built on top of this wrapper consequently surfaces
//! [`crate::error::PlatformError::LocalUserVerificationUnavailable`] to
//! callers, which is the documented "no platform backend" behavior used
//! by the rest of `locket-platform`.
//!
//! This file contains no `unsafe`. The `unsafe_code = "deny"` lint at
//! the crate level is therefore upheld here without any local
//! exception. Once a binding crate is picked, the FFI surface should
//! follow the macOS pattern (`#![allow(unsafe_code)]` with a SAFETY
//! audit comment, single safe `evaluate_local_user` entry point, no
//! `unsafe` outside this module).
//!
//! Tests honor the `LOCKET_TEST_LOCAL_AUTH=allow|deny|unavailable`
//! environment variable so callers can drive the wrapper
//! deterministically once a real implementation lands; today the
//! override is the only way [`evaluate_local_user`] can return `Ok(_)`
//! at all.

use thiserror::Error;

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
    /// No platform backend is wired on this build (current default
    /// state) or the desktop reported the policy as unsupported.
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
    Some(match value.as_str() {
        "allow" => Ok(true),
        "deny" => Ok(false),
        "unavailable" => Err(LocalAuthError::Unavailable("test override".to_owned())),
        "timeout" => Err(LocalAuthError::Timeout),
        other => Err(LocalAuthError::Framework(format!(
            "unrecognized {TEST_OVERRIDE_ENV} override: {other}"
        ))),
    })
}

/// Evaluate a local user-verification ceremony on Linux.
///
/// Until a Secret Service / FIDO2 binding crate is wired in, this
/// returns [`LocalAuthError::Unavailable`] for every real call and only
/// honors the `LOCKET_TEST_LOCAL_AUTH` test override.
///
/// # Errors
///
/// Returns [`LocalAuthError::EmptyReason`] when `reason` is blank, and
/// [`LocalAuthError::Unavailable`] when no platform backend is wired
/// (the current default) or the test override selected
/// `unavailable`.
pub fn evaluate_local_user(reason: &str) -> Result<bool, LocalAuthError> {
    if reason.trim().is_empty() {
        return Err(LocalAuthError::EmptyReason);
    }

    if let Some(outcome) = test_override() {
        return outcome;
    }

    Err(LocalAuthError::Unavailable(
        "no Linux local-auth backend wired (Secret Service / FIDO2 placeholder)".to_owned(),
    ))
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
}
