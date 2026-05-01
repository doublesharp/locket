//! Windows Hello LocalUserVerifier backend (placeholder).
//!
//! Mirrors the structure of [`crate::macos_local_authentication`] but
//! ships as a stub until the
//! `Windows::Security::Credentials::UI::UserConsentVerifier` binding is
//! wired through the `windows` crate. The intended path is:
//!
//!   1. Construct a `UserConsentVerifier` request with the localized
//!      reason via `UserConsentVerifier::RequestVerificationAsync`.
//!   2. Resolve the returned `IAsyncOperation<UserConsentVerificationResult>`
//!      synchronously (using `.get()` from the WinRT runtime).
//!   3. Map `UserConsentVerificationResult::Verified` to `Ok(true)`,
//!      `DeviceBusy`/`Canceled`/`RetriesExhausted` to `Ok(false)` (user
//!      rejected), `DeviceNotPresent`/`NotConfiguredForUser`/
//!      `DisabledByPolicy` to [`LocalAuthError::Unavailable`].
//!
//! The `windows` crate is currently transitive in the workspace
//! lock-graph but is not a direct dependency of `locket-platform`, and
//! adding a new direct dep with the `Security_Credentials_UI` feature
//! flag without on-host Windows verification risks pulling in a
//! mis-configured feature surface. Per the parent spec's "If a
//! platform's binding crate is unavailable, ship a stub that returns
//! [`LocalAuthError::Unavailable`] and document why," this module
//! returns [`LocalAuthError::Unavailable`] for every real call until
//! the dep is picked. The
//! [`WindowsLocalUserVerifier`](crate::windows_user_verifier::WindowsLocalUserVerifier)
//! built on top of this wrapper consequently surfaces
//! [`crate::error::PlatformError::LocalUserVerificationUnavailable`] on
//! Windows hosts, which is the documented "no platform backend"
//! behavior.
//!
//! This file contains no `unsafe`. Once a real implementation lands,
//! follow the macOS pattern: a single safe `evaluate_local_user` entry
//! point, all `unsafe` confined here behind a SAFETY audit comment,
//! and no `unsafe` in
//! [`crate::windows_user_verifier`].
//!
//! Tests honor the `LOCKET_TEST_LOCAL_AUTH=allow|deny|unavailable`
//! environment variable so callers can drive the wrapper
//! deterministically once a real implementation lands; today the
//! override is the only way [`evaluate_local_user`] can return `Ok(_)`
//! at all.

use thiserror::Error;

/// Environment variable consulted by tests so they can drive the wrapper
/// deterministically without invoking Windows Hello.
const TEST_OVERRIDE_ENV: &str = "LOCKET_TEST_LOCAL_AUTH";

/// Errors returned by [`evaluate_local_user`].
///
/// The variants mirror [`crate::macos_local_authentication::LocalAuthError`]
/// so the outer [`LocalUserVerifier`](crate::user_verification::LocalUserVerifier)
/// implementation can treat both backends interchangeably.
#[derive(Debug, Error)]
pub enum LocalAuthError {
    /// No platform backend is wired on this build (current default
    /// state) or `UserConsentVerifier` reported the policy as
    /// unavailable (no Hello enrollment, hardware missing, etc.).
    #[error("Windows Hello unavailable: {0}")]
    Unavailable(String),
    /// The user dismissed, cancelled, or otherwise refused the prompt.
    #[error("Windows Hello ceremony rejected: {0}")]
    Rejected(String),
    /// `UserConsentVerifier` returned a low-level error before a reply
    /// could be observed.
    #[error("Windows Hello backend error: {0}")]
    Framework(String),
    /// The platform never delivered a reply within the configured
    /// timeout.
    #[error("Windows Hello evaluation timed out")]
    Timeout,
    /// The supplied localized reason was empty.
    #[error("Windows Hello requires a non-empty localized reason")]
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

/// Evaluate a local user-verification ceremony on Windows via Hello.
///
/// Until the `windows` crate's
/// `Security::Credentials::UI::UserConsentVerifier` binding is wired,
/// this returns [`LocalAuthError::Unavailable`] for every real call
/// and only honors the `LOCKET_TEST_LOCAL_AUTH` test override.
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
        "no Windows Hello backend wired (UserConsentVerifier placeholder)".to_owned(),
    ))
}

/// Serializes tests that mutate the shared `LOCKET_TEST_LOCAL_AUTH`
/// environment variable so they cannot race across the test binary.
///
/// Lives in this module so the entire `unsafe { env::set_var(..) }`
/// mechanic stays inside the authorized backend module, mirroring the
/// macOS layout. Callers in sibling modules
/// (`windows_user_verifier.rs`) drive their tests through
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
