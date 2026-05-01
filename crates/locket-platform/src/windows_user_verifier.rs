//! Windows implementation of [`LocalUserVerifier`] backed by the
//! Windows Hello wrapper in [`crate::windows_local_authentication`].
//!
//! This file contains zero `unsafe`. All platform interaction is
//! confined to `windows_local_authentication.rs`.

use crate::error::PlatformError;
use crate::platform_name;
use crate::user_verification::{
    LocalUserVerification, LocalUserVerificationMethod, LocalUserVerificationRequest,
    LocalUserVerifier,
};
use crate::windows_local_authentication::{LocalAuthError, evaluate_local_user};

/// Windows [`LocalUserVerifier`] backed by Windows Hello
/// `UserConsentVerifier`.
#[derive(Debug, Clone, Copy, Default)]
pub struct WindowsLocalUserVerifier;

impl WindowsLocalUserVerifier {
    /// Creates a verifier ready to invoke the Windows Hello prompt.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl LocalUserVerifier for WindowsLocalUserVerifier {
    fn verify_user(
        &self,
        request: &LocalUserVerificationRequest,
    ) -> Result<LocalUserVerification, PlatformError> {
        match evaluate_local_user(&request.reason) {
            Ok(true) => Ok(LocalUserVerification::new(
                LocalUserVerificationMethod::PlatformPrompt,
                platform_name(),
            )),
            Err(LocalAuthError::Unavailable(_)) => {
                Err(PlatformError::LocalUserVerificationUnavailable)
            }
            Ok(false)
            | Err(
                LocalAuthError::Rejected(_)
                | LocalAuthError::Framework(_)
                | LocalAuthError::Timeout
                | LocalAuthError::EmptyReason,
            ) => Err(PlatformError::LocalUserVerificationFailed),
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::WindowsLocalUserVerifier;
    use crate::error::PlatformError;
    use crate::user_verification::{
        LocalUserVerificationMethod, LocalUserVerificationRequest, LocalUserVerifier,
    };
    use crate::windows_local_authentication::with_test_override;

    #[test]
    fn allow_maps_to_platform_prompt() {
        with_test_override(Some("allow"), || {
            let request = LocalUserVerificationRequest::new("unlock", "Unlock local vault");
            let verifier = WindowsLocalUserVerifier::new();
            let result = verifier.verify_user(&request).expect("allow override succeeds");
            assert_eq!(result.method, LocalUserVerificationMethod::PlatformPrompt);
            assert_eq!(result.platform, super::platform_name());
        });
    }

    #[test]
    fn deny_maps_to_verification_failed() {
        with_test_override(Some("deny"), || {
            let request = LocalUserVerificationRequest::new("reveal", "Reveal DATABASE_URL");
            let verifier = WindowsLocalUserVerifier::new();
            assert!(matches!(
                verifier.verify_user(&request),
                Err(PlatformError::LocalUserVerificationFailed)
            ));
        });
    }

    #[test]
    fn unavailable_maps_to_unavailable_error() {
        with_test_override(Some("unavailable"), || {
            let request = LocalUserVerificationRequest::new("unlock", "Unlock local vault");
            let verifier = WindowsLocalUserVerifier::new();
            assert!(matches!(
                verifier.verify_user(&request),
                Err(PlatformError::LocalUserVerificationUnavailable)
            ));
        });
    }
}
