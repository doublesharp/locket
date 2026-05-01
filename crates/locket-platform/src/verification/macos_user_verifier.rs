//! macOS implementation of [`LocalUserVerifier`] backed by the
//! LocalAuthentication.framework wrapper in
//! [`crate::macos_local_authentication`].
//!
//! This file contains zero `unsafe`. All Objective-C interaction is
//! confined to `macos_local_authentication.rs`. See
//! `docs/specs/crypto.md:192-218` for the spec this satisfies.

use crate::macos_local_authentication::{LocalAuthError, evaluate_local_user};
use crate::platform_name;
use crate::user_verification::{
    LocalUserVerification, LocalUserVerificationMethod, LocalUserVerificationRequest,
    LocalUserVerifier,
};

use crate::error::PlatformError;

/// macOS [`LocalUserVerifier`] backed by LocalAuthentication.framework.
///
/// The verifier delegates to the safe wrapper
/// [`evaluate_local_user`](crate::macos_local_authentication::evaluate_local_user)
/// and maps its boolean outcome into the
/// [`LocalUserVerifier`] trait's success and failure variants.
#[derive(Debug, Clone, Copy, Default)]
pub struct MacosLocalUserVerifier;

impl MacosLocalUserVerifier {
    /// Creates a verifier ready to invoke the platform prompt.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl LocalUserVerifier for MacosLocalUserVerifier {
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
    use super::MacosLocalUserVerifier;
    use crate::error::PlatformError;
    use crate::macos_local_authentication::with_test_override;
    use crate::user_verification::{
        LocalUserVerificationMethod, LocalUserVerificationRequest, LocalUserVerifier,
    };

    #[test]
    fn allow_maps_to_platform_prompt() {
        with_test_override(Some("allow"), || {
            let request = LocalUserVerificationRequest::new("unlock", "Unlock local vault");
            let verifier = MacosLocalUserVerifier::new();
            let result = verifier.verify_user(&request).expect("allow override succeeds");
            assert_eq!(result.method, LocalUserVerificationMethod::PlatformPrompt);
            assert_eq!(result.platform, super::platform_name());
        });
    }

    #[test]
    fn deny_maps_to_verification_failed() {
        with_test_override(Some("deny"), || {
            let request = LocalUserVerificationRequest::new("reveal", "Reveal DATABASE_URL");
            let verifier = MacosLocalUserVerifier::new();
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
            let verifier = MacosLocalUserVerifier::new();
            assert!(matches!(
                verifier.verify_user(&request),
                Err(PlatformError::LocalUserVerificationUnavailable)
            ));
        });
    }
}
