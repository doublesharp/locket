//! Shared local user-verification gates for sensitive CLI actions.

use locket_core::LocketError;
use locket_platform::{LocalUserVerificationMethod, LocalUserVerificationRequest};
use serde::Serialize;

use crate::runtime::RuntimeContext;
use crate::runtime::error::{CliError, typed_cli_error};

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct UserVerificationAudit {
    pub required: bool,
    pub satisfied: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<LocalUserVerificationMethod>,
}

impl UserVerificationAudit {
    #[must_use]
    pub const fn not_required() -> Self {
        Self { required: false, satisfied: false, method: None }
    }

    #[must_use]
    pub const fn failed_required() -> Self {
        Self { required: true, satisfied: false, method: None }
    }

    #[must_use]
    pub const fn satisfied(method: LocalUserVerificationMethod) -> Self {
        Self { required: true, satisfied: true, method: Some(method) }
    }
}

pub fn require_user_verification(
    context: &RuntimeContext,
    action: &'static str,
    reason: impl Into<String>,
) -> Result<UserVerificationAudit, CliError> {
    let verification = context
        .user_verifier
        .verify_user(&LocalUserVerificationRequest::new(action, reason))
        .map_err(|_| {
            typed_cli_error(
                LocketError::UserVerificationFailed,
                format!("{action}: local user verification failed"),
            )
        })?;
    Ok(UserVerificationAudit::satisfied(verification.method))
}
