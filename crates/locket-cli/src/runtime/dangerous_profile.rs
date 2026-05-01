//! Dangerous-profile read-side consent gate.
//!
//! Reads against profiles marked `dangerous` must be acknowledged at the call
//! site through an explicit `--use-dangerous` flag. The gate is shared by
//! `get`, `get --reveal`, `get --copy`, and the cross-profile `copy` flows so
//! the refusal point and audit denial reason stay consistent.

use locket_core::LocketError;
use locket_store::ProfileRecord;

use crate::runtime::error::{CliError, typed_cli_error};

/// Audit denial reason emitted when the gate refuses a dangerous-profile read.
pub const DANGEROUS_PROFILE_DENIAL_REASON: &str = "dangerous_profile_unconfirmed";

/// Refuse read-side access to a profile marked `dangerous` unless the caller
/// passed the `--use-dangerous` flag.
///
/// When `profile.dangerous` is `false`, this is a no-op regardless of
/// `use_dangerous`. When `profile.dangerous` is `true` and `use_dangerous`
/// is `false`, a typed [`LocketError::DangerousProfileConfirmationRequired`]
/// `CliError` is returned. The message embeds the profile id and name so
/// callers and audit-row metadata can attribute the refusal without an
/// extra store lookup.
pub fn ensure_dangerous_profile_consent(
    profile: &ProfileRecord,
    use_dangerous: bool,
) -> Result<(), CliError> {
    if !profile.dangerous || use_dangerous {
        return Ok(());
    }
    Err(typed_cli_error(
        LocketError::DangerousProfileConfirmationRequired,
        format!(
            "profile {} ({}) is marked dangerous; pass --use-dangerous to confirm the read",
            profile.name, profile.id,
        ),
    ))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use locket_store::ProfileRecord;

    use super::{DANGEROUS_PROFILE_DENIAL_REASON, ensure_dangerous_profile_consent};
    use crate::runtime::error::CliError;

    fn profile(dangerous: bool) -> ProfileRecord {
        ProfileRecord {
            id: "lk_prof_test".to_owned(),
            project_id: "lk_proj_test".to_owned(),
            name: "prod".to_owned(),
            dangerous,
            created_at: 0,
        }
    }

    #[test]
    fn non_dangerous_profile_is_noop_without_flag() {
        ensure_dangerous_profile_consent(&profile(false), false).unwrap();
    }

    #[test]
    fn non_dangerous_profile_is_noop_with_flag() {
        ensure_dangerous_profile_consent(&profile(false), true).unwrap();
    }

    #[test]
    fn dangerous_profile_with_flag_is_allowed() {
        ensure_dangerous_profile_consent(&profile(true), true).unwrap();
    }

    #[test]
    fn dangerous_profile_without_flag_returns_typed_error() {
        let result = ensure_dangerous_profile_consent(&profile(true), false);
        let CliError::Typed { kind, message } = result.unwrap_err() else {
            panic!("expected typed CliError");
        };
        assert_eq!(kind, locket_core::LocketError::DangerousProfileConfirmationRequired);
        assert!(message.contains("prod"));
        assert!(message.contains("lk_prof_test"));
    }

    #[test]
    fn denial_reason_is_stable() {
        assert_eq!(DANGEROUS_PROFILE_DENIAL_REASON, "dangerous_profile_unconfirmed");
    }
}
