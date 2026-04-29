//! Typed opaque identifier wrappers.

use std::fmt::{self, Display};
use std::str::FromStr;

use thiserror::Error;

macro_rules! opaque_id {
    ($name:ident, $prefix:literal) => {
        #[doc = concat!("Opaque identifier with the `", $prefix, "*` prefix.")]
        #[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
        pub struct $name(String);

        impl $name {
            #[doc = concat!("Required string prefix for [`", stringify!($name), "`].")]
            pub const PREFIX: &'static str = $prefix;

            /// Creates a validated opaque identifier.
            ///
            /// # Errors
            ///
            /// Returns [`InvalidId`] when `value` does not have this type's prefix
            /// or has an empty opaque suffix.
            pub fn new(value: impl Into<String>) -> Result<Self, InvalidId> {
                let value = value.into();
                validate_id(&value, Self::PREFIX)?;
                Ok(Self(value))
            }

            /// Returns the validated string value.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }

            /// Consumes the identifier and returns the underlying string.
            #[must_use]
            pub fn into_string(self) -> String {
                self.0
            }
        }

        impl Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl FromStr for $name {
            type Err = InvalidId;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::new(value)
            }
        }
    };
}

opaque_id!(ProjectId, "lk_proj_");
opaque_id!(ProfileId, "lk_prof_");
opaque_id!(SecretId, "lk_sec_");
opaque_id!(KeyId, "lk_key_");
opaque_id!(SessionId, "lk_session_");
opaque_id!(ClientId, "lk_client_");
opaque_id!(KdfProfileId, "lk_kdf_");

/// Error returned when an opaque identifier is invalid.
#[derive(Debug, Clone, Eq, Error, PartialEq)]
#[error("invalid id, expected prefix {expected_prefix}")]
pub struct InvalidId {
    /// Required identifier prefix.
    pub expected_prefix: &'static str,
}

fn validate_id(value: &str, expected_prefix: &'static str) -> Result<(), InvalidId> {
    if value.strip_prefix(expected_prefix).is_some_and(|suffix| !suffix.is_empty()) {
        Ok(())
    } else {
        Err(InvalidId { expected_prefix })
    }
}

#[cfg(test)]
mod tests {
    use super::{ClientId, KdfProfileId, KeyId, ProfileId, ProjectId, SecretId, SessionId};

    #[test]
    fn accepts_ids_with_expected_prefixes() {
        assert!(ProjectId::new("lk_proj_abc").is_ok());
        assert!(ProfileId::new("lk_prof_default").is_ok());
        assert!(SecretId::new("lk_sec_database").is_ok());
        assert!(KeyId::new("lk_key_01").is_ok());
        assert!(SessionId::new("lk_session_shell").is_ok());
        assert!(ClientId::new("lk_client_ci").is_ok());
        assert!(KdfProfileId::new("lk_kdf_argon2id").is_ok());
    }

    #[test]
    fn rejects_wrong_id_prefixes() {
        assert!(ProjectId::new("lk_sec_abc").is_err());
        assert!(ProfileId::new("lk_proj_default").is_err());
        assert!(SecretId::new("DATABASE_URL").is_err());
    }

    #[test]
    fn rejects_empty_id_suffixes() {
        assert!(ProjectId::new("lk_proj_").is_err());
        assert!(ClientId::new("lk_client_").is_err());
    }
}
