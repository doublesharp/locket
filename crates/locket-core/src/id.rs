//! Typed opaque identifier wrappers.

use std::fmt::{self, Display};
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

const GENERATED_ID_RANDOM_BYTES: usize = 16;
const GENERATED_ID_SUFFIX_CHARS: usize = GENERATED_ID_RANDOM_BYTES * 2;

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

            /// Generates a new opaque identifier using operating-system randomness.
            ///
            /// The generated identifier has this type's required prefix followed by
            /// a lowercase hexadecimal random suffix.
            ///
            /// # Errors
            ///
            /// Returns [`IdGenerationError`] when secure random bytes cannot be read
            /// from the operating system.
            pub fn generate() -> Result<Self, IdGenerationError> {
                generate_id(Self::PREFIX).map(Self)
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

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(self.as_str())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::new(value).map_err(serde::de::Error::custom)
            }
        }
    };
}

opaque_id!(ProjectId, "lk_proj_");
opaque_id!(ProfileId, "lk_prof_");
opaque_id!(SecretId, "lk_sec_");
opaque_id!(KeyId, "lk_key_");
opaque_id!(DeviceId, "lk_dev_");
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

/// Error returned when an opaque identifier cannot be generated.
#[derive(Debug, Clone, Eq, Error, PartialEq)]
#[error("secure random id generation failed")]
pub struct IdGenerationError;

fn validate_id(value: &str, expected_prefix: &'static str) -> Result<(), InvalidId> {
    if value.strip_prefix(expected_prefix).is_some_and(|suffix| !suffix.is_empty()) {
        Ok(())
    } else {
        Err(InvalidId { expected_prefix })
    }
}

fn generate_id(prefix: &str) -> Result<String, IdGenerationError> {
    let mut random = [0_u8; GENERATED_ID_RANDOM_BYTES];
    getrandom::getrandom(&mut random).map_err(|_| IdGenerationError)?;

    let mut value = String::with_capacity(prefix.len() + GENERATED_ID_SUFFIX_CHARS);
    value.push_str(prefix);
    append_lower_hex(&mut value, &random);
    Ok(value)
}

fn append_lower_hex(output: &mut String, bytes: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::{
        ClientId, DeviceId, KdfProfileId, KeyId, ProfileId, ProjectId, SecretId, SessionId,
    };

    #[test]
    fn accepts_ids_with_expected_prefixes() {
        assert!(ProjectId::new("lk_proj_abc").is_ok());
        assert!(ProfileId::new("lk_prof_default").is_ok());
        assert!(SecretId::new("lk_sec_database").is_ok());
        assert!(KeyId::new("lk_key_01").is_ok());
        assert!(DeviceId::new("lk_dev_laptop").is_ok());
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

    #[test]
    fn invalid_id_reports_expected_prefix() {
        let result = ProjectId::new("lk_sec_abc");

        assert!(matches!(
            result,
            Err(super::InvalidId { expected_prefix }) if expected_prefix == ProjectId::PREFIX
        ));
    }

    #[test]
    fn display_from_str_and_into_string_preserve_value() -> Result<(), super::InvalidId> {
        let id = "lk_proj_abc";
        let parsed = id.parse::<ProjectId>()?;

        assert_eq!(parsed.to_string(), id);
        assert_eq!(parsed.into_string(), id);
        Ok(())
    }

    #[test]
    fn serializes_as_string_and_revalidates_on_deserialize()
    -> Result<(), Box<dyn std::error::Error>> {
        let id = ProjectId::new("lk_proj_abc")?;
        let serialized = serde_json::to_string(&id)?;

        assert_eq!(serialized, "\"lk_proj_abc\"");
        assert!(matches!(
            serde_json::from_str::<ProjectId>("\"lk_proj_abc\"").as_ref().map(ProjectId::as_str),
            Ok("lk_proj_abc")
        ));
        assert!(serde_json::from_str::<ProjectId>("\"lk_sec_abc\"").is_err());
        Ok(())
    }

    #[test]
    fn generates_lowercase_hex_project_ids() -> Result<(), super::IdGenerationError> {
        let id = ProjectId::generate()?;

        assert!(id.as_str().starts_with(ProjectId::PREFIX));
        let suffix = &id.as_str()[ProjectId::PREFIX.len()..];

        assert_eq!(suffix.len(), 32);
        assert!(suffix.chars().all(|value| value.is_ascii_hexdigit() && !value.is_uppercase()));
        Ok(())
    }

    #[test]
    fn generated_ids_have_type_prefixes_and_unique_shape() -> Result<(), super::IdGenerationError> {
        let ids = [
            (ProfileId::PREFIX, ProfileId::generate()?.into_string()),
            (SecretId::PREFIX, SecretId::generate()?.into_string()),
            (KeyId::PREFIX, KeyId::generate()?.into_string()),
            (DeviceId::PREFIX, DeviceId::generate()?.into_string()),
            (SessionId::PREFIX, SessionId::generate()?.into_string()),
            (ClientId::PREFIX, ClientId::generate()?.into_string()),
            (KdfProfileId::PREFIX, KdfProfileId::generate()?.into_string()),
        ];

        let unique = ids.iter().map(|(_, id)| id).collect::<HashSet<_>>();
        assert_eq!(unique.len(), ids.len());

        for (prefix, id) in ids {
            assert!(id.starts_with(prefix));
            let suffix = &id[prefix.len()..];
            assert_eq!(suffix.len(), 32);
            assert!(suffix.chars().all(|value| value.is_ascii_hexdigit() && !value.is_uppercase()));
        }

        Ok(())
    }
}
