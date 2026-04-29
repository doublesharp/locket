//! Local profile-name validation.

use std::fmt::{self, Display};
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

/// Maximum number of bytes allowed in a local profile name.
pub const MAX_PROFILE_NAME_LEN: usize = 64;

/// A validated local profile name.
///
/// Profile names must start with a lowercase ASCII letter. Remaining
/// characters may be lowercase ASCII alphanumeric characters, `_`, or `-`.
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ProfileName(String);

impl ProfileName {
    /// Creates a validated profile name.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidProfileName`] when `value` is empty, longer than
    /// [`MAX_PROFILE_NAME_LEN`], does not start with a lowercase ASCII letter,
    /// or contains a character outside lowercase ASCII alphanumeric
    /// characters, `_`, and `-`.
    pub fn new(value: impl Into<String>) -> Result<Self, InvalidProfileName> {
        let value = value.into();
        validate_profile_name(&value)?;
        Ok(Self(value))
    }

    /// Returns the validated string value.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consumes the profile name and returns the underlying string.
    #[must_use]
    pub fn into_string(self) -> String {
        self.0
    }
}

impl Display for ProfileName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for ProfileName {
    type Err = InvalidProfileName;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl Serialize for ProfileName {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ProfileName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// Error returned when a local profile name is invalid.
#[derive(Debug, Clone, Eq, Error, PartialEq)]
#[error("invalid profile name")]
pub struct InvalidProfileName;

fn validate_profile_name(value: &str) -> Result<(), InvalidProfileName> {
    if value.is_empty() || value.len() > MAX_PROFILE_NAME_LEN {
        return Err(InvalidProfileName);
    }

    let bytes = value.as_bytes();
    let Some((first, rest)) = bytes.split_first() else {
        return Err(InvalidProfileName);
    };

    if !first.is_ascii_lowercase() {
        return Err(InvalidProfileName);
    }

    if rest.iter().copied().all(is_profile_name_rest) { Ok(()) } else { Err(InvalidProfileName) }
}

const fn is_profile_name_rest(value: u8) -> bool {
    value.is_ascii_lowercase() || value.is_ascii_digit() || matches!(value, b'_' | b'-')
}

#[cfg(test)]
mod tests {
    use super::{MAX_PROFILE_NAME_LEN, ProfileName};

    #[test]
    fn accepts_simple_local_profile_names() {
        for value in ["a", "default", "dev-local", "ci_1", "prod-us-west-2"] {
            assert!(ProfileName::new(value).is_ok(), "{value} should be valid");
        }
    }

    #[test]
    fn accepts_profile_names_up_to_max_length() {
        let value = "a".repeat(MAX_PROFILE_NAME_LEN);
        assert!(ProfileName::new(value).is_ok());
    }

    #[test]
    fn rejects_empty_profile_names() {
        assert!(ProfileName::new("").is_err());
    }

    #[test]
    fn rejects_profile_names_longer_than_max_length() {
        let value = "a".repeat(MAX_PROFILE_NAME_LEN + 1);
        assert!(ProfileName::new(value).is_err());
    }

    #[test]
    fn rejects_names_not_starting_with_lowercase_ascii() {
        for value in ["1dev", "_dev", "-dev", "Dev", "édev"] {
            assert!(ProfileName::new(value).is_err(), "{value} should be invalid");
        }
    }

    #[test]
    fn rejects_invalid_rest_characters() {
        for value in ["dev.local", "dev local", "dev/local", "dev:local", "devLocal", "devé"] {
            assert!(ProfileName::new(value).is_err(), "{value} should be invalid");
        }
    }

    #[test]
    fn exposes_validated_string() {
        let name = ProfileName::new("dev-local");
        assert!(matches!(name.as_ref().map(ProfileName::as_str), Ok("dev-local")));
    }
}
