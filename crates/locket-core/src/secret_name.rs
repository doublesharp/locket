//! Secret-name validation.

use std::fmt::{self, Display};
use std::str::FromStr;

use thiserror::Error;

/// A portable environment-variable-compatible secret name.
///
/// Names must match `^[A-Z_][A-Z0-9_]*$`.
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct SecretName(String);

impl SecretName {
    /// Creates a validated secret name.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidSecretName`] when `value` does not match
    /// `^[A-Z_][A-Z0-9_]*$`.
    pub fn new(value: impl Into<String>) -> Result<Self, InvalidSecretName> {
        let value = value.into();
        validate_secret_name(&value)?;
        Ok(Self(value))
    }

    /// Returns the validated string value.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consumes the name and returns the underlying string.
    #[must_use]
    pub fn into_string(self) -> String {
        self.0
    }
}

impl Display for SecretName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for SecretName {
    type Err = InvalidSecretName;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

/// Error returned when a secret name is invalid.
#[derive(Debug, Clone, Eq, Error, PartialEq)]
#[error("invalid secret name")]
pub struct InvalidSecretName;

fn validate_secret_name(value: &str) -> Result<(), InvalidSecretName> {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return Err(InvalidSecretName);
    };

    if !is_secret_name_start(first) {
        return Err(InvalidSecretName);
    }

    if chars.all(is_secret_name_rest) { Ok(()) } else { Err(InvalidSecretName) }
}

const fn is_secret_name_start(value: char) -> bool {
    matches!(value, 'A'..='Z' | '_')
}

const fn is_secret_name_rest(value: char) -> bool {
    matches!(value, 'A'..='Z' | '0'..='9' | '_')
}

#[cfg(test)]
mod tests {
    use super::SecretName;

    #[test]
    fn accepts_portable_secret_names() {
        for value in ["A", "_", "DATABASE_URL", "_SERVICE_2", "OPENAI_API_KEY"] {
            assert!(SecretName::new(value).is_ok(), "{value} should be valid");
        }
    }

    #[test]
    fn rejects_empty_secret_names() {
        assert!(SecretName::new("").is_err());
    }

    #[test]
    fn rejects_names_starting_with_digits() {
        assert!(SecretName::new("1PASSWORD_TOKEN").is_err());
    }

    #[test]
    fn rejects_lowercase_and_punctuation() {
        for value in ["database_url", "DATABASE-URL", "DATABASE.URL", "DATABASE URL"] {
            assert!(SecretName::new(value).is_err(), "{value} should be invalid");
        }
    }

    #[test]
    fn exposes_validated_string() {
        let name = SecretName::new("DATABASE_URL");
        assert!(matches!(name.as_ref().map(SecretName::as_str), Ok("DATABASE_URL")));
    }
}
