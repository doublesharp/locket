//! External environment source descriptors.

use std::path::PathBuf;

use serde::Deserialize;

use super::error::PolicyParseError;

/// External environment sources declared by a command policy.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ExternalEnvSource {
    /// Consume selected names from the calling process environment.
    Parent,
    /// Read selected names from a `.env`-style file at execution time.
    File(PathBuf),
    /// Resolve names through Docker Compose config at execution time.
    Compose,
    /// Consume names published by the VS Code extension terminal integration.
    Ide,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub(super) enum RawExternalEnvSource {
    Name(String),
    File(RawExternalEnvFileSource),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawExternalEnvFileSource {
    file: String,
}

pub(super) fn parse_external_env_sources(
    command: &str,
    values: Vec<RawExternalEnvSource>,
) -> Result<Vec<ExternalEnvSource>, PolicyParseError> {
    values
        .into_iter()
        .map(|value| match value {
            RawExternalEnvSource::Name(value) => match value.as_str() {
                "parent" => Ok(ExternalEnvSource::Parent),
                "compose" => Ok(ExternalEnvSource::Compose),
                "ide" => Ok(ExternalEnvSource::Ide),
                _ => Err(PolicyParseError::InvalidExternalEnvSource {
                    command: command.to_owned(),
                    value,
                }),
            },
            RawExternalEnvSource::File(source) => {
                if source.file.is_empty() {
                    Err(PolicyParseError::EmptyExternalEnvFile { command: command.to_owned() })
                } else {
                    Ok(ExternalEnvSource::File(PathBuf::from(source.file)))
                }
            }
        })
        .collect()
}
