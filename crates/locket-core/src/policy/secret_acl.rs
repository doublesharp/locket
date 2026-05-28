//! Secret-level access rules from `[secrets.<NAME>]`.

use std::path::{Component, Path};

use serde::Deserialize;

use crate::SecretName;

use super::error::PolicyParseError;

/// Access rules attached to one secret name.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SecretAccessPolicy {
    /// Secret name derived from the TOML table key.
    pub name: SecretName,
    /// Command identity globs, such as `dev` or `npm:*`.
    pub allow_commands: Vec<String>,
    /// Structured argv token patterns. `*` matches within one token and `**`
    /// matches the remaining argv tokens.
    pub allow_argv: Vec<Vec<String>>,
    /// Project-relative path patterns where the secret may be delivered.
    pub allow_paths: Vec<String>,
}

impl SecretAccessPolicy {
    pub(super) fn from_toml_value(
        name: &str,
        value: toml::Value,
    ) -> Result<Self, PolicyParseError> {
        let Some(_) = value.as_table() else {
            return Err(PolicyParseError::SecretAclMustBeTable { secret: name.to_owned() });
        };
        let secret_name = SecretName::new(name.to_owned())
            .map_err(|_| PolicyParseError::InvalidSecretAclName { secret: name.to_owned() })?;
        let raw = value.try_into::<RawSecretAccessPolicy>().map_err(|source| {
            PolicyParseError::SecretAclSchema {
                secret: name.to_owned(),
                message: source.to_string(),
            }
        })?;

        let allow_commands = validate_command_globs(name, raw.allow_commands.unwrap_or_default())?;
        let allow_argv = validate_argv_patterns(name, raw.allow_argv.unwrap_or_default())?;
        let allow_paths = validate_path_patterns(name, raw.allow_paths.unwrap_or_default())?;
        if allow_commands.is_empty() && allow_argv.is_empty() && allow_paths.is_empty() {
            return Err(PolicyParseError::EmptySecretAcl { secret: name.to_owned() });
        }

        Ok(Self { name: secret_name, allow_commands, allow_argv, allow_paths })
    }

    /// Returns true when this ACL permits delivery for the command identity,
    /// argv form, and current project-relative directory.
    #[must_use]
    pub fn allows(&self, command_name: &str, argv: Option<&[String]>, relative_cwd: &Path) -> bool {
        (self.allow_commands.is_empty()
            || self.allow_commands.iter().any(|pattern| glob_matches(pattern, command_name)))
            && (self.allow_argv.is_empty()
                || argv.is_some_and(|argv| {
                    self.allow_argv.iter().any(|pattern| argv_pattern_matches(pattern, argv))
                }))
            && (self.allow_paths.is_empty()
                || self
                    .allow_paths
                    .iter()
                    .any(|pattern| path_pattern_matches(pattern, relative_cwd)))
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_field_names)]
struct RawSecretAccessPolicy {
    allow_commands: Option<Vec<String>>,
    allow_argv: Option<Vec<Vec<String>>>,
    allow_paths: Option<Vec<String>>,
}

fn validate_command_globs(
    secret: &str,
    values: Vec<String>,
) -> Result<Vec<String>, PolicyParseError> {
    let mut parsed = Vec::with_capacity(values.len());
    for value in values {
        if value.trim().is_empty() {
            return Err(PolicyParseError::InvalidSecretAclPattern {
                secret: secret.to_owned(),
                field: "allow_commands",
                pattern: value,
            });
        }
        parsed.push(value);
    }
    Ok(parsed)
}

fn validate_argv_patterns(
    secret: &str,
    values: Vec<Vec<String>>,
) -> Result<Vec<Vec<String>>, PolicyParseError> {
    let mut parsed = Vec::with_capacity(values.len());
    for pattern in values {
        if pattern.is_empty() || pattern.iter().any(String::is_empty) {
            return Err(PolicyParseError::InvalidSecretAclPattern {
                secret: secret.to_owned(),
                field: "allow_argv",
                pattern: format!("{pattern:?}"),
            });
        }
        parsed.push(pattern);
    }
    Ok(parsed)
}

fn validate_path_patterns(
    secret: &str,
    values: Vec<String>,
) -> Result<Vec<String>, PolicyParseError> {
    let mut parsed = Vec::with_capacity(values.len());
    for value in values {
        if value.trim().is_empty() {
            return Err(PolicyParseError::InvalidSecretAclPattern {
                secret: secret.to_owned(),
                field: "allow_paths",
                pattern: value,
            });
        }
        validate_relative_path_pattern(secret, &value)?;
        parsed.push(value);
    }
    Ok(parsed)
}

fn validate_relative_path_pattern(secret: &str, pattern: &str) -> Result<(), PolicyParseError> {
    if pattern == "." {
        return Ok(());
    }
    let wildcard_free = pattern.replace('*', "x");
    let raw = Path::new(&wildcard_free);
    if raw.is_absolute() {
        return Err(PolicyParseError::InvalidSecretAclPattern {
            secret: secret.to_owned(),
            field: "allow_paths",
            pattern: pattern.to_owned(),
        });
    }
    for component in raw.components() {
        match component {
            Component::CurDir | Component::Normal(_) => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(PolicyParseError::InvalidSecretAclPattern {
                    secret: secret.to_owned(),
                    field: "allow_paths",
                    pattern: pattern.to_owned(),
                });
            }
        }
    }
    Ok(())
}

fn argv_pattern_matches(pattern: &[String], argv: &[String]) -> bool {
    argv_pattern_matches_from(pattern, argv)
}

fn argv_pattern_matches_from(pattern: &[String], argv: &[String]) -> bool {
    match (pattern.split_first(), argv.split_first()) {
        (None, None) => true,
        (Some((head, rest)), _) if head == "**" => {
            rest.is_empty()
                || (0..=argv.len()).any(|offset| argv_pattern_matches_from(rest, &argv[offset..]))
        }
        (Some((head, rest)), Some((arg, argv_rest))) => {
            glob_matches(head, arg) && argv_pattern_matches_from(rest, argv_rest)
        }
        (None, Some(_)) | (Some(_), None) => false,
    }
}

fn path_pattern_matches(pattern: &str, relative_cwd: &Path) -> bool {
    if pattern == "." {
        return true;
    }
    let relative = slash_path(relative_cwd);
    if let Some(base) = pattern.strip_suffix("/**") {
        return relative == base || relative.starts_with(&format!("{base}/"));
    }
    if pattern.contains('*') {
        return glob_matches(pattern, &relative);
    }
    relative == pattern || relative.starts_with(&format!("{pattern}/"))
}

fn slash_path(path: &Path) -> String {
    let normalized = path
        .components()
        .filter_map(|component| match component {
            Component::Normal(part) => Some(part.to_string_lossy().into_owned()),
            Component::CurDir
            | Component::ParentDir
            | Component::RootDir
            | Component::Prefix(_) => None,
        })
        .collect::<Vec<_>>()
        .join("/");
    if normalized.is_empty() { ".".to_owned() } else { normalized }
}

fn glob_matches(pattern: &str, value: &str) -> bool {
    let pattern = pattern.as_bytes();
    let value = value.as_bytes();
    let (mut pattern_index, mut value_index) = (0, 0);
    let (mut star_index, mut star_match_index) = (None, 0);

    while value_index < value.len() {
        if pattern_index < pattern.len() && pattern[pattern_index] == value[value_index] {
            pattern_index += 1;
            value_index += 1;
        } else if pattern_index < pattern.len() && pattern[pattern_index] == b'*' {
            star_index = Some(pattern_index);
            star_match_index = value_index;
            pattern_index += 1;
        } else if let Some(star) = star_index {
            pattern_index = star + 1;
            star_match_index += 1;
            value_index = star_match_index;
        } else {
            return false;
        }
    }

    while pattern_index < pattern.len() && pattern[pattern_index] == b'*' {
        pattern_index += 1;
    }
    pattern_index == pattern.len()
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{argv_pattern_matches, glob_matches, path_pattern_matches};

    #[test]
    fn token_glob_matches_within_one_value() {
        assert!(glob_matches("npm:*", "npm:dev"));
        assert!(glob_matches("release:*", "release:prod"));
        assert!(!glob_matches("npm:*", "cargo:test"));
    }

    #[test]
    fn argv_patterns_support_token_and_tail_globs() {
        assert!(argv_pattern_matches(
            &["npm".to_owned(), "run".to_owned(), "release:*".to_owned()],
            &["npm".to_owned(), "run".to_owned(), "release:prod".to_owned()],
        ));
        assert!(argv_pattern_matches(
            &["cargo".to_owned(), "test".to_owned(), "**".to_owned()],
            &["cargo".to_owned(), "test".to_owned(), "-p".to_owned(), "locket-cli".to_owned()],
        ));
        assert!(!argv_pattern_matches(
            &["cargo".to_owned(), "test".to_owned()],
            &["cargo".to_owned(), "test".to_owned(), "-p".to_owned(), "locket-cli".to_owned()],
        ));
    }

    #[test]
    fn path_patterns_match_project_subtrees() {
        assert!(path_pattern_matches("apps/api/**", Path::new("apps/api/src")));
        assert!(path_pattern_matches("apps/api", Path::new("apps/api/src")));
        assert!(path_pattern_matches(".", Path::new("apps/api/src")));
        assert!(!path_pattern_matches("apps/web/**", Path::new("apps/api/src")));
    }
}
