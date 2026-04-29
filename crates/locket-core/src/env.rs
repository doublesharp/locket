//! Environment merge semantics for child process injection.

use std::collections::BTreeMap;
use std::fmt::{self, Display};
use std::str::FromStr;

use thiserror::Error;

/// Deterministic environment map.
pub type EnvMap = BTreeMap<String, String>;

/// Policy for constructing the base child environment before Locket secrets are applied.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum EnvMode {
    /// Start empty and inherit only explicitly listed parent variables.
    Strict,
    /// Inherit safe allowlist variables plus explicitly listed parent variables.
    Minimal,
    /// Inherit the full parent environment.
    Merge,
    /// Inherit the full parent environment and rely on explicit reference resolution.
    Passthrough,
}

impl EnvMode {
    /// Returns the canonical policy TOML value for this mode.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Strict => "strict",
            Self::Minimal => "minimal",
            Self::Merge => "merge",
            Self::Passthrough => "passthrough",
        }
    }
}

impl Display for EnvMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for EnvMode {
    type Err = InvalidEnvMode;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "strict" => Ok(Self::Strict),
            "minimal" => Ok(Self::Minimal),
            "merge" => Ok(Self::Merge),
            "passthrough" => Ok(Self::Passthrough),
            _ => Err(InvalidEnvMode),
        }
    }
}

/// Error returned when an environment mode string is invalid.
#[derive(Debug, Clone, Copy, Eq, Error, PartialEq)]
#[error("invalid environment mode")]
pub struct InvalidEnvMode;

/// Conflict policy when a Locket secret name already exists in the child environment.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum EnvOverrideMode {
    /// Locket values override existing child values for the process only.
    Locket,
    /// Existing child values are preserved.
    Preserve,
    /// Conflicts fail before process spawn.
    Error,
}

impl EnvOverrideMode {
    /// Returns the canonical policy TOML value for this override behavior.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Locket => "locket",
            Self::Preserve => "preserve",
            Self::Error => "error",
        }
    }
}

impl Display for EnvOverrideMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for EnvOverrideMode {
    type Err = InvalidEnvOverrideMode;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "locket" => Ok(Self::Locket),
            "preserve" => Ok(Self::Preserve),
            "error" => Ok(Self::Error),
            _ => Err(InvalidEnvOverrideMode),
        }
    }
}

/// Error returned when an environment override string is invalid.
#[derive(Debug, Clone, Copy, Eq, Error, PartialEq)]
#[error("invalid environment override mode")]
pub struct InvalidEnvOverrideMode;

/// Error returned when environment construction fails.
#[derive(Debug, Clone, Eq, Error, PartialEq)]
pub enum EnvMergeError {
    /// A Locket secret conflicts with an existing environment variable.
    #[error("environment variable conflict: {name}")]
    Conflict {
        /// Conflicting variable name.
        name: String,
    },
}

/// Builds the child environment for process execution.
///
/// The merge order is:
///
/// 1. Base environment from [`EnvMode`].
/// 2. Explicit inherited variables from the parent.
/// 3. External environment sources declared in policy.
/// 4. Authorized Locket secrets according to [`EnvOverrideMode`].
///
/// # Errors
///
/// Returns [`EnvMergeError::Conflict`] when `override_mode` is
/// [`EnvOverrideMode::Error`] and a Locket secret name already exists.
pub fn merge_environment(
    parent: &EnvMap,
    safe_allowlist: &[&str],
    inherit_env: &[&str],
    external: &EnvMap,
    locket: &EnvMap,
    mode: EnvMode,
    override_mode: EnvOverrideMode,
) -> Result<EnvMap, EnvMergeError> {
    let mut child = match mode {
        EnvMode::Strict => EnvMap::new(),
        EnvMode::Minimal => select_names(parent, safe_allowlist),
        EnvMode::Merge | EnvMode::Passthrough => parent.clone(),
    };

    child.extend(select_names(parent, inherit_env));
    child.extend(external.clone());

    for (name, value) in locket {
        match (child.contains_key(name), override_mode) {
            (true, EnvOverrideMode::Error) => {
                return Err(EnvMergeError::Conflict { name: name.clone() });
            }
            (true, EnvOverrideMode::Preserve) => {}
            (true | false, EnvOverrideMode::Locket)
            | (false, EnvOverrideMode::Preserve | EnvOverrideMode::Error) => {
                child.insert(name.clone(), value.clone());
            }
        }
    }

    Ok(child)
}

fn select_names(source: &EnvMap, names: &[&str]) -> EnvMap {
    names
        .iter()
        .filter_map(|name| source.get(*name).map(|value| ((*name).to_owned(), value.clone())))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{EnvMap, EnvMergeError, EnvMode, EnvOverrideMode, merge_environment};

    fn env(values: &[(&str, &str)]) -> EnvMap {
        values.iter().map(|(name, value)| ((*name).to_owned(), (*value).to_owned())).collect()
    }

    #[test]
    fn strict_inherits_only_explicit_names_and_locket_values() -> Result<(), EnvMergeError> {
        let merged = merge_environment(
            &env(&[("PATH", "/bin"), ("HOME", "/home/me"), ("NODE_ENV", "dev")]),
            &["PATH", "HOME"],
            &["NODE_ENV"],
            &EnvMap::new(),
            &env(&[("DATABASE_URL", "postgres://local")]),
            EnvMode::Strict,
            EnvOverrideMode::Locket,
        )?;

        assert_eq!(merged.len(), 2);
        assert_eq!(merged.get("NODE_ENV").map(String::as_str), Some("dev"));
        assert_eq!(merged.get("DATABASE_URL").map(String::as_str), Some("postgres://local"));
        Ok(())
    }

    #[test]
    fn minimal_inherits_safe_allowlist() -> Result<(), EnvMergeError> {
        let merged = merge_environment(
            &env(&[("PATH", "/bin"), ("HOME", "/home/me"), ("SECRET", "parent")]),
            &["PATH", "HOME"],
            &[],
            &EnvMap::new(),
            &EnvMap::new(),
            EnvMode::Minimal,
            EnvOverrideMode::Locket,
        )?;

        assert_eq!(merged.len(), 2);
        assert_eq!(merged.get("PATH").map(String::as_str), Some("/bin"));
        assert!(!merged.contains_key("SECRET"));
        Ok(())
    }

    #[test]
    fn merge_inherits_parent_environment() -> Result<(), EnvMergeError> {
        let merged = merge_environment(
            &env(&[("PATH", "/bin"), ("EXISTING", "value")]),
            &[],
            &[],
            &EnvMap::new(),
            &EnvMap::new(),
            EnvMode::Merge,
            EnvOverrideMode::Locket,
        )?;

        assert_eq!(merged.len(), 2);
        Ok(())
    }

    #[test]
    fn passthrough_inherits_parent_environment() -> Result<(), EnvMergeError> {
        let merged = merge_environment(
            &env(&[("PATH", "/bin"), ("EXISTING", "value")]),
            &[],
            &[],
            &EnvMap::new(),
            &EnvMap::new(),
            EnvMode::Passthrough,
            EnvOverrideMode::Locket,
        )?;

        assert_eq!(merged.len(), 2);
        assert_eq!(merged.get("EXISTING").map(String::as_str), Some("value"));
        Ok(())
    }

    #[test]
    fn explicit_inherit_overrides_safe_allowlist_value_before_external_sources()
    -> Result<(), EnvMergeError> {
        let merged = merge_environment(
            &env(&[("PATH", "/parent")]),
            &["PATH"],
            &["PATH"],
            &env(&[("PATH", "/external")]),
            &EnvMap::new(),
            EnvMode::Minimal,
            EnvOverrideMode::Locket,
        )?;

        assert_eq!(merged.get("PATH").map(String::as_str), Some("/external"));
        Ok(())
    }

    #[test]
    fn external_sources_apply_before_locket_values() -> Result<(), EnvMergeError> {
        let merged = merge_environment(
            &EnvMap::new(),
            &[],
            &[],
            &env(&[("DATABASE_URL", "external")]),
            &env(&[("DATABASE_URL", "locket")]),
            EnvMode::Strict,
            EnvOverrideMode::Locket,
        )?;

        assert_eq!(merged.get("DATABASE_URL").map(String::as_str), Some("locket"));
        Ok(())
    }

    #[test]
    fn preserve_keeps_existing_values() -> Result<(), EnvMergeError> {
        let merged = merge_environment(
            &env(&[("DATABASE_URL", "parent")]),
            &[],
            &[],
            &EnvMap::new(),
            &env(&[("DATABASE_URL", "locket")]),
            EnvMode::Merge,
            EnvOverrideMode::Preserve,
        )?;

        assert_eq!(merged.get("DATABASE_URL").map(String::as_str), Some("parent"));
        Ok(())
    }

    #[test]
    fn error_mode_inserts_locket_values_without_conflicts() -> Result<(), EnvMergeError> {
        let merged = merge_environment(
            &EnvMap::new(),
            &[],
            &[],
            &EnvMap::new(),
            &env(&[("DATABASE_URL", "locket")]),
            EnvMode::Strict,
            EnvOverrideMode::Error,
        )?;

        assert_eq!(merged.get("DATABASE_URL").map(String::as_str), Some("locket"));
        Ok(())
    }

    #[test]
    fn error_rejects_conflicts_before_spawn() {
        let merged = merge_environment(
            &env(&[("DATABASE_URL", "parent")]),
            &[],
            &[],
            &EnvMap::new(),
            &env(&[("DATABASE_URL", "locket")]),
            EnvMode::Merge,
            EnvOverrideMode::Error,
        );

        assert!(matches!(
            merged,
            Err(EnvMergeError::Conflict { name }) if name == "DATABASE_URL"
        ));
    }

    #[test]
    fn environment_modes_parse_and_display_canonical_values() {
        for (value, mode) in [
            ("strict", EnvMode::Strict),
            ("minimal", EnvMode::Minimal),
            ("merge", EnvMode::Merge),
            ("passthrough", EnvMode::Passthrough),
        ] {
            assert_eq!(value.parse::<EnvMode>(), Ok(mode));
            assert_eq!(mode.to_string(), value);
        }

        assert!("Strict".parse::<EnvMode>().is_err());
    }

    #[test]
    fn override_modes_parse_and_display_canonical_values() {
        for (value, mode) in [
            ("locket", EnvOverrideMode::Locket),
            ("preserve", EnvOverrideMode::Preserve),
            ("error", EnvOverrideMode::Error),
        ] {
            assert_eq!(value.parse::<EnvOverrideMode>(), Ok(mode));
            assert_eq!(mode.to_string(), value);
        }

        assert!("override".parse::<EnvOverrideMode>().is_err());
    }
}
