//! Top-level `[commands]` document parser.

use std::collections::BTreeMap;
use std::str::FromStr;

use super::command::CommandPolicy;
use super::error::PolicyParseError;

const COMMANDS_TABLE: &str = "commands";

/// Parsed command policies from a `locket.toml` document.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PolicyDocument {
    /// Command policies keyed by `[commands.<name>]`.
    pub commands: BTreeMap<String, CommandPolicy>,
}

impl PolicyDocument {
    /// Parses command policies from a TOML document.
    ///
    /// Top-level keys outside `[commands]` are ignored so this can parse a full
    /// project `locket.toml`. Each command body is validated strictly.
    ///
    /// Duplicate `[commands.<name>]` headers are rejected by the underlying
    /// TOML parser before this function ever sees the parsed value, so the
    /// `BTreeMap::insert` below cannot silently overwrite a prior entry.
    /// `rejects_duplicate_command_table_at_toml_layer` in `policy::tests`
    /// pins this behavior so future TOML-crate upgrades cannot quietly relax
    /// it without surfacing a test failure.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyParseError`] for invalid TOML, malformed command tables,
    /// unsupported fields, or invalid normalized policy values.
    pub fn from_toml_str(input: &str) -> Result<Self, PolicyParseError> {
        let value = toml::from_str::<toml::Value>(input)
            .map_err(|source| PolicyParseError::Toml { message: source.to_string() })?;
        Self::from_toml_value(&value)
    }

    fn from_toml_value(value: &toml::Value) -> Result<Self, PolicyParseError> {
        let Some(root) = value.as_table() else {
            return Err(PolicyParseError::RootMustBeTable);
        };
        let Some(commands) = root.get(COMMANDS_TABLE) else {
            return Ok(Self { commands: BTreeMap::new() });
        };
        let Some(commands) = commands.as_table() else {
            return Err(PolicyParseError::CommandsMustBeTable);
        };

        let mut parsed = BTreeMap::new();
        for (name, body) in commands {
            let policy = CommandPolicy::from_toml_value(name, body.clone())?;
            parsed.insert(name.clone(), policy);
        }

        Ok(Self { commands: parsed })
    }
}

impl FromStr for PolicyDocument {
    type Err = PolicyParseError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::from_toml_str(input)
    }
}
