//! Top-level `[commands]` document parser.

use std::collections::BTreeMap;
use std::str::FromStr;

use super::command::CommandPolicy;
use super::error::PolicyParseError;

const COMMANDS_TABLE: &str = "commands";
const SCHEMA_VERSION_FIELD: &str = "schema_version";

/// Currently supported `locket.toml` policy document schema version.
pub const SUPPORTED_POLICY_SCHEMA_VERSION: u64 = 1;

/// Top-level keys recognized at the root of a `locket.toml` document.
///
/// The list mirrors the v1 schema: `schema_version` and `commands` come from this
/// crate; `project_id`, `name`, and `default_profile` are project metadata in
/// [`crate::ProjectConfig`]; `bootstrap`, `scan`, and `example` are CLI-side
/// configuration tables. Any other root-level key fails parsing with
/// [`PolicyParseError::UnknownTopLevelKey`].
const ALLOWED_ROOT_KEYS: &[&str] = &[
    SCHEMA_VERSION_FIELD,
    COMMANDS_TABLE,
    "project_id",
    "name",
    "default_profile",
    "bootstrap",
    "scan",
    "example",
];

/// Parsed command policies from a `locket.toml` document.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PolicyDocument {
    /// Schema version declared at the document root.
    pub schema_version: u64,
    /// Command policies keyed by `[commands.<name>]`.
    pub commands: BTreeMap<String, CommandPolicy>,
}

impl PolicyDocument {
    /// Parses command policies from a TOML document.
    ///
    /// The document must declare `schema_version = 1` at the root. Top-level keys
    /// outside the v1 schema fail parsing with [`PolicyParseError::UnknownTopLevelKey`]
    /// so future fields cannot silently downgrade existing tooling. Each command
    /// body is validated strictly.
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
    /// Returns [`PolicyParseError`] for invalid TOML, missing or unsupported
    /// `schema_version`, unknown top-level keys, malformed command tables,
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

        let schema_version = require_schema_version(root)?;

        for key in root.keys() {
            if !ALLOWED_ROOT_KEYS.iter().any(|allowed| allowed == key) {
                return Err(PolicyParseError::UnknownTopLevelKey { key: key.clone() });
            }
        }

        let Some(commands) = root.get(COMMANDS_TABLE) else {
            return Ok(Self { schema_version, commands: BTreeMap::new() });
        };
        let Some(commands) = commands.as_table() else {
            return Err(PolicyParseError::CommandsMustBeTable);
        };

        let mut parsed = BTreeMap::new();
        for (name, body) in commands {
            let policy = CommandPolicy::from_toml_value(name, body.clone())?;
            parsed.insert(name.clone(), policy);
        }

        Ok(Self { schema_version, commands: parsed })
    }
}

fn require_schema_version(root: &toml::value::Table) -> Result<u64, PolicyParseError> {
    let Some(value) = root.get(SCHEMA_VERSION_FIELD) else {
        return Err(PolicyParseError::MissingSchemaVersion);
    };
    let Some(version) = value.as_integer() else {
        return Err(PolicyParseError::InvalidSchemaVersion);
    };
    if version <= 0 {
        return Err(PolicyParseError::InvalidSchemaVersion);
    }
    let version = u64::try_from(version).map_err(|_| PolicyParseError::InvalidSchemaVersion)?;
    if version != SUPPORTED_POLICY_SCHEMA_VERSION {
        return Err(PolicyParseError::UnsupportedSchemaVersion { version });
    }
    Ok(version)
}

impl FromStr for PolicyDocument {
    type Err = PolicyParseError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::from_toml_str(input)
    }
}
