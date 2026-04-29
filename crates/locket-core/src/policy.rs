//! Command policy parsing and validation for `locket.toml`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::str::FromStr;

use serde::Deserialize;
use thiserror::Error;

use crate::{Duration, EnvMode, EnvOverrideMode, SecretName};

const DEFAULT_COMMAND_POLICY_TTL_SECONDS: u64 = 15 * 60;

/// Maximum command-policy grant TTL accepted by the built-in policy parser.
pub const MAX_COMMAND_POLICY_TTL_SECONDS: u64 = 8 * 60 * 60;

const COMMANDS_TABLE: &str = "commands";
const NAME_FIELD: &str = "name";
const SECRETS_FIELD: &str = "secrets";
const REQUIRED_SECRETS_FIELD: &str = "required_secrets";
const OPTIONAL_SECRETS_FIELD: &str = "optional_secrets";

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

/// A normalized command policy from `[commands.<name>]`.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CommandPolicy {
    /// Policy name derived from the TOML table key.
    pub name: String,
    /// Command form to execute.
    pub command: CommandSpec,
    /// Normalized union of required and optional secret names.
    pub allowed_secrets: Vec<SecretName>,
    /// Secret names that must be present before execution.
    pub required_secrets: Vec<SecretName>,
    /// Secret names that may be injected only when present.
    pub optional_secrets: Vec<SecretName>,
    /// Parent environment names explicitly inherited in addition to base mode.
    pub inherit_env: Vec<String>,
    /// Base child environment policy.
    pub env_mode: EnvMode,
    /// Conflict behavior for Locket secret names; TOML field name is `override`.
    pub override_behavior: EnvOverrideMode,
    /// External environment source descriptors.
    pub external_env_sources: Vec<ExternalEnvSource>,
    /// Whether Docker/Compose helpers may deliver secrets to remote contexts.
    pub allow_remote_docker: bool,
    /// Whether execution requires typed confirmation of the policy name.
    pub confirm: bool,
    /// Whether execution requires local user verification.
    pub require_user_verification: bool,
    /// Live agent grant duration for this policy.
    pub ttl: Duration,
}

impl CommandPolicy {
    fn from_toml_value(name: &str, value: toml::Value) -> Result<Self, PolicyParseError> {
        if name.is_empty() {
            return Err(PolicyParseError::EmptyCommandName);
        }
        let Some(table) = value.as_table() else {
            return Err(PolicyParseError::CommandMustBeTable { command: name.to_owned() });
        };
        if table.contains_key(NAME_FIELD) {
            return Err(PolicyParseError::NameFieldUnsupported { command: name.to_owned() });
        }
        if table.contains_key(SECRETS_FIELD) {
            return Err(PolicyParseError::SecretsFieldUnsupported { command: name.to_owned() });
        }

        let raw = value.try_into::<RawCommandPolicy>().map_err(|source| {
            PolicyParseError::CommandSchema {
                command: name.to_owned(),
                message: source.to_string(),
            }
        })?;

        Self::from_raw(name, raw)
    }

    fn from_raw(name: &str, raw: RawCommandPolicy) -> Result<Self, PolicyParseError> {
        let command = match (raw.argv, raw.shell) {
            (Some(argv), None) if argv.is_empty() => {
                return Err(PolicyParseError::EmptyArgv { command: name.to_owned() });
            }
            (Some(argv), None) => CommandSpec::Argv(argv),
            (None, Some(shell)) if shell.trim().is_empty() => {
                return Err(PolicyParseError::EmptyShell { command: name.to_owned() });
            }
            (None, Some(shell)) => CommandSpec::Shell(shell),
            (Some(_), Some(_)) => {
                return Err(PolicyParseError::CommandSpecConflict { command: name.to_owned() });
            }
            (None, None) => {
                return Err(PolicyParseError::MissingCommandSpec { command: name.to_owned() });
            }
        };

        let required_secrets = parse_secret_list(
            name,
            REQUIRED_SECRETS_FIELD,
            raw.required_secrets.unwrap_or_default(),
        )?;
        let optional_secrets = parse_secret_list(
            name,
            OPTIONAL_SECRETS_FIELD,
            raw.optional_secrets.unwrap_or_default(),
        )?;
        let allowed_secrets =
            normalize_allowed_secrets(name, &required_secrets, &optional_secrets)?;

        let env_mode = parse_env_mode(name, raw.env_mode)?;
        let override_behavior = parse_override_behavior(name, raw.override_behavior)?;
        let ttl = parse_ttl(name, raw.ttl)?;
        let external_env_sources =
            parse_external_env_sources(name, raw.external_env_sources.unwrap_or_default())?;

        Ok(Self {
            name: name.to_owned(),
            command,
            allowed_secrets,
            required_secrets,
            optional_secrets,
            inherit_env: raw.inherit_env.unwrap_or_default(),
            env_mode,
            override_behavior,
            external_env_sources,
            allow_remote_docker: raw.allow_remote_docker.unwrap_or(false),
            confirm: raw.confirm.unwrap_or(false),
            require_user_verification: raw.require_user_verification.unwrap_or(false),
            ttl,
        })
    }
}

/// Command representation that controls shell expansion behavior.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum CommandSpec {
    /// Structured argv execution without shell expansion.
    Argv(Vec<String>),
    /// Explicit shell execution.
    Shell(String),
}

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

/// Error returned when a command policy document is invalid.
#[derive(Debug, Clone, Eq, Error, PartialEq)]
pub enum PolicyParseError {
    /// TOML syntax or decoding failed.
    #[error("invalid policy TOML: {message}")]
    Toml {
        /// Parser error message.
        message: String,
    },
    /// The document root was not a TOML table.
    #[error("policy document root must be a table")]
    RootMustBeTable,
    /// The top-level `commands` value was not a table.
    #[error("commands must be a table")]
    CommandsMustBeTable,
    /// A command table key was empty.
    #[error("command name must not be empty")]
    EmptyCommandName,
    /// A command body was not a table.
    #[error("command {command} must be a table")]
    CommandMustBeTable {
        /// Command policy name.
        command: String,
    },
    /// The command body contained the ambiguous `name` field.
    #[error("command {command} must not contain a name field")]
    NameFieldUnsupported {
        /// Command policy name.
        command: String,
    },
    /// The command body contained the unsupported `secrets` shorthand.
    #[error("command {command} must not contain a secrets field")]
    SecretsFieldUnsupported {
        /// Command policy name.
        command: String,
    },
    /// A command body did not match the v1 schema.
    #[error("command {command} schema error: {message}")]
    CommandSchema {
        /// Command policy name.
        command: String,
        /// Deserializer error message.
        message: String,
    },
    /// Neither `argv` nor `shell` was supplied.
    #[error("command {command} must define argv or shell")]
    MissingCommandSpec {
        /// Command policy name.
        command: String,
    },
    /// Both `argv` and `shell` were supplied.
    #[error("command {command} must not define both argv and shell")]
    CommandSpecConflict {
        /// Command policy name.
        command: String,
    },
    /// `argv` was present but empty.
    #[error("command {command} argv must not be empty")]
    EmptyArgv {
        /// Command policy name.
        command: String,
    },
    /// `shell` was present but blank.
    #[error("command {command} shell must not be empty")]
    EmptyShell {
        /// Command policy name.
        command: String,
    },
    /// A secret name failed validation.
    #[error("command {command} field {field} contains invalid secret name {name}")]
    InvalidSecretName {
        /// Command policy name.
        command: String,
        /// Secret-list field name.
        field: &'static str,
        /// Invalid secret name.
        name: String,
    },
    /// A secret-list field contains the same name more than once.
    #[error("command {command} field {field} contains duplicate secret name {name}")]
    DuplicateSecretName {
        /// Command policy name.
        command: String,
        /// Secret-list field name.
        field: &'static str,
        /// Duplicate secret name.
        name: String,
    },
    /// A secret name is both required and optional.
    #[error("command {command} secret {name} cannot be both required and optional")]
    SecretRequiredAndOptional {
        /// Command policy name.
        command: String,
        /// Conflicting secret name.
        name: String,
    },
    /// `env_mode` was not a supported string.
    #[error("command {command} has invalid env_mode {value}")]
    InvalidEnvMode {
        /// Command policy name.
        command: String,
        /// Invalid mode string.
        value: String,
    },
    /// `override` was not a supported string.
    #[error("command {command} has invalid override {value}")]
    InvalidOverrideBehavior {
        /// Command policy name.
        command: String,
        /// Invalid override string.
        value: String,
    },
    /// `ttl` was not a valid duration string.
    #[error("command {command} has invalid ttl {value}")]
    InvalidTtl {
        /// Command policy name.
        command: String,
        /// Invalid duration string.
        value: String,
    },
    /// `ttl` exceeds the built-in policy cap.
    #[error("command {command} ttl {ttl_seconds}s exceeds maximum {max_seconds}s")]
    TtlExceedsMaximum {
        /// Command policy name.
        command: String,
        /// Parsed TTL seconds.
        ttl_seconds: u64,
        /// Maximum accepted TTL seconds.
        max_seconds: u64,
    },
    /// `external_env_sources` contained an unsupported string.
    #[error("command {command} has invalid external env source {value}")]
    InvalidExternalEnvSource {
        /// Command policy name.
        command: String,
        /// Invalid source string.
        value: String,
    },
    /// `external_env_sources` contained a blank file path.
    #[error("command {command} external env file path must not be empty")]
    EmptyExternalEnvFile {
        /// Command policy name.
        command: String,
    },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCommandPolicy {
    argv: Option<Vec<String>>,
    shell: Option<String>,
    required_secrets: Option<Vec<String>>,
    optional_secrets: Option<Vec<String>>,
    inherit_env: Option<Vec<String>>,
    env_mode: Option<String>,
    #[serde(rename = "override")]
    override_behavior: Option<String>,
    external_env_sources: Option<Vec<RawExternalEnvSource>>,
    allow_remote_docker: Option<bool>,
    confirm: Option<bool>,
    require_user_verification: Option<bool>,
    ttl: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum RawExternalEnvSource {
    Name(String),
    File(RawExternalEnvFileSource),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawExternalEnvFileSource {
    file: String,
}

fn parse_secret_list(
    command: &str,
    field: &'static str,
    values: Vec<String>,
) -> Result<Vec<SecretName>, PolicyParseError> {
    let mut seen = BTreeSet::new();
    let mut parsed = Vec::with_capacity(values.len());

    for value in values {
        let name =
            SecretName::new(value.clone()).map_err(|_| PolicyParseError::InvalidSecretName {
                command: command.to_owned(),
                field,
                name: value.clone(),
            })?;
        if !seen.insert(name.clone()) {
            return Err(PolicyParseError::DuplicateSecretName {
                command: command.to_owned(),
                field,
                name: name.into_string(),
            });
        }
        parsed.push(name);
    }

    Ok(parsed)
}

fn normalize_allowed_secrets(
    command: &str,
    required_secrets: &[SecretName],
    optional_secrets: &[SecretName],
) -> Result<Vec<SecretName>, PolicyParseError> {
    let required = required_secrets.iter().collect::<BTreeSet<_>>();
    for name in optional_secrets {
        if required.contains(name) {
            return Err(PolicyParseError::SecretRequiredAndOptional {
                command: command.to_owned(),
                name: name.to_string(),
            });
        }
    }

    Ok(required_secrets
        .iter()
        .chain(optional_secrets.iter())
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect())
}

fn parse_env_mode(command: &str, value: Option<String>) -> Result<EnvMode, PolicyParseError> {
    value.map_or(Ok(EnvMode::Minimal), |value| {
        value
            .parse()
            .map_err(|_| PolicyParseError::InvalidEnvMode { command: command.to_owned(), value })
    })
}

fn parse_override_behavior(
    command: &str,
    value: Option<String>,
) -> Result<EnvOverrideMode, PolicyParseError> {
    value.map_or(Ok(EnvOverrideMode::Locket), |value| {
        value.parse().map_err(|_| PolicyParseError::InvalidOverrideBehavior {
            command: command.to_owned(),
            value,
        })
    })
}

fn parse_ttl(command: &str, value: Option<String>) -> Result<Duration, PolicyParseError> {
    let ttl = match value {
        Some(value) => Duration::from_str(&value)
            .map_err(|_| PolicyParseError::InvalidTtl { command: command.to_owned(), value })?,
        None => Duration::from_secs(DEFAULT_COMMAND_POLICY_TTL_SECONDS),
    };

    if ttl.as_secs() > MAX_COMMAND_POLICY_TTL_SECONDS {
        return Err(PolicyParseError::TtlExceedsMaximum {
            command: command.to_owned(),
            ttl_seconds: ttl.as_secs(),
            max_seconds: MAX_COMMAND_POLICY_TTL_SECONDS,
        });
    }

    Ok(ttl)
}

fn parse_external_env_sources(
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

#[cfg(test)]
mod tests {
    use std::error::Error;

    use super::{
        CommandSpec, ExternalEnvSource, MAX_COMMAND_POLICY_TTL_SECONDS, PolicyDocument,
        PolicyParseError,
    };
    use crate::{EnvMode, EnvOverrideMode};

    #[test]
    fn parses_valid_argv_policy_with_defaults() -> Result<(), Box<dyn Error>> {
        let document = PolicyDocument::from_toml_str(
            r#"
schema_version = 1
name = "example"

[commands.api]
argv = ["pnpm", "dev"]
required_secrets = ["DATABASE_URL"]
optional_secrets = ["OPENAI_API_KEY"]
"#,
        )?;

        let policy = document.commands.get("api").ok_or("missing api policy")?;

        assert_eq!(policy.name, "api");
        assert_eq!(policy.command, CommandSpec::Argv(vec!["pnpm".to_owned(), "dev".to_owned()]));
        assert_eq!(
            policy.required_secrets.iter().map(ToString::to_string).collect::<Vec<_>>(),
            ["DATABASE_URL"]
        );
        assert_eq!(
            policy.optional_secrets.iter().map(ToString::to_string).collect::<Vec<_>>(),
            ["OPENAI_API_KEY"]
        );
        assert_eq!(
            policy.allowed_secrets.iter().map(ToString::to_string).collect::<Vec<_>>(),
            ["DATABASE_URL", "OPENAI_API_KEY"]
        );
        assert_eq!(policy.env_mode, EnvMode::Minimal);
        assert_eq!(policy.override_behavior, EnvOverrideMode::Locket);
        assert_eq!(policy.ttl.as_secs(), 15 * 60);
        assert!(!policy.allow_remote_docker);
        assert!(!policy.confirm);
        assert!(!policy.require_user_verification);
        Ok(())
    }

    #[test]
    fn parses_valid_shell_policy_with_explicit_options() -> Result<(), Box<dyn Error>> {
        let document = PolicyDocument::from_toml_str(
            r#"
[commands.release]
shell = "pnpm build && pnpm publish"
required_secrets = ["NPM_TOKEN"]
inherit_env = ["PATH", "HOME"]
env_mode = "strict"
override = "preserve"
external_env_sources = ["parent", "compose", "ide", { file = ".env.local" }]
confirm = true
require_user_verification = true
allow_remote_docker = true
ttl = "30m"
"#,
        )?;

        let policy = document.commands.get("release").ok_or("missing release policy")?;

        assert_eq!(policy.command, CommandSpec::Shell("pnpm build && pnpm publish".to_owned()));
        assert_eq!(policy.inherit_env, ["PATH", "HOME"]);
        assert_eq!(policy.env_mode, EnvMode::Strict);
        assert_eq!(policy.override_behavior, EnvOverrideMode::Preserve);
        assert_eq!(
            policy.external_env_sources,
            vec![
                ExternalEnvSource::Parent,
                ExternalEnvSource::Compose,
                ExternalEnvSource::Ide,
                ExternalEnvSource::File(".env.local".into()),
            ]
        );
        assert!(policy.confirm);
        assert!(policy.require_user_verification);
        assert!(policy.allow_remote_docker);
        assert_eq!(policy.ttl.as_secs(), 30 * 60);
        Ok(())
    }

    #[test]
    fn rejects_invalid_schema_cases() {
        let cases = [
            (
                r#"[commands.dev]
argv = ["pnpm"]
shell = "pnpm dev"
"#,
                PolicyParseError::CommandSpecConflict { command: "dev".to_owned() },
            ),
            (
                r#"[commands.dev]
argv = ["pnpm"]
secrets = ["DATABASE_URL"]
"#,
                PolicyParseError::SecretsFieldUnsupported { command: "dev".to_owned() },
            ),
            (
                r#"[commands.dev]
name = "other"
argv = ["pnpm"]
"#,
                PolicyParseError::NameFieldUnsupported { command: "dev".to_owned() },
            ),
            (
                r#"[commands.dev]
argv = ["pnpm"]
required_secrets = ["DATABASE_URL", "DATABASE_URL"]
"#,
                PolicyParseError::DuplicateSecretName {
                    command: "dev".to_owned(),
                    field: "required_secrets",
                    name: "DATABASE_URL".to_owned(),
                },
            ),
            (
                r#"[commands.dev]
argv = ["pnpm"]
required_secrets = ["DATABASE_URL"]
optional_secrets = ["DATABASE_URL"]
"#,
                PolicyParseError::SecretRequiredAndOptional {
                    command: "dev".to_owned(),
                    name: "DATABASE_URL".to_owned(),
                },
            ),
            (
                r#"[commands.dev]
argv = ["pnpm"]
optional_secrets = ["database_url"]
"#,
                PolicyParseError::InvalidSecretName {
                    command: "dev".to_owned(),
                    field: "optional_secrets",
                    name: "database_url".to_owned(),
                },
            ),
            (
                r"[commands.dev]
argv = []
",
                PolicyParseError::EmptyArgv { command: "dev".to_owned() },
            ),
        ];

        for (input, expected) in cases {
            assert_eq!(PolicyDocument::from_toml_str(input), Err(expected));
        }
    }

    #[test]
    fn rejects_ttl_above_builtin_policy_cap() {
        let result = PolicyDocument::from_toml_str(
            r#"[commands.dev]
argv = ["pnpm"]
ttl = "9h"
"#,
        );

        assert_eq!(
            result,
            Err(PolicyParseError::TtlExceedsMaximum {
                command: "dev".to_owned(),
                ttl_seconds: 9 * 60 * 60,
                max_seconds: MAX_COMMAND_POLICY_TTL_SECONDS,
            })
        );
    }
}
