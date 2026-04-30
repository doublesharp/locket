//! Command policy parsing and validation for `locket.toml`.

mod command;
mod document;
mod env_source;
mod error;

pub use command::{CommandPolicy, CommandSpec, MAX_COMMAND_POLICY_TTL_SECONDS};
pub use document::PolicyDocument;
pub use env_source::ExternalEnvSource;
pub use error::PolicyParseError;

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
        assert!(!policy.override_explicit());
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
        assert!(policy.override_explicit());
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
    fn deny_by_default_does_not_infer_secret_authorization_from_permissive_settings()
    -> Result<(), Box<dyn Error>> {
        let document = PolicyDocument::from_toml_str(
            r#"
[commands.dev]
argv = ["pnpm", "dev"]
inherit_env = ["DATABASE_URL", "API_KEY"]
external_env_sources = ["parent", "compose"]
env_mode = "merge"
override = "preserve"
confirm = false
require_user_verification = false
allow_remote_docker = true
"#,
        )?;

        let policy = document.commands.get("dev").ok_or("missing dev policy")?;

        assert!(policy.required_secrets.is_empty());
        assert!(policy.optional_secrets.is_empty());
        assert!(policy.allowed_secrets.is_empty());
        assert!(!policy.confirm);
        assert!(!policy.require_user_verification);
        assert!(policy.allow_remote_docker);
        Ok(())
    }

    #[test]
    fn deny_by_default_rejects_permissive_secret_authorization_variants() {
        let cases = [
            (
                r#"[commands.dev]
argv = ["pnpm"]
allowed_secrets = ["DATABASE_URL"]
"#,
                "allowed_secrets",
            ),
            (
                r#"[commands.dev]
argv = ["pnpm"]
secret = "DATABASE_URL"
"#,
                "secret",
            ),
            (
                r#"[commands.dev]
argv = ["pnpm"]
all_secrets = true
"#,
                "all_secrets",
            ),
            (
                r#"[commands.dev]
argv = ["pnpm"]
secrets = ["DATABASE_URL"]
"#,
                "secrets",
            ),
        ];

        for (input, field) in cases {
            let result = PolicyDocument::from_toml_str(input);
            assert!(result.is_err(), "permissive policy passed for field {field}");
            if let Err(error) = result {
                let message = error.to_string();
                assert!(
                    message.contains(field),
                    "error for {field} should mention rejected field, got {message:?}"
                );
            }
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

    #[test]
    fn rejects_invalid_ttl_duration_grammar() {
        for value in ["0s", "1h30m", "1.5h", "1H", " 1h", "1h "] {
            let result = PolicyDocument::from_toml_str(&format!(
                r#"[commands.dev]
argv = ["pnpm"]
ttl = "{value}"
"#
            ));

            assert_eq!(
                result,
                Err(PolicyParseError::InvalidTtl {
                    command: "dev".to_owned(),
                    value: value.to_owned(),
                })
            );
        }
    }
}
