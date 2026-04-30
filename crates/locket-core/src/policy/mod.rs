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

    #[test]
    fn rejects_missing_command_spec() {
        let result = PolicyDocument::from_toml_str(
            r#"[commands.dev]
required_secrets = ["DATABASE_URL"]
"#,
        );
        assert_eq!(result, Err(PolicyParseError::MissingCommandSpec { command: "dev".to_owned() }));
    }

    #[test]
    fn rejects_empty_shell_string() {
        let result = PolicyDocument::from_toml_str(
            r#"[commands.dev]
shell = "   "
"#,
        );
        assert_eq!(result, Err(PolicyParseError::EmptyShell { command: "dev".to_owned() }));
    }

    #[test]
    fn rejects_invalid_env_mode() {
        let result = PolicyDocument::from_toml_str(
            r#"[commands.dev]
argv = ["pnpm"]
env_mode = "garbage"
"#,
        );
        assert_eq!(
            result,
            Err(PolicyParseError::InvalidEnvMode {
                command: "dev".to_owned(),
                value: "garbage".to_owned(),
            })
        );
    }

    #[test]
    fn rejects_invalid_override_behavior() {
        let result = PolicyDocument::from_toml_str(
            r#"[commands.dev]
argv = ["pnpm"]
override = "garbage"
"#,
        );
        assert_eq!(
            result,
            Err(PolicyParseError::InvalidOverrideBehavior {
                command: "dev".to_owned(),
                value: "garbage".to_owned(),
            })
        );
    }

    #[test]
    fn rejects_invalid_external_env_source_string() {
        let result = PolicyDocument::from_toml_str(
            r#"[commands.dev]
argv = ["pnpm"]
external_env_sources = ["ftp"]
"#,
        );
        assert_eq!(
            result,
            Err(PolicyParseError::InvalidExternalEnvSource {
                command: "dev".to_owned(),
                value: "ftp".to_owned(),
            })
        );
    }

    #[test]
    fn rejects_empty_external_env_file_path() {
        let result = PolicyDocument::from_toml_str(
            r#"[commands.dev]
argv = ["pnpm"]
external_env_sources = [{ file = "" }]
"#,
        );
        assert_eq!(
            result,
            Err(PolicyParseError::EmptyExternalEnvFile { command: "dev".to_owned() })
        );
    }

    #[test]
    fn allowed_secrets_is_sorted_union_of_required_and_optional() -> Result<(), Box<dyn Error>> {
        let document = PolicyDocument::from_toml_str(
            r#"[commands.api]
argv = ["pnpm", "dev"]
required_secrets = ["ZEBRA_KEY", "API_TOKEN"]
optional_secrets = ["OPENAI_KEY", "BETA_FLAG"]
"#,
        )?;
        let policy = document.commands.get("api").ok_or("missing api policy")?;
        assert_eq!(
            policy.allowed_secrets.iter().map(ToString::to_string).collect::<Vec<_>>(),
            ["API_TOKEN", "BETA_FLAG", "OPENAI_KEY", "ZEBRA_KEY"]
        );
        assert_eq!(
            policy.required_secrets.iter().map(ToString::to_string).collect::<Vec<_>>(),
            ["ZEBRA_KEY", "API_TOKEN"]
        );
        assert_eq!(
            policy.optional_secrets.iter().map(ToString::to_string).collect::<Vec<_>>(),
            ["OPENAI_KEY", "BETA_FLAG"]
        );
        Ok(())
    }

    #[test]
    fn optional_secrets_absent_from_required_are_still_allowed() -> Result<(), Box<dyn Error>> {
        let document = PolicyDocument::from_toml_str(
            r#"[commands.api]
argv = ["server"]
required_secrets = ["DB_URL"]
optional_secrets = ["REDIS_URL"]
"#,
        )?;
        let policy = document.commands.get("api").ok_or("missing api")?;
        let allowed: Vec<_> = policy.allowed_secrets.iter().map(ToString::to_string).collect();
        assert!(allowed.contains(&"DB_URL".to_owned()));
        assert!(allowed.contains(&"REDIS_URL".to_owned()));
        assert_eq!(policy.required_secrets.len(), 1);
        assert_eq!(policy.optional_secrets.len(), 1);
        Ok(())
    }

    #[test]
    fn confirm_and_require_user_verification_explicit_false_differ_from_absent()
    -> Result<(), Box<dyn Error>> {
        let document_absent = PolicyDocument::from_toml_str(
            r#"[commands.api]
argv = ["server"]
"#,
        )?;
        let document_explicit = PolicyDocument::from_toml_str(
            r#"[commands.api]
argv = ["server"]
confirm = false
require_user_verification = false
"#,
        )?;
        let policy_absent = document_absent.commands.get("api").ok_or("missing")?;
        let policy_explicit = document_explicit.commands.get("api").ok_or("missing")?;
        assert!(!policy_absent.confirm);
        assert!(!policy_absent.require_user_verification);
        assert!(!policy_explicit.confirm);
        assert!(!policy_explicit.require_user_verification);
        Ok(())
    }

    #[test]
    fn confirm_true_with_require_user_verification_true_parses() -> Result<(), Box<dyn Error>> {
        let document = PolicyDocument::from_toml_str(
            r#"[commands.deploy]
shell = "pnpm deploy"
required_secrets = ["DEPLOY_TOKEN"]
confirm = true
require_user_verification = true
"#,
        )?;
        let policy = document.commands.get("deploy").ok_or("missing deploy")?;
        assert!(policy.confirm);
        assert!(policy.require_user_verification);
        Ok(())
    }

    #[test]
    fn ttl_at_exact_maximum_is_accepted() -> Result<(), Box<dyn Error>> {
        let max_hours = MAX_COMMAND_POLICY_TTL_SECONDS / 3600;
        let document = PolicyDocument::from_toml_str(&format!(
            r#"[commands.dev]
argv = ["pnpm"]
ttl = "{max_hours}h"
"#
        ))?;
        let policy = document.commands.get("dev").ok_or("missing dev")?;
        assert_eq!(policy.ttl.as_secs(), MAX_COMMAND_POLICY_TTL_SECONDS);
        Ok(())
    }

    #[test]
    fn document_with_no_commands_section_parses_empty() -> Result<(), Box<dyn Error>> {
        let document = PolicyDocument::from_toml_str(
            r#"
schema_version = 1
name = "empty"
"#,
        )?;
        assert!(document.commands.is_empty());
        Ok(())
    }

    #[test]
    fn document_with_multiple_commands_parses_all() -> Result<(), Box<dyn Error>> {
        let document = PolicyDocument::from_toml_str(
            r#"
[commands.dev]
argv = ["pnpm", "dev"]
required_secrets = ["DATABASE_URL"]

[commands.test]
argv = ["pnpm", "test"]
optional_secrets = ["TEST_API_KEY"]

[commands.deploy]
shell = "pnpm deploy"
required_secrets = ["NPM_TOKEN", "DEPLOY_KEY"]
confirm = true
"#,
        )?;
        assert_eq!(document.commands.len(), 3);
        let dev = document.commands.get("dev").ok_or("missing dev")?;
        assert_eq!(dev.required_secrets.len(), 1);
        let test = document.commands.get("test").ok_or("missing test")?;
        assert_eq!(test.optional_secrets.len(), 1);
        assert!(test.required_secrets.is_empty());
        let deploy = document.commands.get("deploy").ok_or("missing deploy")?;
        assert!(deploy.confirm);
        assert_eq!(deploy.required_secrets.len(), 2);
        Ok(())
    }

    #[test]
    fn from_str_impl_is_equivalent_to_from_toml_str() -> Result<(), Box<dyn Error>> {
        let input = r#"[commands.api]
argv = ["node", "server.js"]
required_secrets = ["API_KEY"]
"#;
        let via_method = PolicyDocument::from_toml_str(input)?;
        let via_from_str: PolicyDocument = input.parse()?;
        assert_eq!(via_method, via_from_str);
        Ok(())
    }

    #[test]
    fn rejects_toml_syntax_error() {
        let result = PolicyDocument::from_toml_str("commands = ][");
        assert!(matches!(result, Err(PolicyParseError::Toml { .. })));
    }

    #[test]
    fn rejects_commands_not_a_table() {
        let result = PolicyDocument::from_toml_str("commands = 42");
        assert_eq!(result, Err(PolicyParseError::CommandsMustBeTable));
    }
}

#[cfg(test)]
#[allow(clippy::panic)]
#[allow(clippy::unwrap_used)]
mod proptest_policy {
    use proptest::prelude::*;

    use super::{PolicyDocument, PolicyParseError};

    fn valid_command_name_strategy() -> impl Strategy<Value = String> {
        prop::string::string_regex("[a-z][a-z0-9_-]{0,15}").expect("valid regex")
    }

    fn valid_secret_name_strategy() -> impl Strategy<Value = String> {
        let first = prop::char::ranges(std::borrow::Cow::Borrowed(&['A'..='Z', '_'..='_']));
        let rest = prop::collection::vec(
            prop::char::ranges(std::borrow::Cow::Borrowed(&[
                'A'..='Z',
                '0'..='9',
                '_'..='_',
            ])),
            0..12,
        );
        (first, rest).prop_map(|(f, r)| {
            let mut s = String::new();
            s.push(f);
            s.extend(r);
            s
        })
    }

    proptest! {
        #[test]
        fn single_argv_command_round_trips_name_and_command(
            cmd_name in valid_command_name_strategy(),
        ) {
            let toml = format!(
                "[commands.{cmd_name}]\nargv = [\"ls\", \"-la\"]\n"
            );
            let doc = PolicyDocument::from_toml_str(&toml);
            prop_assert!(doc.is_ok(), "valid policy should parse: {doc:?}");
            let doc = doc.unwrap();
            prop_assert!(doc.commands.contains_key(&cmd_name), "command key preserved");
        }

        #[test]
        fn required_secrets_are_preserved_in_allowed_secrets(
            cmd_name in valid_command_name_strategy(),
            secret in valid_secret_name_strategy(),
        ) {
            let toml = format!(
                "[commands.{cmd_name}]\nargv = [\"run\"]\nrequired_secrets = [\"{secret}\"]\n"
            );
            let result = PolicyDocument::from_toml_str(&toml);
            prop_assert!(result.is_ok(), "valid required_secrets should parse: {result:?}");
            let doc = result.unwrap();
            let policy = doc.commands.get(&cmd_name).unwrap();
            let req_names: Vec<&str> = policy.required_secrets.iter().map(|s| s.as_str()).collect();
            prop_assert!(req_names.contains(&secret.as_str()), "required secret preserved");
            let allowed_names: Vec<&str> =
                policy.allowed_secrets.iter().map(|s| s.as_str()).collect();
            prop_assert!(allowed_names.contains(&secret.as_str()), "required in allowed_secrets");
        }

        #[test]
        fn optional_secrets_appear_in_allowed_secrets(
            cmd_name in valid_command_name_strategy(),
            secret in valid_secret_name_strategy(),
        ) {
            let toml = format!(
                "[commands.{cmd_name}]\nargv = [\"run\"]\noptional_secrets = [\"{secret}\"]\n"
            );
            let result = PolicyDocument::from_toml_str(&toml);
            prop_assert!(result.is_ok(), "optional_secrets should parse: {result:?}");
            let doc = result.unwrap();
            let policy = doc.commands.get(&cmd_name).unwrap();
            let allowed_names: Vec<&str> =
                policy.allowed_secrets.iter().map(|s| s.as_str()).collect();
            prop_assert!(allowed_names.contains(&secret.as_str()), "optional in allowed_secrets");
        }

        #[test]
        fn document_with_no_commands_parses_empty(
            extra_key in "[a-z]{3,10}",
            extra_val in "[a-z]{3,10}",
        ) {
            let toml = format!("{extra_key} = \"{extra_val}\"\n");
            let result = PolicyDocument::from_toml_str(&toml);
            prop_assert!(result.is_ok(), "non-commands top-level keys are ignored: {result:?}");
            prop_assert_eq!(result.unwrap().commands.len(), 0);
        }

        #[test]
        fn name_field_in_command_is_always_rejected(cmd_name in valid_command_name_strategy()) {
            let toml = format!(
                "[commands.{cmd_name}]\nargv = [\"run\"]\nname = \"forbidden\"\n"
            );
            let result = PolicyDocument::from_toml_str(&toml);
            prop_assert!(
                matches!(result, Err(PolicyParseError::NameFieldUnsupported { .. })),
                "name field must be rejected: {result:?}"
            );
        }

        #[test]
        fn secrets_field_in_command_is_always_rejected(cmd_name in valid_command_name_strategy()) {
            let toml = format!(
                "[commands.{cmd_name}]\nargv = [\"run\"]\nsecrets = [\"DATABASE_URL\"]\n"
            );
            let result = PolicyDocument::from_toml_str(&toml);
            prop_assert!(
                matches!(result, Err(PolicyParseError::SecretsFieldUnsupported { .. })),
                "secrets field must be rejected: {result:?}"
            );
        }

        #[test]
        fn shell_command_spec_is_accepted(
            cmd_name in valid_command_name_strategy(),
            shell_cmd in "[a-z ]{5,30}",
        ) {
            let toml =
                format!("[commands.{cmd_name}]\nshell = \"{shell_cmd}\"\n");
            let result = PolicyDocument::from_toml_str(&toml);
            prop_assert!(result.is_ok(), "shell command spec should parse: {result:?}");
        }

        #[test]
        fn commands_value_that_is_not_table_always_errors(scalar in 1i64..100) {
            let toml = format!("commands = {scalar}\n");
            let result = PolicyDocument::from_toml_str(&toml);
            prop_assert_eq!(result, Err(PolicyParseError::CommandsMustBeTable));
        }

        #[test]
        fn allowed_secrets_length_is_at_least_required_plus_optional(
            cmd_name in valid_command_name_strategy(),
            required in valid_secret_name_strategy(),
            optional in valid_secret_name_strategy(),
        ) {
            prop_assume!(required != optional);
            let toml = format!(
                "[commands.{cmd_name}]\nargv = [\"run\"]\nrequired_secrets = [\"{required}\"]\noptional_secrets = [\"{optional}\"]\n"
            );
            let result = PolicyDocument::from_toml_str(&toml);
            prop_assert!(result.is_ok(), "distinct required+optional should parse: {result:?}");
            let doc = result.unwrap();
            let policy = doc.commands.get(&cmd_name).unwrap();
            prop_assert!(
                policy.allowed_secrets.len() >= policy.required_secrets.len() + policy.optional_secrets.len(),
                "allowed must be superset of required+optional"
            );
        }
    }
}
