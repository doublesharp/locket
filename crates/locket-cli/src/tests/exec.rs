#[allow(unused_imports)]
use super::*;

#[test]
fn exec_all_force_injects_active_profile_secrets_and_writes_audit()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    let db = test_secret_write_args("DATABASE_URL");
    crate::set_secret_value(&context, &db, "postgres://localhost/app", "manual", 1_000)?;
    let api = test_secret_write_args("API_KEY");
    crate::set_secret_value(&context, &api, "tok-v1", "manual", 2_000)?;

    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "exec",
            "--all",
            "--force",
            "--",
            "/bin/sh",
            "-c",
            "test \"$DATABASE_URL\" = \"postgres://localhost/app\" \
             && test \"$API_KEY\" = \"tok-v1\"",
        ])?,
        &context,
        &mut output,
    )?;
    assert!(String::from_utf8(output)?.is_empty());

    let store = crate::open_store(&context)?;
    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'EXEC'
         ORDER BY sequence DESC LIMIT 1",
        [],
        |row| row.get(0),
    )?;
    assert!(metadata.contains("\"action\":\"EXEC\""));
    assert!(metadata.contains("\"all_mode\":true"));
    assert!(metadata.contains("\"argv_program\":\"/bin/sh\""));
    assert!(metadata.contains("\"arg_count\":3"));
    assert!(metadata.contains("\"API_KEY\""));
    assert!(metadata.contains("\"DATABASE_URL\""));
    assert!(!metadata.contains("postgres://localhost/app"));
    assert!(!metadata.contains("tok-v1"));
    Ok(())
}

#[test]
fn exec_all_requires_typed_confirmation_when_not_forced() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempdir()?;
    let key_store: Arc<dyn MasterKeyStore + Send + Sync> =
        Arc::new(MemoryMasterKeyStore::default());
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &test_context_with_key_store(&directory, Arc::clone(&key_store)),
        &mut Vec::new(),
    )?;
    let setup = test_context_with_key_store(&directory, Arc::clone(&key_store));
    let db = test_secret_write_args("DATABASE_URL");
    crate::set_secret_value(&setup, &db, "postgres://localhost/app", "manual", 1_000)?;

    let bad_context =
        test_context_with_key_store_and_confirmation(&directory, Arc::clone(&key_store), "wrong\n");
    let mut output = Vec::new();
    let result = run_with_context(
        Cli::try_parse_from(["locket", "exec", "--all", "--", "/bin/sh", "-c", "true"])?,
        &bad_context,
        &mut output,
    );
    assert_error_contains(result, "confirmation did not match exec --all scope");
    let output = String::from_utf8(output)?;
    assert!(output.contains("exec_profile: dev"));
    assert!(output.contains("exec_argv_program: /bin/sh"));
    assert!(output.contains("exec_secret_count: 1"));
    assert!(output.contains("exec_secret_names: DATABASE_URL"));
    assert!(output.contains("metadata_only: yes"));

    let good_context = test_context_with_key_store_and_confirmation(
        &directory,
        Arc::clone(&key_store),
        "exec --all dev\n",
    );
    let mut good_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "exec", "--all", "--", "/bin/sh", "-c", "true"])?,
        &good_context,
        &mut good_output,
    )?;
    Ok(())
}

#[test]
fn exec_without_secrets_or_all_errors() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    let mut output = Vec::new();
    let result = run_with_context(
        Cli::try_parse_from(["locket", "exec", "--", "/bin/sh", "-c", "true"])?,
        &context,
        &mut output,
    );
    assert_error_contains(result, "exec requires --all or at least one --secret");
    Ok(())
}

#[test]
fn exec_all_and_secret_flags_are_mutually_exclusive() {
    let result = Cli::try_parse_from([
        "locket",
        "exec",
        "--all",
        "--secret",
        "DATABASE_URL",
        "--",
        "/bin/sh",
        "-c",
        "true",
    ]);
    assert!(result.is_err(), "clap should reject combining --all and --secret");
}

#[test]
fn exec_injects_secret_into_child_scope() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    let args = crate::SecretWriteArgs {
        key: "DATABASE_URL".to_owned(),
        source: crate::SourceArg { source: Some(crate::SecretSourceArg::UserLocal) },
        metadata: crate::SecretMetadataFlags {
            description: None,
            owner: None,
            tags: Vec::new(),
            required: false,
            optional: false,
        },
    };
    crate::set_secret_value(&context, &args, "postgres://localhost/app", "manual", 1_000)?;

    let mut exec_output = Vec::new();
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "exec",
            "--secret",
            "DATABASE_URL",
            "--",
            "/bin/sh",
            "-c",
            "test \"$DATABASE_URL\" = \"postgres://localhost/app\"",
        ])?,
        &context,
        &mut exec_output,
    )?;

    assert!(String::from_utf8(exec_output)?.is_empty());
    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let session = store.connection().query_row(
        "SELECT policy_name, ended_at IS NOT NULL, exit_status, secret_names_json
         FROM runtime_sessions",
        [],
        |row| {
            Ok((
                row.get::<_, Option<String>>(0)?,
                row.get::<_, bool>(1)?,
                row.get::<_, Option<i32>>(2)?,
                row.get::<_, String>(3)?,
            ))
        },
    )?;
    assert_eq!(session.0, None);
    assert!(session.1);
    assert_eq!(session.2, Some(0));
    assert_eq!(session.3, "[\"DATABASE_URL\"]");
    assert!(!session.3.contains("postgres://localhost/app"));
    Ok(())
}

#[test]
fn run_policy_injects_required_and_optional_secrets_without_printing_values()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    let db_args = test_secret_write_args("DATABASE_URL");
    crate::set_secret_value(&context, &db_args, "postgres://localhost/app", "manual", 1_000)?;
    let api_args = test_secret_write_args("OPENAI_API_KEY");
    crate::set_secret_value(&context, &api_args, "sk_test_policy_value", "manual", 2_000)?;

    std::fs::OpenOptions::new()
        .append(true)
        .open(directory.path().join("locket.toml"))?
        .write_all(
            br#"
[commands.env_check]
argv = ["/bin/sh", "-c", "printf 'DATABASE_URL=%s\nOPENAI_API_KEY=%s\n' \"${DATABASE_URL:+present}\" \"${OPENAI_API_KEY:+present}\" > env-presence.txt"]
required_secrets = ["DATABASE_URL"]
optional_secrets = ["OPENAI_API_KEY"]
env_mode = "strict"
inherit_env = ["PATH"]
"#,
        )?;

    let mut inspect_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "env", "inspect", "--policy", "env_check"])?,
        &context,
        &mut inspect_output,
    )?;
    let inspect_output = String::from_utf8(inspect_output)?;
    assert!(inspect_output.contains("secret DATABASE_URL kind=required sources=user-local"));
    assert!(inspect_output.contains("secret OPENAI_API_KEY kind=optional sources=user-local"));
    assert!(inspect_output.contains("decision=inject"));
    assert!(!inspect_output.contains("postgres://localhost/app"));
    assert!(!inspect_output.contains("sk_test_policy_value"));

    let mut run_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "run", "env_check"])?,
        &context,
        &mut run_output,
    )?;
    assert!(String::from_utf8(run_output)?.is_empty());
    let presence = std::fs::read_to_string(directory.path().join("env-presence.txt"))?;
    assert_eq!(presence, "DATABASE_URL=present\nOPENAI_API_KEY=present\n");
    assert!(!presence.contains("postgres://localhost/app"));
    assert!(!presence.contains("sk_test_policy_value"));
    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let session = store.connection().query_row(
        "SELECT policy_name, ended_at IS NOT NULL, exit_status, secret_names_json
         FROM runtime_sessions",
        [],
        |row| {
            Ok((
                row.get::<_, Option<String>>(0)?,
                row.get::<_, bool>(1)?,
                row.get::<_, Option<i32>>(2)?,
                row.get::<_, String>(3)?,
            ))
        },
    )?;
    assert_eq!(session.0.as_deref(), Some("env_check"));
    assert!(session.1);
    assert_eq!(session.2, Some(0));
    assert_eq!(session.3, "[\"DATABASE_URL\",\"OPENAI_API_KEY\"]");
    Ok(())
}

#[test]
fn run_policy_audit_records_selected_source_by_precedence_without_values()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    let user_args =
        test_secret_write_args_for_source("DATABASE_URL", crate::SecretSourceArg::UserLocal);
    crate::set_secret_value(&context, &user_args, "user-precedence-value", "manual", 1_000)?;
    let machine_args =
        test_secret_write_args_for_source("DATABASE_URL", crate::SecretSourceArg::MachineLocal);
    crate::set_secret_value(&context, &machine_args, "machine-precedence-value", "manual", 2_000)?;

    std::fs::OpenOptions::new()
        .append(true)
        .open(directory.path().join("locket.toml"))?
        .write_all(
            br#"
[commands.env_check]
argv = ["/bin/sh", "-c", "test \"$DATABASE_URL\" = \"machine-precedence-value\""]
required_secrets = ["DATABASE_URL"]
env_mode = "strict"
inherit_env = ["PATH"]
"#,
        )?;

    run_with_context(
        Cli::try_parse_from(["locket", "run", "env_check"])?,
        &context,
        &mut Vec::new(),
    )?;

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'RUN_POLICY'
         ORDER BY sequence DESC LIMIT 1",
        [],
        |row| row.get(0),
    )?;
    let metadata_json: serde_json::Value = serde_json::from_str(&metadata)?;
    assert_eq!(metadata_json["command"], "run");
    assert_eq!(metadata_json["secret_names"], json!(["DATABASE_URL"]));
    assert_eq!(metadata_json["allowed_secret_names"], json!(["DATABASE_URL"]));
    assert_eq!(metadata_json["required_secret_names"], json!(["DATABASE_URL"]));
    assert_eq!(metadata_json["policy_id"], "env_check");
    assert_eq!(metadata_json["external_sources"], json!([]));
    assert_eq!(metadata_json["confirmation_source"], json!(null));
    assert_eq!(metadata_json["child_exit"], json!(0));
    assert_eq!(metadata_json["override_explicit"], json!(false));
    assert_eq!(
        metadata_json["secrets"],
        json!([{
            "name": "DATABASE_URL",
            "required": true,
            "selected_source": "machine-local",
            "selected_version": 1,
            "sources": ["machine-local", "user-local"]
        }])
    );
    assert!(!metadata.contains("machine-precedence-value"));
    assert!(!metadata.contains("user-precedence-value"));
    Ok(())
}

#[test]
fn run_warns_when_implicit_locket_override_replaces_parent_name_without_values()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    let home = test_secret_write_args("HOME");
    crate::set_secret_value(&context, &home, "locket-home", "manual", 1_000)?;

    std::fs::OpenOptions::new()
        .append(true)
        .open(directory.path().join("locket.toml"))?
        .write_all(
            br#"
[commands.env_check]
argv = ["/bin/sh", "-c", "test \"$HOME\" = \"locket-home\""]
required_secrets = ["HOME"]
env_mode = "minimal"
"#,
        )?;

    let mut output = Vec::new();
    run_with_context(Cli::try_parse_from(["locket", "run", "env_check"])?, &context, &mut output)?;
    let output = String::from_utf8(output)?;
    assert!(
        output
            .contains("warning: implicit override=locket will replace existing env name(s): HOME")
    );
    assert!(!output.contains("locket-home"));
    Ok(())
}

#[test]
fn run_policy_audit_records_child_exit_code_on_failure() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;

    std::fs::OpenOptions::new()
        .append(true)
        .open(directory.path().join("locket.toml"))?
        .write_all(
            br#"
[commands.fail_command]
argv = ["/bin/sh", "-c", "exit 17"]
env_mode = "strict"
inherit_env = ["PATH"]
"#,
        )?;

    let mut output = Vec::new();
    let result = run_with_context(
        Cli::try_parse_from(["locket", "run", "fail_command"])?,
        &context,
        &mut output,
    );
    let Err(error) = result else {
        return Err("policy with `exit 17` should propagate child exit".into());
    };
    assert_eq!(error.exit_code(), 17);

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'RUN_POLICY'
         ORDER BY sequence DESC LIMIT 1",
        [],
        |row| row.get(0),
    )?;
    let metadata_json: serde_json::Value = serde_json::from_str(&metadata)?;
    assert_eq!(metadata_json["status"], "FAILED");
    assert_eq!(metadata_json["child_exit"], json!(17));
    Ok(())
}

#[test]
fn parent_external_env_source_reinjects_only_allowed_names()
-> Result<(), Box<dyn std::error::Error>> {
    let document = locket_core::PolicyDocument::from_toml_str(
        r#"
[commands.env_check]
argv = ["/bin/sh", "-c", "true"]
required_secrets = ["PARENT_ALLOWED"]
optional_secrets = ["PARENT_OPTIONAL"]
external_env_sources = ["parent"]
env_mode = "strict"
"#,
    )?;
    let policy = document.commands.get("env_check").ok_or("missing policy")?;
    let parent_env = [
        ("PARENT_ALLOWED".to_owned(), locket_exec::env_value("from-parent")),
        ("PARENT_OPTIONAL".to_owned(), locket_exec::env_value("also-parent")),
        ("PARENT_DENIED".to_owned(), locket_exec::env_value("must-not-leak")),
    ]
    .into_iter()
    .collect::<locket_exec::EnvMap>();

    let project_root = tempdir()?;
    let external_env =
        crate::resolve_policy_external_env(policy, &parent_env, project_root.path())?;
    assert_eq!(external_env.len(), 2);
    assert_eq!(external_env.get("PARENT_ALLOWED").map(|value| value.as_str()), Some("from-parent"));
    assert_eq!(
        external_env.get("PARENT_OPTIONAL").map(|value| value.as_str()),
        Some("also-parent")
    );
    assert!(!external_env.contains_key("PARENT_DENIED"));

    let request = locket_exec::ExecutionRequest {
        argv: vec!["/bin/sh".to_owned(), "-c".to_owned(), "true".to_owned()],
        parent_env,
        inherit_env: policy.inherit_env.clone(),
        external_env,
        locket_env: locket_exec::EnvMap::new(),
        env_mode: policy.env_mode,
        override_mode: policy.override_behavior,
    };
    let prepared = locket_exec::prepare_execution(&request)?;
    assert_eq!(prepared.env.get("PARENT_ALLOWED").map(|value| value.as_str()), Some("from-parent"));
    assert_eq!(
        prepared.env.get("PARENT_OPTIONAL").map(|value| value.as_str()),
        Some("also-parent")
    );
    assert!(!prepared.env.contains_key("PARENT_DENIED"));
    Ok(())
}

#[test]
fn file_external_env_source_loads_only_policy_allowed_names()
-> Result<(), Box<dyn std::error::Error>> {
    let document = locket_core::PolicyDocument::from_toml_str(
        r#"
[commands.env_check]
argv = ["/bin/sh", "-c", "true"]
required_secrets = ["DATABASE_URL"]
optional_secrets = ["LOG_LEVEL"]
external_env_sources = [{ file = ".env.local" }]
env_mode = "strict"
"#,
    )?;
    let policy = document.commands.get("env_check").ok_or("missing policy")?;
    let project_root = tempdir()?;
    std::fs::write(
        project_root.path().join(".env.local"),
        "DATABASE_URL=postgres://localhost/app\nLOG_LEVEL=debug\nNOT_ALLOWED=denied\n",
    )?;
    let parent_env = locket_exec::EnvMap::new();

    let external_env =
        crate::resolve_policy_external_env(policy, &parent_env, project_root.path())?;
    assert_eq!(external_env.len(), 2);
    assert_eq!(
        external_env.get("DATABASE_URL").map(|value| value.as_str()),
        Some("postgres://localhost/app")
    );
    assert_eq!(external_env.get("LOG_LEVEL").map(|value| value.as_str()), Some("debug"));
    assert!(!external_env.contains_key("NOT_ALLOWED"));
    Ok(())
}

#[test]
fn file_external_env_source_rejects_absolute_path() -> Result<(), Box<dyn std::error::Error>> {
    let document = locket_core::PolicyDocument::from_toml_str(
        r#"
[commands.env_check]
argv = ["/bin/sh", "-c", "true"]
required_secrets = ["DATABASE_URL"]
external_env_sources = [{ file = "/etc/passwd" }]
env_mode = "strict"
"#,
    )?;
    let policy = document.commands.get("env_check").ok_or("missing policy")?;
    let project_root = tempdir()?;

    let result = crate::resolve_policy_external_env(
        policy,
        &locket_exec::EnvMap::new(),
        project_root.path(),
    );
    let Err(error) = result else {
        return Err("absolute external env file paths must be rejected".into());
    };
    assert_eq!(error.exit_code(), locket_core::LocketError::MetadataInvalid.exit_code());
    Ok(())
}

#[test]
fn file_external_env_source_rejects_paths_outside_project_root()
-> Result<(), Box<dyn std::error::Error>> {
    let document = locket_core::PolicyDocument::from_toml_str(
        r#"
[commands.env_check]
argv = ["/bin/sh", "-c", "true"]
required_secrets = ["DATABASE_URL"]
external_env_sources = [{ file = "../escape.env" }]
env_mode = "strict"
"#,
    )?;
    let policy = document.commands.get("env_check").ok_or("missing policy")?;
    let outside = tempdir()?;
    std::fs::write(outside.path().join("escape.env"), "DATABASE_URL=postgres://escape\n")?;
    let project_root = tempdir_in(outside.path())?;

    let result = crate::resolve_policy_external_env(
        policy,
        &locket_exec::EnvMap::new(),
        project_root.path(),
    );
    let Err(error) = result else {
        return Err("external env paths outside the project root must be rejected".into());
    };
    assert_eq!(error.exit_code(), locket_core::LocketError::MetadataInvalid.exit_code());
    Ok(())
}

#[test]
fn compose_external_env_source_uses_process_stub_without_docker()
-> Result<(), Box<dyn std::error::Error>> {
    let document = locket_core::PolicyDocument::from_toml_str(
        r#"
[commands.env_check]
argv = ["/bin/sh", "-c", "true"]
required_secrets = ["DATABASE_URL"]
optional_secrets = ["API_KEY", "LOG_LEVEL", "PORT"]
external_env_sources = ["compose"]
env_mode = "strict"
"#,
    )?;
    let policy = document.commands.get("env_check").ok_or("missing policy")?;
    let project_root = tempdir()?;
    let args = [
        "-c",
        r#"printf '%s' '{"environment":{"LOG_LEVEL":"debug","PORT":5432,"NOT_ALLOWED":"denied"},"services":{"web":{"environment":{"DATABASE_URL":"from-compose"}},"worker":{"environment":["API_KEY=from-compose-array","IGNORED=denied"]}}}'"#,
    ];
    let command = crate::ComposeConfigCommand::new(Path::new("/bin/sh"), &args);

    let external_env = crate::resolve_policy_external_env_with_compose_config_command(
        policy,
        &locket_exec::EnvMap::new(),
        project_root.path(),
        &command,
    )?;

    assert_eq!(external_env.len(), 4);
    assert_eq!(external_env.get("DATABASE_URL").map(|value| value.as_str()), Some("from-compose"));
    assert_eq!(external_env.get("API_KEY").map(|value| value.as_str()), Some("from-compose-array"));
    assert_eq!(external_env.get("LOG_LEVEL").map(|value| value.as_str()), Some("debug"));
    assert_eq!(external_env.get("PORT").map(|value| value.as_str()), Some("5432"));
    assert!(!external_env.contains_key("NOT_ALLOWED"));
    assert!(!external_env.contains_key("IGNORED"));
    Ok(())
}

#[test]
fn compose_external_env_source_reports_command_failure_without_values()
-> Result<(), Box<dyn std::error::Error>> {
    let document = locket_core::PolicyDocument::from_toml_str(
        r#"
[commands.env_check]
argv = ["/bin/sh", "-c", "true"]
required_secrets = ["DATABASE_URL"]
external_env_sources = ["compose"]
env_mode = "strict"
"#,
    )?;
    let policy = document.commands.get("env_check").ok_or("missing policy")?;
    let project_root = tempdir()?;
    let args = ["-c", "printf '%s' 'from-compose' >&2; exit 19"];
    let command = crate::ComposeConfigCommand::new(Path::new("/bin/sh"), &args);

    let result = crate::resolve_policy_external_env_with_compose_config_command(
        policy,
        &locket_exec::EnvMap::new(),
        project_root.path(),
        &command,
    );

    let Err(error) = result else {
        return Err("failing docker compose config stub must fail".into());
    };
    assert_eq!(error.exit_code(), locket_core::LocketError::ExternalSourceUnavailable.exit_code());
    let message = error.to_string();
    assert!(message.contains("docker compose config failed"));
    assert!(!message.contains("from-compose"));
    Ok(())
}

#[test]
fn compose_external_env_source_reports_missing_command_with_typed_error()
-> Result<(), Box<dyn std::error::Error>> {
    let document = locket_core::PolicyDocument::from_toml_str(
        r#"
[commands.env_check]
argv = ["/bin/sh", "-c", "true"]
required_secrets = ["DATABASE_URL"]
external_env_sources = ["compose"]
env_mode = "strict"
"#,
    )?;
    let policy = document.commands.get("env_check").ok_or("missing policy")?;
    let project_root = tempdir()?;
    let missing = project_root.path().join("missing-docker");
    let command = crate::ComposeConfigCommand::new(&missing, &["compose", "config"]);

    let result = crate::resolve_policy_external_env_with_compose_config_command(
        policy,
        &locket_exec::EnvMap::new(),
        project_root.path(),
        &command,
    );

    let Err(error) = result else {
        return Err("missing compose config command must fail".into());
    };
    assert_eq!(error.exit_code(), locket_core::LocketError::ExternalSourceUnavailable.exit_code());
    assert!(error.to_string().contains("could not be started"));
    Ok(())
}

#[test]
fn compose_external_env_source_rejects_invalid_json() -> Result<(), Box<dyn std::error::Error>> {
    let document = locket_core::PolicyDocument::from_toml_str(
        r#"
[commands.env_check]
argv = ["/bin/sh", "-c", "true"]
required_secrets = ["DATABASE_URL"]
external_env_sources = ["compose"]
env_mode = "strict"
"#,
    )?;
    let policy = document.commands.get("env_check").ok_or("missing policy")?;
    let project_root = tempdir()?;
    let args = ["-c", "printf '%s' 'not json'"];
    let command = crate::ComposeConfigCommand::new(Path::new("/bin/sh"), &args);

    let result = crate::resolve_policy_external_env_with_compose_config_command(
        policy,
        &locket_exec::EnvMap::new(),
        project_root.path(),
        &command,
    );

    let Err(error) = result else {
        return Err("invalid docker compose config JSON must fail".into());
    };
    assert_eq!(error.exit_code(), locket_core::LocketError::ExternalSourceUnavailable.exit_code());
    assert!(error.to_string().contains("invalid JSON"));
    Ok(())
}

#[test]
fn docker_policy_plan_and_audit_are_metadata_only() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    let db_args = test_secret_write_args("DATABASE_URL");
    crate::set_secret_value(&context, &db_args, "postgres://localhost/app", "manual", 1_000)?;
    let api_args = test_secret_write_args("API_KEY");
    crate::set_secret_value(&context, &api_args, "sk_test_docker_value", "manual", 2_000)?;

    std::fs::OpenOptions::new()
        .append(true)
        .open(directory.path().join("locket.toml"))?
        .write_all(
            br#"
[commands.docker_app]
argv = ["docker", "run", "app"]
required_secrets = ["DATABASE_URL"]
optional_secrets = ["API_KEY"]
env_mode = "strict"
inherit_env = ["PATH"]
"#,
        )?;

    let parsed = Cli::try_parse_from([
        "locket",
        "env",
        "docker",
        "--policy",
        "docker_app",
        "--",
        "docker",
        "run",
        "alpine",
    ])?;
    assert!(matches!(
        parsed.command,
        Some(crate::Command::Env { command: crate::EnvCommand::Docker(_) })
    ));

    let parent_env = std::iter::once(("PATH".to_owned(), locket_exec::env_value("/bin"))).collect();
    let docker_argv = vec!["docker".to_owned(), "run".to_owned(), "alpine".to_owned()];
    let mut prepared =
        crate::prepare_docker_policy_execution(&context, "docker_app", &docker_argv, parent_env)?;
    assert_eq!(prepared.execution.program, "docker");
    assert!(prepared.plan.argv.windows(2).any(|pair| pair == ["--env", "API_KEY"]));
    assert!(prepared.plan.argv.windows(2).any(|pair| pair == ["--env", "DATABASE_URL"]));
    let argv_text = prepared.plan.argv.join(" ");
    assert!(!argv_text.contains("postgres://localhost/app"));
    assert!(!argv_text.contains("sk_test_docker_value"));

    let metadata = crate::docker_policy_audit_metadata(&prepared, "SUCCESS");
    let metadata_text = metadata.to_string();
    assert!(metadata_text.contains("DATABASE_URL"));
    assert!(metadata_text.contains("API_KEY"));
    assert!(metadata_text.contains("environment_names"));
    assert!(metadata_text.contains("\"argv_program\":\"docker\""));
    assert!(!metadata_text.contains("postgres://localhost/app"));
    assert!(!metadata_text.contains("sk_test_docker_value"));

    crate::write_docker_policy_audit_if_available(&context, &mut prepared, "SUCCESS")?;
    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let audit_metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'RUN'",
        [],
        |row| row.get(0),
    )?;
    assert!(audit_metadata.contains("DATABASE_URL"));
    assert!(audit_metadata.contains("API_KEY"));
    assert!(!audit_metadata.contains("postgres://localhost/app"));
    assert!(!audit_metadata.contains("sk_test_docker_value"));
    Ok(())
}

#[test]
fn compose_policy_plan_supports_options_and_denies_remote_by_default()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    let api_args = test_secret_write_args("API_KEY");
    crate::set_secret_value(&context, &api_args, "sk_test_compose_value", "manual", 1_000)?;

    std::fs::OpenOptions::new()
        .append(true)
        .open(directory.path().join("locket.toml"))?
        .write_all(
            br#"
[commands.compose_app]
argv = ["docker", "compose", "up"]
required_secrets = ["API_KEY"]
env_mode = "strict"
inherit_env = ["PATH"]
"#,
        )?;

    let parsed = Cli::try_parse_from([
        "locket",
        "compose",
        "run",
        "--policy",
        "compose_app",
        "--project-directory",
        ".",
        "--profile",
        "web",
        "--",
        "docker",
        "compose",
        "up",
    ])?;
    assert!(matches!(
        parsed.command,
        Some(crate::Command::Compose { command: crate::ComposeCommand::Run(_) })
    ));

    let argv = crate::compose_argv_with_options(
        vec!["docker".to_owned(), "compose".to_owned(), "up".to_owned()],
        Some(Path::new(".")),
        &["web".to_owned()],
    )?;
    assert_eq!(argv, ["docker", "compose", "--project-directory", ".", "--profile", "web", "up"]);
    let parent_env = std::iter::once(("PATH".to_owned(), locket_exec::env_value("/bin"))).collect();
    let prepared =
        crate::prepare_compose_policy_execution(&context, "compose_app", &argv, parent_env)?;
    assert_eq!(
        prepared.plan.argv,
        prepared.execution.args.iter().fold(
            vec![prepared.execution.program.clone()],
            |mut values, arg| {
                values.push(arg.clone());
                values
            }
        )
    );
    assert_eq!(prepared.plan.injected_names, ["API_KEY"]);
    assert!(!prepared.plan.argv.join(" ").contains("sk_test_compose_value"));
    assert_eq!(
        prepared.execution.env.get("API_KEY").map(|value| value.as_str()),
        Some("sk_test_compose_value")
    );

    let remote_env =
        std::iter::once(("DOCKER_HOST".to_owned(), locket_exec::env_value("ssh://builder")))
            .collect();
    let remote_argv = vec!["docker".to_owned(), "compose".to_owned(), "up".to_owned()];
    let Err(error) =
        crate::prepare_compose_policy_execution(&context, "compose_app", &remote_argv, remote_env)
    else {
        return Err("remote Docker context should be denied".into());
    };
    let message = error.to_string();
    assert!(message.contains("remote Docker context is denied by default"));
    assert!(!message.contains("sk_test_compose_value"));
    Ok(())
}

#[test]
fn context_reports_metadata_only_summaries_without_values() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    let db_args = test_secret_write_args("DATABASE_URL");
    crate::set_secret_value(&context, &db_args, "postgres://localhost/app", "manual", 1_000)?;
    let api_args = test_secret_write_args("OPENAI_API_KEY");
    crate::set_secret_value(&context, &api_args, "sk_test_context_value", "manual", 2_000)?;

    std::fs::OpenOptions::new()
        .append(true)
        .open(directory.path().join("locket.toml"))?
        .write_all(
            br#"
[commands.env_check]
argv = ["/bin/sh", "-c", "true"]
required_secrets = ["DATABASE_URL"]
optional_secrets = ["MISSING_ONLY", "OPENAI_API_KEY"]
confirm = true
require_user_verification = true
"#,
        )?;

    let locked_context = test_context_with_key_store(
        &directory,
        std::sync::Arc::new(MemoryMasterKeyStore::default()),
    );
    let mut context_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "context"])?,
        &locked_context,
        &mut context_output,
    )?;

    let context_output = String::from_utf8(context_output)?;
    assert!(context_output.contains("Project: app"));
    assert!(context_output.contains("Profile: dev"));
    assert!(context_output.contains("- dev active=yes dangerous=no secrets=2"));
    assert!(context_output.contains(
        "- DATABASE_URL profiles=dev,policy:env_check sources=policy-required,user-local"
    ));
    assert!(context_output.contains(
        "- OPENAI_API_KEY profiles=dev,policy:env_check sources=policy-optional,user-local"
    ));
    assert!(
        context_output.contains("- MISSING_ONLY profiles=policy:env_check sources=policy-optional")
    );
    assert!(context_output.contains("- env_check type=argv"));
    assert!(context_output.contains("required=DATABASE_URL"));
    assert!(context_output.contains("optional=MISSING_ONLY,OPENAI_API_KEY"));
    assert!(context_output.contains("confirm=yes verify_user=yes"));
    assert!(context_output.contains("No secret values included."));
    assert!(context_output.contains("metadata_only: yes"));
    assert!(!context_output.contains("postgres://localhost/app"));
    assert!(!context_output.contains("sk_test_context_value"));
    Ok(())
}

#[test]
fn context_redacts_names_from_flag_or_privacy_config() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    let db_args = test_secret_write_args("DATABASE_URL");
    crate::set_secret_value(&context, &db_args, "postgres://localhost/app", "manual", 1_000)?;
    std::fs::OpenOptions::new()
        .append(true)
        .open(directory.path().join("locket.toml"))?
        .write_all(
            br#"
[commands.env_check]
argv = ["/bin/sh", "-c", "true"]
required_secrets = ["DATABASE_URL"]
"#,
        )?;

    let mut flag_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "context", "--redact-names"])?,
        &context,
        &mut flag_output,
    )?;
    let flag_output = String::from_utf8(flag_output)?;
    assert!(flag_output.contains("Project: project-"));
    assert!(flag_output.contains("Profile: profile-"));
    assert!(flag_output.contains("secret-"));
    assert!(flag_output.contains("policy-"));
    assert!(!flag_output.contains("Project: app"));
    assert!(!flag_output.contains("Profile: dev"));
    assert!(!flag_output.contains("DATABASE_URL"));
    assert!(!flag_output.contains("env_check"));
    assert!(!flag_output.contains("postgres://localhost/app"));

    let mut config_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "config", "set", "privacy.redact_names", "true"])?,
        &context,
        &mut config_output,
    )?;
    let mut configured_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "context"])?,
        &context,
        &mut configured_output,
    )?;
    let configured_output = String::from_utf8(configured_output)?;
    assert!(configured_output.contains("Project: project-"));
    assert!(!configured_output.contains("DATABASE_URL"));
    assert!(!configured_output.contains("env_check"));
    Ok(())
}

#[test]
fn run_policy_confirm_gate_rejects_wrong_confirmation() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let key_store: Arc<dyn MasterKeyStore + Send + Sync> =
        Arc::new(MemoryMasterKeyStore::default());
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &test_context_with_key_store(&directory, Arc::clone(&key_store)),
        &mut Vec::new(),
    )?;
    std::fs::OpenOptions::new()
        .append(true)
        .open(directory.path().join("locket.toml"))?
        .write_all(
            br#"
[commands.deploy]
argv = ["/bin/sh", "-c", "true"]
confirm = true
env_mode = "strict"
inherit_env = ["PATH"]
"#,
        )?;

    let bad_context =
        test_context_with_key_store_and_confirmation(&directory, Arc::clone(&key_store), "wrong\n");
    let result = run_with_context(
        Cli::try_parse_from(["locket", "run", "deploy"])?,
        &bad_context,
        &mut Vec::new(),
    );
    let Err(error) = result else {
        return Err("policy with confirm=true must reject wrong confirmation".into());
    };
    assert_eq!(error.exit_code(), 68);
    assert!(error.to_string().contains("confirmation did not match run scope"));

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let count: i64 = store.connection().query_row(
        "SELECT COUNT(*) FROM audit_log WHERE action = 'RUN_POLICY'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(count, 0, "rejected run must not write a RUN_POLICY audit row");
    Ok(())
}

#[test]
fn run_policy_confirm_gate_accepts_typed_confirmation() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let key_store: Arc<dyn MasterKeyStore + Send + Sync> =
        Arc::new(MemoryMasterKeyStore::default());
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &test_context_with_key_store(&directory, Arc::clone(&key_store)),
        &mut Vec::new(),
    )?;
    std::fs::OpenOptions::new()
        .append(true)
        .open(directory.path().join("locket.toml"))?
        .write_all(
            br#"
[commands.deploy]
argv = ["/bin/sh", "-c", "true"]
confirm = true
env_mode = "strict"
inherit_env = ["PATH"]
"#,
        )?;

    let good_context = test_context_with_key_store_and_confirmation(
        &directory,
        Arc::clone(&key_store),
        "run deploy\n",
    );
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "run", "deploy"])?,
        &good_context,
        &mut output,
    )?;
    let output = String::from_utf8(output)?;
    assert!(output.contains("type 'run deploy' to confirm run"));

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'RUN_POLICY'
         ORDER BY sequence DESC LIMIT 1",
        [],
        |row| row.get(0),
    )?;
    let metadata_json: serde_json::Value = serde_json::from_str(&metadata)?;
    assert_eq!(metadata_json["status"], "SUCCESS");
    assert_eq!(metadata_json["confirmation_source"], json!("interactive"));
    assert_eq!(metadata_json["policy"], "deploy");
    Ok(())
}

#[test]
fn run_policy_user_verification_gate_rejects_when_unsatisfied()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    std::fs::OpenOptions::new()
        .append(true)
        .open(directory.path().join("locket.toml"))?
        .write_all(
            br#"
[commands.sensitive]
argv = ["/bin/sh", "-c", "true"]
require_user_verification = true
env_mode = "strict"
inherit_env = ["PATH"]
"#,
        )?;

    let cases: [(&str, Arc<dyn LocalUserVerifier + Send + Sync>); 3] = [
        ("denied", Arc::new(MemoryLocalUserVerifier::denying())),
        ("cancelled", Arc::new(MemoryLocalUserVerifier::cancelled())),
        ("unavailable", Arc::new(MemoryLocalUserVerifier::unavailable())),
    ];
    for (label, verifier) in cases {
        let rejecting_context = context_with_user_verifier(&context, verifier);
        let result = run_with_context(
            Cli::try_parse_from(["locket", "run", "sensitive"])?,
            &rejecting_context,
            &mut Vec::new(),
        );
        let Err(error) = result else {
            return Err(format!("policy must reject {label} user verification").into());
        };
        assert_eq!(error.exit_code(), 74);
        assert!(error.to_string().contains("local user verification"));
    }

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let count: i64 = store.connection().query_row(
        "SELECT COUNT(*) FROM audit_log WHERE action = 'RUN_POLICY'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(count, 0, "rejected verification must not write a RUN_POLICY audit row");
    Ok(())
}

#[test]
fn run_policy_user_verification_gate_records_method_on_success()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    std::fs::OpenOptions::new()
        .append(true)
        .open(directory.path().join("locket.toml"))?
        .write_all(
            br#"
[commands.sensitive]
argv = ["/bin/sh", "-c", "true"]
require_user_verification = true
env_mode = "strict"
inherit_env = ["PATH"]
"#,
        )?;

    run_with_context(
        Cli::try_parse_from(["locket", "run", "sensitive"])?,
        &context,
        &mut Vec::new(),
    )?;

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'RUN_POLICY'
         ORDER BY sequence DESC LIMIT 1",
        [],
        |row| row.get(0),
    )?;
    let metadata_json: serde_json::Value = serde_json::from_str(&metadata)?;
    assert_eq!(metadata_json["status"], "SUCCESS");
    assert_eq!(metadata_json["user_verification"]["required"], json!(true));
    assert_eq!(metadata_json["user_verification"]["satisfied"], json!(true));
    assert_eq!(metadata_json["user_verification"]["method"], json!("test"));
    Ok(())
}

#[test]
fn run_policy_user_verification_metadata_is_unsatisfied_when_not_required()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    std::fs::OpenOptions::new()
        .append(true)
        .open(directory.path().join("locket.toml"))?
        .write_all(
            br#"
[commands.unprotected]
argv = ["/bin/sh", "-c", "true"]
env_mode = "strict"
inherit_env = ["PATH"]
"#,
        )?;

    run_with_context(
        Cli::try_parse_from(["locket", "run", "unprotected"])?,
        &context,
        &mut Vec::new(),
    )?;

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'RUN_POLICY'
         ORDER BY sequence DESC LIMIT 1",
        [],
        |row| row.get(0),
    )?;
    let metadata_json: serde_json::Value = serde_json::from_str(&metadata)?;
    assert_eq!(metadata_json["user_verification"]["required"], json!(false));
    assert_eq!(metadata_json["user_verification"]["satisfied"], json!(false));
    assert_eq!(metadata_json["user_verification"]["method"], json!(null));
    Ok(())
}

#[test]
#[cfg(unix)]
fn run_shell_policy_executes_via_sh_and_audits_shape_shell()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    let marker_path = directory.path().join("shell-marker.txt");
    let marker_str = marker_path.display().to_string();
    std::fs::OpenOptions::new()
        .append(true)
        .open(directory.path().join("locket.toml"))?
        .write_all(
            format!(
                r#"
[commands.shell_check]
shell = "echo shell-mode-marker > {marker_str}"
env_mode = "strict"
inherit_env = ["PATH"]
"#,
            )
            .as_bytes(),
        )?;

    run_with_context(
        Cli::try_parse_from(["locket", "run", "shell_check"])?,
        &context,
        &mut Vec::new(),
    )?;

    let marker_contents = std::fs::read_to_string(&marker_path)?;
    assert!(
        marker_contents.contains("shell-mode-marker"),
        "shell-mode policy must invoke /bin/sh -c so shell features run; got {marker_contents:?}"
    );

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'RUN_POLICY'
         ORDER BY sequence DESC LIMIT 1",
        [],
        |row| row.get(0),
    )?;
    let metadata_json: serde_json::Value = serde_json::from_str(&metadata)?;
    assert_eq!(metadata_json["status"], "SUCCESS");
    assert_eq!(metadata_json["command_type"], "shell");
    assert_eq!(metadata_json["policy"], "shell_check");
    Ok(())
}

#[test]
fn run_argv_policy_audit_records_command_type_argv() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    std::fs::OpenOptions::new()
        .append(true)
        .open(directory.path().join("locket.toml"))?
        .write_all(
            br#"
[commands.argv_check]
argv = ["/bin/sh", "-c", "true"]
env_mode = "strict"
inherit_env = ["PATH"]
"#,
        )?;

    run_with_context(
        Cli::try_parse_from(["locket", "run", "argv_check"])?,
        &context,
        &mut Vec::new(),
    )?;

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'RUN_POLICY'
         ORDER BY sequence DESC LIMIT 1",
        [],
        |row| row.get(0),
    )?;
    let metadata_json: serde_json::Value = serde_json::from_str(&metadata)?;
    assert_eq!(metadata_json["command_type"], "argv");
    Ok(())
}

#[test]
#[cfg(unix)]
fn run_shell_policy_injects_locket_secrets_into_shell_environment()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    let db = test_secret_write_args("DATABASE_URL");
    crate::set_secret_value(&context, &db, "postgres://shell-mode-secret", "manual", 1_000)?;

    let marker_path = directory.path().join("shell-secret-check.txt");
    let marker_str = marker_path.display().to_string();
    std::fs::OpenOptions::new()
        .append(true)
        .open(directory.path().join("locket.toml"))?
        .write_all(
            format!(
                r#"
[commands.shell_secret]
shell = "printf '%s' \"$DATABASE_URL\" > {marker_str}"
required_secrets = ["DATABASE_URL"]
env_mode = "strict"
inherit_env = ["PATH"]
"#,
            )
            .as_bytes(),
        )?;

    run_with_context(
        Cli::try_parse_from(["locket", "run", "shell_secret"])?,
        &context,
        &mut Vec::new(),
    )?;

    let value = std::fs::read_to_string(&marker_path)?;
    assert_eq!(value, "postgres://shell-mode-secret");
    Ok(())
}
