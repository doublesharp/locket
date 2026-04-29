#[allow(unused_imports)]
use super::*;

#[test]
fn set_command_reads_secure_secret_value_without_leaking_it()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context_with_secret_value(&directory, "postgres://localhost/prompt");
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;

    let mut set_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "set", "DATABASE_URL"])?,
        &context,
        &mut set_output,
    )?;
    let set_output = String::from_utf8(set_output)?;
    assert!(set_output.contains("set DATABASE_URL"));
    assert!(!set_output.contains("postgres://localhost/prompt"));

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'SET'",
        [],
        |row| row.get(0),
    )?;
    assert!(!metadata.contains("postgres://localhost/prompt"));

    let mut reveal_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "get", "DATABASE_URL", "--reveal", "--force"])?,
        &context,
        &mut reveal_output,
    )?;
    assert_eq!(String::from_utf8(reveal_output)?, "postgres://localhost/prompt\n");
    Ok(())
}

#[test]
fn set_command_rejects_empty_secure_secret_before_writing() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempdir()?;
    let context = test_context_with_secret_value(&directory, "");
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;

    let result = run_with_context(
        Cli::try_parse_from(["locket", "set", "DATABASE_URL"])?,
        &context,
        &mut Vec::new(),
    );
    assert_error_contains(result, "secret value cannot be empty");

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let set_count: u32 = store.connection().query_row(
        "SELECT COUNT(*) FROM audit_log WHERE action = 'SET'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(set_count, 0);
    Ok(())
}

#[test]
fn set_command_preflights_source_conflicts_before_reading_secret()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context_with_failing_secret_reader(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    let args =
        test_secret_write_args_for_source("DATABASE_URL", crate::SecretSourceArg::MachineLocal);
    crate::set_secret_value(&context, &args, "postgres://localhost/machine", "manual", 1_000)?;

    let result = run_with_context(
        Cli::try_parse_from(["locket", "set", "DATABASE_URL"])?,
        &context,
        &mut Vec::new(),
    );
    assert_error_contains(result, "pass --source");
    Ok(())
}

#[test]
fn set_command_preflights_deleted_source_as_typed_error_before_reading_secret()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    let args = test_secret_write_args("DATABASE_URL");
    crate::set_secret_value(&context, &args, "postgres://localhost/deleted", "manual", 1_000)?;
    run_with_context(
        Cli::try_parse_from(["locket", "rm", "DATABASE_URL"])?,
        &context,
        &mut Vec::new(),
    )?;

    let failing_context = test_context_with_failing_secret_reader(&directory);
    let result = run_with_context(
        Cli::try_parse_from(["locket", "set", "DATABASE_URL", "--source", "user-local"])?,
        &failing_context,
        &mut Vec::new(),
    );
    let Err(error) = result else {
        return Err("deleted source should fail".into());
    };
    assert_eq!(error.exit_code(), locket_core::LocketError::SecretDeleted.exit_code());
    assert!(error.to_string().contains("secret source is deleted"), "{error}");
    Ok(())
}

#[test]
fn rotate_command_reads_secure_secret_value_without_leaking_it()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context_with_secret_value(&directory, "postgres://localhost/new");
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    let args = test_secret_write_args("DATABASE_URL");
    crate::set_secret_value(&context, &args, "postgres://localhost/old", "manual", 1_000)?;

    let mut rotate_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "rotate", "DATABASE_URL"])?,
        &context,
        &mut rotate_output,
    )?;
    let rotate_output = String::from_utf8(rotate_output)?;
    assert!(rotate_output.contains("rotated DATABASE_URL"));
    assert!(rotate_output.contains("version=2"));
    assert!(!rotate_output.contains("postgres://localhost/new"));
    assert!(!rotate_output.contains("postgres://localhost/old"));

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'ROTATE'",
        [],
        |row| row.get(0),
    )?;
    assert!(!metadata.contains("postgres://localhost/new"));
    assert!(!metadata.contains("postgres://localhost/old"));

    let mut reveal_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "get", "DATABASE_URL", "--reveal", "--force"])?,
        &context,
        &mut reveal_output,
    )?;
    assert_eq!(String::from_utf8(reveal_output)?, "postgres://localhost/new\n");
    Ok(())
}

#[test]
fn rotate_command_preflights_source_ambiguity_before_reading_secret()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context_with_failing_secret_reader(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    let user_args = test_secret_write_args("DATABASE_URL");
    crate::set_secret_value(&context, &user_args, "postgres://localhost/user", "manual", 1_000)?;
    let machine_args =
        test_secret_write_args_for_source("DATABASE_URL", crate::SecretSourceArg::MachineLocal);
    crate::set_secret_value(
        &context,
        &machine_args,
        "postgres://localhost/machine",
        "manual",
        2_000,
    )?;

    let result = run_with_context(
        Cli::try_parse_from(["locket", "rotate", "DATABASE_URL"])?,
        &context,
        &mut Vec::new(),
    );
    assert_error_contains(result, "multiple sources");
    Ok(())
}

#[test]
fn set_list_get_and_rm_secret_value() -> Result<(), Box<dyn std::error::Error>> {
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

    let mut list_output = Vec::new();
    run_with_context(Cli::try_parse_from(["locket", "list"])?, &context, &mut list_output)?;
    let list_output = String::from_utf8(list_output)?;
    assert!(list_output.contains("DATABASE_URL"));
    assert!(!list_output.contains("postgres://localhost/app"));

    let mut get_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "get", "DATABASE_URL"])?,
        &context,
        &mut get_output,
    )?;
    let get_output = String::from_utf8(get_output)?;
    assert!(get_output.contains("version=1"));
    assert!(!get_output.contains("postgres://localhost/app"));

    let mut reveal_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "get", "DATABASE_URL", "--reveal", "--force"])?,
        &context,
        &mut reveal_output,
    )?;
    assert_eq!(String::from_utf8(reveal_output)?, "postgres://localhost/app\n");

    let mut rm_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "rm", "DATABASE_URL"])?,
        &context,
        &mut rm_output,
    )?;
    let mut list_after_rm = Vec::new();
    run_with_context(Cli::try_parse_from(["locket", "list"])?, &context, &mut list_after_rm)?;
    assert!(String::from_utf8(list_after_rm)?.contains("no secrets"));
    Ok(())
}

#[test]
fn get_copy_writes_metadata_only_audit_without_value_leakage()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    let args = test_secret_write_args("DATABASE_URL");
    crate::set_secret_value(&context, &args, "postgres://localhost/app", "manual", 1_000)?;

    let copy_args =
        crate::GetArgs { key: "DATABASE_URL".to_owned(), reveal: false, force: false, copy: true };
    let mut copy_output = Vec::new();
    let mut copy_stderr = Vec::new();
    crate::get_command_with_clipboard(
        &context,
        &mut copy_output,
        &mut copy_stderr,
        &copy_args,
        |value| {
            assert_eq!(value, "postgres://localhost/app");
            Ok(())
        },
    )?;
    let copy_output = String::from_utf8(copy_output)?;
    let copy_stderr = String::from_utf8(copy_stderr)?;
    assert!(copy_output.contains("metadata_only=yes"));
    assert!(copy_output.contains("clipboard_clear_supported=no"));
    assert!(!copy_output.contains("postgres://localhost/app"));
    assert!(copy_stderr.contains("clipboard TTL clearing is unsupported"));
    assert!(!copy_output.contains("clipboard TTL clearing is unsupported"));

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'COPY'",
        [],
        |row| row.get(0),
    )?;
    assert!(metadata.contains("\"access_mode\":\"clipboard\""));
    assert!(metadata.contains("\"ttl_seconds\":60"));
    assert!(metadata.contains("\"clipboard_clear_supported\":false"));
    assert!(metadata.contains("\"secret_name\":\"DATABASE_URL\""));
    assert!(!metadata.contains("postgres://localhost/app"));
    Ok(())
}

#[test]
fn get_copy_unavailable_audits_unsupported_state_without_value_leakage()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    let args = test_secret_write_args("DATABASE_URL");
    crate::set_secret_value(&context, &args, "postgres://localhost/app", "manual", 1_000)?;

    let copy_args =
        crate::GetArgs { key: "DATABASE_URL".to_owned(), reveal: false, force: false, copy: true };
    let mut copy_output = Vec::new();
    let mut copy_stderr = Vec::new();
    let result = crate::get_command_with_clipboard(
        &context,
        &mut copy_output,
        &mut copy_stderr,
        &copy_args,
        |_value| Err("clipboard command unavailable".to_owned()),
    );
    assert_error_contains(result, "clipboard command unavailable");
    let copy_output = String::from_utf8(copy_output)?;
    let copy_stderr = String::from_utf8(copy_stderr)?;
    assert!(copy_stderr.contains("clipboard TTL clearing is unsupported"));
    assert!(!copy_output.contains("clipboard TTL clearing is unsupported"));
    assert!(!copy_output.contains("postgres://localhost/app"));
    assert!(!copy_stderr.contains("postgres://localhost/app"));

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'COPY'",
        [],
        |row| row.get(0),
    )?;
    assert!(metadata.contains("\"status\":\"FAILED\""));
    assert!(metadata.contains("\"clipboard_supported\":false"));
    assert!(metadata.contains("\"unsupported_reason\":\"clipboard command unavailable\""));
    assert!(!metadata.contains("postgres://localhost/app"));
    Ok(())
}

#[test]
fn reveal_requires_force_for_noninteractive_stdout_and_audits_force()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    let args = test_secret_write_args("DATABASE_URL");
    crate::set_secret_value(&context, &args, "postgres://localhost/app", "manual", 1_000)?;

    let mut reveal_output = Vec::new();
    let result = run_with_context(
        Cli::try_parse_from(["locket", "get", "DATABASE_URL", "--reveal"])?,
        &context,
        &mut reveal_output,
    );
    assert_error_contains(result.map(|_| ()), "requires an interactive terminal");

    let mut forced_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "get", "DATABASE_URL", "--reveal", "--force"])?,
        &context,
        &mut forced_output,
    )?;
    assert_eq!(String::from_utf8(forced_output)?, "postgres://localhost/app\n");

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'REVEAL'",
        [],
        |row| row.get(0),
    )?;
    assert!(metadata.contains("\"force\":true"));
    assert!(metadata.contains("\"access_mode\":\"stdout\""));
    assert!(!metadata.contains("postgres://localhost/app"));
    Ok(())
}

#[test]
fn meta_updates_secret_metadata_without_printing_values() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    let args = test_secret_write_args("DATABASE_URL");
    crate::set_secret_value(&context, &args, "postgres://localhost/app", "manual", 1_000)?;

    let mut meta_output = Vec::new();
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "meta",
            "DATABASE_URL",
            "--description",
            "primary database",
            "--owner",
            "platform",
            "--tag",
            "database",
            "--tag",
            "prod",
            "--required",
        ])?,
        &context,
        &mut meta_output,
    )?;
    let meta_output = String::from_utf8(meta_output)?;
    assert!(meta_output.contains("metadata updated DATABASE_URL"));
    assert!(meta_output.contains("updated_fields: description,owner,tags,required"));
    assert!(meta_output.contains("metadata_only: yes"));
    assert!(!meta_output.contains("postgres://localhost/app"));

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let row = store.connection().query_row(
        "SELECT description, owner, tags_json, required, updated_at
         FROM secrets
         WHERE name = 'DATABASE_URL'",
        [],
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, bool>(3)?,
                row.get::<_, i64>(4)?,
            ))
        },
    )?;
    assert_eq!(row.0, "primary database");
    assert_eq!(row.1, "platform");
    assert_eq!(row.2, "[\"database\",\"prod\"]");
    assert!(row.3);
    assert_eq!(row.4, 1_000);

    let audit_metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'SECRET_META_UPDATE'",
        [],
        |row| row.get(0),
    )?;
    assert!(
        audit_metadata
            .contains("\"updated_fields\":[\"description\",\"owner\",\"tags\",\"required\"]")
    );
    assert!(audit_metadata.contains("\"updated_field_count\":4"));
    assert!(audit_metadata.contains("\"tag_update_count\":2"));
    assert!(audit_metadata.contains("\"required_update\":true"));
    assert!(!audit_metadata.contains("primary database"));
    assert!(!audit_metadata.contains("platform"));
    assert!(!audit_metadata.contains("postgres://localhost/app"));
    Ok(())
}

#[test]
fn meta_rejects_secret_like_metadata_without_storing_value()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    let args = test_secret_write_args("DATABASE_URL");
    crate::set_secret_value(&context, &args, "postgres://localhost/app", "manual", 1_000)?;

    let provider = "sk_test_sampleTokenValue123";
    let result = run_with_context(
        Cli::try_parse_from(["locket", "meta", "DATABASE_URL", "--description", provider])?,
        &context,
        &mut Vec::new(),
    );
    assert_error_contains(result, "metadata field description looks like a secret");

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let row = store.connection().query_row(
        "SELECT description, updated_at FROM secrets WHERE name = 'DATABASE_URL'",
        [],
        |row| Ok((row.get::<_, Option<String>>(0)?, row.get::<_, i64>(1)?)),
    )?;
    assert_eq!(row, (None, 1_000));

    let audit_metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log
         WHERE action = 'SECRET_META_UPDATE' AND status = 'FAILED'",
        [],
        |row| row.get(0),
    )?;
    assert!(audit_metadata.contains("\"failure_reason\":\"metadata_privacy_validation\""));
    assert!(!audit_metadata.contains(provider));
    assert!(!audit_metadata.contains("postgres://localhost/app"));
    Ok(())
}

#[test]
fn meta_rejects_known_secret_value_metadata() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    let args = test_secret_write_args("DATABASE_URL");
    crate::set_secret_value(&context, &args, "postgres://localhost/app", "manual", 1_000)?;

    let result = run_with_context(
        Cli::try_parse_from([
            "locket",
            "meta",
            "DATABASE_URL",
            "--owner",
            "postgres://localhost/app",
        ])?,
        &context,
        &mut Vec::new(),
    );
    assert_error_contains(result, "metadata field owner matches an existing secret value");

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let owner: Option<String> = store.connection().query_row(
        "SELECT owner FROM secrets WHERE name = 'DATABASE_URL'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(owner, None);

    let audit_metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log
         WHERE action = 'SECRET_META_UPDATE' AND status = 'FAILED'",
        [],
        |row| row.get(0),
    )?;
    assert!(!audit_metadata.contains("postgres://localhost/app"));
    Ok(())
}

#[test]
fn meta_rejects_control_character_metadata() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    let args = test_secret_write_args("DATABASE_URL");
    crate::set_secret_value(&context, &args, "postgres://localhost/app", "manual", 1_000)?;

    let result = run_with_context(
        Cli::try_parse_from(["locket", "meta", "DATABASE_URL", "--tag", "prod\u{1b}[31m"])?,
        &context,
        &mut Vec::new(),
    );
    assert_error_contains(result, "metadata field tag contains control characters");
    Ok(())
}

#[test]
fn meta_requires_source_for_multiple_active_sources_and_updates_explicit_source()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    let user_args = test_secret_write_args("DATABASE_URL");
    crate::set_secret_value(&context, &user_args, "postgres://localhost/user", "manual", 1_000)?;
    let machine_args = crate::SecretWriteArgs {
        key: "DATABASE_URL".to_owned(),
        source: crate::SourceArg { source: Some(crate::SecretSourceArg::MachineLocal) },
        metadata: crate::SecretMetadataFlags {
            description: None,
            owner: None,
            tags: Vec::new(),
            required: false,
            optional: false,
        },
    };
    crate::set_secret_value(
        &context,
        &machine_args,
        "postgres://localhost/machine",
        "manual",
        2_000,
    )?;

    let ambiguous = run_with_context(
        Cli::try_parse_from([
            "locket",
            "meta",
            "DATABASE_URL",
            "--description",
            "ambiguous database",
        ])?,
        &context,
        &mut Vec::new(),
    );
    assert_error_contains(ambiguous, "multiple sources exist for this secret");

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let versions_before: i64 =
        store
            .connection()
            .query_row("SELECT COUNT(*) FROM secret_versions", [], |row| row.get(0))?;

    let mut meta_output = Vec::new();
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "meta",
            "DATABASE_URL",
            "--source",
            "machine-local",
            "--description",
            "machine database",
        ])?,
        &context,
        &mut meta_output,
    )?;
    let meta_output = String::from_utf8(meta_output)?;
    assert!(meta_output.contains("source=machine-local"));
    assert!(!meta_output.contains("postgres://localhost"));

    let descriptions = store.connection().query_row(
        "SELECT
            MAX(CASE WHEN source = 'user-local' THEN description END),
            MAX(CASE WHEN source = 'machine-local' THEN description END)
         FROM secrets
         WHERE name = 'DATABASE_URL'",
        [],
        |row| Ok((row.get::<_, Option<String>>(0)?, row.get::<_, Option<String>>(1)?)),
    )?;
    assert_eq!(descriptions.0, None);
    assert_eq!(descriptions.1.as_deref(), Some("machine database"));
    let versions_after: i64 =
        store
            .connection()
            .query_row("SELECT COUNT(*) FROM secret_versions", [], |row| row.get(0))?;
    assert_eq!(versions_after, versions_before);

    let audit_metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log
         WHERE action = 'SECRET_META_UPDATE' AND status = 'SUCCESS'",
        [],
        |row| row.get(0),
    )?;
    assert!(audit_metadata.contains("\"source\":\"machine-local\""));
    assert!(!audit_metadata.contains("machine database"));
    assert!(!audit_metadata.contains("postgres://localhost"));
    Ok(())
}
