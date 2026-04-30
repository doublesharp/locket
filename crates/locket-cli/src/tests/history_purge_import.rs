#[allow(unused_imports)]
use super::*;

#[test]
fn rotate_history_and_purge_keep_values_hidden() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;

    let set_args = test_secret_write_args("DATABASE_URL");
    crate::set_secret_value(&context, &set_args, "postgres://localhost/old", "manual", 1_000)?;

    let rotate_args = test_rotate_args("DATABASE_URL", Some("24h"));
    let grace_until = crate::grace_until_from_args(rotate_args.grace_ttl.as_deref(), 2_000)?;
    let (_source, version) = crate::rotate_secret_value(
        &context,
        &rotate_args,
        "postgres://localhost/new",
        2_000,
        grace_until,
    )?;
    assert_eq!(version, 2);

    let mut get_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "get", "DATABASE_URL"])?,
        &context,
        &mut get_output,
    )?;
    let get_output = String::from_utf8(get_output)?;
    assert!(get_output.contains("version=2"));
    assert!(!get_output.contains("postgres://localhost/new"));

    let mut reveal_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "get", "DATABASE_URL", "--reveal", "--force"])?,
        &context,
        &mut reveal_output,
    )?;
    assert_eq!(String::from_utf8(reveal_output)?, "postgres://localhost/new\n");

    let mut history_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "history", "DATABASE_URL"])?,
        &context,
        &mut history_output,
    )?;
    let history_output = String::from_utf8(history_output)?;
    assert!(history_output.contains("v1 state=deprecated"));
    assert!(history_output.contains("v2 state=current"));
    assert!(history_output.contains("grace_until="));
    assert!(!history_output.contains("postgres://localhost/old"));
    assert!(!history_output.contains("postgres://localhost/new"));

    let purge_args = ["locket", "purge", "DATABASE_URL", "--version", "1", "--force"];
    let mut purge_output = Vec::new();
    run_with_context(Cli::try_parse_from(purge_args)?, &context, &mut purge_output)?;
    assert!(String::from_utf8(purge_output)?.contains("versions=1"));

    let mut history_after_purge = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "history", "DATABASE_URL"])?,
        &context,
        &mut history_after_purge,
    )?;
    let history_after_purge = String::from_utf8(history_after_purge)?;
    assert!(history_after_purge.contains("v1 state=purged"));
    assert!(history_after_purge.contains("v2 state=current"));

    let invalid_purge_args = ["locket", "purge", "DATABASE_URL", "--version", "2", "--force"];
    let mut invalid_purge_output = Vec::new();
    let invalid_purge = run_with_context(
        Cli::try_parse_from(invalid_purge_args)?,
        &context,
        &mut invalid_purge_output,
    );
    assert!(invalid_purge.is_err());

    let mut rm_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "rm", "DATABASE_URL"])?,
        &context,
        &mut rm_output,
    )?;
    let purge_all_args = ["locket", "purge", "DATABASE_URL", "--all-versions", "--force"];
    let mut purge_all_output = Vec::new();
    run_with_context(Cli::try_parse_from(purge_all_args)?, &context, &mut purge_all_output)?;
    assert!(String::from_utf8(purge_all_output)?.contains("versions=1,2"));

    let mut audit_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "audit", "verify"])?,
        &context,
        &mut audit_output,
    )?;
    assert!(String::from_utf8(audit_output)?.contains("verified 7 row(s)"));

    assert_lifecycle_audit_log(&directory)?;
    Ok(())
}

#[test]
fn purge_requires_typed_confirmation_of_full_scope() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let key_store: Arc<dyn MasterKeyStore + Send + Sync> =
        Arc::new(MemoryMasterKeyStore::default());
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &test_context_with_key_store(&directory, Arc::clone(&key_store)),
        &mut Vec::new(),
    )?;
    let setup_context = test_context_with_key_store(&directory, Arc::clone(&key_store));
    let set_args = test_secret_write_args("DATABASE_URL");
    crate::set_secret_value(
        &setup_context,
        &set_args,
        "postgres://localhost/old",
        "manual",
        1_000,
    )?;
    let rotate_args = test_rotate_args("DATABASE_URL", Some("24h"));
    let grace_until = crate::grace_until_from_args(rotate_args.grace_ttl.as_deref(), 2_000)?;
    crate::rotate_secret_value(
        &setup_context,
        &rotate_args,
        "postgres://localhost/new",
        2_000,
        grace_until,
    )?;

    let bad_context = test_context_with_key_store_and_confirmation(
        &directory,
        Arc::clone(&key_store),
        "purge dev/user-local/DATABASE_URL/v2\n",
    );
    let mut bad_output = Vec::new();
    let result = run_with_context(
        Cli::try_parse_from(["locket", "purge", "DATABASE_URL", "--version", "1"])?,
        &bad_context,
        &mut bad_output,
    );
    assert_error_contains(result, "confirmation did not match");
    let bad_output = String::from_utf8(bad_output)?;
    assert!(bad_output.contains("purge_profile: dev"));
    assert!(bad_output.contains("purge_source: user-local"));
    assert!(bad_output.contains("purge_secret: DATABASE_URL"));
    assert!(bad_output.contains("purge_version_scope: v1"));
    assert!(bad_output.contains("metadata_only: yes"));

    let good_context = test_context_with_key_store_and_confirmation(
        &directory,
        Arc::clone(&key_store),
        "purge dev/user-local/DATABASE_URL/v1\n",
    );
    let mut good_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "purge", "DATABASE_URL", "--version", "1"])?,
        &good_context,
        &mut good_output,
    )?;
    let good_output = String::from_utf8(good_output)?;
    assert!(good_output.contains("purged DATABASE_URL"));
    assert!(good_output.contains("versions=1"));

    Ok(())
}

#[test]
fn purge_force_skips_confirmation_prompt() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    let set_args = test_secret_write_args("API_KEY");
    crate::set_secret_value(&context, &set_args, "tok-v1", "manual", 1_000)?;
    let rotate_args = test_rotate_args("API_KEY", Some("24h"));
    let grace = crate::grace_until_from_args(rotate_args.grace_ttl.as_deref(), 2_000)?;
    crate::rotate_secret_value(&context, &rotate_args, "tok-v2", 2_000, grace)?;

    let mut force_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "purge", "API_KEY", "--version", "1", "--force"])?,
        &context,
        &mut force_output,
    )?;
    let force_output = String::from_utf8(force_output)?;
    assert!(force_output.contains("purged API_KEY"));
    assert!(!force_output.contains("type 'purge"));
    Ok(())
}

#[test]
fn purge_already_purged_skips_confirmation_and_writes_no_audit()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let key_store: Arc<dyn MasterKeyStore + Send + Sync> =
        Arc::new(MemoryMasterKeyStore::default());
    let context = test_context_with_key_store(&directory, Arc::clone(&key_store));
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    let set_args = test_secret_write_args("API_KEY");
    crate::set_secret_value(&context, &set_args, "tok-v1", "manual", 1_000)?;
    let rotate_args = test_rotate_args("API_KEY", Some("24h"));
    let grace = crate::grace_until_from_args(rotate_args.grace_ttl.as_deref(), 2_000)?;
    crate::rotate_secret_value(&context, &rotate_args, "tok-v2", 2_000, grace)?;

    run_with_context(
        Cli::try_parse_from(["locket", "purge", "API_KEY", "--version", "1", "--force"])?,
        &context,
        &mut Vec::new(),
    )?;
    let store_pre = crate::open_store(&context)?;
    let count_before: i64 = store_pre.connection().query_row(
        "SELECT COUNT(*) FROM audit_log WHERE action = 'PURGE'",
        [],
        |row| row.get(0),
    )?;
    drop(store_pre);

    let no_confirm_context = test_context_with_key_store_and_confirmation(
        &directory,
        Arc::clone(&key_store),
        "should-not-be-read\n",
    );
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "purge", "API_KEY", "--version", "1"])?,
        &no_confirm_context,
        &mut output,
    )?;
    let output = String::from_utf8(output)?;
    assert!(output.contains("already purged"));
    let store_post = crate::open_store(&no_confirm_context)?;
    let count_after: i64 = store_post.connection().query_row(
        "SELECT COUNT(*) FROM audit_log WHERE action = 'PURGE'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(count_before, count_after, "no-op purge must not write audit");
    Ok(())
}

#[test]
fn history_filters_by_source_state_limit_and_renders_iso_timestamps()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;

    let user_local = test_secret_write_args("DATABASE_URL");
    crate::set_secret_value(&context, &user_local, "postgres://localhost/u-v1", "manual", 1_000)?;
    let rotate_user = test_rotate_args("DATABASE_URL", Some("24h"));
    let grace_user = crate::grace_until_from_args(rotate_user.grace_ttl.as_deref(), 2_000)?;
    crate::rotate_secret_value(
        &context,
        &rotate_user,
        "postgres://localhost/u-v2",
        2_000,
        grace_user,
    )?;

    let mut machine_local = test_secret_write_args("DATABASE_URL");
    machine_local.source = crate::SourceArg { source: Some(crate::SecretSourceArg::MachineLocal) };
    crate::set_secret_value(
        &context,
        &machine_local,
        "postgres://localhost/m-v1",
        "manual",
        3_000,
    )?;

    let mut all_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "history", "DATABASE_URL"])?,
        &context,
        &mut all_output,
    )?;
    let all_output = String::from_utf8(all_output)?;
    assert!(all_output.contains("history DATABASE_URL profile=dev"));
    assert!(all_output.contains("source=user-local"));
    assert!(all_output.contains("source=machine-local"));
    assert!(all_output.contains("v1 state=deprecated"));
    assert!(all_output.contains("v2 state=current"));
    assert!(all_output.contains("created_at=1000(1970-01-01T00:00:00.000001000Z)"));
    assert!(!all_output.contains("postgres://"));

    let mut user_only = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "history", "DATABASE_URL", "--source", "user-local"])?,
        &context,
        &mut user_only,
    )?;
    let user_only = String::from_utf8(user_only)?;
    assert!(user_only.contains("source=user-local"));
    assert!(!user_only.contains("source=machine-local"));

    let mut current_only = Vec::new();
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "history",
            "DATABASE_URL",
            "--source",
            "user-local",
            "--state",
            "current",
        ])?,
        &context,
        &mut current_only,
    )?;
    let current_only = String::from_utf8(current_only)?;
    assert!(current_only.contains("v2 state=current"));
    assert!(!current_only.contains("v1 state=deprecated"));

    let mut limit_one = Vec::new();
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "history",
            "DATABASE_URL",
            "--source",
            "user-local",
            "--limit",
            "1",
        ])?,
        &context,
        &mut limit_one,
    )?;
    let limit_one = String::from_utf8(limit_one)?;
    let version_lines = limit_one.matches("\n  v").count();
    assert_eq!(version_lines, 1, "limit=1 should print exactly one version line");

    Ok(())
}

#[test]
fn history_state_filter_prints_no_versions_notice_and_exits_ok()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    let args = test_secret_write_args("API_TOKEN");
    crate::set_secret_value(&context, &args, "tok-v1", "manual", 1_000)?;

    let mut history_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "history", "API_TOKEN", "--state", "purged"])?,
        &context,
        &mut history_output,
    )?;
    let history_output = String::from_utf8(history_output)?;
    assert!(history_output.contains("history: no versions"));
    assert!(!history_output.contains("v1"));
    Ok(())
}

#[test]
fn history_unknown_source_fails_without_listing_other_sources()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    let args = test_secret_write_args("API_TOKEN");
    crate::set_secret_value(&context, &args, "tok-v1", "manual", 1_000)?;

    let mut history_output = Vec::new();
    let result = run_with_context(
        Cli::try_parse_from(["locket", "history", "API_TOKEN", "--source", "team-managed"])?,
        &context,
        &mut history_output,
    );
    assert!(result.is_err(), "missing source should error");
    assert!(history_output.is_empty());
    Ok(())
}

#[test]
fn history_missing_key_errors_with_secret_not_found() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    let mut history_output = Vec::new();
    let result = run_with_context(
        Cli::try_parse_from(["locket", "history", "NOPE_TOKEN"])?,
        &context,
        &mut history_output,
    );
    assert_error_contains(result, "secret not found");
    Ok(())
}

#[test]
fn unix_nanos_to_rfc3339_renders_known_timestamps() {
    assert_eq!(crate::unix_nanos_to_rfc3339(0), Some("1970-01-01T00:00:00.000000000Z".to_owned()));
    assert_eq!(
        crate::unix_nanos_to_rfc3339(1_700_000_000_000_000_000),
        Some("2023-11-14T22:13:20.000000000Z".to_owned())
    );
    assert_eq!(crate::unix_nanos_to_rfc3339(-1), None);
}

#[test]
fn optional_formatters_use_dash_for_absent_values() {
    assert_eq!(crate::optional_i64(None), "-");
    assert_eq!(crate::format_optional_unix_nanos(None), "-");
    assert_eq!(crate::format_optional_str(None), "-");
    assert_eq!(crate::format_optional_str(Some("run")), "run");
}

#[test]
fn import_env_encrypts_values_and_refreshes_example() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    std::fs::write(
        directory.path().join(".env"),
        "DATABASE_URL=postgres://localhost/app\nINVALID-NAME=value\nOPENAI_API_KEY='sk_test_sample'\n",
    )?;

    let mut import_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "import", ".env"])?,
        &context,
        &mut import_output,
    )?;
    let import_output = String::from_utf8(import_output)?;
    assert!(import_output.contains("imported: 2"));
    assert!(import_output.contains("invalid: 1"));
    assert!(import_output.contains("profile: dev"));
    assert!(import_output.contains("source: user-local"));
    assert!(import_output.contains("missing_in_profile: none"));
    assert!(import_output.contains("delete_env: kept"));
    assert!(import_output.contains("metadata_only: yes"));
    assert!(!import_output.contains("postgres://localhost/app"));

    let example = std::fs::read_to_string(directory.path().join(".env.example"))?;
    assert!(example.contains("DATABASE_URL="));
    assert!(example.contains("OPENAI_API_KEY="));
    assert!(!example.contains("postgres://localhost/app"));

    std::fs::write(directory.path().join(".env"), "DATABASE_URL=postgres://localhost/new\n")?;
    let mut duplicate_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "import", ".env"])?,
        &context,
        &mut duplicate_output,
    )?;
    let duplicate_output = String::from_utf8(duplicate_output)?;
    assert!(duplicate_output.contains("imported: 0"));
    assert!(duplicate_output.contains("skipped: 1"));
    assert!(duplicate_output.contains("skipped_names: DATABASE_URL"));
    assert!(!duplicate_output.contains("postgres://localhost/new"));

    let mut overwrite_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "import", ".env", "--overwrite"])?,
        &context,
        &mut overwrite_output,
    )?;
    let overwrite_output = String::from_utf8(overwrite_output)?;
    assert!(overwrite_output.contains("overwritten: 1"));
    assert!(!overwrite_output.contains("postgres://localhost/new"));

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
fn import_env_targets_named_profile_and_reports_parity() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    run_with_context(
        Cli::try_parse_from(["locket", "profile", "create", "staging"])?,
        &context,
        &mut Vec::new(),
    )?;
    std::fs::write(directory.path().join(".env"), "API_KEY=sk_test_stagingImport123\n")?;

    let mut import_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "import", ".env", "--profile", "staging"])?,
        &context,
        &mut import_output,
    )?;

    let import_output = String::from_utf8(import_output)?;
    assert!(import_output.contains("imported: 1"));
    assert!(import_output.contains("profile: staging"));
    assert!(import_output.contains("env_names: 1"));
    assert!(import_output.contains("profile_names: 1"));
    assert!(import_output.contains("missing_in_profile: none"));
    assert!(import_output.contains("extra_in_profile: none"));
    assert!(import_output.contains("delete_env: kept"));
    assert!(!import_output.contains("sk_test_stagingImport123"));

    let resolved = crate::resolve_project(&context.cwd)?.ok_or("project should resolve")?;
    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let staging = store
        .get_profile_by_name(resolved.config.project_id.as_str(), "staging")?
        .ok_or("staging profile should exist")?;
    let secret = store
        .get_secret_by_source(
            resolved.config.project_id.as_str(),
            &staging.id,
            "API_KEY",
            "user-local",
        )?
        .ok_or("imported secret should exist")?;
    assert_eq!(secret.origin, "imported");
    assert_eq!(secret.current_version, 1);
    let audit_metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'IMPORT'",
        [],
        |row| row.get(0),
    )?;
    assert!(audit_metadata.contains("\"secret_name\":\"API_KEY\""));
    assert!(audit_metadata.contains(&staging.id));
    assert!(!audit_metadata.contains("sk_test_stagingImport123"));
    Ok(())
}

#[test]
fn import_overwrite_to_dangerous_profile_requires_confirmation_before_rotation()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let key_store: Arc<dyn MasterKeyStore + Send + Sync> =
        Arc::new(MemoryMasterKeyStore::default());
    let context = test_context_with_key_store(&directory, Arc::clone(&key_store));
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    run_with_context(
        Cli::try_parse_from(["locket", "profile", "create", "prod"])?,
        &context,
        &mut Vec::new(),
    )?;
    let mark_context =
        test_context_with_key_store_and_confirmation(&directory, Arc::clone(&key_store), "prod\n");
    run_with_context(
        Cli::try_parse_from(["locket", "profile", "mark-dangerous", "prod"])?,
        &mark_context,
        &mut Vec::new(),
    )?;
    std::fs::write(directory.path().join(".env"), "API_KEY=sk_test_prodOriginal123\n")?;
    run_with_context(
        Cli::try_parse_from(["locket", "import", ".env", "--profile", "prod"])?,
        &context,
        &mut Vec::new(),
    )?;

    std::fs::write(directory.path().join(".env"), "API_KEY=sk_test_prodRotated123\n")?;
    let mut overwrite_output = Vec::new();
    assert_error_contains(
        run_with_context(
            Cli::try_parse_from(["locket", "import", ".env", "--profile", "prod", "--overwrite"])?,
            &context,
            &mut overwrite_output,
        ),
        "dangerous profile",
    );
    let overwrite_output = String::from_utf8(overwrite_output)?;
    assert!(overwrite_output.contains("dangerous_profile: prod"));
    assert!(!overwrite_output.contains("sk_test_prodRotated123"));

    let resolved = crate::resolve_project(&context.cwd)?.ok_or("project should resolve")?;
    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let prod = store
        .get_profile_by_name(resolved.config.project_id.as_str(), "prod")?
        .ok_or("prod profile should exist")?;
    let secret = store
        .get_secret_by_source(
            resolved.config.project_id.as_str(),
            &prod.id,
            "API_KEY",
            "user-local",
        )?
        .ok_or("prod import should exist")?;
    assert_eq!(secret.current_version, 1);
    Ok(())
}

#[test]
fn import_with_delete_confirmation_removes_env_and_emits_example()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    let secret_value = "postgres://user:secret@db.example.local/myapp";
    std::fs::write(
        directory.path().join(".env"),
        format!("DATABASE_URL={secret_value}\nAPI_TOKEN=tok_test_abc123\n"),
    )?;

    let confirm_context = context_with_confirmation(&context, "delete .env\n");
    let mut import_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "import", ".env"])?,
        &confirm_context,
        &mut import_output,
    )?;
    let import_output = String::from_utf8(import_output)?;
    assert!(import_output.contains("imported: 2"), "output: {import_output}");
    assert!(import_output.contains("delete_env: deleted"), "output: {import_output}");
    assert!(!import_output.contains(secret_value), "secret value must not appear in output");
    assert!(!import_output.contains("tok_test_abc123"), "secret value must not appear in output");

    assert!(!directory.path().join(".env").exists(), ".env should be deleted after confirmation");

    let example = std::fs::read_to_string(directory.path().join(".env.example"))?;
    assert!(example.contains("DATABASE_URL="), ".env.example should list DATABASE_URL");
    assert!(example.contains("API_TOKEN="), ".env.example should list API_TOKEN");
    assert!(!example.contains(secret_value), "secret value must not appear in .env.example");
    assert!(!example.contains("tok_test_abc123"), "secret value must not appear in .env.example");

    Ok(())
}
