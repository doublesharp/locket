#[allow(unused_imports)]
use super::*;

#[test]
fn scan_reports_metadata_only_provider_findings() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let sample_path = directory.path().join("sample.txt");
    std::fs::write(&sample_path, "token=sk_test_sampleTokenValue123\n")?;
    let context = test_context(&directory);
    let mut output = Vec::new();

    run_with_context(
        Cli::try_parse_from(["locket", "scan", "sample.txt"])?,
        &context,
        &mut output,
    )?;

    let output = String::from_utf8(output)?;
    assert!(output.contains("provider-token-pattern"));
    assert!(!output.contains("sk_test_sampleTokenValue123"));
    Ok(())
}

#[test]
fn scan_staged_requires_git_worktree() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();

    let result = run_with_context(
        Cli::try_parse_from(["locket", "scan", "--staged"])?,
        &context,
        &mut output,
    );

    assert!(result.is_err());
    if let Err(error) = result {
        assert_eq!(error.exit_code(), 64);
        assert!(error.to_string().contains("git worktree required"));
    }
    Ok(())
}

#[test]
fn scan_respects_locketignore_for_project_scan() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut init_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut init_output,
    )?;
    std::fs::write(directory.path().join(".locketignore"), "ignored.txt\n")?;
    std::fs::write(directory.path().join("ignored.txt"), "token=sk_test_sampleTokenValue123\n")?;
    std::fs::write(directory.path().join("visible.txt"), "token=sk_test_visibleTokenValue123\n")?;

    let mut scan_output = Vec::new();
    run_with_context(Cli::try_parse_from(["locket", "scan"])?, &context, &mut scan_output)?;

    let scan_output = String::from_utf8(scan_output)?;
    assert!(scan_output.contains("visible.txt:1:7: [warning] provider-token-pattern"));
    assert!(!scan_output.contains("ignored.txt"));
    assert!(!scan_output.contains("sk_test_sampleTokenValue123"));
    assert!(!scan_output.contains("sk_test_visibleTokenValue123"));
    Ok(())
}

#[test]
fn scan_uses_project_high_entropy_thresholds() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    std::fs::write(
        directory.path().join("notes.txt"),
        "short-token=aB3$dE5&gH7*\npublic=lk_proj_0123456789abcdef\n",
    )?;
    std::fs::OpenOptions::new()
        .append(true)
        .open(directory.path().join("locket.toml"))?
        .write_all(
            br"
[scan.high_entropy]
min_length = 12
entropy_threshold = 3.0
",
        )?;

    let mut scan_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "scan", "notes.txt"])?,
        &context,
        &mut scan_output,
    )?;

    let scan_output = String::from_utf8(scan_output)?;
    assert!(scan_output.contains("notes.txt:1:13: [warning] high-entropy"));
    assert!(scan_output.contains("scan: 1 finding(s)"));
    assert!(!scan_output.contains("aB3$dE5&gH7*"));
    assert!(!scan_output.contains("lk_proj_0123456789abcdef"));
    Ok(())
}

#[test]
fn scan_rejects_invalid_high_entropy_thresholds() -> Result<(), Box<dyn std::error::Error>> {
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
            br"
[scan.high_entropy]
min_length = 0
",
        )?;

    let result =
        run_with_context(Cli::try_parse_from(["locket", "scan"])?, &context, &mut Vec::new());

    let Err(error) = result else {
        return Err("invalid scan entropy config must fail closed".into());
    };
    assert_eq!(error.exit_code(), 64);
    assert!(error.to_string().contains("scan.high_entropy.min_length"));
    Ok(())
}

#[test]
fn scan_inline_suppression_drops_high_entropy_finding_and_writes_audit_row()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut init_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut init_output,
    )?;

    let entropy_token = "Z9a$kLmN2pQx7R!sT4vW8yB3cD6eF";
    std::fs::write(
        directory.path().join("notes.txt"),
        format!("token={entropy_token} # locket-allow: known fixture\n"),
    )?;

    let mut scan_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "scan", "notes.txt"])?,
        &context,
        &mut scan_output,
    )?;

    let scan_output = String::from_utf8(scan_output)?;
    assert!(scan_output.contains("scan: no findings"));
    assert!(scan_output.contains("scan: 1 suppressed finding(s)"));
    assert!(scan_output.contains("high-entropy suppressed reason=known fixture"));
    assert!(!scan_output.contains(entropy_token));

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let mut statement = store.connection().prepare(
        "SELECT status, metadata_json FROM audit_log WHERE action = 'SCAN' ORDER BY sequence",
    )?;
    let rows = statement
        .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))?
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(rows.len(), 1);
    let (status, metadata) = &rows[0];
    assert_eq!(status, "SUPPRESSED");
    assert!(metadata.contains("\"rule_id\":\"high-entropy\""));
    assert!(metadata.contains("\"reason\":\"known fixture\""));
    assert!(metadata.contains("notes.txt"));
    assert!(!metadata.contains(entropy_token));
    Ok(())
}

#[test]
fn scan_inline_suppression_does_not_silence_known_secret_match()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut init_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut init_output,
    )?;
    let args = test_secret_write_args("DATABASE_URL");
    crate::set_secret_value(&context, &args, "known-secret-value", "manual", 1_000)?;
    std::fs::write(
        directory.path().join("leak.txt"),
        "db=known-secret-value # locket-allow: try to hide it\n",
    )?;

    let mut scan_output = Vec::new();
    let result = run_with_context(
        Cli::try_parse_from(["locket", "scan", "--require-known", "leak.txt"])?,
        &context,
        &mut scan_output,
    );
    let Err(error) = result else {
        return Err("known-secret match must fail closed (blocking)".into());
    };
    assert_eq!(error.exit_code(), 69);

    let scan_output = String::from_utf8(scan_output)?;
    assert!(scan_output.contains("leak.txt:1:4: [blocking] known-secret"));
    assert!(scan_output.contains("scan: 1 finding(s) (blocking=1 warning=0)"));
    assert!(!scan_output.contains("scan: 1 suppressed"));
    assert!(!scan_output.contains("known-secret-value"));
    Ok(())
}

#[test]
fn scan_inline_suppression_audit_omits_when_no_suppression_present()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut init_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut init_output,
    )?;
    std::fs::write(directory.path().join("notes.txt"), "token=sk_test_sampleTokenValue123\n")?;

    let mut scan_output = Vec::new();
    run_with_context(Cli::try_parse_from(["locket", "scan"])?, &context, &mut scan_output)?;

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let scan_rows: u32 = store.connection().query_row(
        "SELECT COUNT(*) FROM audit_log WHERE action = 'SCAN'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(scan_rows, 0);
    Ok(())
}

#[test]
fn scan_require_known_matches_vault_values_without_printing_them()
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
    crate::set_secret_value(&context, &args, "known-secret-value", "manual", 1_000)?;
    std::fs::write(directory.path().join("sample.txt"), "db=known-secret-value\n")?;

    let mut scan_output = Vec::new();
    let result = run_with_context(
        Cli::try_parse_from(["locket", "scan", "--require-known", "sample.txt"])?,
        &context,
        &mut scan_output,
    );
    let Err(error) = result else {
        return Err("known-secret match must fail closed (blocking)".into());
    };
    assert_eq!(error.exit_code(), 69);

    let scan_output = String::from_utf8(scan_output)?;
    assert!(scan_output.contains("known-secret"));
    assert!(scan_output.contains("[blocking]"));
    assert!(scan_output.contains("known-value coverage checked 1 value(s)"));
    assert!(!scan_output.contains("known-secret-value"));
    Ok(())
}

#[test]
fn scan_require_known_matches_deleted_current_version_with_blob()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    let args = test_secret_write_args("DATABASE_URL");
    crate::set_secret_value(&context, &args, "deleted-current-fixture", "manual", 1_000)?;
    run_with_context(
        Cli::try_parse_from(["locket", "rm", "DATABASE_URL"])?,
        &context,
        &mut Vec::new(),
    )?;
    std::fs::write(directory.path().join("sample.txt"), "db=deleted-current-fixture\n")?;

    let mut scan_output = Vec::new();
    let result = run_with_context(
        Cli::try_parse_from(["locket", "scan", "--require-known", "sample.txt"])?,
        &context,
        &mut scan_output,
    );
    let Err(error) = result else {
        return Err("deleted current version with blob must remain known-scan eligible".into());
    };
    assert_eq!(error.exit_code(), 69);
    let scan_output = String::from_utf8(scan_output)?;
    assert!(scan_output.contains("[blocking] known-secret"));
    assert!(scan_output.contains("known-value coverage checked 1 value(s)"));
    assert!(!scan_output.contains("deleted-current-fixture"));
    Ok(())
}

#[test]
fn scan_require_known_includes_grace_versions_and_excludes_purged_versions()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    let args = test_secret_write_args("DATABASE_URL");
    crate::set_secret_value(&context, &args, "grace-old-fixture", "manual", 1_000)?;
    let rotate_args = test_rotate_args("DATABASE_URL", Some("24h"));
    let timestamp = crate::now_unix_nanos()?;
    let grace_until = crate::grace_until_from_args(rotate_args.grace_ttl.as_deref(), timestamp)?;
    crate::rotate_secret_value(
        &context,
        &rotate_args,
        "grace-new-fixture",
        timestamp,
        grace_until,
    )?;
    std::fs::write(directory.path().join("grace.txt"), "db=grace-old-fixture\n")?;

    let mut grace_scan_output = Vec::new();
    let grace_result = run_with_context(
        Cli::try_parse_from(["locket", "scan", "--require-known", "grace.txt"])?,
        &context,
        &mut grace_scan_output,
    );
    let Err(error) = grace_result else {
        return Err("deprecated version inside grace window must be scan eligible".into());
    };
    assert_eq!(error.exit_code(), 69);
    let grace_scan_output = String::from_utf8(grace_scan_output)?;
    assert!(grace_scan_output.contains("[blocking] known-secret"));
    assert!(!grace_scan_output.contains("grace-old-fixture"));

    run_with_context(
        Cli::try_parse_from(["locket", "purge", "DATABASE_URL", "--version", "1", "--force"])?,
        &context,
        &mut Vec::new(),
    )?;
    let mut purged_scan_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "scan", "--require-known", "grace.txt"])?,
        &context,
        &mut purged_scan_output,
    )?;
    let purged_scan_output = String::from_utf8(purged_scan_output)?;
    assert!(purged_scan_output.contains("known-value coverage checked 1 value(s)"));
    assert!(!purged_scan_output.contains("[blocking] known-secret"));
    assert!(!purged_scan_output.contains("grace-old-fixture"));
    Ok(())
}

#[test]
fn scan_staged_uses_index_content_without_printing_known_values()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    run_git(directory.path(), &["init"])?;
    let context = test_context(&directory);
    let mut init_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut init_output,
    )?;
    let args = test_secret_write_args("DATABASE_URL");
    crate::set_secret_value(&context, &args, "known-secret-value", "manual", 1_000)?;
    let sample_path = directory.path().join("sample.txt");
    std::fs::write(&sample_path, "db=known-secret-value\n")?;
    run_git(directory.path(), &["add", "sample.txt"])?;
    std::fs::write(&sample_path, "db=redacted-in-working-tree\n")?;

    let mut scan_output = Vec::new();
    let result = run_with_context(
        Cli::try_parse_from(["locket", "scan", "--staged", "--require-known"])?,
        &context,
        &mut scan_output,
    );
    let Err(error) = result else {
        return Err("staged known-secret match must fail closed (blocking)".into());
    };
    assert_eq!(error.exit_code(), 69);

    let scan_output = String::from_utf8(scan_output)?;
    assert!(scan_output.contains("sample.txt:1:4: [blocking] known-secret"));
    assert!(scan_output.contains("known-value coverage checked 1 value(s)"));
    assert!(!scan_output.contains("known-secret-value"));
    assert!(!scan_output.contains("redacted-in-working-tree"));
    Ok(())
}

#[test]
fn redact_replaces_provider_tokens() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let sample_path = directory.path().join("sample.log");
    std::fs::write(&sample_path, "token=ghp_sampleTokenValue123\n")?;
    let context = test_context(&directory);
    let mut output = Vec::new();

    run_with_context(
        Cli::try_parse_from(["locket", "redact", "sample.log"])?,
        &context,
        &mut output,
    )?;

    let output = String::from_utf8(output)?;
    assert!(output.contains("lk_redacted_PROVIDER_TOKEN"));
    assert!(!output.contains("ghp_sampleTokenValue123"));
    Ok(())
}

#[test]
fn redact_replaces_active_and_grace_known_values() -> Result<(), Box<dyn std::error::Error>> {
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
    let timestamp = crate::now_unix_nanos()?;
    let rotate_args = test_rotate_args("DATABASE_URL", Some("24h"));
    let grace_until = crate::grace_until_from_args(rotate_args.grace_ttl.as_deref(), timestamp)?;
    crate::rotate_secret_value(
        &context,
        &rotate_args,
        "postgres://localhost/new",
        timestamp,
        grace_until,
    )?;

    std::fs::write(
        directory.path().join("sample.log"),
        "old=postgres://localhost/old\nnew=postgres://localhost/new\n",
    )?;
    let mut redact_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "redact", "sample.log"])?,
        &context,
        &mut redact_output,
    )?;

    let redact_output = String::from_utf8(redact_output)?;
    assert_eq!(redact_output.matches("lk_redacted_DATABASE_URL").count(), 2);
    assert!(!redact_output.contains("postgres://localhost/old"));
    assert!(!redact_output.contains("postgres://localhost/new"));
    Ok(())
}

#[test]
fn redact_names_uses_privacy_alias_for_known_values() -> Result<(), Box<dyn std::error::Error>> {
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
    std::fs::write(directory.path().join("sample.log"), "db=postgres://localhost/app\n")?;

    let mut redact_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "redact", "--redact-names", "sample.log"])?,
        &context,
        &mut redact_output,
    )?;

    let redact_output = String::from_utf8(redact_output)?;
    assert!(redact_output.contains("lk_redacted_secret-"));
    assert!(!redact_output.contains("lk_redacted_DATABASE_URL"));
    assert!(!redact_output.contains("postgres://localhost/app"));
    Ok(())
}

#[test]
fn redact_writes_audit_row_with_counts_and_names() -> Result<(), Box<dyn std::error::Error>> {
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
    std::fs::write(directory.path().join("sample.log"), "db=postgres://localhost/app\n")?;

    let mut redact_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "redact", "sample.log"])?,
        &context,
        &mut redact_output,
    )?;

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'REDACT'",
        [],
        |row| row.get(0),
    )?;
    assert!(metadata.contains("\"action\":\"REDACT\""));
    assert!(metadata.contains("\"input_kind\":\"file\""));
    assert!(metadata.contains("\"known_coverage_active\":true"));
    assert!(metadata.contains("\"DATABASE_URL\""));
    assert!(metadata.contains("\"known_secret_value\""));
    assert!(!metadata.contains("postgres://"));
    Ok(())
}

#[test]
fn redact_require_known_without_project_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    std::fs::write(directory.path().join("sample.log"), "anything\n")?;

    let mut redact_output = Vec::new();
    let result = run_with_context(
        Cli::try_parse_from(["locket", "redact", "--require-known", "sample.log"])?,
        &context,
        &mut redact_output,
    );
    let Err(crate::CliError::Typed { kind, message }) = result else {
        return Err(format!("expected typed project-not-found error, got {result:?}").into());
    };
    assert_eq!(kind, locket_core::LocketError::ProjectNotFound);
    assert_eq!(message, "project not found");
    Ok(())
}

#[test]
fn redact_warns_when_known_coverage_skipped_without_project()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    std::fs::write(directory.path().join("sample.log"), "abcdef\n")?;

    let mut redact_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "redact", "sample.log"])?,
        &context,
        &mut redact_output,
    )?;

    let coverage = crate::collect_redaction_values_for_redact(
        &context,
        None,
        false,
        false,
        crate::now_unix_nanos()?,
    )?;
    assert!(!coverage.known_coverage_active);
    assert!(coverage.skipped_message.is_some());
    Ok(())
}

#[test]
fn scan_warning_only_provider_token_returns_zero_exit_code()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    std::fs::write(directory.path().join("notes.txt"), "token=sk_test_warningTokenValueA\n")?;

    let mut scan_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "scan", "notes.txt"])?,
        &context,
        &mut scan_output,
    )?;

    let scan_output = String::from_utf8(scan_output)?;
    assert!(scan_output.contains("[warning] provider-token-pattern"));
    assert!(scan_output.contains("scan: 1 finding(s) (blocking=0 warning=1)"));
    Ok(())
}

#[test]
fn scan_blocking_known_secret_fails_with_exit_69() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    let args = test_secret_write_args("DATABASE_URL");
    crate::set_secret_value(&context, &args, "block-me-secret-value", "manual", 1_000)?;
    std::fs::write(directory.path().join("leak.txt"), "db=block-me-secret-value\n")?;

    let mut scan_output = Vec::new();
    let result = run_with_context(
        Cli::try_parse_from(["locket", "scan", "--require-known", "leak.txt"])?,
        &context,
        &mut scan_output,
    );

    let Err(error) = result else {
        return Err("blocking scan finding must surface a typed error".into());
    };
    assert_eq!(error.exit_code(), 69);
    let scan_output = String::from_utf8(scan_output)?;
    assert!(scan_output.contains("[blocking] known-secret"));
    assert!(scan_output.contains("(blocking=1 warning=0)"));
    assert!(!scan_output.contains("block-me-secret-value"));
    Ok(())
}

#[test]
fn scan_suppressed_audit_row_records_severity_breakdown() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    let entropy_token = "Z9a$kLmN2pQx7R!sT4vW8yB3cD6eF";
    std::fs::write(
        directory.path().join("mixed.txt"),
        format!(
            "high={entropy_token} # locket-allow: known fixture\n\
             pat=sk_test_warningTokenValueB\n",
        ),
    )?;

    let mut scan_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "scan", "mixed.txt"])?,
        &context,
        &mut scan_output,
    )?;

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'SCAN' AND status = 'SUPPRESSED'",
        [],
        |row| row.get(0),
    )?;
    assert!(metadata.contains("\"command\":\"scan\""));
    assert!(metadata.contains("\"kept_warning_count\":1"));
    assert!(metadata.contains("\"kept_blocking_count\":0"));
    assert!(metadata.contains("\"severity\":\"warning\""));
    assert!(!metadata.contains(entropy_token));
    assert!(!metadata.contains("sk_test_warningTokenValueB"));
    Ok(())
}
