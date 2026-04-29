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
    assert!(scan_output.contains("visible.txt:1:7: provider-token-pattern"));
    assert!(!scan_output.contains("ignored.txt"));
    assert!(!scan_output.contains("sk_test_sampleTokenValue123"));
    assert!(!scan_output.contains("sk_test_visibleTokenValue123"));
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
    run_with_context(
        Cli::try_parse_from(["locket", "scan", "--require-known", "leak.txt"])?,
        &context,
        &mut scan_output,
    )?;

    let scan_output = String::from_utf8(scan_output)?;
    assert!(scan_output.contains("leak.txt:1:4: known-secret"));
    assert!(scan_output.contains("scan: 1 finding(s)"));
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
    run_with_context(
        Cli::try_parse_from(["locket", "scan", "--require-known", "sample.txt"])?,
        &context,
        &mut scan_output,
    )?;

    let scan_output = String::from_utf8(scan_output)?;
    assert!(scan_output.contains("known-secret"));
    assert!(scan_output.contains("known-value coverage checked 1 value(s)"));
    assert!(!scan_output.contains("known-secret-value"));
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
    run_with_context(
        Cli::try_parse_from(["locket", "scan", "--staged", "--require-known"])?,
        &context,
        &mut scan_output,
    )?;

    let scan_output = String::from_utf8(scan_output)?;
    assert!(scan_output.contains("sample.txt:1:4: known-secret"));
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
    let Err(crate::CliError::Config(message)) = result else {
        return Err(format!("expected CliError::Config, got {result:?}").into());
    };
    assert!(message.contains("known-value redaction"));
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
