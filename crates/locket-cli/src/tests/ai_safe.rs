#[allow(unused_imports)]
use super::*;

#[test]
fn ai_safe_redacts_child_output_and_transcript() -> Result<(), Box<dyn std::error::Error>> {
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

    let mut ai_safe_output = Vec::new();
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "ai-safe",
            "--output",
            "transcript.log",
            "--",
            "/bin/sh",
            "-c",
            "printf 'db=postgres://localhost/app\n'; printf 'err=postgres://localhost/app\n' >&2",
        ])?,
        &context,
        &mut ai_safe_output,
    )?;

    let ai_safe_output = String::from_utf8(ai_safe_output)?;
    let transcript = std::fs::read_to_string(directory.path().join("transcript.log"))?;
    assert!(ai_safe_output.contains("lk_redacted_DATABASE_URL"));
    assert!(transcript.contains("lk_redacted_DATABASE_URL"));
    assert!(transcript.contains("[stdout timestamp="));
    assert!(transcript.contains("[stderr timestamp="));
    assert!(!ai_safe_output.contains("postgres://localhost/app"));
    assert!(!transcript.contains("postgres://localhost/app"));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mode = std::fs::metadata(directory.path().join("transcript.log"))?.permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'REDACT'",
        [],
        |row| row.get(0),
    )?;
    let metadata: serde_json::Value = serde_json::from_str(&metadata)?;
    assert_eq!(metadata["scope"], "ai-safe");
    assert_eq!(metadata["pattern_only"], false);
    assert_eq!(metadata["known_value_coverage"], true);
    assert_eq!(metadata["output_destinations"]["transcript"], true);
    assert_eq!(metadata["redacted_secret_names"], json!(["DATABASE_URL"]));
    assert_eq!(metadata["finding_counts"]["known_secret_value"], 2);
    assert!(!metadata.to_string().contains("postgres://localhost/app"));
    Ok(())
}

#[test]
fn ai_safe_redacts_known_secret_across_partial_line_flush_boundary() {
    let secret = "SPLIT_SECRET_VALUE";
    let redactions = vec![crate::KnownSecretRedaction {
        value: zeroize::Zeroizing::new(secret.to_owned()),
        marker: "lk_redacted_SPLIT_SECRET".to_owned(),
        secret_name: Some("SPLIT_SECRET".to_owned()),
    }];
    let mut redactor = crate::AiSafeStreamRedactor::new(&redactions);
    let prefix_len = crate::AI_SAFE_PARTIAL_LINE_MAX_BYTES - 5;
    let mut first = vec![b'a'; prefix_len];
    first.extend_from_slice(&secret.as_bytes()[..5]);

    let first_chunks =
        redactor.push(crate::AiSafeRawChunk { stream: crate::AiSafeStream::Stdout, bytes: first });
    let first_text = first_chunks.iter().map(|chunk| chunk.text.as_str()).collect::<String>();
    assert!(!first_text.contains(&secret[..5]));

    let mut second = secret.as_bytes()[5..].to_vec();
    second.push(b'\n');
    let mut chunks =
        redactor.push(crate::AiSafeRawChunk { stream: crate::AiSafeStream::Stdout, bytes: second });
    chunks.extend(redactor.finish());
    let text = chunks.iter().map(|chunk| chunk.text.as_str()).collect::<String>();

    assert!(text.contains("lk_redacted_SPLIT_SECRET"));
    assert!(!text.contains(secret));
}

#[test]
fn ai_safe_fails_closed_when_locked_unless_pattern_only() -> Result<(), Box<dyn std::error::Error>>
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
    let (project_id, _) = test_project_id_and_master_key(&context)?;
    context.key_store.delete_master_key(&project_id)?;

    let mut default_output = Vec::new();
    let default_result = run_with_context(
        Cli::try_parse_from(["locket", "ai-safe", "--", "/bin/sh", "-c", "touch spawned-default"])?,
        &context,
        &mut default_output,
    );
    assert_error_contains(default_result, "UnlockRequired");
    assert!(!directory.path().join("spawned-default").exists());

    let mut pattern_output = Vec::new();
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "ai-safe",
            "--pattern-only",
            "--",
            "/bin/sh",
            "-c",
            "printf 'token=sk_test_sampleTokenValue123\n'; touch spawned-pattern",
        ])?,
        &context,
        &mut pattern_output,
    )?;
    let pattern_output = String::from_utf8(pattern_output)?;
    assert!(pattern_output.contains("lk_redacted_PROVIDER_TOKEN"));
    assert!(!pattern_output.contains("sk_test_sampleTokenValue123"));
    assert!(directory.path().join("spawned-pattern").exists());
    Ok(())
}

#[test]
fn ai_safe_without_project_uses_project_not_found() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);

    let result = run_with_context(
        Cli::try_parse_from(["locket", "ai-safe", "--", "/bin/sh", "-c", "true"])?,
        &context,
        &mut Vec::new(),
    );
    let Err(error) = result else {
        return Err("ai-safe should fail closed outside a Locket project".into());
    };
    assert_eq!(error.exit_code(), 64);
    let crate::CliError::Typed { kind, message } = error else {
        return Err("ai-safe should return a typed project-not-found error".into());
    };
    assert_eq!(kind, locket_core::LocketError::ProjectNotFound);
    assert_eq!(message, "project not found");
    Ok(())
}

#[test]
fn ai_safe_uses_privacy_config_aliases_but_audits_exact_names()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    run_with_context(
        Cli::try_parse_from(["locket", "config", "set", "privacy.redact_names", "true"])?,
        &context,
        &mut Vec::new(),
    )?;
    let args = test_secret_write_args("DATABASE_URL");
    crate::set_secret_value(&context, &args, "postgres://localhost/app", "manual", 1_000)?;

    let mut ai_safe_output = Vec::new();
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "ai-safe",
            "--",
            "/bin/sh",
            "-c",
            "printf 'db=postgres://localhost/app\n'",
        ])?,
        &context,
        &mut ai_safe_output,
    )?;
    let ai_safe_output = String::from_utf8(ai_safe_output)?;
    assert!(ai_safe_output.contains("lk_redacted_secret-"));
    assert!(!ai_safe_output.contains("lk_redacted_DATABASE_URL"));
    assert!(!ai_safe_output.contains("postgres://localhost/app"));

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'REDACT'",
        [],
        |row| row.get(0),
    )?;
    let metadata: serde_json::Value = serde_json::from_str(&metadata)?;
    assert_eq!(metadata["redact_names"], true);
    assert_eq!(metadata["redacted_secret_names"], json!(["DATABASE_URL"]));
    assert!(!metadata.to_string().contains("postgres://localhost/app"));
    Ok(())
}

#[test]
fn ai_safe_transcript_force_repairs_permissions_and_child_exit_is_forwarded()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let transcript_path = directory.path().join("transcript.log");
    std::fs::write(&transcript_path, "old\n")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mut permissions = std::fs::metadata(&transcript_path)?.permissions();
        permissions.set_mode(0o644);
        std::fs::set_permissions(&transcript_path, permissions)?;
    }

    let mut no_force_output = Vec::new();
    let no_force_result = run_with_context(
        Cli::try_parse_from([
            "locket",
            "ai-safe",
            "--pattern-only",
            "--output",
            "transcript.log",
            "--",
            "/bin/sh",
            "-c",
            "true",
        ])?,
        &context,
        &mut no_force_output,
    );
    assert!(no_force_result.is_err());

    let mut forced_output = Vec::new();
    let forced_result = run_with_context(
        Cli::try_parse_from([
            "locket",
            "ai-safe",
            "--pattern-only",
            "--force",
            "--output",
            "transcript.log",
            "--",
            "/bin/sh",
            "-c",
            "printf 'token=sk_test_sampleTokenValue123'; exit 7",
        ])?,
        &context,
        &mut forced_output,
    );
    let Err(error) = forced_result else {
        return Err("ai-safe should forward child exit status".into());
    };
    assert_eq!(error.exit_code(), 7);
    let forced_output = String::from_utf8(forced_output)?;
    let transcript = std::fs::read_to_string(&transcript_path)?;
    assert!(forced_output.contains("lk_redacted_PROVIDER_TOKEN"));
    assert!(transcript.contains("lk_redacted_PROVIDER_TOKEN"));
    assert!(!transcript.contains("sk_test_sampleTokenValue123"));
    assert!(!transcript.contains("old"));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mode = std::fs::metadata(&transcript_path)?.permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    Ok(())
}
