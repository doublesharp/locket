//! Mutation tests for pinned `lk://...@vN` resolution past `grace_until`.
//!
//! Covers `resolve_pinned_version` and the scan-eligibility gate
//! (`should_scan_known_version`-equivalent behavior) for deprecated versions
//! whose grace window has expired or was never set.
#[allow(unused_imports)]
use super::*;

use locket_store::{SecretRecord, SecretVersionRecord};

fn make_secret(name: &str, current_version: u32, state: &str) -> SecretRecord {
    SecretRecord {
        id: "lk_secret_test".to_owned(),
        project_id: "lk_proj_test".to_owned(),
        profile_id: "lk_prof_test".to_owned(),
        name: name.to_owned(),
        source: "user-local".to_owned(),
        origin: "manual".to_owned(),
        current_version,
        state: state.to_owned(),
        created_at: 1_000,
        updated_at: 1_000,
        last_rotated_at: None,
        deleted_at: None,
    }
}

fn make_version(
    version: u32,
    state: &str,
    deprecated_at: Option<i64>,
    grace_until: Option<i64>,
) -> SecretVersionRecord {
    SecretVersionRecord {
        secret_id: "lk_secret_test".to_owned(),
        version,
        source: "user-local".to_owned(),
        origin: "manual".to_owned(),
        state: state.to_owned(),
        created_at: 1_000,
        deprecated_at,
        grace_until,
        purged_at: None,
    }
}

#[test]
fn resolve_pinned_current_version_succeeds() -> Result<(), Box<dyn std::error::Error>> {
    let secret = make_secret("DATABASE_URL", 2, "active");
    let version = make_version(2, "current", None, None);
    crate::resolve_pinned_version(&secret, &version, 5_000)?;
    Ok(())
}

#[test]
fn resolve_pinned_deprecated_version_with_active_grace_succeeds()
-> Result<(), Box<dyn std::error::Error>> {
    let secret = make_secret("DATABASE_URL", 2, "active");
    let version = make_version(1, "deprecated", Some(1_500), Some(10_000));
    crate::resolve_pinned_version(&secret, &version, 5_000)?;
    Ok(())
}

#[test]
fn resolve_pinned_deprecated_version_past_grace_returns_secret_version_expired()
-> Result<(), Box<dyn std::error::Error>> {
    let secret = make_secret("DATABASE_URL", 2, "active");
    let version = make_version(1, "deprecated", Some(1_500), Some(2_000));
    let result = crate::resolve_pinned_version(&secret, &version, 5_000);
    let Err(error) = result else {
        return Err("expired grace window must reject pinned resolution".into());
    };
    assert_eq!(
        error.exit_code(),
        locket_core::LocketError::SecretVersionExpired.exit_code(),
        "SecretVersionExpired is exit 75"
    );
    assert!(error.to_string().contains("DATABASE_URL"));
    assert!(error.to_string().contains("v1"));
    Ok(())
}

#[test]
fn resolve_pinned_deprecated_version_at_grace_boundary_returns_secret_version_expired()
-> Result<(), Box<dyn std::error::Error>> {
    // grace_until == timestamp must fail closed: the spec says "still in the future".
    let secret = make_secret("DATABASE_URL", 2, "active");
    let version = make_version(1, "deprecated", Some(1_500), Some(5_000));
    let result = crate::resolve_pinned_version(&secret, &version, 5_000);
    let Err(error) = result else {
        return Err("grace boundary (grace_until == now) must fail closed".into());
    };
    assert_eq!(error.exit_code(), locket_core::LocketError::SecretVersionExpired.exit_code());
    Ok(())
}

#[test]
fn resolve_pinned_deprecated_version_without_grace_returns_secret_version_expired()
-> Result<(), Box<dyn std::error::Error>> {
    // Rotation without `--grace-ttl` leaves grace_until null; pinned access must fail.
    let secret = make_secret("DATABASE_URL", 2, "active");
    let version = make_version(1, "deprecated", Some(1_500), None);
    let result = crate::resolve_pinned_version(&secret, &version, 5_000);
    let Err(error) = result else {
        return Err("ungraced deprecated version must fail closed".into());
    };
    assert_eq!(error.exit_code(), locket_core::LocketError::SecretVersionExpired.exit_code());
    Ok(())
}

#[test]
fn resolve_pinned_purged_version_returns_secret_version_expired()
-> Result<(), Box<dyn std::error::Error>> {
    let secret = make_secret("DATABASE_URL", 2, "active");
    let version = SecretVersionRecord {
        secret_id: "lk_secret_test".to_owned(),
        version: 1,
        source: "user-local".to_owned(),
        origin: "manual".to_owned(),
        state: "purged".to_owned(),
        created_at: 1_000,
        deprecated_at: Some(1_500),
        grace_until: None,
        purged_at: Some(2_000),
    };
    let result = crate::resolve_pinned_version(&secret, &version, 5_000);
    let Err(error) = result else {
        return Err("purged version must fail closed".into());
    };
    assert_eq!(error.exit_code(), locket_core::LocketError::SecretVersionExpired.exit_code());
    Ok(())
}

#[test]
fn resolve_pinned_version_for_deleted_secret_source_returns_secret_deleted()
-> Result<(), Box<dyn std::error::Error>> {
    let secret = make_secret("DATABASE_URL", 2, "deleted");
    let version = make_version(2, "current", None, None);
    let result = crate::resolve_pinned_version(&secret, &version, 5_000);
    let Err(error) = result else {
        return Err("deleted secret source must reject pinned resolution".into());
    };
    assert_eq!(error.exit_code(), locket_core::LocketError::SecretDeleted.exit_code());
    Ok(())
}

#[test]
fn scan_excludes_deprecated_version_after_grace_expiry_via_rotate_then_purge()
-> Result<(), Box<dyn std::error::Error>> {
    // End-to-end variant: rotate with a grace TTL, then purge the deprecated
    // version (purge clears grace_until and sets state=purged). Subsequent
    // scans must not match the old value, mirroring expired-grace semantics
    // for known-value scans.
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;

    let args = test_secret_write_args("DATABASE_URL");
    crate::set_secret_value(&context, &args, "expired-old-fixture", "manual", 1_000)?;
    let rotate_args = test_rotate_args("DATABASE_URL", Some("24h"));
    let timestamp = crate::now_unix_nanos()?;
    let grace_until = crate::grace_until_from_args(rotate_args.grace_ttl.as_deref(), timestamp)?;
    crate::rotate_secret_value(
        &context,
        &rotate_args,
        "expired-new-fixture",
        timestamp,
        grace_until,
    )?;

    // Force-purge the deprecated v1 to simulate post-grace state.
    run_with_context(
        Cli::try_parse_from(["locket", "purge", "DATABASE_URL", "--version", "1", "--force"])?,
        &context,
        &mut Vec::new(),
    )?;

    std::fs::write(directory.path().join("expired.txt"), "db=expired-old-fixture\n")?;
    let mut scan_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "scan", "--require-known", "expired.txt"])?,
        &context,
        &mut scan_output,
    )?;
    let scan_output = String::from_utf8(scan_output)?;
    assert!(scan_output.contains("known-value coverage checked 1 value(s)"));
    assert!(!scan_output.contains("[blocking] known-secret"));
    assert!(!scan_output.contains("expired-old-fixture"));
    Ok(())
}
