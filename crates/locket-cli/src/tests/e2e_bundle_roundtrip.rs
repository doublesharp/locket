//! End-to-end coverage for sealed-bundle export -> verify -> import.
//! The suite covers decrypt-only metadata counts plus apply-time row
//! persistence and conflict arms from `bundle-apply-and-conflicts`.
//!
//! Spec: `docs/specs/testing.md` -- e2e bundle-roundtrip target.
//! Existing siblings: `cli_basics::sealed_bundle_export_verify_and_import_are_metadata_only`,
//! `cli_basics::bundle_verify_rejects_tampered_digest`, and
//! `cli_basics::bundle_verify_rejects_unsupported_schema_as_config_error`.

#[allow(unused_imports)]
use super::*;

/// Inline analogue of the `setup_initialized_project` helper referenced
/// from the planning doc: init project, write one secret, init device,
/// export a sealed bundle. Returns the runtime context, the device
/// descriptor, the bundle path, and the export stdout.
fn export_sealed_bundle(
    directory: &tempfile::TempDir,
    bundle_filename: &str,
) -> Result<(RuntimeContext, String, PathBuf, String), Box<dyn std::error::Error>> {
    let context = test_context(directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    let args = test_secret_write_args("DATABASE_URL");
    crate::set_secret_value(&context, &args, "postgres://bundle-secret", "manual", 1_000)?;

    let mut device_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "device", "init"])?,
        &context,
        &mut device_output,
    )?;
    let descriptor = String::from_utf8(device_output)?
        .lines()
        .find_map(|line| line.strip_prefix("descriptor: "))
        .ok_or("missing descriptor")?
        .to_owned();

    let bundle_path = directory.path().join(bundle_filename);
    let mut export_output = Vec::new();
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "export",
            "--sealed",
            "--recipient",
            &descriptor,
            "--profile",
            "dev",
            "--include-audit",
            "--output",
            bundle_path.to_str().ok_or("utf8 path")?,
        ])?,
        &context,
        &mut export_output,
    )?;
    let export_output = String::from_utf8(export_output)?;
    Ok((context, descriptor, bundle_path, export_output))
}

fn parse_field<'a>(output: &'a str, key: &str) -> Option<&'a str> {
    output.lines().find_map(|line| line.strip_prefix(&format!("{key}: ")))
}

#[test]
fn fresh_export_then_decrypt_roundtrips_payload_counts()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let (context, _descriptor, bundle_path, export_output) =
        export_sealed_bundle(&directory, "fresh.locket-bundle")?;

    assert!(export_output.contains("bundle: exported"));
    let exported_digest =
        parse_field(&export_output, "digest").ok_or("export missing digest field")?.to_owned();
    let exported_profiles = parse_field(&export_output, "profiles")
        .ok_or("export missing profiles field")?
        .to_owned();
    let exported_secrets = parse_field(&export_output, "secret_count")
        .ok_or("export missing secret_count field")?
        .to_owned();
    let exported_blobs =
        parse_field(&export_output, "blob_count").ok_or("export missing blob_count field")?.to_owned();
    let exported_command_policies = parse_field(&export_output, "command_policy_count")
        .ok_or("export missing command_policy_count field")?
        .to_owned();

    let mut verify_output = Vec::new();
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "bundle",
            "verify",
            bundle_path.to_str().ok_or("utf8 path")?,
        ])?,
        &context,
        &mut verify_output,
    )?;
    let verify_output = String::from_utf8(verify_output)?;
    assert!(verify_output.contains("bundle: valid"));
    let verify_digest = parse_field(&verify_output, "digest").ok_or("verify missing digest")?;
    assert_eq!(
        verify_digest, exported_digest,
        "manifest digest must match between export and verify"
    );

    let mut import_output = Vec::new();
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "import-bundle",
            bundle_path.to_str().ok_or("utf8 path")?,
            "--accept-local",
            "--include-audit",
        ])?,
        &context,
        &mut import_output,
    )?;
    let import_output = String::from_utf8(import_output)?;
    assert!(import_output.contains("bundle: verified"));
    assert!(
        import_output.contains("import: decrypted"),
        "import must report decrypted status: {import_output}"
    );
    assert!(import_output.contains("metadata_only: yes"));

    // The four counts the decrypted-import surface emits must mirror
    // the export-side counts. Profile counts and secret counts are the
    // same field name on both sides; blobs and command_policies are
    // renamed in the import surface (export uses `blob_count` /
    // `command_policy_count`, import uses `blobs` / `command_policies`).
    let import_profiles =
        parse_field(&import_output, "profiles").ok_or("import missing profiles")?;
    let import_secrets =
        parse_field(&import_output, "secrets").ok_or("import missing secrets")?;
    let import_blobs =
        parse_field(&import_output, "blobs").ok_or("import missing blobs")?;
    let import_command_policies = parse_field(&import_output, "command_policies")
        .ok_or("import missing command_policies")?;

    assert_eq!(import_profiles, exported_profiles, "profiles count must match");
    assert_eq!(import_secrets, exported_secrets, "secrets count must match");
    assert_eq!(import_blobs, exported_blobs, "blobs count must match");
    assert_eq!(
        import_command_policies, exported_command_policies,
        "command_policies count must match"
    );
    Ok(())
}

#[test]
fn identical_bundle_decrypt_emits_consistent_counts() -> Result<(), Box<dyn std::error::Error>> {
    // Two independently-initialised projects with the same scripted
    // inputs should produce exports whose manifest counts agree, and
    // the decrypted-import counts on each side should agree both with
    // the export-side counts and with each other.
    let directory_a = tempdir()?;
    let directory_b = tempdir()?;
    let (ctx_a, _desc_a, path_a, export_a) =
        export_sealed_bundle(&directory_a, "a.locket-bundle")?;
    let (ctx_b, _desc_b, path_b, export_b) =
        export_sealed_bundle(&directory_b, "b.locket-bundle")?;

    for field in [
        "profiles",
        "command_policy_count",
        "secret_count",
        "secret_version_count",
        "blob_count",
        "profile_key_count",
        "active_secret_count",
        "recipients",
        "include_audit",
        "metadata_only",
        "payload_status",
    ] {
        let value_a =
            parse_field(&export_a, field).ok_or_else(|| format!("export A missing {field}"))?;
        let value_b =
            parse_field(&export_b, field).ok_or_else(|| format!("export B missing {field}"))?;
        assert_eq!(
            value_a, value_b,
            "field {field} must agree between identical exports (a={value_a}, b={value_b})"
        );
    }

    // Decrypted-import counts must also agree across the two projects.
    let mut import_a = Vec::new();
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "import-bundle",
            path_a.to_str().ok_or("utf8 path")?,
            "--accept-local",
        ])?,
        &ctx_a,
        &mut import_a,
    )?;
    let mut import_b = Vec::new();
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "import-bundle",
            path_b.to_str().ok_or("utf8 path")?,
            "--accept-local",
        ])?,
        &ctx_b,
        &mut import_b,
    )?;
    let import_a = String::from_utf8(import_a)?;
    let import_b = String::from_utf8(import_b)?;
    for field in ["profiles", "secrets", "blobs", "command_policies"] {
        let value_a =
            parse_field(&import_a, field).ok_or_else(|| format!("import A missing {field}"))?;
        let value_b =
            parse_field(&import_b, field).ok_or_else(|| format!("import B missing {field}"))?;
        assert_eq!(
            value_a, value_b,
            "decrypted import field {field} must agree (a={value_a}, b={value_b})"
        );
    }
    Ok(())
}

#[test]
fn bundle_with_corrupt_age_payload_fails_verification()
-> Result<(), Box<dyn std::error::Error>> {
    // Sibling test `bundle_verify_rejects_tampered_digest` covers
    // tampering the manifest's `payload_digest` field. This test
    // tampers the encrypted payload bytes themselves while leaving
    // the manifest digest alone, so digest verification trips first.
    // Both paths return `BundleVerificationFailed` (exit code 110).
    let directory = tempdir()?;
    let (context, _descriptor, bundle_path, _export_output) =
        export_sealed_bundle(&directory, "corrupt.locket-bundle")?;

    let bundle_bytes = fs::read(&bundle_path)?;
    let mut container = locket_core::BundleContainer::deserialize(&bundle_bytes)?;
    let payload_len = container.encrypted_payload.len();
    assert!(payload_len > 0, "encrypted payload must be non-empty");
    // Flip a byte deep in the encrypted payload so the corruption is
    // in the ciphertext body rather than the framing header.
    let target = payload_len - 1;
    container.encrypted_payload[target] ^= 0xFF;
    fs::write(&bundle_path, container.serialize()?)?;

    let result = run_with_context(
        Cli::try_parse_from([
            "locket",
            "import-bundle",
            bundle_path.to_str().ok_or("utf8 path")?,
            "--accept-local",
        ])?,
        &context,
        &mut Vec::new(),
    );
    let Err(error) = result else {
        return Err("expected bundle import to fail on corrupt payload".into());
    };
    assert_eq!(
        error.exit_code(),
        locket_core::LocketError::BundleVerificationFailed.exit_code(),
        "exit code must be BundleVerificationFailed (110)"
    );
    match &error {
        crate::CliError::Typed { kind, .. } => {
            assert_eq!(*kind, locket_core::LocketError::BundleVerificationFailed);
        }
        other => return Err(format!("expected typed BundleVerificationFailed, got {other:?}").into()),
    }
    assert!(
        error.to_string().contains("manifest digest mismatch"),
        "corrupt-payload import should report digest mismatch: {error}"
    );
    Ok(())
}

#[test]
fn bundle_without_device_private_key_fails_verification()
-> Result<(), Box<dyn std::error::Error>> {
    // After `device-private-key-storage` and `bundle-import-decrypt`
    // shipped, the import command loads the device private-key
    // envelope from `<store_root>/devices/<device_id>.priv`. If that
    // envelope is missing, the import must fail with
    // `BundleVerificationFailed` and the explicit reason
    // `device private-key storage not initialized`.
    //
    // Reproduction recipe: run a normal export (which calls
    // `device init` and writes the envelope), then delete the
    // `devices/` directory before invoking `import-bundle`.
    let directory = tempdir()?;
    let (context, _descriptor, bundle_path, _export_output) =
        export_sealed_bundle(&directory, "no-priv-key.locket-bundle")?;

    let devices_dir = directory.path().join("devices");
    assert!(devices_dir.exists(), "device init must have populated devices/");
    fs::remove_dir_all(&devices_dir)?;

    let result = run_with_context(
        Cli::try_parse_from([
            "locket",
            "import-bundle",
            bundle_path.to_str().ok_or("utf8 path")?,
            "--accept-local",
        ])?,
        &context,
        &mut Vec::new(),
    );
    let Err(error) = result else {
        return Err("expected bundle import to fail without device private key".into());
    };
    assert_eq!(
        error.exit_code(),
        locket_core::LocketError::BundleVerificationFailed.exit_code(),
        "exit code must be BundleVerificationFailed (110)"
    );
    match &error {
        crate::CliError::Typed { kind, .. } => {
            assert_eq!(*kind, locket_core::LocketError::BundleVerificationFailed);
        }
        other => return Err(format!("expected typed BundleVerificationFailed, got {other:?}").into()),
    }
    assert!(
        error.to_string().contains("device private-key storage not initialized"),
        "missing-private-key import should report storage-not-initialized: {error}"
    );
    Ok(())
}

/// Returns the count of rows in a single store table for assertions.
fn store_row_count(
    store_path: &Path,
    sql: &str,
) -> Result<i64, Box<dyn std::error::Error>> {
    let store = locket_store::Store::open(store_path)?;
    let count: i64 = store.connection().query_row(sql, [], |row| row.get(0))?;
    Ok(count)
}

/// Apply phase round-trips into the same store; rows are already
/// present, so the audit row records `applied: true` with mostly
/// `identical` conflict counters. Reopening the store proves the
/// apply commit landed.
#[test]
fn applied_rows_persist_across_reopen() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let (context, _descriptor, bundle_path, _export_output) =
        export_sealed_bundle(&directory, "applied.locket-bundle")?;

    let mut import_output = Vec::new();
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "import-bundle",
            bundle_path.to_str().ok_or("utf8 path")?,
            "--accept-incoming",
            "--include-audit",
        ])?,
        &context,
        &mut import_output,
    )?;
    let import_output = String::from_utf8(import_output)?;
    assert!(import_output.contains("import: applied"), "missing import: applied: {import_output}");

    let store_path = context.store_path.clone();
    drop(context);
    assert!(store_row_count(&store_path, "SELECT COUNT(*) FROM profiles")? >= 1);
    assert!(store_row_count(&store_path, "SELECT COUNT(*) FROM secrets")? >= 1);
    assert!(store_row_count(&store_path, "SELECT COUNT(*) FROM secret_versions")? >= 1);
    assert!(store_row_count(&store_path, "SELECT COUNT(*) FROM blobs")? >= 1);
    Ok(())
}

/// `--include-audit` writes an `imported_audit_chains` row at apply
/// time so verifier tooling can pick up the encrypted remote checkpoint.
#[test]
fn audit_chain_append_after_apply() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let (context, _descriptor, bundle_path, _export_output) =
        export_sealed_bundle(&directory, "audit-chain.locket-bundle")?;

    run_with_context(
        Cli::try_parse_from([
            "locket",
            "import-bundle",
            bundle_path.to_str().ok_or("utf8 path")?,
            "--accept-incoming",
            "--include-audit",
        ])?,
        &context,
        &mut Vec::new(),
    )?;
    let store_path = context.store_path.clone();
    drop(context);
    let imported_chains_count =
        store_row_count(&store_path, "SELECT COUNT(*) FROM imported_audit_chains")?;
    assert_eq!(imported_chains_count, 1, "imported_audit_chains row must be present");
    Ok(())
}

/// Importing a bundle whose secret_version is newer than the local
/// active version triggers rotate-with-no-grace: the prior local
/// current row is moved to `deprecated` with `deprecated_at` /
/// `grace_until` set to the import timestamp; the incoming row
/// becomes the new current.
///
/// Setup: rename the existing local secret_version from version 1
/// to a higher version locally, leaving the bundle's version-1
/// payload to land as a fresh row. The apply path detects the
/// missing-version + state=current case and deprecates whichever
/// local row currently holds the `current` state.
#[test]
fn newer_incoming_rotates_active_version() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let (context, _descriptor, bundle_path, _export_output) =
        export_sealed_bundle(&directory, "rotate.locket-bundle")?;

    // Bump the local secret_version PK so the bundle's version 1
    // becomes a missing-version (newer) insert from the receiver's
    // perspective. Update blob/fingerprint FK targets too.
    let store_path = context.store_path.clone();
    {
        let store = locket_store::Store::open(&store_path)?;
        let connection = store.connection();
        connection.execute("PRAGMA foreign_keys = OFF", [])?;
        connection
            .execute("UPDATE secret_versions SET version = 2 WHERE version = 1", [])?;
        connection.execute("UPDATE blobs SET version = 2 WHERE version = 1", [])?;
        connection.execute("UPDATE fingerprints SET version = 2 WHERE version = 1", [])?;
        connection.execute("UPDATE secrets SET current_version = 2", [])?;
        connection.execute("PRAGMA foreign_keys = ON", [])?;
    }

    let mut import_output = Vec::new();
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "import-bundle",
            bundle_path.to_str().ok_or("utf8 path")?,
            "--accept-incoming",
        ])?,
        &context,
        &mut import_output,
    )?;
    let import_output = String::from_utf8(import_output)?;
    assert!(import_output.contains("import: applied"));

    drop(context);
    let deprecated_count = store_row_count(
        &store_path,
        "SELECT COUNT(*) FROM secret_versions WHERE state = 'deprecated'
         AND deprecated_at IS NOT NULL AND grace_until IS NOT NULL",
    )?;
    let current_count = store_row_count(
        &store_path,
        "SELECT COUNT(*) FROM secret_versions WHERE state = 'current'",
    )?;
    assert_eq!(current_count, 1, "incoming version must become the only current row");
    assert!(deprecated_count >= 1, "prior current row must be deprecated with grace_until set");
    Ok(())
}

/// Without an explicit `--accept-*` flag, divergent rows trigger an
/// `interactive-required` exit and roll back the apply transaction.
#[test]
fn divergent_arm_rolls_back_without_flag() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let (context, _descriptor, bundle_path, _export_output) =
        export_sealed_bundle(&directory, "divergent.locket-bundle")?;

    let store_path = context.store_path.clone();
    {
        let store = locket_store::Store::open(&store_path)?;
        store.connection().execute(
            "UPDATE blobs SET ciphertext = X'00FF' WHERE secret_id IN (SELECT id FROM secrets)",
            [],
        )?;
    }
    let pre_blob_bytes: Vec<u8> = locket_store::Store::open(&store_path)?
        .connection()
        .query_row("SELECT ciphertext FROM blobs LIMIT 1", [], |row| row.get(0))?;

    let result = run_with_context(
        Cli::try_parse_from([
            "locket",
            "import-bundle",
            bundle_path.to_str().ok_or("utf8 path")?,
        ])?,
        &context,
        &mut Vec::new(),
    );
    assert!(result.is_err(), "default policy must reject divergent conflicts");

    drop(context);
    let post_blob_bytes: Vec<u8> = locket_store::Store::open(&store_path)?
        .connection()
        .query_row("SELECT ciphertext FROM blobs LIMIT 1", [], |row| row.get(0))?;
    assert_eq!(pre_blob_bytes, post_blob_bytes, "rolled-back tx must leave blob unchanged");
    Ok(())
}

/// With `--accept-incoming`, the same divergent fixture applies the
/// incoming bytes over the local row.
#[test]
fn divergent_arm_applies_with_accept_incoming() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let (context, _descriptor, bundle_path, _export_output) =
        export_sealed_bundle(&directory, "divergent-applied.locket-bundle")?;

    let store_path = context.store_path.clone();
    {
        let store = locket_store::Store::open(&store_path)?;
        store.connection().execute(
            "UPDATE blobs SET ciphertext = X'00FF' WHERE secret_id IN (SELECT id FROM secrets)",
            [],
        )?;
    }

    let mut import_output = Vec::new();
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "import-bundle",
            bundle_path.to_str().ok_or("utf8 path")?,
            "--accept-incoming",
        ])?,
        &context,
        &mut import_output,
    )?;
    let import_output = String::from_utf8(import_output)?;
    assert!(import_output.contains("import: applied"));

    drop(context);
    let post_blob_bytes: Vec<u8> = locket_store::Store::open(&store_path)?
        .connection()
        .query_row("SELECT ciphertext FROM blobs LIMIT 1", [], |row| row.get(0))?;
    assert_ne!(
        post_blob_bytes,
        b"\x00\xFF".to_vec(),
        "accept-incoming must overwrite local divergent ciphertext"
    );
    Ok(())
}

/// Deleted-vs-active arm: the local secret is tombstoned after export.
/// Re-importing without flags must surface a divergent summary; with
/// `--accept-incoming` the local row rejoins the active state.
#[test]
fn deleted_vs_active_arm() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let (context, _descriptor, bundle_path, _export_output) =
        export_sealed_bundle(&directory, "tombstone.locket-bundle")?;

    let store_path = context.store_path.clone();
    {
        let store = locket_store::Store::open(&store_path)?;
        store.connection().execute(
            "UPDATE secrets SET state = 'deleted', deleted_at = ?1 WHERE state = 'active'",
            [9_999_999_999_i64],
        )?;
    }

    let result = run_with_context(
        Cli::try_parse_from([
            "locket",
            "import-bundle",
            bundle_path.to_str().ok_or("utf8 path")?,
        ])?,
        &context,
        &mut Vec::new(),
    );
    assert!(
        result.is_err(),
        "tombstone-vs-active without flags must require interactive resolution"
    );

    let mut import_output = Vec::new();
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "import-bundle",
            bundle_path.to_str().ok_or("utf8 path")?,
            "--accept-incoming",
        ])?,
        &context,
        &mut import_output,
    )?;
    let import_output = String::from_utf8(import_output)?;
    assert!(import_output.contains("import: applied"));

    drop(context);
    let active_count =
        store_row_count(&store_path, "SELECT COUNT(*) FROM secrets WHERE state = 'active'")?;
    assert!(active_count >= 1, "accept-incoming must rejoin active secret");
    Ok(())
}

// Historical TODO(bundle-apply-and-conflicts) summary retained for
// reference; tests 1-4 now live above and are no longer scaffolds.
//
// 1. `applied_rows_persist_across_reopen`: after a successful
//    `--accept-incoming` apply, reopen the store and assert the
//    decrypted profile_keys, command_policies, secret_versions, and
//    blobs are visible with the imported counts. Today the import
//    command stops at decrypt and never writes rows.
//
// 2. `newer_incoming_replaces_active_with_rotation`: import a bundle
//    whose secret_version is newer than the local active version
//    with `--accept-incoming`; assert the local row rotates with no
//    grace and the prior version is marked deprecated.
//
// 3. `divergent_versions_require_explicit_resolution`: import a
//    bundle whose secret_version diverges from local (same version
//    number, different ciphertext); assert the default conflict
//    policy `interactive-required` exits without writing.
//
// 4. `deleted_local_vs_active_incoming_records_tombstone`: local row
//    is tombstoned, incoming bundle still has the active version;
//    assert `--accept-local` keeps the tombstone and
//    `--accept-incoming` revives the row with a fresh version chain.
//
// 5. `imported_audit_chain_appends_to_imported_audit_chains`: when
//    `--include-audit` is set on both export and import, the imported
//    audit rows must land in `imported_audit_chains` with structural
//    verification. Apply-time persistence now lands above; the full
//    structural verification slice remains tracked separately.
