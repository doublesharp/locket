//! End-to-end coverage for the sealed-bundle export → verify → import
//! roundtrip. The decrypt half (`bundle-import-decrypt`) and the apply
//! half (`bundle-import-apply-rows` / `bundle-apply-and-conflicts`) are
//! still pending; these tests pin the metadata-only path that ships
//! today and leave a TODO breadcrumb for the cases that depend on the
//! decrypted import emitting structured counts.
//!
//! Spec: `docs/specs/testing.md` — e2e bundle-roundtrip target.
//! Existing siblings: `cli_basics::sealed_bundle_export_verify_and_import_are_metadata_only`,
//! `cli_basics::bundle_verify_rejects_tampered_digest`, and
//! `cli_basics::bundle_verify_rejects_unsupported_schema_as_config_error`.

#[allow(unused_imports)]
use super::*;

/// Inline analogue of the `setup_initialized_project` helper referenced
/// from the planning doc — kept local so this file is self-contained
/// and uses the same exported helpers as the existing bundle tests.
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

fn parse_export_field<'a>(output: &'a str, key: &str) -> Option<&'a str> {
    output.lines().find_map(|line| line.strip_prefix(&format!("{key}: ")))
}

#[test]
fn fresh_export_then_decrypt_roundtrips_payload_counts()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let (context, _descriptor, bundle_path, export_output) =
        export_sealed_bundle(&directory, "fresh.locket-bundle")?;

    // Export reports the canonical payload counts that the (eventual)
    // decrypted import should mirror.
    assert!(export_output.contains("bundle: exported"));
    let exported_digest = parse_export_field(&export_output, "digest")
        .ok_or("export missing digest field")?
        .to_owned();
    let exported_profiles = parse_export_field(&export_output, "profiles")
        .ok_or("export missing profiles field")?
        .to_owned();
    let exported_secrets = parse_export_field(&export_output, "secret_count")
        .ok_or("export missing secret_count field")?
        .to_owned();
    let exported_blobs = parse_export_field(&export_output, "blob_count")
        .ok_or("export missing blob_count field")?
        .to_owned();
    let exported_command_policies = parse_export_field(&export_output, "command_policy_count")
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
    let verify_digest =
        parse_export_field(&verify_output, "digest").ok_or("verify missing digest")?;
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

    // Import currently emits the metadata-only stub. When
    // `bundle-import-decrypt` ships, the assertion block below should
    // flip to assert `import: decrypted` plus matching counts.
    assert!(import_output.contains("import: not_applied"));
    assert!(import_output.contains("metadata_only: yes"));
    let import_profiles =
        parse_export_field(&import_output, "profiles").ok_or("import missing profiles")?;
    assert_eq!(
        import_profiles, exported_profiles,
        "import must report the same profile count as export (metadata-only)"
    );

    // Document the expected post-decrypt-counts contract so the next
    // agent has a clear target. These are not yet emitted.
    assert!(
        !import_output.contains("import: decrypted"),
        "if decrypted-counts shipped, update this test to assert counts: \
         profiles={exported_profiles} secrets={exported_secrets} \
         blobs={exported_blobs} command_policies={exported_command_policies}"
    );
    Ok(())
}

#[test]
fn identical_bundle_decrypt_emits_consistent_counts() -> Result<(), Box<dyn std::error::Error>> {
    // Two independently-initialised projects with the same scripted
    // inputs should produce bundles whose manifest counts agree. The
    // payload digests differ because age encryption is randomised and
    // the project_id / device key are freshly generated, but the
    // metadata-only counts shown in the export and import surfaces are
    // deterministic.
    let directory_a = tempdir()?;
    let directory_b = tempdir()?;
    let (_ctx_a, _desc_a, _path_a, export_a) =
        export_sealed_bundle(&directory_a, "a.locket-bundle")?;
    let (_ctx_b, _desc_b, _path_b, export_b) =
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
        let value_a = parse_export_field(&export_a, field)
            .ok_or_else(|| format!("export A missing {field}"))?;
        let value_b = parse_export_field(&export_b, field)
            .ok_or_else(|| format!("export B missing {field}"))?;
        assert_eq!(
            value_a, value_b,
            "field {field} must agree between identical exports (a={value_a}, b={value_b})"
        );
    }
    Ok(())
}

#[test]
fn bundle_with_corrupt_age_payload_fails_verification()
-> Result<(), Box<dyn std::error::Error>> {
    // Sibling test `bundle_verify_rejects_tampered_digest` covers the
    // case where the manifest digest field is replaced. This test
    // covers the dual: the encrypted payload bytes themselves are
    // tampered while the manifest digest is left alone, so digest
    // verification trips first. Both paths return `BundleVerificationFailed`
    // (exit code 110); the wording differs.
    let directory = tempdir()?;
    let (context, _descriptor, bundle_path, _export_output) =
        export_sealed_bundle(&directory, "corrupt.locket-bundle")?;

    let bundle_bytes = fs::read(&bundle_path)?;
    let mut container = locket_core::BundleContainer::deserialize(&bundle_bytes)?;
    // Flip a byte deep in the encrypted payload — past the age v1
    // magic and recipient stanzas — so the corruption is in the
    // ciphertext body rather than the framing header.
    let payload_len = container.encrypted_payload.len();
    assert!(payload_len > 0, "encrypted payload must be non-empty");
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
        locket_core::LocketError::BundleVerificationFailed.exit_code()
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
    // Today, *every* import fails to apply because device-private-key
    // storage and the decrypt step are not wired (`import: not_applied`,
    // reason: `local device private-key import is not implemented in
    // this build`). Once `device-private-key-storage` and
    // `bundle-import-decrypt` ship, this case must transition into a
    // hard-fail import that returns `BundleVerificationFailed` with
    // reason `device private-key storage not initialized`.
    //
    // For now, pin the current contract: the metadata-only stub is the
    // only thing that runs without device-private-key storage.
    let directory = tempdir()?;
    let (context, _descriptor, bundle_path, _export_output) =
        export_sealed_bundle(&directory, "no-priv-key.locket-bundle")?;

    let mut import_output = Vec::new();
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "import-bundle",
            bundle_path.to_str().ok_or("utf8 path")?,
            "--accept-local",
        ])?,
        &context,
        &mut import_output,
    )?;
    let import_output = String::from_utf8(import_output)?;
    assert!(import_output.contains("import: not_applied"));
    assert!(
        import_output.contains("local device private-key import is not implemented"),
        "import should explain why decrypt is unavailable: {import_output}"
    );
    Ok(())
}

// TODO(bundle-apply-and-conflicts): the cases below depend on the
// apply/conflict matrix and the `bundle-import-decrypt` step. Each is
// scaffolded in a sentence so the next agent can lift them straight
// into tests once the underlying behaviour ships.
//
// 1. `decrypted_counts_match_exported_counts`: once `import: decrypted`
//    is emitted, assert the four counts (profiles, secrets, blobs,
//    command_policies) literally match the export field values rather
//    than the metadata-only stub. Replace the negative assertion in
//    `fresh_export_then_decrypt_roundtrips_payload_counts`.
//
// 2. `newer_incoming_replaces_active_with_rotation`: import a bundle
//    whose secret_version is newer than the local active version with
//    `--accept-incoming`; assert the local row rotates with no grace
//    and the prior version is marked deprecated.
//
// 3. `divergent_versions_require_explicit_resolution`: import a bundle
//    whose secret_version diverges from local (same version number,
//    different ciphertext); assert the default conflict policy
//    `interactive-required` exits without writing.
//
// 4. `deleted_local_vs_active_incoming_records_tombstone`: local row
//    is tombstoned, incoming bundle still has the active version;
//    assert `--accept-local` keeps the tombstone and `--accept-incoming`
//    revives the row with a fresh version chain.
//
// 5. `applied_rows_persist_across_reopen`: after a successful apply,
//    reopen the store and assert profile_keys, command_policies,
//    secret_versions, and blobs are visible with the imported counts.
//
// 6. `missing_device_private_key_fails_with_typed_error`: replace the
//    metadata-only assertion in
//    `bundle_without_device_private_key_fails_verification` with a
//    hard error assertion: `BundleVerificationFailed` and message
//    `device private-key storage not initialized`.
