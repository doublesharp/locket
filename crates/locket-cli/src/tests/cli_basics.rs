#[allow(unused_imports)]
use super::*;

#[test]
fn completion_command_generates_scripts_without_project() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();

    run_with_context(
        Cli::try_parse_from(["locket", "completion", "bash"])?,
        &context,
        &mut output,
    )?;

    let output = String::from_utf8(output)?;
    assert!(output.contains("_locket()"));
    assert!(output.contains("complete -F _locket"));
    assert!(output.contains("completion"));
    assert!(!directory.path().join("locket.toml").exists());
    Ok(())
}

#[test]
fn client_add_list_and_revoke_are_metadata_only() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    run_with_context(
        Cli::try_parse_from(["locket", "policy", "add", "ci", "--", "cargo", "test"])?,
        &context,
        &mut Vec::new(),
    )?;
    let public_key = "11".repeat(32);
    let mut add_output = Vec::new();
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "client",
            "add",
            "ci_bot",
            "--pubkey",
            &public_key,
            "--action",
            "run-policy",
            "--action",
            "redact",
            "--policy",
            "ci",
        ])?,
        &context,
        &mut add_output,
    )?;

    let add_output = String::from_utf8(add_output)?;
    assert!(add_output.contains("client: ci_bot"));
    assert!(add_output.contains("private_key_material: never displayed"));
    assert!(!add_output.contains(&public_key));

    let mut list_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "client", "list"])?,
        &context,
        &mut list_output,
    )?;
    let list_output = String::from_utf8(list_output)?;
    assert!(list_output.contains("ci_bot"));
    assert!(list_output.contains("actions=redact,run-policy"));
    assert!(list_output.contains("policies=ci"));
    assert!(list_output.contains("private_key_material: never displayed"));
    assert!(!list_output.contains(&public_key));

    let mut revoke_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "client", "revoke", "ci_bot"])?,
        &context,
        &mut revoke_output,
    )?;
    let revoke_output = String::from_utf8(revoke_output)?;
    assert!(revoke_output.contains("revoked_at:"));

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let resolved = crate::resolve_project(&context.cwd)?.ok_or("project should resolve")?;
    assert!(store.list_automation_clients(resolved.config.project_id.as_str(), false)?.is_empty());
    assert!(
        store.list_automation_clients(resolved.config.project_id.as_str(), true)?[0]
            .revoked_at
            .is_some()
    );
    let mut statement = store
        .connection()
        .prepare("SELECT action, metadata_json FROM audit_log ORDER BY sequence")?;
    let rows = statement
        .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))?
        .collect::<Result<Vec<_>, _>>()?;
    assert!(rows.iter().any(|(action, _)| action == "CLIENT_ADD"));
    assert!(rows.iter().any(|(action, _)| action == "CLIENT_REVOKE"));
    for (_, metadata) in rows {
        assert!(!metadata.contains(&public_key));
    }
    Ok(())
}

#[test]
fn client_create_stores_locket_managed_private_key_refs() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    run_with_context(
        Cli::try_parse_from(["locket", "policy", "add", "ci", "--", "cargo", "test"])?,
        &context,
        &mut Vec::new(),
    )?;

    let mut keychain_output = Vec::new();
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "client",
            "create",
            "managed_keychain",
            "--action",
            "run-policy",
            "--policy",
            "ci",
        ])?,
        &context,
        &mut keychain_output,
    )?;
    let keychain_output = String::from_utf8(keychain_output)?;
    assert!(keychain_output.contains("private_key_storage: os-keychain"));
    assert!(keychain_output.contains("private_key_material: never displayed"));

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let resolved = crate::resolve_project(&context.cwd)?.ok_or("project should resolve")?;
    let keychain_client = store
        .get_automation_client(resolved.config.project_id.as_str(), "managed_keychain")?
        .ok_or("keychain client should exist")?;
    let keychain_ref = store
        .get_automation_client_private_key_ref(&keychain_client.id)?
        .ok_or("keychain private key ref should exist")?;
    assert_eq!(keychain_ref.storage, "os-keychain");
    assert!(keychain_ref.keychain_account.as_deref().unwrap_or("").contains(&keychain_client.id));
    assert!(keychain_ref.local_path_hash.is_none());

    let mut file_output = Vec::new();
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "client",
            "create",
            "managed_file",
            "--storage",
            "wrapped-local-file",
            "--action",
            "run-policy",
            "--policy",
            "ci",
        ])?,
        &context,
        &mut file_output,
    )?;
    let file_output = String::from_utf8(file_output)?;
    assert!(file_output.contains("private_key_storage: wrapped-local-file"));
    assert!(file_output.contains("private_key_material: never displayed"));

    let file_client = store
        .get_automation_client(resolved.config.project_id.as_str(), "managed_file")?
        .ok_or("file client should exist")?;
    let file_ref = store
        .get_automation_client_private_key_ref(&file_client.id)?
        .ok_or("file private key ref should exist")?;
    assert_eq!(file_ref.storage, "wrapped-local-file");
    assert!(file_ref.local_path_hash.is_some());
    assert!(file_ref.keychain_account.is_none());
    let key_file =
        directory.path().join("automation-clients").join(format!("{}.key", file_client.id));
    let key_file_text = fs::read_to_string(&key_file)?;
    assert!(key_file_text.contains("wrapped_private_key"));
    assert!(!key_file_text.contains("private_key_material"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        assert_eq!(fs::metadata(&key_file)?.permissions().mode() & 0o777, 0o600);
    }

    run_with_context(
        Cli::try_parse_from(["locket", "client", "revoke", "managed_file"])?,
        &context,
        &mut Vec::new(),
    )?;
    assert!(!key_file.exists());
    assert!(store.get_automation_client_private_key_ref(&file_client.id)?.is_none());
    Ok(())
}

#[test]
fn client_rejects_unsupported_actions_and_missing_policies()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    let public_key = "22".repeat(32);
    assert_error_contains(
        run_with_context(
            Cli::try_parse_from([
                "locket",
                "client",
                "add",
                "ci_bot",
                "--pubkey",
                &public_key,
                "--action",
                "reveal",
                "--policy",
                "ci",
            ])?,
            &context,
            &mut Vec::new(),
        ),
        "InvalidPolicy",
    );
    assert_error_contains(
        run_with_context(
            Cli::try_parse_from([
                "locket",
                "client",
                "add",
                "ci_bot",
                "--pubkey",
                &public_key,
                "--action",
                "run-policy",
            ])?,
            &context,
            &mut Vec::new(),
        ),
        "at least one --policy",
    );

    let missing_policy_result = run_with_context(
        Cli::try_parse_from([
            "locket",
            "client",
            "add",
            "ci_bot",
            "--pubkey",
            &public_key,
            "--action",
            "run-policy",
            "--policy",
            "missing",
        ])?,
        &context,
        &mut Vec::new(),
    );
    let Err(error) = missing_policy_result else {
        return Err("client add with missing policy should fail".into());
    };
    assert_eq!(error.exit_code(), locket_core::LocketError::PolicyNotFound.exit_code());
    assert!(error.to_string().contains("command policy not found: missing"));

    let missing_client_result = run_with_context(
        Cli::try_parse_from(["locket", "client", "revoke", "missing-client"])?,
        &context,
        &mut Vec::new(),
    );
    let Err(error) = missing_client_result else {
        return Err("client revoke with missing client should fail".into());
    };
    assert_eq!(error.exit_code(), locket_core::LocketError::PolicyNotFound.exit_code());
    assert!(error.to_string().contains("automation client not found: missing-client"));
    Ok(())
}

#[test]
#[allow(clippy::too_many_lines)]
fn sealed_bundle_export_verify_and_import_are_metadata_only()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
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
    let bundle_path = directory.path().join("dev.locket-bundle");

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
    assert!(export_output.contains("bundle: exported"));
    assert!(export_output.contains("secret_count: 1"));
    assert!(export_output.contains("secret_version_count: 1"));
    assert!(export_output.contains("blob_count: 1"));
    assert!(export_output.contains("profile_key_count: 2"));
    assert!(export_output.contains("active_secret_count: 1"));
    assert!(export_output.contains("metadata_only: yes"));
    let bundle_bytes = fs::read(&bundle_path)?;
    assert!(bundle_bytes.starts_with(locket_core::BUNDLE_MAGIC));
    assert!(
        !bundle_bytes
            .windows("postgres://bundle-secret".len())
            .any(|window| window == b"postgres://bundle-secret")
    );
    assert!(!bundle_bytes.windows("DATABASE_URL".len()).any(|window| window == b"DATABASE_URL"));

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
    // Per docs/specs/team-sync-recovery.md:213, when the verifying device
    // is also a recipient (this same context exported the bundle to its
    // own descriptor), `bundle verify` must attempt decryption and report
    // the truthful flag plus inner counts. Bundle verify remains
    // metadata-only — no rows are applied.
    assert!(verify_output.contains("decryptable_by_this_device: yes"));
    assert!(verify_output.contains("decrypted_secret_count: 1"));
    assert!(verify_output.contains("decrypted_blob_count: 1"));
    assert!(verify_output.contains("metadata_only: yes"));

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
    assert!(import_output.contains("import: decrypted"));
    assert!(import_output.contains("profiles: 1"));
    assert!(import_output.contains("secrets: 1"));
    assert!(import_output.contains("blobs: 1"));
    assert!(import_output.contains("command_policies: 0"));
    assert!(import_output.contains("metadata_only: yes"));

    assert_error_contains(
        run_with_context(
            Cli::try_parse_from([
                "locket",
                "export",
                "--sealed",
                "--recipient",
                &descriptor,
                "--profile",
                "dev",
                "--output",
                bundle_path.to_str().ok_or("utf8 path")?,
            ])?,
            &context,
            &mut Vec::new(),
        ),
        "bundle output already exists",
    );

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let mut statement = store
        .connection()
        .prepare("SELECT action, metadata_json FROM audit_log ORDER BY sequence")?;
    let rows = statement
        .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))?
        .collect::<Result<Vec<_>, _>>()?;
    assert!(rows.iter().any(|(action, _)| action == "BACKUP_EXPORT"));
    let verify_metadata = rows
        .iter()
        .find_map(|(action, metadata)| (action == "BUNDLE_VERIFY").then_some(metadata))
        .ok_or("missing BUNDLE_VERIFY audit row")?;
    let verify_metadata: serde_json::Value = serde_json::from_str(verify_metadata)?;
    assert_eq!(verify_metadata["bundle_schema_version"], serde_json::json!(1));
    assert_eq!(verify_metadata["profile_count"], serde_json::json!(1));
    assert_eq!(verify_metadata["recipient_count"], serde_json::json!(1));
    assert_eq!(verify_metadata["decryptable_by_this_device"], serde_json::json!(true));
    assert_eq!(verify_metadata["decrypted_profile_count"], serde_json::json!(1));
    assert_eq!(verify_metadata["decrypted_secret_count"], serde_json::json!(1));
    assert_eq!(verify_metadata["decrypted_blob_count"], serde_json::json!(1));
    assert_eq!(verify_metadata["decrypted_command_policy_count"], serde_json::json!(0));
    assert_eq!(verify_metadata["metadata_only"], serde_json::json!(true));
    assert!(verify_metadata.get("recipient_fingerprints").is_none());
    let import_metadata = rows
        .iter()
        .find_map(|(action, metadata)| (action == "BACKUP_IMPORT").then_some(metadata))
        .ok_or("missing BACKUP_IMPORT audit row")?;
    let import_metadata: serde_json::Value = serde_json::from_str(import_metadata)?;
    assert_eq!(import_metadata["profile_count"], serde_json::json!(1));
    assert_eq!(import_metadata["secret_count"], serde_json::json!(1));
    assert_eq!(import_metadata["blob_count"], serde_json::json!(1));
    assert_eq!(import_metadata["command_policy_count"], serde_json::json!(0));
    for (_, metadata) in rows {
        assert!(!metadata.contains("postgres://bundle-secret"));
    }
    Ok(())
}

#[test]
fn bundle_verify_rejects_unsupported_schema_as_config_error()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
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
    let bundle_path = directory.path().join("unsupported.locket-bundle");
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "export",
            "--sealed",
            "--recipient",
            &descriptor,
            "--output",
            bundle_path.to_str().ok_or("utf8 path")?,
        ])?,
        &context,
        &mut Vec::new(),
    )?;
    let mut bundle_bytes = fs::read(&bundle_path)?;
    bundle_bytes[locket_core::BUNDLE_MAGIC.len()] = 99;
    bundle_bytes[locket_core::BUNDLE_MAGIC.len() + 1] = 0;
    fs::write(&bundle_path, bundle_bytes)?;

    let result = run_with_context(
        Cli::try_parse_from([
            "locket",
            "bundle",
            "verify",
            bundle_path.to_str().ok_or("utf8 path")?,
        ])?,
        &context,
        &mut Vec::new(),
    );
    let Err(error) = result else {
        return Err("expected unsupported schema error".into());
    };
    assert_eq!(error.exit_code(), locket_core::LocketError::MetadataInvalid.exit_code());
    assert!(error.to_string().contains("unsupported bundle schema version 99"));
    match error {
        crate::CliError::Typed { kind, .. } => {
            assert_eq!(kind, locket_core::LocketError::MetadataInvalid);
        }
        other => return Err(format!("expected typed MetadataInvalid error, got {other:?}").into()),
    }
    Ok(())
}

#[test]
fn import_bundle_without_device_private_key_fails_verification()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    let args = test_secret_write_args("DATABASE_URL");
    crate::set_secret_value(&context, &args, "postgres://x", "manual", 1_000)?;

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
    let bundle_path = directory.path().join("dev.locket-bundle");
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "export",
            "--sealed",
            "--recipient",
            &descriptor,
            "--profile",
            "dev",
            "--output",
            bundle_path.to_str().ok_or("utf8 path")?,
        ])?,
        &context,
        &mut Vec::new(),
    )?;

    // Remove the device's wrapped private-key file so the import path
    // observes DevicePrivateKeyNotFound and returns BundleVerificationFailed.
    let devices_dir = directory.path().join("devices");
    if devices_dir.exists() {
        fs::remove_dir_all(&devices_dir)?;
    }

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
        return Err("expected bundle verification error".into());
    };
    assert_eq!(error.exit_code(), locket_core::LocketError::BundleVerificationFailed.exit_code(),);
    assert!(
        error.to_string().contains("device private-key storage not initialized"),
        "unexpected error message: {error}"
    );
    Ok(())
}

#[test]
fn import_bundle_with_corrupt_age_payload_fails_verification()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;

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
    let bundle_path = directory.path().join("dev.locket-bundle");
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "export",
            "--sealed",
            "--recipient",
            &descriptor,
            "--profile",
            "dev",
            "--output",
            bundle_path.to_str().ok_or("utf8 path")?,
        ])?,
        &context,
        &mut Vec::new(),
    )?;

    // Flip a byte inside the encrypted payload (after the manifest header)
    // so age authenticated decryption fails. The container-level digest is
    // recomputed to bypass the manifest digest check and exercise the age
    // decrypt path.
    let bundle_bytes = fs::read(&bundle_path)?;
    let mut container = locket_core::BundleContainer::deserialize(&bundle_bytes)?;
    let payload_len = container.encrypted_payload.len();
    assert!(payload_len > 32, "encrypted payload unexpectedly short");
    // Flip a byte well inside the ciphertext to corrupt the auth tag.
    container.encrypted_payload[payload_len - 8] ^= 0xff;
    let mut hasher = <sha2::Sha256 as sha2::Digest>::new();
    <sha2::Sha256 as sha2::Digest>::update(&mut hasher, &container.encrypted_payload);
    container.manifest.payload_digest =
        format!("{:x}", <sha2::Sha256 as sha2::Digest>::finalize(hasher));
    let rebuilt =
        locket_core::BundleContainer::new(container.manifest, container.encrypted_payload)?;
    fs::write(&bundle_path, rebuilt.serialize()?)?;

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
        return Err("expected bundle decryption to fail".into());
    };
    assert_eq!(error.exit_code(), locket_core::LocketError::BundleVerificationFailed.exit_code(),);
    assert!(
        error.to_string().contains("bundle verification failed"),
        "unexpected error message: {error}"
    );
    Ok(())
}

#[test]
fn dangerous_profile_bundle_export_honors_configured_user_verification()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    run_with_context(
        Cli::try_parse_from(["locket", "device", "init"])?,
        &context,
        &mut Vec::new(),
    )?;
    run_with_context(
        Cli::try_parse_from(["locket", "profile", "mark-dangerous", "dev"])?,
        &context_with_confirmation(&context, "dev\n"),
        &mut Vec::new(),
    )?;
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "config",
            "set",
            "user_verification_required_for.dangerous_profile_switch",
            "true",
        ])?,
        &context,
        &mut Vec::new(),
    )?;

    let store = crate::open_store(&context)?;
    let descriptor = store
        .get_active_local_device(
            crate::read_project_config(&directory.path().join("locket.toml"))?.project_id.as_str(),
        )?
        .map(|device| crate::encode_device_descriptor(&device))
        .transpose()?
        .ok_or("missing local device")?;
    let bundle_path = directory.path().join("dangerous.locket-bundle");
    let denied_context = context_with_user_verifier(
        &context_with_confirmation(&context, "export --sealed dev\n"),
        Arc::new(MemoryLocalUserVerifier::denying()),
    );
    let denied = run_with_context(
        Cli::try_parse_from([
            "locket",
            "export",
            "--sealed",
            "--recipient",
            &descriptor,
            "--profile",
            "dev",
            "--output",
            bundle_path.to_str().ok_or("utf8 path")?,
        ])?,
        &denied_context,
        &mut Vec::new(),
    );
    assert_error_contains(denied, "local user verification failed");
    assert!(!bundle_path.exists());

    run_with_context(
        Cli::try_parse_from([
            "locket",
            "export",
            "--sealed",
            "--recipient",
            &descriptor,
            "--profile",
            "dev",
            "--output",
            bundle_path.to_str().ok_or("utf8 path")?,
        ])?,
        &context_with_confirmation(&context, "export --sealed dev\n"),
        &mut Vec::new(),
    )?;
    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'BACKUP_EXPORT'
         ORDER BY sequence DESC LIMIT 1",
        [],
        |row| row.get(0),
    )?;
    let metadata: serde_json::Value = serde_json::from_str(&metadata)?;
    assert_eq!(metadata["user_verification"]["required"], json!(true));
    assert_eq!(metadata["user_verification"]["satisfied"], json!(true));
    assert_eq!(metadata["user_verification"]["method"], json!("test"));
    Ok(())
}

#[test]
fn bundle_verify_rejects_tampered_digest() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
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
    let bundle_path = directory.path().join("tampered.locket-bundle");
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "export",
            "--sealed",
            "--recipient",
            &descriptor,
            "--output",
            bundle_path.to_str().ok_or("utf8 path")?,
        ])?,
        &context,
        &mut Vec::new(),
    )?;
    let bundle_bytes = fs::read(&bundle_path)?;
    let mut container = locket_core::BundleContainer::deserialize(&bundle_bytes)?;
    container.manifest.payload_digest = "0".repeat(64);
    fs::write(&bundle_path, container.serialize()?)?;
    let result = run_with_context(
        Cli::try_parse_from([
            "locket",
            "bundle",
            "verify",
            bundle_path.to_str().ok_or("utf8 path")?,
        ])?,
        &context,
        &mut Vec::new(),
    );
    assert_error_contains(result, "manifest digest mismatch");
    assert_eq!(crate::bundle_verification_error("failed").exit_code(), 110);
    Ok(())
}

#[test]
fn status_reports_not_initialized_without_project() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();

    run_with_context(Cli::try_parse_from(["locket"])?, &context, &mut output)?;

    let output = String::from_utf8(output)?;
    assert!(output.contains("not initialized"));
    assert!(output.contains("next_action: run locket init"));
    Ok(())
}

#[test]
fn status_reports_metadata_summary_and_next_action() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut init_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut init_output,
    )?;

    std::fs::write(directory.path().join("leak.txt"), "token=sk_test_sampleTokenValue123\n")?;
    let resolved = crate::resolve_project(&context.cwd)?.ok_or("project should resolve")?;
    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let profile = store
        .get_profile_by_name(resolved.config.project_id.as_str(), "dev")?
        .ok_or("default profile should exist")?;
    store.insert_runtime_session(&locket_store::RuntimeSessionRecord {
        id: "lk_sess_status".to_owned(),
        project_id: resolved.config.project_id.to_string(),
        profile_id: profile.id,
        policy_name: Some("dev".to_owned()),
        process_id: 42,
        process_start_time: 900,
        started_at: 1_000,
        ended_at: None,
        exit_status: None,
        secret_names: vec!["API_KEY".to_owned()],
        spawn_audit_sequence: None,
        completion_audit_sequence: None,
    })?;

    let mut output = Vec::new();
    run_with_context(Cli::try_parse_from(["locket", "status"])?, &context, &mut output)?;

    let output = String::from_utf8(output)?;
    assert!(output.contains("project: app"));
    assert!(output.contains("default_profile: dev"));
    assert!(output.contains("active_profile: dev"));
    assert!(output.contains("lock_state: locked"));
    assert!(output.contains("agent_state: unavailable"));
    assert!(output.contains("running_sessions: 1"));
    assert!(output.contains("scan_warnings: 1"), "{output}");
    assert!(output.contains("trusted_root: yes"));
    assert!(output.contains("metadata_only: yes"));
    assert!(output.contains("next_action: run locket scan"));
    assert!(!output.contains("sk_test_sampleTokenValue123"));
    Ok(())
}

#[test]
fn status_redacts_project_and_profile_names_from_privacy_config()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut init_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut init_output,
    )?;
    let mut config_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "config", "set", "privacy.redact_names", "true"])?,
        &context,
        &mut config_output,
    )?;

    let mut output = Vec::new();
    run_with_context(Cli::try_parse_from(["locket", "status"])?, &context, &mut output)?;

    let output = String::from_utf8(output)?;
    assert!(output.contains("project: project-"));
    assert!(output.contains("project_id: project-"));
    assert!(output.contains("default_profile: profile-"));
    assert!(output.contains("active_profile: profile-"));
    assert!(!output.contains("project: app"));
    assert!(!output.contains("default_profile: dev"));
    assert!(!output.contains("active_profile: dev"));
    Ok(())
}

#[test]
fn completion_generates_shell_script() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();

    run_with_context(
        Cli::try_parse_from(["locket", "completion", "bash"])?,
        &context,
        &mut output,
    )?;

    let output = String::from_utf8(output)?;
    assert!(output.contains("_locket"));
    assert!(output.contains("bootstrap"));
    Ok(())
}
