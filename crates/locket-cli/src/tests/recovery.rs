#[allow(unused_imports)]
use super::*;
use sha2::Digest;

#[test]
fn recovery_restore_rejects_mismatched_kdf_profile() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut init_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut init_output,
    )?;
    let resolved = crate::require_project(&context)?;
    let (project_id, master_key) = test_project_id_and_master_key(&context)?;
    let (kdf, mut envelope, code_bytes) =
        setup_recovery_envelope(&context, &project_id, &master_key)?;
    envelope.kdf_profile_id = "lk_kdf_other".to_owned();

    let result = crate::restore_from_recovery_code(
        &context,
        &mut Vec::new(),
        &resolved,
        &kdf,
        &envelope,
        &code_bytes,
        true,
    );

    assert_error_contains(result, "kdf profile mismatch");
    Ok(())
}

#[test]
fn recovery_restore_recovers_master_key_from_envelope() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut init_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut init_output,
    )?;
    let resolved = crate::require_project(&context)?;
    let (project_id, master_key) = test_project_id_and_master_key(&context)?;
    let (kdf, envelope, code_bytes) = setup_recovery_envelope(&context, &project_id, &master_key)?;
    context.key_store.delete_master_key(&project_id)?;

    let mut recover_output = Vec::new();
    crate::restore_from_recovery_code(
        &context,
        &mut recover_output,
        &resolved,
        &kdf,
        &envelope,
        &code_bytes,
        false,
    )?;

    assert_eq!(*context.key_store.load_master_key(&project_id)?, master_key);
    let recover_output = String::from_utf8(recover_output)?;
    assert!(recover_output.contains("recovered: master_key"));
    assert!(recover_output.contains("metadata_only: yes"));
    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let (schema_version, command, metadata, previous_hmac, hmac): (
        u16,
        String,
        String,
        Vec<u8>,
        Vec<u8>,
    ) = store.connection().query_row(
        "SELECT schema_version, command, metadata_json, previous_hmac, hmac
         FROM audit_log WHERE action = 'RECOVER'",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
    )?;
    assert_eq!(schema_version, 1);
    assert_eq!(command, "recover");
    assert_eq!(previous_hmac.len(), locket_core::AUDIT_HMAC_LEN);
    assert_eq!(hmac.len(), locket_core::AUDIT_HMAC_LEN);
    let expected_checksum = crate::format_hex(&sha2::Sha256::digest(envelope.serialize()?));
    let metadata: serde_json::Value = serde_json::from_str(&metadata)?;
    assert_eq!(metadata["schema_version"], 1);
    assert_eq!(metadata["action"], "RECOVER");
    assert_eq!(metadata["status"], "SUCCESS");
    assert_eq!(metadata["command"], "recover");
    assert_eq!(metadata["project_id"], project_id);
    assert_eq!(metadata["kdf_profile_id"], kdf.kdf_profile_id);
    assert_eq!(metadata["force"], false);
    assert_eq!(metadata["restored_entry_kinds"], serde_json::json!(["master_key"]));
    assert_eq!(metadata["restored_entry_counts"]["master_key"], 1);
    assert_eq!(metadata["envelope_checksum_sha256"], expected_checksum);
    Ok(())
}

#[test]
fn recovery_restore_validation_failure_writes_no_recover_audit()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut init_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut init_output,
    )?;
    let resolved = crate::require_project(&context)?;
    let (project_id, master_key) = test_project_id_and_master_key(&context)?;
    let (kdf, mut envelope, code_bytes) =
        setup_recovery_envelope(&context, &project_id, &master_key)?;
    envelope.kdf_profile_id = "lk_kdf_other".to_owned();

    let result = crate::restore_from_recovery_code(
        &context,
        &mut Vec::new(),
        &resolved,
        &kdf,
        &envelope,
        &code_bytes,
        true,
    );

    assert_error_contains(result, "kdf profile mismatch");
    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let recover_rows: i64 = store.connection().query_row(
        "SELECT COUNT(*) FROM audit_log WHERE action = 'RECOVER'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(recover_rows, 0);
    Ok(())
}

#[test]
fn recovery_rotate_creates_envelope_and_prints_full_code() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut init_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut init_output,
    )?;
    let init_output = String::from_utf8(init_output)?;
    let initial_recovery_code = recovery_code_from_output(&init_output)?.to_owned();
    let (project_id, master_key) = test_project_id_and_master_key(&context)?;

    let rotate_context = context_with_recovery_code(&context, &initial_recovery_code);
    let mut rotate_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "recovery", "rotate"])?,
        &rotate_context,
        &mut rotate_output,
    )?;

    let rotate_output = String::from_utf8(rotate_output)?;
    assert!(rotate_output.contains("recovery_code_rotate: success"));
    assert!(rotate_output.contains("warning: terminal scrollback may retain this code"));
    assert!(rotate_output.contains("metadata_only: yes"));
    let code_line = recovery_code_from_output(&rotate_output)?;
    let code_bytes = locket_crypto::recovery_code_decode(code_line)?;
    let recovery_dir = directory.path().join(".locket").join("recovery");
    let kdf = crate::load_recovery_kdf_toml(&recovery_dir)?;
    let envelope = crate::load_recovery_envelope(&recovery_dir)?;
    assert_eq!(envelope.kdf_profile_id, kdf.kdf_profile_id);

    context.key_store.delete_master_key(&project_id)?;
    let resolved = crate::require_project(&context)?;
    crate::restore_from_recovery_code(
        &context,
        &mut Vec::new(),
        &resolved,
        &kdf,
        &envelope,
        &code_bytes,
        false,
    )?;
    assert_eq!(*context.key_store.load_master_key(&project_id)?, master_key);

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'RECOVERY_ROTATE'",
        [],
        |row| row.get(0),
    )?;
    assert!(metadata.contains("\"kdf_profile_id\""));
    assert!(metadata.contains("\"command\":\"recovery rotate\""));
    assert!(!metadata.contains(code_line));
    Ok(())
}

#[test]
fn recover_with_corrupted_kdf_file_exits_with_metadata_invalid()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    let kdf_path = directory.path().join(".locket/recovery/kdf.toml");
    std::fs::write(&kdf_path, "this-is-not-valid-toml = = = corrupted\n")?;

    let recover_context = context_with_recovery_code(&context, "ignored-code\n");
    let result = run_with_context(
        Cli::try_parse_from(["locket", "recover"])?,
        &recover_context,
        &mut Vec::new(),
    );

    let Err(error) = result else {
        return Err("recover with corrupted kdf.toml must fail".into());
    };
    assert_eq!(error.exit_code(), 64, "MetadataInvalid is in the input/config band");
    assert!(error.to_string().contains("recovery/kdf.toml"));
    Ok(())
}
