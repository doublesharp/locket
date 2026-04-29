use locket_crypto::{KeyPurpose, derive_recovery_key_v1, open_recovery_entry_v1};
use locket_platform::{
    RecoveryEnvelope, RecoveryEnvelopeEntry, RecoveryKdfToml, load_recovery_envelope,
    load_recovery_kdf_toml, save_recovery_envelope, save_recovery_kdf_toml,
};
use locket_store::AuditWrite;
use serde_json::json;
use std::io::Write;
use std::path::PathBuf;

use crate::{
    CliError, RecoverArgs, RecoveryCommand, ResolvedProject, RuntimeContext, format_hex,
    formatted_recovery_code, generate_recovery_code_bytes, generate_recovery_salt, load_master_key,
    load_project_key, now_unix_nanos, open_store, recovery_code_decode, require_project,
    seal_recovery_envelope_entry,
};

pub fn recover_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &RecoverArgs,
) -> Result<(), CliError> {
    let resolved = require_project(context)?;
    let recovery_dir = recovery_dir(&resolved);
    let kdf = load_recovery_kdf_toml(&recovery_dir)
        .map_err(|error| CliError::Config(format!("recovery/kdf.toml: {error}")))?;
    let envelope = load_recovery_envelope(&recovery_dir)
        .map_err(|error| CliError::Config(format!("recovery/envelope.bin: {error}")))?;
    let code = context.recovery_code_reader.read_recovery_code("recovery code")?;
    let code_bytes = recovery_code_decode(code.trim())?;
    restore_from_recovery_code(context, output, &resolved, &kdf, &envelope, &code_bytes, args.force)
}

pub fn recovery_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    command: RecoveryCommand,
) -> Result<(), CliError> {
    match command {
        RecoveryCommand::Rotate => recovery_rotate_command(context, output),
    }
}

pub fn recovery_rotate_command(
    context: &RuntimeContext,
    output: &mut impl Write,
) -> Result<(), CliError> {
    let resolved = require_project(context)?;
    let project_id = resolved.config.project_id.as_str();
    let recovery_dir = recovery_dir(&resolved);
    let timestamp = now_unix_nanos()?;
    let code_bytes = generate_recovery_code_bytes()?;
    let salt = generate_recovery_salt()?;
    let kdf_profile_id = format!("lk_kdf_{}", format_hex(&salt[..16]));
    let new_kdf = RecoveryKdfToml::new_v1(kdf_profile_id, &salt, timestamp);
    let new_root = derive_recovery_key_v1(&code_bytes, &salt, new_kdf.to_crypto_params())?;

    let entries = if recovery_dir.join("envelope.bin").exists() {
        let old_kdf = load_recovery_kdf_toml(&recovery_dir)
            .map_err(|error| CliError::Config(format!("recovery/kdf.toml: {error}")))?;
        let old_envelope = load_recovery_envelope(&recovery_dir)
            .map_err(|error| CliError::Config(format!("recovery/envelope.bin: {error}")))?;
        validate_recovery_metadata(project_id, &old_kdf, &old_envelope)?;
        let old_code = context.recovery_code_reader.read_recovery_code("current recovery code")?;
        let old_code_bytes = recovery_code_decode(old_code.trim())?;
        let old_salt = old_kdf
            .decode_salt()
            .map_err(|error| CliError::Config(format!("recovery kdf salt: {error}")))?;
        let old_root =
            derive_recovery_key_v1(&old_code_bytes, &old_salt, old_kdf.to_crypto_params())?;
        rewrap_recovery_entries(
            &old_envelope,
            &old_kdf.kdf_profile_id,
            &old_root,
            &new_kdf,
            &new_root,
        )?
    } else {
        let (master_key, _source) = load_master_key(context, project_id)?;
        vec![seal_recovery_envelope_entry(
            &new_root,
            &new_kdf.kdf_profile_id,
            "master_key",
            project_id,
            master_key.as_ref(),
        )?]
    };

    let new_envelope = RecoveryEnvelope {
        kdf_profile_id: new_kdf.kdf_profile_id.clone(),
        created_at_unix_nanos: i128::from(timestamp),
        entries,
    };
    save_recovery_kdf_toml(&recovery_dir, &new_kdf)
        .map_err(|error| CliError::Config(format!("save recovery kdf: {error}")))?;
    save_recovery_envelope(&recovery_dir, &new_envelope)
        .map_err(|error| CliError::Config(format!("save recovery envelope: {error}")))?;
    write_recovery_rotate_audit(context, &resolved, &new_kdf.kdf_profile_id, timestamp)?;
    display_recovery_code(output, &code_bytes)
}

pub fn restore_from_recovery_code(
    context: &RuntimeContext,
    output: &mut impl Write,
    resolved: &ResolvedProject,
    kdf: &RecoveryKdfToml,
    envelope: &RecoveryEnvelope,
    code_bytes: &[u8; locket_crypto::RECOVERY_CODE_BYTES],
    force: bool,
) -> Result<(), CliError> {
    let project_id = resolved.config.project_id.as_str();
    validate_recovery_metadata(project_id, kdf, envelope)?;
    if !force {
        match context.key_store.load_master_key(project_id) {
            Ok(_) => {
                return Err(crate::secret_already_exists_error(
                    "master key already exists; use --force to overwrite",
                ));
            }
            Err(locket_platform::PlatformError::MasterKeyNotFound) => {}
            Err(error) => return Err(CliError::Platform(error)),
        }
    }

    let salt = kdf
        .decode_salt()
        .map_err(|error| CliError::Config(format!("recovery kdf salt: {error}")))?;
    let unwrap_root = derive_recovery_key_v1(code_bytes, &salt, kdf.to_crypto_params())?;
    let mut restored = 0usize;
    for entry in &envelope.entries {
        if entry.entry_kind != "master_key" {
            continue;
        }
        if entry.entry_id != project_id {
            return Err(CliError::Config("recovery envelope project id mismatch".to_owned()));
        }
        let plaintext = open_recovery_entry_v1(
            &unwrap_root,
            &kdf.kdf_profile_id,
            &entry.entry_kind,
            &entry.entry_id,
            &entry.nonce,
            &entry.ciphertext,
        )?;
        if plaintext.len() != locket_crypto::KEY_LEN {
            return Err(CliError::Crypto(locket_crypto::CryptoError::InvalidWrappedKey));
        }
        let mut master_key = zeroize::Zeroizing::new([0_u8; locket_crypto::KEY_LEN]);
        master_key.copy_from_slice(&plaintext);
        context.key_store.store_master_key(project_id, &master_key)?;
        restored += 1;
    }
    if restored == 0 {
        return Err(CliError::Config(
            "no master_key entries found in recovery envelope".to_owned(),
        ));
    }
    writeln!(output, "recovered: master_key")?;
    writeln!(output, "metadata_only: yes")?;
    Ok(())
}

fn validate_recovery_metadata(
    project_id: &str,
    kdf: &RecoveryKdfToml,
    envelope: &RecoveryEnvelope,
) -> Result<(), CliError> {
    kdf.validate()?;
    if envelope.kdf_profile_id != kdf.kdf_profile_id {
        return Err(CliError::Config("recovery envelope kdf profile mismatch".to_owned()));
    }
    if !envelope
        .entries
        .iter()
        .any(|entry| entry.entry_kind == "master_key" && entry.entry_id == project_id)
    {
        return Err(CliError::Config(
            "recovery envelope does not contain this project master key".to_owned(),
        ));
    }
    Ok(())
}

fn rewrap_recovery_entries(
    old_envelope: &RecoveryEnvelope,
    old_kdf_profile_id: &str,
    old_root: &locket_crypto::KeyBytes,
    new_kdf: &RecoveryKdfToml,
    new_root: &locket_crypto::KeyBytes,
) -> Result<Vec<RecoveryEnvelopeEntry>, CliError> {
    let mut entries = Vec::with_capacity(old_envelope.entries.len());
    for entry in &old_envelope.entries {
        let plaintext = open_recovery_entry_v1(
            old_root,
            old_kdf_profile_id,
            &entry.entry_kind,
            &entry.entry_id,
            &entry.nonce,
            &entry.ciphertext,
        )?;
        entries.push(seal_recovery_envelope_entry(
            new_root,
            &new_kdf.kdf_profile_id,
            &entry.entry_kind,
            &entry.entry_id,
            &plaintext,
        )?);
    }
    Ok(entries)
}

pub fn recovery_dir(resolved: &ResolvedProject) -> PathBuf {
    resolved.root.join(".locket").join("recovery")
}

fn display_recovery_code(
    output: &mut impl Write,
    code_bytes: &[u8; locket_crypto::RECOVERY_CODE_BYTES],
) -> Result<(), CliError> {
    let code = formatted_recovery_code(code_bytes)?;
    writeln!(output, "recovery_code_rotate: success")?;
    writeln!(output, "recovery_code (shown once, store securely):")?;
    writeln!(output, "{code}")?;
    writeln!(output, "metadata_only: yes")?;
    Ok(())
}

fn write_recovery_rotate_audit(
    context: &RuntimeContext,
    resolved: &ResolvedProject,
    kdf_profile_id: &str,
    timestamp: i64,
) -> Result<(), CliError> {
    let mut store = open_store(context)?;
    let audit_key =
        load_project_key(context, &store, resolved.config.project_id.as_str(), KeyPurpose::Audit)?;
    let metadata = json!({
        "schema_version": 1,
        "action": "RECOVERY_ROTATE",
        "status": "SUCCESS",
        "kdf_profile_id": kdf_profile_id,
    });
    let audit = AuditWrite {
        project_id: resolved.config.project_id.as_str(),
        profile_id: None,
        action: "RECOVERY_ROTATE",
        status: "SUCCESS",
        secret_name: None,
        command: Some("recovery rotate"),
        metadata_json: &metadata,
        timestamp,
    };
    store.append_audit(audit_key.as_ref(), &audit)?;
    Ok(())
}
