use data_encoding::BASE64URL_NOPAD;
use locket_core::{DeviceId, LocketError, ProjectConfig, safety_words_from_fingerprint_hex};
use locket_crypto::{
    KeyPurpose, derive_recovery_key_v1, generate_key, generate_recovery_code_bytes,
    generate_recovery_salt,
};
use locket_platform::{
    LocalDevicePrivateKeyStorage, PlatformError, RecoveryEnvelope, RecoveryKdfToml,
    WrappedLocalFileDevicePrivateKeyStorage, save_recovery_envelope, save_recovery_kdf_toml,
};
use locket_store::{AuditContext, AuditWrite, DeviceRecord, Store};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};

use crate::runtime::error::{confirmation_failed_error, corrupt_db_error, typed_cli_error};
use crate::runtime::user_verification::{
    UserVerificationAudit, configured_user_verification, require_user_verification,
};
use crate::{
    CliError, DeviceAddArgs, DeviceCommand, DeviceInitArgs, DeviceListArgs, DeviceRemoveArgs,
    ResolvedProject, RuntimeContext, access_denied_error, ensure_project_exists,
    ensure_project_metadata, format_hex, formatted_recovery_code, insert_wrapped_key,
    invalid_reference_error, load_project_key, metadata_invalid_error, now_unix_nanos, open_store,
    require_project, seal_recovery_envelope_entry, store_master_key_with_fallback, trust_root,
};

pub fn device_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    command: DeviceCommand,
) -> Result<(), CliError> {
    match command {
        DeviceCommand::Init(args) => device_init_command(context, output, &args),
        DeviceCommand::Pubkey => device_pubkey_command(context, output),
        DeviceCommand::Add(args) => device_add_command(context, output, &args),
        DeviceCommand::List(args) => device_list_command(context, output, &args),
        DeviceCommand::Remove(args) => device_remove_command(context, output, &args),
    }
}

fn device_init_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &DeviceInitArgs,
) -> Result<(), CliError> {
    let resolved = require_project(context)?;
    let mut store = open_store(context)?;
    let project_id = resolved.config.project_id.as_str();
    let timestamp = now_unix_nanos()?;
    let bootstrapped =
        maybe_bootstrap_first_run_on_machine(context, &mut store, &resolved, output, timestamp)?;
    if !bootstrapped {
        ensure_project_exists(&store, project_id)?;
    }

    let existing_replacement = if let Some(existing) = store.get_active_local_device(project_id)? {
        if !args.force {
            writeln!(output, "device: already initialized")?;
            writeln!(output, "device_id: {}", existing.id)?;
            writeln!(output, "fingerprint: {}", existing.fingerprint)?;
            writeln!(output, "metadata_only: yes")?;
            return Ok(());
        }
        let verification =
            require_user_verification(context, "device init --force", "Replace local device key")?;
        Some((existing, verification))
    } else {
        None
    };
    let user_verification = if let Some((_, verification)) = existing_replacement.as_ref() {
        *verification
    } else {
        configured_user_verification(
            context,
            "user_verification_required_for.device_register",
            "device init",
            "register a local device",
        )?
    };
    let GeneratedLocalDevice { record: device, sealing_private_key } =
        generate_local_device_record(project_id, timestamp)?;
    let storage = build_device_private_key_storage(context, project_id)?;
    if let Some((existing, verification)) = existing_replacement {
        replace_local_device_with_audit(
            context,
            &mut store,
            project_id,
            &existing,
            &device,
            verification,
            timestamp,
        )?;
        // Force-rekey envelope swap: store the replacement envelope BEFORE
        // deleting the prior device's envelope so a failure mid-rotation
        // never leaves the active device row pointing at a missing envelope.
        // If the new store succeeds, drop the prior envelope on a best-effort
        // basis: the active row already points at the replacement, so a
        // stranded old envelope is a soft cleanup issue rather than a
        // correctness failure.
        storage.store(&device.id, &sealing_private_key)?;
        let _ = storage.delete(&existing.id);
    } else {
        store.insert_device(&device)?;
        write_device_audit_if_available(
            context,
            &mut store,
            project_id,
            "DEVICE_ADD",
            "device init",
            &device,
            user_verification,
        )?;
        storage.store(&device.id, &sealing_private_key)?;
    }
    let descriptor = encode_device_descriptor(&device)?;

    writeln!(output, "device: initialized")?;
    writeln!(output, "device_id: {}", device.id)?;
    writeln!(output, "fingerprint: {}", device.fingerprint)?;
    writeln!(output, "safety_words: {}", device.safety_words.join(" "))?;
    writeln!(output, "descriptor: {descriptor}")?;
    writeln!(output, "private_key_storage: wrapped-local-file")?;
    writeln!(output, "metadata_only: yes")?;
    Ok(())
}

fn device_pubkey_command(
    context: &RuntimeContext,
    output: &mut impl Write,
) -> Result<(), CliError> {
    let resolved = require_project(context)?;
    let store = open_store(context)?;
    let project_id = resolved.config.project_id.as_str();
    ensure_project_exists(&store, project_id)?;
    let device = store
        .get_active_local_device(project_id)?
        .ok_or_else(|| invalid_reference_error("local device is not initialized"))?;
    let descriptor = encode_device_descriptor(&device)?;
    let storage = build_device_private_key_storage(context, project_id)?;
    let private_key = storage.load(&device.id)?;
    let secret = X25519StaticSecret::from(*private_key);
    let derived_public = X25519PublicKey::from(&secret).to_bytes();
    let stored_public: [u8; 32] = device
        .sealing_public_key
        .as_slice()
        .try_into()
        .map_err(|_| corrupt_db_error("device sealing public key has unexpected length"))?;
    if derived_public != stored_public {
        return Err(corrupt_db_error("device private key does not match stored public key"));
    }

    writeln!(output, "device_id: {}", device.id)?;
    writeln!(output, "fingerprint: {}", device.fingerprint)?;
    writeln!(output, "safety_words: {}", device.safety_words.join(" "))?;
    writeln!(output, "sealing_public_key_x25519: {}", BASE64URL_NOPAD.encode(&derived_public))?;
    writeln!(output, "descriptor: {descriptor}")?;
    writeln!(output, "private_key_storage: wrapped-local-file")?;
    writeln!(output, "metadata_only: yes")?;
    Ok(())
}

fn device_add_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &DeviceAddArgs,
) -> Result<(), CliError> {
    validate_device_name(&args.name)?;
    let resolved = require_project(context)?;
    let mut store = open_store(context)?;
    let project_id = resolved.config.project_id.as_str();
    ensure_project_exists(&store, project_id)?;
    let descriptor = decode_device_descriptor(&args.device)?;
    let signing_public_key = decode_descriptor_key(&descriptor.signing_public_key_ed25519)?;
    let sealing_public_key = decode_descriptor_key(&descriptor.sealing_public_key_x25519)?;
    let fingerprint = device_fingerprint_hex(&signing_public_key, &sealing_public_key);
    if fingerprint != descriptor.fingerprint_sha256 {
        return Err(metadata_invalid_error("device descriptor fingerprint mismatch"));
    }
    let user_verification = configured_user_verification(
        context,
        "user_verification_required_for.device_register",
        "device add",
        format!("register device {}", args.name),
    )?;
    let device = DeviceRecord {
        id: descriptor.device_id,
        project_id: project_id.to_owned(),
        member_id: None,
        name: args.name.clone(),
        // v1 device add does not collect a separate display label;
        // mirror `name` so existing CLI/UI surfaces have a non-empty
        // label until label-on-add is wired in a follow-up.
        label: args.name.clone(),
        signing_public_key: signing_public_key.to_vec(),
        sealing_public_key: sealing_public_key.to_vec(),
        fingerprint,
        safety_words: descriptor.safety_words,
        local: false,
        created_at: now_unix_nanos()?,
        last_seen_at: None,
        revoked_at: None,
    };
    store.insert_device(&device)?;
    write_device_audit_if_available(
        context,
        &mut store,
        project_id,
        "DEVICE_ADD",
        "device add",
        &device,
        user_verification,
    )?;

    writeln!(output, "device: added")?;
    writeln!(output, "name: {}", device.name)?;
    writeln!(output, "device_id: {}", device.id)?;
    writeln!(output, "fingerprint: {}", device.fingerprint)?;
    writeln!(output, "metadata_only: yes")?;
    Ok(())
}

fn device_list_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &DeviceListArgs,
) -> Result<(), CliError> {
    let resolved = require_project(context)?;
    let store = open_store(context)?;
    let project_id = resolved.config.project_id.as_str();
    ensure_project_exists(&store, project_id)?;
    let devices = store.list_devices(project_id, args.all)?;
    if devices.is_empty() {
        writeln!(output, "devices: none")?;
    } else {
        writeln!(output, "devices:")?;
        for device in devices {
            let state = if device.revoked_at.is_some() { "revoked" } else { "active" };
            let local = if device.local { " local" } else { "" };
            writeln!(
                output,
                "- {} id={} fingerprint={} state={}{}",
                device.name, device.id, device.fingerprint, state, local
            )?;
        }
    }
    writeln!(output, "metadata_only: yes")?;
    Ok(())
}

fn device_remove_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &DeviceRemoveArgs,
) -> Result<(), CliError> {
    let resolved = require_project(context)?;
    let mut store = open_store(context)?;
    let project_id = resolved.config.project_id.as_str();
    ensure_project_exists(&store, project_id)?;
    let device = store
        .find_device(project_id, &args.device)?
        .ok_or_else(|| invalid_reference_error("device not found"))?;
    if device.local && !args.force {
        return Err(access_denied_error("removing the active local device requires --force"));
    }
    if device.revoked_at.is_some() {
        writeln!(output, "device: already revoked")?;
        writeln!(output, "device_id: {}", device.id)?;
        writeln!(output, "metadata_only: yes")?;
        return Ok(());
    }
    store.revoke_device(project_id, &device.id, now_unix_nanos()?)?;
    write_device_audit_if_available(
        context,
        &mut store,
        project_id,
        "DEVICE_REVOKE",
        "device remove",
        &device,
        UserVerificationAudit::not_required(),
    )?;
    // Local-device revocation also drops the wrapped private-key envelope.
    // We only ever held a private key for the local device; remote teammate
    // device records never have an envelope to clean up.
    if device.local {
        let storage = build_device_private_key_storage(context, project_id)?;
        let _ = storage.delete(&device.id);
    }
    writeln!(output, "device: revoked")?;
    writeln!(output, "device_id: {}", device.id)?;
    writeln!(output, "fingerprint: {}", device.fingerprint)?;
    writeln!(output, "metadata_only: yes")?;
    Ok(())
}

/// Best-effort delete of a wrapped-local-file device private-key envelope when
/// the revoked device row was the active local device.
///
/// Sibling commands (e.g. `team revoke-device`) use this to keep the local
/// envelope store consistent with the `team_devices` table. Remote teammate
/// device records never have an envelope on this host, so callers should pass
/// `device.local` as the gate.
pub(super) fn cleanup_local_device_envelope_if_local(
    context: &RuntimeContext,
    project_id: &str,
    device: &DeviceRecord,
) -> Result<(), CliError> {
    if !device.local {
        // Remote teammate device record: we never had its private key on this
        // host; nothing to delete.
        return Ok(());
    }
    let storage = build_device_private_key_storage(context, project_id)?;
    let _ = storage.delete(&device.id);
    Ok(())
}

struct GeneratedLocalDevice {
    record: DeviceRecord,
    sealing_private_key: zeroize::Zeroizing<[u8; 32]>,
}

fn generate_local_device_record(
    project_id: &str,
    timestamp: i64,
) -> Result<GeneratedLocalDevice, CliError> {
    let signing_seed = generate_key()?;
    let signing_public_key = *signing_seed;
    let sealing_seed = generate_key()?;
    let sealing_secret = X25519StaticSecret::from(*sealing_seed);
    let sealing_public_key = X25519PublicKey::from(&sealing_secret);
    let mut sealing_private_key = zeroize::Zeroizing::new([0_u8; 32]);
    sealing_private_key.copy_from_slice(sealing_secret.as_bytes());
    let sealing_public_bytes = sealing_public_key.to_bytes();
    let fingerprint = device_fingerprint_hex(&signing_public_key, &sealing_public_bytes);
    let device_name = default_device_name();
    let record = DeviceRecord {
        id: DeviceId::generate()
            .map_err(|_| corrupt_db_error("device id generation failed"))?
            .into_string(),
        project_id: project_id.to_owned(),
        member_id: None,
        // Local device records mirror `name` into `label` until a
        // dedicated label flow exists. See data-model.md lines 254-265.
        label: device_name.clone(),
        name: device_name,
        signing_public_key: signing_public_key.to_vec(),
        sealing_public_key: sealing_public_bytes.to_vec(),
        safety_words: safety_words_from_fingerprint(&fingerprint),
        fingerprint,
        local: true,
        created_at: timestamp,
        last_seen_at: Some(timestamp),
        revoked_at: None,
    };
    Ok(GeneratedLocalDevice { record, sealing_private_key })
}

pub fn device_private_key_root(context: &RuntimeContext) -> Result<PathBuf, CliError> {
    context
        .store_path
        .parent()
        .map(std::path::Path::to_path_buf)
        .ok_or_else(|| corrupt_db_error("could not resolve device private key root"))
}

pub fn build_device_private_key_storage(
    context: &RuntimeContext,
    project_id: &str,
) -> Result<WrappedLocalFileDevicePrivateKeyStorage, CliError> {
    Ok(WrappedLocalFileDevicePrivateKeyStorage::new(
        device_private_key_root(context)?,
        project_id.to_owned(),
        std::sync::Arc::clone(&context.key_store),
    ))
}

pub fn encode_device_descriptor(device: &DeviceRecord) -> Result<String, CliError> {
    let descriptor = DeviceDescriptorV1 {
        v: 1,
        device_id: device.id.clone(),
        label: device.name.clone(),
        signing_public_key_ed25519: BASE64URL_NOPAD.encode(&device.signing_public_key),
        sealing_public_key_x25519: BASE64URL_NOPAD.encode(&device.sealing_public_key),
        fingerprint_sha256: device.fingerprint.clone(),
        safety_words: device.safety_words.clone(),
    };
    let json = serde_json::to_vec(&descriptor)?;
    Ok(format!("lkdev1_{}", BASE64URL_NOPAD.encode(&json)))
}

pub fn decode_device_descriptor(value: &str) -> Result<DeviceDescriptorV1, CliError> {
    let Some(encoded) = value.strip_prefix("lkdev1_") else {
        return Err(metadata_invalid_error("device descriptor must start with lkdev1_"));
    };
    let bytes = BASE64URL_NOPAD
        .decode(encoded.as_bytes())
        .map_err(|_| metadata_invalid_error("device descriptor is not valid base64url"))?;
    let descriptor: DeviceDescriptorV1 = serde_json::from_slice(&bytes)?;
    if descriptor.v != 1 {
        return Err(metadata_invalid_error("unsupported device descriptor version"));
    }
    DeviceId::new(descriptor.device_id.clone())
        .map_err(|_| metadata_invalid_error("device descriptor id is invalid"))?;
    Ok(descriptor)
}

pub fn decode_descriptor_key(value: &str) -> Result<[u8; 32], CliError> {
    let bytes = BASE64URL_NOPAD
        .decode(value.as_bytes())
        .map_err(|_| metadata_invalid_error("device descriptor key is not valid base64url"))?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        metadata_invalid_error(format!(
            "device descriptor key must be 32 bytes, got {}",
            bytes.len()
        ))
    })
}

pub fn device_fingerprint_hex(
    signing_public_key: &[u8; 32],
    sealing_public_key: &[u8; 32],
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"locket-device-v1");
    hasher.update(32_u16.to_le_bytes());
    hasher.update(signing_public_key);
    hasher.update(32_u16.to_le_bytes());
    hasher.update(sealing_public_key);
    format_hex(&hasher.finalize())
}

pub(super) fn safety_words_from_fingerprint(fingerprint: &str) -> Vec<String> {
    safety_words_from_fingerprint_hex(fingerprint).into_iter().map(str::to_owned).collect()
}

fn default_device_name() -> String {
    std::env::var("HOSTNAME")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "local-device".to_owned())
}

fn validate_device_name(name: &str) -> Result<(), CliError> {
    if name.trim().is_empty() || name.len() > 80 || name.chars().any(char::is_control) {
        return Err(metadata_invalid_error("invalid device name"));
    }
    Ok(())
}

fn write_device_audit_if_available(
    context: &RuntimeContext,
    store: &mut Store,
    project_id: &str,
    action: &'static str,
    command: &'static str,
    device: &DeviceRecord,
    user_verification: UserVerificationAudit,
) -> Result<(), CliError> {
    let audit_key = load_project_key(context, store, project_id, KeyPurpose::Audit)?;
    let metadata = device_audit_metadata(action, command, device, user_verification);
    let timestamp = now_unix_nanos()?;
    let audit = device_audit_write(project_id, action, command, &metadata, timestamp);
    store.append_audit(audit_key.as_ref(), &audit)?;
    Ok(())
}

fn replace_local_device_with_audit(
    context: &RuntimeContext,
    store: &mut Store,
    project_id: &str,
    existing: &DeviceRecord,
    replacement: &DeviceRecord,
    user_verification: UserVerificationAudit,
    timestamp: i64,
) -> Result<(), CliError> {
    let audit_key = load_project_key(context, store, project_id, KeyPurpose::Audit)?;
    let revoke_metadata =
        device_audit_metadata("DEVICE_REVOKE", "device init --force", existing, user_verification);
    let add_metadata =
        device_audit_metadata("DEVICE_ADD", "device init --force", replacement, user_verification);
    let revoke_audit = device_audit_write(
        project_id,
        "DEVICE_REVOKE",
        "device init --force",
        &revoke_metadata,
        timestamp,
    );
    let add_audit = device_audit_write(
        project_id,
        "DEVICE_ADD",
        "device init --force",
        &add_metadata,
        timestamp,
    );
    let replaced = store.replace_local_device(
        project_id,
        &existing.id,
        timestamp,
        replacement,
        Some(AuditContext { key: audit_key.as_ref(), write: &revoke_audit }),
        Some(AuditContext { key: audit_key.as_ref(), write: &add_audit }),
    )?;
    if !replaced {
        return Err(invalid_reference_error("local device is not initialized"));
    }
    Ok(())
}

fn device_audit_metadata(
    action: &'static str,
    command: &'static str,
    device: &DeviceRecord,
    user_verification: UserVerificationAudit,
) -> serde_json::Value {
    json!({
        "schema_version": 1,
        "action": action,
        "status": "SUCCESS",
        "command": command,
        "device_id": device.id,
        "device_name": device.name,
        "fingerprint": device.fingerprint,
        "local": device.local,
        "user_verification": user_verification,
    })
}

const fn device_audit_write<'a>(
    project_id: &'a str,
    action: &'static str,
    command: &'static str,
    metadata: &'a serde_json::Value,
    timestamp: i64,
) -> AuditWrite<'a> {
    AuditWrite {
        project_id,
        profile_id: None,
        action,
        status: "SUCCESS",
        secret_name: None,
        command: Some(command),
        metadata_json: metadata,
        timestamp,
    }
}

/// Detects whether `device init` is the first invocation on this machine and,
/// if so, bootstraps the local master key, recovery envelope, recovery code,
/// and project records before the regular `device init` flow proceeds.
///
/// Returns `Ok(true)` when the bootstrap was performed, `Ok(false)` when the
/// existing-master-key path applies, and an `AmbiguousBootstrapState`-flavored
/// error (mapped to `LostKeychainEntry`) when partial state is detected.
fn maybe_bootstrap_first_run_on_machine(
    context: &RuntimeContext,
    store: &mut Store,
    resolved: &ResolvedProject,
    output: &mut impl Write,
    timestamp: i64,
) -> Result<bool, CliError> {
    let project_id = resolved.config.project_id.as_str();
    match context.key_store.load_master_key(project_id) {
        Ok(_) => Ok(false),
        Err(PlatformError::MasterKeyNotFound) => {
            if context.passphrase_store.contains_project(project_id)? {
                return Ok(false);
            }
            let envelope_present = recovery_envelope_present(&resolved.root);
            let team_row_present =
                store.get_project(project_id)?.is_some() && team_row_exists(store, project_id)?;
            if envelope_present || team_row_present {
                return Err(ambiguous_bootstrap_state_error(envelope_present, team_row_present));
            }
            bootstrap_first_run_on_machine(context, store, resolved, output, timestamp)?;
            Ok(true)
        }
        Err(error) => Err(CliError::Platform(error)),
    }
}

fn recovery_envelope_present(root: &Path) -> bool {
    let recovery_dir = root.join(".locket").join("recovery");
    recovery_dir.join("envelope.bin").exists() || recovery_dir.join("kdf.toml").exists()
}

fn team_row_exists(store: &Store, project_id: &str) -> Result<bool, CliError> {
    Ok(store.get_team_by_project(project_id)?.is_some())
}

fn ambiguous_bootstrap_state_error(envelope_present: bool, team_row_present: bool) -> CliError {
    let message = match (envelope_present, team_row_present) {
        (true, true) => {
            "ambiguous bootstrap state: recovery envelope and team membership both present \
             without a local master key; run `locket recover` to restore the keychain entry, \
             or `locket team accept` if you have a fresh invite"
        }
        (true, false) => {
            "ambiguous bootstrap state: recovery envelope is present but the local master key \
             is missing; run `locket recover` to restore the keychain entry"
        }
        (false, true) => {
            "ambiguous bootstrap state: a team record exists for this project but no local \
             master key is present; run `locket team accept <invite>` or `locket recover`"
        }
        (false, false) => {
            "ambiguous bootstrap state: master key is missing and partial state was detected"
        }
    };
    typed_cli_error(LocketError::LostKeychainEntry, message)
}

/// Performs the first-run-on-machine bootstrap for `device init`.
///
/// This is invoked when no local master key exists and no partial state
/// (recovery envelope, team membership) is detected. It generates a fresh
/// master key, persists it via the configured master-key store with passphrase
/// fallback, creates the project records, project key material, recovery
/// envelope, and displays the recovery code under the same one-time-display
/// rules used by `locket init`.
fn bootstrap_first_run_on_machine(
    context: &RuntimeContext,
    store: &mut Store,
    resolved: &ResolvedProject,
    output: &mut impl Write,
    timestamp: i64,
) -> Result<(), CliError> {
    let config = &resolved.config;
    let project_id = config.project_id.as_str();

    ensure_project_metadata(store, config, timestamp)?;

    let master_key = generate_key()?;
    store_master_key_with_fallback(context, project_id, &master_key, timestamp)?;

    insert_wrapped_key(
        store,
        project_id,
        None,
        KeyPurpose::ProjectMetadata,
        &master_key,
        timestamp,
    )?;
    insert_wrapped_key(store, project_id, None, KeyPurpose::Audit, &master_key, timestamp)?;

    let profile = store
        .get_profile_by_name(project_id, config.default_profile.as_str())?
        .ok_or_else(|| corrupt_db_error("default profile is missing after bootstrap"))?;
    insert_wrapped_key(
        store,
        project_id,
        Some(&profile.id),
        KeyPurpose::ProfileSecret,
        &master_key,
        timestamp,
    )?;
    insert_wrapped_key(
        store,
        project_id,
        Some(&profile.id),
        KeyPurpose::ProfileFingerprint,
        &master_key,
        timestamp,
    )?;

    let code_bytes =
        create_bootstrap_recovery_envelope(&resolved.root, config, &master_key, timestamp)?;

    trust_root(store, config, &resolved.root, timestamp)?;

    display_bootstrap_recovery_code(context, output, config, &code_bytes)?;

    write_bootstrap_audit(context, store, resolved, &profile.id, timestamp)?;

    Ok(())
}

fn create_bootstrap_recovery_envelope(
    root: &Path,
    config: &ProjectConfig,
    master_key: &locket_crypto::KeyBytes,
    timestamp: i64,
) -> Result<[u8; locket_crypto::RECOVERY_CODE_BYTES], CliError> {
    let recovery_dir = root.join(".locket").join("recovery");
    let code_bytes = generate_recovery_code_bytes()?;
    let salt = generate_recovery_salt()?;
    let kdf_profile_id = format!("lk_kdf_{}", format_hex(&salt[..16]));
    let kdf = RecoveryKdfToml::new_v1(kdf_profile_id, &salt, timestamp);
    let recovery_root = derive_recovery_key_v1(&code_bytes, &salt, kdf.to_crypto_params())?;
    let entry = seal_recovery_envelope_entry(
        &recovery_root,
        &kdf.kdf_profile_id,
        "master_key",
        config.project_id.as_str(),
        master_key,
    )?;
    let envelope = RecoveryEnvelope {
        kdf_profile_id: kdf.kdf_profile_id.clone(),
        created_at_unix_nanos: i128::from(timestamp),
        entries: vec![entry],
    };
    save_recovery_kdf_toml(&recovery_dir, &kdf)
        .map_err(|error| metadata_invalid_error(format!("save recovery kdf: {error}")))?;
    save_recovery_envelope(&recovery_dir, &envelope)
        .map_err(|error| metadata_invalid_error(format!("save recovery envelope: {error}")))?;
    Ok(code_bytes)
}

fn display_bootstrap_recovery_code(
    context: &RuntimeContext,
    output: &mut impl Write,
    config: &ProjectConfig,
    code_bytes: &[u8; locket_crypto::RECOVERY_CODE_BYTES],
) -> Result<(), CliError> {
    let code = formatted_recovery_code(code_bytes)?;
    writeln!(output, "device_init_bootstrap: success")?;
    writeln!(output, "recovery_code (shown once, store securely):")?;
    writeln!(output, "{code}")?;
    writeln!(output, "Write this down. It will not be shown again.")?;
    writeln!(output, "warning: terminal scrollback may retain this code")?;
    writeln!(output, "type project name '{}' after recording the recovery code", config.name)?;
    let confirmation =
        context.confirmation_reader.read_confirmation("device init recovery code")?;
    if confirmation.trim_end_matches(['\r', '\n']) != config.name {
        return Err(confirmation_failed_error("confirmation did not match project name"));
    }
    if io::stdout().is_terminal() {
        let _ = io::stdout().write_all(b"\x1b[2J\x1b[H");
    }
    Ok(())
}

fn write_bootstrap_audit(
    context: &RuntimeContext,
    store: &mut Store,
    resolved: &ResolvedProject,
    default_profile_id: &str,
    timestamp: i64,
) -> Result<(), CliError> {
    let project_id = resolved.config.project_id.as_str();
    let audit_key = load_project_key(context, store, project_id, KeyPurpose::Audit)?;
    let metadata = json!({
        "schema_version": 1,
        "action": "BOOTSTRAP",
        "status": "SUCCESS",
        "command": "device init",
        "project_id": project_id,
        "default_profile_id": default_profile_id,
        "generated_files": Vec::<&str>::new(),
        "recovery_code_displayed": true,
    });
    let audit = AuditWrite {
        project_id,
        profile_id: Some(default_profile_id),
        action: "BOOTSTRAP",
        status: "SUCCESS",
        secret_name: None,
        command: Some("device init"),
        metadata_json: &metadata,
        timestamp,
    };
    store.append_audit(audit_key.as_ref(), &audit)?;
    Ok(())
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DeviceDescriptorV1 {
    pub v: u16,
    pub device_id: String,
    pub label: String,
    pub signing_public_key_ed25519: String,
    pub sealing_public_key_x25519: String,
    pub fingerprint_sha256: String,
    pub safety_words: Vec<String>,
}
