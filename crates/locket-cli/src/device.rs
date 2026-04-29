use data_encoding::BASE64URL_NOPAD;
use locket_core::DeviceId;
use locket_crypto::{KeyPurpose, generate_key};
use locket_store::{AuditWrite, DeviceRecord, Store};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::io::Write;

use crate::{
    CliError, DeviceAddArgs, DeviceCommand, DeviceInitArgs, DeviceListArgs, DeviceRemoveArgs,
    RuntimeContext, ensure_project_exists, format_hex, load_project_key, now_unix_nanos,
    open_store, require_project,
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
    ensure_project_exists(&store, project_id)?;
    let timestamp = now_unix_nanos()?;

    if let Some(existing) = store.get_active_local_device(project_id)? {
        if !args.force {
            writeln!(output, "device: already initialized")?;
            writeln!(output, "device_id: {}", existing.id)?;
            writeln!(output, "fingerprint: {}", existing.fingerprint)?;
            writeln!(output, "metadata_only: yes")?;
            return Ok(());
        }
        store.revoke_device(project_id, &existing.id, timestamp)?;
        write_device_audit_if_available(
            context,
            &mut store,
            project_id,
            "DEVICE_REVOKE",
            "device init --force",
            &existing,
        )?;
    }

    let device = generate_local_device_record(project_id, timestamp)?;
    store.insert_device(&device)?;
    write_device_audit_if_available(
        context,
        &mut store,
        project_id,
        "DEVICE_ADD",
        "device init",
        &device,
    )?;
    let descriptor = encode_device_descriptor(&device)?;

    writeln!(output, "device: initialized")?;
    writeln!(output, "device_id: {}", device.id)?;
    writeln!(output, "fingerprint: {}", device.fingerprint)?;
    writeln!(output, "safety_words: {}", device.safety_words.join(" "))?;
    writeln!(output, "descriptor: {descriptor}")?;
    writeln!(output, "private_key_storage: unavailable")?;
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
        .ok_or_else(|| CliError::Config("local device is not initialized".to_owned()))?;
    let descriptor = encode_device_descriptor(&device)?;

    writeln!(output, "device_id: {}", device.id)?;
    writeln!(output, "fingerprint: {}", device.fingerprint)?;
    writeln!(output, "safety_words: {}", device.safety_words.join(" "))?;
    writeln!(output, "descriptor: {descriptor}")?;
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
        return Err(CliError::Config("device descriptor fingerprint mismatch".to_owned()));
    }
    let device = DeviceRecord {
        id: descriptor.device_id,
        project_id: project_id.to_owned(),
        name: args.name.clone(),
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
        .ok_or_else(|| CliError::Config("device not found".to_owned()))?;
    if device.local && !args.force {
        return Err(CliError::Config(
            "removing the active local device requires --force".to_owned(),
        ));
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
    )?;
    writeln!(output, "device: revoked")?;
    writeln!(output, "device_id: {}", device.id)?;
    writeln!(output, "fingerprint: {}", device.fingerprint)?;
    writeln!(output, "metadata_only: yes")?;
    Ok(())
}

fn generate_local_device_record(
    project_id: &str,
    timestamp: i64,
) -> Result<DeviceRecord, CliError> {
    let signing_seed = generate_key()?;
    let sealing_seed = generate_key()?;
    let signing_public_key = *signing_seed;
    let sealing_public_key = *sealing_seed;
    let fingerprint = device_fingerprint_hex(&signing_public_key, &sealing_public_key);
    Ok(DeviceRecord {
        id: DeviceId::generate()
            .map_err(|_| CliError::Config("device id generation failed".to_owned()))?
            .into_string(),
        project_id: project_id.to_owned(),
        name: default_device_name(),
        signing_public_key: signing_public_key.to_vec(),
        sealing_public_key: sealing_public_key.to_vec(),
        safety_words: safety_words_from_fingerprint(&fingerprint),
        fingerprint,
        local: true,
        created_at: timestamp,
        last_seen_at: Some(timestamp),
        revoked_at: None,
    })
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
        return Err(CliError::Config("device descriptor must start with lkdev1_".to_owned()));
    };
    let bytes = BASE64URL_NOPAD
        .decode(encoded.as_bytes())
        .map_err(|_| CliError::Config("device descriptor is not valid base64url".to_owned()))?;
    let descriptor: DeviceDescriptorV1 = serde_json::from_slice(&bytes)?;
    if descriptor.v != 1 {
        return Err(CliError::Config("unsupported device descriptor version".to_owned()));
    }
    DeviceId::new(descriptor.device_id.clone())
        .map_err(|_| CliError::Config("device descriptor id is invalid".to_owned()))?;
    Ok(descriptor)
}

pub fn decode_descriptor_key(value: &str) -> Result<[u8; 32], CliError> {
    let bytes = BASE64URL_NOPAD
        .decode(value.as_bytes())
        .map_err(|_| CliError::Config("device descriptor key is not valid base64url".to_owned()))?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        CliError::Config(format!("device descriptor key must be 32 bytes, got {}", bytes.len()))
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

fn safety_words_from_fingerprint(fingerprint: &str) -> Vec<String> {
    const WORDS: [&str; 16] = [
        "amber", "basil", "cedar", "delta", "ember", "frost", "glade", "harbor", "indigo",
        "juniper", "kelp", "linen", "maple", "north", "onyx", "prairie",
    ];
    fingerprint
        .bytes()
        .take(6)
        .filter_map(|byte| char::from(byte).to_digit(16))
        .filter_map(|index| WORDS.get(index as usize))
        .map(|word| (*word).to_owned())
        .collect()
}

fn default_device_name() -> String {
    std::env::var("HOSTNAME")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "local-device".to_owned())
}

fn validate_device_name(name: &str) -> Result<(), CliError> {
    if name.trim().is_empty() || name.len() > 80 || name.chars().any(char::is_control) {
        return Err(CliError::Config("invalid device name".to_owned()));
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
) -> Result<(), CliError> {
    let Ok(audit_key) = load_project_key(context, store, project_id, KeyPurpose::Audit) else {
        return Ok(());
    };
    let metadata = json!({
        "schema_version": 1,
        "action": action,
        "status": "SUCCESS",
        "command": command,
        "device_id": device.id,
        "device_name": device.name,
        "fingerprint": device.fingerprint,
        "local": device.local,
    });
    let audit = AuditWrite {
        project_id,
        profile_id: None,
        action,
        status: "SUCCESS",
        secret_name: None,
        command: Some(command),
        metadata_json: &metadata,
        timestamp: now_unix_nanos()?,
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
