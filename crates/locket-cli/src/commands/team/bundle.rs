//! Bundle export, import, and verify command implementations.

use std::collections::BTreeSet;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use locket_crypto::KeyPurpose;
use locket_store::{AuditWrite, ProfileRecord, Store};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

use super::device;
use crate::{
    BundleCommand, BundleVerifyArgs, CliError, ExportArgs, ImportBundleArgs, ResolvedProject,
    RuntimeContext, bundle_verification_error, default_profile, ensure_project_exists,
    ensure_trusted_project_root, format_hex, load_project_key, now_unix_nanos, open_store,
    require_project, set_user_only_file_options, set_user_only_file_permissions,
};

const BUNDLE_MAGIC_V1: &str = "LOCKET-BUNDLE-V1";

#[derive(Debug, Deserialize, Serialize)]
struct SealedBundleFileV1 {
    magic: String,
    schema_version: u16,
    kind: String,
    created_at: i64,
    project_id: String,
    include_audit: bool,
    recipient_fingerprints: Vec<String>,
    payload_status: String,
    manifest_digest_sha256: String,
    payload: SealedBundlePayloadV1,
}

#[derive(Debug, Deserialize, Serialize)]
struct SealedBundlePayloadV1 {
    profiles: Vec<SealedBundleProfileV1>,
    profile_count: usize,
    active_secret_count: usize,
    audit_rows_included: bool,
}

#[derive(Debug, Deserialize, Serialize)]
struct SealedBundleProfileV1 {
    profile_id: String,
    dangerous: bool,
    active_secret_count: usize,
}

pub fn bundle_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    command: BundleCommand,
) -> Result<(), CliError> {
    match command {
        BundleCommand::Verify(args) => bundle_verify_command(context, output, &args),
    }
}

pub fn export_bundle_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &ExportArgs,
) -> Result<(), CliError> {
    if !args.sealed {
        return Err(CliError::Config("bundle export requires --sealed".to_owned()));
    }
    if args.recipients.is_empty() {
        return Err(CliError::Config("bundle export requires at least one --recipient".to_owned()));
    }

    let resolved = require_project(context)?;
    let mut store = open_store(context)?;
    ensure_project_exists(&store, resolved.config.project_id.as_str())?;
    ensure_trusted_project_root(&store, &resolved)?;
    let recipient_fingerprints = bundle_recipient_fingerprints(&args.recipients)?;
    let selected_profiles = selected_bundle_profiles(&store, &resolved, args)?;
    let timestamp = now_unix_nanos()?;
    let payload = bundle_payload(&store, &selected_profiles, args.include_audit)?;
    let manifest_digest_sha256 = bundle_payload_digest(&payload)?;
    let bundle = SealedBundleFileV1 {
        magic: BUNDLE_MAGIC_V1.to_owned(),
        schema_version: 1,
        kind: "sealed-bundle".to_owned(),
        created_at: timestamp,
        project_id: resolved.config.project_id.to_string(),
        include_audit: args.include_audit,
        recipient_fingerprints,
        payload_status: "metadata-only-placeholder".to_owned(),
        manifest_digest_sha256,
        payload,
    };
    let output_path =
        args.output.clone().unwrap_or_else(|| default_bundle_output_path(context, timestamp));
    write_bundle_file(&output_path, &bundle)?;
    write_bundle_audit_if_available(
        context,
        &mut store,
        &BundleAuditRequest {
            resolved: &resolved,
            action: "BACKUP_EXPORT",
            command: "export --sealed",
            bundle: &bundle,
            path_kind: output_path_kind(&output_path, context),
            timestamp,
        },
    )?;

    writeln!(output, "bundle: exported")?;
    writeln!(output, "path: {}", output_path.display())?;
    writeln!(output, "profiles: {}", bundle.payload.profile_count)?;
    writeln!(output, "active_secret_count: {}", bundle.payload.active_secret_count)?;
    writeln!(output, "recipients: {}", bundle.recipient_fingerprints.len())?;
    writeln!(output, "include_audit: {}", if bundle.include_audit { "yes" } else { "no" })?;
    writeln!(output, "payload_status: {}", bundle.payload_status)?;
    writeln!(output, "digest: {}", bundle.manifest_digest_sha256)?;
    writeln!(output, "metadata_only: yes")?;
    Ok(())
}

pub fn import_bundle_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &ImportBundleArgs,
) -> Result<(), CliError> {
    let resolved = require_project(context)?;
    let mut store = open_store(context)?;
    ensure_project_exists(&store, resolved.config.project_id.as_str())?;
    ensure_trusted_project_root(&store, &resolved)?;
    let bundle = verify_bundle_file(&args.bundle)?;
    if bundle.project_id != resolved.config.project_id.as_str() {
        return Err(CliError::Config(
            "bundle project id does not match current project".to_owned(),
        ));
    }
    let conflict_policy = if args.accept_incoming {
        "accept-incoming"
    } else if args.accept_local {
        "accept-local"
    } else {
        "interactive-required"
    };
    write_bundle_audit_if_available(
        context,
        &mut store,
        &BundleAuditRequest {
            resolved: &resolved,
            action: "BACKUP_IMPORT",
            command: "import-bundle",
            bundle: &bundle,
            path_kind: "input",
            timestamp: now_unix_nanos()?,
        },
    )?;

    writeln!(output, "bundle: verified")?;
    writeln!(output, "import: not_applied")?;
    writeln!(output, "reason: local device private-key import is not implemented in this build")?;
    writeln!(output, "profiles: {}", bundle.payload.profile_count)?;
    writeln!(output, "active_secret_count: {}", bundle.payload.active_secret_count)?;
    writeln!(output, "include_audit_requested: {}", if args.include_audit { "yes" } else { "no" })?;
    writeln!(output, "bundle_include_audit: {}", if bundle.include_audit { "yes" } else { "no" })?;
    writeln!(output, "conflict_policy: {conflict_policy}")?;
    writeln!(output, "metadata_only: yes")?;
    Ok(())
}

fn bundle_verify_command(
    _context: &RuntimeContext,
    output: &mut impl Write,
    args: &BundleVerifyArgs,
) -> Result<(), CliError> {
    let bundle = verify_bundle_file(&args.bundle)?;
    writeln!(output, "bundle: valid")?;
    writeln!(output, "schema_version: {}", bundle.schema_version)?;
    writeln!(output, "project_id: {}", bundle.project_id)?;
    writeln!(output, "profiles: {}", bundle.payload.profile_count)?;
    writeln!(output, "active_secret_count: {}", bundle.payload.active_secret_count)?;
    writeln!(output, "recipients: {}", bundle.recipient_fingerprints.len())?;
    writeln!(output, "digest: {}", bundle.manifest_digest_sha256)?;
    writeln!(output, "decryptable_by_this_device: no")?;
    writeln!(output, "metadata_only: yes")?;
    Ok(())
}

fn bundle_recipient_fingerprints(recipients: &[String]) -> Result<Vec<String>, CliError> {
    let mut fingerprints = BTreeSet::new();
    for recipient in recipients {
        let descriptor = device::decode_device_descriptor(recipient)?;
        let signing_public_key =
            device::decode_descriptor_key(&descriptor.signing_public_key_ed25519)?;
        let sealing_public_key =
            device::decode_descriptor_key(&descriptor.sealing_public_key_x25519)?;
        let fingerprint = device::device_fingerprint_hex(&signing_public_key, &sealing_public_key);
        if fingerprint != descriptor.fingerprint_sha256 {
            return Err(CliError::Config(
                "recipient device descriptor fingerprint mismatch".to_owned(),
            ));
        }
        fingerprints.insert(fingerprint);
    }
    Ok(fingerprints.into_iter().collect())
}

fn selected_bundle_profiles(
    store: &Store,
    resolved: &ResolvedProject,
    args: &ExportArgs,
) -> Result<Vec<ProfileRecord>, CliError> {
    if args.all_profiles {
        return store.list_profiles(resolved.config.project_id.as_str()).map_err(Into::into);
    }
    if let Some(profile_name) = &args.profile {
        return store
            .get_profile_by_name(resolved.config.project_id.as_str(), profile_name)?
            .map(|profile| vec![profile])
            .ok_or_else(|| CliError::Config(format!("profile not found: {profile_name}")));
    }
    Ok(vec![default_profile(store, &resolved.config)?])
}

fn bundle_payload(
    store: &Store,
    profiles: &[ProfileRecord],
    include_audit: bool,
) -> Result<SealedBundlePayloadV1, CliError> {
    let mut profile_summaries = Vec::with_capacity(profiles.len());
    let mut active_secret_count = 0_usize;
    for profile in profiles {
        let secrets = store.list_active_secrets_by_profile(&profile.project_id, &profile.id)?;
        active_secret_count = active_secret_count.saturating_add(secrets.len());
        profile_summaries.push(SealedBundleProfileV1 {
            profile_id: profile.id.clone(),
            dangerous: profile.dangerous,
            active_secret_count: secrets.len(),
        });
    }
    Ok(SealedBundlePayloadV1 {
        profile_count: profile_summaries.len(),
        active_secret_count,
        audit_rows_included: include_audit,
        profiles: profile_summaries,
    })
}

fn bundle_payload_digest(payload: &SealedBundlePayloadV1) -> Result<String, CliError> {
    let bytes = serde_json::to_vec(payload)?;
    let mut hasher = Sha256::new();
    hasher.update(b"locket-bundle-payload-v1");
    hasher.update(bytes);
    Ok(format_hex(&hasher.finalize()))
}

fn default_bundle_output_path(context: &RuntimeContext, timestamp: i64) -> PathBuf {
    context.cwd.join(format!("locket-bundle-{timestamp}.locket-bundle"))
}

fn write_bundle_file(path: &Path, bundle: &SealedBundleFileV1) -> Result<(), CliError> {
    let text = serde_json::to_string_pretty(bundle)?;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    set_user_only_file_options(&mut options);
    let mut file = options.open(path).map_err(|error| {
        if error.kind() == io::ErrorKind::AlreadyExists {
            CliError::Config("bundle output already exists".to_owned())
        } else {
            CliError::Io(error)
        }
    })?;
    file.write_all(text.as_bytes())?;
    file.write_all(b"\n")?;
    set_user_only_file_permissions(path)?;
    Ok(())
}

fn verify_bundle_file(path: &Path) -> Result<SealedBundleFileV1, CliError> {
    let bytes = fs::read(path)?;
    let bundle: SealedBundleFileV1 = serde_json::from_slice(&bytes).map_err(|error| {
        bundle_verification_error(format!("bundle verification failed: {error}"))
    })?;
    if bundle.magic != BUNDLE_MAGIC_V1 {
        return Err(bundle_verification_error("bundle verification failed: bad magic"));
    }
    if bundle.schema_version != 1 {
        return Err(bundle_verification_error(
            "bundle verification failed: unsupported schema version",
        ));
    }
    if bundle.kind != "sealed-bundle" {
        return Err(bundle_verification_error("bundle verification failed: bad kind"));
    }
    let digest = bundle_payload_digest(&bundle.payload)?;
    if digest != bundle.manifest_digest_sha256 {
        return Err(bundle_verification_error(
            "bundle verification failed: manifest digest mismatch",
        ));
    }
    Ok(bundle)
}

fn output_path_kind(path: &Path, context: &RuntimeContext) -> &'static str {
    if path.parent().is_some_and(|parent| parent == context.cwd) {
        "current_directory"
    } else if path.is_absolute() {
        "absolute"
    } else {
        "relative"
    }
}

struct BundleAuditRequest<'a> {
    resolved: &'a ResolvedProject,
    action: &'static str,
    command: &'static str,
    bundle: &'a SealedBundleFileV1,
    path_kind: &'static str,
    timestamp: i64,
}

fn write_bundle_audit_if_available(
    context: &RuntimeContext,
    store: &mut Store,
    request: &BundleAuditRequest<'_>,
) -> Result<(), CliError> {
    let Ok(audit_key) = load_project_key(
        context,
        store,
        request.resolved.config.project_id.as_str(),
        KeyPurpose::Audit,
    ) else {
        return Ok(());
    };
    let metadata = json!({
        "schema_version": 1,
        "action": request.action,
        "status": "SUCCESS",
        "command": request.command,
        "project_id": request.resolved.config.project_id.as_str(),
        "profile_count": request.bundle.payload.profile_count,
        "active_secret_count": request.bundle.payload.active_secret_count,
        "recipient_fingerprints": &request.bundle.recipient_fingerprints,
        "bundle_digest": &request.bundle.manifest_digest_sha256,
        "path_kind": request.path_kind,
        "include_audit": request.bundle.include_audit,
        "metadata_only": true,
    });
    let audit = AuditWrite {
        project_id: request.resolved.config.project_id.as_str(),
        profile_id: None,
        action: request.action,
        status: "SUCCESS",
        secret_name: None,
        command: Some(request.command),
        metadata_json: &metadata,
        timestamp: request.timestamp,
    };
    store.append_audit(audit_key.as_ref(), &audit)?;
    Ok(())
}
