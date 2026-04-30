//! Bundle export, import, and verify command implementations.

use std::collections::BTreeSet;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use locket_core::{
    BUNDLE_SCHEMA_V1, BundleContainer, BundleContainerError, BundleManifest,
    encrypt_bundle_payload_for_age_recipients, verify_age_payload_structure,
};
use locket_crypto::KeyPurpose;
use locket_store::{AuditWrite, ProfileRecord, Store};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use super::device;
use crate::{
    BundleCommand, BundleVerifyArgs, CliError, ExportArgs, ImportBundleArgs, ResolvedProject,
    RuntimeContext, bundle_verification_error, confirmation_failed_error, default_profile,
    ensure_project_exists, ensure_trusted_project_root, format_hex, invalid_reference_error,
    load_project_key, metadata_invalid_error, now_unix_nanos, open_store, profile_not_found_error,
    require_project, set_user_only_file_options, set_user_only_file_permissions,
};

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

struct BundleRecipientV1 {
    fingerprint: String,
    sealing_public_key: [u8; 32],
}

struct ExportedBundleV1 {
    manifest: BundleManifest,
    active_secret_count: usize,
    include_audit: bool,
}

struct VerifiedBundleV1 {
    manifest: BundleManifest,
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
        return Err(invalid_reference_error("bundle export requires --sealed"));
    }
    if args.recipients.is_empty() {
        return Err(invalid_reference_error("bundle export requires at least one --recipient"));
    }

    let resolved = require_project(context)?;
    let mut store = open_store(context)?;
    ensure_project_exists(&store, resolved.config.project_id.as_str())?;
    ensure_trusted_project_root(&store, &resolved)?;
    let recipients = bundle_recipients(&args.recipients)?;
    let recipient_fingerprints =
        recipients.iter().map(|recipient| recipient.fingerprint.clone()).collect::<Vec<_>>();
    let selected_profiles = selected_bundle_profiles(&store, &resolved, args)?;
    confirm_dangerous_profile_export(context, output, &selected_profiles)?;
    let timestamp = now_unix_nanos()?;
    let payload = bundle_payload(&store, &selected_profiles, args.include_audit)?;
    let plaintext_payload = serde_json::to_vec(&payload)?;
    let recipient_keys =
        recipients.iter().map(|recipient| recipient.sealing_public_key).collect::<Vec<_>>();
    let encrypted_payload =
        encrypt_bundle_payload_for_age_recipients(&plaintext_payload, &recipient_keys)
            .map_err(|error| metadata_invalid_error(error.to_string()))?;
    let manifest_digest_sha256 = bundle_encrypted_payload_digest(&encrypted_payload);
    let manifest = BundleManifest {
        recipient_fingerprints,
        project_id: resolved.config.project_id.to_string(),
        schema_version: BUNDLE_SCHEMA_V1,
        created_at: timestamp,
        profile_count: u32::try_from(payload.profile_count)
            .map_err(|_| metadata_invalid_error("bundle profile count exceeds schema limit"))?,
        payload_digest: manifest_digest_sha256,
    };
    let container = BundleContainer::new(manifest.clone(), encrypted_payload)
        .map_err(bundle_container_cli_error)?;
    let output_path =
        args.output.clone().unwrap_or_else(|| default_bundle_output_path(context, timestamp));
    write_bundle_file(&output_path, &container)?;
    let bundle = ExportedBundleV1 {
        manifest,
        active_secret_count: payload.active_secret_count,
        include_audit: args.include_audit,
    };
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
            include_audit_requested: None,
        },
    )?;

    writeln!(output, "bundle: exported")?;
    writeln!(output, "path: {}", output_path.display())?;
    writeln!(output, "profiles: {}", bundle.manifest.profile_count)?;
    writeln!(output, "active_secret_count: {}", bundle.active_secret_count)?;
    writeln!(output, "recipients: {}", bundle.manifest.recipient_fingerprints.len())?;
    writeln!(output, "include_audit: {}", if bundle.include_audit { "yes" } else { "no" })?;
    writeln!(output, "payload_status: age-encrypted")?;
    writeln!(output, "digest: {}", bundle.manifest.payload_digest)?;
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
    if bundle.manifest.project_id != resolved.config.project_id.as_str() {
        return Err(bundle_verification_error("bundle project id does not match current project"));
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
            include_audit_requested: Some(args.include_audit),
        },
    )?;

    writeln!(output, "bundle: verified")?;
    writeln!(output, "import: not_applied")?;
    writeln!(output, "reason: local device private-key import is not implemented in this build")?;
    writeln!(output, "profiles: {}", bundle.manifest.profile_count)?;
    writeln!(output, "active_secret_count: encrypted")?;
    writeln!(output, "include_audit_requested: {}", if args.include_audit { "yes" } else { "no" })?;
    writeln!(output, "bundle_include_audit: encrypted")?;
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
    writeln!(output, "schema_version: {}", bundle.manifest.schema_version)?;
    writeln!(output, "project_id: {}", bundle.manifest.project_id)?;
    writeln!(output, "profiles: {}", bundle.manifest.profile_count)?;
    writeln!(output, "active_secret_count: encrypted")?;
    writeln!(output, "recipients: {}", bundle.manifest.recipient_fingerprints.len())?;
    writeln!(output, "digest: {}", bundle.manifest.payload_digest)?;
    writeln!(output, "decryptable_by_this_device: no")?;
    writeln!(output, "metadata_only: yes")?;
    Ok(())
}

fn bundle_recipients(recipients: &[String]) -> Result<Vec<BundleRecipientV1>, CliError> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::with_capacity(recipients.len());
    for recipient in recipients {
        let descriptor = device::decode_device_descriptor(recipient)?;
        let signing_public_key =
            device::decode_descriptor_key(&descriptor.signing_public_key_ed25519)?;
        let sealing_public_key =
            device::decode_descriptor_key(&descriptor.sealing_public_key_x25519)?;
        let fingerprint = device::device_fingerprint_hex(&signing_public_key, &sealing_public_key);
        if fingerprint != descriptor.fingerprint_sha256 {
            return Err(metadata_invalid_error("recipient device descriptor fingerprint mismatch"));
        }
        if seen.insert(fingerprint.clone()) {
            out.push(BundleRecipientV1 { fingerprint, sealing_public_key });
        }
    }
    Ok(out)
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
            .ok_or_else(|| profile_not_found_error(format!("profile not found: {profile_name}")));
    }
    Ok(vec![default_profile(store, &resolved.config)?])
}

fn confirm_dangerous_profile_export(
    context: &RuntimeContext,
    output: &mut impl Write,
    profiles: &[ProfileRecord],
) -> Result<(), CliError> {
    let dangerous: Vec<&str> =
        profiles.iter().filter(|p| p.dangerous).map(|p| p.name.as_str()).collect();
    if dangerous.is_empty() {
        return Ok(());
    }
    let names = dangerous.join(",");
    writeln!(output, "dangerous_profiles: {names}")?;
    writeln!(output, "metadata_only: yes")?;
    writeln!(output, "type 'export --sealed {names}' to confirm dangerous bundle export")?;
    let confirmation = context.confirmation_reader.read_confirmation("export --sealed")?;
    let expected = format!("export --sealed {names}");
    if confirmation.trim_end_matches(['\r', '\n']) != expected {
        return Err(confirmation_failed_error(
            "confirmation did not match dangerous bundle export scope",
        ));
    }
    Ok(())
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

fn bundle_encrypted_payload_digest(encrypted_payload: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(encrypted_payload);
    format_hex(&hasher.finalize())
}

fn default_bundle_output_path(context: &RuntimeContext, timestamp: i64) -> PathBuf {
    context.cwd.join(format!("locket-bundle-{timestamp}.locket-bundle"))
}

fn write_bundle_file(path: &Path, bundle: &BundleContainer) -> Result<(), CliError> {
    let bytes = bundle.serialize().map_err(bundle_container_cli_error)?;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    set_user_only_file_options(&mut options);
    let mut file = options.open(path).map_err(|error| {
        if error.kind() == io::ErrorKind::AlreadyExists {
            invalid_reference_error("bundle output already exists")
        } else {
            CliError::Io(error)
        }
    })?;
    file.write_all(&bytes)?;
    set_user_only_file_permissions(path)?;
    Ok(())
}

fn verify_bundle_file(path: &Path) -> Result<VerifiedBundleV1, CliError> {
    let bytes = fs::read(path)?;
    let container = BundleContainer::deserialize(&bytes).map_err(bundle_container_cli_error)?;
    let digest = bundle_encrypted_payload_digest(&container.encrypted_payload);
    if digest != container.manifest.payload_digest {
        return Err(bundle_verification_error(
            "bundle verification failed: manifest digest mismatch",
        ));
    }
    verify_age_payload_structure(&container.encrypted_payload)
        .map_err(|error| bundle_verification_error(error.to_string()))?;
    Ok(VerifiedBundleV1 { manifest: container.manifest })
}

fn bundle_container_cli_error(error: BundleContainerError) -> CliError {
    bundle_verification_error(format!("bundle verification failed: {error}"))
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
    bundle: &'a dyn BundleAuditSubject,
    path_kind: &'static str,
    timestamp: i64,
    include_audit_requested: Option<bool>,
}

trait BundleAuditSubject {
    fn manifest(&self) -> &BundleManifest;

    fn active_secret_count(&self) -> Option<usize> {
        None
    }

    fn include_audit(&self) -> Option<bool> {
        None
    }
}

impl BundleAuditSubject for ExportedBundleV1 {
    fn manifest(&self) -> &BundleManifest {
        &self.manifest
    }

    fn active_secret_count(&self) -> Option<usize> {
        Some(self.active_secret_count)
    }

    fn include_audit(&self) -> Option<bool> {
        Some(self.include_audit)
    }
}

impl BundleAuditSubject for VerifiedBundleV1 {
    fn manifest(&self) -> &BundleManifest {
        &self.manifest
    }
}

fn write_bundle_audit_if_available(
    context: &RuntimeContext,
    store: &mut Store,
    request: &BundleAuditRequest<'_>,
) -> Result<(), CliError> {
    let audit_key = load_project_key(
        context,
        store,
        request.resolved.config.project_id.as_str(),
        KeyPurpose::Audit,
    )?;
    let manifest = request.bundle.manifest();
    let mut metadata = Map::new();
    metadata.insert("schema_version".to_owned(), Value::from(1));
    metadata.insert("action".to_owned(), Value::from(request.action));
    metadata.insert("status".to_owned(), Value::from("SUCCESS"));
    metadata.insert("command".to_owned(), Value::from(request.command));
    metadata
        .insert("project_id".to_owned(), Value::from(request.resolved.config.project_id.as_str()));
    metadata.insert("profile_count".to_owned(), Value::from(manifest.profile_count));
    metadata.insert(
        "recipient_fingerprints".to_owned(),
        Value::Array(manifest.recipient_fingerprints.iter().cloned().map(Value::from).collect()),
    );
    metadata.insert("bundle_digest".to_owned(), Value::from(manifest.payload_digest.as_str()));
    metadata.insert("path_kind".to_owned(), Value::from(request.path_kind));
    metadata.insert("metadata_only".to_owned(), Value::from(true));
    if let Some(active_secret_count) = request.bundle.active_secret_count() {
        metadata.insert("active_secret_count".to_owned(), Value::from(active_secret_count));
    }
    if let Some(include_audit) = request.bundle.include_audit() {
        metadata.insert("include_audit".to_owned(), Value::from(include_audit));
    }
    if let Some(include_audit_requested) = request.include_audit_requested {
        metadata.insert("include_audit_requested".to_owned(), Value::from(include_audit_requested));
    }
    let metadata = Value::Object(metadata);
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
