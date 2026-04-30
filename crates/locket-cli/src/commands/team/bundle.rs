//! Bundle export, import, and verify command implementations.

use std::collections::BTreeSet;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use data_encoding::BASE64URL_NOPAD;
use locket_core::{
    BUNDLE_SCHEMA_V1, BundleContainer, BundleContainerError, BundleManifest, CommandPolicy,
    CommandSpec, encrypt_bundle_payload_for_age_recipients, verify_age_payload_structure,
};
use locket_crypto::KeyPurpose;
use locket_store::{AuditWrite, ProfileRecord, SecretBlobRecord, SecretRecord, Store};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use super::device;
use crate::runtime::key_access::load_profile_key;
use crate::runtime::user_verification::{UserVerificationAudit, configured_user_verification};
use crate::{
    BundleCommand, BundleVerifyArgs, CliError, ExportArgs, ImportBundleArgs, LOCKET_TOML,
    ResolvedProject, RuntimeContext, bundle_verification_error, command_type,
    confirmation_failed_error, default_profile, ensure_project_exists, ensure_trusted_project_root,
    external_env_source_label, format_hex, invalid_reference_error, load_project_key,
    metadata_invalid_error, now_unix_nanos, open_store, profile_not_found_error,
    read_policy_document, require_project, resolve_project, set_user_only_file_options,
    set_user_only_file_permissions,
};

#[derive(Debug, Deserialize, Serialize)]
struct SealedBundlePayloadV1 {
    profiles: Vec<SealedBundleProfileV1>,
    command_policies: Vec<SealedBundleCommandPolicyV1>,
    secrets: Vec<SealedBundleSecretV1>,
    secret_versions: Vec<SealedBundleSecretVersionV1>,
    blobs: Vec<SealedBundleBlobV1>,
    profile_keys: Vec<SealedBundleProfileKeyV1>,
    profile_count: usize,
    command_policy_count: usize,
    secret_count: usize,
    secret_version_count: usize,
    blob_count: usize,
    profile_key_count: usize,
    active_secret_count: usize,
    audit_rows_included: bool,
}

#[derive(Debug, Deserialize, Serialize)]
struct SealedBundleProfileV1 {
    profile_id: String,
    name: String,
    dangerous: bool,
    active_secret_count: usize,
    created_at: i64,
}

#[derive(Debug, Deserialize, Serialize)]
#[allow(clippy::struct_excessive_bools)]
struct SealedBundleCommandPolicyV1 {
    name: String,
    command_kind: String,
    argv: Vec<String>,
    shell: Option<String>,
    allowed_secrets: Vec<String>,
    required_secrets: Vec<String>,
    optional_secrets: Vec<String>,
    inherit_env: Vec<String>,
    env_mode: String,
    override_mode: String,
    override_explicit: bool,
    external_env_sources: Vec<String>,
    allow_remote_docker: bool,
    confirm: bool,
    require_user_verification: bool,
    ttl_seconds: u64,
}

#[derive(Debug, Deserialize, Serialize)]
struct SealedBundleSecretV1 {
    id: String,
    profile_id: String,
    name: String,
    source: String,
    origin: String,
    current_version: u32,
    state: String,
    created_at: i64,
    updated_at: i64,
    last_rotated_at: Option<i64>,
    deleted_at: Option<i64>,
}

#[derive(Debug, Deserialize, Serialize)]
struct SealedBundleSecretVersionV1 {
    secret_id: String,
    version: u32,
    source: String,
    origin: String,
    state: String,
    created_at: i64,
    deprecated_at: Option<i64>,
    grace_until: Option<i64>,
    purged_at: Option<i64>,
}

#[derive(Debug, Deserialize, Serialize)]
struct SealedBundleBlobV1 {
    secret_id: String,
    version: u32,
    encrypted_dek_b64: String,
    ciphertext_b64: String,
    value_nonce_b64: String,
    aad_schema_version: u16,
    created_at: i64,
}

#[derive(Debug, Deserialize, Serialize)]
struct SealedBundleProfileKeyV1 {
    profile_id: String,
    purpose: String,
    key_material_b64: String,
}

struct BundleRecipientV1 {
    fingerprint: String,
    sealing_public_key: [u8; 32],
}

struct ExportedBundleV1 {
    manifest: BundleManifest,
    active_secret_count: usize,
    command_policy_count: usize,
    secret_count: usize,
    secret_version_count: usize,
    blob_count: usize,
    profile_key_count: usize,
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
    let user_verification = confirm_dangerous_profile_export(context, output, &selected_profiles)?;
    let timestamp = now_unix_nanos()?;
    let payload =
        bundle_payload(context, &store, &resolved, &selected_profiles, args.include_audit)?;
    let plaintext_payload = zeroize::Zeroizing::new(serde_json::to_vec(&payload)?);
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
        .map_err(|error| bundle_container_cli_error(&error))?;
    let output_path =
        args.output.clone().unwrap_or_else(|| default_bundle_output_path(context, timestamp));
    write_bundle_file(&output_path, &container)?;
    let bundle = ExportedBundleV1 {
        manifest,
        active_secret_count: payload.active_secret_count,
        command_policy_count: payload.command_policy_count,
        secret_count: payload.secret_count,
        secret_version_count: payload.secret_version_count,
        blob_count: payload.blob_count,
        profile_key_count: payload.profile_key_count,
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
            user_verification,
        },
    )?;

    writeln!(output, "bundle: exported")?;
    writeln!(output, "path: {}", output_path.display())?;
    writeln!(output, "profiles: {}", bundle.manifest.profile_count)?;
    writeln!(output, "command_policy_count: {}", bundle.command_policy_count)?;
    writeln!(output, "secret_count: {}", bundle.secret_count)?;
    writeln!(output, "secret_version_count: {}", bundle.secret_version_count)?;
    writeln!(output, "blob_count: {}", bundle.blob_count)?;
    writeln!(output, "profile_key_count: {}", bundle.profile_key_count)?;
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
            user_verification: UserVerificationAudit::not_required(),
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
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &BundleVerifyArgs,
) -> Result<(), CliError> {
    let bundle = verify_bundle_file(&args.bundle)?;
    write_bundle_verify_audit_if_available(context, &bundle)?;
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
) -> Result<UserVerificationAudit, CliError> {
    let dangerous: Vec<&str> =
        profiles.iter().filter(|p| p.dangerous).map(|p| p.name.as_str()).collect();
    if dangerous.is_empty() {
        return Ok(UserVerificationAudit::not_required());
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
    configured_user_verification(
        context,
        "user_verification_required_for.dangerous_profile_switch",
        "export dangerous profile",
        format!("export dangerous profiles {names}"),
    )
}

fn bundle_payload(
    context: &RuntimeContext,
    store: &Store,
    resolved: &ResolvedProject,
    profiles: &[ProfileRecord],
    include_audit: bool,
) -> Result<SealedBundlePayloadV1, CliError> {
    let command_policies = bundle_command_policies(resolved)?;
    let mut profile_payloads = Vec::with_capacity(profiles.len());
    let mut secrets = Vec::new();
    let mut secret_versions = Vec::new();
    let mut blobs = Vec::new();
    let mut profile_keys = Vec::with_capacity(profiles.len().saturating_mul(2));
    let mut active_secret_count = 0_usize;
    for profile in profiles {
        let active_secrets =
            store.list_active_secrets_by_profile(&profile.project_id, &profile.id)?;
        active_secret_count = active_secret_count.saturating_add(active_secrets.len());
        profile_payloads.push(SealedBundleProfileV1 {
            profile_id: profile.id.clone(),
            name: profile.name.clone(),
            dangerous: profile.dangerous,
            active_secret_count: active_secrets.len(),
            created_at: profile.created_at,
        });
        profile_keys.extend(bundle_profile_keys(context, store, &profile.project_id, &profile.id)?);
        for secret in store.list_secrets_by_profile(&profile.project_id, &profile.id)? {
            let versions = store.list_secret_versions(&secret.id)?;
            for version in versions {
                if let Some(blob) = store.get_blob(&secret.id, version.version)? {
                    blobs.push(bundle_blob(blob));
                }
                secret_versions.push(SealedBundleSecretVersionV1 {
                    secret_id: version.secret_id,
                    version: version.version,
                    source: version.source,
                    origin: version.origin,
                    state: version.state,
                    created_at: version.created_at,
                    deprecated_at: version.deprecated_at,
                    grace_until: version.grace_until,
                    purged_at: version.purged_at,
                });
            }
            secrets.push(bundle_secret(secret));
        }
    }
    Ok(SealedBundlePayloadV1 {
        profile_count: profile_payloads.len(),
        command_policy_count: command_policies.len(),
        secret_count: secrets.len(),
        secret_version_count: secret_versions.len(),
        blob_count: blobs.len(),
        profile_key_count: profile_keys.len(),
        active_secret_count,
        audit_rows_included: include_audit,
        profiles: profile_payloads,
        command_policies,
        secrets,
        secret_versions,
        blobs,
        profile_keys,
    })
}

fn bundle_command_policies(
    resolved: &ResolvedProject,
) -> Result<Vec<SealedBundleCommandPolicyV1>, CliError> {
    let policy_document = read_policy_document(&resolved.root.join(LOCKET_TOML))?;
    Ok(policy_document.commands.values().map(bundle_command_policy).collect())
}

fn bundle_command_policy(policy: &CommandPolicy) -> SealedBundleCommandPolicyV1 {
    let (argv, shell) = match &policy.command {
        CommandSpec::Argv(arguments) => (arguments.clone(), None),
        CommandSpec::Shell(script) => (Vec::new(), Some(script.clone())),
    };
    SealedBundleCommandPolicyV1 {
        name: policy.name.clone(),
        command_kind: command_type(&policy.command).to_owned(),
        argv,
        shell,
        allowed_secrets: policy
            .allowed_secrets
            .iter()
            .map(|name| name.as_str().to_owned())
            .collect(),
        required_secrets: policy
            .required_secrets
            .iter()
            .map(|name| name.as_str().to_owned())
            .collect(),
        optional_secrets: policy
            .optional_secrets
            .iter()
            .map(|name| name.as_str().to_owned())
            .collect(),
        inherit_env: policy.inherit_env.clone(),
        env_mode: policy.env_mode.as_str().to_owned(),
        override_mode: policy.override_behavior.as_str().to_owned(),
        override_explicit: policy.override_explicit(),
        external_env_sources: policy
            .external_env_sources
            .iter()
            .map(external_env_source_label)
            .collect(),
        allow_remote_docker: policy.allow_remote_docker,
        confirm: policy.confirm,
        require_user_verification: policy.require_user_verification,
        ttl_seconds: policy.ttl.as_secs(),
    }
}

fn bundle_profile_keys(
    context: &RuntimeContext,
    store: &Store,
    project_id: &str,
    profile_id: &str,
) -> Result<Vec<SealedBundleProfileKeyV1>, CliError> {
    [KeyPurpose::ProfileSecret, KeyPurpose::ProfileFingerprint]
        .into_iter()
        .map(|purpose| {
            let key = load_profile_key(context, store, project_id, profile_id, purpose)?;
            Ok(SealedBundleProfileKeyV1 {
                profile_id: profile_id.to_owned(),
                purpose: purpose.as_str().to_owned(),
                key_material_b64: BASE64URL_NOPAD.encode(key.as_ref()),
            })
        })
        .collect()
}

fn bundle_secret(secret: SecretRecord) -> SealedBundleSecretV1 {
    SealedBundleSecretV1 {
        id: secret.id,
        profile_id: secret.profile_id,
        name: secret.name,
        source: secret.source,
        origin: secret.origin,
        current_version: secret.current_version,
        state: secret.state,
        created_at: secret.created_at,
        updated_at: secret.updated_at,
        last_rotated_at: secret.last_rotated_at,
        deleted_at: secret.deleted_at,
    }
}

fn bundle_blob(blob: SecretBlobRecord) -> SealedBundleBlobV1 {
    SealedBundleBlobV1 {
        secret_id: blob.secret_id,
        version: blob.version,
        encrypted_dek_b64: BASE64URL_NOPAD.encode(&blob.encrypted_dek),
        ciphertext_b64: BASE64URL_NOPAD.encode(&blob.ciphertext),
        value_nonce_b64: BASE64URL_NOPAD.encode(&blob.value_nonce),
        aad_schema_version: blob.aad_schema_version,
        created_at: blob.created_at,
    }
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
    let bytes = bundle.serialize().map_err(|error| bundle_container_cli_error(&error))?;
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
    let container =
        BundleContainer::deserialize(&bytes).map_err(|error| bundle_container_cli_error(&error))?;
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

fn bundle_container_cli_error(error: &BundleContainerError) -> CliError {
    match error {
        BundleContainerError::UnsupportedSchema(version) => metadata_invalid_error(format!(
            "unsupported bundle schema version {version}; upgrade locket to verify this bundle"
        )),
        _ => bundle_verification_error(format!("bundle verification failed: {error}")),
    }
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
    user_verification: UserVerificationAudit,
}

trait BundleAuditSubject {
    fn manifest(&self) -> &BundleManifest;

    fn active_secret_count(&self) -> Option<usize> {
        None
    }

    fn command_policy_count(&self) -> Option<usize> {
        None
    }

    fn secret_count(&self) -> Option<usize> {
        None
    }

    fn secret_version_count(&self) -> Option<usize> {
        None
    }

    fn blob_count(&self) -> Option<usize> {
        None
    }

    fn profile_key_count(&self) -> Option<usize> {
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

    fn command_policy_count(&self) -> Option<usize> {
        Some(self.command_policy_count)
    }

    fn secret_count(&self) -> Option<usize> {
        Some(self.secret_count)
    }

    fn secret_version_count(&self) -> Option<usize> {
        Some(self.secret_version_count)
    }

    fn blob_count(&self) -> Option<usize> {
        Some(self.blob_count)
    }

    fn profile_key_count(&self) -> Option<usize> {
        Some(self.profile_key_count)
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

fn write_bundle_verify_audit_if_available(
    context: &RuntimeContext,
    bundle: &VerifiedBundleV1,
) -> Result<(), CliError> {
    let Some(resolved) = resolve_project(&context.cwd)? else {
        return Ok(());
    };
    let mut store = open_store(context)?;
    let project_id = resolved.config.project_id.as_str();
    if store.get_project(project_id)?.is_none() {
        return Ok(());
    }
    let Ok(audit_key) = load_project_key(context, &store, project_id, KeyPurpose::Audit) else {
        return Ok(());
    };
    let timestamp = now_unix_nanos()?;
    let metadata = serde_json::json!({
        "schema_version": 1,
        "action": "BUNDLE_VERIFY",
        "status": "SUCCESS",
        "command": "bundle verify",
        "project_id": project_id,
        "bundle_schema_version": bundle.manifest.schema_version,
        "bundle_digest": bundle.manifest.payload_digest,
        "profile_count": bundle.manifest.profile_count,
        "recipient_count": bundle.manifest.recipient_fingerprints.len(),
        "decryptable_by_this_device": false,
        "metadata_only": true,
    });
    let audit = AuditWrite {
        project_id,
        profile_id: None,
        action: "BUNDLE_VERIFY",
        status: "SUCCESS",
        secret_name: None,
        command: Some("bundle verify"),
        metadata_json: &metadata,
        timestamp,
    };
    store.append_audit(audit_key.as_ref(), &audit)?;
    Ok(())
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
    if let Some(command_policy_count) = request.bundle.command_policy_count() {
        metadata.insert("command_policy_count".to_owned(), Value::from(command_policy_count));
    }
    if let Some(secret_count) = request.bundle.secret_count() {
        metadata.insert("secret_count".to_owned(), Value::from(secret_count));
    }
    if let Some(secret_version_count) = request.bundle.secret_version_count() {
        metadata.insert("secret_version_count".to_owned(), Value::from(secret_version_count));
    }
    if let Some(blob_count) = request.bundle.blob_count() {
        metadata.insert("blob_count".to_owned(), Value::from(blob_count));
    }
    if let Some(profile_key_count) = request.bundle.profile_key_count() {
        metadata.insert("profile_key_count".to_owned(), Value::from(profile_key_count));
    }
    if let Some(include_audit) = request.bundle.include_audit() {
        metadata.insert("include_audit".to_owned(), Value::from(include_audit));
    }
    if let Some(include_audit_requested) = request.include_audit_requested {
        metadata.insert("include_audit_requested".to_owned(), Value::from(include_audit_requested));
    }
    metadata.insert(
        "user_verification".to_owned(),
        serde_json::to_value(&request.user_verification)?,
    );
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
