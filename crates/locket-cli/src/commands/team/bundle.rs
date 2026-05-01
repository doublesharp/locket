//! Bundle export, import, and verify command implementations.

use std::collections::BTreeSet;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use chacha20poly1305::{
    Key, XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use data_encoding::BASE64URL_NOPAD;
use locket_core::{
    AUDIT_HMAC_LEN, BUNDLE_SCHEMA_V1, BundleContainer, BundleContainerError, BundleManifest,
    CommandPolicy, CommandSpec, KeyId, decrypt_bundle_payload_with_x25519_secret,
    encrypt_bundle_payload_for_age_recipients, verify_age_payload_structure,
};
use locket_crypto::{AAD_SCHEMA_V1, KeyPurpose};
use locket_platform::{
    LocalDevicePrivateKeyStorage, PlatformError, WrappedLocalFileDevicePrivateKeyStorage,
};
use locket_store::{
    AuditWrite, ExportableAuditRow, KeyRecord, ProfileRecord, SecretBlobRecord, SecretRecord,
    Store,
};
use rusqlite::params;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use super::device;
use crate::runtime::key_access::{load_master_key, load_profile_key, rewrap_imported_profile_key};
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
    /// Encrypted audit-chain payload, present only when the export was
    /// requested with `--include-audit`. Populated 1:1 with the columns
    /// of the receiver's `imported_audit_chains` row so import is a
    /// straight column copy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    audit_chain: Option<SealedAuditChainPayloadV1>,
}

/// Audit-chain payload carried inside [`SealedBundlePayloadV1`] when
/// the exporter set `--include-audit`.
///
/// Fields map to the `imported_audit_chains` `SQLite` columns 1:1 with
/// one exception: `bundle_digest` is intentionally not duplicated
/// inside the payload because the digest is taken over the encrypted
/// payload that itself contains this struct (chicken-and-egg). The
/// receiver sources `imported_audit_chains.bundle_digest` from the
/// plaintext bundle manifest (`BundleManifest::payload_digest`) at
/// insertion time, which carries the same value verifiable against the
/// container bytes. The remaining columns (`aad_schema_version`,
/// `checkpoint_sequence`, `checkpoint_hmac`, `encrypted_rows`, `nonce`)
/// have direct field counterparts here.
///
/// Encryption scheme (v1):
///
/// - Cipher: XChaCha20-Poly1305, matching the table's
///   `nonce BLOB CHECK (length(nonce) = 24)` constraint.
/// - Key: a fresh 32-byte random key generated per export and stored in
///   `encryption_key_b64`. The key never leaves the age-encrypted
///   bundle payload — only age recipients can decrypt the bundle and
///   reach the key. Receivers can decrypt the rows for their own
///   verification before insertion; the stored at-rest ciphertext in
///   `imported_audit_chains.encrypted_rows` is opaque to anyone without
///   a copy of that key.
/// - Nonce: 24 random bytes per export.
/// - AAD: a domain-separated byte string built by
///   [`audit_chain_aad_v1`] covering bundle digest, schema version,
///   checkpoint sequence, checkpoint HMAC, and `aad_schema_version`. The
///   ciphertext is bound to those exact fields so an attacker cannot
///   move the rows blob between bundles or splice a different
///   checkpoint.
/// - Plaintext: a canonical-JSON list of audit rows
///   (`SealedAuditChainRowV1` below) — minimal serializer; this matches
///   the "per-row chacha20poly1305 with documented AAD" guidance in the
///   subtask brief.
#[derive(Debug, Deserialize, Serialize)]
struct SealedAuditChainPayloadV1 {
    /// AAD schema version covering the audit-chain encryption.
    aad_schema_version: u16,
    /// Sequence number of the final row in `encrypted_rows`.
    checkpoint_sequence: u64,
    /// HMAC of the final row in `encrypted_rows`, base64url unpadded.
    checkpoint_hmac_b64: String,
    /// XChaCha20-Poly1305 ciphertext of the canonical-JSON audit-row
    /// list, base64url unpadded.
    encrypted_rows_b64: String,
    /// 24-byte XChaCha20-Poly1305 nonce, base64url unpadded.
    nonce_b64: String,
    /// 32-byte symmetric key used to encrypt `encrypted_rows`,
    /// base64url unpadded. Carried inside the age-encrypted bundle so
    /// age recipients can decrypt and structurally verify the rows;
    /// non-recipients never see it because they cannot decrypt the
    /// outer age payload.
    encryption_key_b64: String,
    /// Plaintext row count for cross-checking against the decrypted
    /// row list. Counts only; never names.
    row_count: usize,
}

#[derive(Debug, Deserialize, Serialize)]
struct SealedAuditChainRowV1 {
    sequence: u64,
    schema_version: u16,
    timestamp: i64,
    profile_id: Option<String>,
    action: String,
    status: String,
    metadata_json: String,
    secret_name: Option<String>,
    command: Option<String>,
    previous_hmac_b64: String,
    hmac_b64: String,
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
    encrypted_payload: Vec<u8>,
}

#[derive(Debug, Default)]
#[allow(clippy::struct_field_names)]
struct ImportedBundleCounts {
    profile_count: usize,
    secret_count: usize,
    blob_count: usize,
    command_policy_count: usize,
}

/// Per-row-family count of rows newly written by the apply phase.
#[derive(Debug, Default, Clone, Copy)]
#[allow(clippy::struct_field_names)]
struct AppliedBundleCounts {
    profile_count: usize,
    secret_count: usize,
    secret_version_count: usize,
    blob_count: usize,
    command_policy_count: usize,
    profile_key_count: usize,
}

/// Aggregated conflict-matrix counters across all bundle row families.
#[derive(Debug, Default, Clone, Copy)]
struct BundleConflictCounts {
    identical: usize,
    newer_incoming: usize,
    divergent: usize,
    deleted_vs_active: usize,
    applied: usize,
    rejected: usize,
}

/// Conflict resolution flags carried from `ImportBundleArgs`.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum ConflictResolution {
    AcceptIncoming,
    AcceptLocal,
    InteractiveRequired,
}

impl ConflictResolution {
    const fn from_args(args: &ImportBundleArgs) -> Self {
        if args.accept_incoming {
            Self::AcceptIncoming
        } else if args.accept_local {
            Self::AcceptLocal
        } else {
            Self::InteractiveRequired
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::AcceptIncoming => "accept-incoming",
            Self::AcceptLocal => "accept-local",
            Self::InteractiveRequired => "interactive-required",
        }
    }
}

/// Outcome of `apply_bundle_payload`.
#[derive(Debug)]
enum ApplyOutcome {
    Applied { applied: AppliedBundleCounts, conflicts: BundleConflictCounts },
    InteractiveRequired { divergent: Vec<String> },
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum DivergentDecision {
    Apply,
    Skip,
    Defer,
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
            decrypted_counts: None,
            applied_counts: None,
            conflict_counts: None,
            applied: None,
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

#[allow(clippy::too_many_lines)]
pub fn import_bundle_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &ImportBundleArgs,
) -> Result<(), CliError> {
    let resolved = require_project(context)?;
    let mut store = open_store(context)?;
    let project_id = resolved.config.project_id.as_str();
    ensure_project_exists(&store, project_id)?;
    ensure_trusted_project_root(&store, &resolved)?;
    let bundle = verify_bundle_file(&args.bundle)?;
    if bundle.manifest.project_id != project_id {
        return Err(bundle_verification_error("bundle project id does not match current project"));
    }
    let resolution = ConflictResolution::from_args(args);

    let device = store
        .get_active_local_device(project_id)?
        .ok_or_else(|| bundle_verification_error("local device is not initialized"))?;
    let storage = build_import_device_private_key_storage(context, project_id)?;
    let private_key = storage.load(&device.id).map_err(map_private_key_load_error)?;
    let plaintext =
        decrypt_bundle_payload_with_x25519_secret(&bundle.encrypted_payload, &private_key)
            .map_err(|error| {
                bundle_verification_error(format!("bundle verification failed: {error}"))
            })?;
    let payload: SealedBundlePayloadV1 = serde_json::from_slice(&plaintext)
        .map_err(|error| bundle_verification_error(format!("bundle verification failed: {error}")))?;
    let counts = ImportedBundleCounts {
        profile_count: payload.profile_count,
        secret_count: payload.secret_count,
        blob_count: payload.blob_count,
        command_policy_count: payload.command_policy_count,
    };

    let now = now_unix_nanos()?;
    let (master_key, _master_key_source) = load_master_key(context, project_id)?;
    let outcome = apply_bundle_payload(
        &mut store,
        project_id,
        &payload,
        resolution,
        args.include_audit,
        &bundle.manifest,
        &master_key,
        now,
    )?;

    if let ApplyOutcome::InteractiveRequired { divergent } = &outcome {
        writeln!(output, "bundle: verified")?;
        writeln!(output, "import: decrypted")?;
        writeln!(output, "profiles: {}", counts.profile_count)?;
        writeln!(output, "secrets: {}", counts.secret_count)?;
        writeln!(output, "blobs: {}", counts.blob_count)?;
        writeln!(output, "command_policies: {}", counts.command_policy_count)?;
        writeln!(output, "active_secret_count: {}", payload.active_secret_count)?;
        writeln!(
            output,
            "include_audit_requested: {}",
            if args.include_audit { "yes" } else { "no" }
        )?;
        writeln!(
            output,
            "bundle_include_audit: {}",
            if payload.audit_rows_included { "yes" } else { "no" }
        )?;
        writeln!(output, "conflict_policy: {}", resolution.label())?;
        writeln!(output, "metadata_only: yes")?;
        for entry in divergent {
            writeln!(output, "conflict: {entry}")?;
        }
        writeln!(
            output,
            "import: conflicts require resolution; pass --accept-incoming or --accept-local"
        )?;
        return Err(invalid_reference_error(
            "import: conflicts require resolution; pass --accept-incoming or --accept-local",
        ));
    }

    let ApplyOutcome::Applied { applied, conflicts } = outcome else {
        unreachable!("ApplyOutcome must be Applied after InteractiveRequired branch");
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
            timestamp: now,
            include_audit_requested: Some(args.include_audit),
            user_verification: UserVerificationAudit::not_required(),
            decrypted_counts: Some(&counts),
            applied_counts: Some(&applied),
            conflict_counts: Some(&conflicts),
            applied: Some(true),
        },
    )?;

    writeln!(output, "bundle: verified")?;
    writeln!(output, "import: decrypted")?;
    writeln!(output, "profiles: {}", counts.profile_count)?;
    writeln!(output, "secrets: {}", counts.secret_count)?;
    writeln!(output, "blobs: {}", counts.blob_count)?;
    writeln!(output, "command_policies: {}", counts.command_policy_count)?;
    writeln!(output, "active_secret_count: {}", payload.active_secret_count)?;
    writeln!(output, "include_audit_requested: {}", if args.include_audit { "yes" } else { "no" })?;
    writeln!(
        output,
        "bundle_include_audit: {}",
        if payload.audit_rows_included { "yes" } else { "no" }
    )?;
    writeln!(output, "conflict_policy: {}", resolution.label())?;
    writeln!(output, "metadata_only: yes")?;
    writeln!(output, "import: applied")?;
    writeln!(output, "applied_profile_count: {}", applied.profile_count)?;
    writeln!(output, "applied_secret_count: {}", applied.secret_count)?;
    writeln!(output, "applied_secret_version_count: {}", applied.secret_version_count)?;
    writeln!(output, "applied_blob_count: {}", applied.blob_count)?;
    writeln!(output, "applied_command_policy_count: {}", applied.command_policy_count)?;
    writeln!(output, "applied_profile_key_count: {}", applied.profile_key_count)?;
    writeln!(output, "conflict_identical: {}", conflicts.identical)?;
    writeln!(output, "conflict_newer_incoming: {}", conflicts.newer_incoming)?;
    writeln!(output, "conflict_divergent: {}", conflicts.divergent)?;
    writeln!(output, "conflict_deleted_vs_active: {}", conflicts.deleted_vs_active)?;
    writeln!(output, "conflict_applied: {}", conflicts.applied)?;
    writeln!(output, "conflict_rejected: {}", conflicts.rejected)?;
    Ok(())
}

/// Applies a decrypted sealed-bundle payload to the local store under one
/// `SQLite` transaction.
///
/// Identical rows are counted but never re-written. Newer-incoming and
/// divergent rows are resolved by [`ConflictResolution`]; under
/// [`ConflictResolution::InteractiveRequired`] the transaction is rolled
/// back and the function returns [`ApplyOutcome::InteractiveRequired`]
/// with a metadata-only summary list.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn apply_bundle_payload(
    store: &mut Store,
    project_id: &str,
    payload: &SealedBundlePayloadV1,
    resolution: ConflictResolution,
    include_audit: bool,
    manifest: &BundleManifest,
    receiver_master_key: &locket_crypto::KeyBytes,
    now: i64,
) -> Result<ApplyOutcome, CliError> {
    let bundle_digest_bytes = decode_bundle_digest(&manifest.payload_digest)?;
    let mut applied = AppliedBundleCounts::default();
    let mut conflicts = BundleConflictCounts::default();
    let mut divergent_summary: Vec<String> = Vec::new();

    let connection = store.connection_mut();
    let transaction = connection.transaction().map_err(|error| {
        metadata_invalid_error(format!("apply transaction begin failed: {error}"))
    })?;

    // Profiles: insert if absent, otherwise compare. Profile rows have no
    // version field; the conflict matrix is identical-vs-divergent only.
    for profile in &payload.profiles {
        match read_local_profile(&transaction, project_id, &profile.profile_id)? {
            None => {
                transaction
                    .execute(
                        "INSERT INTO profiles(id, project_id, name, dangerous, created_at)
                         VALUES (?1, ?2, ?3, ?4, ?5)",
                        params![
                            profile.profile_id,
                            project_id,
                            profile.name,
                            profile.dangerous,
                            profile.created_at,
                        ],
                    )
                    .map_err(map_apply_sqlite_error)?;
                applied.profile_count = applied.profile_count.saturating_add(1);
                conflicts.applied = conflicts.applied.saturating_add(1);
            }
            Some(local) => {
                let identical = local.name == profile.name
                    && local.dangerous == profile.dangerous
                    && local.created_at == profile.created_at;
                if identical {
                    conflicts.identical = conflicts.identical.saturating_add(1);
                    continue;
                }
                if resolve_divergent(
                    resolution,
                    &mut conflicts,
                    &mut divergent_summary,
                    "profile",
                    &profile.profile_id,
                ) == DivergentDecision::Apply
                {
                    transaction
                        .execute(
                            "UPDATE profiles
                             SET name = ?2, dangerous = ?3, created_at = ?4
                             WHERE id = ?1 AND project_id = ?5",
                            params![
                                profile.profile_id,
                                profile.name,
                                profile.dangerous,
                                profile.created_at,
                                project_id,
                            ],
                        )
                        .map_err(map_apply_sqlite_error)?;
                    applied.profile_count = applied.profile_count.saturating_add(1);
                }
            }
        }
    }

    // Profile keys: rewrap each plaintext key under the receiver's
    // master-key-derived wrapping key with a fresh receiver-side key id.
    for profile_key in &payload.profile_keys {
        let purpose = parse_key_purpose(&profile_key.purpose)?;
        let existing = transaction
            .query_row(
                "SELECT 1 FROM keys
                 WHERE project_id = ?1 AND profile_id IS ?2 AND purpose = ?3",
                params![project_id, profile_key.profile_id, profile_key.purpose],
                |_| Ok(()),
            )
            .map(Some)
            .or_else(|error| {
                if matches!(error, rusqlite::Error::QueryReturnedNoRows) {
                    Ok(None)
                } else {
                    Err(error)
                }
            })
            .map_err(map_apply_sqlite_error)?;
        if existing.is_some() {
            conflicts.identical = conflicts.identical.saturating_add(1);
            continue;
        }
        let plaintext_bytes =
            BASE64URL_NOPAD.decode(profile_key.key_material_b64.as_bytes()).map_err(|_| {
                bundle_verification_error("profile key material is not valid base64url")
            })?;
        let mut plaintext_array = [0_u8; locket_crypto::KEY_LEN];
        if plaintext_bytes.len() != plaintext_array.len() {
            return Err(bundle_verification_error("profile key material has wrong length"));
        }
        plaintext_array.copy_from_slice(&plaintext_bytes);
        let receiver_key_id = KeyId::generate().map_err(|_| CliError::Time)?;
        let wrapped = rewrap_imported_profile_key(
            receiver_master_key,
            project_id,
            &profile_key.profile_id,
            receiver_key_id.as_str(),
            purpose,
            &plaintext_array,
        )?;
        let key_record = KeyRecord {
            id: receiver_key_id.into_string(),
            project_id: project_id.to_owned(),
            profile_id: Some(profile_key.profile_id.clone()),
            purpose: purpose.as_str().to_owned(),
            wrapped_material: wrapped.ciphertext,
            nonce: wrapped.nonce,
            created_at: now,
        };
        transaction
            .execute(
                "INSERT INTO keys(id, project_id, profile_id, purpose, wrapped_material, nonce, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    key_record.id,
                    key_record.project_id,
                    key_record.profile_id,
                    key_record.purpose,
                    key_record.wrapped_material,
                    key_record.nonce,
                    key_record.created_at,
                ],
            )
            .map_err(map_apply_sqlite_error)?;
        applied.profile_key_count = applied.profile_key_count.saturating_add(1);
        conflicts.applied = conflicts.applied.saturating_add(1);
    }

    // Command policies: upsert is always idempotent.
    for policy in &payload.command_policies {
        let policy_json = command_policy_value(policy);
        let exists = transaction
            .query_row(
                "SELECT 1 FROM command_policies WHERE project_id = ?1 AND name = ?2",
                params![project_id, policy.name],
                |_| Ok(()),
            )
            .map(Some)
            .or_else(|error| {
                if matches!(error, rusqlite::Error::QueryReturnedNoRows) {
                    Ok(None)
                } else {
                    Err(error)
                }
            })
            .map_err(map_apply_sqlite_error)?
            .is_some();
        let policy_text = serde_json::to_string(&policy_json).map_err(CliError::from)?;
        let normalized_text = policy_text.clone();
        transaction
            .execute(
                "INSERT INTO command_policies(
                   project_id, name, policy_json, normalized_json, created_at, updated_at
                 )
                 VALUES (?1, ?2, ?3, ?4, ?5, ?5)
                 ON CONFLICT(project_id, name) DO UPDATE SET
                   policy_json = excluded.policy_json,
                   normalized_json = excluded.normalized_json,
                   updated_at = excluded.updated_at",
                params![project_id, policy.name, policy_text, normalized_text, now],
            )
            .map_err(map_apply_sqlite_error)?;
        if exists {
            conflicts.identical = conflicts.identical.saturating_add(1);
        } else {
            applied.command_policy_count = applied.command_policy_count.saturating_add(1);
            conflicts.applied = conflicts.applied.saturating_add(1);
        }
    }

    // Secrets: insert when absent, otherwise resolve via the conflict matrix.
    for secret in &payload.secrets {
        match read_local_secret(&transaction, &secret.id)? {
            None => {
                transaction
                    .execute(
                        "INSERT INTO secrets(
                           id, project_id, profile_id, name, source, origin, required,
                           current_version, state, created_at, updated_at, last_rotated_at, deleted_at
                         )
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, ?7, ?8, ?9, ?10, ?11, ?12)",
                        params![
                            secret.id,
                            project_id,
                            secret.profile_id,
                            secret.name,
                            secret.source,
                            secret.origin,
                            secret.current_version,
                            secret.state,
                            secret.created_at,
                            secret.updated_at,
                            secret.last_rotated_at,
                            secret.deleted_at,
                        ],
                    )
                    .map_err(map_apply_sqlite_error)?;
                applied.secret_count = applied.secret_count.saturating_add(1);
                conflicts.applied = conflicts.applied.saturating_add(1);
            }
            Some(local) => {
                let identical = local.profile_id == secret.profile_id
                    && local.name == secret.name
                    && local.source == secret.source
                    && local.origin == secret.origin
                    && local.current_version == secret.current_version
                    && local.state == secret.state
                    && local.created_at == secret.created_at
                    && local.updated_at == secret.updated_at
                    && local.last_rotated_at == secret.last_rotated_at
                    && local.deleted_at == secret.deleted_at;
                if identical {
                    conflicts.identical = conflicts.identical.saturating_add(1);
                    continue;
                }
                let deleted_vs_active = local.state != secret.state;
                if deleted_vs_active {
                    conflicts.deleted_vs_active =
                        conflicts.deleted_vs_active.saturating_add(1);
                }
                let newer_incoming = secret.updated_at > local.updated_at
                    || secret.current_version > local.current_version;
                if newer_incoming && !deleted_vs_active {
                    conflicts.newer_incoming = conflicts.newer_incoming.saturating_add(1);
                }
                let decision = if deleted_vs_active || !newer_incoming {
                    resolve_divergent(
                        resolution,
                        &mut conflicts,
                        &mut divergent_summary,
                        "secret",
                        &secret.id,
                    )
                } else if matches!(resolution, ConflictResolution::AcceptIncoming) {
                    DivergentDecision::Apply
                } else if matches!(resolution, ConflictResolution::AcceptLocal) {
                    DivergentDecision::Skip
                } else {
                    divergent_summary.push(format!("secret/{}: newer-incoming", secret.id));
                    DivergentDecision::Defer
                };
                if matches!(decision, DivergentDecision::Apply) {
                    transaction
                        .execute(
                            "UPDATE secrets
                             SET name = ?2, source = ?3, origin = ?4, current_version = ?5,
                                 state = ?6, created_at = ?7, updated_at = ?8,
                                 last_rotated_at = ?9, deleted_at = ?10
                             WHERE id = ?1",
                            params![
                                secret.id,
                                secret.name,
                                secret.source,
                                secret.origin,
                                secret.current_version,
                                secret.state,
                                secret.created_at,
                                secret.updated_at,
                                secret.last_rotated_at,
                                secret.deleted_at,
                            ],
                        )
                        .map_err(map_apply_sqlite_error)?;
                    applied.secret_count = applied.secret_count.saturating_add(1);
                }
            }
        }
    }

    // Secret versions: identical-on-match, newer-incoming triggers
    // rotate-with-no-grace against the local current version, divergent
    // routes through `resolve_divergent`.
    for version in &payload.secret_versions {
        match read_local_secret_version(&transaction, &version.secret_id, version.version)? {
            None => {
                if version.state == "current" {
                    deprecate_local_current_version(&transaction, &version.secret_id, now)?;
                }
                insert_secret_version(&transaction, version)?;
                applied.secret_version_count = applied.secret_version_count.saturating_add(1);
                conflicts.applied = conflicts.applied.saturating_add(1);
            }
            Some(local) => {
                let identical = local.source == version.source
                    && local.origin == version.origin
                    && local.state == version.state
                    && local.created_at == version.created_at
                    && local.deprecated_at == version.deprecated_at
                    && local.grace_until == version.grace_until
                    && local.purged_at == version.purged_at;
                if identical {
                    conflicts.identical = conflicts.identical.saturating_add(1);
                    continue;
                }
                let local_active = local.state == "current";
                let incoming_active = version.state == "current";
                let deleted_vs_active = local_active != incoming_active;
                if deleted_vs_active {
                    conflicts.deleted_vs_active =
                        conflicts.deleted_vs_active.saturating_add(1);
                }
                let newer_incoming =
                    !deleted_vs_active && version.created_at > local.created_at;
                if newer_incoming {
                    conflicts.newer_incoming = conflicts.newer_incoming.saturating_add(1);
                }
                let decision = if deleted_vs_active || !newer_incoming {
                    resolve_divergent(
                        resolution,
                        &mut conflicts,
                        &mut divergent_summary,
                        "secret_version",
                        &format!("{}@{}", version.secret_id, version.version),
                    )
                } else if matches!(resolution, ConflictResolution::AcceptIncoming) {
                    DivergentDecision::Apply
                } else if matches!(resolution, ConflictResolution::AcceptLocal) {
                    DivergentDecision::Skip
                } else {
                    divergent_summary.push(format!(
                        "secret_version/{}@{}: newer-incoming",
                        version.secret_id, version.version
                    ));
                    DivergentDecision::Defer
                };
                if matches!(decision, DivergentDecision::Apply) {
                    transaction
                        .execute(
                            "UPDATE secret_versions
                             SET source = ?3, origin = ?4, state = ?5, created_at = ?6,
                                 deprecated_at = ?7, grace_until = ?8, purged_at = ?9
                             WHERE secret_id = ?1 AND version = ?2",
                            params![
                                version.secret_id,
                                version.version,
                                version.source,
                                version.origin,
                                version.state,
                                version.created_at,
                                version.deprecated_at,
                                version.grace_until,
                                version.purged_at,
                            ],
                        )
                        .map_err(map_apply_sqlite_error)?;
                    applied.secret_version_count =
                        applied.secret_version_count.saturating_add(1);
                }
            }
        }
    }

    // Blobs: insert when absent; identical when stored bytes match;
    // divergent otherwise.
    for blob in &payload.blobs {
        match read_local_blob(&transaction, &blob.secret_id, blob.version)? {
            None => {
                let blob_record = decode_bundle_blob(blob)?;
                transaction
                    .execute(
                        "INSERT INTO blobs(
                           secret_id, version, encrypted_dek, ciphertext, value_nonce,
                           aad_schema_version, created_at
                         )
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                        params![
                            blob_record.secret_id,
                            blob_record.version,
                            blob_record.encrypted_dek,
                            blob_record.ciphertext,
                            blob_record.value_nonce.as_slice(),
                            blob_record.aad_schema_version,
                            blob_record.created_at,
                        ],
                    )
                    .map_err(map_apply_sqlite_error)?;
                applied.blob_count = applied.blob_count.saturating_add(1);
                conflicts.applied = conflicts.applied.saturating_add(1);
            }
            Some(local) => {
                let incoming = decode_bundle_blob(blob)?;
                let identical = local.encrypted_dek == incoming.encrypted_dek
                    && local.ciphertext == incoming.ciphertext
                    && local.value_nonce == incoming.value_nonce;
                if identical {
                    conflicts.identical = conflicts.identical.saturating_add(1);
                    continue;
                }
                let decision = resolve_divergent(
                    resolution,
                    &mut conflicts,
                    &mut divergent_summary,
                    "blob",
                    &format!("{}@{}", blob.secret_id, blob.version),
                );
                if matches!(decision, DivergentDecision::Apply) {
                    transaction
                        .execute(
                            "UPDATE blobs
                             SET encrypted_dek = ?3, ciphertext = ?4, value_nonce = ?5,
                                 aad_schema_version = ?6, created_at = ?7
                             WHERE secret_id = ?1 AND version = ?2",
                            params![
                                incoming.secret_id,
                                incoming.version,
                                incoming.encrypted_dek,
                                incoming.ciphertext,
                                incoming.value_nonce.as_slice(),
                                incoming.aad_schema_version,
                                incoming.created_at,
                            ],
                        )
                        .map_err(map_apply_sqlite_error)?;
                    applied.blob_count = applied.blob_count.saturating_add(1);
                }
            }
        }
    }

    if !divergent_summary.is_empty()
        && matches!(resolution, ConflictResolution::InteractiveRequired)
    {
        transaction.rollback().map_err(|error| {
            metadata_invalid_error(format!("apply transaction rollback failed: {error}"))
        })?;
        return Ok(ApplyOutcome::InteractiveRequired { divergent: divergent_summary });
    }

    if include_audit && let Some(audit_chain) = payload.audit_chain.as_ref() {
        insert_imported_audit_chain(
            &transaction,
            project_id,
            &bundle_digest_bytes,
            manifest,
            audit_chain,
            now,
        )?;
    }

    transaction.commit().map_err(|error| {
        metadata_invalid_error(format!("apply transaction commit failed: {error}"))
    })?;
    Ok(ApplyOutcome::Applied { applied, conflicts })
}

fn resolve_divergent(
    resolution: ConflictResolution,
    conflicts: &mut BundleConflictCounts,
    divergent: &mut Vec<String>,
    family: &str,
    identifier: &str,
) -> DivergentDecision {
    conflicts.divergent = conflicts.divergent.saturating_add(1);
    match resolution {
        ConflictResolution::AcceptIncoming => {
            conflicts.applied = conflicts.applied.saturating_add(1);
            DivergentDecision::Apply
        }
        ConflictResolution::AcceptLocal => {
            conflicts.rejected = conflicts.rejected.saturating_add(1);
            DivergentDecision::Skip
        }
        ConflictResolution::InteractiveRequired => {
            divergent.push(format!("{family}/{identifier}: divergent"));
            DivergentDecision::Defer
        }
    }
}

#[derive(Debug)]
struct LocalProfileRow {
    name: String,
    dangerous: bool,
    created_at: i64,
}

fn read_local_profile(
    transaction: &rusqlite::Transaction<'_>,
    project_id: &str,
    profile_id: &str,
) -> Result<Option<LocalProfileRow>, CliError> {
    use rusqlite::OptionalExtension;
    transaction
        .query_row(
            "SELECT name, dangerous, created_at
             FROM profiles
             WHERE id = ?1 AND project_id = ?2",
            params![profile_id, project_id],
            |row| {
                Ok(LocalProfileRow {
                    name: row.get(0)?,
                    dangerous: row.get(1)?,
                    created_at: row.get(2)?,
                })
            },
        )
        .optional()
        .map_err(map_apply_sqlite_error)
}

#[derive(Debug)]
struct LocalSecretRow {
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

fn read_local_secret(
    transaction: &rusqlite::Transaction<'_>,
    secret_id: &str,
) -> Result<Option<LocalSecretRow>, CliError> {
    use rusqlite::OptionalExtension;
    transaction
        .query_row(
            "SELECT profile_id, name, source, origin, current_version, state,
                    created_at, updated_at, last_rotated_at, deleted_at
             FROM secrets
             WHERE id = ?1",
            params![secret_id],
            |row| {
                Ok(LocalSecretRow {
                    profile_id: row.get(0)?,
                    name: row.get(1)?,
                    source: row.get(2)?,
                    origin: row.get(3)?,
                    current_version: row.get(4)?,
                    state: row.get(5)?,
                    created_at: row.get(6)?,
                    updated_at: row.get(7)?,
                    last_rotated_at: row.get(8)?,
                    deleted_at: row.get(9)?,
                })
            },
        )
        .optional()
        .map_err(map_apply_sqlite_error)
}

#[derive(Debug)]
struct LocalSecretVersionRow {
    source: String,
    origin: String,
    state: String,
    created_at: i64,
    deprecated_at: Option<i64>,
    grace_until: Option<i64>,
    purged_at: Option<i64>,
}

fn read_local_secret_version(
    transaction: &rusqlite::Transaction<'_>,
    secret_id: &str,
    version: u32,
) -> Result<Option<LocalSecretVersionRow>, CliError> {
    use rusqlite::OptionalExtension;
    transaction
        .query_row(
            "SELECT source, origin, state, created_at, deprecated_at, grace_until, purged_at
             FROM secret_versions
             WHERE secret_id = ?1 AND version = ?2",
            params![secret_id, version],
            |row| {
                Ok(LocalSecretVersionRow {
                    source: row.get(0)?,
                    origin: row.get(1)?,
                    state: row.get(2)?,
                    created_at: row.get(3)?,
                    deprecated_at: row.get(4)?,
                    grace_until: row.get(5)?,
                    purged_at: row.get(6)?,
                })
            },
        )
        .optional()
        .map_err(map_apply_sqlite_error)
}

#[derive(Debug)]
struct LocalBlobRow {
    encrypted_dek: Vec<u8>,
    ciphertext: Vec<u8>,
    value_nonce: [u8; 24],
}

fn read_local_blob(
    transaction: &rusqlite::Transaction<'_>,
    secret_id: &str,
    version: u32,
) -> Result<Option<LocalBlobRow>, CliError> {
    use rusqlite::OptionalExtension;
    transaction
        .query_row(
            "SELECT encrypted_dek, ciphertext, value_nonce
             FROM blobs
             WHERE secret_id = ?1 AND version = ?2",
            params![secret_id, version],
            |row| {
                let nonce_bytes: Vec<u8> = row.get(2)?;
                let mut nonce = [0_u8; 24];
                if nonce_bytes.len() != 24 {
                    return Err(rusqlite::Error::InvalidColumnType(
                        2,
                        "blobs.value_nonce".to_owned(),
                        rusqlite::types::Type::Blob,
                    ));
                }
                nonce.copy_from_slice(&nonce_bytes);
                Ok(LocalBlobRow {
                    encrypted_dek: row.get(0)?,
                    ciphertext: row.get(1)?,
                    value_nonce: nonce,
                })
            },
        )
        .optional()
        .map_err(map_apply_sqlite_error)
}

fn deprecate_local_current_version(
    transaction: &rusqlite::Transaction<'_>,
    secret_id: &str,
    now: i64,
) -> Result<(), CliError> {
    transaction
        .execute(
            "UPDATE secret_versions
             SET state = 'deprecated', deprecated_at = ?2, grace_until = ?2
             WHERE secret_id = ?1 AND state = 'current'",
            params![secret_id, now],
        )
        .map_err(map_apply_sqlite_error)?;
    Ok(())
}

fn insert_secret_version(
    transaction: &rusqlite::Transaction<'_>,
    version: &SealedBundleSecretVersionV1,
) -> Result<(), CliError> {
    transaction
        .execute(
            "INSERT INTO secret_versions(
               secret_id, version, source, origin, state, created_at,
               deprecated_at, grace_until, purged_at
             )
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                version.secret_id,
                version.version,
                version.source,
                version.origin,
                version.state,
                version.created_at,
                version.deprecated_at,
                version.grace_until,
                version.purged_at,
            ],
        )
        .map_err(map_apply_sqlite_error)?;
    Ok(())
}

fn decode_bundle_blob(blob: &SealedBundleBlobV1) -> Result<SecretBlobRecord, CliError> {
    let encrypted_dek = BASE64URL_NOPAD
        .decode(blob.encrypted_dek_b64.as_bytes())
        .map_err(|_| bundle_verification_error("blob encrypted_dek_b64 is not valid base64url"))?;
    let ciphertext = BASE64URL_NOPAD
        .decode(blob.ciphertext_b64.as_bytes())
        .map_err(|_| bundle_verification_error("blob ciphertext_b64 is not valid base64url"))?;
    let nonce_bytes = BASE64URL_NOPAD
        .decode(blob.value_nonce_b64.as_bytes())
        .map_err(|_| bundle_verification_error("blob value_nonce_b64 is not valid base64url"))?;
    if nonce_bytes.len() != 24 {
        return Err(bundle_verification_error("blob value_nonce must be 24 bytes"));
    }
    let mut value_nonce = [0_u8; 24];
    value_nonce.copy_from_slice(&nonce_bytes);
    Ok(SecretBlobRecord {
        secret_id: blob.secret_id.clone(),
        version: blob.version,
        encrypted_dek,
        ciphertext,
        value_nonce,
        aad_schema_version: blob.aad_schema_version,
        created_at: blob.created_at,
    })
}

fn command_policy_value(policy: &SealedBundleCommandPolicyV1) -> Value {
    serde_json::to_value(policy).unwrap_or(Value::Null)
}

fn parse_key_purpose(value: &str) -> Result<KeyPurpose, CliError> {
    match value {
        v if v == KeyPurpose::ProfileSecret.as_str() => Ok(KeyPurpose::ProfileSecret),
        v if v == KeyPurpose::ProfileFingerprint.as_str() => Ok(KeyPurpose::ProfileFingerprint),
        v if v == KeyPurpose::ProjectMetadata.as_str() => Ok(KeyPurpose::ProjectMetadata),
        v if v == KeyPurpose::Audit.as_str() => Ok(KeyPurpose::Audit),
        other => Err(bundle_verification_error(format!(
            "unknown profile key purpose in bundle: {other}"
        ))),
    }
}

#[allow(clippy::needless_pass_by_value)]
fn map_apply_sqlite_error(error: rusqlite::Error) -> CliError {
    metadata_invalid_error(format!("apply step failed: {error}"))
}

fn decode_bundle_digest(digest: &str) -> Result<[u8; 32], CliError> {
    if digest.len() != 64 {
        return Err(metadata_invalid_error("bundle digest must be 64 hex characters"));
    }
    let mut output = [0_u8; 32];
    for (index, chunk) in digest.as_bytes().chunks_exact(2).enumerate() {
        let high = bundle_hex_nibble(chunk[0])?;
        let low = bundle_hex_nibble(chunk[1])?;
        output[index] = (high << 4) | low;
    }
    Ok(output)
}

fn bundle_hex_nibble(byte: u8) -> Result<u8, CliError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(metadata_invalid_error("bundle digest must be hex encoded")),
    }
}

/// Inserts the bundle's encrypted audit-chain payload as one
/// `imported_audit_chains` row.
fn insert_imported_audit_chain(
    transaction: &rusqlite::Transaction<'_>,
    project_id: &str,
    bundle_digest: &[u8; 32],
    manifest: &BundleManifest,
    audit_chain: &SealedAuditChainPayloadV1,
    now: i64,
) -> Result<(), CliError> {
    let chain_id = generate_imported_audit_chain_id()?;
    let source_device_fingerprint = manifest
        .recipient_fingerprints
        .first()
        .cloned()
        .unwrap_or_else(|| format_hex(bundle_digest));
    let checkpoint_hmac = BASE64URL_NOPAD
        .decode(audit_chain.checkpoint_hmac_b64.as_bytes())
        .map_err(|_| bundle_verification_error("audit chain checkpoint hmac is not base64url"))?;
    if checkpoint_hmac.len() != AUDIT_HMAC_LEN {
        return Err(bundle_verification_error("audit chain checkpoint hmac must be 32 bytes"));
    }
    let encrypted_rows = BASE64URL_NOPAD
        .decode(audit_chain.encrypted_rows_b64.as_bytes())
        .map_err(|_| bundle_verification_error("audit chain ciphertext is not base64url"))?;
    let nonce = BASE64URL_NOPAD
        .decode(audit_chain.nonce_b64.as_bytes())
        .map_err(|_| bundle_verification_error("audit chain nonce is not base64url"))?;
    if nonce.len() != 24 {
        return Err(bundle_verification_error("audit chain nonce must be 24 bytes"));
    }
    transaction
        .execute(
            "INSERT INTO imported_audit_chains(
               id, project_id, source_device_fingerprint, bundle_digest, checkpoint_sequence,
               checkpoint_hmac, encrypted_rows, nonce, aad_schema_version, imported_at
             )
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                chain_id,
                project_id,
                source_device_fingerprint,
                bundle_digest.as_slice(),
                audit_chain.checkpoint_sequence,
                checkpoint_hmac,
                encrypted_rows,
                nonce,
                audit_chain.aad_schema_version,
                now,
            ],
        )
        .map_err(map_apply_sqlite_error)?;
    Ok(())
}

fn generate_imported_audit_chain_id() -> Result<String, CliError> {
    let random: [u8; 16] = locket_crypto::random_bytes::<16>()?;
    Ok(format!("lk_chain_{}", format_hex(&random)))
}

fn build_import_device_private_key_storage(
    context: &RuntimeContext,
    project_id: &str,
) -> Result<WrappedLocalFileDevicePrivateKeyStorage, CliError> {
    let directory = context
        .store_path
        .parent()
        .map(std::path::Path::to_path_buf)
        .ok_or_else(|| {
            crate::runtime::error::corrupt_db_error("could not resolve device private key root")
        })?;
    Ok(WrappedLocalFileDevicePrivateKeyStorage::new(
        directory,
        project_id.to_owned(),
        std::sync::Arc::clone(&context.key_store),
    ))
}

fn map_private_key_load_error(error: PlatformError) -> CliError {
    match error {
        PlatformError::DevicePrivateKeyNotFound => bundle_verification_error(
            "device private-key storage not initialized",
        ),
        other => CliError::Platform(other),
    }
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
    let audit_chain = if include_audit {
        let project_id = resolved.config.project_id.as_str();
        let rows = store.list_exportable_audit_rows(project_id)?;
        if rows.is_empty() {
            // Empty audit log: include_audit was set but nothing has been
            // appended yet. Skip the encrypted-chain section rather than
            // attaching an empty ciphertext; the bundle still records
            // include_audit=true on the manifest/audit row.
            None
        } else {
            Some(encrypt_audit_chain(&rows, BUNDLE_SCHEMA_V1)?)
        }
    } else {
        None
    };
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
        audit_chain,
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

/// Domain separator + canonical AAD bytes covering the audit-chain
/// encryption parameters carried inside [`SealedBundlePayloadV1`].
///
/// AAD layout (v1):
///
/// ```text
/// b"locket-bundle-audit-chain-v1\0"   // 30 bytes domain separator
/// u16_le(aad_schema_version)
/// u16_le(bundle_schema_version)
/// u64_le(checkpoint_sequence)
/// [u8; 32] checkpoint_hmac
/// ```
///
/// `aad_schema_version` is the audit AAD schema (mirrors
/// `locket_crypto::AAD_SCHEMA_V1`); `bundle_schema_version` is the
/// outer sealed-bundle container version. `checkpoint_sequence` and
/// `checkpoint_hmac` are the trailing audit-row fields the receiver
/// stores in `imported_audit_chains`. The bundle digest is not bound
/// here because it is computed over ciphertext that itself contains
/// this payload (chicken-and-egg). The outer age envelope already
/// authenticates the full bundle payload, including the encryption
/// key, nonce, ciphertext, and checkpoint fields.
fn audit_chain_aad_v1(
    aad_schema_version: u16,
    bundle_schema_version: u16,
    checkpoint_sequence: u64,
    checkpoint_hmac: &[u8; AUDIT_HMAC_LEN],
) -> Vec<u8> {
    const DOMAIN: &[u8] = b"locket-bundle-audit-chain-v1\0";
    let mut aad = Vec::with_capacity(DOMAIN.len() + 2 + 2 + 8 + AUDIT_HMAC_LEN);
    aad.extend_from_slice(DOMAIN);
    aad.extend_from_slice(&aad_schema_version.to_le_bytes());
    aad.extend_from_slice(&bundle_schema_version.to_le_bytes());
    aad.extend_from_slice(&checkpoint_sequence.to_le_bytes());
    aad.extend_from_slice(checkpoint_hmac);
    aad
}

/// Random 32-byte symmetric key for the audit-chain XChaCha20-Poly1305
/// step. The key never leaves the age-encrypted bundle payload.
fn random_audit_chain_key() -> Result<[u8; 32], CliError> {
    let bytes = locket_crypto::random_bytes::<32>()?;
    Ok(bytes)
}

/// Random 24-byte XChaCha20-Poly1305 nonce.
fn random_audit_chain_nonce() -> Result<[u8; 24], CliError> {
    let bytes = locket_crypto::random_bytes::<24>()?;
    Ok(bytes)
}

/// Encrypts a project's audit rows into a [`SealedAuditChainPayloadV1`]
/// suitable for inclusion in a sealed bundle payload.
///
/// The plaintext is a canonical-JSON list of [`SealedAuditChainRowV1`]
/// values; this is the minimal serializer called out in the subtask
/// brief. AAD binding is documented on [`audit_chain_aad_v1`].
fn encrypt_audit_chain(
    rows: &[ExportableAuditRow],
    bundle_schema_version: u16,
) -> Result<SealedAuditChainPayloadV1, CliError> {
    let final_row = rows.last().ok_or_else(|| {
        metadata_invalid_error("audit chain export requires at least one audit row")
    })?;
    let checkpoint_sequence = final_row.sequence;
    let checkpoint_hmac = final_row.hmac;

    let plaintext_rows: Vec<SealedAuditChainRowV1> = rows
        .iter()
        .map(|row| SealedAuditChainRowV1 {
            sequence: row.sequence,
            schema_version: row.schema_version,
            timestamp: row.timestamp,
            profile_id: row.profile_id.clone(),
            action: row.action.clone(),
            status: row.status.clone(),
            metadata_json: row.metadata_json.clone(),
            secret_name: row.secret_name.clone(),
            command: row.command.clone(),
            previous_hmac_b64: BASE64URL_NOPAD.encode(&row.previous_hmac),
            hmac_b64: BASE64URL_NOPAD.encode(&row.hmac),
        })
        .collect();
    let plaintext = zeroize::Zeroizing::new(serde_json::to_vec(&plaintext_rows)?);

    let key = random_audit_chain_key()?;
    let nonce = random_audit_chain_nonce()?;
    let aad = audit_chain_aad_v1(
        AAD_SCHEMA_V1,
        bundle_schema_version,
        checkpoint_sequence,
        &checkpoint_hmac,
    );
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: plaintext.as_slice(), aad: &aad })
        .map_err(|_| metadata_invalid_error("audit chain encryption failed"))?;

    Ok(SealedAuditChainPayloadV1 {
        aad_schema_version: AAD_SCHEMA_V1,
        checkpoint_sequence,
        checkpoint_hmac_b64: BASE64URL_NOPAD.encode(&checkpoint_hmac),
        encrypted_rows_b64: BASE64URL_NOPAD.encode(&ciphertext),
        nonce_b64: BASE64URL_NOPAD.encode(&nonce),
        encryption_key_b64: BASE64URL_NOPAD.encode(&key),
        row_count: rows.len(),
    })
}

/// Decrypts a sealed audit-chain payload back into the row list.
///
/// Used by the bundle import path and by round-trip tests. Returns the
/// decoded rows on success. Tag, key, nonce, or AAD mismatches return a
/// bundle-verification error so callers can map to exit code 110.
// Bundle import lands in a follow-up slice; tests below exercise it.
#[allow(dead_code)]
fn decrypt_audit_chain(
    payload: &SealedAuditChainPayloadV1,
    bundle_schema_version: u16,
) -> Result<Vec<SealedAuditChainRowV1>, CliError> {
    let key_bytes = BASE64URL_NOPAD
        .decode(payload.encryption_key_b64.as_bytes())
        .map_err(|_| bundle_verification_error("audit chain encryption key is not valid base64url"))?;
    let nonce_bytes = BASE64URL_NOPAD
        .decode(payload.nonce_b64.as_bytes())
        .map_err(|_| bundle_verification_error("audit chain nonce is not valid base64url"))?;
    let ciphertext = BASE64URL_NOPAD
        .decode(payload.encrypted_rows_b64.as_bytes())
        .map_err(|_| bundle_verification_error("audit chain ciphertext is not valid base64url"))?;
    let checkpoint_hmac_bytes = BASE64URL_NOPAD
        .decode(payload.checkpoint_hmac_b64.as_bytes())
        .map_err(|_| bundle_verification_error("audit chain checkpoint hmac is not valid base64url"))?;
    if key_bytes.len() != 32 {
        return Err(bundle_verification_error("audit chain encryption key must be 32 bytes"));
    }
    if nonce_bytes.len() != 24 {
        return Err(bundle_verification_error("audit chain nonce must be 24 bytes"));
    }
    if checkpoint_hmac_bytes.len() != AUDIT_HMAC_LEN {
        return Err(bundle_verification_error("audit chain checkpoint hmac must be 32 bytes"));
    }
    let mut checkpoint_hmac = [0_u8; AUDIT_HMAC_LEN];
    checkpoint_hmac.copy_from_slice(&checkpoint_hmac_bytes);

    let aad = audit_chain_aad_v1(
        payload.aad_schema_version,
        bundle_schema_version,
        payload.checkpoint_sequence,
        &checkpoint_hmac,
    );
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key_bytes));
    let plaintext = cipher
        .decrypt(XNonce::from_slice(&nonce_bytes), Payload { msg: ciphertext.as_slice(), aad: &aad })
        .map_err(|_| bundle_verification_error("audit chain decryption failed"))?;
    let rows: Vec<SealedAuditChainRowV1> = serde_json::from_slice(&plaintext)
        .map_err(|error| bundle_verification_error(format!("audit chain row decode failed: {error}")))?;
    if rows.len() != payload.row_count {
        return Err(bundle_verification_error("audit chain row count mismatch"));
    }
    Ok(rows)
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
    Ok(VerifiedBundleV1 {
        manifest: container.manifest,
        encrypted_payload: container.encrypted_payload,
    })
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
    decrypted_counts: Option<&'a ImportedBundleCounts>,
    applied_counts: Option<&'a AppliedBundleCounts>,
    conflict_counts: Option<&'a BundleConflictCounts>,
    applied: Option<bool>,
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

#[allow(clippy::too_many_lines)]
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
    if let Some(counts) = request.decrypted_counts {
        metadata.insert("profile_count".to_owned(), Value::from(counts.profile_count));
        metadata.insert("secret_count".to_owned(), Value::from(counts.secret_count));
        metadata.insert("blob_count".to_owned(), Value::from(counts.blob_count));
        metadata
            .insert("command_policy_count".to_owned(), Value::from(counts.command_policy_count));
    }
    if let Some(applied_counts) = request.applied_counts {
        metadata
            .insert("applied_profile_count".to_owned(), Value::from(applied_counts.profile_count));
        metadata
            .insert("applied_secret_count".to_owned(), Value::from(applied_counts.secret_count));
        metadata.insert(
            "applied_secret_version_count".to_owned(),
            Value::from(applied_counts.secret_version_count),
        );
        metadata.insert("applied_blob_count".to_owned(), Value::from(applied_counts.blob_count));
        metadata.insert(
            "applied_command_policy_count".to_owned(),
            Value::from(applied_counts.command_policy_count),
        );
        metadata.insert(
            "applied_profile_key_count".to_owned(),
            Value::from(applied_counts.profile_key_count),
        );
    }
    if let Some(conflict_counts) = request.conflict_counts {
        let mut entry = Map::new();
        entry.insert("identical".to_owned(), Value::from(conflict_counts.identical));
        entry.insert("newer_incoming".to_owned(), Value::from(conflict_counts.newer_incoming));
        entry.insert("divergent".to_owned(), Value::from(conflict_counts.divergent));
        entry
            .insert("deleted_vs_active".to_owned(), Value::from(conflict_counts.deleted_vs_active));
        entry.insert("applied".to_owned(), Value::from(conflict_counts.applied));
        entry.insert("rejected".to_owned(), Value::from(conflict_counts.rejected));
        metadata.insert("conflict_counts".to_owned(), Value::Object(entry));
    }
    if let Some(applied) = request.applied {
        metadata.insert("applied".to_owned(), Value::from(applied));
    }
    metadata
        .insert("user_verification".to_owned(), serde_json::to_value(request.user_verification)?);
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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn sample_rows() -> Vec<ExportableAuditRow> {
        // Two-row chain: row 1 has zero previous_hmac; row 2 chains to
        // row 1's hmac. Values are illustrative; encrypt_audit_chain
        // does not validate HMAC continuity (that runs on the receiver
        // via verify_imported_audit_chain_structure).
        let hmac_one = [0x11_u8; AUDIT_HMAC_LEN];
        let hmac_two = [0x22_u8; AUDIT_HMAC_LEN];
        vec![
            ExportableAuditRow {
                sequence: 1,
                schema_version: 1,
                timestamp: 1_700_000_000_000_000_000,
                profile_id: None,
                action: "TEAM_INIT".to_owned(),
                status: "SUCCESS".to_owned(),
                metadata_json: r#"{"k":"v1"}"#.to_owned(),
                secret_name: None,
                command: Some("team init".to_owned()),
                previous_hmac: [0_u8; AUDIT_HMAC_LEN],
                hmac: hmac_one,
            },
            ExportableAuditRow {
                sequence: 2,
                schema_version: 1,
                timestamp: 1_700_000_001_000_000_000,
                profile_id: Some("lk_prof_dev".to_owned()),
                action: "BACKUP_EXPORT".to_owned(),
                status: "SUCCESS".to_owned(),
                metadata_json: r#"{"k":"v2"}"#.to_owned(),
                secret_name: Some("API_KEY".to_owned()),
                command: Some("export --sealed".to_owned()),
                previous_hmac: hmac_one,
                hmac: hmac_two,
            },
        ]
    }

    #[test]
    fn audit_chain_round_trip_recovers_originals() {
        let rows = sample_rows();
        let payload = encrypt_audit_chain(&rows, BUNDLE_SCHEMA_V1).unwrap();
        // Checkpoint fields mirror the final row 1:1.
        assert_eq!(payload.checkpoint_sequence, rows.last().unwrap().sequence);
        assert_eq!(
            BASE64URL_NOPAD.decode(payload.checkpoint_hmac_b64.as_bytes()).unwrap(),
            rows.last().unwrap().hmac.to_vec()
        );
        assert_eq!(payload.row_count, rows.len());
        assert_eq!(payload.aad_schema_version, AAD_SCHEMA_V1);
        // Nonce is exactly 24 bytes (XChaCha20-Poly1305).
        assert_eq!(BASE64URL_NOPAD.decode(payload.nonce_b64.as_bytes()).unwrap().len(), 24);
        // Encryption key is exactly 32 bytes.
        assert_eq!(
            BASE64URL_NOPAD.decode(payload.encryption_key_b64.as_bytes()).unwrap().len(),
            32
        );

        let recovered = decrypt_audit_chain(&payload, BUNDLE_SCHEMA_V1).unwrap();
        assert_eq!(recovered.len(), rows.len());
        for (idx, original) in rows.iter().enumerate() {
            let decoded = &recovered[idx];
            assert_eq!(decoded.sequence, original.sequence);
            assert_eq!(decoded.schema_version, original.schema_version);
            assert_eq!(decoded.timestamp, original.timestamp);
            assert_eq!(decoded.profile_id, original.profile_id);
            assert_eq!(decoded.action, original.action);
            assert_eq!(decoded.status, original.status);
            assert_eq!(decoded.metadata_json, original.metadata_json);
            assert_eq!(decoded.secret_name, original.secret_name);
            assert_eq!(decoded.command, original.command);
            assert_eq!(
                BASE64URL_NOPAD.decode(decoded.previous_hmac_b64.as_bytes()).unwrap(),
                original.previous_hmac.to_vec()
            );
            assert_eq!(
                BASE64URL_NOPAD.decode(decoded.hmac_b64.as_bytes()).unwrap(),
                original.hmac.to_vec()
            );
        }
    }

    #[test]
    fn audit_chain_decrypt_rejects_aad_mismatch() {
        // Tampering with checkpoint_sequence (covered by AAD) must
        // cause AEAD authentication to fail.
        let rows = sample_rows();
        let mut payload = encrypt_audit_chain(&rows, BUNDLE_SCHEMA_V1).unwrap();
        payload.checkpoint_sequence = payload.checkpoint_sequence.saturating_add(1);
        let result = decrypt_audit_chain(&payload, BUNDLE_SCHEMA_V1);
        assert!(result.is_err(), "tampered AAD must fail tag verification");
    }

    #[test]
    fn audit_chain_decrypt_rejects_bundle_schema_mismatch() {
        // Different bundle_schema_version is part of the AAD, so a
        // receiver presenting the wrong schema cannot decrypt.
        let rows = sample_rows();
        let payload = encrypt_audit_chain(&rows, BUNDLE_SCHEMA_V1).unwrap();
        let result = decrypt_audit_chain(&payload, BUNDLE_SCHEMA_V1.wrapping_add(1));
        assert!(result.is_err(), "bundle schema mismatch must fail tag verification");
    }

    #[test]
    fn audit_chain_uses_independent_nonce_per_call() {
        // Repeated encryptions must produce distinct nonces and
        // distinct ciphertexts so XChaCha20-Poly1305 (key, nonce) pairs
        // are never reused.
        let rows = sample_rows();
        let first = encrypt_audit_chain(&rows, BUNDLE_SCHEMA_V1).unwrap();
        let second = encrypt_audit_chain(&rows, BUNDLE_SCHEMA_V1).unwrap();
        assert_ne!(first.nonce_b64, second.nonce_b64);
        assert_ne!(first.encrypted_rows_b64, second.encrypted_rows_b64);
        assert_ne!(first.encryption_key_b64, second.encryption_key_b64);
    }

    #[test]
    fn audit_chain_field_is_none_when_not_requested() {
        // A bundle payload without --include-audit must serialize with
        // audit_chain absent (skip_serializing_if = "Option::is_none")
        // so existing manifests stay byte-stable.
        let payload = SealedBundlePayloadV1 {
            profiles: Vec::new(),
            command_policies: Vec::new(),
            secrets: Vec::new(),
            secret_versions: Vec::new(),
            blobs: Vec::new(),
            profile_keys: Vec::new(),
            profile_count: 0,
            command_policy_count: 0,
            secret_count: 0,
            secret_version_count: 0,
            blob_count: 0,
            profile_key_count: 0,
            active_secret_count: 0,
            audit_rows_included: false,
            audit_chain: None,
        };
        let json = serde_json::to_value(&payload).unwrap();
        assert!(json.get("audit_chain").is_none(), "audit_chain must be omitted when None");

        // Round-trip: the deserializer uses Option<...>::default() to
        // accept payloads without the field, mirroring forward-compat.
        let deserialized: SealedBundlePayloadV1 = serde_json::from_value(json).unwrap();
        assert!(deserialized.audit_chain.is_none());
    }

    #[test]
    fn encrypt_audit_chain_rejects_empty_row_list() {
        let result = encrypt_audit_chain(&[], BUNDLE_SCHEMA_V1);
        assert!(result.is_err(), "empty audit row list must fail");
    }
}
