//! Implementation of the `locket set` command and its private helpers.

use std::io::Write;

use locket_core::{SecretId, SecretName};
use locket_crypto::KeyPurpose;
use locket_store::{
    AuditContext, AuditWrite, ProfileRecord, SecretBlobRecord, SecretFingerprintRecord,
    SecretRecord, SecretVersionRecord, Store,
};

use crate::runtime::RuntimeContext;
use crate::runtime::error::{CliError, invalid_secret_name_error};
use crate::runtime::key_access::{default_profile, load_project_key};
use crate::support::project_files::refresh_example_for_project_if_enabled;
use crate::support::secret_helpers::{
    SecretEncryptRequest, encrypt_secret_version, secret_audit_metadata,
};
use crate::{
    ResolvedProject, SecretSourceArg, SecretWriteArgs, ensure_trusted_project_root, now_unix_nanos,
    open_store, require_project, secret_already_exists_error, secret_deleted_error,
    source_arg_to_str,
};

pub fn set_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &SecretWriteArgs,
) -> Result<(), CliError> {
    preflight_set_secret_value(context, args)?;
    let prompt = format!("set secret value for {}", args.key);
    let value = context.secret_value_reader.read_secret_value(&prompt)?;
    set_secret_value(context, args, value.as_str(), "manual", now_unix_nanos()?)?;
    refresh_example_for_project_if_enabled(context)?;
    let source = source_arg_to_str(args.source.source.unwrap_or(SecretSourceArg::UserLocal));
    writeln!(output, "set {} ({source})", args.key)?;
    Ok(())
}

pub fn preflight_set_secret_value(
    context: &RuntimeContext,
    args: &SecretWriteArgs,
) -> Result<(), CliError> {
    let name = SecretName::new(args.key.clone())
        .map_err(|_| invalid_secret_name_error("invalid secret name"))?;
    let resolved = require_project(context)?;
    let store = open_store(context)?;
    let profile = default_profile(&store, &resolved.config)?;
    let source = source_arg_to_str(args.source.source.unwrap_or(SecretSourceArg::UserLocal));
    if let Some(existing) = store.get_secret_by_source(
        resolved.config.project_id.as_str(),
        &profile.id,
        name.as_str(),
        source,
    )? {
        if existing.state == "deleted" {
            return Err(secret_deleted_error(
                "secret source is deleted; v1 does not reactivate tombstones",
            ));
        }
        return Err(secret_already_exists_error("secret exists; use rotate"));
    }
    if args.source.source.is_none() {
        let existing = store.list_secrets_by_name(
            resolved.config.project_id.as_str(),
            &profile.id,
            name.as_str(),
        )?;
        if !existing.is_empty() {
            return Err(secret_already_exists_error(
                "secret exists in another source; pass --source to choose a target",
            ));
        }
    }
    Ok(())
}

pub fn set_secret_value(
    context: &RuntimeContext,
    args: &SecretWriteArgs,
    value: &str,
    origin: &str,
    timestamp: i64,
) -> Result<(), CliError> {
    let source = source_arg_to_str(args.source.source.unwrap_or(SecretSourceArg::UserLocal));
    let resolved = require_project(context)?;
    let mut store = open_store(context)?;
    ensure_trusted_project_root(&store, &resolved)?;
    let profile = default_profile(&store, &resolved.config)?;
    set_secret_value_in_profile(
        context,
        &mut store,
        SecretWriteRequest {
            resolved: &resolved,
            profile: &profile,
            key: &args.key,
            source,
            value,
            origin,
            audit_action: "SET",
            timestamp,
        },
    )
}

#[derive(Clone, Copy)]
pub struct SecretWriteRequest<'a> {
    pub resolved: &'a ResolvedProject,
    pub profile: &'a ProfileRecord,
    pub key: &'a str,
    pub source: &'a str,
    pub value: &'a str,
    pub origin: &'a str,
    pub audit_action: &'a str,
    pub timestamp: i64,
}

pub fn set_secret_value_in_profile(
    context: &RuntimeContext,
    store: &mut Store,
    request: SecretWriteRequest<'_>,
) -> Result<(), CliError> {
    let name = SecretName::new(request.key.to_owned())
        .map_err(|_| invalid_secret_name_error("invalid secret name"))?;
    if let Some(existing) = store.get_secret_by_source(
        request.resolved.config.project_id.as_str(),
        &request.profile.id,
        name.as_str(),
        request.source,
    )? {
        if existing.state == "deleted" {
            return Err(secret_deleted_error(
                "secret source is deleted; v1 does not reactivate tombstones",
            ));
        }
        return Err(secret_already_exists_error("secret exists; use rotate"));
    }

    let secret_id = SecretId::generate().map_err(|_| CliError::Time)?;
    let version = 1;
    let audit_key = load_project_key(
        context,
        store,
        request.resolved.config.project_id.as_str(),
        KeyPurpose::Audit,
    )?;
    let (encrypted, fingerprint) = encrypt_secret_version(
        context,
        store,
        SecretEncryptRequest {
            project_id: request.resolved.config.project_id.as_str(),
            profile_id: &request.profile.id,
            secret_id: secret_id.as_str(),
            secret_name: name.as_str(),
            version,
            value: request.value,
        },
    )?;
    let secret_id_string = secret_id.into_string();
    let metadata = secret_audit_metadata(
        request.audit_action,
        name.as_str(),
        &request.profile.id,
        request.source,
        Some(version),
    );
    let audit = AuditWrite {
        project_id: request.resolved.config.project_id.as_str(),
        profile_id: Some(&request.profile.id),
        action: request.audit_action,
        status: "SUCCESS",
        secret_name: Some(name.as_str()),
        command: None,
        metadata_json: &metadata,
        timestamp: request.timestamp,
    };

    store.create_active_secret_with_audit(
        &SecretRecord {
            id: secret_id_string.clone(),
            project_id: request.resolved.config.project_id.as_str().to_owned(),
            profile_id: request.profile.id.clone(),
            name: name.as_str().to_owned(),
            source: request.source.to_owned(),
            origin: request.origin.to_owned(),
            current_version: version,
            state: "active".to_owned(),
            created_at: request.timestamp,
            updated_at: request.timestamp,
            last_rotated_at: None,
            deleted_at: None,
        },
        &SecretVersionRecord {
            secret_id: secret_id_string.clone(),
            version,
            source: request.source.to_owned(),
            origin: request.origin.to_owned(),
            state: "current".to_owned(),
            created_at: request.timestamp,
            deprecated_at: None,
            grace_until: None,
            purged_at: None,
        },
        &SecretBlobRecord {
            secret_id: secret_id_string.clone(),
            version,
            encrypted_dek: encrypted.encrypted_dek,
            ciphertext: encrypted.ciphertext,
            value_nonce: encrypted.value_nonce,
            aad_schema_version: encrypted.aad_schema_version,
            created_at: request.timestamp,
        },
        &SecretFingerprintRecord {
            secret_id: secret_id_string,
            version,
            fingerprint,
            created_at: request.timestamp,
        },
        Some(AuditContext { key: audit_key.as_ref(), write: &audit }),
    )?;
    Ok(())
}
