//! Shared helpers for working with encrypted secrets, profile secret
//! resolution, and audit metadata. These are reused across multiple CLI
//! commands (get, exec, run, set, rotate, copy, env inspect, etc.).

use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;

use locket_core::{CommandPolicy, Duration as LocketDuration, ProfileName, SecretName};
use locket_crypto::{
    EncryptedSecretValue, KeyPurpose, KeyWrapAad, KeyWrapPurpose, decrypt_secret_value_v1,
    encrypt_secret_value_v1, key_wrap_aad_v1, secret_blob_aad_v1, secret_fingerprint_v1,
};
use locket_store::{AuditWrite, ProfileRecord, SecretRecord, Store};
use serde_json::{Value, json};

use crate::commands::config::spec::{config_get_value, read_user_config};
use crate::runtime::RuntimeContext;
use crate::runtime::error::{
    CliError, corrupt_db_error, invalid_profile_name_error, invalid_reference_error,
    invalid_secret_name_error, metadata_invalid_error, profile_not_found_error,
    secret_deleted_error, secret_not_found_error,
};
use crate::runtime::key_access::{default_profile, load_profile_key, load_project_key};
use crate::runtime::user_verification::UserVerificationAudit;
use crate::{
    CopyArgs, CopySelection, ResolvedProject, SecretSourceArg, active_secrets_by_name,
    ensure_trusted_project_root, now_unix_nanos, open_store, require_project, source_arg_to_str,
    source_precedence,
};

pub struct ResolvedSecret {
    pub project: ResolvedProject,
    pub profile: ProfileRecord,
    pub secret: SecretRecord,
}

pub struct PolicySecretSelection {
    pub name: String,
    pub required: bool,
    pub sources: Vec<String>,
    pub selected: Option<SecretRecord>,
}

pub struct ValueAccessAudit<'a> {
    pub context: &'a RuntimeContext,
    pub resolved: &'a ResolvedSecret,
    pub action: &'static str,
    pub status: &'static str,
    pub access_mode: &'static str,
    pub ttl_seconds: Option<u64>,
    pub force: bool,
    pub clipboard_supported: Option<bool>,
    pub clipboard_clear_supported: Option<bool>,
    pub unsupported_reason: Option<&'a str>,
    pub denial_reason: Option<&'static str>,
    pub user_verification: UserVerificationAudit,
}

#[derive(Clone, Copy)]
pub struct SecretEncryptRequest<'a> {
    pub project_id: &'a str,
    pub profile_id: &'a str,
    pub secret_id: &'a str,
    pub secret_name: &'a str,
    pub version: u32,
    pub value: &'a str,
}

pub fn encrypt_secret_version(
    context: &RuntimeContext,
    store: &Store,
    request: SecretEncryptRequest<'_>,
) -> Result<(EncryptedSecretValue, Vec<u8>), CliError> {
    let profile_secret_key = load_profile_key(
        context,
        store,
        request.project_id,
        request.profile_id,
        KeyPurpose::ProfileSecret,
    )?;
    let profile_fingerprint_key = load_profile_key(
        context,
        store,
        request.project_id,
        request.profile_id,
        KeyPurpose::ProfileFingerprint,
    )?;
    let value_aad = secret_blob_aad_v1(&locket_crypto::SecretBlobAad::new(
        request.project_id,
        request.profile_id,
        request.secret_id,
        request.secret_name,
        request.version,
    ))?;
    let wrap_aad = key_wrap_aad_v1(&KeyWrapAad::new(
        request.project_id,
        request.secret_id,
        Some(request.profile_id),
        request.version,
        KeyWrapPurpose::SecretDek,
    ))?;
    let encrypted =
        encrypt_secret_value_v1(&profile_secret_key, request.value, &value_aad, &wrap_aad)?;
    let fingerprint = secret_fingerprint_v1(&profile_fingerprint_key, request.value)?;
    Ok((encrypted, fingerprint.to_vec()))
}

pub fn decrypt_secret_version(
    context: &RuntimeContext,
    store: &Store,
    project_id: &str,
    profile_id: &str,
    secret: &SecretRecord,
    version: u32,
) -> Result<zeroize::Zeroizing<String>, CliError> {
    let profile_secret_key =
        load_profile_key(context, store, project_id, profile_id, KeyPurpose::ProfileSecret)?;
    let blob = store
        .get_blob(&secret.id, version)?
        .ok_or_else(|| corrupt_db_error("secret blob is missing"))?;
    let value_aad = secret_blob_aad_v1(&locket_crypto::SecretBlobAad::new(
        project_id,
        profile_id,
        &secret.id,
        &secret.name,
        version,
    ))?;
    let wrap_aad = key_wrap_aad_v1(&KeyWrapAad::new(
        project_id,
        &secret.id,
        Some(profile_id),
        version,
        KeyWrapPurpose::SecretDek,
    ))?;
    let encrypted = EncryptedSecretValue {
        encrypted_dek: blob.encrypted_dek,
        ciphertext: blob.ciphertext,
        value_nonce: blob.value_nonce,
        aad_schema_version: blob.aad_schema_version,
    };
    Ok(decrypt_secret_value_v1(&profile_secret_key, &encrypted, &value_aad, &wrap_aad)?)
}

pub fn decrypt_current_secret(
    context: &RuntimeContext,
    resolved: &ResolvedSecret,
) -> Result<zeroize::Zeroizing<String>, CliError> {
    let store = open_store(context)?;
    decrypt_secret_version(
        context,
        &store,
        resolved.project.config.project_id.as_str(),
        &resolved.profile.id,
        &resolved.secret,
        resolved.secret.current_version,
    )
}

pub fn resolve_active_secret(
    context: &RuntimeContext,
    key: &str,
) -> Result<ResolvedSecret, CliError> {
    let name = SecretName::new(key.to_owned())
        .map_err(|_| invalid_secret_name_error("invalid secret name"))?;
    let project = require_project(context)?;
    let store = open_store(context)?;
    ensure_trusted_project_root(&store, &project)?;
    let profile = default_profile(&store, &project.config)?;
    let secrets =
        store.list_active_secrets_by_profile(project.config.project_id.as_str(), &profile.id)?;
    let secret = secrets
        .into_iter()
        .filter(|secret| secret.name == name.as_str())
        .max_by_key(|secret| source_precedence(&secret.source))
        .ok_or_else(|| secret_not_found_error("secret not found"))?;
    Ok(ResolvedSecret { project, profile, secret })
}

pub fn resolve_active_secret_for_source(
    context: &RuntimeContext,
    key: &str,
    source: Option<SecretSourceArg>,
) -> Result<ResolvedSecret, CliError> {
    let resolved = resolve_secret_for_source(context, key, source)?;
    if resolved.secret.state == "deleted" {
        return Err(secret_deleted_error("secret source is deleted"));
    }
    Ok(resolved)
}

pub fn resolve_secret_for_source(
    context: &RuntimeContext,
    key: &str,
    source: Option<SecretSourceArg>,
) -> Result<ResolvedSecret, CliError> {
    let name = SecretName::new(key.to_owned())
        .map_err(|_| invalid_secret_name_error("invalid secret name"))?;
    let project = require_project(context)?;
    let store = open_store(context)?;
    ensure_trusted_project_root(&store, &project)?;
    let profile = default_profile(&store, &project.config)?;
    let secret = if let Some(source) = source {
        let source = source_arg_to_str(source);
        store
            .get_secret_by_source(
                project.config.project_id.as_str(),
                &profile.id,
                name.as_str(),
                source,
            )?
            .ok_or_else(|| secret_not_found_error("secret not found"))?
    } else {
        let secrets = store.list_secrets_by_name(
            project.config.project_id.as_str(),
            &profile.id,
            name.as_str(),
        )?;
        match secrets.as_slice() {
            [] => return Err(secret_not_found_error("secret not found")),
            [secret] => secret.clone(),
            _ => {
                return Err(invalid_reference_error(
                    "multiple sources exist for this secret; pass --source",
                ));
            }
        }
    };
    Ok(ResolvedSecret { project, profile, secret })
}

pub fn select_copy_source_secret(
    store: &Store,
    project_id: &str,
    profile_id: &str,
    name: &str,
    source: Option<SecretSourceArg>,
) -> Result<SecretRecord, CliError> {
    if let Some(source) = source {
        let source = source_arg_to_str(source);
        let secret = store
            .get_secret_by_source(project_id, profile_id, name, source)?
            .ok_or_else(|| secret_not_found_error("secret not found"))?;
        if secret.state == "deleted" {
            return Err(secret_deleted_error("secret source is deleted"));
        }
        return Ok(secret);
    }

    let active = store
        .list_secrets_by_name(project_id, profile_id, name)?
        .into_iter()
        .filter(|secret| secret.state == "active")
        .collect::<Vec<_>>();
    let highest = active
        .iter()
        .map(|secret| source_precedence(&secret.source))
        .max()
        .ok_or_else(|| secret_not_found_error("secret not found"))?;
    let selected = active
        .iter()
        .filter(|secret| source_precedence(&secret.source) == highest)
        .collect::<Vec<_>>();
    match selected.as_slice() {
        [secret] => Ok((*secret).clone()),
        _ => Err(invalid_reference_error(
            "multiple source candidates have ambiguous precedence; pass --from-source",
        )),
    }
}

pub fn select_copy_target_source(
    store: &Store,
    project_id: &str,
    profile_id: &str,
    name: &str,
    from_source: &str,
    to_source: Option<SecretSourceArg>,
) -> Result<String, CliError> {
    if let Some(to_source) = to_source {
        return Ok(source_arg_to_str(to_source).to_owned());
    }
    if store.get_secret_by_source(project_id, profile_id, name, from_source)?.is_some() {
        return Ok(from_source.to_owned());
    }
    Ok(source_arg_to_str(SecretSourceArg::UserLocal).to_owned())
}

pub fn select_copy_profiles_and_sources(
    store: &Store,
    project_id: &str,
    name: &str,
    args: &CopyArgs,
) -> Result<CopySelection, CliError> {
    let from_profile_name = ProfileName::new(args.from.clone())
        .map_err(|_| invalid_profile_name_error("invalid source profile name"))?;
    let to_profile_name = ProfileName::new(args.to.clone())
        .map_err(|_| invalid_profile_name_error("invalid target profile name"))?;
    let from_profile = store
        .get_profile_by_name(project_id, from_profile_name.as_str())?
        .ok_or_else(|| profile_not_found_error("source profile not found"))?;
    let to_profile = store
        .get_profile_by_name(project_id, to_profile_name.as_str())?
        .ok_or_else(|| profile_not_found_error("target profile not found"))?;
    let source_secret =
        select_copy_source_secret(store, project_id, &from_profile.id, name, args.from_source)?;
    let from_source = source_secret.source.clone();
    let to_source = select_copy_target_source(
        store,
        project_id,
        &to_profile.id,
        name,
        &from_source,
        args.to_source,
    )?;
    if from_profile.id == to_profile.id && from_source == to_source {
        return Err(invalid_reference_error(
            "copy source and target are the same profile and source; use rotate",
        ));
    }
    Ok(CopySelection { from_profile, to_profile, source_secret, from_source, to_source })
}

pub fn secret_audit_metadata(
    action: &str,
    secret_name: &str,
    profile_id: &str,
    source: &str,
    version: Option<u32>,
) -> Value {
    json!({
        "schema_version": 1,
        "action": action,
        "status": "SUCCESS",
        "secret_name": secret_name,
        "profile_id": profile_id,
        "source": source,
        "version": version,
    })
}

pub fn write_value_access_audit_if_available(
    request: &ValueAccessAudit<'_>,
) -> Result<(), CliError> {
    let mut store = open_store(request.context)?;
    let project_id = request.resolved.project.config.project_id.as_str();
    if store.get_project(project_id)?.is_none() {
        return Ok(());
    }
    let audit_key = load_project_key(request.context, &store, project_id, KeyPurpose::Audit)?;
    let metadata = json!({
        "schema_version": 1,
        "action": request.action,
        "status": request.status,
        "command": "get",
        "secret_name": &request.resolved.secret.name,
        "profile": &request.resolved.profile.name,
        "profile_id": &request.resolved.profile.id,
        "source": &request.resolved.secret.source,
        "version": request.resolved.secret.current_version,
        "access_mode": request.access_mode,
        "ttl_seconds": request.ttl_seconds,
        "force": request.force,
        "clipboard_supported": request.clipboard_supported,
        "clipboard_clear_supported": request.clipboard_clear_supported,
        "unsupported_reason": request.unsupported_reason,
        "denial_reason": request.denial_reason,
        "user_verification": &request.user_verification,
    });
    let audit = AuditWrite {
        project_id,
        profile_id: Some(&request.resolved.profile.id),
        action: request.action,
        status: request.status,
        secret_name: Some(&request.resolved.secret.name),
        command: Some("get"),
        metadata_json: &metadata,
        timestamp: now_unix_nanos()?,
    };
    store.append_audit(audit_key.as_ref(), &audit)?;
    Ok(())
}

pub fn reveal_ttl_seconds(context: &RuntimeContext) -> Result<u64, CliError> {
    let config = read_user_config(context)?;
    let Some(value) = config_get_value(&config, "reveal.ttl") else {
        return Ok(60);
    };
    let Some(value) = value.as_str() else {
        return Err(metadata_invalid_error("reveal.ttl must be a duration"));
    };
    let duration = LocketDuration::from_str(value)
        .map_err(|_| metadata_invalid_error("invalid reveal.ttl duration"))?;
    Ok(duration.as_secs().min(300))
}

/// Maximum number of names kept verbatim before the list is truncated to stay
/// safely under the 64 KiB metadata-JSON per-row cap.
const SECRET_NAMES_INLINE_LIMIT: usize = 200;

/// Returns names as a `Vec<String>` suitable for embedding in audit metadata.
/// When the list exceeds `SECRET_NAMES_INLINE_LIMIT`, only the first N names
/// are kept and a trailing `"... M more"` sentinel is appended.
pub fn summarize_names<S: AsRef<str>>(names: &[S]) -> Vec<String> {
    if names.len() <= SECRET_NAMES_INLINE_LIMIT {
        return names.iter().map(|s| s.as_ref().to_owned()).collect();
    }
    let mut out: Vec<String> =
        names[..SECRET_NAMES_INLINE_LIMIT].iter().map(|s| s.as_ref().to_owned()).collect();
    out.push(format!("... {} more", names.len() - SECRET_NAMES_INLINE_LIMIT));
    out
}

pub fn policy_secret_selections(
    store: &Store,
    resolved: &ResolvedProject,
    profile: &ProfileRecord,
    policy: &CommandPolicy,
) -> Result<Vec<PolicySecretSelection>, CliError> {
    let active_by_name =
        active_secrets_by_name(store, resolved.config.project_id.as_str(), &profile.id)?;
    let mut selections = Vec::new();
    for name in &policy.required_secrets {
        selections.push(policy_secret_selection(name.as_str(), true, &active_by_name));
    }
    for name in &policy.optional_secrets {
        selections.push(policy_secret_selection(name.as_str(), false, &active_by_name));
    }
    Ok(selections)
}

pub fn policy_secret_selection(
    name: &str,
    required: bool,
    active_by_name: &BTreeMap<String, Vec<SecretRecord>>,
) -> PolicySecretSelection {
    let secrets = active_by_name.get(name).cloned().unwrap_or_default();
    let sources = secrets
        .iter()
        .map(|secret| secret.source.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let selected = secrets.into_iter().max_by_key(|secret| source_precedence(&secret.source));
    PolicySecretSelection { name: name.to_owned(), required, sources, selected }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::{SECRET_NAMES_INLINE_LIMIT, summarize_names};

    #[test]
    fn summarize_names_passes_through_small_list() {
        let names = vec!["SECRET_A", "SECRET_B", "SECRET_C"];
        let result = summarize_names(&names);
        assert_eq!(result, vec!["SECRET_A", "SECRET_B", "SECRET_C"]);
    }

    #[test]
    fn summarize_names_passes_through_list_at_limit() {
        let names: Vec<String> =
            (0..SECRET_NAMES_INLINE_LIMIT).map(|i| format!("SECRET_{i}")).collect();
        let result = summarize_names(&names);
        assert_eq!(result.len(), SECRET_NAMES_INLINE_LIMIT);
        assert!(!result.last().unwrap().starts_with("..."));
    }

    #[test]
    fn summarize_names_truncates_list_above_limit() {
        let count = SECRET_NAMES_INLINE_LIMIT + 50;
        let names: Vec<String> = (0..count).map(|i| format!("SECRET_{i}")).collect();
        let result = summarize_names(&names);
        assert_eq!(result.len(), SECRET_NAMES_INLINE_LIMIT + 1);
        assert_eq!(result.last().unwrap(), "... 50 more");
    }
}
