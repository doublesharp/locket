//! Implementation of the `locket import` command and its private helpers.

use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fs;
use std::io::{self, IsTerminal, Write};
use std::path::Path;

use locket_core::{LocketError, ProfileName, SecretName};
use locket_crypto::KeyPurpose;
use locket_store::{
    AuditContext, AuditWrite, ProfileRecord, SecretBlobRecord, SecretFingerprintRecord,
    SecretVersionRecord, Store, VersionDeprecation,
};
use serde_json::json;

use super::set::{SecretWriteRequest, set_secret_value_in_profile};
use crate::runtime::RuntimeContext;
use crate::runtime::error::{
    CliError, confirmation_failed_error, invalid_profile_name_error, invalid_secret_name_error,
    profile_not_found_error, secret_not_found_error, tty_required_error,
};
use crate::runtime::key_access::load_project_key;
use crate::support::project_files::{ensure_gitignore, refresh_example_for_project_if_enabled};
use crate::support::secret_helpers::{SecretEncryptRequest, encrypt_secret_version};
use crate::{
    ImportArgs, ResolvedProject, SecretSourceArg, absolutize, active_profile_secret_names,
    ensure_trusted_project_root, next_secret_version, now_unix_nanos, open_store, require_project,
    secret_deleted_error, source_arg_to_str,
};

pub fn import_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &ImportArgs,
) -> Result<(), CliError> {
    let resolved = require_project(context)?;
    let mut store = open_store(context)?;
    ensure_trusted_project_root(&store, &resolved)?;
    let profile = import_target_profile(&store, &resolved, args.profile.as_deref())?;
    if args.overwrite && profile.dangerous {
        confirm_dangerous_import_overwrite(output, &profile)?;
    }
    let path = absolutize(&context.cwd, Path::new(&args.file));
    let env_file_text = fs::read_to_string(&path)?;
    let source = args.source.unwrap_or(SecretSourceArg::UserLocal);
    let source_name = source_arg_to_str(source);
    let parsed = parse_env_import(&env_file_text);
    let env_names = parsed
        .iter()
        .filter_map(|entry| match entry {
            EnvImportEntry::Secret { key, .. } => Some(key.clone()),
            EnvImportEntry::Invalid => None,
        })
        .collect::<BTreeSet<_>>();
    let mut imported = 0_u32;
    let mut overwritten = 0_u32;
    let mut skipped = 0_u32;
    let mut invalid = 0_u32;
    let mut skipped_names = BTreeSet::new();

    for entry in parsed {
        match entry {
            EnvImportEntry::Secret { key, value } => {
                match set_secret_value_in_profile(
                    context,
                    &mut store,
                    SecretWriteRequest {
                        resolved: &resolved,
                        profile: &profile,
                        key: &key,
                        source: source_name,
                        value: &value,
                        origin: "imported",
                        audit_action: "IMPORT",
                        timestamp: now_unix_nanos()?,
                    },
                ) {
                    Ok(()) => imported += 1,
                    Err(CliError::Typed { kind: LocketError::SecretAlreadyExists, .. })
                        if args.overwrite =>
                    {
                        rotate_import_secret_value_in_profile(
                            context,
                            &mut store,
                            ImportRotateRequest {
                                resolved: &resolved,
                                profile: &profile,
                                key: &key,
                                source: source_name,
                                value: &value,
                                timestamp: now_unix_nanos()?,
                            },
                        )?;
                        overwritten += 1;
                    }
                    Err(CliError::Typed { kind: LocketError::SecretAlreadyExists, .. }) => {
                        skipped += 1;
                        skipped_names.insert(key);
                    }
                    Err(error) => return Err(error),
                }
            }
            EnvImportEntry::Invalid => invalid += 1,
        }
    }

    refresh_example_for_project_if_enabled(context)?;
    ensure_gitignore(&resolved.root)?;
    let profile_names =
        active_profile_secret_names(&store, resolved.config.project_id.as_str(), &profile.id)?;
    let missing_in_profile = env_names.difference(&profile_names).cloned().collect::<BTreeSet<_>>();
    let extra_in_profile = profile_names.difference(&env_names).cloned().collect::<BTreeSet<_>>();
    writeln!(output, "imported: {imported}")?;
    writeln!(output, "overwritten: {overwritten}")?;
    writeln!(output, "skipped: {skipped}")?;
    writeln!(output, "invalid: {invalid}")?;
    writeln!(output, "profile: {}", profile.name)?;
    writeln!(output, "source: {source_name}")?;
    writeln!(output, "env_names: {}", env_names.len())?;
    writeln!(output, "profile_names: {}", profile_names.len())?;
    writeln!(output, "skipped_names: {}", format_name_set(&skipped_names))?;
    writeln!(output, "missing_in_profile: {}", format_name_set(&missing_in_profile))?;
    writeln!(output, "extra_in_profile: {}", format_name_set(&extra_in_profile))?;
    write_env_delete_prompt(output, &path)?;
    writeln!(output, "metadata_only: yes")?;
    Ok(())
}

fn import_target_profile(
    store: &Store,
    resolved: &ResolvedProject,
    profile_name: Option<&str>,
) -> Result<ProfileRecord, CliError> {
    let profile_name = profile_name.unwrap_or(resolved.config.default_profile.as_str());
    let profile_name = ProfileName::new(profile_name.to_owned())
        .map_err(|_| invalid_profile_name_error("invalid profile name"))?;
    store
        .get_profile_by_name(resolved.config.project_id.as_str(), profile_name.as_str())?
        .ok_or_else(|| profile_not_found_error("profile not found"))
}

fn confirm_dangerous_import_overwrite(
    output: &mut impl Write,
    profile: &ProfileRecord,
) -> Result<(), CliError> {
    writeln!(output, "dangerous_profile: {}", profile.name)?;
    writeln!(output, "metadata_only: yes")?;
    if !io::stdin().is_terminal() {
        return Err(tty_required_error(
            "import --overwrite targets a dangerous profile and requires interactive confirmation",
        ));
    }
    writeln!(output, "type '{}' to confirm dangerous import overwrite", profile.name)?;
    let mut confirmation = String::new();
    io::stdin().read_line(&mut confirmation)?;
    if confirmation.trim_end() != profile.name {
        return Err(confirmation_failed_error("confirmation did not match"));
    }
    Ok(())
}

fn format_name_set(names: &BTreeSet<String>) -> String {
    if names.is_empty() {
        "none".to_owned()
    } else {
        names.iter().cloned().collect::<Vec<_>>().join(",")
    }
}

fn write_env_delete_prompt(output: &mut impl Write, path: &Path) -> Result<(), CliError> {
    if path.file_name().and_then(OsStr::to_str) != Some(".env") {
        writeln!(output, "delete_env_prompt: not_applicable")?;
        return Ok(());
    }
    if !io::stdin().is_terminal() {
        writeln!(output, "delete_env_prompt: skipped_noninteractive")?;
        writeln!(output, "delete_env: kept")?;
        return Ok(());
    }
    writeln!(output, "delete_env_prompt: type 'delete .env' to remove the plaintext .env file")?;
    let mut confirmation = String::new();
    io::stdin().read_line(&mut confirmation)?;
    if confirmation.trim_end() == "delete .env" {
        fs::remove_file(path)?;
        writeln!(output, "delete_env: deleted")?;
    } else {
        writeln!(output, "delete_env: kept")?;
    }
    Ok(())
}

pub enum EnvImportEntry {
    Secret { key: String, value: String },
    Invalid,
}

pub fn parse_env_import(content: &str) -> Vec<EnvImportEntry> {
    content
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                return None;
            }
            Some(parse_env_line(trimmed))
        })
        .collect()
}

fn parse_env_line(line: &str) -> EnvImportEntry {
    let line = line.strip_prefix("export ").unwrap_or(line);
    let Some((key, value)) = line.split_once('=') else {
        return EnvImportEntry::Invalid;
    };
    let key = key.trim();
    if SecretName::new(key.to_owned()).is_err() {
        return EnvImportEntry::Invalid;
    }
    let raw_value = value.trim();
    if has_unmatched_env_quote(raw_value) {
        return EnvImportEntry::Invalid;
    }
    let value = unquote_env_value(raw_value);
    if value.contains('\0') {
        return EnvImportEntry::Invalid;
    }
    EnvImportEntry::Secret { key: key.to_owned(), value }
}

const fn has_unmatched_env_quote(value: &str) -> bool {
    let bytes = value.as_bytes();
    matches!(bytes.first(), Some(b'"')) && !matches!(bytes.last(), Some(b'"'))
        || matches!(bytes.first(), Some(b'\'')) && !matches!(bytes.last(), Some(b'\''))
}

fn unquote_env_value(value: &str) -> String {
    if value.len() >= 2 {
        let bytes = value.as_bytes();
        if matches!(
            (bytes.first(), bytes.last()),
            (Some(b'"'), Some(b'"')) | (Some(b'\''), Some(b'\''))
        ) {
            return value[1..value.len() - 1].to_owned();
        }
    }
    value.to_owned()
}

#[derive(Clone, Copy)]
struct ImportRotateRequest<'a> {
    resolved: &'a ResolvedProject,
    profile: &'a ProfileRecord,
    key: &'a str,
    source: &'a str,
    value: &'a str,
    timestamp: i64,
}

fn rotate_import_secret_value_in_profile(
    context: &RuntimeContext,
    store: &mut Store,
    request: ImportRotateRequest<'_>,
) -> Result<u32, CliError> {
    let name = SecretName::new(request.key.to_owned())
        .map_err(|_| invalid_secret_name_error("invalid secret name"))?;
    let secret = store
        .get_secret_by_source(
            request.resolved.config.project_id.as_str(),
            &request.profile.id,
            name.as_str(),
            request.source,
        )?
        .ok_or_else(|| secret_not_found_error("secret does not exist"))?;
    if secret.state == "deleted" {
        return Err(secret_deleted_error("secret source is deleted"));
    }
    let new_version = next_secret_version(secret.current_version)?;
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
            secret_id: &secret.id,
            secret_name: &secret.name,
            version: new_version,
            value: request.value,
        },
    )?;
    let metadata = json!({
        "schema_version": 1,
        "action": "ROTATE",
        "status": "SUCCESS",
        "secret_name": &secret.name,
        "profile_id": &request.profile.id,
        "source": &secret.source,
        "prior_version": secret.current_version,
        "deprecated_version": secret.current_version,
        "target_version": new_version,
        "deprecated_at": request.timestamp,
        "grace_until": null,
    });
    let audit = AuditWrite {
        project_id: request.resolved.config.project_id.as_str(),
        profile_id: Some(&request.profile.id),
        action: "ROTATE",
        status: "SUCCESS",
        secret_name: Some(&secret.name),
        command: None,
        metadata_json: &metadata,
        timestamp: request.timestamp,
    };
    store.rotate_secret_with_audit(
        &secret,
        &SecretVersionRecord {
            secret_id: secret.id.clone(),
            version: new_version,
            source: secret.source.clone(),
            origin: "imported".to_owned(),
            state: "current".to_owned(),
            created_at: request.timestamp,
            deprecated_at: None,
            grace_until: None,
            purged_at: None,
        },
        &SecretBlobRecord {
            secret_id: secret.id.clone(),
            version: new_version,
            encrypted_dek: encrypted.encrypted_dek,
            ciphertext: encrypted.ciphertext,
            value_nonce: encrypted.value_nonce,
            aad_schema_version: encrypted.aad_schema_version,
            created_at: request.timestamp,
        },
        &SecretFingerprintRecord {
            secret_id: secret.id.clone(),
            version: new_version,
            fingerprint,
            created_at: request.timestamp,
        },
        VersionDeprecation { deprecated_at: request.timestamp, grace_until: None },
        Some(AuditContext { key: audit_key.as_ref(), write: &audit }),
    )?;
    Ok(new_version)
}
