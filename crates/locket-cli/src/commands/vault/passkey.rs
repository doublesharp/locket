//! Passkey command implementations.

use std::io::Write;

use locket_crypto::KeyPurpose;
use locket_store::{AuditWrite, PasskeyCredentialRecord, Store};
use serde_json::json;

use crate::{
    CliError, PasskeyCommand, PasskeyListArgs, ResolvedProject, RuntimeContext,
    confirmation_failed_error, ensure_project_exists, format_hex, format_unix_nanos,
    invalid_reference_error, load_project_key, metadata_invalid_error, now_unix_nanos, open_store,
    require_project, unimplemented_in_build_error, yes_no,
};

pub fn passkey_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    command: PasskeyCommand,
) -> Result<(), CliError> {
    match command {
        PasskeyCommand::Register => Err(unimplemented_in_build_error(
            "passkey registration is not available in this build; no credential metadata was written",
        )),
        PasskeyCommand::List(args) => passkey_list_command(context, output, &args),
        PasskeyCommand::Remove { passkey } => passkey_remove_command(context, output, &passkey),
    }
}

fn passkey_list_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &PasskeyListArgs,
) -> Result<(), CliError> {
    let resolved = require_project(context)?;
    let store = open_store(context)?;
    let project_id = resolved.config.project_id.as_str();
    ensure_project_exists(&store, project_id)?;
    let credentials = store.list_passkey_credentials(project_id, args.all)?;
    if credentials.is_empty() {
        writeln!(output, "credentials: none")?;
    } else {
        writeln!(output, "credentials:")?;
        for credential in credentials {
            writeln!(
                output,
                "- {} id={} credential_id_prefix={} transports={} prf={} backup_eligible={} backup_state={} created_at={} last_used_at={} revoked_at={}",
                credential.label,
                credential.id,
                credential_id_prefix(&credential.credential_id),
                render_passkey_transports(&credential.transports),
                yes_no(credential.prf_capable),
                render_optional_bool(credential.backup_eligible),
                render_optional_bool(credential.backup_state),
                format_unix_nanos(credential.created_at),
                credential.last_used_at.map_or_else(|| "never".to_owned(), format_unix_nanos),
                credential.revoked_at.map_or_else(|| "active".to_owned(), format_unix_nanos),
            )?;
        }
    }
    writeln!(output, "include_revoked: {}", if args.all { "yes" } else { "no" })?;
    writeln!(output, "private_key_material: never displayed")?;
    Ok(())
}

fn passkey_remove_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    passkey: &str,
) -> Result<(), CliError> {
    let selector = passkey.trim();
    if selector.is_empty() {
        return Err(invalid_reference_error("passkey identifier cannot be empty"));
    }
    let resolved = require_project(context)?;
    let mut store = open_store(context)?;
    let project_id = resolved.config.project_id.as_str();
    ensure_project_exists(&store, project_id)?;
    let matches = store.find_passkey_credentials(project_id, selector)?;
    let active_matches = matches
        .into_iter()
        .filter(|credential| credential.revoked_at.is_none())
        .collect::<Vec<_>>();
    let credential = match active_matches.as_slice() {
        [] => return Err(invalid_reference_error("passkey credential not found")),
        [credential] => credential.clone(),
        _ => {
            return Err(metadata_invalid_error(
                "passkey identifier is ambiguous; use a longer credential id prefix",
            ));
        }
    };
    writeln!(output, "passkey: revoke")?;
    writeln!(output, "label: {}", credential.label)?;
    writeln!(output, "credential_id_prefix: {}", credential_id_prefix(&credential.credential_id))?;
    writeln!(output, "transports: {}", render_passkey_transports(&credential.transports))?;
    writeln!(output, "prf: {}", yes_no(credential.prf_capable))?;
    let confirmation = context.confirmation_reader.read_confirmation("passkey remove")?;
    if confirmation.trim_end() != selector {
        return Err(confirmation_failed_error("confirmation did not match passkey identifier"));
    }
    let timestamp = now_unix_nanos()?;
    store.revoke_passkey_credential(project_id, &credential.id, timestamp)?;
    write_passkey_remove_audit_if_available(
        context,
        &mut store,
        &resolved,
        &credential,
        timestamp,
    )?;
    writeln!(output, "passkey: revoked")?;
    writeln!(output, "passkey_id: {}", credential.id)?;
    writeln!(output, "revoked_at: {}", format_unix_nanos(timestamp))?;
    writeln!(output, "metadata_only: yes")?;
    Ok(())
}

fn credential_id_prefix(credential_id: &[u8]) -> String {
    format_hex(credential_id).chars().take(12).collect()
}

fn render_passkey_transports(transports: &[String]) -> String {
    if transports.is_empty() { "-".to_owned() } else { transports.join(",") }
}

fn render_optional_bool(value: Option<bool>) -> &'static str {
    value.map_or("unknown", yes_no)
}

fn write_passkey_remove_audit_if_available(
    context: &RuntimeContext,
    store: &mut Store,
    resolved: &ResolvedProject,
    credential: &PasskeyCredentialRecord,
    timestamp: i64,
) -> Result<(), CliError> {
    let audit_key =
        load_project_key(context, store, resolved.config.project_id.as_str(), KeyPurpose::Audit)?;
    let metadata = json!({
        "schema_version": 1,
        "action": "PASSKEY_REMOVE",
        "status": "SUCCESS",
        "command": "passkey remove",
        "passkey_id": credential.id,
        "label": credential.label,
        "credential_id_prefix": credential_id_prefix(&credential.credential_id),
        "transports": credential.transports,
        "prf_capable": credential.prf_capable,
        "backup_eligible": credential.backup_eligible,
        "backup_state": credential.backup_state,
    });
    let audit = AuditWrite {
        project_id: resolved.config.project_id.as_str(),
        profile_id: None,
        action: "PASSKEY_REMOVE",
        status: "SUCCESS",
        secret_name: None,
        command: Some("passkey remove"),
        metadata_json: &metadata,
        timestamp,
    };
    store.append_audit(audit_key.as_ref(), &audit)?;
    Ok(())
}
