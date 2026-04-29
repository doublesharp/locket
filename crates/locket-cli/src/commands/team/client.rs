//! Automation client command implementations.

use std::collections::BTreeSet;
use std::io::Write;

use ed25519_dalek::SigningKey;
use locket_core::ClientId;
use locket_crypto::{KeyPurpose, generate_key};
use locket_store::{AuditWrite, AutomationClientRecord, Store};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::{
    CliError, ClientAddArgs, ClientCommand, ClientCreateArgs, ResolvedProject, RuntimeContext,
    ensure_project_exists, ensure_trusted_project_root, format_hex, format_unix_nanos,
    hex_nibble_with_message, load_command_policy, load_project_key, now_unix_nanos, open_store,
    require_project,
};

pub fn client_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    command: ClientCommand,
) -> Result<(), CliError> {
    match command {
        ClientCommand::Create(args) => client_create_command(context, output, &args),
        ClientCommand::Add(args) => client_add_command(context, output, &args),
        ClientCommand::List(args) => client_list_command(context, output, args.all),
        ClientCommand::Revoke { client } => client_revoke_command(context, output, &client),
    }
}

fn client_create_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &ClientCreateArgs,
) -> Result<(), CliError> {
    let seed = generate_key()?;
    let signing_key = SigningKey::from_bytes(&seed);
    let public_key = signing_key.verifying_key().to_bytes();
    register_client_metadata(
        context,
        output,
        ClientRegistrationRequest {
            name: &args.name,
            public_key: &public_key,
            storage: args.storage.as_str(),
            actions: &args.actions,
            policies: &args.policies,
            created_by_locket: true,
        },
    )
}

fn client_add_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &ClientAddArgs,
) -> Result<(), CliError> {
    let public_key = parse_client_public_key(&args.pubkey)?;
    register_client_metadata(
        context,
        output,
        ClientRegistrationRequest {
            name: &args.name,
            public_key: &public_key,
            storage: "external",
            actions: &args.actions,
            policies: &args.policies,
            created_by_locket: false,
        },
    )
}

#[derive(Clone, Copy)]
struct ClientRegistrationRequest<'a> {
    name: &'a str,
    public_key: &'a [u8; 32],
    storage: &'a str,
    actions: &'a [String],
    policies: &'a [String],
    created_by_locket: bool,
}

fn register_client_metadata(
    context: &RuntimeContext,
    output: &mut impl Write,
    request: ClientRegistrationRequest<'_>,
) -> Result<(), CliError> {
    let resolved = require_project(context)?;
    let mut store = open_store(context)?;
    ensure_project_exists(&store, resolved.config.project_id.as_str())?;
    ensure_trusted_project_root(&store, &resolved)?;
    let name = validate_client_name(request.name)?;
    let actions = validate_client_actions(request.actions)?;
    let policies = validate_client_policies(&resolved, request.policies)?;
    let timestamp = now_unix_nanos()?;
    let id = ClientId::generate().map_err(|error| CliError::Config(error.to_string()))?;
    let fingerprint = client_public_key_fingerprint(request.public_key);
    let client = AutomationClientRecord {
        id: id.as_str().to_owned(),
        project_id: resolved.config.project_id.to_string(),
        name: name.to_owned(),
        public_key: request.public_key.to_vec(),
        fingerprint: fingerprint.clone(),
        storage: request.storage.to_owned(),
        allowed_actions: actions.clone(),
        allowed_policies: policies.clone(),
        created_at: timestamp,
        last_used_at: None,
        revoked_at: None,
    };
    store.insert_automation_client(&client)?;
    let metadata = json!({
        "schema_version": 1,
        "action": "CLIENT_ADD",
        "status": "SUCCESS",
        "project_id": resolved.config.project_id.as_str(),
        "client_id": &client.id,
        "client_name": &client.name,
        "public_key_fingerprint": &fingerprint,
        "storage": request.storage,
        "allowed_actions": &actions,
        "allowed_policies": &policies,
        "created_by_locket": request.created_by_locket,
    });
    write_client_audit_if_available(
        context,
        &mut store,
        &resolved,
        "CLIENT_ADD",
        &metadata,
        timestamp,
    )?;

    writeln!(output, "client: {}", client.name)?;
    writeln!(output, "client_id: {}", client.id)?;
    writeln!(output, "fingerprint: {}", client.fingerprint)?;
    writeln!(output, "storage: {}", client.storage)?;
    writeln!(output, "allowed_actions: {}", client.allowed_actions.join(","))?;
    writeln!(output, "allowed_policies: {}", client.allowed_policies.join(","))?;
    writeln!(output, "private_key_material: never displayed")?;
    if request.created_by_locket {
        writeln!(output, "private_key_storage: not implemented in this metadata foundation")?;
    }
    Ok(())
}

fn client_list_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    include_revoked: bool,
) -> Result<(), CliError> {
    let resolved = require_project(context)?;
    let store = open_store(context)?;
    ensure_project_exists(&store, resolved.config.project_id.as_str())?;
    let clients =
        store.list_automation_clients(resolved.config.project_id.as_str(), include_revoked)?;
    if clients.is_empty() {
        writeln!(output, "clients: none")?;
        writeln!(output, "include_revoked: {}", if include_revoked { "yes" } else { "no" })?;
        writeln!(output, "private_key_material: never displayed")?;
        return Ok(());
    }
    for client in clients {
        writeln!(
            output,
            "{} {} fingerprint={} actions={} policies={} created_at={} last_used_at={} revoked_at={}",
            client.id,
            client.name,
            truncated_fingerprint(&client.fingerprint),
            client.allowed_actions.join(","),
            client.allowed_policies.join(","),
            format_unix_nanos(client.created_at),
            client.last_used_at.map_or_else(|| "never".to_owned(), format_unix_nanos),
            client.revoked_at.map_or_else(|| "active".to_owned(), format_unix_nanos),
        )?;
    }
    writeln!(output, "private_key_material: never displayed")?;
    Ok(())
}

fn client_revoke_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    client_ref: &str,
) -> Result<(), CliError> {
    if client_ref.trim().is_empty() {
        return Err(CliError::Config("client identifier cannot be empty".to_owned()));
    }
    let resolved = require_project(context)?;
    let mut store = open_store(context)?;
    ensure_project_exists(&store, resolved.config.project_id.as_str())?;
    ensure_trusted_project_root(&store, &resolved)?;
    let Some(client) =
        store.get_automation_client(resolved.config.project_id.as_str(), client_ref)?
    else {
        return Err(CliError::Config(format!("automation client not found: {client_ref}")));
    };
    if client.revoked_at.is_some() {
        writeln!(output, "client: {}", client.name)?;
        writeln!(output, "client_id: {}", client.id)?;
        writeln!(output, "status: already revoked")?;
        return Ok(());
    }
    let timestamp = now_unix_nanos()?;
    store.revoke_automation_client(resolved.config.project_id.as_str(), &client.id, timestamp)?;
    let metadata = json!({
        "schema_version": 1,
        "action": "CLIENT_REVOKE",
        "status": "SUCCESS",
        "project_id": resolved.config.project_id.as_str(),
        "client_id": &client.id,
        "client_name": &client.name,
        "public_key_fingerprint": &client.fingerprint,
        "storage": &client.storage,
        "allowed_actions": &client.allowed_actions,
        "allowed_policies": &client.allowed_policies,
        "revoked_at": timestamp,
    });
    write_client_audit_if_available(
        context,
        &mut store,
        &resolved,
        "CLIENT_REVOKE",
        &metadata,
        timestamp,
    )?;
    writeln!(output, "client: {}", client.name)?;
    writeln!(output, "client_id: {}", client.id)?;
    writeln!(output, "revoked_at: {}", format_unix_nanos(timestamp))?;
    writeln!(output, "private_key_material: never displayed")?;
    Ok(())
}

fn parse_client_public_key(value: &str) -> Result<[u8; 32], CliError> {
    let value = value.strip_prefix("0x").unwrap_or(value);
    if value.len() != 64 {
        return Err(CliError::Config("public key must be 64 hex characters".to_owned()));
    }
    let mut output = [0_u8; 32];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_nibble_with_message(chunk[0], "public key must be hex encoded")?;
        let low = hex_nibble_with_message(chunk[1], "public key must be hex encoded")?;
        output[index] = (high << 4) | low;
    }
    Ok(output)
}

fn client_public_key_fingerprint(public_key: &[u8; 32]) -> String {
    let digest = Sha256::digest(public_key);
    format_hex(&digest[..16])
}

fn truncated_fingerprint(fingerprint: &str) -> &str {
    fingerprint.get(..16).unwrap_or(fingerprint)
}

fn validate_client_name(name: &str) -> Result<&str, CliError> {
    let name = name.trim();
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return Err(CliError::Config("client name cannot be empty".to_owned()));
    };
    if !first.is_ascii_lowercase()
        || !chars.all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-' || ch == '_')
        || name.len() > 64
    {
        return Err(CliError::Config("client name must match ^[a-z][a-z0-9_-]{0,63}$".to_owned()));
    }
    Ok(name)
}

fn validate_client_actions(actions: &[String]) -> Result<Vec<String>, CliError> {
    if actions.is_empty() {
        return Err(CliError::Config(
            "InvalidPolicy: at least one --action is required".to_owned(),
        ));
    }
    let mut normalized = BTreeSet::new();
    for action in actions {
        match action.as_str() {
            "run-policy" | "resolve-reference" | "scan-known-values" | "redact" => {
                normalized.insert(action.clone());
            }
            unsupported => {
                return Err(CliError::Config(format!(
                    "InvalidPolicy: unsupported automation-client action: {unsupported}"
                )));
            }
        }
    }
    Ok(normalized.into_iter().collect())
}

fn validate_client_policies(
    resolved: &ResolvedProject,
    policies: &[String],
) -> Result<Vec<String>, CliError> {
    if policies.is_empty() {
        return Err(CliError::Config(
            "InvalidPolicy: at least one --policy is required".to_owned(),
        ));
    }
    let mut normalized = BTreeSet::new();
    for policy in policies {
        if policy == "*" || policy.trim().is_empty() {
            return Err(CliError::Config(
                "InvalidPolicy: wildcard or empty client policies are not supported".to_owned(),
            ));
        }
        load_command_policy(resolved, policy)?;
        normalized.insert(policy.clone());
    }
    Ok(normalized.into_iter().collect())
}

fn write_client_audit_if_available(
    context: &RuntimeContext,
    store: &mut Store,
    resolved: &ResolvedProject,
    action: &'static str,
    metadata: &Value,
    timestamp: i64,
) -> Result<(), CliError> {
    let audit_key =
        load_project_key(context, store, resolved.config.project_id.as_str(), KeyPurpose::Audit)?;
    let audit = AuditWrite {
        project_id: resolved.config.project_id.as_str(),
        profile_id: None,
        action,
        status: "SUCCESS",
        secret_name: None,
        command: Some("client"),
        metadata_json: metadata,
        timestamp,
    };
    store.append_audit(audit_key.as_ref(), &audit)?;
    Ok(())
}
