//! Helpers that maintain `.env.example`, `.gitignore`, and audit metadata
//! emitted when those files are refreshed.

use std::collections::BTreeSet;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use locket_crypto::KeyPurpose;
use locket_store::{AuditWrite, Store};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::commands::config::spec::{read_user_config, split_config_key};
use crate::{
    CliError, LOCKET_TOML, ResolvedProject, RuntimeContext, confirmation_failed_error, format_hex,
    load_project_key, metadata_invalid_error, now_unix_nanos, open_store, require_project,
    tty_required_error,
};

pub const EXAMPLE_FILE: &str = ".env.example";
pub const GITIGNORE_FILE: &str = ".gitignore";
pub const EXAMPLE_BEGIN: &str = "# --- BEGIN LOCKET MANAGED ---";
pub const EXAMPLE_END: &str = "# --- END LOCKET MANAGED ---";
pub const GITIGNORE_ENTRIES: [&str; 4] = [".env", ".env.*", ".locket.local", ".locketignore"];

#[derive(Debug)]
pub struct ExampleWriteResult {
    pub path: PathBuf,
    pub secret_name_count: usize,
    pub replaced_unmanaged: bool,
}

#[derive(Clone, Copy)]
pub enum UnmanagedExamplePolicy {
    Refuse,
    Confirm,
}

pub fn write_example_emit_audit(
    context: &RuntimeContext,
    store: &mut Store,
    resolved: &ResolvedProject,
    result: &ExampleWriteResult,
) -> Result<(), CliError> {
    if store.get_project(resolved.config.project_id.as_str())?.is_none() {
        return Ok(());
    }
    let audit_key =
        load_project_key(context, store, resolved.config.project_id.as_str(), KeyPurpose::Audit)?;
    let path_hash = Sha256::digest(EXAMPLE_FILE.as_bytes());
    let metadata = json!({
        "schema_version": 1,
        "action": "EXAMPLE_EMIT",
        "status": "SUCCESS",
        "command": "emit-example",
        "path_kind": "project_env_example",
        "path_hash": format_hex(&path_hash),
        "example_path_kind": "project_env_example",
        "example_path_hash": format_hex(&path_hash),
        "secret_name_count": result.secret_name_count,
        "marker_only": !result.replaced_unmanaged,
        "replaced_unmanaged": result.replaced_unmanaged,
    });
    let audit = AuditWrite {
        project_id: resolved.config.project_id.as_str(),
        profile_id: None,
        action: "EXAMPLE_EMIT",
        status: "SUCCESS",
        secret_name: None,
        command: Some("emit-example"),
        metadata_json: &metadata,
        timestamp: now_unix_nanos()?,
    };
    store.append_audit(audit_key.as_ref(), &audit)?;
    Ok(())
}

pub fn ensure_gitignore(root: &Path) -> Result<(), CliError> {
    let path = root.join(GITIGNORE_FILE);
    let existing = match fs::read_to_string(&path) {
        Ok(content) => content,
        Err(error) if error.kind() == io::ErrorKind::NotFound => String::new(),
        Err(error) => return Err(error.into()),
    };

    let mut content = existing.clone();
    for entry in GITIGNORE_ENTRIES {
        if !existing.lines().any(|line| line.trim() == entry) {
            if !content.is_empty() && !content.ends_with('\n') {
                content.push('\n');
            }
            content.push_str(entry);
            content.push('\n');
        }
    }

    if content != existing {
        fs::write(path, content)?;
    }
    Ok(())
}

pub fn ensure_example_file(root: &Path) -> Result<(), CliError> {
    let path = root.join(EXAMPLE_FILE);
    let names = BTreeSet::new();
    let managed_block = managed_example_block(&names);
    let existing = match fs::read_to_string(&path) {
        Ok(content) => content,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::write(path, managed_block)?;
            return Ok(());
        }
        Err(error) => return Err(error.into()),
    };

    let Some(begin) = existing.find(EXAMPLE_BEGIN) else {
        return Err(metadata_invalid_error(
            ".env.example exists without Locket managed markers; refusing silent overwrite",
        ));
    };
    let Some(relative_end) = existing[begin..].find(EXAMPLE_END) else {
        return Err(metadata_invalid_error(
            ".env.example has an unterminated Locket managed block",
        ));
    };
    let end = begin + relative_end + EXAMPLE_END.len();
    let mut updated = String::new();
    updated.push_str(&existing[..begin]);
    updated.push_str(&managed_block);
    updated.push_str(&existing[end..]);

    if updated != existing {
        fs::write(path, updated)?;
    }
    Ok(())
}

pub fn refresh_example_for_project_if_enabled(context: &RuntimeContext) -> Result<(), CliError> {
    let resolved = require_project(context)?;
    if !example_auto_refresh_enabled(context, &resolved)? {
        return Ok(());
    }
    refresh_example_for_resolved(context, &resolved)?;
    Ok(())
}

fn example_auto_refresh_enabled(
    context: &RuntimeContext,
    resolved: &ResolvedProject,
) -> Result<bool, CliError> {
    let project_config = read_config_table(&resolved.root.join(LOCKET_TOML))?;
    if let Some(value) = config_bool_value(&project_config, "example.auto_refresh")? {
        return Ok(value);
    }
    let user_config = read_user_config(context)?;
    Ok(config_bool_value(&user_config, "example.auto_refresh")?.unwrap_or(true))
}

fn read_config_table(path: &Path) -> Result<toml::Table, CliError> {
    let text = fs::read_to_string(path)?;
    toml::from_str::<toml::Table>(&text).map_err(CliError::from)
}

pub fn config_bool_value(config: &toml::Table, key: &str) -> Result<Option<bool>, CliError> {
    let Some((section, name)) = split_config_key(key) else {
        return Err(metadata_invalid_error("unsupported config key"));
    };
    let Some(section_value) = config.get(section) else {
        return Ok(None);
    };
    let Some(section_table) = section_value.as_table() else {
        return Err(metadata_invalid_error(format!("config section {section:?} must be a table")));
    };
    let Some(value) = section_table.get(name) else {
        return Ok(None);
    };
    value
        .as_bool()
        .map(Some)
        .ok_or_else(|| metadata_invalid_error(format!("config key {key:?} must be boolean")))
}

fn refresh_example_for_resolved(
    context: &RuntimeContext,
    resolved: &ResolvedProject,
) -> Result<ExampleWriteResult, CliError> {
    let store = open_store(context)?;
    let names = collect_example_secret_names(&store, resolved)?;
    write_example_block(&resolved.root, &names)
}

pub fn collect_example_secret_names(
    store: &Store,
    resolved: &ResolvedProject,
) -> Result<BTreeSet<String>, CliError> {
    let mut names = BTreeSet::new();
    for profile in store.list_profiles(resolved.config.project_id.as_str())? {
        for secret in store
            .list_active_secrets_by_profile(resolved.config.project_id.as_str(), &profile.id)?
        {
            names.insert(secret.name);
        }
    }
    Ok(names)
}

pub fn write_example_block(
    root: &Path,
    names: &BTreeSet<String>,
) -> Result<ExampleWriteResult, CliError> {
    let path = root.join(EXAMPLE_FILE);
    write_example_block_with_policy(&path, names, UnmanagedExamplePolicy::Refuse, None, None)
}

pub fn write_example_block_for_emit(
    context: &RuntimeContext,
    root: &Path,
    names: &BTreeSet<String>,
    output: &mut impl Write,
) -> Result<ExampleWriteResult, CliError> {
    let path = root.join(EXAMPLE_FILE);
    write_example_block_with_policy(
        &path,
        names,
        UnmanagedExamplePolicy::Confirm,
        Some(context),
        Some(output as &mut dyn Write),
    )
}

fn write_example_block_with_policy(
    path: &Path,
    names: &BTreeSet<String>,
    unmanaged_policy: UnmanagedExamplePolicy,
    runtime_context: Option<&RuntimeContext>,
    output: Option<&mut dyn Write>,
) -> Result<ExampleWriteResult, CliError> {
    let managed_block = managed_example_block(names);
    let existing = match fs::read_to_string(path) {
        Ok(content) => content,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::write(path, managed_block)?;
            return Ok(ExampleWriteResult {
                path: path.to_path_buf(),
                secret_name_count: names.len(),
                replaced_unmanaged: false,
            });
        }
        Err(error) => return Err(error.into()),
    };
    let Some(begin) = existing.find(EXAMPLE_BEGIN) else {
        return replace_unmanaged_example(
            path,
            names,
            &managed_block,
            unmanaged_policy,
            runtime_context,
            output,
        );
    };
    let Some(relative_end) = existing[begin..].find(EXAMPLE_END) else {
        return Err(metadata_invalid_error(
            ".env.example has an unterminated Locket managed block",
        ));
    };
    let end = begin + relative_end + EXAMPLE_END.len();
    let mut updated = String::new();
    updated.push_str(&existing[..begin]);
    updated.push_str(&managed_block);
    updated.push_str(&existing[end..]);
    if updated != existing {
        fs::write(path, updated)?;
    }
    Ok(ExampleWriteResult {
        path: path.to_path_buf(),
        secret_name_count: names.len(),
        replaced_unmanaged: false,
    })
}

fn replace_unmanaged_example(
    path: &Path,
    names: &BTreeSet<String>,
    managed_block: &str,
    unmanaged_policy: UnmanagedExamplePolicy,
    runtime_context: Option<&RuntimeContext>,
    output: Option<&mut dyn Write>,
) -> Result<ExampleWriteResult, CliError> {
    match unmanaged_policy {
        UnmanagedExamplePolicy::Refuse => Err(metadata_invalid_error(
            ".env.example exists without Locket managed markers; refusing automatic overwrite",
        )),
        UnmanagedExamplePolicy::Confirm => {
            let Some(output) = output else {
                return Err(tty_required_error(
                    ".env.example replacement requires interactive confirmation",
                ));
            };
            let Some(runtime_context) = runtime_context else {
                return Err(tty_required_error(
                    ".env.example replacement requires interactive confirmation",
                ));
            };
            writeln!(output, ".env.example: unmanaged")?;
            writeln!(output, "secret_name_count: {}", names.len())?;
            writeln!(output, "metadata_only: yes")?;
            writeln!(output, "type 'replace .env.example' to replace the unmanaged file")?;
            let confirmation =
                runtime_context.confirmation_reader.read_confirmation("replace .env.example")?;
            if confirmation.trim_end() != "replace .env.example" {
                return Err(confirmation_failed_error("confirmation did not match"));
            }
            fs::write(path, managed_block)?;
            Ok(ExampleWriteResult {
                path: path.to_path_buf(),
                secret_name_count: names.len(),
                replaced_unmanaged: true,
            })
        }
    }
}

pub fn managed_example_block(names: &BTreeSet<String>) -> String {
    let mut block = format!("{EXAMPLE_BEGIN}\n");
    for name in names {
        block.push_str(name);
        block.push_str("=\n");
    }
    block.push_str(EXAMPLE_END);
    block.push('\n');
    block
}
