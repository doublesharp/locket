//! Shell-integration commands: shellenv, hook, allow, deny.

use std::io::Write;
use std::path::Path;

use locket_crypto::KeyPurpose;
use locket_store::{AuditWrite, DirectoryGrantRecord};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::{
    CliError, DenyArgs, HookArgs, RuntimeContext, ShellArg, ShellenvArgs, default_profile,
    ensure_project_exists, format_hex, load_project_key, now_unix_nanos, open_store,
    project_root_untrusted_error, require_project, root_hash,
};

const DIRECTORY_GRANT_SCOPE_PROJECT_ROOT: &str = "project-root";
pub const SHELL_HOOK_BEGIN: &str = "# --- BEGIN LOCKET SHELL HOOK ---";
pub const SHELL_HOOK_END: &str = "# --- END LOCKET SHELL HOOK ---";

pub fn shellenv_command(output: &mut impl Write, args: &ShellenvArgs) -> Result<(), CliError> {
    let shell = args.shell.unwrap_or_else(detect_shell);
    write_shellenv_snippet(output, shell)
}

pub fn hook_command(output: &mut impl Write, args: &HookArgs) -> Result<(), CliError> {
    let shell = args.shell.unwrap_or_else(detect_shell);
    if args.install {
        writeln!(output, "hook install: no-op")?;
        writeln!(output, "agent: unavailable")?;
        writeln!(
            output,
            "reason: full agent-backed shell grant installation is not available in this build"
        )?;
        writeln!(output, "metadata_only: yes")?;
        return Ok(());
    }

    write_shell_hook_snippet(output, shell)
}

pub fn allow_command(context: &RuntimeContext, output: &mut impl Write) -> Result<(), CliError> {
    let resolved = require_project(context)?;
    let mut store = open_store(context)?;
    ensure_project_exists(&store, resolved.config.project_id.as_str())?;
    let profile = default_profile(&store, &resolved.config)?;
    let root_hash = root_hash(&resolved.root)?;
    if !store.project_root_is_trusted(resolved.config.project_id.as_str(), &root_hash)? {
        return Err(project_root_untrusted_error());
    }

    let timestamp = now_unix_nanos()?;
    let directory_hash = root_hash;
    let display_path = resolved.root.to_string_lossy().to_string();
    let grant = DirectoryGrantRecord {
        grant_id: directory_grant_id(
            resolved.config.project_id.as_str(),
            &profile.id,
            &root_hash,
            &directory_hash,
            DIRECTORY_GRANT_SCOPE_PROJECT_ROOT,
        ),
        project_id: resolved.config.project_id.as_str().to_owned(),
        profile_id: profile.id.clone(),
        root_hash,
        directory_hash,
        grant_scope: DIRECTORY_GRANT_SCOPE_PROJECT_ROOT.to_owned(),
        display_path: Some(display_path),
        created_at: timestamp,
        updated_at: timestamp,
    };

    let prior_grant = store.get_directory_grant(
        resolved.config.project_id.as_str(),
        &profile.id,
        &root_hash,
        &directory_hash,
        DIRECTORY_GRANT_SCOPE_PROJECT_ROOT,
    )?;
    let existed = prior_grant.is_some();
    store.allow_directory_grant(&grant)?;

    let audit_key =
        load_project_key(context, &store, resolved.config.project_id.as_str(), KeyPurpose::Audit)?;
    let metadata = json!({
        "schema_version": 1,
        "action": "ALLOW_DIRECTORY",
        "status": "SUCCESS",
        "grant_id": &grant.grant_id,
        "project_id": resolved.config.project_id.as_str(),
        "profile_id": &profile.id,
        "grant_scope": &grant.grant_scope,
        "root_hash": format_hex(&root_hash),
        "directory_hash": format_hex(&directory_hash),
        "prior_grant": prior_grant.as_ref().map(|prior| json!({
            "grant_id": &prior.grant_id,
            "created_at": prior.created_at,
            "updated_at": prior.updated_at,
        })),
        "result_state": if existed { "replaced" } else { "created" },
    });
    let audit = AuditWrite {
        project_id: resolved.config.project_id.as_str(),
        profile_id: Some(&profile.id),
        action: "ALLOW_DIRECTORY",
        status: "SUCCESS",
        secret_name: None,
        command: Some("allow"),
        metadata_json: &metadata,
        timestamp,
    };
    store.append_audit(audit_key.as_ref(), &audit)?;

    writeln!(
        output,
        "{}",
        if existed { "directory grant already present" } else { "directory grant allowed" }
    )?;
    writeln!(output, "project_id: {}", resolved.config.project_id)?;
    writeln!(output, "profile_id: {}", profile.id)?;
    writeln!(output, "grant_scope: {}", grant.grant_scope)?;
    writeln!(output, "root_hash: {}", format_hex(&root_hash))?;
    writeln!(output, "directory_hash: {}", format_hex(&directory_hash))?;
    writeln!(output, "metadata_only: yes")?;
    writeln!(output, "live_grant: unavailable")?;
    Ok(())
}

pub fn deny_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &DenyArgs,
) -> Result<(), CliError> {
    let resolved = require_project(context)?;
    let mut store = open_store(context)?;
    ensure_project_exists(&store, resolved.config.project_id.as_str())?;
    let timestamp = now_unix_nanos()?;
    let audit_key =
        load_project_key(context, &store, resolved.config.project_id.as_str(), KeyPurpose::Audit)?;

    if args.all {
        let removed = store.deny_all_directory_grants(resolved.config.project_id.as_str())?;
        let metadata = json!({
            "schema_version": 1,
            "action": "DENY_DIRECTORY",
            "status": "SUCCESS",
            "project_id": resolved.config.project_id.as_str(),
            "grant_scope": "all",
            "revoked_count": removed,
            "result_state": "all",
        });
        let audit = AuditWrite {
            project_id: resolved.config.project_id.as_str(),
            profile_id: None,
            action: "DENY_DIRECTORY",
            status: "SUCCESS",
            secret_name: None,
            command: Some("deny"),
            metadata_json: &metadata,
            timestamp,
        };
        store.append_audit(audit_key.as_ref(), &audit)?;
        writeln!(output, "directory grants revoked: {removed}")?;
        writeln!(output, "project_id: {}", resolved.config.project_id)?;
        writeln!(output, "metadata_only: yes")?;
        writeln!(output, "live_grants: unavailable")?;
        return Ok(());
    }

    let profile = default_profile(&store, &resolved.config)?;
    let root_hash = root_hash(&resolved.root)?;
    let directory_hash = root_hash;
    let prior_grant = store.get_directory_grant(
        resolved.config.project_id.as_str(),
        &profile.id,
        &root_hash,
        &directory_hash,
        DIRECTORY_GRANT_SCOPE_PROJECT_ROOT,
    )?;
    let removed = store.deny_directory_grant(
        resolved.config.project_id.as_str(),
        &profile.id,
        &root_hash,
        &directory_hash,
        DIRECTORY_GRANT_SCOPE_PROJECT_ROOT,
    )?;

    let metadata = json!({
        "schema_version": 1,
        "action": "DENY_DIRECTORY",
        "status": "SUCCESS",
        "project_id": resolved.config.project_id.as_str(),
        "profile_id": &profile.id,
        "grant_scope": DIRECTORY_GRANT_SCOPE_PROJECT_ROOT,
        "root_hash": format_hex(&root_hash),
        "directory_hash": format_hex(&directory_hash),
        "prior_grant": prior_grant.as_ref().map(|prior| json!({
            "grant_id": &prior.grant_id,
            "created_at": prior.created_at,
            "updated_at": prior.updated_at,
        })),
        "result_state": if removed { "removed" } else { "absent" },
    });
    let audit = AuditWrite {
        project_id: resolved.config.project_id.as_str(),
        profile_id: Some(&profile.id),
        action: "DENY_DIRECTORY",
        status: "SUCCESS",
        secret_name: None,
        command: Some("deny"),
        metadata_json: &metadata,
        timestamp,
    };
    store.append_audit(audit_key.as_ref(), &audit)?;

    writeln!(
        output,
        "{}",
        if removed { "directory grant revoked" } else { "directory grant not found" }
    )?;
    writeln!(output, "project_id: {}", resolved.config.project_id)?;
    writeln!(output, "profile_id: {}", profile.id)?;
    writeln!(output, "grant_scope: {DIRECTORY_GRANT_SCOPE_PROJECT_ROOT}")?;
    writeln!(output, "root_hash: {}", format_hex(&root_hash))?;
    writeln!(output, "metadata_only: yes")?;
    writeln!(output, "live_grant: unavailable")?;
    Ok(())
}

fn detect_shell() -> ShellArg {
    std::env::var("SHELL").map_or(ShellArg::Bash, |shell| shell_arg_from_name(&shell))
}

fn shell_arg_from_name(shell: &str) -> ShellArg {
    let name = Path::new(shell).file_name().and_then(|name| name.to_str()).unwrap_or(shell);
    match name {
        "zsh" => ShellArg::Zsh,
        "fish" => ShellArg::Fish,
        _ => ShellArg::Bash,
    }
}

fn write_shellenv_snippet(output: &mut impl Write, shell: ShellArg) -> Result<(), CliError> {
    match shell {
        ShellArg::Bash | ShellArg::Zsh => {
            writeln!(output, "{SHELL_HOOK_BEGIN}")?;
            writeln!(output, "if [ -z \"${{__LOCKET_SHELLENV_SOURCED:-}}\" ]; then")?;
            writeln!(output, "  export __LOCKET_SHELLENV_SOURCED=1")?;
            writeln!(
                output,
                "  locket_prompt_segment() {{ locket status 2>/dev/null | sed -n 's/^project: //p; s/^default_profile: //p' | paste -sd ' / ' -; }}"
            )?;
            writeln!(output, "fi")?;
            writeln!(output, "{SHELL_HOOK_END}")?;
        }
        ShellArg::Fish => {
            writeln!(output, "{SHELL_HOOK_BEGIN}")?;
            writeln!(output, "if not set -q __LOCKET_SHELLENV_SOURCED")?;
            writeln!(output, "  set -gx __LOCKET_SHELLENV_SOURCED 1")?;
            writeln!(output, "  function locket_prompt_segment")?;
            writeln!(
                output,
                "    locket status 2>/dev/null | string match -r '^(project|default_profile): ' | string replace -r '^[^:]+: ' '' | string join ' / '"
            )?;
            writeln!(output, "  end")?;
            writeln!(output, "end")?;
            writeln!(output, "{SHELL_HOOK_END}")?;
        }
    }
    Ok(())
}

fn write_shell_hook_snippet(output: &mut impl Write, shell: ShellArg) -> Result<(), CliError> {
    match shell {
        ShellArg::Bash => {
            writeln!(output, "{SHELL_HOOK_BEGIN}")?;
            writeln!(output, "__locket_hook() {{")?;
            writeln!(output, "  local dir=\"$PWD\"")?;
            writeln!(output, "  while [ \"$dir\" != \"/\" ]; do")?;
            writeln!(output, "    if [ -f \"$dir/locket.toml\" ]; then")?;
            writeln!(output, "      locket hook --install >/dev/null 2>&1 || true")?;
            writeln!(output, "      return")?;
            writeln!(output, "    fi")?;
            writeln!(output, "    dir=\"${{dir%/*}}\"")?;
            writeln!(output, "    [ -n \"$dir\" ] || dir=\"/\"")?;
            writeln!(output, "  done")?;
            writeln!(output, "}}")?;
            output.write_all(
                br#"case ";${PROMPT_COMMAND:-};" in *';__locket_hook;'*) ;; *) PROMPT_COMMAND="__locket_hook;${PROMPT_COMMAND:-}" ;; esac
"#,
            )?;
            writeln!(output, "{SHELL_HOOK_END}")?;
        }
        ShellArg::Zsh => {
            writeln!(output, "{SHELL_HOOK_BEGIN}")?;
            writeln!(output, "__locket_hook() {{")?;
            writeln!(output, "  local dir=\"$PWD\"")?;
            writeln!(output, "  while [ \"$dir\" != \"/\" ]; do")?;
            writeln!(output, "    if [ -f \"$dir/locket.toml\" ]; then")?;
            writeln!(output, "      locket hook --install >/dev/null 2>&1 || true")?;
            writeln!(output, "      return")?;
            writeln!(output, "    fi")?;
            output.write_all(
                br#"    dir="${dir:h}"
"#,
            )?;
            writeln!(output, "  done")?;
            writeln!(output, "}}")?;
            writeln!(
                output,
                "if ! ((${{chpwd_functions[(I)__locket_hook]}})); then chpwd_functions+=(__locket_hook); fi"
            )?;
            writeln!(output, "__locket_hook")?;
            writeln!(output, "{SHELL_HOOK_END}")?;
        }
        ShellArg::Fish => {
            writeln!(output, "{SHELL_HOOK_BEGIN}")?;
            writeln!(output, "function __locket_hook --on-variable PWD")?;
            writeln!(output, "  set -l dir $PWD")?;
            writeln!(output, "  while test \"$dir\" != /")?;
            writeln!(output, "    if test -f \"$dir/locket.toml\"")?;
            writeln!(output, "      locket hook --install >/dev/null 2>&1; or true")?;
            writeln!(output, "      return")?;
            writeln!(output, "    end")?;
            writeln!(output, "    set dir (dirname \"$dir\")")?;
            writeln!(output, "  end")?;
            writeln!(output, "end")?;
            writeln!(output, "{SHELL_HOOK_END}")?;
        }
    }
    Ok(())
}

fn directory_grant_id(
    project_id: &str,
    profile_id: &str,
    root_hash: &[u8; 32],
    directory_hash: &[u8; 32],
    grant_scope: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"locket-directory-grant-v1");
    hasher.update(project_id.as_bytes());
    hasher.update(profile_id.as_bytes());
    hasher.update(root_hash);
    hasher.update(directory_hash);
    hasher.update(grant_scope.as_bytes());
    let digest = hasher.finalize();
    format!("lk_dgrant_{}", format_hex(&digest[..16]))
}
