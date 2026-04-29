use locket_crypto::KeyPurpose;
use locket_store::{AuditWrite, Store};
use serde_json::json;
use std::fs;
use std::io::Write;
use std::path::Path;

use crate::{
    CliError, EXAMPLE_FILE, HOOK_BEGIN, HOOK_END, LOCKET_TOML, ResolvedProject, RuntimeContext,
    git_dir_for_worktree, load_project_key, now_unix_nanos, open_store, read_policy_document,
    require_project, root_hash, yes_no,
};

pub fn bootstrap_command(
    context: &RuntimeContext,
    output: &mut impl Write,
) -> Result<(), CliError> {
    let resolved = require_project(context)?;
    let store = open_store(context)?;
    let report = collect_bootstrap_report(&resolved, &store)?;
    write_bootstrap_report(output, &report)?;
    write_bootstrap_audit_if_available(context, &resolved, &report)?;
    Ok(())
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum HookState {
    Installed,
    Unmanaged,
    Missing,
    NotGitRepo,
}

impl HookState {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Installed => "installed",
            Self::Unmanaged => "unmanaged",
            Self::Missing => "missing",
            Self::NotGitRepo => "not_git_repo",
        }
    }
}

#[derive(Debug, Clone)]
#[allow(clippy::struct_excessive_bools)]
struct BootstrapReport {
    project_name: String,
    project_id: String,
    profile_name: String,
    project_in_store: bool,
    profile_ready: bool,
    trusted_root: bool,
    example_exists: bool,
    hook_state: HookState,
    policy_count: usize,
    smoke_policy: Option<String>,
    smoke_policy_present: bool,
    team_status: &'static str,
}

fn collect_bootstrap_report(
    resolved: &ResolvedProject,
    store: &Store,
) -> Result<BootstrapReport, CliError> {
    let project_id = resolved.config.project_id.as_str();
    let project = store.get_project(project_id)?;
    let profile =
        store.get_profile_by_name(project_id, resolved.config.default_profile.as_str())?;
    let root_hash = root_hash(&resolved.root)?;
    let trusted_root = store.project_root_is_trusted(project_id, &root_hash)?;
    let example_exists = resolved.root.join(EXAMPLE_FILE).exists();
    let hook_state = detect_pre_commit_hook_state(&resolved.root);
    let policy_document = read_policy_document(&resolved.root.join(LOCKET_TOML))?;
    let policy_count = policy_document.commands.len();
    let bootstrap_settings = read_bootstrap_settings(&resolved.root.join(LOCKET_TOML))?;
    let smoke_policy = bootstrap_settings.and_then(|settings| settings.smoke_policy);
    let smoke_policy_present = smoke_policy
        .as_ref()
        .is_some_and(|name| policy_document.commands.contains_key(name.as_str()));

    Ok(BootstrapReport {
        project_name: resolved.config.name.clone(),
        project_id: project_id.to_owned(),
        profile_name: resolved.config.default_profile.to_string(),
        project_in_store: project.is_some(),
        profile_ready: profile.is_some(),
        trusted_root,
        example_exists,
        hook_state,
        policy_count,
        smoke_policy,
        smoke_policy_present,
        team_status: "solo",
    })
}

fn write_bootstrap_report(
    output: &mut impl Write,
    report: &BootstrapReport,
) -> Result<(), CliError> {
    writeln!(output, "project: {}", report.project_name)?;
    writeln!(output, "project_id: {}", report.project_id)?;
    writeln!(output, "profile: {}", report.profile_name)?;
    writeln!(output, "profile_ready: {}", yes_no(report.profile_ready))?;
    writeln!(output, "store_project: {}", yes_no(report.project_in_store))?;
    writeln!(output, ".env.example: {}", yes_no(report.example_exists))?;
    writeln!(output, "trusted_root: {}", yes_no(report.trusted_root))?;
    writeln!(output, "pre_commit_hook: {}", report.hook_state.as_str())?;
    writeln!(output, "team: {}", report.team_status)?;
    writeln!(output, "policies: {}", report.policy_count)?;
    match &report.smoke_policy {
        Some(name) if report.smoke_policy_present => {
            writeln!(output, "smoke_policy: configured ({name})")?;
        }
        Some(name) => writeln!(output, "smoke_policy: missing ({name})")?,
        None => writeln!(output, "smoke_policy: none")?,
    }
    writeln!(output, "metadata_only: yes")?;
    writeln!(output, "next_actions:")?;
    let actions = bootstrap_next_actions(report);
    if actions.is_empty() {
        writeln!(output, "- none")?;
    } else {
        for action in actions {
            writeln!(output, "- {action}")?;
        }
    }
    Ok(())
}

fn bootstrap_next_actions(report: &BootstrapReport) -> Vec<String> {
    let mut actions = Vec::new();
    if !report.project_in_store || !report.profile_ready {
        actions.push("run locket init to resume local metadata setup".to_owned());
    }
    if !report.example_exists {
        actions.push("run locket emit-example".to_owned());
    }
    if !report.trusted_root {
        actions.push("run locket project trust-root".to_owned());
    }
    if matches!(report.hook_state, HookState::Missing | HookState::Unmanaged) {
        actions.push("run locket install-hooks".to_owned());
    }
    if let Some(name) = &report.smoke_policy
        && !report.smoke_policy_present
    {
        actions.push(format!("run locket policy add {name}"));
    }
    actions
}

fn detect_pre_commit_hook_state(root: &Path) -> HookState {
    let Ok(git_dir) = git_dir_for_worktree(root) else {
        return HookState::NotGitRepo;
    };
    let hook_path = git_dir.join("hooks").join("pre-commit");
    let Ok(content) = fs::read_to_string(&hook_path) else {
        return HookState::Missing;
    };
    if content.contains(HOOK_BEGIN) && content.contains(HOOK_END) {
        HookState::Installed
    } else {
        HookState::Unmanaged
    }
}

#[derive(Debug, Clone, Default)]
struct BootstrapSettings {
    smoke_policy: Option<String>,
}

fn read_bootstrap_settings(path: &Path) -> Result<Option<BootstrapSettings>, CliError> {
    let content = fs::read_to_string(path)?;
    let value: toml::Value = toml::from_str(&content).map_err(CliError::TomlDe)?;
    let Some(table) = value.as_table().and_then(|table| table.get("bootstrap")) else {
        return Ok(None);
    };
    let Some(table) = table.as_table() else {
        return Err(CliError::Config("bootstrap settings must be a table".to_owned()));
    };
    let smoke_policy = match table.get("smoke_policy") {
        None => None,
        Some(value) => Some(
            value
                .as_str()
                .ok_or_else(|| {
                    CliError::Config("bootstrap.smoke_policy must be a string".to_owned())
                })?
                .to_owned(),
        ),
    };
    Ok(Some(BootstrapSettings { smoke_policy }))
}

fn write_bootstrap_audit_if_available(
    context: &RuntimeContext,
    resolved: &ResolvedProject,
    report: &BootstrapReport,
) -> Result<(), CliError> {
    let mut store = open_store(context)?;
    if store.get_project(resolved.config.project_id.as_str())?.is_none() {
        return Ok(());
    }
    let Ok(audit_key) =
        load_project_key(context, &store, resolved.config.project_id.as_str(), KeyPurpose::Audit)
    else {
        return Ok(());
    };
    let profile_id = store
        .get_profile_by_name(
            resolved.config.project_id.as_str(),
            resolved.config.default_profile.as_str(),
        )?
        .map(|profile| profile.id);
    let mut generated_files: Vec<&str> = Vec::new();
    if report.example_exists {
        generated_files.push(EXAMPLE_FILE);
    }
    if matches!(report.hook_state, HookState::Installed) {
        generated_files.push(".git/hooks/pre-commit");
    }
    let metadata = json!({
        "schema_version": 1,
        "action": "BOOTSTRAP",
        "status": "SUCCESS",
        "project_id": resolved.config.project_id.as_str(),
        "default_profile_id": profile_id,
        "generated_files": generated_files,
        "recovery_code_displayed": false,
        "team_status": report.team_status,
        "policy_count": report.policy_count,
        "smoke_policy_configured": report.smoke_policy.is_some(),
    });
    let audit = AuditWrite {
        project_id: resolved.config.project_id.as_str(),
        profile_id: profile_id.as_deref(),
        action: "BOOTSTRAP",
        status: "SUCCESS",
        secret_name: None,
        command: Some("bootstrap"),
        metadata_json: &metadata,
        timestamp: now_unix_nanos()?,
    };
    store.append_audit(audit_key.as_ref(), &audit)?;
    Ok(())
}
