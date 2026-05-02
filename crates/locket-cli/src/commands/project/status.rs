//! `locket status` command.

use std::io::Write;
use std::path::Path;

use locket_store::ProfileRecord;

use crate::commands::config::spec::read_user_config;
use crate::commands::scan::scanner;
use crate::{
    CliError, EXAMPLE_FILE, LOCKET_TOML, ResolvedProject, RuntimeContext, config_bool_value,
    open_store, privacy_alias, resolve_project, root_hash,
};

pub fn status(context: &RuntimeContext, output: &mut impl Write) -> Result<(), CliError> {
    let Some(resolved) = resolve_project(&context.cwd)? else {
        writeln!(output, "locket: not initialized")?;
        writeln!(output, "next_action: run locket init")?;
        return Ok(());
    };

    let store = open_store(context)?;
    let project = store.get_project(resolved.config.project_id.as_str())?;
    let root_hash = root_hash(&resolved.root)?;
    let trusted = store.project_root_is_trusted(resolved.config.project_id.as_str(), &root_hash)?;
    let profile = store.get_profile_by_name(
        resolved.config.project_id.as_str(),
        resolved.config.default_profile.as_str(),
    )?;
    let redact_names = status_privacy_redact_names_enabled(context)?;
    let project_label = status_project_label(&resolved, redact_names);
    let profile_label = status_profile_label(
        profile.as_ref(),
        resolved.config.default_profile.as_str(),
        redact_names,
    );
    let running_sessions =
        store.list_incomplete_runtime_sessions(resolved.config.project_id.as_str())?.len();
    let scan_warning_count = status_scan_warning_count(&resolved.root)?;
    let example_exists = resolved.root.join(EXAMPLE_FILE).exists();
    let next_action = status_next_action(
        project.as_ref(),
        profile.as_ref(),
        trusted,
        example_exists,
        scan_warning_count,
    );

    writeln!(output, "project: {project_label}")?;
    writeln!(
        output,
        "project_id: {}",
        status_project_id_label(resolved.config.project_id.as_str(), redact_names)
    )?;
    writeln!(output, "root: {}", resolved.root.display())?;
    let canonical_cwd = context.cwd.canonicalize().ok();
    let cwd_display = canonical_cwd
        .as_deref()
        .map_or_else(|| context.cwd.display().to_string(), |path| path.display().to_string());
    let cwd_matches_root = canonical_cwd.as_deref() == Some(&resolved.root);
    writeln!(output, "cwd: {cwd_display}")?;
    writeln!(
        output,
        "cwd_matches_root: {}",
        if cwd_matches_root { "yes" } else { "no" }
    )?;
    if !cwd_matches_root {
        writeln!(
            output,
            "cwd_hint: locket.toml resolved from a parent directory; commands act on the project at root:"
        )?;
    }
    writeln!(output, "default_profile: {profile_label}")?;
    writeln!(output, "active_profile: {profile_label}")?;
    writeln!(output, "lock_state: {}", status_lock_state(project.as_ref(), profile.as_ref()))?;
    writeln!(output, "agent: unavailable")?;
    writeln!(output, "agent_state: unavailable")?;
    writeln!(output, "running_sessions: {running_sessions}")?;
    writeln!(output, "scan_warnings: {scan_warning_count}")?;
    writeln!(output, "store: {}", if project.is_some() { "ready" } else { "partial" })?;
    writeln!(output, "trusted_root: {}", if trusted { "yes" } else { "no" })?;
    writeln!(output, "profile: {}", if profile.is_some() { "ready" } else { "missing" })?;
    writeln!(output, "metadata_only: yes")?;
    writeln!(output, "next_action: {next_action}")?;
    Ok(())
}

fn status_privacy_redact_names_enabled(context: &RuntimeContext) -> Result<bool, CliError> {
    let config = read_user_config(context)?;
    Ok(config_bool_value(&config, "privacy.redact_names")?.unwrap_or(false))
}

fn status_project_label(resolved: &ResolvedProject, redact_names: bool) -> String {
    if redact_names {
        privacy_alias("project", resolved.config.project_id.as_str())
    } else {
        resolved.config.name.clone()
    }
}

fn status_project_id_label(project_id: &str, redact_names: bool) -> String {
    if redact_names { privacy_alias("project", project_id) } else { project_id.to_owned() }
}

fn status_profile_label(
    profile: Option<&ProfileRecord>,
    default_profile: &str,
    redact_names: bool,
) -> String {
    if redact_names {
        let profile_id = profile.map_or(default_profile, |profile| profile.id.as_str());
        privacy_alias("profile", profile_id)
    } else {
        default_profile.to_owned()
    }
}

const fn status_lock_state(
    project: Option<&locket_store::ProjectRecord>,
    profile: Option<&ProfileRecord>,
) -> &'static str {
    if project.is_none() || profile.is_none() { "unavailable" } else { "locked" }
}

fn status_scan_warning_count(root: &Path) -> Result<usize, CliError> {
    let mut findings = Vec::new();
    let mut suppressed = Vec::new();
    let entropy_rule = scanner::read_scan_entropy_rule(&root.join(LOCKET_TOML))?;
    scanner::scan_path(root, root, &[], entropy_rule, true, &mut findings, &mut suppressed)?;
    findings.retain(|finding| !matches!(finding.path_label.as_str(), LOCKET_TOML | EXAMPLE_FILE));
    Ok(findings.len())
}

const fn status_next_action(
    project: Option<&locket_store::ProjectRecord>,
    profile: Option<&ProfileRecord>,
    trusted_root: bool,
    example_exists: bool,
    scan_warning_count: usize,
) -> &'static str {
    if project.is_none() || profile.is_none() {
        "run locket init to resume local metadata setup"
    } else if !trusted_root {
        "run locket project trust-root"
    } else if !example_exists {
        "run locket emit-example"
    } else if scan_warning_count > 0 {
        "run locket scan"
    } else {
        "none"
    }
}
