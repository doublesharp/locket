use std::fs;
use std::io::{self, Write};
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use flate2::Compression;
use flate2::write::GzEncoder;
use locket_core::PROJECT_CONFIG_SCHEMA_VERSION;
use locket_crypto::KeyPurpose;
use locket_store::{AuditWrite, SCHEMA_VERSION};
use serde_json::{Value, json};

use super::{
    CONFIG_KEY_SPECS, CliError, GITIGNORE_ENTRIES, GITIGNORE_FILE, HOOK_BEGIN, LOCKET_TOML,
    RuntimeContext, agent_log_path, agent_pid_path, agent_socket_path, format_hex,
    git_dir_for_worktree, load_project_key, now_unix_nanos, open_store, read_project_config,
    read_user_config, resolve_project, root_hash,
};

const SKIPPED_LOCKED_CHECKS: [&str; 5] = [
    "audit_hmac_verification",
    "key_unwrap_probe",
    "recovery_envelope_decryptability",
    "known_value_scanner_readiness",
    "bundle_decryptability",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CheckStatus {
    Pass,
    Warn,
    Fail,
    Skip,
}

#[derive(Debug)]
struct DiagnosticCheck {
    name: &'static str,
    status: CheckStatus,
    critical: bool,
    detail: String,
}

impl DiagnosticCheck {
    fn pass(name: &'static str, detail: impl Into<String>) -> Self {
        Self { name, status: CheckStatus::Pass, critical: false, detail: detail.into() }
    }

    fn warn(name: &'static str, detail: impl Into<String>) -> Self {
        Self { name, status: CheckStatus::Warn, critical: false, detail: detail.into() }
    }

    fn fail(name: &'static str, critical: bool, detail: impl Into<String>) -> Self {
        Self { name, status: CheckStatus::Fail, critical, detail: detail.into() }
    }

    fn skip(name: &'static str, detail: impl Into<String>) -> Self {
        Self { name, status: CheckStatus::Skip, critical: false, detail: detail.into() }
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct DiagnosticCounts {
    pass: u32,
    warn: u32,
    fail: u32,
    skip: u32,
    critical_fail: u32,
}

impl DiagnosticCounts {
    const fn record(&mut self, check: &DiagnosticCheck) {
        match check.status {
            CheckStatus::Pass => self.pass += 1,
            CheckStatus::Warn => self.warn += 1,
            CheckStatus::Fail => {
                self.fail += 1;
                if check.critical {
                    self.critical_fail += 1;
                }
            }
            CheckStatus::Skip => self.skip += 1,
        }
    }

    const fn exit_code(self) -> u8 {
        if self.critical_fail > 0 {
            2
        } else if self.fail > 0 {
            1
        } else {
            0
        }
    }
}

#[derive(Debug)]
struct DiagnosticReport {
    checks: Vec<DiagnosticCheck>,
    counts: DiagnosticCounts,
}

impl DiagnosticReport {
    fn new(checks: Vec<DiagnosticCheck>) -> Self {
        let mut counts = DiagnosticCounts::default();
        for check in &checks {
            counts.record(check);
        }
        Self { checks, counts }
    }

    const fn exit_code(&self) -> u8 {
        self.counts.exit_code()
    }

    fn as_json(&self) -> Value {
        json!({
            "schema_version": 1,
            "counts": {
                "pass": self.counts.pass,
                "warn": self.counts.warn,
                "fail": self.counts.fail,
                "skip": self.counts.skip,
                "critical_fail": self.counts.critical_fail,
            },
            "checks": self.checks.iter().map(|check| {
                json!({
                    "name": check.name,
                    "status": status_label(check.status),
                    "critical": check.critical,
                    "detail": check.detail,
                })
            }).collect::<Vec<_>>(),
        })
    }

    fn audit_metadata(&self) -> Value {
        json!({
            "schema_version": 1,
            "action": "DOCTOR",
            "status": if self.counts.fail == 0 { "SUCCESS" } else { "FAILED" },
            "check_names": self.checks.iter().map(|check| check.name).collect::<Vec<_>>(),
            "pass_count": self.counts.pass,
            "warn_count": self.counts.warn,
            "fail_count": self.counts.fail,
            "skip_count": self.counts.skip,
            "critical_fail_count": self.counts.critical_fail,
        })
    }
}

pub fn doctor_command(context: &RuntimeContext, output: &mut impl Write) -> Result<u8, CliError> {
    let report = collect_diagnostics(context);
    write_doctor_audit_if_available(context, &report);
    write_doctor_report(output, &report)?;
    Ok(report.exit_code())
}

pub fn debug_bundle_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    redacted: bool,
    output_path: Option<&str>,
) -> Result<(), CliError> {
    if !redacted {
        return Err(CliError::Config(
            "debug bundle currently requires --redacted; unredacted bundles are not supported"
                .to_owned(),
        ));
    }

    let diagnostics = collect_diagnostics(context);
    let project = resolve_project(&context.cwd)?;
    let user_config = read_user_config(context).unwrap_or_default();
    let config_keys = CONFIG_KEY_SPECS
        .iter()
        .filter_map(|spec| config_key_is_set(&user_config, spec.key).then_some(spec.key))
        .collect::<Vec<_>>();
    let audit_actions = project.as_ref().map_or_else(Vec::new, |project| {
        open_store(context).map_or_else(
            |_| Vec::new(),
            |store| {
                store
                    .list_recent_audit_actions(project.config.project_id.as_str(), 25)
                    .unwrap_or_default()
            },
        )
    });
    let project_json = project.as_ref().map(|project| {
        json!({
            "id": project.config.project_id.as_str(),
            "name": project.config.name,
            "default_profile": project.config.default_profile.as_str(),
            "root_kind": "project_root",
            "root_hash": root_hash(&project.root).map(|hash| format_hex(&hash)).ok(),
        })
    });
    let bundle = json!({
        "schema_version": 1,
        "redacted": true,
        "versions": {
            "locket_cli": env!("CARGO_PKG_VERSION"),
            "project_config_schema": PROJECT_CONFIG_SCHEMA_VERSION,
            "store_schema": SCHEMA_VERSION,
        },
        "platform": {
            "os": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
            "cwd_kind": "current_working_directory",
            "store_path_hash": path_hash(&context.store_path),
            "config_path_hash": path_hash(&context.config_path),
        },
        "project": project_json,
        "config_keys": config_keys,
        "recent_audit_actions": audit_actions,
        "agent": agent_metadata(context),
        "diagnostics": diagnostics.as_json(),
    });
    let text = serde_json::to_string_pretty(&bundle)
        .map_err(|error| CliError::Config(error.to_string()))?;

    let path = output_path.map_or_else(
        || default_debug_bundle_path(context),
        |output_path| Ok(PathBuf::from(output_path)),
    )?;
    write_debug_bundle_file(&path, &text)?;
    writeln!(output, "debug_bundle: {}", path.display())?;
    writeln!(output, "redacted: yes")?;

    Ok(())
}

#[allow(clippy::too_many_lines)]
fn collect_diagnostics(context: &RuntimeContext) -> DiagnosticReport {
    let mut checks = Vec::new();

    match resolve_project(&context.cwd) {
        Ok(Some(project)) => {
            checks.push(DiagnosticCheck::pass(
                "project_resolution",
                format!(
                    "project_id={} root_hash={}",
                    project.config.project_id,
                    root_hash(&project.root)
                        .map_or_else(|_| "unavailable".to_owned(), |hash| format_hex(&hash))
                ),
            ));
            checks.push(check_locket_toml(&project.root.join(LOCKET_TOML)));
            match open_store(context) {
                Ok(store) => {
                    checks.push(DiagnosticCheck::pass(
                        "store_open_schema_bootstrap",
                        format!("schema_version={SCHEMA_VERSION}"),
                    ));
                    let integrity_ok = store
                        .integrity_check()
                        .map(|rows| rows.iter().any(|row| row == "ok"))
                        .unwrap_or(false);
                    checks.push(if integrity_ok {
                        DiagnosticCheck::pass("sqlite_integrity", "ok")
                    } else {
                        DiagnosticCheck::fail("sqlite_integrity", true, "integrity_check failed")
                    });
                    checks.push(match store.get_project(project.config.project_id.as_str()) {
                        Ok(Some(record)) => DiagnosticCheck::pass(
                            "project_store_metadata",
                            format!("project_id={} name={}", record.id, record.name),
                        ),
                        Ok(None) => DiagnosticCheck::fail(
                            "project_store_metadata",
                            false,
                            "project metadata is not present in the local store",
                        ),
                        Err(error) => DiagnosticCheck::fail(
                            "project_store_metadata",
                            false,
                            error.to_string(),
                        ),
                    });
                    checks.push(check_trusted_roots(
                        &store,
                        &project.root,
                        project.config.project_id.as_str(),
                    ));
                    checks.push(
                        match store.get_profile_by_name(
                            project.config.project_id.as_str(),
                            project.config.default_profile.as_str(),
                        ) {
                            Ok(Some(profile)) => DiagnosticCheck::pass(
                                "default_profile",
                                format!("profile_id={} name={}", profile.id, profile.name),
                            ),
                            Ok(None) => DiagnosticCheck::fail(
                                "default_profile",
                                false,
                                "default profile is missing from the local store",
                            ),
                            Err(error) => {
                                DiagnosticCheck::fail("default_profile", false, error.to_string())
                            }
                        },
                    );
                }
                Err(error) => checks.push(DiagnosticCheck::fail(
                    "store_open_schema_bootstrap",
                    true,
                    error.to_string(),
                )),
            }
            checks.push(check_gitignore(&project.root));
            checks.push(check_pre_commit_hook(&project.root));
        }
        Ok(None) => {
            checks.push(DiagnosticCheck::fail(
                "project_resolution",
                false,
                "no locket.toml found from current directory",
            ));
            match open_store(context) {
                Ok(_) => checks.push(DiagnosticCheck::pass(
                    "store_open_schema_bootstrap",
                    format!("schema_version={SCHEMA_VERSION}"),
                )),
                Err(error) => checks.push(DiagnosticCheck::fail(
                    "store_open_schema_bootstrap",
                    true,
                    error.to_string(),
                )),
            }
        }
        Err(error) => {
            checks.push(DiagnosticCheck::fail("project_resolution", true, error.to_string()));
        }
    }

    checks.push(check_agent_placeholder(context));
    for check in SKIPPED_LOCKED_CHECKS {
        checks.push(DiagnosticCheck::skip(check, "locked-safe metadata-only invocation"));
    }

    DiagnosticReport::new(checks)
}

fn check_locket_toml(path: &Path) -> DiagnosticCheck {
    match read_project_config(path) {
        Ok(config) if config.schema_version == PROJECT_CONFIG_SCHEMA_VERSION => {
            DiagnosticCheck::pass("locket_toml_parseability", "schema_version=1")
        }
        Ok(config) => DiagnosticCheck::fail(
            "locket_toml_parseability",
            true,
            format!(
                "schema_version={} supported={PROJECT_CONFIG_SCHEMA_VERSION}",
                config.schema_version
            ),
        ),
        Err(error) => DiagnosticCheck::fail("locket_toml_parseability", true, error.to_string()),
    }
}

fn check_trusted_roots(
    store: &locket_store::Store,
    root: &Path,
    project_id: &str,
) -> DiagnosticCheck {
    match root_hash(root).and_then(|hash| {
        store
            .project_root_is_trusted(project_id, &hash)
            .map(|trusted| (hash, trusted))
            .map_err(CliError::from)
    }) {
        Ok((hash, true)) => DiagnosticCheck::pass(
            "trusted_roots",
            format!("current_root_trusted=yes root_hash={}", format_hex(&hash)),
        ),
        Ok((hash, false)) => DiagnosticCheck::fail(
            "trusted_roots",
            true,
            format!("current_root_trusted=no root_hash={}", format_hex(&hash)),
        ),
        Err(error) => DiagnosticCheck::fail("trusted_roots", true, error.to_string()),
    }
}

fn check_gitignore(root: &Path) -> DiagnosticCheck {
    let path = root.join(GITIGNORE_FILE);
    let content = match fs::read_to_string(&path) {
        Ok(content) => content,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return DiagnosticCheck::warn(".gitignore", "missing");
        }
        Err(error) => return DiagnosticCheck::fail(".gitignore", false, error.to_string()),
    };
    let missing = GITIGNORE_ENTRIES
        .iter()
        .filter(|entry| !content.lines().any(|line| line.trim() == **entry))
        .copied()
        .collect::<Vec<_>>();
    if missing.is_empty() {
        DiagnosticCheck::pass(".gitignore", "required entries present")
    } else {
        DiagnosticCheck::warn(".gitignore", format!("missing entries: {}", missing.join(",")))
    }
}

fn check_pre_commit_hook(root: &Path) -> DiagnosticCheck {
    let git_dir = match git_dir_for_worktree(root) {
        Ok(git_dir) => git_dir,
        Err(error) => return DiagnosticCheck::warn("pre_commit_hook", error.to_string()),
    };
    let hook_path = git_dir.join("hooks").join("pre-commit");
    match fs::read_to_string(&hook_path) {
        Ok(content) if content.contains(HOOK_BEGIN) => {
            DiagnosticCheck::pass("pre_commit_hook", "locket managed block present")
        }
        Ok(_) => {
            DiagnosticCheck::warn("pre_commit_hook", "pre-commit hook exists without locket block")
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            DiagnosticCheck::warn("pre_commit_hook", "missing")
        }
        Err(error) => DiagnosticCheck::fail("pre_commit_hook", false, error.to_string()),
    }
}

fn check_agent_placeholder(context: &RuntimeContext) -> DiagnosticCheck {
    let pid = fs::read_to_string(agent_pid_path(context)).ok();
    let status = if pid.as_deref().is_some_and(|pid| !pid.trim().is_empty()) {
        "unavailable last_known_pid=yes"
    } else {
        "unavailable last_known_pid=no"
    };
    DiagnosticCheck::pass("agent_placeholder", status)
}

fn write_doctor_audit_if_available(context: &RuntimeContext, report: &DiagnosticReport) {
    let Ok(Some(project)) = resolve_project(&context.cwd) else {
        return;
    };
    let Ok(mut store) = open_store(context) else {
        return;
    };
    match store.get_project(project.config.project_id.as_str()) {
        Ok(Some(_)) => {}
        Ok(None) | Err(_) => return,
    }
    let Ok(audit_key) =
        load_project_key(context, &store, project.config.project_id.as_str(), KeyPurpose::Audit)
    else {
        return;
    };
    let metadata = report.audit_metadata();
    let status = if report.counts.fail == 0 { "SUCCESS" } else { "FAILED" };
    let Ok(timestamp) = now_unix_nanos() else {
        return;
    };
    let audit = AuditWrite {
        project_id: project.config.project_id.as_str(),
        profile_id: None,
        action: "DOCTOR",
        status,
        secret_name: None,
        command: Some("doctor"),
        metadata_json: &metadata,
        timestamp,
    };
    let _ignored = store.append_audit(audit_key.as_ref(), &audit);
}

fn write_doctor_report(output: &mut impl Write, report: &DiagnosticReport) -> Result<(), CliError> {
    writeln!(output, "locket doctor")?;
    for check in &report.checks {
        writeln!(output, "{} {}: {}", status_label(check.status), check.name, check.detail)?;
    }
    writeln!(
        output,
        "summary: pass={} warn={} fail={} skip={} critical_fail={}",
        report.counts.pass,
        report.counts.warn,
        report.counts.fail,
        report.counts.skip,
        report.counts.critical_fail
    )?;
    Ok(())
}

fn default_debug_bundle_path(context: &RuntimeContext) -> Result<PathBuf, CliError> {
    let parent = context
        .store_path
        .parent()
        .ok_or_else(|| CliError::Config("could not resolve diagnostics directory".to_owned()))?;
    Ok(parent.join("diagnostics").join(format!("locket-debug-{}.tar.gz", now_unix_nanos()?)))
}

fn write_debug_bundle_file(path: &Path, text: &str) -> Result<(), CliError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
        set_user_only_dir_permissions(parent)?;
    }
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    set_user_only_file_options(&mut options);
    let file = options.open(path).map_err(|error| {
        if error.kind() == io::ErrorKind::AlreadyExists {
            CliError::Config("debug bundle output already exists".to_owned())
        } else {
            CliError::Io(error)
        }
    })?;
    write_debug_bundle_archive(file, text)?;
    set_user_only_file_permissions(path)?;
    Ok(())
}

fn write_debug_bundle_archive(file: fs::File, text: &str) -> Result<(), CliError> {
    let encoder = GzEncoder::new(file, Compression::default());
    let mut archive = tar::Builder::new(encoder);
    let bytes = format!("{text}\n").into_bytes();
    let mut header = tar::Header::new_gnu();
    header.set_size(u64::try_from(bytes.len()).map_err(|_| CliError::Time)?);
    header.set_mode(0o600);
    header.set_mtime(u64::try_from(now_unix_nanos()? / 1_000_000_000).map_err(|_| CliError::Time)?);
    header.set_cksum();
    archive.append_data(&mut header, "bundle.json", bytes.as_slice())?;
    let encoder = archive.into_inner()?;
    encoder.finish()?;
    Ok(())
}

#[cfg(unix)]
fn set_user_only_file_options(options: &mut fs::OpenOptions) {
    options.mode(0o600);
}

#[cfg(not(unix))]
fn set_user_only_file_options(_options: &mut fs::OpenOptions) {}

#[cfg(unix)]
fn set_user_only_file_permissions(path: &Path) -> Result<(), CliError> {
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_user_only_file_permissions(_path: &Path) -> Result<(), CliError> {
    Ok(())
}

#[cfg(unix)]
fn set_user_only_dir_permissions(path: &Path) -> Result<(), CliError> {
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_user_only_dir_permissions(_path: &Path) -> Result<(), CliError> {
    Ok(())
}

const fn status_label(status: CheckStatus) -> &'static str {
    match status {
        CheckStatus::Pass => "pass",
        CheckStatus::Warn => "warn",
        CheckStatus::Fail => "fail",
        CheckStatus::Skip => "skip",
    }
}

fn config_key_is_set(config: &toml::Table, key: &str) -> bool {
    let Some((section, name)) = key.split_once('.') else {
        return false;
    };
    config.get(section).and_then(toml::Value::as_table).and_then(|table| table.get(name)).is_some()
}

fn agent_metadata(context: &RuntimeContext) -> Value {
    json!({
        "status": "unavailable",
        "socket_path_hash": path_hash(&agent_socket_path(context)),
        "pid_path_hash": path_hash(&agent_pid_path(context)),
        "log_path_hash": path_hash(&agent_log_path(context)),
    })
}

fn path_hash(path: &Path) -> String {
    use sha2::{Digest, Sha256};

    let digest = Sha256::digest(path.to_string_lossy().as_bytes());
    format_hex(&digest)
}
