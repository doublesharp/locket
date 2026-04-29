//! Scan command implementation.

use std::ffi::OsStr;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;

use ignore::{WalkBuilder, gitignore::GitignoreBuilder};
use locket_crypto::KeyPurpose;
use locket_scan::{
    FindingKind, ScanFinding, SuppressedFinding, partition_inline_suppressions, scan_text,
};
use locket_store::AuditWrite;
use serde_json::{Value, json};

use crate::{
    CliError, ResolvedProject, RuntimeContext, ScanArgs, absolutize, collect_known_secret_values,
    load_project_key, now_unix_nanos, open_store, resolve_project,
};

const LOCKETIGNORE_FILE: &str = ".locketignore";

pub fn scan_command(
    context: &RuntimeContext,
    output: &mut impl io::Write,
    args: &ScanArgs,
) -> Result<(), CliError> {
    let project = resolve_project(&context.cwd)?;
    let git_root = if args.staged {
        Some(ensure_git_worktree(project.as_ref().map_or(&context.cwd, |project| &project.root))?)
    } else {
        None
    };
    if args.require_known && project.is_none() {
        return Err(CliError::Config(
            "known-value scanning requires a Locket project and unlocked vault".to_owned(),
        ));
    }
    if args.no_gitignore {
        writeln!(output, "scan: gitignore rules disabled")?;
    }

    let scan_root = args.path.as_deref().map_or_else(
        || project.as_ref().map_or_else(|| context.cwd.clone(), |project| project.root.clone()),
        |path| absolutize(&context.cwd, Path::new(path)),
    );
    let known_values = if args.require_known {
        let project = project.as_ref().ok_or_else(|| {
            CliError::Config("known-value scanning requires a project".to_owned())
        })?;
        collect_known_secret_values(context, project, now_unix_nanos()?)?
    } else {
        Vec::new()
    };

    let mut findings = Vec::new();
    let mut suppressed = Vec::new();
    if let Some(git_root) = git_root {
        scan_staged_path(&git_root, &known_values, &mut findings, &mut suppressed)?;
    } else {
        scan_path(
            &scan_root,
            &scan_root,
            &known_values,
            !args.no_gitignore,
            &mut findings,
            &mut suppressed,
        )?;
    }
    for finding in &findings {
        writeln!(output, "{}", format_finding(finding))?;
    }

    if findings.is_empty() {
        writeln!(output, "scan: no findings")?;
    } else {
        writeln!(output, "scan: {} finding(s)", findings.len())?;
    }

    if !suppressed.is_empty() {
        writeln!(output, "scan: {} suppressed finding(s)", suppressed.len())?;
        for finding in &suppressed {
            writeln!(output, "{}", format_suppressed_finding(finding))?;
        }
    }

    if args.require_known {
        writeln!(output, "scan: known-value coverage checked {} value(s)", known_values.len())?;
    }

    if !suppressed.is_empty()
        && let Some(project) = project.as_ref()
    {
        write_scan_suppression_audit(context, project, &suppressed, args.staged)?;
    }

    Ok(())
}

fn format_suppressed_finding(finding: &SuppressedFinding) -> String {
    if finding.reason.is_empty() {
        format!(
            "{}:{}:{}: {} suppressed",
            finding.path_label, finding.line, finding.column, finding.rule_id,
        )
    } else {
        format!(
            "{}:{}:{}: {} suppressed reason={}",
            finding.path_label, finding.line, finding.column, finding.rule_id, finding.reason,
        )
    }
}

fn write_scan_suppression_audit(
    context: &RuntimeContext,
    project: &ResolvedProject,
    suppressed: &[SuppressedFinding],
    staged: bool,
) -> Result<(), CliError> {
    let mut store = open_store(context)?;
    if store.get_project(project.config.project_id.as_str())?.is_none() {
        return Ok(());
    }
    let audit_key =
        load_project_key(context, &store, project.config.project_id.as_str(), KeyPurpose::Audit)?;

    let entries: Vec<Value> = suppressed
        .iter()
        .map(|finding| {
            json!({
                "path_label": finding.path_label,
                "line": finding.line,
                "column": finding.column,
                "rule_id": finding.rule_id,
                "reason": finding.reason,
            })
        })
        .collect();

    let metadata = json!({
        "schema_version": 1,
        "action": "SCAN",
        "status": "SUPPRESSED",
        "scope": if staged { "staged" } else { "tree" },
        "suppressed_count": suppressed.len(),
        "suppressions": entries,
    });
    let audit = AuditWrite {
        project_id: project.config.project_id.as_str(),
        profile_id: None,
        action: "SCAN",
        status: "SUPPRESSED",
        secret_name: None,
        command: Some("scan"),
        metadata_json: &metadata,
        timestamp: now_unix_nanos()?,
    };
    store.append_audit(audit_key.as_ref(), &audit)?;
    Ok(())
}

pub fn scan_path(
    root: &Path,
    path: &Path,
    known_values: &[zeroize::Zeroizing<String>],
    use_gitignore: bool,
    findings: &mut Vec<ScanFinding>,
    suppressed: &mut Vec<SuppressedFinding>,
) -> Result<(), CliError> {
    if path.is_dir() {
        let mut builder = WalkBuilder::new(path);
        builder
            .add_custom_ignore_filename(LOCKETIGNORE_FILE)
            .filter_entry(|entry| !should_skip_scan_path(entry.path()))
            .hidden(false)
            .git_ignore(use_gitignore)
            .git_global(use_gitignore)
            .git_exclude(use_gitignore);
        for entry in builder.build() {
            let entry = entry.map_err(|error| CliError::Config(error.to_string()))?;
            let child = entry.path();
            if child == path || !child.is_file() {
                continue;
            }
            scan_file(root, child, known_values, findings, suppressed)?;
        }
        return Ok(());
    }

    scan_file(root, path, known_values, findings, suppressed)
}

fn scan_file(
    root: &Path,
    path: &Path,
    known_values: &[zeroize::Zeroizing<String>],
    findings: &mut Vec<ScanFinding>,
    suppressed: &mut Vec<SuppressedFinding>,
) -> Result<(), CliError> {
    if !path.is_file() {
        return Ok(());
    }

    let label = path_label(root, path);
    match fs::read_to_string(path) {
        Ok(text) => {
            let mut file_findings = scan_text(&label, &text);
            file_findings.extend(scan_known_values(&label, &text, known_values));
            let result = partition_inline_suppressions(&text, file_findings);
            findings.extend(result.kept);
            suppressed.extend(result.suppressed);
        }
        Err(error) if error.kind() == io::ErrorKind::InvalidData => {
            findings.extend(scan_text(&label, ""));
        }
        Err(error) => return Err(error.into()),
    }

    Ok(())
}

fn scan_staged_path(
    git_root: &Path,
    known_values: &[zeroize::Zeroizing<String>],
    findings: &mut Vec<ScanFinding>,
    suppressed: &mut Vec<SuppressedFinding>,
) -> Result<(), CliError> {
    let locket_ignore = locket_ignore(git_root)?;
    let staged_paths =
        git_output(git_root, ["diff", "--cached", "--name-only", "-z", "--diff-filter=ACMRT"])?;

    for path_bytes in staged_paths.split(|byte| *byte == 0).filter(|path| !path.is_empty()) {
        let path = String::from_utf8_lossy(path_bytes);
        if locket_ignore.matched_path_or_any_parents(path.as_ref(), false).is_ignore() {
            continue;
        }
        if should_skip_scan_path(Path::new(path.as_ref())) {
            continue;
        }

        let spec = format!(":{path}");
        let object_type =
            String::from_utf8_lossy(&git_output(git_root, ["cat-file", "-t", &spec])?)
                .trim()
                .to_owned();
        if object_type != "blob" {
            continue;
        }

        let contents = git_output(git_root, ["cat-file", "-p", &spec])?;
        match String::from_utf8(contents) {
            Ok(text) => {
                let mut file_findings = scan_text(&path, &text);
                file_findings.extend(scan_known_values(&path, &text, known_values));
                let result = partition_inline_suppressions(&text, file_findings);
                findings.extend(result.kept);
                suppressed.extend(result.suppressed);
            }
            Err(_) => findings.extend(scan_text(&path, "")),
        }
    }

    Ok(())
}

fn locket_ignore(git_root: &Path) -> Result<ignore::gitignore::Gitignore, CliError> {
    let mut builder = GitignoreBuilder::new(git_root);
    let path = git_root.join(LOCKETIGNORE_FILE);
    if path.exists()
        && let Some(error) = builder.add(path)
    {
        return Err(CliError::Config(error.to_string()));
    }
    builder.build().map_err(|error| CliError::Config(error.to_string()))
}

fn scan_known_values(
    path_label: &str,
    text: &str,
    known_values: &[zeroize::Zeroizing<String>],
) -> Vec<ScanFinding> {
    let mut findings = Vec::new();
    for known_value in known_values {
        if known_value.is_empty() {
            continue;
        }
        let mut cursor = 0;
        while let Some(relative) = text[cursor..].find(known_value.as_str()) {
            let start = cursor + relative;
            let (line, column) = line_column_for_byte(text, start);
            findings.push(ScanFinding {
                path_label: path_label.to_owned(),
                line,
                column,
                token_length: known_value.len(),
                kind: FindingKind::KnownSecretValue,
            });
            cursor = start + known_value.len();
        }
    }
    findings
}

fn line_column_for_byte(text: &str, byte_index: usize) -> (usize, usize) {
    let mut line = 1;
    let mut column = 1;
    for (index, character) in text.char_indices() {
        if index >= byte_index {
            break;
        }
        if character == '\n' {
            line += 1;
            column = 1;
        } else {
            column += 1;
        }
    }
    (line, column)
}

fn should_skip_scan_path(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| matches!(name, ".git" | ".locket" | "target"))
}

fn path_label(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .ok()
        .filter(|relative| !relative.as_os_str().is_empty())
        .unwrap_or(path)
        .to_string_lossy()
        .into_owned()
}

pub fn format_finding(finding: &ScanFinding) -> String {
    format!(
        "{}:{}:{}: {} token_length={}",
        finding.path_label,
        finding.line,
        finding.column,
        finding_kind_label(finding.kind),
        finding.token_length
    )
}

const fn finding_kind_label(kind: FindingKind) -> &'static str {
    match kind {
        FindingKind::HighEntropy => "high-entropy",
        FindingKind::ProviderTokenPattern => "provider-token-pattern",
        FindingKind::EnvFileMarker => "env-file",
        FindingKind::KnownSecretValue => "known-secret",
    }
}

pub fn ensure_git_worktree(start: &Path) -> Result<PathBuf, CliError> {
    let mut current = start.canonicalize()?;
    loop {
        if current.join(".git").exists() {
            return Ok(current);
        }
        if !current.pop() {
            return Err(CliError::Config("git worktree required for --staged".to_owned()));
        }
    }
}

pub fn git_output<I, S>(git_root: &Path, args: I) -> Result<Vec<u8>, CliError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let output = ProcessCommand::new("git").arg("-C").arg(git_root).args(args).output()?;
    if output.status.success() {
        return Ok(output.stdout);
    }

    let message = String::from_utf8_lossy(&output.stderr);
    Err(CliError::Config(format!("git command failed: {}", message.trim())))
}
