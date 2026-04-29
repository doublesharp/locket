//! Diff command implementations.

use std::collections::BTreeSet;
use std::io::Write;

use locket_core::ProfileName;
use locket_store::{AuditLogRecord, SecretRecord, SecretVersionRecord, Store};

use crate::{
    CliError, DiffArgs, RuntimeContext, active_secret_map, default_profile, format_optional_str,
    open_store, optional_i64, require_project, resolve_diff_since,
};

pub fn diff_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &DiffArgs,
) -> Result<(), CliError> {
    if let Some(since) = &args.since {
        if args.profile_a.is_some() || args.profile_b.is_some() {
            return Err(CliError::Config(
                "diff --since uses the active profile and does not accept profile arguments"
                    .to_owned(),
            ));
        }
        return diff_since_command(context, output, since);
    }

    let profile_a = args
        .profile_a
        .as_deref()
        .ok_or_else(|| CliError::Config("diff requires two profile names".to_owned()))?;
    let profile_b = args
        .profile_b
        .as_deref()
        .ok_or_else(|| CliError::Config("diff requires two profile names".to_owned()))?;
    let lhs = ProfileName::new(profile_a.to_owned())
        .map_err(|_| CliError::Config("invalid profile name".to_owned()))?;
    let rhs = ProfileName::new(profile_b.to_owned())
        .map_err(|_| CliError::Config("invalid profile name".to_owned()))?;

    let resolved = require_project(context)?;
    let store = open_store(context)?;
    let profile_a = store
        .get_profile_by_name(resolved.config.project_id.as_str(), lhs.as_str())?
        .ok_or_else(|| CliError::Config("first profile not found".to_owned()))?;
    let profile_b = store
        .get_profile_by_name(resolved.config.project_id.as_str(), rhs.as_str())?
        .ok_or_else(|| CliError::Config("second profile not found".to_owned()))?;

    let lhs_secrets =
        active_secret_map(&store, resolved.config.project_id.as_str(), &profile_a.id)?;
    let rhs_secrets =
        active_secret_map(&store, resolved.config.project_id.as_str(), &profile_b.id)?;
    let keys = lhs_secrets.keys().chain(rhs_secrets.keys()).cloned().collect::<BTreeSet<_>>();
    let mut differences = 0_u32;

    for key in keys {
        match (lhs_secrets.get(&key), rhs_secrets.get(&key)) {
            (Some(left_record), Some(right_record))
                if left_record.current_version != right_record.current_version =>
            {
                differences += 1;
                writeln!(
                    output,
                    "changed {} source={} {}_version={} {}_version={}",
                    key.0,
                    key.1,
                    profile_a.name,
                    left_record.current_version,
                    profile_b.name,
                    right_record.current_version
                )?;
            }
            (Some(secret), None) => {
                differences += 1;
                writeln!(
                    output,
                    "only {}: {} source={} version={}",
                    profile_a.name, key.0, key.1, secret.current_version
                )?;
            }
            (None, Some(secret)) => {
                differences += 1;
                writeln!(
                    output,
                    "only {}: {} source={} version={}",
                    profile_b.name, key.0, key.1, secret.current_version
                )?;
            }
            _ => {}
        }
    }

    if differences == 0 {
        writeln!(output, "no differences")?;
    }
    Ok(())
}

fn diff_since_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    since: &str,
) -> Result<(), CliError> {
    let resolved = require_project(context)?;
    let store = open_store(context)?;
    let profile = default_profile(&store, &resolved.config)?;
    let since_nanos = resolve_diff_since(&resolved.root, since)?;
    let changes = collect_diff_since_changes(
        &store,
        resolved.config.project_id.as_str(),
        &profile.id,
        since_nanos,
    )?;

    if changes.is_empty() {
        writeln!(output, "no differences")?;
        return Ok(());
    }

    writeln!(output, "profile: {} ({})", profile.name, profile.id)?;
    writeln!(output, "since: {since}")?;
    writeln!(output, "since_unix_nanos: {since_nanos}")?;
    writeln!(output, "metadata_only: yes")?;
    for change in changes {
        writeln!(output, "{change}")?;
    }
    Ok(())
}

fn collect_diff_since_changes(
    store: &Store,
    project_id: &str,
    profile_id: &str,
    since_nanos: i64,
) -> Result<Vec<String>, CliError> {
    let mut changes = Vec::<DiffSinceChange>::new();
    for audit in store.list_audit_rows_since(project_id, profile_id, since_nanos)? {
        if audit.status != "SUCCESS" || !is_diff_since_mutating_audit_action(&audit.action) {
            continue;
        }
        changes.push(DiffSinceChange {
            timestamp: audit.timestamp,
            sequence: audit.sequence,
            text: diff_since_audit_line(&audit),
        });
    }
    for secret in store.list_secrets_by_profile(project_id, profile_id)? {
        let mut latest_secret_timestamp = latest_secret_change_timestamp(&secret, since_nanos);
        let versions = store.list_secret_versions(&secret.id)?;
        let mut version_changes = Vec::new();
        for version in versions {
            if let Some(timestamp) = latest_version_change_timestamp(&version, since_nanos) {
                latest_secret_timestamp =
                    Some(latest_secret_timestamp.map_or(timestamp, |latest| latest.max(timestamp)));
                version_changes.push(DiffSinceChange {
                    timestamp,
                    sequence: u64::MAX,
                    text: format!(
                    "version {} source={} v{} state={} created_at={} deprecated_at={} grace_until={} purged_at={}",
                    secret.name,
                    secret.source,
                    version.version,
                    version.state,
                    version.created_at,
                    optional_i64(version.deprecated_at),
                    optional_i64(version.grace_until),
                    optional_i64(version.purged_at)
                    ),
                });
            }
        }
        if let Some(timestamp) = latest_secret_timestamp {
            changes.push(DiffSinceChange {
                timestamp,
                sequence: u64::MAX,
                text: format!(
                "changed {} source={} state={} current_version={} created_at={} updated_at={} last_rotated_at={} deleted_at={}",
                secret.name,
                secret.source,
                secret.state,
                secret.current_version,
                secret.created_at,
                secret.updated_at,
                optional_i64(secret.last_rotated_at),
                optional_i64(secret.deleted_at)
                ),
            });
            changes.extend(version_changes);
        }
    }
    changes.sort_by(|left, right| {
        (left.timestamp, left.sequence, left.text.as_str()).cmp(&(
            right.timestamp,
            right.sequence,
            right.text.as_str(),
        ))
    });
    Ok(changes.into_iter().map(|change| change.text).collect())
}

fn is_diff_since_mutating_audit_action(action: &str) -> bool {
    matches!(action, "SET" | "ROTATE" | "DELETE" | "PURGE" | "SECRET_COPY" | "SECRET_META_UPDATE")
}

struct DiffSinceChange {
    timestamp: i64,
    sequence: u64,
    text: String,
}

fn latest_secret_change_timestamp(secret: &SecretRecord, since_nanos: i64) -> Option<i64> {
    [Some(secret.created_at), Some(secret.updated_at), secret.last_rotated_at, secret.deleted_at]
        .into_iter()
        .flatten()
        .filter(|timestamp| *timestamp >= since_nanos)
        .max()
}

fn latest_version_change_timestamp(version: &SecretVersionRecord, since_nanos: i64) -> Option<i64> {
    [Some(version.created_at), version.deprecated_at, version.grace_until, version.purged_at]
        .into_iter()
        .flatten()
        .filter(|timestamp| *timestamp >= since_nanos)
        .max()
}

fn diff_since_audit_line(audit: &AuditLogRecord) -> String {
    format!(
        "audit sequence={} action={} status={} secret={} command={} timestamp={}",
        audit.sequence,
        audit.action,
        audit.status,
        format_optional_str(audit.secret_name.as_deref()),
        format_optional_str(audit.command.as_deref()),
        audit.timestamp
    )
}
