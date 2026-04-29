//! Agent command implementation (start/status/stop/logs).

use std::fs;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::time::Duration as StdDuration;

use serde_json::Value;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::{
    AGENT_LOG_FOLLOW_SLEEP_MS, AgentCommand, AgentLogsArgs, CliError, NANOS_PER_SECOND,
    RuntimeContext, agent_data_dir, agent_log_path, agent_log_paths_oldest_first, agent_pid_path,
    append_agent_log, invalid_reference_error, metadata_invalid_error, prepare_agent_log_dir,
    read_agent_pid, resolve_project, sanitize_agent_log_line, set_user_only_file_permissions,
    write_agent_paths,
};

pub fn agent_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    command: AgentCommand,
) -> Result<(), CliError> {
    match command {
        AgentCommand::Start => agent_start_command(context, output),
        AgentCommand::Status => agent_status_command(context, output),
        AgentCommand::Stop => agent_stop_command(context, output),
        AgentCommand::Logs(args) => agent_logs_command(context, output, &args),
    }
}

fn agent_start_command(context: &RuntimeContext, output: &mut impl Write) -> Result<(), CliError> {
    fs::create_dir_all(agent_data_dir(context))?;
    append_agent_log(context, "start", "unavailable", "daemon not available in this build")?;
    writeln!(output, "agent: unavailable")?;
    writeln!(output, "running: no")?;
    writeln!(output, "start: daemon not available in this build")?;
    write_agent_paths(context, output)?;
    Ok(())
}

fn agent_status_command(context: &RuntimeContext, output: &mut impl Write) -> Result<(), CliError> {
    writeln!(output, "agent: unavailable")?;
    writeln!(output, "running: no")?;
    match read_agent_pid(context)? {
        Some(pid) => writeln!(output, "last_known_pid: {pid}")?,
        None => writeln!(output, "last_known_pid: -")?,
    }
    write_agent_paths(context, output)?;
    writeln!(output, "lock_state: unavailable")?;
    writeln!(output, "live_grants: unavailable")?;
    writeln!(output, "last_error: daemon not available in this build")?;
    if let Some(project) = resolve_project(&context.cwd)? {
        writeln!(output, "active_project_id: {}", project.config.project_id)?;
        writeln!(output, "active_profile: {}", project.config.default_profile)?;
    }
    Ok(())
}

fn agent_stop_command(context: &RuntimeContext, output: &mut impl Write) -> Result<(), CliError> {
    let pid_path = agent_pid_path(context);
    let removed_stale_pid = match fs::remove_file(&pid_path) {
        Ok(()) => true,
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(error) => return Err(error.into()),
    };
    append_agent_log(context, "stop", "stopped", "no daemon was running")?;
    writeln!(output, "agent: stopped")?;
    writeln!(output, "running: no")?;
    writeln!(output, "removed_stale_pid: {}", if removed_stale_pid { "yes" } else { "no" })?;
    write_agent_paths(context, output)?;
    Ok(())
}

fn agent_logs_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &AgentLogsArgs,
) -> Result<(), CliError> {
    if args.lines > 10_000 {
        return Err(invalid_reference_error("agent logs --lines is capped at 10000"));
    }
    let since = args.since.as_deref().map(parse_agent_log_since).transpose()?;
    let lines = read_agent_log_lines(context, since)?;
    if lines.is_empty() {
        if !args.follow {
            writeln!(output, "no agent logs")?;
        }
    } else {
        for line in lines.iter().skip(lines.len().saturating_sub(args.lines)) {
            writeln!(output, "{}", sanitize_agent_log_line(line))?;
        }
    }
    if args.follow {
        follow_agent_logs(context, output, since)?;
    }
    Ok(())
}

fn parse_agent_log_since(value: &str) -> Result<i64, CliError> {
    if let Ok(timestamp) = value.parse::<i64>() {
        return Ok(normalize_log_since(timestamp));
    }
    let timestamp = OffsetDateTime::parse(value, &Rfc3339).map_err(|_| {
        metadata_invalid_error("agent logs --since must be RFC3339 UTC or Unix seconds")
    })?;
    timestamp.unix_timestamp_nanos().try_into().map_err(|_| CliError::Time)
}

const fn normalize_log_since(value: i64) -> i64 {
    if value.abs() < 10_000_000_000 { value.saturating_mul(NANOS_PER_SECOND) } else { value }
}

fn read_agent_log_lines(
    context: &RuntimeContext,
    since: Option<i64>,
) -> Result<Vec<String>, CliError> {
    let mut lines = Vec::new();
    for path in agent_log_paths_oldest_first(context) {
        let log_text = match fs::read_to_string(&path) {
            Ok(log_text) => log_text,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        lines.extend(
            log_text.lines().filter(|line| agent_log_line_is_since(line, since)).map(str::to_owned),
        );
    }
    Ok(lines)
}

fn agent_log_line_is_since(line: &str, since: Option<i64>) -> bool {
    let Some(since) = since else {
        return true;
    };
    serde_json::from_str::<Value>(line)
        .ok()
        .and_then(|value| agent_log_timestamp_nanos(value.get("timestamp")?))
        .is_some_and(|timestamp| timestamp >= since)
}

fn agent_log_timestamp_nanos(value: &Value) -> Option<i64> {
    if let Some(timestamp) = value.as_i64() {
        return Some(normalize_log_since(timestamp));
    }
    let timestamp = OffsetDateTime::parse(value.as_str()?, &Rfc3339).ok()?;
    timestamp.unix_timestamp_nanos().try_into().ok()
}

fn follow_agent_logs(
    context: &RuntimeContext,
    output: &mut impl Write,
    since: Option<i64>,
) -> Result<(), CliError> {
    prepare_agent_log_dir(context)?;
    let log_path = agent_log_path(context);
    let mut file = fs::OpenOptions::new().read(true).create(true).append(true).open(&log_path)?;
    set_user_only_file_permissions(&log_path)?;
    file.seek(SeekFrom::End(0))?;
    let mut pending = String::new();
    loop {
        let mut chunk = String::new();
        file.read_to_string(&mut chunk)?;
        if !chunk.is_empty() {
            pending.push_str(&chunk);
            while let Some(newline) = pending.find('\n') {
                let line = pending[..newline].to_owned();
                pending.drain(..=newline);
                if agent_log_line_is_since(&line, since) {
                    writeln!(output, "{}", sanitize_agent_log_line(&line))?;
                }
            }
        }
        std::thread::sleep(StdDuration::from_millis(AGENT_LOG_FOLLOW_SLEEP_MS));
    }
}
