//! Agent command implementation (start/status/stop/logs).

use std::fs;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::time::{Duration as StdDuration, Instant};

use serde_json::Value;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::runtime::error::typed_cli_error;
use crate::{
    AGENT_LOG_FOLLOW_SLEEP_MS, AgentCommand, AgentLogsArgs, CliError, InternalAgentServeArgs,
    NANOS_PER_SECOND, RuntimeContext, agent_data_dir, agent_log_path, agent_log_paths_oldest_first,
    agent_pid_path, agent_socket_path, append_agent_log, metadata_invalid_error,
    prepare_agent_log_dir, read_agent_pid, resolve_project, sanitize_agent_log_line,
    set_user_only_file_permissions, write_agent_paths,
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

/// Maximum time `agent start` waits for the spawned daemon to bind its socket.
const AGENT_START_SOCKET_WAIT: StdDuration = StdDuration::from_secs(2);
/// Polling interval while `agent start` waits for the spawned daemon's socket.
const AGENT_START_POLL_INTERVAL: StdDuration = StdDuration::from_millis(25);
/// Maximum time `agent stop` waits for the daemon to exit after SIGTERM.
const AGENT_STOP_WAIT: StdDuration = StdDuration::from_secs(5);
/// Polling interval while `agent stop` waits for the daemon to exit.
const AGENT_STOP_POLL_INTERVAL: StdDuration = StdDuration::from_millis(50);

fn agent_start_command(context: &RuntimeContext, output: &mut impl Write) -> Result<(), CliError> {
    let report = ensure_agent_running_with_launcher(context, &ProcessAgentDaemonLauncher)?;
    if report.started {
        append_agent_log(context, "start", "running", "daemon started")?;
        writeln!(output, "agent: running")?;
    } else {
        writeln!(output, "agent: already running")?;
    }
    writeln!(output, "running: yes")?;
    match report.pid {
        Some(pid) => writeln!(output, "pid: {pid}")?,
        None => writeln!(output, "pid: -")?,
    }
    write_agent_paths(context, output)?;
    Ok(())
}

#[cfg(not(test))]
pub(crate) fn ensure_agent_running_for_execution(context: &RuntimeContext) -> Result<(), CliError> {
    ensure_agent_running_with_launcher(context, &ProcessAgentDaemonLauncher).map(|_| ())
}

#[cfg(test)]
pub(crate) fn ensure_agent_running_for_execution(
    _context: &RuntimeContext,
) -> Result<(), CliError> {
    // `cargo test` runs the libtest harness as `current_exe()`, so the
    // production spawn path cannot exec `internal-agent-serve`. The startup
    // state machine itself is covered below with an injectable launcher.
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AgentStartupReport {
    started: bool,
    pid: Option<u32>,
}

trait AgentDaemonLauncher {
    fn spawn(&self, socket: &Path, pid_file: &Path) -> Result<(), CliError>;
    fn status_snapshot(&self, socket: &Path) -> Result<Value, io::Error>;
}

struct ProcessAgentDaemonLauncher;

impl AgentDaemonLauncher for ProcessAgentDaemonLauncher {
    fn spawn(&self, socket: &Path, pid_file: &Path) -> Result<(), CliError> {
        spawn_agent_daemon(socket, pid_file)
    }

    fn status_snapshot(&self, socket: &Path) -> Result<Value, io::Error> {
        request_status_snapshot(socket)
    }
}

fn ensure_agent_running_with_launcher(
    context: &RuntimeContext,
    launcher: &dyn AgentDaemonLauncher,
) -> Result<AgentStartupReport, CliError> {
    fs::create_dir_all(agent_data_dir(context))?;

    let pid_path = agent_pid_path(context);
    let socket_path = agent_socket_path(context);

    // Idempotency: if a live PID owns the pid file and responds on the
    // socket, execution can proceed without spawning a second daemon.
    if let Some(pid) = read_running_pid(context)? {
        if launcher.status_snapshot(&socket_path).is_ok() {
            return Ok(AgentStartupReport { started: false, pid: Some(pid) });
        }
        let _ignored = fs::remove_file(&pid_path);
        let _ignored = fs::remove_file(&socket_path);
    }

    // If the pid file is missing or stale but the socket owner still
    // answers trusted status requests, preserve the live daemon and
    // keep start idempotent instead of unlinking its socket.
    if socket_path.exists() {
        if launcher.status_snapshot(&socket_path).is_ok() {
            return Ok(AgentStartupReport { started: false, pid: None });
        }
    }

    // Best-effort cleanup of stale pid/socket files. The daemon may have
    // crashed and left them behind; bind_socket_listener will refuse if
    // a live owner is still present.
    let _ignored = fs::remove_file(&pid_path);
    let _ignored = fs::remove_file(&socket_path);

    launcher.spawn(&socket_path, &pid_path)?;

    // Poll for the socket to appear so the caller's first
    // `agent status`/connect attempt does not race the child.
    wait_for_path_to_exist(&socket_path, AGENT_START_SOCKET_WAIT, AGENT_START_POLL_INTERVAL);

    let pid = read_running_pid(context)?;
    launcher.status_snapshot(&socket_path).map_err(|error| {
        typed_cli_error(
            locket_core::LocketError::AgentUnavailable,
            format!("agent did not become reachable after on-demand startup: {error}"),
        )
    })?;
    Ok(AgentStartupReport { started: true, pid })
}

fn agent_status_command(context: &RuntimeContext, output: &mut impl Write) -> Result<(), CliError> {
    let pid_path = agent_pid_path(context);
    let socket_path = agent_socket_path(context);

    let live_pid = read_running_pid(context)?;
    let Some(pid) = live_pid else {
        let last_known = read_agent_pid(context)?;
        writeln!(output, "agent: stopped")?;
        writeln!(output, "running: no")?;
        match last_known {
            Some(pid) => writeln!(output, "last_known_pid: {pid}")?,
            None => writeln!(output, "last_known_pid: -")?,
        }
        write_agent_paths(context, output)?;
        if let Some(project) = resolve_project(&context.cwd)? {
            writeln!(output, "active_project_id: {}", project.config.project_id)?;
            writeln!(output, "active_profile: {}", project.config.default_profile)?;
        }
        return Ok(());
    };

    match request_status_snapshot(&socket_path) {
        Ok(snapshot) => {
            writeln!(output, "agent: running")?;
            writeln!(output, "running: yes")?;
            writeln!(output, "pid: {pid}")?;
            write_agent_paths(context, output)?;
            write_agent_status_snapshot(output, &snapshot)?;
            if let Some(project) = resolve_project(&context.cwd)? {
                writeln!(output, "active_project_id: {}", project.config.project_id)?;
                writeln!(output, "active_profile: {}", project.config.default_profile)?;
            }
            Ok(())
        }
        Err(_error) => {
            // The pid file says the daemon is alive but we cannot reach
            // it on the socket. Treat as stopped + stale and clean up
            // the pid file so the next `agent start` is unblocked.
            let _ignored = fs::remove_file(&pid_path);
            writeln!(output, "agent: stopped")?;
            writeln!(output, "running: no")?;
            writeln!(output, "last_known_pid: {pid}")?;
            write_agent_paths(context, output)?;
            writeln!(output, "lock_state: unknown")?;
            writeln!(output, "live_grants: 0")?;
            if let Some(project) = resolve_project(&context.cwd)? {
                writeln!(output, "active_project_id: {}", project.config.project_id)?;
                writeln!(output, "active_profile: {}", project.config.default_profile)?;
            }
            Ok(())
        }
    }
}

fn agent_stop_command(context: &RuntimeContext, output: &mut impl Write) -> Result<(), CliError> {
    let pid_path = agent_pid_path(context);
    let socket_path = agent_socket_path(context);

    let last_known = read_agent_pid(context)?;
    let Some(raw_pid) = last_known else {
        append_agent_log(context, "stop", "stopped", "no daemon was running")?;
        writeln!(output, "agent: stopped")?;
        writeln!(output, "running: no")?;
        writeln!(output, "removed_stale_pid: no")?;
        write_agent_paths(context, output)?;
        return Ok(());
    };

    let Some(pid) = parse_pid(&raw_pid) else {
        let _ignored = fs::remove_file(&pid_path);
        append_agent_log(context, "stop", "stopped", "removed unparseable pid file")?;
        writeln!(output, "agent: stopped")?;
        writeln!(output, "running: no")?;
        writeln!(output, "removed_stale_pid: yes")?;
        write_agent_paths(context, output)?;
        return Ok(());
    };

    if !process_is_live(pid) {
        let _ignored = fs::remove_file(&pid_path);
        let _ignored = fs::remove_file(&socket_path);
        append_agent_log(context, "stop", "stopped", "removed stale pid file")?;
        writeln!(output, "agent: stopped")?;
        writeln!(output, "running: no")?;
        writeln!(output, "removed_stale_pid: yes")?;
        write_agent_paths(context, output)?;
        return Ok(());
    }

    send_sigterm(pid)?;

    let deadline = Instant::now() + AGENT_STOP_WAIT;
    while Instant::now() < deadline {
        if !process_is_live(pid) && !pid_path.exists() {
            break;
        }
        std::thread::sleep(AGENT_STOP_POLL_INTERVAL);
    }

    if process_is_live(pid) {
        return Err(typed_cli_error(
            locket_core::LocketError::AgentUnavailable,
            format!("agent (pid {pid}) did not exit within {} seconds", AGENT_STOP_WAIT.as_secs()),
        ));
    }

    let _ignored = fs::remove_file(&pid_path);
    let _ignored = fs::remove_file(&socket_path);
    append_agent_log(context, "stop", "stopped", "daemon stopped")?;
    writeln!(output, "agent: stopped")?;
    writeln!(output, "running: no")?;
    write_agent_paths(context, output)?;
    Ok(())
}

/// Spawns the daemon child via `current_exe internal-agent-serve`.
#[cfg(unix)]
fn spawn_agent_daemon(socket: &Path, pid_file: &Path) -> Result<(), CliError> {
    use std::os::unix::process::CommandExt;
    use std::process::{Command as StdCommand, Stdio};

    let exe = std::env::current_exe()?;
    let mut command = StdCommand::new(&exe);
    command
        .arg("internal-agent-serve")
        .arg("--socket")
        .arg(socket)
        .arg("--pid-file")
        .arg(pid_file)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        // Place the child in a fresh process group so terminal signals
        // delivered to the parent (SIGINT/SIGHUP from a foreground
        // shell) are not forwarded to the daemon. This is the
        // unsafe-free counterpart of the `setsid` call recommended by
        // the agent-daemon plan; combined with the null stdio streams
        // it is sufficient to detach the daemon from a controlling
        // terminal for both interactive and CI invocations.
        .process_group(0);
    let _child = command.spawn()?;
    Ok(())
}

#[cfg(not(unix))]
fn spawn_agent_daemon(_socket: &Path, _pid_file: &Path) -> Result<(), CliError> {
    Err(typed_cli_error(
        locket_core::LocketError::AgentUnavailable,
        "agent daemon is only supported on Unix targets",
    ))
}

fn wait_for_path_to_exist(path: &Path, timeout: StdDuration, interval: StdDuration) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if path.exists() {
            return;
        }
        std::thread::sleep(interval);
    }
}

/// Returns the live PID owning the pid file, if any. A pid file with a
/// dead PID is treated as stale and ignored (but is not deleted here —
/// the caller decides when to remove it).
fn read_running_pid(context: &RuntimeContext) -> Result<Option<u32>, CliError> {
    let Some(raw) = read_agent_pid(context)? else {
        return Ok(None);
    };
    let Some(pid) = parse_pid(&raw) else {
        return Ok(None);
    };
    Ok(if process_is_live(pid) { Some(pid) } else { None })
}

fn write_agent_status_snapshot(output: &mut impl Write, snapshot: &Value) -> Result<(), io::Error> {
    let lock_state = snapshot.get("lock_state").and_then(Value::as_str).unwrap_or("unknown");
    writeln!(output, "lock_state: {lock_state}")?;
    if let Some(ttl) = snapshot.get("unlock_ttl_seconds").and_then(Value::as_u64) {
        writeln!(output, "unlock_ttl_seconds: {ttl}")?;
    }
    let live_grants = snapshot.get("live_grant_count").and_then(Value::as_u64).unwrap_or(0);
    writeln!(output, "live_grants: {live_grants}")?;
    let version = snapshot.get("agent_version").and_then(Value::as_str).unwrap_or("unknown");
    writeln!(output, "agent_version: {version}")?;
    Ok(())
}

fn parse_pid(value: &str) -> Option<u32> {
    value.trim().parse::<u32>().ok()
}

#[cfg(unix)]
fn process_is_live(pid: u32) -> bool {
    let Ok(raw) = i32::try_from(pid) else {
        return false;
    };
    let Some(rust_pid) = rustix::process::Pid::from_raw(raw) else {
        return false;
    };
    rustix::process::test_kill_process(rust_pid).is_ok()
}

#[cfg(not(unix))]
const fn process_is_live(_pid: u32) -> bool {
    false
}

#[cfg(unix)]
fn send_sigterm(pid: u32) -> Result<(), CliError> {
    let raw = i32::try_from(pid)
        .map_err(|_| typed_cli_error(locket_core::LocketError::AgentUnavailable, "invalid pid"))?;
    let rust_pid = rustix::process::Pid::from_raw(raw).ok_or_else(|| {
        typed_cli_error(locket_core::LocketError::AgentUnavailable, "invalid pid")
    })?;
    rustix::process::kill_process(rust_pid, rustix::process::Signal::TERM)
        .map_err(|error| io::Error::from_raw_os_error(error.raw_os_error()))?;
    Ok(())
}

#[cfg(not(unix))]
fn send_sigterm(_pid: u32) -> Result<(), CliError> {
    Err(typed_cli_error(
        locket_core::LocketError::AgentUnavailable,
        "agent daemon is only supported on Unix targets",
    ))
}

/// Connects to the socket, sends a `Status` request, and parses the
/// response payload.
#[cfg(unix)]
fn request_status_snapshot(socket_path: &Path) -> Result<Value, io::Error> {
    use locket_agent::{
        AgentMethod, DEFAULT_MAX_MESSAGE_SIZE, RequestEnvelope, ResponseEnvelope,
        decode_response_frame, encode_frame,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixStream;

    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(async move {
        let mut stream = UnixStream::connect(socket_path).await?;
        let request =
            RequestEnvelope::new("status-1", AgentMethod::Status, serde_json::Value::Null);
        let frame = encode_frame(&request, DEFAULT_MAX_MESSAGE_SIZE)
            .map_err(|error| io::Error::other(error.to_string()))?;
        stream.write_all(&frame).await?;
        stream.flush().await?;

        let mut buffer = Vec::with_capacity(1024);
        loop {
            if let Ok((response, _)) = decode_response_frame(&buffer, DEFAULT_MAX_MESSAGE_SIZE) {
                return match response {
                    ResponseEnvelope::Success(success) => Ok(success.payload),
                    ResponseEnvelope::Error(error) => Err(io::Error::other(format!(
                        "agent error: {} ({})",
                        error.error, error.message
                    ))),
                };
            }
            let mut chunk = [0_u8; 1024];
            let read = stream.read(&mut chunk).await?;
            if read == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "agent closed connection without a response",
                ));
            }
            buffer.extend_from_slice(&chunk[..read]);
        }
    })
}

#[cfg(not(unix))]
fn request_status_snapshot(_socket_path: &Path) -> Result<Value, io::Error> {
    Err(io::Error::other("agent daemon is only supported on Unix targets"))
}

/// Daemon entry point spawned by `agent_start_command`.
///
/// Owns the Unix socket and `agent.pid` file for the duration of its
/// lifetime, accepts connections on a current-thread Tokio runtime, and
/// shuts down on `SIGTERM`/`SIGINT`. On exit it removes both the pid
/// file and the socket so the next `agent start` is unblocked.
#[cfg(unix)]
pub fn run_internal_agent_serve(args: &InternalAgentServeArgs) -> Result<(), CliError> {
    // Daemon-startup ordering invariant:
    //
    // `agent_lifecycle::run_internal_agent_serve_listens_and_cleans_up_on_sigterm`
    // signals the test process with SIGTERM after observing the pid file on
    // disk. Tokio's `signal::unix::signal(SignalKind::terminate())` only
    // masks the default-terminate disposition once it has been registered,
    // so the pid file MUST NOT be written until both `term` and `intr`
    // signal handlers are installed below. Reordering the write to run
    // before the handler registration would re-introduce a race against
    // any parallel test that emits SIGTERM, allowing the test process to
    // exit instead of the daemon.
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    let result = runtime.block_on(async {
        let (listener, state) = bind_and_record(args)?;
        serve_until_signal(listener, state).await.map_err(CliError::Io)
    });

    let _ignored = fs::remove_file(&args.socket);
    let _ignored = fs::remove_file(&args.pid_file);
    result
}

#[cfg(unix)]
fn bind_and_record(
    args: &InternalAgentServeArgs,
) -> Result<(tokio::net::UnixListener, locket_agent::AgentSocketState), CliError> {
    use locket_agent::{AgentSocketConfig, AgentSocketState, bind_socket_listener};

    // bind_socket_listener creates a tokio UnixListener and so must run
    // inside a runtime; the caller invokes us from within `block_on` so
    // a runtime is already on the current thread.
    let listener = bind_socket_listener(&AgentSocketConfig::new(
        args.socket.clone(),
        env!("CARGO_PKG_VERSION"),
    ))
    .map_err(socket_error_to_cli)?;
    write_pid_file(&args.pid_file)?;
    let state = AgentSocketState::locked(env!("CARGO_PKG_VERSION"));
    Ok((listener, state))
}

#[cfg(unix)]
async fn serve_until_signal(
    listener: tokio::net::UnixListener,
    state: locket_agent::AgentSocketState,
) -> io::Result<()> {
    use locket_agent::handle_connection;
    use tokio::signal::unix::{SignalKind, signal};

    let mut term = signal(SignalKind::terminate())?;
    let mut intr = signal(SignalKind::interrupt())?;
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, _) = accepted?;
                let connection_state = state.clone();
                tokio::spawn(async move {
                    let _outcome = handle_connection(stream, connection_state).await;
                });
            }
            _ = term.recv() => break,
            _ = intr.recv() => break,
        }
    }
    Ok(())
}

#[cfg(not(unix))]
pub fn run_internal_agent_serve(_args: &InternalAgentServeArgs) -> Result<(), CliError> {
    Err(typed_cli_error(
        locket_core::LocketError::AgentUnavailable,
        "agent daemon is only supported on Unix targets",
    ))
}

#[cfg(unix)]
fn write_pid_file(path: &Path) -> Result<(), CliError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, format!("{}\n", std::process::id()))?;
    set_user_only_file_permissions(path)?;
    Ok(())
}

#[cfg(unix)]
fn socket_error_to_cli(error: locket_agent::SocketServerError) -> CliError {
    use locket_agent::SocketServerError;
    use locket_core::LocketError;

    match error {
        SocketServerError::AgentSocketInUse { path } => typed_cli_error(
            LocketError::AgentSocketInUse,
            format!("agent socket already bound: {}", path.display()),
        ),
        SocketServerError::PeerCredentialDenied { peer_uid, daemon_uid } => typed_cli_error(
            LocketError::AccessDenied,
            format!(
                "peer uid {peer_uid} does not match daemon uid {daemon_uid}; refusing cross-user connection"
            ),
        ),
        // SocketPathTooWide is a configuration error (parent dir or
        // socket file has wider permissions than 0o700/0o600). The
        // closest existing typed variant is AgentSocketInUse, which is
        // imprecise — the path is not in use, it is misconfigured.
        // Adding `LocketError::AgentSocketParentTooPermissive` is
        // tracked as a follow-up (cross-crate change to
        // `locket-core::error` plus an exit-code-table entry). Until
        // then, the formatted message retains the offending mode and
        // path so users can act on it.
        SocketServerError::SocketPathTooWide { path, mode, expected } => typed_cli_error(
            LocketError::AgentSocketInUse,
            format!(
                "agent socket path {} has mode {mode:#o}; expected at most {expected:#o}",
                path.display()
            ),
        ),
        SocketServerError::Io(error) => CliError::Io(error),
    }
}

fn agent_logs_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &AgentLogsArgs,
) -> Result<(), CliError> {
    if args.lines > 10_000 {
        return Err(metadata_invalid_error("agent logs --lines is capped at 10000"));
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

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::sync::Arc;

    use locket_platform::{
        KeyringAutomationClientKeyStore, KeyringMasterKeyStore, PassphraseFallbackMasterKeyStore,
        UnavailableLocalUserVerifier,
    };
    use serde_json::json;
    use tempfile::{TempDir, tempdir};

    use super::*;
    use crate::runtime::prompts::{
        EnvOrPromptPassphraseReader, StdinConfirmationReader, StdinOrPromptSecretValueReader,
        TtyRecoveryCodeReader,
    };

    struct FakeLauncher {
        spawn_calls: Cell<usize>,
        status_ok: Cell<bool>,
        spawn_ok: bool,
    }

    impl FakeLauncher {
        const fn succeeding() -> Self {
            Self { spawn_calls: Cell::new(0), status_ok: Cell::new(true), spawn_ok: true }
        }

        const fn status_failing() -> Self {
            Self { spawn_calls: Cell::new(0), status_ok: Cell::new(false), spawn_ok: true }
        }

        fn spawn_calls(&self) -> usize {
            self.spawn_calls.get()
        }
    }

    impl AgentDaemonLauncher for FakeLauncher {
        fn spawn(&self, socket: &Path, pid_file: &Path) -> Result<(), CliError> {
            self.spawn_calls.set(self.spawn_calls.get() + 1);
            if !self.spawn_ok {
                return Err(typed_cli_error(locket_core::LocketError::AgentUnavailable, "spawn"));
            }
            if let Some(parent) = pid_file.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(pid_file, format!("{}\n", std::process::id()))?;
            fs::write(socket, b"")?;
            Ok(())
        }

        fn status_snapshot(&self, _socket: &Path) -> Result<Value, io::Error> {
            if self.status_ok.get() {
                Ok(json!({ "lock_state": "locked", "agent_version": "test" }))
            } else {
                Err(io::Error::other("unreachable"))
            }
        }
    }

    fn temp_context(directory: &TempDir) -> RuntimeContext {
        RuntimeContext {
            cwd: directory.path().to_path_buf(),
            store_path: directory.path().join("store.db"),
            config_path: directory.path().join("config.toml"),
            template_dir: directory.path().join(".locket").join("templates"),
            key_store: Arc::new(KeyringMasterKeyStore),
            automation_client_key_store: Arc::new(KeyringAutomationClientKeyStore),
            passphrase_store: PassphraseFallbackMasterKeyStore::new(
                directory.path().join("passphrase-fallback"),
            ),
            passphrase_reader: Arc::new(EnvOrPromptPassphraseReader),
            recovery_code_reader: Arc::new(TtyRecoveryCodeReader),
            confirmation_reader: Arc::new(StdinConfirmationReader),
            secret_value_reader: Arc::new(StdinOrPromptSecretValueReader),
            user_verifier: Arc::new(UnavailableLocalUserVerifier),
        }
    }

    #[test]
    fn on_demand_startup_spawns_once_then_reuses_running_agent()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let context = temp_context(&directory);
        let launcher = FakeLauncher::succeeding();

        let first = ensure_agent_running_with_launcher(&context, &launcher)?;
        assert_eq!(first, AgentStartupReport { started: true, pid: Some(std::process::id()) });
        assert_eq!(launcher.spawn_calls(), 1);

        let second = ensure_agent_running_with_launcher(&context, &launcher)?;
        assert_eq!(second, AgentStartupReport { started: false, pid: Some(std::process::id()) });
        assert_eq!(launcher.spawn_calls(), 1);
        Ok(())
    }

    #[test]
    fn on_demand_startup_fails_closed_when_spawned_agent_is_unreachable()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let context = temp_context(&directory);
        let launcher = FakeLauncher::status_failing();

        let error = ensure_agent_running_with_launcher(&context, &launcher)
            .expect_err("unreachable agent must fail closed");
        assert_eq!(launcher.spawn_calls(), 1);
        let CliError::Typed { kind, message } = error else {
            return Err("expected typed AgentUnavailable".into());
        };
        assert_eq!(kind, locket_core::LocketError::AgentUnavailable);
        assert!(message.contains("on-demand startup"));
        Ok(())
    }
}
