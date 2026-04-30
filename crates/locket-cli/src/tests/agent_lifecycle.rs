//! Focused regression test for the agent process supervisor.
//!
//! `agent_start_command` execs `current_exe()` to spawn the daemon. In
//! `cargo test` the test harness binary is `current_exe()`, so a true
//! end-to-end test of the parent-spawns-child dance is not possible
//! from inside the test crate. Instead, we exercise the daemon entry
//! point (`run_internal_agent_serve`) directly: bind a socket on a
//! background thread, drive a `Status` request through the same Unix
//! socket the CLI would use, then signal the thread to exit via
//! SIGTERM and verify that the socket and pid file are cleaned up.

#[allow(unused_imports)]
use super::*;

use std::time::{Duration, Instant};

#[cfg(unix)]
#[test]
fn run_internal_agent_serve_listens_and_cleans_up_on_sigterm()
-> Result<(), Box<dyn std::error::Error>> {
    use locket_agent::{
        AgentMethod, DEFAULT_MAX_MESSAGE_SIZE, RequestEnvelope, ResponseEnvelope,
        decode_response_frame, encode_frame,
    };
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    use std::os::unix::fs::PermissionsExt;

    let directory = tempdir()?;
    // Use a short directory name to keep the AF_UNIX path under sun_path
    // limits on macOS (~104 bytes).
    let agent_dir = directory.path().join("a");
    fs::create_dir_all(&agent_dir)?;
    // bind_socket_listener refuses parent dirs with mode beyond 0o700,
    // so tighten the permissions before the daemon thread starts.
    fs::set_permissions(&agent_dir, fs::Permissions::from_mode(0o700))?;
    let socket_path = agent_dir.join("agent.sock");
    let pid_path = agent_dir.join("agent.pid");

    let serve_socket = socket_path.clone();
    let serve_pid = pid_path.clone();
    let serve_thread = std::thread::spawn(move || -> Result<(), crate::CliError> {
        let args = crate::InternalAgentServeArgs { socket: serve_socket, pid_file: serve_pid };
        crate::commands::agent::run_internal_agent_serve(&args)
    });

    // Wait for the daemon to bind its socket (up to ~3s).
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        if socket_path.exists() && pid_path.exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    assert!(socket_path.exists(), "agent did not bind socket within deadline");
    assert!(pid_path.exists(), "agent did not write pid file within deadline");

    // The pid file should record this process's pid (the daemon shares
    // the test process when invoked directly).
    let pid_text = fs::read_to_string(&pid_path)?;
    let recorded_pid: u32 = pid_text.trim().parse()?;
    assert_eq!(recorded_pid, std::process::id(), "pid file should record current process");

    // Drive a Status request through the socket using a blocking client
    // so we don't have to spin up another tokio runtime in the test.
    let mut stream = UnixStream::connect(&socket_path)?;
    let request = RequestEnvelope::new("status-test", AgentMethod::Status, serde_json::Value::Null);
    let frame = encode_frame(&request, DEFAULT_MAX_MESSAGE_SIZE)?;
    stream.write_all(&frame)?;
    stream.flush()?;

    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 1024];
    loop {
        if let Ok((response, _)) = decode_response_frame(&buffer, DEFAULT_MAX_MESSAGE_SIZE) {
            match response {
                ResponseEnvelope::Success(success) => {
                    let snapshot = success.payload;
                    let lock_state =
                        snapshot.get("lock_state").and_then(|v| v.as_str()).unwrap_or("");
                    assert_eq!(lock_state, "locked", "expected locked state, got {snapshot}");
                    assert!(snapshot.get("agent_version").is_some(), "missing agent_version");
                    break;
                }
                ResponseEnvelope::Error(error) => {
                    return Err(format!(
                        "agent returned error: {} ({})",
                        error.error, error.message
                    )
                    .into());
                }
            }
        }
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            return Err("agent closed connection without a response".into());
        }
        buffer.extend_from_slice(&chunk[..read]);
    }
    drop(stream);

    // Send SIGTERM to ourselves; the daemon's signal handler will pick
    // it up because the test process is the daemon process.
    let our_pid =
        rustix::process::Pid::from_raw(i32::try_from(std::process::id())?).ok_or("invalid pid")?;
    rustix::process::kill_process(our_pid, rustix::process::Signal::TERM)?;

    // Wait for the serve thread to drain.
    let join_deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < join_deadline {
        if serve_thread.is_finished() {
            break;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    assert!(serve_thread.is_finished(), "serve thread did not exit after SIGTERM");
    serve_thread.join().map_err(|_| "serve thread panicked")??;

    assert!(!socket_path.exists(), "socket should be removed on shutdown");
    assert!(!pid_path.exists(), "pid file should be removed on shutdown");
    Ok(())
}
