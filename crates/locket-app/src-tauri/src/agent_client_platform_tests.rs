//! Deterministic endpoint and polling regressions, without environment mutation.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;

use super::{AgentClientError, CancelToken, endpoint_from_inputs, poll_status_events_with};
use locket_agent::{LockState, StatusEvent, StatusPayload};
use tokio::sync::{Notify, mpsc};

#[test]
fn macos_default_endpoint_matches_cli_application_support_directory() {
    assert_eq!(
        endpoint_from_inputs(
            "macos",
            None,
            Path::new("/Users/fixture"),
            Some(OsStr::new("/ignored-runtime")),
            None
        ),
        PathBuf::from("/Users/fixture/Library/Application Support/locket/agent.sock")
    );
}

#[test]
fn linux_endpoint_uses_xdg_runtime_then_home_fallback() {
    let home = Path::new("/home/fixture");
    assert_eq!(
        endpoint_from_inputs("linux", None, home, Some(OsStr::new("/run/user/1000")), None),
        PathBuf::from("/run/user/1000/locket/agent.sock")
    );
    for runtime in [None, Some(OsStr::new(""))] {
        assert_eq!(
            endpoint_from_inputs("linux", None, home, runtime, None),
            home.join(".locket/agent.sock")
        );
    }
}

#[test]
fn explicit_endpoint_override_wins_on_every_platform_and_empty_override_is_ignored() {
    for platform in ["macos", "linux", "windows"] {
        assert_eq!(
            endpoint_from_inputs(
                platform,
                Some(OsStr::new("explicit-agent-endpoint")),
                Path::new("home"),
                None,
                None
            ),
            PathBuf::from("explicit-agent-endpoint")
        );
    }
    assert_eq!(
        endpoint_from_inputs("macos", Some(OsStr::new("")), Path::new("home"), None, None),
        PathBuf::from("home/Library/Application Support/locket/agent.sock")
    );
}

#[test]
fn windows_endpoint_uses_resolved_user_pipe_and_fails_closed_without_sid() {
    let pipe = Path::new(r"\\.\pipe\locket-agent-S-1-5-21-1000");
    assert_eq!(endpoint_from_inputs("windows", None, Path::new("home"), None, Some(pipe)), pipe);
    assert!(
        endpoint_from_inputs("windows", None, Path::new("home"), None, None).as_os_str().is_empty()
    );
}

#[tokio::test]
async fn status_polling_emits_real_snapshot_heartbeat_and_changed_status()
-> Result<(), Box<dyn std::error::Error>> {
    let mut locked = StatusPayload::locked("synthetic");
    locked.project_id = Some("project-fixture".into());
    let mut unlocked = locked.clone();
    unlocked.lock_state = LockState::Unlocked;
    unlocked.unlock_ttl_seconds = Some(37);
    let expected = unlocked.clone();
    let mut statuses = std::collections::VecDeque::from([locked.clone(), locked, unlocked]);
    let (sender, mut receiver) = mpsc::channel::<StatusEvent>(4);
    let cancel = CancelToken::new();
    let task_cancel = cancel.clone();
    let task = tokio::spawn(async move {
        poll_status_events_with(
            move || {
                std::future::ready(statuses.pop_front().ok_or_else(|| AgentClientError::Protocol {
                    reason: "fixture exhausted".into(),
                }))
            },
            sender,
            &task_cancel,
            Duration::from_millis(5),
        )
        .await
    });
    let first = tokio::time::timeout(Duration::from_secs(1), receiver.recv())
        .await?
        .ok_or("initial status missing")?;
    let second = tokio::time::timeout(Duration::from_secs(1), receiver.recv())
        .await?
        .ok_or("heartbeat missing")?;
    let third = tokio::time::timeout(Duration::from_secs(1), receiver.recv())
        .await?
        .ok_or("changed status missing")?;
    cancel.cancel();
    task.await??;
    assert!(first.is_state_change());
    assert!(second.is_heartbeat());
    assert!(third.is_state_change());
    assert_eq!(third.status, expected);
    assert!(first.sequence < second.sequence && second.sequence < third.sequence);
    Ok(())
}

#[tokio::test]
async fn polling_cancellation_interrupts_pending_rpc() -> Result<(), Box<dyn std::error::Error>> {
    let (sender, _receiver) = mpsc::channel(1);
    let cancel = CancelToken::new();
    let task_cancel = cancel.clone();
    let entered = Arc::new(Notify::new());
    let task_entered = Arc::clone(&entered);
    let task = tokio::spawn(async move {
        poll_status_events_with(
            move || {
                task_entered.notify_one();
                std::future::pending::<Result<StatusPayload, AgentClientError>>()
            },
            sender,
            &task_cancel,
            Duration::from_secs(30),
        )
        .await
    });
    tokio::time::timeout(Duration::from_secs(1), entered.notified()).await?;
    cancel.cancel();
    tokio::time::timeout(Duration::from_millis(100), task).await???;
    Ok(())
}

#[tokio::test]
async fn polling_cancellation_interrupts_full_event_queue() -> Result<(), Box<dyn std::error::Error>>
{
    let (sender, mut receiver) = mpsc::channel(1);
    let cancel = CancelToken::new();
    let task_cancel = cancel.clone();
    let calls = Arc::new(AtomicUsize::new(0));
    let task_calls = Arc::clone(&calls);
    let blocked = Arc::new(Notify::new());
    let task_blocked = Arc::clone(&blocked);
    let task = tokio::spawn(async move {
        poll_status_events_with(
            move || {
                if task_calls.fetch_add(1, Ordering::SeqCst) == 1 {
                    task_blocked.notify_one();
                }
                std::future::ready(Ok(StatusPayload::locked("synthetic")))
            },
            sender,
            &task_cancel,
            Duration::from_millis(1),
        )
        .await
    });
    tokio::time::timeout(Duration::from_secs(1), blocked.notified()).await?;
    cancel.cancel();
    tokio::time::timeout(Duration::from_millis(100), task).await???;
    assert!(receiver.recv().await.is_some());
    assert!(receiver.recv().await.is_none());
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    Ok(())
}

#[tokio::test]
async fn polling_propagates_rpc_failure_without_inventing_freshness() {
    let (sender, mut receiver) = mpsc::channel(1);
    let result = poll_status_events_with(
        || {
            std::future::ready(Err(AgentClientError::Protocol {
                reason: "synthetic failure".into(),
            }))
        },
        sender,
        &CancelToken::new(),
        Duration::from_millis(1),
    )
    .await;
    assert!(
        matches!(result, Err(AgentClientError::Protocol { reason }) if reason == "synthetic failure")
    );
    assert!(receiver.recv().await.is_none());
}
