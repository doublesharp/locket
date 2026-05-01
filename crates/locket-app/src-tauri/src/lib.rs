//! Tauri 2 desktop shell entry point for Locket.
//!
//! Registers a minimal scoped IPC surface. Each command opts in to the
//! smallest capability set needed for metadata-only desktop views and
//! agent-backed actions.

use std::path::PathBuf;

use directories::ProjectDirs;
use serde::Deserialize;

use tauri::Emitter as _;
#[cfg(debug_assertions)]
use tauri::Manager as _;

// Test-only dev-deps; suppress `unused_crate_dependencies` for the lib-test target.
#[cfg(test)]
use locket_store as _;
#[cfg(test)]
use tempfile as _;

mod agent_client;
mod clipboard;
mod tray;

pub use agent_client::{
    AgentClientError, fetch_status, invoke_method, resolve_socket_path, stream_status_events,
};
pub use clipboard::{
    ClipboardCopyDecision, ClipboardCopyOutcome, ClipboardError, ClipboardPlatform,
    ClipboardSession, clipboard_platform, decide_clear,
};
pub use tray::{
    LOCKET_TRAY_ID, TRAY_MENU_ACTION_EVENT, TrayMenuAction, TrayMenuSideEffect, TrayState,
    icon_bytes_for, setup_tray, tooltip_for, tray_menu_action_for_id, tray_menu_action_side_effect,
    tray_menu_action_view, tray_menu_actions, tray_state_for_status, tray_state_for_status_event,
    update_tray_state,
};

const CONFIG_TOML: &str = "config.toml";

#[derive(Deserialize)]
struct DesktopListSecretsRequest {
    store_path: Option<PathBuf>,
    project_id: String,
    profile_id: String,
    #[serde(default)]
    redact_names: bool,
}

#[derive(Deserialize)]
struct DesktopListDeviceMembersRequest {
    store_path: Option<PathBuf>,
    project_id: String,
    #[serde(default)]
    redact_names: bool,
    #[serde(default = "default_true")]
    include_revoked_devices: bool,
}

#[derive(Debug, Deserialize)]
struct DesktopReadConfigRequest {
    config_path: Option<PathBuf>,
    store_path: Option<PathBuf>,
    project_id: Option<String>,
    profile_name: Option<String>,
}

impl DesktopReadConfigRequest {
    fn into_agent_request(self) -> Result<locket_agent::ReadConfigRequest, AgentClientError> {
        Ok(locket_agent::ReadConfigRequest {
            config_path: self.config_path.unwrap_or(default_config_path()?),
            store_path: self.store_path,
            project_id: self.project_id,
            profile_name: self.profile_name,
        })
    }
}

#[derive(Debug, Deserialize)]
struct DesktopWriteConfigRequest {
    config_path: Option<PathBuf>,
    store_path: Option<PathBuf>,
    project_id: String,
    profile_name: Option<String>,
    #[serde(default)]
    changes: locket_agent::WriteConfigChanges,
}

impl DesktopWriteConfigRequest {
    fn into_agent_request(self) -> Result<locket_agent::WriteConfigRequest, AgentClientError> {
        Ok(locket_agent::WriteConfigRequest {
            config_path: self.config_path.unwrap_or(default_config_path()?),
            store_path: self.store_path.unwrap_or(default_store_path()?),
            project_id: self.project_id,
            profile_name: self.profile_name,
            changes: self.changes,
        })
    }
}

/// Desktop-side audit-list request.
///
/// Mirrors `locket_agent::ListAuditRequest`, but lets the webview omit
/// `store_path` so the shell can use the same default store location as
/// the CLI without exposing local filesystem details to the frontend.
#[derive(Debug, Deserialize)]
struct DesktopListAuditRequest {
    /// Optional explicit SQLite store path for tests or advanced shells.
    store_path: Option<PathBuf>,
    /// Project id whose audit chain is listed.
    project_id: String,
    /// Optional profile id filter.
    profile_id: Option<String>,
    /// Optional audit action filter.
    action: Option<String>,
    /// Optional audit status filter.
    status: Option<String>,
    /// Optional inclusive lower timestamp bound.
    since_unix_nanos: Option<i64>,
    /// Optional inclusive upper timestamp bound.
    until_unix_nanos: Option<i64>,
    /// Maximum number of recent matching rows.
    limit: Option<u32>,
    /// Whether project/profile/secret/command labels should be aliased.
    #[serde(default)]
    redact_names: bool,
}

#[derive(Debug, Deserialize)]
struct DesktopListVersionsRequest {
    store_path: Option<PathBuf>,
    project_id: String,
    profile_id: String,
    secret_name: Option<String>,
    source: Option<String>,
    now_unix_nanos: i64,
    #[serde(default)]
    redact_names: bool,
}

impl DesktopListAuditRequest {
    fn into_agent_request(self) -> Result<locket_agent::ListAuditRequest, AgentClientError> {
        let store_path = match self.store_path {
            Some(path) => path,
            None => default_store_path()?,
        };
        Ok(locket_agent::ListAuditRequest {
            store_path,
            project_id: self.project_id,
            profile_id: self.profile_id,
            action: self.action,
            status: self.status,
            since_unix_nanos: self.since_unix_nanos,
            until_unix_nanos: self.until_unix_nanos,
            limit: self.limit,
            redact_names: self.redact_names,
        })
    }
}

fn project_dirs() -> Result<ProjectDirs, AgentClientError> {
    ProjectDirs::from("dev", "0xdoublesharp", "Locket").ok_or_else(|| AgentClientError::Protocol {
        reason: "could not resolve the default Locket data directory".to_owned(),
    })
}

fn default_config_path() -> Result<PathBuf, AgentClientError> {
    Ok(project_dirs()?.config_dir().join(CONFIG_TOML))
}

fn default_store_path() -> Result<PathBuf, AgentClientError> {
    Ok(project_dirs()?.data_dir().join("store.db"))
}

const fn default_true() -> bool {
    true
}

const AGENT_STATUS_EVENT: &str = "agent-status";
const AGENT_STATUS_ERROR_EVENT: &str = "agent-status-error";

/// Tauri command exposing the agent client to the webview.
///
/// Honors `LOCKET_AGENT_SOCKET` for the socket path, falls back to the
/// user-default `~/.locket/agent.sock`, and returns either a metadata-only
/// status payload or a typed [`AgentClientError`].
#[tauri::command]
async fn agent_status() -> Result<locket_agent::StatusPayload, AgentClientError> {
    let path = agent_client::resolve_socket_path();
    agent_client::fetch_status(&path).await
}

/// Tauri command bridging `SubscribeStatus` stream frames to webview events.
#[tauri::command]
async fn agent_subscribe_status(app: tauri::AppHandle) -> Result<(), AgentClientError> {
    let path = agent_client::resolve_socket_path();
    let (sender, mut receiver) = tokio::sync::mpsc::channel::<locket_agent::StatusEvent>(16);
    let event_app = app.clone();
    tauri::async_runtime::spawn(async move {
        while let Some(event) = receiver.recv().await {
            let _emit_result = event_app.emit(AGENT_STATUS_EVENT, &event);
        }
    });
    tauri::async_runtime::spawn(async move {
        if let Err(error) = agent_client::stream_status_events(&path, sender).await {
            let _emit_result = app.emit(AGENT_STATUS_ERROR_EVENT, &error);
        }
    });
    Ok(())
}

/// Tauri command exposing the agent's `Lock` RPC to the webview and tray.
#[tauri::command]
async fn agent_lock() -> Result<(), AgentClientError> {
    let path = agent_client::resolve_socket_path();
    agent_client::invoke_method(&path, locket_agent::AgentMethod::Lock, &()).await
}

/// Source describing how the agent should derive the unwrapped key.
///
/// Stays distinct from the agent's wire format so we can grow the set
/// of unlock paths without leaking key material to the webview. Only
/// `passphrase` is wired today; the other variants are placeholders for
/// later slices and currently surface a typed `unsupported-source`
/// protocol error.
#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
enum UnlockSource {
    Passphrase {
        passphrase: String,
    },
    Recovery {
        #[allow(dead_code)]
        recovery: String,
    },
    OsKeychain,
}

#[derive(Debug, Deserialize)]
struct DesktopUnlockAudit {
    store_path: Option<PathBuf>,
    profile_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct DesktopUnlockRequest {
    project_id: String,
    ttl_seconds: u64,
    source: UnlockSource,
    #[serde(default)]
    audit: Option<DesktopUnlockAudit>,
}

/// Tauri command exposing the agent's `Unlock` RPC behind a passphrase
/// fallback. The agent owns the unwrap path: it pulls the master key
/// from the OS keychain when no passphrase is supplied, and from the
/// passphrase-fallback envelope otherwise. The webview never holds the
/// unwrapped key.
#[tauri::command]
async fn agent_unlock(request: DesktopUnlockRequest) -> Result<(), AgentClientError> {
    let passphrase: Option<String> = match request.source {
        UnlockSource::Passphrase { passphrase } => Some(passphrase),
        UnlockSource::OsKeychain => None,
        UnlockSource::Recovery { .. } => {
            return Err(AgentClientError::Protocol {
                reason: "unsupported unlock source".to_owned(),
            });
        }
    };
    let mut payload = serde_json::json!({
        "project_id": request.project_id,
        "ttl_seconds": request.ttl_seconds,
    });
    if let Some(passphrase) = passphrase {
        payload["passphrase"] = serde_json::json!(passphrase);
        payload["method"] = serde_json::json!("passphrase");
    }
    if let Some(audit) = request.audit {
        let mut audit_value = serde_json::json!({});
        if let Some(store_path) = audit.store_path {
            audit_value["store_path"] = serde_json::json!(store_path.display().to_string());
        }
        if let Some(profile_id) = audit.profile_id {
            audit_value["profile_id"] = serde_json::json!(profile_id);
        }
        payload["audit"] = audit_value;
    }
    let path = agent_client::resolve_socket_path();
    agent_client::invoke_method(&path, locket_agent::AgentMethod::Unlock, &payload).await
}

#[derive(Debug, Deserialize)]
struct DesktopSetActiveProfileRequest {
    config_path: Option<PathBuf>,
    store_path: Option<PathBuf>,
    project_id: String,
    profile_name: String,
    confirmation: Option<String>,
    #[serde(default)]
    privacy_redact_names: bool,
    root_hash: Option<String>,
}

/// Tauri command exposing the agent's `SetActiveProfile` RPC.
#[tauri::command]
async fn agent_set_active_profile(
    request: DesktopSetActiveProfileRequest,
) -> Result<locket_agent::SetActiveProfileResponse, AgentClientError> {
    let path = agent_client::resolve_socket_path();
    let agent_request = locket_agent::SetActiveProfileRequest {
        config_path: request.config_path.unwrap_or(default_config_path()?),
        store_path: request.store_path.unwrap_or(default_store_path()?),
        project_id: request.project_id,
        profile_name: request.profile_name,
        confirmation: request.confirmation,
        privacy_redact_names: request.privacy_redact_names,
        root_hash: request.root_hash,
    };
    agent_client::invoke_method(&path, locket_agent::AgentMethod::SetActiveProfile, &agent_request)
        .await
}

/// Tauri command exposing the agent's `Reveal` RPC to the webview.
///
/// Today the agent stub returns `UnlockRequired`; the webview's reveal
/// modal renders that as a typed denial without ever holding plaintext.
/// Real value-returning behavior lands once the agent unlock cache and
/// grant table ship.
#[tauri::command]
async fn agent_reveal(
    request: locket_agent::RevealRequest,
) -> Result<locket_agent::RevealResponse, AgentClientError> {
    let path = agent_client::resolve_socket_path();
    agent_client::invoke_method(&path, locket_agent::AgentMethod::Reveal, &request).await
}

/// Tauri command exposing the agent's `Copy` RPC to the webview.
#[tauri::command]
async fn agent_copy(
    request: locket_agent::CopyRequest,
) -> Result<locket_agent::CopyResponse, AgentClientError> {
    let path = agent_client::resolve_socket_path();
    agent_client::invoke_method(&path, locket_agent::AgentMethod::Copy, &request).await
}

/// Tauri command exposing the agent's `ScanKnownValues` RPC.
#[tauri::command]
async fn agent_scan(
    request: locket_agent::ScanRequest,
) -> Result<locket_agent::ScanResponse, AgentClientError> {
    let path = agent_client::resolve_socket_path();
    agent_client::invoke_method(&path, locket_agent::AgentMethod::ScanKnownValues, &request).await
}

/// Tauri command exposing the agent's `ResolveReference` RPC.
#[tauri::command]
async fn agent_resolve(
    request: locket_agent::ResolveRequest,
) -> Result<locket_agent::ResolveResponse, AgentClientError> {
    let path = agent_client::resolve_socket_path();
    agent_client::invoke_method(&path, locket_agent::AgentMethod::ResolveReference, &request).await
}

/// Tauri command exposing the agent's `PrepareExec` RPC.
#[tauri::command]
async fn agent_prepare_exec(
    request: locket_agent::PrepareExecRequest,
) -> Result<locket_agent::PrepareExecResponse, AgentClientError> {
    let path = agent_client::resolve_socket_path();
    agent_client::invoke_method(&path, locket_agent::AgentMethod::PrepareExec, &request).await
}

/// Tauri command exposing the agent's metadata-only runtime session list.
#[tauri::command]
async fn agent_list_runtime_sessions(
    request: locket_agent::ListRuntimeSessionsRequest,
) -> Result<locket_agent::ListRuntimeSessionsResponse, AgentClientError> {
    let path = agent_client::resolve_socket_path();
    agent_client::invoke_method(&path, locket_agent::AgentMethod::ListRuntimeSessions, &request)
        .await
}

/// Tauri command exposing the agent's metadata-only saved policy list.
#[tauri::command]
async fn agent_list_policies(
    request: locket_agent::ListPoliciesRequest,
) -> Result<locket_agent::ListPoliciesResponse, AgentClientError> {
    let path = agent_client::resolve_socket_path();
    agent_client::invoke_method(&path, locket_agent::AgentMethod::ListPolicies, &request).await
}

/// Tauri command exposing the agent's metadata-only device/member directory.
#[tauri::command]
async fn agent_list_device_members(
    request: DesktopListDeviceMembersRequest,
) -> Result<locket_agent::ListDeviceMembersResponse, AgentClientError> {
    let path = agent_client::resolve_socket_path();
    let store_path = match request.store_path {
        Some(path) => path,
        None => default_store_path()?,
    };
    let request = locket_agent::ListDeviceMembersRequest {
        store_path,
        project_id: request.project_id,
        redact_names: request.redact_names,
        include_revoked_devices: request.include_revoked_devices,
    };
    agent_client::invoke_method(&path, locket_agent::AgentMethod::ListDeviceMembers, &request).await
}

/// Tauri command exposing the agent's metadata-only active-profile secret list.
#[tauri::command]
async fn agent_list_secrets(
    request: DesktopListSecretsRequest,
) -> Result<locket_agent::ListSecretsResponse, AgentClientError> {
    let path = agent_client::resolve_socket_path();
    let store_path = match request.store_path {
        Some(path) => path,
        None => default_store_path()?,
    };
    let request = locket_agent::ListSecretsRequest {
        store_path,
        project_id: request.project_id,
        profile_id: request.profile_id,
        redact_names: request.redact_names,
    };
    agent_client::invoke_method(&path, locket_agent::AgentMethod::ListSecrets, &request).await
}

/// Tauri command exposing metadata-only desktop settings.
#[tauri::command]
async fn agent_read_config(
    request: DesktopReadConfigRequest,
) -> Result<locket_agent::AgentConfigSettings, AgentClientError> {
    let request = request.into_agent_request()?;
    let path = agent_client::resolve_socket_path();
    agent_client::invoke_method(&path, locket_agent::AgentMethod::ReadConfig, &request).await
}

/// Tauri command writing desktop settings through the agent.
#[tauri::command]
async fn agent_write_config(
    request: DesktopWriteConfigRequest,
) -> Result<locket_agent::WriteConfigResponse, AgentClientError> {
    let request = request.into_agent_request()?;
    let path = agent_client::resolve_socket_path();
    agent_client::invoke_method(&path, locket_agent::AgentMethod::WriteConfig, &request).await
}

#[derive(Deserialize)]
struct DesktopVerifyAuditRequest {
    project_id: String,
}

/// Tauri command exposing the agent's metadata-only audit list.
#[tauri::command]
async fn agent_list_audit(
    request: DesktopListAuditRequest,
) -> Result<locket_agent::ListAuditResponse, AgentClientError> {
    let request = request.into_agent_request()?;
    let path = agent_client::resolve_socket_path();
    agent_client::invoke_method(&path, locket_agent::AgentMethod::ListAudit, &request).await
}

/// Tauri command exposing read-only audit chain verification.
#[tauri::command]
async fn agent_verify_audit(
    request: DesktopVerifyAuditRequest,
) -> Result<locket_agent::VerifyAuditResponse, AgentClientError> {
    let path = agent_client::resolve_socket_path();
    let request = locket_agent::VerifyAuditRequest {
        store_path: default_store_path()?,
        project_id: request.project_id,
    };
    agent_client::invoke_method(&path, locket_agent::AgentMethod::VerifyAudit, &request).await
}

/// Tauri command exposing the agent's metadata-only secret version history.
#[tauri::command]
async fn agent_list_versions(
    request: DesktopListVersionsRequest,
) -> Result<locket_agent::ListVersionsResponse, AgentClientError> {
    let path = agent_client::resolve_socket_path();
    let store_path = match request.store_path {
        Some(path) => path,
        None => default_store_path()?,
    };
    let request = locket_agent::ListVersionsRequest {
        store_path,
        project_id: request.project_id,
        profile_id: request.profile_id,
        secret_name: request.secret_name,
        source: request.source,
        now_unix_nanos: request.now_unix_nanos,
        redact_names: request.redact_names,
    };
    agent_client::invoke_method(&path, locket_agent::AgentMethod::ListVersions, &request).await
}

#[derive(Debug, Deserialize)]
struct DesktopClipboardCopyRequest {
    secret_name: String,
    profile_id: String,
    project_id: Option<String>,
    store_path: Option<PathBuf>,
    grant_id: Option<String>,
    ttl_seconds: Option<u32>,
}

#[derive(Debug, serde::Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
enum DesktopClipboardCopyResponse {
    Copied {
        ttl_seconds: u32,
    },
    Unsupported {
        unsupported_reason: String,
    },
}

/// Tauri `agent_copy_secret` command. Calls the agent `Copy` RPC,
/// writes the returned value to the OS clipboard, and schedules a
/// TTL-bound clear that re-reads the clipboard before wiping anything.
/// Returns an `unsupported` shape on Wayland sessions and skips the
/// timer.
#[tauri::command]
async fn agent_copy_secret(
    request: DesktopClipboardCopyRequest,
) -> Result<DesktopClipboardCopyResponse, AgentClientError> {
    if matches!(clipboard::clipboard_platform(), clipboard::ClipboardPlatform::Wayland) {
        return Ok(DesktopClipboardCopyResponse::Unsupported {
            unsupported_reason: "wayland-session".to_owned(),
        });
    }
    let path = agent_client::resolve_socket_path();
    let agent_request = locket_agent::CopyRequest {
        secret_name: request.secret_name,
        profile_id: request.profile_id,
        project_id: request.project_id,
        store_path: request.store_path,
        grant_id: request.grant_id,
        binding: None,
    };
    let response: locket_agent::CopyResponse = agent_client::invoke_method(
        &path,
        locket_agent::AgentMethod::Copy,
        &agent_request,
    )
    .await?;
    let ttl_seconds = request.ttl_seconds.unwrap_or(response.ttl_seconds.max(1));
    if let Err(error) = clipboard::write_clipboard(&response.value) {
        return Err(AgentClientError::Protocol {
            reason: format!("clipboard write failed: {error}"),
        });
    }
    let value_for_timer = response.value;
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(u64::from(ttl_seconds))).await;
        let current = clipboard::read_clipboard().ok();
        if matches!(
            clipboard::decide_clear(current.as_deref(), &value_for_timer),
            clipboard::ClipboardCopyDecision::Clear,
        ) {
            let _ = clipboard::clear_clipboard();
        }
    });
    Ok(DesktopClipboardCopyResponse::Copied { ttl_seconds })
}

/// Tauri command pushing a new tray icon state from the webview.
///
/// The frontend's `useTray` composable derives the desired
/// [`TrayState`] from `AgentStatus` and `AgentClientError` and invokes
/// this command on every change. Returns a string error rather than a
/// typed [`AgentClientError`] because tray failures are local rendering
/// faults, not agent protocol faults.
#[tauri::command]
async fn tray_set_state(app: tauri::AppHandle, state: TrayState) -> Result<(), String> {
    tray::update_tray_state(&app, state.into()).map_err(|error| error.to_string())
}

/// Run the Locket desktop application.
///
/// Builds the Tauri 2 app, registers the scoped IPC handlers, sets up
/// the system tray, and — in debug builds only — opens devtools on the
/// main window. Returns the Tauri result so the binary entry point can
/// surface a non-zero exit on startup failure.
///
/// # Errors
///
/// Returns any error produced by Tauri while building or running the
/// application.
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() -> tauri::Result<()> {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            agent_status,
            agent_subscribe_status,
            agent_lock,
            agent_unlock,
            agent_set_active_profile,
            agent_reveal,
            agent_copy,
            agent_scan,
            agent_resolve,
            agent_prepare_exec,
            agent_list_runtime_sessions,
            agent_list_policies,
            agent_list_device_members,
            agent_list_secrets,
            agent_read_config,
            agent_write_config,
            agent_list_audit,
            agent_verify_audit,
            agent_list_versions,
            agent_copy_secret,
            tray_set_state,
        ])
        .setup(|app| {
            #[cfg(debug_assertions)]
            {
                if let Some(window) = app.get_webview_window("main") {
                    window.open_devtools();
                }
            }
            tray::setup_tray(app.handle())?;
            Ok(())
        })
        .run(tauri::generate_context!())
}
