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
mod tray;

pub use agent_client::{
    AgentClientError, fetch_status, invoke_method, resolve_socket_path, stream_status_events,
};
pub use tray::{
    LOCKET_TRAY_ID, TRAY_MENU_ACTION_EVENT, TrayMenuAction, TrayState, icon_bytes_for, setup_tray,
    tooltip_for, tray_menu_action_for_id, tray_menu_actions, tray_state_for_status,
    tray_state_for_status_event, update_tray_state,
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
            agent_reveal,
            agent_copy,
            agent_scan,
            agent_resolve,
            agent_prepare_exec,
            agent_list_runtime_sessions,
            agent_list_secrets,
            agent_read_config,
            agent_write_config,
            agent_list_audit,
            agent_verify_audit,
            agent_list_versions,
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
