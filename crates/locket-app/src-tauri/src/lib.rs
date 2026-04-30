//! Tauri 2 desktop shell entry point for Locket.
//!
//! Registers a minimal scoped IPC surface. Each command opts in to the
//! smallest capability set needed for metadata-only desktop views and
//! agent-backed actions.

use std::path::PathBuf;

use directories::ProjectDirs;

#[cfg(debug_assertions)]
use tauri::Manager as _;

// Test-only dev-deps; suppress `unused_crate_dependencies` for the lib-test target.
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

#[derive(serde::Deserialize)]
struct DesktopListSecretsRequest {
    store_path: Option<PathBuf>,
    project_id: String,
    profile_id: String,
    #[serde(default)]
    redact_names: bool,
}

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

fn default_store_path() -> Result<PathBuf, AgentClientError> {
    let Some(project_dirs) = ProjectDirs::from("dev", "0xdoublesharp", "Locket") else {
        return Err(AgentClientError::Protocol {
            reason: "could not resolve Locket data directory".to_owned(),
        });
    };
    Ok(project_dirs.data_dir().join("store.db"))
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
            agent_lock,
            agent_reveal,
            agent_copy,
            agent_scan,
            agent_resolve,
            agent_prepare_exec,
            agent_list_runtime_sessions,
            agent_list_secrets,
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
