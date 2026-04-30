//! Tauri 2 desktop shell entry point for Locket.
//!
//! Registers a minimal scoped IPC surface. Today only the `agent_status`
//! command is registered. Reveal/copy, scan, and policy surfaces ship in
//! later slices and each opt in to the smallest capability set they need.

#[cfg(debug_assertions)]
use tauri::Manager as _;

// Test-only dev-deps; suppress `unused_crate_dependencies` for the lib-test target.
#[cfg(test)]
use tempfile as _;

mod agent_client;
mod tray;

pub use agent_client::{AgentClientError, fetch_status, invoke_method, resolve_socket_path};
pub use tray::{
    LOCKET_TRAY_ID, TrayState, icon_bytes_for, setup_tray, tooltip_for, update_tray_state,
};

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
            agent_reveal,
            agent_copy,
            agent_scan,
            agent_resolve,
            agent_prepare_exec,
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
