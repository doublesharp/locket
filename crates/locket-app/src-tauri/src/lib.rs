//! Tauri 2 desktop shell entry point for Locket.
//!
//! This crate intentionally registers no `#[tauri::command]` handlers and
//! ships an empty capability set. Reveal/copy, status, and agent-RPC
//! surfaces land in their own slices on top of this shell.

#[cfg(debug_assertions)]
use tauri::Manager as _;

// Test-only dev-deps; suppress `unused_crate_dependencies` for the lib-test target.
#[cfg(test)]
use locket_app as _;
#[cfg(test)]
use serde_json as _;

/// Run the Locket desktop application.
///
/// Builds the Tauri 2 app, registers an empty IPC handler, and — in debug
/// builds only — opens devtools on the main window. Returns the Tauri
/// result so the binary entry point can surface a non-zero exit on
/// startup failure.
///
/// # Errors
///
/// Returns any error produced by Tauri while building or running the
/// application.
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() -> tauri::Result<()> {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![])
        .setup(|_app| {
            #[cfg(debug_assertions)]
            {
                if let Some(window) = _app.get_webview_window("main") {
                    window.open_devtools();
                }
            }
            Ok(())
        })
        .run(tauri::generate_context!())
}
