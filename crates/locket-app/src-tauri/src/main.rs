//! Locket desktop binary entry point.
//!
//! Hides the console subprocess on Windows release builds and delegates to
//! the library `run` function. Startup errors propagate as a non-zero exit.

#![cfg_attr(all(not(debug_assertions), target_os = "windows"), windows_subsystem = "windows")]

// Test-only dev-deps would otherwise trigger `unused_crate_dependencies` here.
#[cfg(test)]
use locket_app as _;
#[cfg(test)]
use serde_json as _;

fn main() -> tauri::Result<()> {
    locket_desktop_lib::run()
}
