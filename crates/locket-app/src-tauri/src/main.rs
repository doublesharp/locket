//! Locket desktop binary entry point.
//!
//! Hides the console subprocess on Windows release builds and delegates to
//! the library `run` function. Startup errors propagate as a non-zero exit.

#![cfg_attr(all(not(debug_assertions), target_os = "windows"), windows_subsystem = "windows")]

// Runtime + test deps consumed only via the lib crate trip
// `unused_crate_dependencies` at the bin boundary; pull each in
// explicitly so the lint stays quiet without disabling it.
use locket_agent as _;
use locket_app as _;
use serde as _;
use serde_json as _;
#[cfg(test)]
use tempfile as _;
use thiserror as _;
use tokio as _;

fn main() -> tauri::Result<()> {
    locket_desktop_lib::run()
}
