//! Security-shape regressions for the Tauri 2 desktop shell.
//!
//! These tests pin the release Content-Security-Policy, the deny-by-default
//! capability set, and the empty IPC surface against the load-bearing
//! `ReleaseWebviewPolicy::default()` descriptor in `locket-app`. A future
//! change to either the Tauri config or the descriptor breaks here, in CI,
//! before the release build can drift.
#![allow(
    clippy::missing_docs_in_private_items,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc
)]

// Pull dev-deps into the integration test target so `unused_crate_dependencies`
// stays quiet for crates referenced only via path lookups below.
use locket_desktop_lib as _;
use tauri as _;

use std::fs;
use std::path::{Path, PathBuf};

use locket_app::ReleaseWebviewPolicy;
use serde_json::Value;

fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read_json(rel: &str) -> Value {
    let path: PathBuf = crate_root().join(rel);
    let raw =
        fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    serde_json::from_str(&raw).unwrap_or_else(|err| panic!("parse json {}: {err}", path.display()))
}

#[test]
fn release_csp_matches_release_webview_policy_default() {
    let conf = read_json("tauri.conf.json");
    let csp = conf
        .get("app")
        .and_then(|app| app.get("security"))
        .and_then(|sec| sec.get("csp"))
        .and_then(Value::as_str)
        .expect("tauri.conf.json missing app.security.csp");

    let expected = ReleaseWebviewPolicy::default().content_security_policy;
    assert_eq!(
        csp, expected,
        "tauri.conf.json release CSP must equal ReleaseWebviewPolicy::default().content_security_policy"
    );
}

#[test]
fn dev_csp_only_relaxes_localhost_hmr() {
    let conf = read_json("tauri.conf.json");
    let dev_csp = conf
        .get("app")
        .and_then(|app| app.get("security"))
        .and_then(|sec| sec.get("devCsp"))
        .and_then(Value::as_str)
        .expect("tauri.conf.json missing app.security.devCsp");

    // Vite HMR needs the dev server on localhost:1420; nothing else is allowed
    // beyond the release set.
    assert!(dev_csp.contains("ws://localhost:1420"));
    assert!(dev_csp.contains("http://localhost:1420"));
    // Dev relaxations beyond the localhost HMR socket would mean we drifted from
    // the release security posture without anyone noticing.
    assert!(!dev_csp.contains("https:"), "dev CSP must not allow remote https");
    assert!(!dev_csp.contains("http://*"), "dev CSP must not wildcard hosts");
    assert!(!dev_csp.contains("data: ws:"), "dev CSP must not allow arbitrary ws: connect-src",);
}

#[test]
fn main_window_metadata_is_present() {
    let conf = read_json("tauri.conf.json");
    let windows = conf
        .get("app")
        .and_then(|app| app.get("windows"))
        .and_then(Value::as_array)
        .expect("tauri.conf.json missing app.windows array");
    assert_eq!(windows.len(), 1, "shell ships exactly one main window");

    let window = &windows[0];
    assert_eq!(window.get("label").and_then(Value::as_str), Some("main"));
    assert_eq!(window.get("title").and_then(Value::as_str), Some("Locket"));
}

#[test]
fn capability_file_denies_default_and_lists_no_broad_permissions() {
    let cap = read_json("capabilities/desktop.json");
    let permissions = cap
        .get("permissions")
        .and_then(Value::as_array)
        .expect("capabilities/desktop.json missing permissions array");
    assert!(
        permissions.is_empty(),
        "deny-by-default capability set must register zero permissions",
    );

    let raw = fs::read_to_string(crate_root().join("capabilities/desktop.json"))
        .expect("re-read capability file");
    for forbidden in ["fs:", "shell:", "http:", "updater:", "clipboard:"] {
        assert!(
            !raw.contains(forbidden),
            "capability file must not enable {forbidden} permissions",
        );
    }
}

#[test]
fn lib_registers_no_commands_and_keeps_devtools_debug_only() {
    let path = crate_root().join("src/lib.rs");
    let source = fs::read_to_string(&path).expect("read src/lib.rs");

    assert!(
        source.contains("tauri::generate_handler![]"),
        "src/lib.rs must register an empty IPC surface",
    );

    // Look for the command attribute on non-doc-comment lines only.
    let attribute_marker = "#[tauri::command";
    let registered_command = source
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .any(|line| line.contains(attribute_marker));
    assert!(!registered_command, "tauri-shell slice must not register any tauri command handlers",);

    // open_devtools may exist but must be gated behind cfg(debug_assertions).
    if source.contains("open_devtools") {
        assert!(
            source.contains("cfg(debug_assertions)") || source.contains("debug_assertions"),
            "open_devtools must be gated behind cfg(debug_assertions)",
        );
    }
}

#[test]
fn frontend_dist_points_at_ui_build_output() {
    let conf = read_json("tauri.conf.json");
    let dist = conf
        .get("build")
        .and_then(|b| b.get("frontendDist"))
        .and_then(Value::as_str)
        .expect("tauri.conf.json missing build.frontendDist");
    assert_eq!(dist, "../ui/dist");

    let dev_url = conf
        .get("build")
        .and_then(|b| b.get("devUrl"))
        .and_then(Value::as_str)
        .expect("tauri.conf.json missing build.devUrl");
    assert_eq!(dev_url, "http://localhost:1420");
}

#[test]
fn ui_project_layout_is_present_on_disk() {
    let ui = crate_root().join("../ui");
    for required in [
        "package.json",
        "index.html",
        "vite.config.ts",
        "tsconfig.json",
        "src/main.ts",
        "src/App.vue",
    ] {
        let path: PathBuf = ui.join(required);
        assert!(
            <Path as AsRef<Path>>::as_ref(&path).exists(),
            "ui project missing {}",
            path.display(),
        );
    }
}
