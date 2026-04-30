//! Tauri 2 system tray binding for the Locket desktop shell.
//!
//! This slice only registers the tray icon, an empty menu, and a way to
//! push state updates from the rest of the app. Menu actions, click
//! routing, and notification dispatch land in later slices. Per the
//! desktop tray privacy spec the registered surface is metadata-only:
//! tooltip text comes from `TrayIconState::descriptor().label`, which is
//! a fixed, name-free string.
//!
//! Asset selection mirrors `tray_icon_asset_styles_for_os`:
//!
//! - macOS uses a single template (alpha-mask) variant — the OS picks
//!   the right rendering for light or dark menu bar modes.
//! - Windows and Linux use full-color variants and pick `light` or
//!   `dark` based on the main webview theme, defaulting to `dark`.
//!
//! Placeholder PNG bytes are emitted by `build.rs` into `OUT_DIR` and
//! baked into the binary via `include_bytes!`. A later slice swaps in
//! Lucide-derived final assets without touching this module.
#![allow(clippy::missing_panics_doc)]

use locket_app::TrayIconState;
use serde::{Deserialize, Serialize};
use tauri::image::Image;
use tauri::menu::Menu;
use tauri::tray::TrayIconBuilder;
use tauri::{AppHandle, Manager, Runtime};

/// Stable identifier used to look up the registered tray icon.
pub const LOCKET_TRAY_ID: &str = "locket";

// macOS template (alpha-mask) variants.
const MACOS_AGENT_UNLOCKED: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/tray/macos/agent-unlocked.png"));
const MACOS_AGENT_LOCKED: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/tray/macos/agent-locked.png"));
const MACOS_AGENT_STOPPED: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/tray/macos/agent-stopped.png"));
const MACOS_SCAN_WARNING: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/tray/macos/scan-warning.png"));
const MACOS_ERROR_DEGRADED: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/tray/macos/error-degraded.png"));

// Light-theme full-color variants (Windows / Linux).
const LIGHT_AGENT_UNLOCKED: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/tray/light/agent-unlocked.png"));
const LIGHT_AGENT_LOCKED: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/tray/light/agent-locked.png"));
const LIGHT_AGENT_STOPPED: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/tray/light/agent-stopped.png"));
const LIGHT_SCAN_WARNING: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/tray/light/scan-warning.png"));
const LIGHT_ERROR_DEGRADED: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/tray/light/error-degraded.png"));

// Dark-theme full-color variants (Windows / Linux).
const DARK_AGENT_UNLOCKED: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/tray/dark/agent-unlocked.png"));
const DARK_AGENT_LOCKED: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/tray/dark/agent-locked.png"));
const DARK_AGENT_STOPPED: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/tray/dark/agent-stopped.png"));
const DARK_SCAN_WARNING: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/tray/dark/scan-warning.png"));
const DARK_ERROR_DEGRADED: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/tray/dark/error-degraded.png"));

/// Wire-shape tray state used by the `tray_set_state` Tauri command.
///
/// Mirrors `TrayIconState` with kebab-case variant names so the
/// frontend composable can call `invoke('tray_set_state', { state: '...' })`
/// using the same vocabulary as `tray_icon_descriptors()`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TrayState {
    /// Agent reachable and vault unlocked.
    AgentUnlocked,
    /// Agent reachable and vault locked.
    AgentLocked,
    /// No reachable agent.
    AgentStopped,
    /// One or more unresolved scan warnings.
    ScanWarning,
    /// Agent error or degraded hardening state.
    ErrorDegraded,
}

impl From<TrayState> for TrayIconState {
    fn from(value: TrayState) -> Self {
        match value {
            TrayState::AgentUnlocked => Self::AgentUnlocked,
            TrayState::AgentLocked => Self::AgentLocked,
            TrayState::AgentStopped => Self::AgentStopped,
            TrayState::ScanWarning => Self::ScanWarning,
            TrayState::ErrorDegraded => Self::ErrorDegraded,
        }
    }
}

/// Pure mapping from a tray icon state to the baked-in PNG bytes for
/// the current platform. Exposed as a `pub` helper so the integration
/// tests can assert on it without spinning up a full Tauri runtime.
#[must_use]
pub fn icon_bytes_for(state: TrayIconState) -> &'static [u8] {
    if cfg!(target_os = "macos") {
        macos_bytes(state)
    } else {
        // Without a webview to consult we default to the dark variant.
        // `update_tray_state` overrides this when a `WebviewWindow` is
        // available and reports a concrete theme.
        dark_bytes(state)
    }
}

/// Pure mapping from a tray icon state to its tooltip string. Sourced
/// from `TrayIconState::descriptor().label` so the metadata-only spec
/// stays the single source of truth for tray copy.
#[must_use]
pub fn tooltip_for(state: TrayIconState) -> &'static str {
    state.descriptor().label
}

const fn macos_bytes(state: TrayIconState) -> &'static [u8] {
    match state {
        TrayIconState::AgentUnlocked => MACOS_AGENT_UNLOCKED,
        TrayIconState::AgentLocked => MACOS_AGENT_LOCKED,
        TrayIconState::AgentStopped => MACOS_AGENT_STOPPED,
        TrayIconState::ScanWarning => MACOS_SCAN_WARNING,
        TrayIconState::ErrorDegraded => MACOS_ERROR_DEGRADED,
    }
}

const fn light_bytes(state: TrayIconState) -> &'static [u8] {
    match state {
        TrayIconState::AgentUnlocked => LIGHT_AGENT_UNLOCKED,
        TrayIconState::AgentLocked => LIGHT_AGENT_LOCKED,
        TrayIconState::AgentStopped => LIGHT_AGENT_STOPPED,
        TrayIconState::ScanWarning => LIGHT_SCAN_WARNING,
        TrayIconState::ErrorDegraded => LIGHT_ERROR_DEGRADED,
    }
}

const fn dark_bytes(state: TrayIconState) -> &'static [u8] {
    match state {
        TrayIconState::AgentUnlocked => DARK_AGENT_UNLOCKED,
        TrayIconState::AgentLocked => DARK_AGENT_LOCKED,
        TrayIconState::AgentStopped => DARK_AGENT_STOPPED,
        TrayIconState::ScanWarning => DARK_SCAN_WARNING,
        TrayIconState::ErrorDegraded => DARK_ERROR_DEGRADED,
    }
}

/// Pick the appropriate icon bytes for the current platform and theme.
///
/// macOS: always returns the template (alpha-mask) variant — the OS
/// applies the correct light/dark menu bar appearance itself.
///
/// Windows / Linux: probes the main webview's theme via
/// `WebviewWindow::theme()` and returns the matching full-color variant,
/// falling back to the dark variant if the theme can't be resolved.
fn platform_icon_bytes<R: Runtime>(app: &AppHandle<R>, state: TrayIconState) -> &'static [u8] {
    if cfg!(target_os = "macos") {
        return macos_bytes(state);
    }
    let theme = app.get_webview_window("main").and_then(|window| window.theme().ok());
    match theme {
        Some(tauri::Theme::Light) => light_bytes(state),
        _ => dark_bytes(state),
    }
}

/// Whether the icon should be flagged as a macOS template image.
const fn icon_is_template() -> bool {
    cfg!(target_os = "macos")
}

/// Register the Locket tray icon at app startup.
///
/// Call this exactly once from inside the Tauri `setup` hook. The tray
/// is registered with the `LOCKET_TRAY_ID`, an empty `Menu` (menu
/// actions arrive in a later slice), and a stub `on_tray_icon_event`
/// handler that intentionally does nothing — click routing also lands
/// in a later slice.
///
/// The initial icon is the `AgentStopped` placeholder because the
/// agent socket connect happens after `setup`. The frontend's
/// `useTray` composable replaces it with the real state on the first
/// `agent_status` poll.
///
/// # Errors
///
/// Returns any `tauri::Error` produced while building the empty menu
/// or the tray icon, decoding the baked-in PNG bytes, or registering
/// the icon with the app.
pub fn setup_tray<R: Runtime>(app: &AppHandle<R>) -> tauri::Result<()> {
    let initial = TrayIconState::AgentStopped;
    let bytes = platform_icon_bytes(app, initial);
    let image = Image::from_bytes(bytes)?;
    let menu: Menu<R> = Menu::new(app)?;
    TrayIconBuilder::<R>::with_id(LOCKET_TRAY_ID)
        .icon(image)
        .icon_as_template(icon_is_template())
        .tooltip(tooltip_for(initial))
        .menu(&menu)
        .on_tray_icon_event(|_tray, _event| {
            // Click routing is wired up in a later slice. We register
            // a no-op handler here so the menu still surfaces on the
            // platforms that need an explicit listener.
        })
        .build(app)?;
    Ok(())
}

/// Update the registered tray icon to reflect a new `TrayIconState`.
///
/// Looks up the tray by `LOCKET_TRAY_ID`, re-decodes the baked-in PNG
/// bytes for the requested state under the current platform / theme,
/// and updates the icon and tooltip atomically.
///
/// Silently no-ops if the tray icon has not been registered yet —
/// callers may invoke this before `setup_tray` runs (e.g. during a
/// frontend hot reload) and we do not want that to crash the app.
///
/// # Errors
///
/// Returns any `tauri::Error` produced while decoding the PNG bytes
/// or pushing the icon / tooltip update through to the OS.
pub fn update_tray_state<R: Runtime>(
    app: &AppHandle<R>,
    state: TrayIconState,
) -> tauri::Result<()> {
    let Some(tray) = app.tray_by_id(LOCKET_TRAY_ID) else {
        return Ok(());
    };
    let bytes = platform_icon_bytes(app, state);
    let image = Image::from_bytes(bytes)?;
    tray.set_icon(Some(image))?;
    tray.set_tooltip(Some(tooltip_for(state)))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{TrayState, dark_bytes, icon_bytes_for, light_bytes, macos_bytes, tooltip_for};
    use locket_app::{TrayIconState, tray_icon_states};

    #[test]
    fn icon_bytes_are_non_empty_for_every_state() {
        for state in tray_icon_states() {
            assert!(!icon_bytes_for(*state).is_empty());
            assert!(!macos_bytes(*state).is_empty());
            assert!(!light_bytes(*state).is_empty());
        }
    }

    #[test]
    fn generated_icon_variants_contain_visible_pixels() {
        for state in tray_icon_states() {
            for bytes in [macos_bytes(*state), light_bytes(*state), dark_bytes(*state)] {
                let pixels = decode_stored_rgba_png(bytes);
                assert_eq!(pixels.width, 32);
                assert_eq!(pixels.height, 32);
                assert!(
                    pixels.visible_alpha_pixels() > 32,
                    "{state:?} must not be a transparent placeholder",
                );
            }
            assert_ne!(
                light_bytes(*state),
                dark_bytes(*state),
                "{state:?} must have distinct light and dark variants",
            );
        }
    }

    #[test]
    fn tooltip_matches_descriptor_label_for_every_state() {
        for state in tray_icon_states() {
            assert_eq!(tooltip_for(*state), state.descriptor().label);
            assert!(!tooltip_for(*state).is_empty());
        }
    }

    #[test]
    fn tray_state_round_trips_to_tray_icon_state() {
        let pairs = [
            (TrayState::AgentUnlocked, TrayIconState::AgentUnlocked),
            (TrayState::AgentLocked, TrayIconState::AgentLocked),
            (TrayState::AgentStopped, TrayIconState::AgentStopped),
            (TrayState::ScanWarning, TrayIconState::ScanWarning),
            (TrayState::ErrorDegraded, TrayIconState::ErrorDegraded),
        ];
        for (wire, expected) in pairs {
            assert_eq!(TrayIconState::from(wire), expected);
        }
    }

    struct DecodedPng {
        width: u32,
        height: u32,
        pixels: Vec<u8>,
    }

    impl DecodedPng {
        fn visible_alpha_pixels(&self) -> usize {
            self.pixels.chunks_exact(4).filter(|rgba| rgba[3] > 0).count()
        }
    }

    fn decode_stored_rgba_png(bytes: &[u8]) -> DecodedPng {
        assert!(bytes.starts_with(b"\x89PNG\r\n\x1a\n"));
        let mut offset = 8;
        let mut width = 0;
        let mut height = 0;
        let mut idat = Vec::new();
        while offset + 12 <= bytes.len() {
            let length = read_be_u32(&bytes[offset..offset + 4]) as usize;
            offset += 4;
            let tag = &bytes[offset..offset + 4];
            offset += 4;
            let data = &bytes[offset..offset + length];
            offset += length;
            offset += 4;
            match tag {
                b"IHDR" => {
                    width = read_be_u32(&data[0..4]);
                    height = read_be_u32(&data[4..8]);
                    assert_eq!(data[8], 8, "expected 8-bit PNG");
                    assert_eq!(data[9], 6, "expected RGBA PNG");
                }
                b"IDAT" => idat.extend_from_slice(data),
                b"IEND" => break,
                _ => {}
            }
        }
        let raw = decode_zlib_stored(&idat);
        let row_len = (width as usize * 4) + 1;
        assert_eq!(raw.len(), row_len * height as usize);
        let mut pixels = Vec::with_capacity(width as usize * height as usize * 4);
        for row in raw.chunks_exact(row_len) {
            assert_eq!(row[0], 0, "expected unfiltered rows");
            pixels.extend_from_slice(&row[1..]);
        }
        DecodedPng { width, height, pixels }
    }

    fn decode_zlib_stored(bytes: &[u8]) -> Vec<u8> {
        assert_eq!(&bytes[0..2], &[0x78, 0x01]);
        let mut offset = 2;
        let mut out = Vec::new();
        loop {
            let header = bytes[offset];
            offset += 1;
            let final_block = header & 1 == 1;
            assert_eq!(header & 0b110, 0, "expected stored deflate block");
            let len = read_le_u16(&bytes[offset..offset + 2]);
            offset += 2;
            let nlen = read_le_u16(&bytes[offset..offset + 2]);
            offset += 2;
            assert_eq!(nlen, !len);
            let len = usize::from(len);
            out.extend_from_slice(&bytes[offset..offset + len]);
            offset += len;
            if final_block {
                break;
            }
        }
        out
    }

    fn read_be_u32(bytes: &[u8]) -> u32 {
        assert_eq!(bytes.len(), 4);
        let mut value = [0; 4];
        value.copy_from_slice(bytes);
        u32::from_be_bytes(value)
    }

    fn read_le_u16(bytes: &[u8]) -> u16 {
        assert_eq!(bytes.len(), 2);
        let mut value = [0; 2];
        value.copy_from_slice(bytes);
        u16::from_le_bytes(value)
    }
}
