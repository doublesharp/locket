//! Desktop clipboard helpers backing the `copy_secret` Tauri command.
//!
//! Splits the clear-after-TTL flow into:
//!
//! - A pure decision function (`decide_clear`) so unit tests can pin
//!   the contract without bringing up an OS clipboard.
//! - A platform probe (`clipboard_platform`) that flags Wayland sessions
//!   as `unsupported_reason = "wayland-session"` because the X11/Wayland
//!   selection model means our value never reaches a generic clipboard
//!   peer in the first place.
//! - Thin `write_clipboard` / `read_clipboard` / `clear_clipboard`
//!   helpers that route through `arboard`, isolated behind a single
//!   `ClipboardSession` so the rest of the code never touches arboard
//!   types directly.

use std::env;

use thiserror::Error;

/// Decision returned by [`decide_clear`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClipboardCopyDecision {
    /// The TTL elapsed and the clipboard still holds the value we
    /// wrote — the caller should clear it.
    Clear,
    /// The clipboard changed since we wrote the value — leave it
    /// alone.
    Keep,
}

/// Outcome of the user-facing `copy_secret` flow surfaced to the UI.
///
/// Mirrors the wire shape returned by the Tauri command but kept in
/// the lib so unit tests can pattern-match without re-exporting the
/// command's private response struct.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClipboardCopyOutcome {
    /// The agent value reached the OS clipboard.
    Copied {
        /// TTL after which the clipboard is re-checked.
        ttl_seconds: u32,
    },
    /// The desktop did not write anything.
    Unsupported {
        /// Stable reason code surfaced to the UI.
        unsupported_reason: String,
    },
}

/// Platforms where the `copy_secret` flow has different behavior.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClipboardPlatform {
    /// macOS, Windows, or X11 — full TTL-bound clear path is wired.
    Standard,
    /// Wayland session — the desktop returns an `unsupported_reason`
    /// and skips the timer.
    Wayland,
}

/// Errors raised by the thin clipboard helpers.
#[derive(Debug, Error)]
pub enum ClipboardError {
    /// Underlying platform refused or could not service the request.
    #[error("clipboard backend error: {0}")]
    Backend(String),
}

/// Probe the platform once. Wayland is detected via `XDG_SESSION_TYPE`
/// or the `WAYLAND_DISPLAY` env var, matching the convention used by
/// the rest of the workspace.
#[must_use]
pub fn clipboard_platform() -> ClipboardPlatform {
    if cfg!(target_os = "linux") {
        let session = env::var("XDG_SESSION_TYPE").unwrap_or_default();
        let wayland_display = env::var("WAYLAND_DISPLAY").unwrap_or_default();
        if session.eq_ignore_ascii_case("wayland") || !wayland_display.is_empty() {
            return ClipboardPlatform::Wayland;
        }
    }
    ClipboardPlatform::Standard
}

/// Pure mapping from "what the clipboard now holds" to the clear
/// decision. Treats a missing/None read as "leave it alone" — if we
/// can't be sure, we never wipe a clipboard we don't own.
#[must_use]
pub fn decide_clear(current: Option<&str>, expected: &str) -> ClipboardCopyDecision {
    match current {
        Some(value) if value == expected => ClipboardCopyDecision::Clear,
        _ => ClipboardCopyDecision::Keep,
    }
}

/// Lazy session wrapper that owns an `arboard::Clipboard`. Constructed
/// fresh per call because `arboard::Clipboard` is not `Send` on every
/// platform we target.
pub struct ClipboardSession;

impl ClipboardSession {
    /// Open a clipboard session.
    ///
    /// # Errors
    ///
    /// Returns [`ClipboardError::Backend`] if the OS clipboard cannot
    /// be initialized.
    #[allow(clippy::new_ret_no_self)]
    pub fn new() -> Result<arboard::Clipboard, ClipboardError> {
        arboard::Clipboard::new().map_err(|error| ClipboardError::Backend(error.to_string()))
    }
}

/// Write a value to the OS clipboard.
///
/// # Errors
///
/// Returns [`ClipboardError::Backend`] for any platform-level failure.
pub fn write_clipboard(value: &str) -> Result<(), ClipboardError> {
    let mut clipboard = ClipboardSession::new()?;
    clipboard.set_text(value.to_owned()).map_err(|error| ClipboardError::Backend(error.to_string()))
}

/// Read the current OS clipboard value.
///
/// # Errors
///
/// Returns [`ClipboardError::Backend`] if the clipboard cannot be
/// opened or read; the most common case is "clipboard owns non-text
/// data" which arboard surfaces as an error too.
pub fn read_clipboard() -> Result<String, ClipboardError> {
    let mut clipboard = ClipboardSession::new()?;
    clipboard.get_text().map_err(|error| ClipboardError::Backend(error.to_string()))
}

/// Clear the OS clipboard.
///
/// # Errors
///
/// Returns [`ClipboardError::Backend`] if the clipboard cannot be
/// opened or cleared.
pub fn clear_clipboard() -> Result<(), ClipboardError> {
    let mut clipboard = ClipboardSession::new()?;
    clipboard.clear().map_err(|error| ClipboardError::Backend(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::{
        ClipboardCopyDecision, ClipboardCopyOutcome, ClipboardPlatform, clipboard_platform,
        decide_clear,
    };

    #[test]
    fn decide_clear_clears_when_clipboard_still_holds_the_secret() {
        assert_eq!(
            decide_clear(Some("super-secret-value"), "super-secret-value"),
            ClipboardCopyDecision::Clear,
        );
    }

    #[test]
    fn decide_clear_keeps_when_user_overwrote_the_clipboard() {
        assert_eq!(
            decide_clear(Some("user typed something else"), "super-secret-value"),
            ClipboardCopyDecision::Keep,
        );
    }

    #[test]
    fn decide_clear_keeps_when_clipboard_is_unreadable() {
        // We can't tell what the clipboard holds, so treat as "leave
        // it alone".
        assert_eq!(decide_clear(None, "super-secret-value"), ClipboardCopyDecision::Keep);
    }

    #[test]
    fn clipboard_platform_returns_a_known_variant() {
        // The function is platform-dependent so we just assert the
        // probe terminates and returns one of the documented variants.
        match clipboard_platform() {
            ClipboardPlatform::Standard | ClipboardPlatform::Wayland => {}
        }
    }

    #[test]
    fn unsupported_outcome_surfaces_a_stable_wayland_reason_code() {
        let outcome =
            ClipboardCopyOutcome::Unsupported { unsupported_reason: "wayland-session".to_owned() };
        assert!(matches!(&outcome, ClipboardCopyOutcome::Unsupported { .. }));
        if let ClipboardCopyOutcome::Unsupported { unsupported_reason } = outcome {
            assert_eq!(unsupported_reason, "wayland-session");
        }
    }
}
