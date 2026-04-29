//! Desktop app and tray shell primitives for Locket.
//!
//! This crate intentionally starts as a thin, non-Tauri skeleton. It gives the
//! workspace a stable `locket-app` crate boundary while the real Tauri v2 app,
//! commands, and frontend are delivered in later slices.

/// Top-level app surfaces described by the desktop spec.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AppSurface {
    /// Full desktop control surface.
    Desktop,
    /// Compact tray or app-bar status surface.
    Tray,
}

/// Primary desktop views required by the v1 desktop spec.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrimaryView {
    /// Project-level dashboard.
    ProjectDashboard,
    /// Profile switcher.
    ProfileSwitcher,
    /// Secret metadata list.
    SecretMetadataList,
    /// Gated secret editor.
    SecretEditor,
    /// Secret version history.
    SecretVersionHistory,
    /// Command policy editor.
    CommandPolicyEditor,
    /// Execution and runtime session monitor.
    ExecutionMonitor,
    /// Scan results.
    ScanResults,
    /// Audit log and verification view.
    AuditLog,
    /// Backup, recovery, and device import/export.
    BackupRecovery,
    /// Settings.
    Settings,
}

/// Tray icon state from the desktop spec.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrayIconState {
    /// Agent running and vault unlocked.
    AgentUnlocked,
    /// Agent running and vault locked.
    AgentLocked,
    /// No reachable agent.
    AgentStopped,
    /// One or more unresolved scan warnings.
    ScanWarning,
    /// Agent error or degraded hardening state.
    ErrorDegraded,
}

/// Access setting for a release webview capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapabilityAccess {
    /// Capability is denied by default.
    Denied,
    /// Capability is allowed.
    Allowed,
}

/// Release-webview security defaults for the desktop app shell.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseWebviewPolicy {
    /// Release builds must not load remote content.
    pub remote_content: CapabilityAccess,
    /// Release builds must not load remote fonts.
    pub remote_fonts: CapabilityAccess,
    /// Release builds must not include analytics.
    pub analytics: CapabilityAccess,
    /// Release builds must not expose broad filesystem access.
    pub broad_filesystem_access: CapabilityAccess,
    /// Release builds must not expose broad shell access.
    pub broad_shell_access: CapabilityAccess,
    /// Release builds must not expose broad network access.
    pub broad_network_access: CapabilityAccess,
    /// Release builds must not expose broad clipboard access.
    pub broad_clipboard_access: CapabilityAccess,
    /// Content Security Policy applied to packaged webviews.
    pub content_security_policy: &'static str,
}

impl Default for ReleaseWebviewPolicy {
    fn default() -> Self {
        Self {
            remote_content: CapabilityAccess::Denied,
            remote_fonts: CapabilityAccess::Denied,
            analytics: CapabilityAccess::Denied,
            broad_filesystem_access: CapabilityAccess::Denied,
            broad_shell_access: CapabilityAccess::Denied,
            broad_network_access: CapabilityAccess::Denied,
            broad_clipboard_access: CapabilityAccess::Denied,
            content_security_policy: "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'",
        }
    }
}

/// All primary views in spec order.
#[must_use]
pub const fn primary_views() -> &'static [PrimaryView] {
    &[
        PrimaryView::ProjectDashboard,
        PrimaryView::ProfileSwitcher,
        PrimaryView::SecretMetadataList,
        PrimaryView::SecretEditor,
        PrimaryView::SecretVersionHistory,
        PrimaryView::CommandPolicyEditor,
        PrimaryView::ExecutionMonitor,
        PrimaryView::ScanResults,
        PrimaryView::AuditLog,
        PrimaryView::BackupRecovery,
        PrimaryView::Settings,
    ]
}

/// All tray icon states in spec order.
#[must_use]
pub const fn tray_icon_states() -> &'static [TrayIconState] {
    &[
        TrayIconState::AgentUnlocked,
        TrayIconState::AgentLocked,
        TrayIconState::AgentStopped,
        TrayIconState::ScanWarning,
        TrayIconState::ErrorDegraded,
    ]
}

#[cfg(test)]
mod tests {
    use super::{
        CapabilityAccess, ReleaseWebviewPolicy, TrayIconState, primary_views, tray_icon_states,
    };

    #[test]
    fn primary_views_match_desktop_spec_inventory() {
        assert_eq!(primary_views().len(), 11);
    }

    #[test]
    fn tray_icon_states_match_desktop_spec_inventory() {
        assert_eq!(
            tray_icon_states(),
            &[
                TrayIconState::AgentUnlocked,
                TrayIconState::AgentLocked,
                TrayIconState::AgentStopped,
                TrayIconState::ScanWarning,
                TrayIconState::ErrorDegraded,
            ]
        );
    }

    #[test]
    fn release_webview_policy_denies_broad_and_remote_capabilities() {
        let policy = ReleaseWebviewPolicy::default();

        assert_eq!(policy.remote_content, CapabilityAccess::Denied);
        assert_eq!(policy.remote_fonts, CapabilityAccess::Denied);
        assert_eq!(policy.analytics, CapabilityAccess::Denied);
        assert_eq!(policy.broad_filesystem_access, CapabilityAccess::Denied);
        assert_eq!(policy.broad_shell_access, CapabilityAccess::Denied);
        assert_eq!(policy.broad_network_access, CapabilityAccess::Denied);
        assert_eq!(policy.broad_clipboard_access, CapabilityAccess::Denied);
        assert!(!policy.content_security_policy.contains("https:"));
        assert!(!policy.content_security_policy.contains("http:"));
    }
}
