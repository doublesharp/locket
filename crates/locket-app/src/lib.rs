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

/// Tray icon asset style required for a platform.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrayIconAssetStyle {
    /// macOS template image: black-only alpha mask.
    TemplateMask,
    /// Full-color icon for light system themes.
    FullColorLight,
    /// Full-color icon for dark system themes.
    FullColorDark,
}

/// Metadata-only tray icon descriptor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TrayIconDescriptor {
    /// State represented by this icon.
    pub state: TrayIconState,
    /// Lucide icon name backing the state.
    pub lucide_icon: &'static str,
    /// Short safe label for accessibility and diagnostics.
    pub label: &'static str,
}

/// Passive tray notification event classes covered by the desktop privacy spec.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrayNotificationKind {
    /// A reveal or copy flow completed or needs user attention.
    RevealOrCopy,
    /// A reveal, copy, run, or grant request was denied.
    DeniedAccess,
    /// Scan findings are present.
    ScanFinding,
    /// A saved command policy failed during execution.
    ExecutionFailure,
}

/// Potentially sensitive event metadata from core or agent surfaces.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TrayNotificationContext<'a> {
    /// Exact secret name, if known. Passive notifications ignore it.
    pub secret_name: Option<&'a str>,
    /// Exact policy name, if known. Passive notifications ignore it.
    pub policy_name: Option<&'a str>,
    /// Exact project name, if known. Passive notifications ignore it.
    pub project_name: Option<&'a str>,
    /// Secret value, if a caller accidentally provides one. Passive notifications ignore it.
    pub secret_value: Option<&'a str>,
    /// Metadata-only scan finding count.
    pub finding_count: Option<u32>,
}

/// Metadata-only passive tray notification copy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrayNotification {
    /// Generic notification title.
    pub title: String,
    /// Generic notification body.
    pub body: String,
}

/// Distinct denial reasons surfaced by desktop error views.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DenialReason {
    /// Vault must be unlocked before the requested action can proceed.
    LockedVault,
    /// No live grant covers the requested action.
    MissingGrant,
    /// A saved policy or role rule denied the action.
    PolicyDenied,
    /// Dangerous-profile safeguards require explicit confirmation.
    DangerousProfile,
    /// The selected device is no longer trusted.
    RevokedDevice,
    /// The invite can no longer be accepted.
    ExpiredInvite,
}

/// Metadata-only copy and recovery affordance for a denial view.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DenialUxDescriptor {
    /// Denial reason represented by this descriptor.
    pub reason: DenialReason,
    /// Stable UI copy heading.
    pub title: &'static str,
    /// Metadata-only next-action text.
    pub next_action: &'static str,
    /// Primary recovery affordance.
    pub affordance: &'static str,
}

/// Empty setup states called out by the desktop UX spec.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EmptyState {
    /// No local project is available yet.
    NoProject,
    /// No profile exists in the current project.
    NoProfile,
    /// No secret has been created or imported yet.
    NoSecret,
    /// No saved command policy exists yet.
    NoPolicy,
    /// No trusted local agent is running.
    NoAgent,
    /// No local team device key exists yet.
    NoTeamDevice,
}

/// Metadata-only desktop guidance for an empty setup state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EmptyStateDescriptor {
    /// Empty state represented by this descriptor.
    pub state: EmptyState,
    /// Stable UI copy heading.
    pub title: &'static str,
    /// Short safe explanation.
    pub guidance: &'static str,
    /// Primary setup command to offer.
    pub primary_command: &'static str,
    /// Optional alternate setup command.
    pub secondary_command: Option<&'static str>,
}

/// Desktop accessibility baseline requirements from the UX spec.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccessibilityRequirement {
    /// Every workflow is reachable without a pointer device.
    KeyboardNavigation,
    /// Focus is visible and high-contrast on interactive controls.
    VisibleFocus,
    /// Icon-only and dynamic controls expose non-secret assistive labels.
    ScreenReaderLabels,
    /// Text, controls, warnings, and focus treatments meet contrast budgets.
    SufficientContrast,
    /// Motion and transitions respect reduced-motion preferences.
    ReducedMotion,
    /// Reveal/copy flows never leave secret values in accessibility metadata after TTL expiry.
    PostTtlMetadataScrub,
}

/// Metadata-only checklist entry for desktop accessibility implementation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AccessibilityDescriptor {
    /// Requirement represented by this descriptor.
    pub requirement: AccessibilityRequirement,
    /// Stable implementation key for UI tests and component mapping.
    pub key: &'static str,
    /// Safe assistive copy or validation guidance.
    pub guidance: &'static str,
    /// Whether the requirement applies to short-lived plaintext flows.
    pub plaintext_ttl_sensitive: bool,
}

impl DenialReason {
    /// Return the desktop denial view descriptor for this reason.
    #[must_use]
    pub const fn descriptor(self) -> DenialUxDescriptor {
        let (title, next_action, affordance) = match self {
            Self::LockedVault => ("Vault locked", "Unlock the vault to continue.", "unlock-vault"),
            Self::MissingGrant => {
                ("Grant required", "Approve a short-lived grant before retrying.", "request-grant")
            }
            Self::PolicyDenied => {
                ("Policy denied", "Review the saved policy or ask for access.", "open-policy")
            }
            Self::DangerousProfile => (
                "Dangerous profile",
                "Confirm the profile scope before continuing.",
                "confirm-profile",
            ),
            Self::RevokedDevice => {
                ("Device revoked", "Use a trusted device or add a new one.", "manage-devices")
            }
            Self::ExpiredInvite => {
                ("Invite expired", "Request a fresh invite from a maintainer.", "request-invite")
            }
        };
        DenialUxDescriptor { reason: self, title, next_action, affordance }
    }
}

impl AccessibilityRequirement {
    /// Return the metadata-only descriptor for this accessibility requirement.
    #[must_use]
    pub const fn descriptor(self) -> AccessibilityDescriptor {
        let (key, guidance, plaintext_ttl_sensitive) = match self {
            Self::KeyboardNavigation => (
                "keyboard-navigation",
                "Expose every primary action through tab order and shortcuts.",
                false,
            ),
            Self::VisibleFocus => (
                "visible-focus",
                "Render a persistent focus treatment for every interactive control.",
                false,
            ),
            Self::ScreenReaderLabels => (
                "screen-reader-labels",
                "Use labels that describe metadata-only actions and state.",
                false,
            ),
            Self::SufficientContrast => (
                "sufficient-contrast",
                "Keep text, status, warning, and focus colors above contrast thresholds.",
                false,
            ),
            Self::ReducedMotion => (
                "reduced-motion",
                "Disable nonessential animation when reduced motion is requested.",
                false,
            ),
            Self::PostTtlMetadataScrub => (
                "post-ttl-metadata-scrub",
                "Clear reveal and copy accessibility metadata when plaintext TTL expires.",
                true,
            ),
        };
        AccessibilityDescriptor { requirement: self, key, guidance, plaintext_ttl_sensitive }
    }
}

impl EmptyState {
    /// Return the desktop empty-state guidance descriptor for this state.
    #[must_use]
    pub const fn descriptor(self) -> EmptyStateDescriptor {
        let (title, guidance, primary_command, secondary_command) = match self {
            Self::NoProject => (
                "No project",
                "Initialize a project or accept a team invite.",
                "locket init",
                Some("locket team accept <invite.locket>"),
            ),
            Self::NoProfile => (
                "No profile",
                "Create a development profile before adding secrets.",
                "locket profile create dev",
                None,
            ),
            Self::NoSecret => (
                "No secrets",
                "Add or import a secret to populate this view.",
                "locket set <KEY>",
                Some("locket import <file.env>"),
            ),
            Self::NoPolicy => (
                "No policy",
                "Create a saved command policy before running through Locket.",
                "locket policy add dev -- <cmd>",
                None,
            ),
            Self::NoAgent => (
                "No agent",
                "Start the local agent to enable live status and grants.",
                "locket agent start",
                None,
            ),
            Self::NoTeamDevice => (
                "No team device",
                "Initialize this device before team invite or bundle flows.",
                "locket device init",
                None,
            ),
        };
        EmptyStateDescriptor { state: self, title, guidance, primary_command, secondary_command }
    }
}

impl TrayNotificationKind {
    /// Render the default passive notification without exact names or values.
    #[must_use]
    pub fn passive_notification(self, context: &TrayNotificationContext<'_>) -> TrayNotification {
        match self {
            Self::RevealOrCopy => TrayNotification {
                title: "Secret ready".to_owned(),
                body: "The requested secret action completed.".to_owned(),
            },
            Self::DeniedAccess => TrayNotification {
                title: "Access denied".to_owned(),
                body: "A secret or policy action needs attention in the app.".to_owned(),
            },
            Self::ScanFinding => TrayNotification {
                title: "Scan warning".to_owned(),
                body: scan_notification_body(context.finding_count),
            },
            Self::ExecutionFailure => TrayNotification {
                title: "Policy failed".to_owned(),
                body: "A saved policy failed. Open the app for details.".to_owned(),
            },
        }
    }
}

impl TrayIconState {
    /// Return the metadata-only icon descriptor for this state.
    #[must_use]
    pub const fn descriptor(self) -> TrayIconDescriptor {
        let (lucide_icon, label) = match self {
            Self::AgentUnlocked => ("lock-open", "agent running, vault unlocked"),
            Self::AgentLocked => ("lock", "agent running, vault locked"),
            Self::AgentStopped => ("lock", "agent stopped"),
            Self::ScanWarning => ("shield-alert", "scan warning"),
            Self::ErrorDegraded => ("alert-triangle", "error or degraded"),
        };
        TrayIconDescriptor { state: self, lucide_icon, label }
    }
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

/// Return the icon asset styles required for a target platform.
#[must_use]
pub const fn tray_icon_asset_styles_for_os(os: &str) -> &'static [TrayIconAssetStyle] {
    match os.as_bytes() {
        b"macos" => &[TrayIconAssetStyle::TemplateMask],
        b"windows" | b"linux" => {
            &[TrayIconAssetStyle::FullColorLight, TrayIconAssetStyle::FullColorDark]
        }
        _ => &[TrayIconAssetStyle::FullColorLight, TrayIconAssetStyle::FullColorDark],
    }
}

/// Return all tray icon descriptors in spec order.
#[must_use]
pub fn tray_icon_descriptors() -> Vec<TrayIconDescriptor> {
    tray_icon_states().iter().map(|state| state.descriptor()).collect()
}

/// All denial reasons in desktop UX spec order.
#[must_use]
pub const fn denial_reasons() -> &'static [DenialReason] {
    &[
        DenialReason::LockedVault,
        DenialReason::MissingGrant,
        DenialReason::PolicyDenied,
        DenialReason::DangerousProfile,
        DenialReason::RevokedDevice,
        DenialReason::ExpiredInvite,
    ]
}

/// Return all denial UX descriptors in spec order.
#[must_use]
pub fn denial_ux_descriptors() -> Vec<DenialUxDescriptor> {
    denial_reasons().iter().map(|reason| reason.descriptor()).collect()
}

/// All empty setup states in desktop UX spec order.
#[must_use]
pub const fn empty_states() -> &'static [EmptyState] {
    &[
        EmptyState::NoProject,
        EmptyState::NoProfile,
        EmptyState::NoSecret,
        EmptyState::NoPolicy,
        EmptyState::NoAgent,
        EmptyState::NoTeamDevice,
    ]
}

/// Return all desktop empty-state descriptors in spec order.
#[must_use]
pub fn empty_state_descriptors() -> Vec<EmptyStateDescriptor> {
    empty_states().iter().map(|state| state.descriptor()).collect()
}

/// All desktop accessibility requirements in spec order.
#[must_use]
pub const fn accessibility_requirements() -> &'static [AccessibilityRequirement] {
    &[
        AccessibilityRequirement::KeyboardNavigation,
        AccessibilityRequirement::VisibleFocus,
        AccessibilityRequirement::ScreenReaderLabels,
        AccessibilityRequirement::SufficientContrast,
        AccessibilityRequirement::ReducedMotion,
        AccessibilityRequirement::PostTtlMetadataScrub,
    ]
}

/// Return all desktop accessibility descriptors in spec order.
#[must_use]
pub fn accessibility_descriptors() -> Vec<AccessibilityDescriptor> {
    accessibility_requirements().iter().map(|requirement| requirement.descriptor()).collect()
}

fn scan_notification_body(finding_count: Option<u32>) -> String {
    match finding_count {
        Some(1) => "1 scan warning needs attention.".to_owned(),
        Some(count) => format!("{count} scan warnings need attention."),
        None => "Scan warnings need attention.".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AccessibilityRequirement, CapabilityAccess, DenialReason, EmptyState, ReleaseWebviewPolicy,
        TrayIconAssetStyle, TrayIconState, TrayNotificationContext, TrayNotificationKind,
        accessibility_descriptors, accessibility_requirements, denial_reasons,
        denial_ux_descriptors, empty_state_descriptors, empty_states, primary_views,
        tray_icon_asset_styles_for_os, tray_icon_descriptors, tray_icon_states,
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
    fn tray_icon_descriptors_use_lucide_spec_icons() {
        let descriptors = tray_icon_descriptors();

        assert_eq!(descriptors.len(), tray_icon_states().len());
        assert_eq!(descriptors[0].lucide_icon, "lock-open");
        assert_eq!(descriptors[1].lucide_icon, "lock");
        assert_eq!(descriptors[2].lucide_icon, "lock");
        assert_eq!(descriptors[3].lucide_icon, "shield-alert");
        assert_eq!(descriptors[4].lucide_icon, "alert-triangle");
        assert!(descriptors.iter().all(|descriptor| !descriptor.label.contains("secret")));
    }

    #[test]
    fn tray_icon_asset_styles_match_platform_requirements() {
        assert_eq!(tray_icon_asset_styles_for_os("macos"), &[TrayIconAssetStyle::TemplateMask]);
        assert_eq!(
            tray_icon_asset_styles_for_os("windows"),
            &[TrayIconAssetStyle::FullColorLight, TrayIconAssetStyle::FullColorDark,]
        );
        assert_eq!(
            tray_icon_asset_styles_for_os("linux"),
            &[TrayIconAssetStyle::FullColorLight, TrayIconAssetStyle::FullColorDark,]
        );
    }

    #[test]
    fn passive_tray_notifications_use_generic_labels_by_default() {
        let context = TrayNotificationContext {
            secret_name: Some("DATABASE_URL"),
            policy_name: Some("deploy-prod"),
            project_name: Some("payments-api"),
            secret_value: Some("postgres://user:pass@example.invalid/db"),
            finding_count: Some(3),
        };

        let notifications = [
            TrayNotificationKind::RevealOrCopy.passive_notification(&context),
            TrayNotificationKind::DeniedAccess.passive_notification(&context),
            TrayNotificationKind::ScanFinding.passive_notification(&context),
            TrayNotificationKind::ExecutionFailure.passive_notification(&context),
        ];

        for notification in notifications {
            let rendered = format!("{} {}", notification.title, notification.body);
            assert!(!rendered.contains("DATABASE_URL"));
            assert!(!rendered.contains("deploy-prod"));
            assert!(!rendered.contains("payments-api"));
            assert!(!rendered.contains("postgres://"));
            assert!(
                rendered.contains("secret")
                    || rendered.contains("policy")
                    || rendered.contains("Scan")
                    || rendered.contains("scan")
            );
        }
    }

    #[test]
    fn scan_notifications_show_metadata_counts_only() {
        let one =
            TrayNotificationKind::ScanFinding.passive_notification(&TrayNotificationContext {
                finding_count: Some(1),
                ..TrayNotificationContext::default()
            });
        let many =
            TrayNotificationKind::ScanFinding.passive_notification(&TrayNotificationContext {
                finding_count: Some(12),
                secret_name: Some("API_TOKEN"),
                ..TrayNotificationContext::default()
            });

        assert_eq!(one.body, "1 scan warning needs attention.");
        assert_eq!(many.body, "12 scan warnings need attention.");
        assert!(!many.body.contains("API_TOKEN"));
    }

    #[test]
    fn denial_reasons_match_desktop_error_view_inventory() {
        assert_eq!(
            denial_reasons(),
            &[
                DenialReason::LockedVault,
                DenialReason::MissingGrant,
                DenialReason::PolicyDenied,
                DenialReason::DangerousProfile,
                DenialReason::RevokedDevice,
                DenialReason::ExpiredInvite,
            ]
        );
    }

    #[test]
    fn denial_ux_descriptors_have_distinct_safe_recovery_affordances() {
        let descriptors = denial_ux_descriptors();

        assert_eq!(descriptors.len(), denial_reasons().len());
        for descriptor in descriptors {
            assert_eq!(descriptor, descriptor.reason.descriptor());
            assert!(!descriptor.title.contains("DATABASE_URL"));
            assert!(!descriptor.next_action.contains("postgres://"));
            assert!(!descriptor.affordance.is_empty());
        }

        let affordances = denial_ux_descriptors()
            .into_iter()
            .map(|descriptor| descriptor.affordance)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(affordances.len(), denial_reasons().len());
    }

    #[test]
    fn empty_states_match_desktop_setup_inventory() {
        assert_eq!(
            empty_states(),
            &[
                EmptyState::NoProject,
                EmptyState::NoProfile,
                EmptyState::NoSecret,
                EmptyState::NoPolicy,
                EmptyState::NoAgent,
                EmptyState::NoTeamDevice,
            ]
        );
    }

    #[test]
    fn empty_state_descriptors_offer_safe_setup_commands() {
        let descriptors = empty_state_descriptors();

        assert_eq!(descriptors.len(), empty_states().len());
        assert_eq!(descriptors[0].primary_command, "locket init");
        assert_eq!(descriptors[0].secondary_command, Some("locket team accept <invite.locket>"));
        assert_eq!(descriptors[1].primary_command, "locket profile create dev");
        assert_eq!(descriptors[2].primary_command, "locket set <KEY>");
        assert_eq!(descriptors[2].secondary_command, Some("locket import <file.env>"));
        assert_eq!(descriptors[3].primary_command, "locket policy add dev -- <cmd>");
        assert_eq!(descriptors[4].primary_command, "locket agent start");
        assert_eq!(descriptors[5].primary_command, "locket device init");

        for descriptor in descriptors {
            assert_eq!(descriptor, descriptor.state.descriptor());
            let rendered = format!(
                "{} {} {} {:?}",
                descriptor.title,
                descriptor.guidance,
                descriptor.primary_command,
                descriptor.secondary_command
            );
            assert!(!rendered.contains("DATABASE_URL"));
            assert!(!rendered.contains("deploy-prod"));
            assert!(!rendered.contains("payments-api"));
            assert!(!rendered.contains("postgres://"));
        }
    }

    #[test]
    fn accessibility_requirements_match_desktop_spec_baseline() {
        assert_eq!(
            accessibility_requirements(),
            &[
                AccessibilityRequirement::KeyboardNavigation,
                AccessibilityRequirement::VisibleFocus,
                AccessibilityRequirement::ScreenReaderLabels,
                AccessibilityRequirement::SufficientContrast,
                AccessibilityRequirement::ReducedMotion,
                AccessibilityRequirement::PostTtlMetadataScrub,
            ]
        );
    }

    #[test]
    fn accessibility_descriptors_are_metadata_only_and_cover_ttl_scrub() {
        let descriptors = accessibility_descriptors();

        assert_eq!(descriptors.len(), accessibility_requirements().len());
        assert_eq!(descriptors[0].key, "keyboard-navigation");
        assert_eq!(descriptors[1].key, "visible-focus");
        assert_eq!(descriptors[2].key, "screen-reader-labels");
        assert_eq!(descriptors[3].key, "sufficient-contrast");
        assert_eq!(descriptors[4].key, "reduced-motion");
        assert_eq!(descriptors[5].key, "post-ttl-metadata-scrub");

        for descriptor in descriptors {
            assert_eq!(descriptor, descriptor.requirement.descriptor());
            let rendered = format!("{} {}", descriptor.key, descriptor.guidance);
            assert!(!rendered.contains("DATABASE_URL"));
            assert!(!rendered.contains("postgres://"));
            assert!(!rendered.contains("recovery code"));
            assert!(!rendered.contains("grant token"));
        }

        let ttl_sensitive = accessibility_descriptors()
            .into_iter()
            .filter(|descriptor| descriptor.plaintext_ttl_sensitive)
            .collect::<Vec<_>>();
        assert_eq!(ttl_sensitive.len(), 1);
        assert_eq!(ttl_sensitive[0].requirement, AccessibilityRequirement::PostTtlMetadataScrub);
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
