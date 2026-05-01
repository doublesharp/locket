//! Core-dump suppression for processes that hold key material.
//!
//! Per `docs/specs/agent.md`:
//!
//! - Linux agents must call `prctl(PR_SET_DUMPABLE, 0)` and set
//!   `RLIMIT_CORE = 0` where available.
//! - macOS and Windows agents must use the closest platform-supported
//!   core-dump suppression and process hardening available to a
//!   user-space app.
//!
//! On Linux this lowers `RLIMIT_CORE` to zero (so the kernel writes no
//! core file even if the user's shell raised the limit) and clears
//! `PR_SET_DUMPABLE` (so `/proc/<pid>/mem` and `ptrace` from same-uid
//! debuggers don't yield key material). On macOS only `RLIMIT_CORE = 0`
//! is available — `prctl` has no equivalent for an unprivileged
//! user-space process; system-wide controls (`sysctl kern.coredump`,
//! codesigning entitlements) are out of scope. On Windows the
//! supported mitigation is `SetErrorMode(SEM_NOGPFAULTERRORBOX |
//! SEM_FAILCRITICALERRORS)`, which suppresses Windows Error Reporting
//! crash dumps; until the `windows` crate is wired in this build ships
//! a stub returning `Unsupported` so diagnostics surface the gap.

use std::fmt::{self, Display};

/// Outcome of a [`disable_core_dumps`] call.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoreDumpHardening {
    /// All available mitigations succeeded on this platform.
    Active,
    /// The platform has no implementation in this build (currently
    /// Windows). Diagnostics should surface this so users know the
    /// fall-back state.
    Unsupported,
    /// At least one mitigation failed; key material may still be
    /// observable. The caller should fail closed where the spec
    /// demands it and otherwise surface `Degraded` to diagnostics.
    Degraded,
}

impl Display for CoreDumpHardening {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Active => "active",
            Self::Unsupported => "unsupported",
            Self::Degraded => "degraded",
        })
    }
}

/// Disables core-dump generation for the current process.
///
/// Dispatches to the platform-specific implementation:
///
/// - **Linux:** [`unix::disable_linux_core_dumps`] —
///   `prctl(PR_SET_DUMPABLE, 0)` plus `setrlimit(RLIMIT_CORE, 0, 0)`.
/// - **macOS / other BSD Unixes:** [`unix::disable_macos_core_dumps`] —
///   `setrlimit(RLIMIT_CORE, 0, 0)` only (no `prctl` equivalent).
/// - **Windows:** [`windows_stub::disable_windows_core_dumps`] — stub
///   returning `Unsupported` until `SetErrorMode` is wired in.
///
/// The call is idempotent and safe to invoke from any process.
#[must_use]
pub fn disable_core_dumps() -> CoreDumpHardening {
    #[cfg(target_os = "linux")]
    {
        unix::disable_linux_core_dumps()
    }
    #[cfg(all(unix, not(target_os = "linux")))]
    {
        unix::disable_macos_core_dumps()
    }
    #[cfg(target_os = "windows")]
    {
        windows_stub::disable_windows_core_dumps()
    }
    #[cfg(not(any(unix, target_os = "windows")))]
    {
        CoreDumpHardening::Unsupported
    }
}

/// Returns the current core-dump hardening state without changing it.
///
/// This is what `locket doctor` reports — `disable_core_dumps()` is
/// already called once at process startup, so this just inspects
/// `RLIMIT_CORE` (and `PR_GET_DUMPABLE` on Linux) and reports whether
/// the mitigations stuck. On Windows the stub reports `Unsupported`.
#[must_use]
pub fn core_dump_hardening_state() -> CoreDumpHardening {
    #[cfg(unix)]
    {
        unix::core_dump_hardening_state()
    }
    #[cfg(target_os = "windows")]
    {
        windows_stub::core_dump_hardening_state()
    }
    #[cfg(not(any(unix, target_os = "windows")))]
    {
        CoreDumpHardening::Unsupported
    }
}

#[cfg(unix)]
mod unix {
    use rustix::process::{Resource, Rlimit, getrlimit, setrlimit};

    use super::CoreDumpHardening;

    /// Linux-specific entry point: `prctl(PR_SET_DUMPABLE, 0)` plus
    /// `setrlimit(RLIMIT_CORE, 0, 0)`. Both calls in one place so the
    /// agent boot path and tests can target the Linux contract
    /// directly. Equivalent to:
    ///
    /// ```text
    /// libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
    /// libc::setrlimit(libc::RLIMIT_CORE, &rlim { rlim_cur: 0, rlim_max: 0 });
    /// ```
    ///
    /// Routed through `rustix` so the call is `unsafe`-free and shares
    /// the typed `DumpableBehavior` enum with the doctor read path.
    #[cfg(target_os = "linux")]
    pub fn disable_linux_core_dumps() -> CoreDumpHardening {
        let core_ok = set_core_rlimit_zero();
        let dumpable_ok = clear_dumpable_flag();
        if core_ok && dumpable_ok { CoreDumpHardening::Active } else { CoreDumpHardening::Degraded }
    }

    /// macOS / BSD entry point: `setrlimit(RLIMIT_CORE, 0, 0)` only.
    ///
    /// Documented limitation: macOS exposes no `prctl(PR_SET_DUMPABLE)`
    /// equivalent for an unprivileged user-space process. A same-uid
    /// debugger (`lldb attach`) can still inspect address space; that is
    /// mitigated separately by the session-lock and zeroize layers.
    /// System-wide controls (`sysctl kern.coredump`, codesigning
    /// entitlements) require privileges this agent does not assume and
    /// are out of scope for this slice.
    #[cfg(not(target_os = "linux"))]
    pub fn disable_macos_core_dumps() -> CoreDumpHardening {
        if set_core_rlimit_zero() { CoreDumpHardening::Active } else { CoreDumpHardening::Degraded }
    }

    pub fn core_dump_hardening_state() -> CoreDumpHardening {
        let core_zeroed =
            matches!(getrlimit(Resource::Core), Rlimit { current: Some(0), maximum: Some(0) });
        let dumpable_cleared = dumpable_flag_cleared();
        if core_zeroed && dumpable_cleared {
            CoreDumpHardening::Active
        } else {
            CoreDumpHardening::Degraded
        }
    }

    fn set_core_rlimit_zero() -> bool {
        setrlimit(Resource::Core, Rlimit { current: Some(0), maximum: Some(0) }).is_ok()
    }

    /// `prctl(PR_SET_DUMPABLE, 0)` via rustix's typed wrapper.
    #[cfg(target_os = "linux")]
    fn clear_dumpable_flag() -> bool {
        rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)
            .is_ok()
    }

    /// `prctl(PR_GET_DUMPABLE)` via rustix's typed wrapper.
    #[cfg(target_os = "linux")]
    fn dumpable_flag_cleared() -> bool {
        matches!(
            rustix::process::dumpable_behavior(),
            Ok(rustix::process::DumpableBehavior::NotDumpable)
        )
    }

    #[cfg(not(target_os = "linux"))]
    const fn dumpable_flag_cleared() -> bool {
        // Mirrors the macOS/BSD `disable_macos_core_dumps` path: there's
        // nothing to query off Linux, so treat as the success state.
        true
    }
}

#[cfg(target_os = "windows")]
mod windows_stub {
    use super::CoreDumpHardening;

    /// Windows entry point.
    ///
    /// TODO(harden-windows-core-dump): wire the `windows` crate and call
    /// `SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS)` to
    /// suppress Windows Error Reporting crash dumps. Adding the dep is
    /// out of scope for this slice; doctor surfaces `Unsupported` so
    /// operators know the gap.
    #[must_use]
    pub fn disable_windows_core_dumps() -> CoreDumpHardening {
        CoreDumpHardening::Unsupported
    }

    #[must_use]
    pub fn core_dump_hardening_state() -> CoreDumpHardening {
        CoreDumpHardening::Unsupported
    }
}

#[cfg(test)]
mod tests {
    use super::{CoreDumpHardening, core_dump_hardening_state, disable_core_dumps};

    #[test]
    fn hardening_outcomes_render_as_doctor_labels() {
        assert_eq!(CoreDumpHardening::Active.to_string(), "active");
        assert_eq!(CoreDumpHardening::Unsupported.to_string(), "unsupported");
        assert_eq!(CoreDumpHardening::Degraded.to_string(), "degraded");
    }

    /// Cross-platform dispatcher smoke check: must not panic and must
    /// return a value the doctor can render.
    #[test]
    fn dispatcher_returns_a_well_formed_outcome() {
        let outcome = disable_core_dumps();
        assert!(matches!(
            outcome,
            CoreDumpHardening::Active
                | CoreDumpHardening::Degraded
                | CoreDumpHardening::Unsupported
        ));
        let _ = core_dump_hardening_state().to_string();
    }

    #[cfg(unix)]
    #[test]
    fn disable_core_dumps_lowers_rlimit_core_to_zero() {
        use rustix::process::{Resource, getrlimit};

        let outcome = disable_core_dumps();
        assert_eq!(outcome, CoreDumpHardening::Active);

        let limit = getrlimit(Resource::Core);
        assert_eq!(limit.current, Some(0));
        assert_eq!(limit.maximum, Some(0));
    }

    #[cfg(unix)]
    #[test]
    fn disable_core_dumps_is_idempotent() {
        let first = disable_core_dumps();
        let second = disable_core_dumps();
        assert_eq!(first, CoreDumpHardening::Active);
        assert_eq!(second, CoreDumpHardening::Active);
    }

    /// Subtask 1: explicit Linux entry-point smoke test — confirms
    /// `disable_linux_core_dumps` returns `Active` on Linux hosts.
    #[cfg(target_os = "linux")]
    #[test]
    fn disable_linux_core_dumps_returns_ok() {
        assert_eq!(super::unix::disable_linux_core_dumps(), CoreDumpHardening::Active);
    }

    /// Subtask 1: confirm `prctl(PR_GET_DUMPABLE)` returns 0 after
    /// `disable_linux_core_dumps()` runs.
    #[cfg(target_os = "linux")]
    #[test]
    fn disable_linux_core_dumps_clears_pr_get_dumpable() {
        use rustix::process::{DumpableBehavior, dumpable_behavior};

        let outcome = super::unix::disable_linux_core_dumps();
        assert_eq!(outcome, CoreDumpHardening::Active);
        assert!(matches!(dumpable_behavior(), Ok(DumpableBehavior::NotDumpable)));
    }

    /// Subtask 2: macOS / BSD entry-point returns `Active` after
    /// `RLIMIT_CORE = 0`.
    #[cfg(all(unix, not(target_os = "linux")))]
    #[test]
    fn disable_macos_core_dumps_returns_ok() {
        assert_eq!(super::unix::disable_macos_core_dumps(), CoreDumpHardening::Active);
    }

    /// Subtask 2: Windows stub reports `Unsupported` until the real
    /// `SetErrorMode` wiring lands.
    #[cfg(target_os = "windows")]
    #[test]
    fn disable_windows_core_dumps_returns_unsupported() {
        assert_eq!(
            super::windows_stub::disable_windows_core_dumps(),
            CoreDumpHardening::Unsupported
        );
    }

    #[cfg(not(any(unix, target_os = "windows")))]
    #[test]
    fn disable_core_dumps_reports_unsupported_on_other_targets() {
        assert_eq!(disable_core_dumps(), CoreDumpHardening::Unsupported);
    }
}
