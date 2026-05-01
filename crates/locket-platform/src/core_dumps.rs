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
//! debuggers don't yield key material). On other Unixes only
//! `RLIMIT_CORE = 0` is available — `prctl` has no portable equivalent.
//! Windows support is out of scope for this slice; calling the helper
//! there returns `Unsupported` so diagnostics can surface the gap.

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
/// On Linux this delegates to [`unix::disable_linux_core_dumps`], which
/// runs `prctl(PR_SET_DUMPABLE, 0)` and `setrlimit(RLIMIT_CORE, 0, 0)`.
/// On other Unixes only `RLIMIT_CORE = 0` is available. On Windows it
/// returns `Unsupported`. The call is idempotent and safe to invoke
/// from any process.
#[must_use]
pub fn disable_core_dumps() -> CoreDumpHardening {
    #[cfg(unix)]
    {
        unix::disable_core_dumps()
    }
    #[cfg(not(unix))]
    {
        CoreDumpHardening::Unsupported
    }
}

/// Returns the current core-dump hardening state without changing it.
///
/// This is what `locket doctor` reports — `disable_core_dumps()` is
/// already called once at process startup, so this just inspects
/// `RLIMIT_CORE` (and `PR_GET_DUMPABLE` on Linux) and reports whether
/// the mitigations stuck.
#[must_use]
pub fn core_dump_hardening_state() -> CoreDumpHardening {
    #[cfg(unix)]
    {
        unix::core_dump_hardening_state()
    }
    #[cfg(not(unix))]
    {
        CoreDumpHardening::Unsupported
    }
}

#[cfg(unix)]
mod unix {
    use rustix::process::{Resource, Rlimit, getrlimit, setrlimit};

    use super::CoreDumpHardening;

    pub fn disable_core_dumps() -> CoreDumpHardening {
        #[cfg(target_os = "linux")]
        {
            disable_linux_core_dumps()
        }
        #[cfg(not(target_os = "linux"))]
        {
            let core_ok = set_core_rlimit_zero();
            let dumpable_ok = clear_dumpable_flag();
            if core_ok && dumpable_ok {
                CoreDumpHardening::Active
            } else {
                CoreDumpHardening::Degraded
            }
        }
    }

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

    #[cfg(not(target_os = "linux"))]
    const fn clear_dumpable_flag() -> bool {
        // No equivalent on macOS/BSD: `RLIMIT_CORE = 0` is the supported
        // mitigation. Treat as success so the caller doesn't see a
        // false `Degraded`.
        true
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
        // Mirrors `clear_dumpable_flag`: there's nothing to query off
        // Linux, so treat as the success state.
        true
    }
}

#[cfg(test)]
mod tests {
    use super::{CoreDumpHardening, disable_core_dumps};

    #[test]
    fn hardening_outcomes_render_as_doctor_labels() {
        assert_eq!(CoreDumpHardening::Active.to_string(), "active");
        assert_eq!(CoreDumpHardening::Unsupported.to_string(), "unsupported");
        assert_eq!(CoreDumpHardening::Degraded.to_string(), "degraded");
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

    #[cfg(not(unix))]
    #[test]
    fn disable_core_dumps_reports_unsupported_on_windows() {
        assert_eq!(disable_core_dumps(), CoreDumpHardening::Unsupported);
    }
}
