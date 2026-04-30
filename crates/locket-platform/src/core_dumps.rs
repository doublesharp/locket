//! Core-dump suppression for processes that hold key material.
//!
//! On Unix this lowers `RLIMIT_CORE` to zero (so the kernel writes no
//! core file even if the user's shell raised the limit) and on Linux
//! additionally clears `PR_SET_DUMPABLE` (so `/proc/<pid>/mem` and
//! `ptrace` from same-uid debuggers don't yield key material). Windows
//! support is out of scope for this slice; calling the helper there
//! returns `Unsupported` so diagnostics can surface the gap.

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
/// On Unix, sets the soft and hard `RLIMIT_CORE` to zero. On Linux,
/// also clears `PR_SET_DUMPABLE`. The call is idempotent and safe to
/// invoke from any process; on Windows it returns `Unsupported`.
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

    #[cfg(not(unix))]
    #[test]
    fn disable_core_dumps_reports_unsupported_on_windows() {
        assert_eq!(disable_core_dumps(), CoreDumpHardening::Unsupported);
    }
}
