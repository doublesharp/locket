//! Memory locking for processes that hold key material.
//!
//! Locking pages with `mlockall` keeps unwrapped key material out of
//! the swap file even if the operating system would otherwise page
//! the process. The CLI and the agent both call this at startup. On
//! Linux, success requires `RLIMIT_MEMLOCK` to permit at least the
//! process's working set; otherwise the call falls back to
//! `Degraded` and `locket doctor` surfaces the gap.
//!
//! Windows support is out of scope for this slice; the helper returns
//! `Unsupported` there.

use std::fmt::{self, Display};

/// Outcome of a [`lock_process_memory`] call.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryLockHardening {
    /// `mlockall(MCL_CURRENT | MCL_FUTURE)` succeeded.
    Active,
    /// The platform has no implementation in this build (currently
    /// Windows). Diagnostics should surface this so users know the
    /// fall-back state.
    Unsupported,
    /// The lock attempt failed (most often `RLIMIT_MEMLOCK` is too
    /// small for the working set). Key material is still wrapped in
    /// `Zeroizing` buffers, but pages may reach swap.
    Degraded,
}

impl Display for MemoryLockHardening {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Active => "active",
            Self::Unsupported => "unsupported",
            Self::Degraded => "degraded",
        })
    }
}

/// Locks the calling process's current and future memory pages.
///
/// Idempotent: calling it again after a successful lock is a no-op
/// from the process's perspective.
// `const fn` would require all return paths to be const-evaluable, but
// the Linux path calls into rustix which is not. The macOS/Windows
// path is const-friendly on its own, but the function as a whole
// can't be const.
#[allow(clippy::missing_const_for_fn)]
#[must_use]
pub fn lock_process_memory() -> MemoryLockHardening {
    #[cfg(any(
        target_os = "linux",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd"
    ))]
    {
        mlockall_supported::lock_process_memory()
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd"
    )))]
    {
        // macOS does not provide `mlockall`; per-buffer `mlock` is the
        // only option and isn't useful for the small key buffers
        // Locket already wraps in `Zeroizing`. Windows has no
        // equivalent. Both surface as `Unsupported` so doctor can
        // report the gap.
        MemoryLockHardening::Unsupported
    }
}

/// Returns the current memory-lock hardening state without changing it.
///
/// `mlockall` doesn't expose a queryable "is the process locked" bit
/// the way `RLIMIT_CORE` does, so this helper just calls
/// [`lock_process_memory`] again — it's idempotent and the kernel
/// returns success when the requested flags are already in effect.
#[must_use]
pub fn memory_lock_hardening_state() -> MemoryLockHardening {
    lock_process_memory()
}

#[cfg(any(
    target_os = "linux",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd"
))]
mod mlockall_supported {
    use rustix::mm::{MlockAllFlags, mlockall};

    use super::MemoryLockHardening;

    pub fn lock_process_memory() -> MemoryLockHardening {
        let flags = MlockAllFlags::CURRENT | MlockAllFlags::FUTURE;
        if mlockall(flags).is_ok() {
            MemoryLockHardening::Active
        } else {
            MemoryLockHardening::Degraded
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{MemoryLockHardening, lock_process_memory, memory_lock_hardening_state};

    #[test]
    fn hardening_outcomes_render_as_doctor_labels() {
        assert_eq!(MemoryLockHardening::Active.to_string(), "active");
        assert_eq!(MemoryLockHardening::Unsupported.to_string(), "unsupported");
        assert_eq!(MemoryLockHardening::Degraded.to_string(), "degraded");
    }

    #[test]
    fn lock_process_memory_outcome_matches_platform() {
        let outcome = lock_process_memory();
        if cfg!(any(
            target_os = "linux",
            target_os = "freebsd",
            target_os = "netbsd",
            target_os = "openbsd",
        )) {
            // The success path requires RLIMIT_MEMLOCK to be high
            // enough for the test process; some sandboxes don't allow
            // it, so accept either Active or Degraded and let the
            // doctor surface the difference.
            assert!(matches!(outcome, MemoryLockHardening::Active | MemoryLockHardening::Degraded));
        } else {
            // macOS lacks `mlockall`; Windows lacks any equivalent.
            assert_eq!(outcome, MemoryLockHardening::Unsupported);
        }
    }

    #[test]
    fn state_query_matches_lock_outcome() {
        // `memory_lock_hardening_state` is just `lock_process_memory`
        // again, so the result should be one of the same variants.
        let first = lock_process_memory();
        let second = memory_lock_hardening_state();
        assert_eq!(first, second);
    }
}
