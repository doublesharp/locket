//! Best-effort wiring of [`LockedVaultAuditLogger`] into the CLI's
//! refused-while-locked early-return sites.
//!
//! The encrypted audit chain cannot record refusals while the vault is
//! locked, so each `UnlockRequired` early-return mirrors a metadata-only
//! row into the degraded-audit log under `${LOCKET_HOME}/audit-degraded.log`.
//! See `crates/locket-platform/src/locked_vault_audit.rs` for the file
//! format, rotation policy, and 0600 permission contract.
//!
//! Logging here is best-effort: a failure to append the row never masks
//! a legitimate `UnlockRequired` return.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use locket_platform::{LockedVaultAuditLogger, LockedVaultDenialRow};

use crate::runtime::RuntimeContext;

/// Resolves the locket-home equivalent for the running CLI: the parent
/// directory of `store.db` is the per-user data directory and the same
/// location the agent uses when constructing platform paths.
fn locket_home_for_context(context: &RuntimeContext) -> Option<PathBuf> {
    context.store_path.parent().map(std::path::Path::to_path_buf)
}

fn now_nanos_or_zero() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| i64::try_from(elapsed.as_nanos()).ok())
        .unwrap_or(0)
}

/// Appends a `DENIED_LOCKED` row for a refused-while-locked CLI command.
///
/// Always returns; any I/O or serialization failure is silently dropped
/// so the caller's typed `UnlockRequired` return is not masked.
pub fn record_locked_refusal(
    context: &RuntimeContext,
    action: &str,
    project_id: Option<&str>,
    command: &str,
) {
    let Some(home) = locket_home_for_context(context) else {
        return;
    };
    let logger = LockedVaultAuditLogger::new(&home);
    let row =
        LockedVaultDenialRow::new(action, project_id, now_nanos_or_zero(), "vault_locked", command);
    let _ = logger.append(&row);
}

// Higher-level coverage lives in `tests/secrets_crud.rs` and
// `tests/ai_safe.rs`, where the full CLI dispatch hits these helpers
// through real refusal sites. Adding a duplicate fixture here would
// re-implement the test-only `RuntimeContext` plumbing, so the helper
// is exercised end-to-end via those crate-level tests rather than a
// stand-alone unit test.
