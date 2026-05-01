//! Session-lock handling shared by explicit and platform-triggered locks.

use locket_store::{AuditWrite, Store, StoreError};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// Metadata-only source that caused the agent to lock.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionLockSource {
    /// Explicit `Lock` RPC or `locket lock`.
    #[default]
    Explicit,
    /// Unlock TTL or idle timeout elapsed.
    IdleTimeout,
    /// Agent process is exiting.
    ProcessExit,
    /// System sleep notification.
    SystemSleep,
    /// Screen lock notification.
    ScreenLock,
    /// User session switched, logged out, or the controlling session hung up.
    UserSessionSwitch,
}

impl SessionLockSource {
    /// Returns the stable audit metadata string for this source.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Explicit => "explicit",
            Self::IdleTimeout => "idle_timeout",
            Self::ProcessExit => "process_exit",
            Self::SystemSleep => "system_sleep",
            Self::ScreenLock => "screen_lock",
            Self::UserSessionSwitch => "user_session_switch",
        }
    }
}

/// Summary of memory state cleared by a lock event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionLockOutcome {
    /// Number of per-project cached keys cleared.
    pub cached_keys_cleared: usize,
    /// Number of live grants revoked.
    pub live_grants_revoked: usize,
}

impl SessionLockOutcome {
    /// Returns whether the lock event changed held agent state.
    #[must_use]
    pub const fn changed(self) -> bool {
        self.cached_keys_cleared > 0 || self.live_grants_revoked > 0
    }
}

/// Audit append context for a `LOCK` row.
pub struct SessionLockAudit<'a> {
    /// Project whose audit chain receives the row.
    pub project_id: &'a str,
    /// Optional profile id when the lock was tied to a project profile.
    pub profile_id: Option<&'a str>,
    /// Unwrapped project audit key.
    pub audit_key: &'a [u8],
    /// Source of the lock event.
    pub source: SessionLockSource,
    /// State cleared by the lock event.
    pub outcome: SessionLockOutcome,
    /// Event timestamp in Unix nanoseconds.
    pub timestamp: i64,
}

/// Builds the HMAC-covered metadata object for a `LOCK` audit row.
#[must_use]
pub fn lock_audit_metadata(source: SessionLockSource, outcome: SessionLockOutcome) -> Value {
    json!({
        "schema_version": 1,
        "action": "LOCK",
        "status": "OK",
        "source": source.as_str(),
        "cached_keys_cleared": outcome.cached_keys_cleared,
        "live_grants_revoked": outcome.live_grants_revoked,
        "metadata_only": true,
        "client_kind": "agent",
        "grant_actions": [],
        "ttl_seconds": 0,
    })
}

/// Appends a metadata-only `LOCK` audit row.
///
/// # Errors
///
/// Returns [`StoreError`] when the store rejects or cannot append the row.
pub fn append_lock_audit(
    store: &mut Store,
    audit: &SessionLockAudit<'_>,
) -> Result<(), StoreError> {
    let metadata = lock_audit_metadata(audit.source, audit.outcome);
    let write = AuditWrite {
        project_id: audit.project_id,
        profile_id: audit.profile_id,
        action: "LOCK",
        status: "OK",
        secret_name: None,
        command: None,
        metadata_json: &metadata,
        timestamp: audit.timestamp,
    };
    store.append_audit(audit.audit_key, &write)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_audit_row_is_metadata_only() -> Result<(), Box<dyn std::error::Error>> {
        let tempdir = tempfile::tempdir()?;
        let path = tempdir.path().join("locket.sqlite3");
        let mut store = Store::open(&path)?;
        store.initialize_schema()?;
        store.connection().execute(
            "INSERT INTO projects(id, name, created_at) VALUES ('lk_proj_test', 'test', 1)",
            [],
        )?;
        store.connection().execute(
            "INSERT INTO profiles(id, project_id, name, dangerous, created_at)
             VALUES ('lk_prof_test', 'lk_proj_test', 'default', 0, 1)",
            [],
        )?;
        let outcome = SessionLockOutcome { cached_keys_cleared: 2, live_grants_revoked: 3 };
        append_lock_audit(
            &mut store,
            &SessionLockAudit {
                project_id: "lk_proj_test",
                profile_id: Some("lk_prof_test"),
                audit_key: &[7_u8; 32],
                source: SessionLockSource::SystemSleep,
                outcome,
                timestamp: 123,
            },
        )?;

        let (action, status, profile_id, metadata): (String, String, String, String) =
            store.connection().query_row(
                "SELECT action, status, profile_id, metadata_json
                 FROM audit_log
                 WHERE project_id = 'lk_proj_test'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )?;
        let metadata: Value = serde_json::from_str(&metadata)?;

        assert_eq!(action, "LOCK");
        assert_eq!(status, "OK");
        assert_eq!(profile_id, "lk_prof_test");
        assert_eq!(metadata["action"], "LOCK");
        assert_eq!(metadata["status"], "OK");
        assert_eq!(metadata["source"], "system_sleep");
        assert_eq!(metadata["cached_keys_cleared"], 2);
        assert_eq!(metadata["live_grants_revoked"], 3);
        assert_eq!(metadata["metadata_only"], true);
        assert!(metadata.get("secret_name").is_none());
        assert!(metadata.get("command").is_none());
        Ok(())
    }
}
