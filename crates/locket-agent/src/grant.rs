//! In-memory live grant records for the local agent.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Process identity attached to a live grant.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GrantBinding {
    /// Operating-system process id.
    pub pid: u32,
    /// Opaque platform start-time token captured when the grant was issued.
    pub process_start_time: String,
}

impl GrantBinding {
    /// Creates a process-bound grant identity.
    #[must_use]
    pub fn new(pid: u32, process_start_time: impl Into<String>) -> Self {
        Self { pid, process_start_time: process_start_time.into() }
    }
}

/// Metadata-only live grant record.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GrantRecord {
    /// Opaque grant id. This is never a secret value.
    pub grant_id: String,
    /// Process identity required to use the grant.
    pub binding: GrantBinding,
    /// Expiry timestamp in Unix nanoseconds.
    pub expires_at_unix_nanos: i128,
}

impl GrantRecord {
    /// Creates a metadata-only grant record.
    #[must_use]
    pub fn new(
        grant_id: impl Into<String>,
        binding: GrantBinding,
        expires_at_unix_nanos: i128,
    ) -> Self {
        Self { grant_id: grant_id.into(), binding, expires_at_unix_nanos }
    }
}

/// Result of validating a process-bound live grant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GrantValidation {
    /// The grant exists, is not expired, and still belongs to the same process.
    Valid,
    /// No live grant exists for the requested id.
    Unknown,
    /// The live grant has expired.
    Expired,
    /// The PID is missing or its start-time token changed.
    ProcessMismatch,
}

/// In-memory live grant table.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct GrantTable {
    grants: BTreeMap<String, GrantRecord>,
}

impl GrantTable {
    /// Insert or replace a live grant.
    pub fn insert(&mut self, grant: GrantRecord) {
        self.grants.insert(grant.grant_id.clone(), grant);
    }

    /// Remove a live grant.
    pub fn revoke(&mut self, grant_id: &str) -> Option<GrantRecord> {
        self.grants.remove(grant_id)
    }

    /// Count live grant records without exposing grant ids.
    #[must_use]
    pub fn len(&self) -> usize {
        self.grants.len()
    }

    /// Return whether the grant table is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.grants.is_empty()
    }

    /// Validate a live grant against time and process identity.
    #[must_use]
    pub fn validate(
        &self,
        grant_id: &str,
        now_unix_nanos: i128,
        current_binding: Option<&GrantBinding>,
    ) -> GrantValidation {
        let Some(grant) = self.grants.get(grant_id) else {
            return GrantValidation::Unknown;
        };
        if now_unix_nanos >= grant.expires_at_unix_nanos {
            return GrantValidation::Expired;
        }
        let Some(current_binding) = current_binding else {
            return GrantValidation::ProcessMismatch;
        };
        if grant.binding == *current_binding {
            GrantValidation::Valid
        } else {
            GrantValidation::ProcessMismatch
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{GrantBinding, GrantRecord, GrantTable, GrantValidation};

    #[test]
    fn grant_table_requires_pid_and_start_time_match() {
        let mut table = GrantTable::default();
        table.insert(GrantRecord::new("grant-1", GrantBinding::new(4242, "start-a"), 200));

        assert_eq!(
            table.validate("grant-1", 100, Some(&GrantBinding::new(4242, "start-a"))),
            GrantValidation::Valid
        );
        assert_eq!(
            table.validate("grant-1", 100, Some(&GrantBinding::new(4242, "start-b"))),
            GrantValidation::ProcessMismatch
        );
        assert_eq!(
            table.validate("grant-1", 100, Some(&GrantBinding::new(4343, "start-a"))),
            GrantValidation::ProcessMismatch
        );
    }

    #[test]
    fn grant_table_fails_closed_for_unknown_expired_and_missing_process() {
        let mut table = GrantTable::default();
        table.insert(GrantRecord::new("grant-1", GrantBinding::new(4242, "start-a"), 200));

        assert_eq!(table.validate("missing", 100, None), GrantValidation::Unknown);
        assert_eq!(
            table.validate("grant-1", 200, Some(&GrantBinding::new(4242, "start-a"))),
            GrantValidation::Expired
        );
        assert_eq!(table.validate("grant-1", 100, None), GrantValidation::ProcessMismatch);
    }
}
