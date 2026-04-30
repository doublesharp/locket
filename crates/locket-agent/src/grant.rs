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

/// Action set authorized by a live grant.
///
/// Spec: `docs/specs/agent.md:36-37`.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "PascalCase")]
pub enum GrantAction {
    /// Run a command policy.
    RunPolicy,
    /// Resolve an `lk://` reference.
    ResolveReference,
    /// Scan known secret values without persisting them.
    ScanKnownValues,
    /// Reveal one secret value through a gated path.
    Reveal,
    /// Copy one secret value through a gated path.
    Copy,
}

/// Metadata-only live grant record.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GrantRecord {
    /// Opaque grant id. This is never a secret value.
    pub grant_id: String,
    /// Project identifier the grant is scoped to.
    pub project_id: String,
    /// Profile identifier the grant is scoped to.
    pub profile_id: String,
    /// Authorized action.
    pub action: GrantAction,
    /// Process identity required to use the grant.
    pub binding: GrantBinding,
    /// Issue timestamp in Unix nanoseconds.
    pub issued_at_unix_nanos: i128,
    /// TTL in seconds.
    pub ttl_seconds: u64,
    /// Expiry timestamp in Unix nanoseconds.
    pub expires_at_unix_nanos: i128,
}

impl GrantRecord {
    /// Creates a metadata-only grant record.
    #[must_use]
    pub fn new(
        grant_id: impl Into<String>,
        project_id: impl Into<String>,
        profile_id: impl Into<String>,
        action: GrantAction,
        binding: GrantBinding,
        issued_at_unix_nanos: i128,
        ttl_seconds: u64,
        expires_at_unix_nanos: i128,
    ) -> Self {
        Self {
            grant_id: grant_id.into(),
            project_id: project_id.into(),
            profile_id: profile_id.into(),
            action,
            binding,
            issued_at_unix_nanos,
            ttl_seconds,
            expires_at_unix_nanos,
        }
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

    /// Remove every live grant record.
    pub fn clear(&mut self) {
        self.grants.clear();
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
        project_id: &str,
        profile_id: &str,
        action: GrantAction,
        now_unix_nanos: i128,
        current_binding: Option<&GrantBinding>,
    ) -> GrantValidation {
        let Some(grant) = self.grants.get(grant_id) else {
            return GrantValidation::Unknown;
        };
        if now_unix_nanos >= grant.expires_at_unix_nanos {
            return GrantValidation::Expired;
        }
        if grant.project_id != project_id
            || grant.profile_id != profile_id
            || grant.action != action
        {
            return GrantValidation::ProcessMismatch;
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

    /// Returns the grant record for a given id without mutating the table.
    #[must_use]
    pub fn get(&self, grant_id: &str) -> Option<&GrantRecord> {
        self.grants.get(grant_id)
    }

    /// Issues a fresh grant. The id is a typed opaque `GrantId` (`lk_grant_<32 hex>`).
    /// Callers are responsible for emitting the `RequestGrant` audit row.
    ///
    /// # Errors
    ///
    /// Returns `IdGenerationError` if the OS RNG fails.
    pub fn issue(
        &mut self,
        payload: RequestGrantPayload,
        issued_at_unix_nanos: i128,
        expires_at_unix_nanos: i128,
    ) -> Result<GrantRecord, locket_core::id::IdGenerationError> {
        let grant_id = locket_core::id::GrantId::generate()?;
        let record = GrantRecord::new(
            grant_id.into_string(),
            payload.project_id,
            payload.profile_id,
            payload.action,
            payload.binding,
            issued_at_unix_nanos,
            payload.ttl_seconds,
            expires_at_unix_nanos,
        );
        self.insert(record.clone());
        Ok(record)
    }
}

/// Wire payload for `RequestGrant`.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RequestGrantPayload {
    /// Project identifier the grant is scoped to.
    pub project_id: String,
    /// Profile identifier the grant is scoped to.
    pub profile_id: String,
    /// Action set authorized by this grant.
    pub action: GrantAction,
    /// TTL in seconds.
    pub ttl_seconds: u64,
    /// Caller's process binding.
    pub binding: GrantBinding,
}

/// Wire payload for `RevokeGrant`/`ExpireGrant`.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GrantIdPayload {
    /// Grant id to revoke or mark expired.
    pub grant_id: String,
}

#[cfg(test)]
mod tests {
    use super::{
        GrantAction, GrantBinding, GrantRecord, GrantTable, GrantValidation, RequestGrantPayload,
    };

    #[test]
    fn grant_table_requires_pid_and_start_time_match() {
        let mut table = GrantTable::default();
        table.insert(GrantRecord::new(
            "grant-1",
            "p-1",
            "prof-1",
            GrantAction::RunPolicy,
            GrantBinding::new(4242, "start-a"),
            100,
            30,
            200,
        ));

        assert_eq!(
            table.validate(
                "grant-1",
                "p-1",
                "prof-1",
                GrantAction::RunPolicy,
                100,
                Some(&GrantBinding::new(4242, "start-a")),
            ),
            GrantValidation::Valid
        );
        assert_eq!(
            table.validate(
                "grant-1",
                "p-1",
                "prof-1",
                GrantAction::RunPolicy,
                100,
                Some(&GrantBinding::new(4242, "start-b")),
            ),
            GrantValidation::ProcessMismatch
        );
        assert_eq!(
            table.validate(
                "grant-1",
                "p-1",
                "prof-1",
                GrantAction::RunPolicy,
                100,
                Some(&GrantBinding::new(4343, "start-a")),
            ),
            GrantValidation::ProcessMismatch
        );
    }

    #[test]
    fn grant_table_fails_closed_for_unknown_expired_and_missing_process() {
        let mut table = GrantTable::default();
        table.insert(GrantRecord::new(
            "grant-1",
            "p-1",
            "prof-1",
            GrantAction::RunPolicy,
            GrantBinding::new(4242, "start-a"),
            100,
            30,
            200,
        ));

        assert_eq!(
            table.validate("missing", "p-1", "prof-1", GrantAction::RunPolicy, 100, None),
            GrantValidation::Unknown
        );
        assert_eq!(
            table.validate(
                "grant-1",
                "p-1",
                "prof-1",
                GrantAction::RunPolicy,
                200,
                Some(&GrantBinding::new(4242, "start-a")),
            ),
            GrantValidation::Expired
        );
        assert_eq!(
            table.validate("grant-1", "p-1", "prof-1", GrantAction::RunPolicy, 100, None),
            GrantValidation::ProcessMismatch
        );
    }

    #[test]
    fn grant_table_scope_is_part_of_validation() {
        let mut table = GrantTable::default();
        table.insert(GrantRecord::new(
            "grant-1",
            "p-1",
            "prof-1",
            GrantAction::Reveal,
            GrantBinding::new(4242, "start-a"),
            100,
            30,
            200,
        ));
        let binding = GrantBinding::new(4242, "start-a");

        assert_eq!(
            table.validate("grant-1", "p-2", "prof-1", GrantAction::Reveal, 100, Some(&binding),),
            GrantValidation::ProcessMismatch
        );
        assert_eq!(
            table.validate("grant-1", "p-1", "prof-2", GrantAction::Reveal, 100, Some(&binding),),
            GrantValidation::ProcessMismatch
        );
        assert_eq!(
            table.validate("grant-1", "p-1", "prof-1", GrantAction::Copy, 100, Some(&binding),),
            GrantValidation::ProcessMismatch
        );
    }

    #[test]
    fn issued_grants_retain_metadata_without_values() {
        let mut table = GrantTable::default();
        let record = table
            .issue(
                RequestGrantPayload {
                    project_id: "p-1".to_owned(),
                    profile_id: "prof-1".to_owned(),
                    action: GrantAction::ScanKnownValues,
                    ttl_seconds: 45,
                    binding: GrantBinding::new(4242, "start-a"),
                },
                100,
                45_000_000_100,
            )
            .expect("grant id");

        assert_eq!(record.project_id, "p-1");
        assert_eq!(record.profile_id, "prof-1");
        assert_eq!(record.action, GrantAction::ScanKnownValues);
        assert_eq!(record.issued_at_unix_nanos, 100);
        assert_eq!(record.ttl_seconds, 45);
        assert_eq!(record.expires_at_unix_nanos, 45_000_000_100);
    }
}
