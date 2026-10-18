//! Typed metadata-only requests for explicit pending-profile reconciliation.

use serde::{Deserialize, Serialize};

use crate::TeamSyncRequest;

/// Explicit local operation for a verified pending incoming profile.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum TeamSyncAction {
    /// Rename the colliding local profile while retaining its existing data.
    RenameProfile {
        /// Actual stored id of the local profile the user chose to rename.
        local_profile_id: String,
        /// New local profile name. Domain validation remains in the service.
        new_name: String,
    },
    /// Preserve a colliding local secret as an override before accepting team data.
    PreserveOverride {
        /// Actual stored id of the local secret the user chose to preserve.
        local_secret_id: String,
    },
}

/// Request for `TeamSyncReconcile`. The agent enforces its existing `TeamSync` grant.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TeamSyncReconcileRequest {
    /// Existing selected project, actual profile, store and process-bound grant.
    #[serde(flatten)]
    pub scope: TeamSyncRequest,
    /// Verified incoming profile id whose pending collision is being resolved.
    pub incoming_profile_id: String,
    /// Explicit user-selected metadata-only operation.
    pub action: TeamSyncAction,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn reconciliation_actions_have_distinct_metadata_only_wire_shapes()
    -> Result<(), serde_json::Error> {
        let rename = TeamSyncAction::RenameProfile {
            local_profile_id: "local-profile".into(),
            new_name: "preserved-local".into(),
        };
        assert_eq!(
            serde_json::to_value(&rename)?,
            json!({"kind":"rename_profile","local_profile_id":"local-profile","new_name":"preserved-local"})
        );
        assert_eq!(
            serde_json::from_value::<TeamSyncAction>(serde_json::to_value(&rename)?)?,
            rename
        );
        let preserve = TeamSyncAction::PreserveOverride { local_secret_id: "local-secret".into() };
        assert_eq!(
            serde_json::to_value(&preserve)?,
            json!({"kind":"preserve_override","local_secret_id":"local-secret"})
        );
        assert!(
            serde_json::from_value::<TeamSyncAction>(
                json!({"kind":"preserve_override","local_secret_id":"id","value":"not-accepted"})
            )
            .is_err()
        );
        assert!(
            serde_json::from_value::<TeamSyncAction>(
                json!({"kind":"rename_profile","local_secret_id":"id"})
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn reconciliation_scope_is_flat_and_does_not_contain_values() -> Result<(), serde_json::Error> {
        let request = TeamSyncReconcileRequest {
            scope: TeamSyncRequest {
                project_id: "project".into(),
                store_path: None,
                profile_id: Some("actual-profile".into()),
                grant_id: Some("grant".into()),
                binding: Some(crate::GrantBinding::new(123, "start")),
            },
            incoming_profile_id: "incoming".into(),
            action: TeamSyncAction::PreserveOverride { local_secret_id: "local-secret".into() },
        };
        let encoded = serde_json::to_value(request)?;
        assert_eq!(encoded["project_id"], "project");
        assert_eq!(encoded["profile_id"], "actual-profile");
        assert_eq!(encoded["action"]["kind"], "preserve_override");
        assert!(encoded.get("scope").is_none());
        assert!(encoded.get("value").is_none());
        Ok(())
    }
}
