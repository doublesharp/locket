//! Metadata-only status payloads streamed by the agent.

use serde::{Deserialize, Serialize};

/// Metadata-only lock state reported by status calls.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum LockState {
    /// Agent is not holding unwrapped keys.
    Locked,
    /// Agent has unwrapped keys for the current user/session.
    Unlocked,
    /// Agent is unavailable or cannot determine lock state.
    Unknown,
}

/// Metadata-only status payload shared by `Status` and status events.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StatusPayload {
    /// Lock state.
    pub lock_state: LockState,
    /// Optional active project id or privacy alias.
    pub project_id: Option<String>,
    /// Optional active profile name or privacy alias.
    pub profile_name: Option<String>,
    /// Count of live grants, never grant tokens.
    pub live_grant_count: u32,
    /// Agent version string.
    pub agent_version: String,
}

impl StatusPayload {
    /// Creates a locked status payload with no active project context.
    #[must_use]
    pub fn locked(agent_version: impl Into<String>) -> Self {
        Self {
            lock_state: LockState::Locked,
            project_id: None,
            profile_name: None,
            live_grant_count: 0,
            agent_version: agent_version.into(),
        }
    }
}
