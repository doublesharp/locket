//! Team sync RPCs must distinguish locked state from verified updates.
#![allow(unused_crate_dependencies)]
use locket_agent::{AgentSocketState, RequestEnvelope, ResponseEnvelope, dispatch};
#[tokio::test]
async fn locked_status_does_not_claim_verification() {
    let state = AgentSocketState::locked("test");
    let request = RequestEnvelope {
        v: 1,
        id: "status".into(),
        kind: "TeamSyncStatus".into(),
        payload: serde_json::json!({"project_id":"project"}),
    };
    let response = dispatch(&request, &state).await;
    assert!(
        matches!(response,ResponseEnvelope::Success(s) if s.payload["state"]=="locked" && s.payload["last_verified_at"].is_null())
    );
}
#[tokio::test]
async fn sync_mutation_requires_live_grant() {
    let state = AgentSocketState::locked("test");
    let request = RequestEnvelope {
        v: 1,
        id: "now".into(),
        kind: "TeamSyncNow".into(),
        payload: serde_json::json!({"project_id":"project"}),
    };
    let response = dispatch(&request, &state).await;
    assert!(matches!(response,ResponseEnvelope::Error(e) if e.error=="GrantRequired"));
}
