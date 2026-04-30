//! Tests for `Store::mark_invite_accepted` (invite-replay-protect).

use std::error::Error;

use crate::error::StoreError;

use super::{insert_project_profile, open_initialized_store};

fn insert_team_with_pending_invite(
    store: &crate::Store,
    invite_id: &str,
) -> Result<(), Box<dyn Error>> {
    let connection = store.connection();
    connection.execute(
        "INSERT INTO teams(id, project_id, name, created_at, updated_at)
         VALUES ('lk_team_test', 'lk_proj_test', 'app-team', 1, 1)",
        [],
    )?;
    connection.execute(
        "INSERT INTO team_members(id, team_id, display_name, role, joined_at)
         VALUES ('lk_member_test', 'lk_team_test', 'Alice', 'owner', 1)",
        [],
    )?;
    connection.execute(
        "INSERT INTO team_invites(
           id, team_id, issuer_member_id, recipient_device_fingerprint, role, profiles_json,
           nonce, created_at, expires_at
         )
         VALUES (
           ?1, 'lk_team_test', 'lk_member_test', 'recipient-fp',
           'developer', '[\"dev\"]', zeroblob(24), 1, 1000
         )",
        [invite_id],
    )?;
    Ok(())
}

#[test]
fn mark_invite_accepted_first_call_sets_accepted_at() -> Result<(), Box<dyn Error>> {
    let test = open_initialized_store()?;
    insert_project_profile(&test.store)?;
    insert_team_with_pending_invite(&test.store, "lk_invite_first")?;

    test.store.mark_invite_accepted("lk_invite_first", 500)?;

    let accepted_at: Option<i64> = test
        .store
        .connection()
        .query_row(
            "SELECT accepted_at FROM team_invites WHERE id = 'lk_invite_first'",
            [],
            |row| row.get(0),
        )?;
    assert_eq!(accepted_at, Some(500));
    Ok(())
}

#[test]
fn mark_invite_accepted_second_call_returns_replay_detected() -> Result<(), Box<dyn Error>> {
    let test = open_initialized_store()?;
    insert_project_profile(&test.store)?;
    insert_team_with_pending_invite(&test.store, "lk_invite_replay")?;

    test.store.mark_invite_accepted("lk_invite_replay", 500)?;

    let second = test.store.mark_invite_accepted("lk_invite_replay", 600);
    let Err(StoreError::InviteReplayDetected { invite_id }) = second else {
        panic!("expected InviteReplayDetected, got {second:?}");
    };
    assert_eq!(invite_id, "lk_invite_replay");

    // The original accepted_at must not be overwritten by the replay.
    let accepted_at: Option<i64> = test
        .store
        .connection()
        .query_row(
            "SELECT accepted_at FROM team_invites WHERE id = 'lk_invite_replay'",
            [],
            |row| row.get(0),
        )?;
    assert_eq!(accepted_at, Some(500));
    Ok(())
}

#[test]
fn mark_invite_accepted_revoked_invite_returns_replay_detected() -> Result<(), Box<dyn Error>> {
    let test = open_initialized_store()?;
    insert_project_profile(&test.store)?;
    insert_team_with_pending_invite(&test.store, "lk_invite_revoked")?;

    test.store.connection().execute(
        "UPDATE team_invites SET revoked_at = 700 WHERE id = 'lk_invite_revoked'",
        [],
    )?;

    let result = test.store.mark_invite_accepted("lk_invite_revoked", 800);
    let Err(StoreError::InviteReplayDetected { invite_id }) = result else {
        panic!("expected InviteReplayDetected on revoked invite, got {result:?}");
    };
    assert_eq!(invite_id, "lk_invite_revoked");
    Ok(())
}

#[test]
fn mark_invite_accepted_unknown_invite_returns_invite_not_found() -> Result<(), Box<dyn Error>> {
    let test = open_initialized_store()?;
    insert_project_profile(&test.store)?;

    let result = test.store.mark_invite_accepted("lk_invite_nope", 500);
    let Err(StoreError::InviteNotFound { invite_id }) = result else {
        panic!("expected InviteNotFound, got {result:?}");
    };
    assert_eq!(invite_id, "lk_invite_nope");
    Ok(())
}

#[test]
fn invite_replay_detected_maps_to_locket_replay_detected() -> Result<(), Box<dyn Error>> {
    let test = open_initialized_store()?;
    insert_project_profile(&test.store)?;
    insert_team_with_pending_invite(&test.store, "lk_invite_mapping")?;
    test.store.mark_invite_accepted("lk_invite_mapping", 500)?;

    let second = test.store.mark_invite_accepted("lk_invite_mapping", 600);
    let Err(error) = second else {
        panic!("expected error, got Ok");
    };
    assert_eq!(error.locket_error(), locket_core::LocketError::ReplayDetected);
    Ok(())
}
