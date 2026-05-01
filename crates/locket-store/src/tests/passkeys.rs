use std::error::Error;

use super::{insert_project_profile, open_initialized_store, test_device, test_passkey_credential};

#[test]
fn stores_lists_finds_and_revokes_passkey_credentials() -> Result<(), Box<dyn Error>> {
    let test_store = open_initialized_store()?;
    insert_passkey_project_bindings(&test_store.store)?;
    let credential = test_passkey_credential();

    test_store.store.insert_passkey_credential(&credential)?;

    let listed = test_store.store.list_passkey_credentials("lk_proj_test", false)?;
    assert_eq!(listed[0].device_id, "lk_dev_test");
    assert_eq!(listed[0].member_id.as_deref(), Some("lk_member_test"));
    assert_eq!(listed[0].public_key, vec![0x42; 65]);
    assert_eq!(listed[0].user_handle, vec![0x77; 32]);
    assert_eq!(listed, vec![credential.clone()]);
    assert_eq!(
        test_store.store.find_passkey_credentials("lk_proj_test", "work-laptop")?,
        vec![credential.clone()]
    );
    assert_eq!(
        test_store.store.find_passkey_credentials("lk_proj_test", "abcdef")?,
        vec![credential.clone()]
    );
    assert_eq!(
        test_store.store.find_passkey_credentials("lk_proj_test", "0xABCD")?,
        vec![credential]
    );

    assert!(test_store.store.revoke_passkey_credential("lk_proj_test", "lk_passkey_test", 200)?);
    assert!(test_store.store.list_passkey_credentials("lk_proj_test", false)?.is_empty());
    let all = test_store.store.list_passkey_credentials("lk_proj_test", true)?;
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].revoked_at, Some(200));
    Ok(())
}

#[test]
fn passkey_credentials_default_relying_party_id_when_omitted() -> Result<(), Box<dyn Error>> {
    let test_store = open_initialized_store()?;
    insert_passkey_project_bindings(&test_store.store)?;
    test_store.store.connection().execute(
        "INSERT INTO passkey_credentials(
           id, project_id, device_id, label, credential_id, public_key, transports_json,
           prf_capable, user_handle, created_at
         )
         VALUES (
           'lk_passkey_default_rp', 'lk_proj_test', 'lk_dev_test', 'default-rp',
           x'ABCDEF', x'01020304', '[]', 1, zeroblob(32), 100
         )",
        [],
    )?;

    let credentials = test_store.store.find_passkey_credentials("lk_proj_test", "default-rp")?;
    assert_eq!(credentials.len(), 1);
    assert_eq!(credentials[0].webauthn_relying_party_id, crate::DEFAULT_WEBAUTHN_RELYING_PARTY_ID);
    Ok(())
}

fn insert_passkey_project_bindings(store: &crate::Store) -> Result<(), Box<dyn Error>> {
    insert_project_profile(store)?;
    store.insert_device(&test_device())?;
    store.connection().execute(
        "INSERT INTO teams(id, project_id, name, created_at, updated_at)
         VALUES ('lk_team_test', 'lk_proj_test', 'team', 1, 1)",
        [],
    )?;
    store.connection().execute(
        "INSERT INTO team_members(id, team_id, device_id, display_name, role, joined_at)
         VALUES ('lk_member_test', 'lk_team_test', 'lk_dev_test', 'Work Laptop', 'owner', 1)",
        [],
    )?;
    Ok(())
}
