use std::error::Error;

use super::{insert_project_profile, open_initialized_store, test_passkey_credential};

#[test]
fn stores_lists_finds_and_revokes_passkey_credentials() -> Result<(), Box<dyn Error>> {
    let test_store = open_initialized_store()?;
    insert_project_profile(&test_store.store)?;
    let credential = test_passkey_credential();

    test_store.store.insert_passkey_credential(&credential)?;

    assert_eq!(
        test_store.store.list_passkey_credentials("lk_proj_test", false)?,
        vec![credential.clone()]
    );
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
