use std::error::Error;

use super::{insert_project_profile, open_initialized_store, test_device};

#[test]
fn stores_lists_and_revokes_devices() -> Result<(), Box<dyn Error>> {
    let test_store = open_initialized_store()?;
    insert_project_profile(&test_store.store)?;
    let device = test_device();

    test_store.store.insert_device(&device)?;

    assert_eq!(test_store.store.get_active_local_device("lk_proj_test")?, Some(device.clone()));
    assert_eq!(test_store.store.find_device("lk_proj_test", "work-laptop")?, Some(device.clone()));
    assert_eq!(test_store.store.find_device("lk_proj_test", &device.fingerprint)?, Some(device));

    assert!(test_store.store.revoke_device("lk_proj_test", "lk_dev_test", 200)?);
    assert!(test_store.store.get_active_local_device("lk_proj_test")?.is_none());
    assert!(test_store.store.list_devices("lk_proj_test", false)?.is_empty());
    let all = test_store.store.list_devices("lk_proj_test", true)?;
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].revoked_at, Some(200));
    Ok(())
}

#[test]
fn devices_allow_name_and_fingerprint_reuse_after_revocation() -> Result<(), Box<dyn Error>> {
    let test_store = open_initialized_store()?;
    insert_project_profile(&test_store.store)?;
    let device = test_device();
    test_store.store.insert_device(&device)?;

    let mut duplicate = device;
    duplicate.id = "lk_dev_duplicate".to_owned();
    assert!(
        test_store.store.insert_device(&duplicate).is_err(),
        "active duplicate name/fingerprint must be rejected"
    );

    assert!(test_store.store.revoke_device("lk_proj_test", "lk_dev_test", 200)?);
    test_store.store.insert_device(&duplicate)?;

    let active = test_store.store.list_devices("lk_proj_test", false)?;
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].id, "lk_dev_duplicate");
    Ok(())
}
