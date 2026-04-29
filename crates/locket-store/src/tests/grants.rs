use std::error::Error;

use crate::DirectoryGrantRecord;

use super::open_initialized_store;

#[test]
fn directory_grants_are_profile_scoped_and_revocable() -> Result<(), Box<dyn Error>> {
    let test_store = open_initialized_store()?;
    test_store.store.insert_project_if_absent("lk_proj_test", "test", 100)?;
    test_store.store.insert_profile_if_absent("lk_prof_dev", "lk_proj_test", "dev", false, 100)?;
    test_store.store.insert_profile_if_absent(
        "lk_prof_prod",
        "lk_proj_test",
        "prod",
        false,
        100,
    )?;

    let root_hash = [1_u8; 32];
    let directory_hash = [2_u8; 32];
    let grant = DirectoryGrantRecord {
        grant_id: "lk_dgrant_dev".to_owned(),
        project_id: "lk_proj_test".to_owned(),
        profile_id: "lk_prof_dev".to_owned(),
        root_hash,
        directory_hash,
        grant_scope: "project-root".to_owned(),
        display_path: Some("/tmp/app".to_owned()),
        created_at: 200,
        updated_at: 200,
    };

    test_store.store.allow_directory_grant(&grant)?;
    assert_eq!(
        test_store.store.get_directory_grant(
            "lk_proj_test",
            "lk_prof_dev",
            &root_hash,
            &directory_hash,
            "project-root",
        )?,
        Some(grant.clone())
    );
    assert_eq!(
        test_store.store.get_directory_grant(
            "lk_proj_test",
            "lk_prof_prod",
            &root_hash,
            &directory_hash,
            "project-root",
        )?,
        None
    );

    let mut refreshed = grant;
    refreshed.display_path = Some("/tmp/app-renamed".to_owned());
    refreshed.updated_at = 300;
    test_store.store.allow_directory_grant(&refreshed)?;
    let refreshed_row = test_store
        .store
        .get_directory_grant(
            "lk_proj_test",
            "lk_prof_dev",
            &root_hash,
            &directory_hash,
            "project-root",
        )?
        .ok_or("grant should exist")?;
    assert_eq!(refreshed_row.created_at, 200);
    assert_eq!(refreshed_row.updated_at, 300);
    assert_eq!(refreshed_row.display_path.as_deref(), Some("/tmp/app-renamed"));

    assert!(test_store.store.deny_directory_grant(
        "lk_proj_test",
        "lk_prof_dev",
        &root_hash,
        &directory_hash,
        "project-root",
    )?);
    assert!(!test_store.store.deny_directory_grant(
        "lk_proj_test",
        "lk_prof_dev",
        &root_hash,
        &directory_hash,
        "project-root",
    )?);

    Ok(())
}

#[test]
fn directory_grants_can_be_revoked_by_root() -> Result<(), Box<dyn Error>> {
    let test_store = open_initialized_store()?;
    test_store.store.insert_project_if_absent("lk_proj_test", "test", 100)?;
    test_store.store.insert_profile_if_absent("lk_prof_dev", "lk_proj_test", "dev", false, 100)?;
    test_store.store.insert_profile_if_absent(
        "lk_prof_prod",
        "lk_proj_test",
        "prod",
        false,
        100,
    )?;

    let root_hash = [1_u8; 32];
    let other_root_hash = [9_u8; 32];
    let directory_hash = [2_u8; 32];
    for (grant_id, profile_id, root_hash) in [
        ("lk_dgrant_dev", "lk_prof_dev", root_hash),
        ("lk_dgrant_prod", "lk_prof_prod", root_hash),
        ("lk_dgrant_other", "lk_prof_dev", other_root_hash),
    ] {
        test_store.store.allow_directory_grant(&DirectoryGrantRecord {
            grant_id: grant_id.to_owned(),
            project_id: "lk_proj_test".to_owned(),
            profile_id: profile_id.to_owned(),
            root_hash,
            directory_hash,
            grant_scope: "project-root".to_owned(),
            display_path: Some("/tmp/app".to_owned()),
            created_at: 200,
            updated_at: 200,
        })?;
    }

    assert_eq!(test_store.store.deny_directory_grants_for_root("lk_proj_test", &root_hash,)?, 2);
    assert_eq!(test_store.store.deny_directory_grants_for_root("lk_proj_test", &root_hash,)?, 0);
    let remaining_count: u32 = test_store.store.connection().query_row(
        "SELECT COUNT(*) FROM directory_grants WHERE root_hash = ?1",
        [other_root_hash.as_slice()],
        |row| row.get(0),
    )?;
    assert_eq!(remaining_count, 1);

    Ok(())
}
