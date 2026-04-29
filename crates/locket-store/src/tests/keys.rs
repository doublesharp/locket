use std::error::Error;

use crate::KeyRecord;

use super::{insert_project_profile, open_initialized_store};

#[test]
fn key_insert_get_by_scope_and_id() -> Result<(), Box<dyn Error>> {
    let test_store = open_initialized_store()?;
    insert_project_profile(&test_store.store)?;

    let key = KeyRecord {
        id: "lk_key_test".to_owned(),
        project_id: "lk_proj_test".to_owned(),
        profile_id: Some("lk_prof_test".to_owned()),
        purpose: "profile-secret".to_owned(),
        wrapped_material: vec![1, 2, 3],
        nonce: [4; 24],
        created_at: 200,
    };
    test_store.store.insert_key(&key)?;

    let project_key = KeyRecord {
        id: "lk_key_project".to_owned(),
        project_id: "lk_proj_test".to_owned(),
        profile_id: None,
        purpose: "project-metadata".to_owned(),
        wrapped_material: vec![5, 6, 7],
        nonce: [8; 24],
        created_at: 300,
    };
    test_store.store.insert_key(&project_key)?;

    assert_eq!(test_store.store.get_key("lk_key_test")?, Some(key.clone()));
    assert_eq!(
        test_store.store.get_key_by_scope(
            "lk_proj_test",
            Some("lk_prof_test"),
            "profile-secret"
        )?,
        Some(key)
    );
    assert_eq!(
        test_store.store.get_key_by_scope("lk_proj_test", None, "project-metadata")?,
        Some(project_key.clone())
    );
    assert_eq!(test_store.store.get_key("lk_key_project")?, Some(project_key));

    Ok(())
}

#[test]
fn key_scope_check_rejects_profile_purpose_without_profile() -> Result<(), Box<dyn Error>> {
    let test_store = open_initialized_store()?;
    test_store.store.connection().execute(
        "INSERT INTO projects(id, name, created_at) VALUES ('lk_proj_test', 'test', 1)",
        [],
    )?;

    let result = test_store.store.connection().execute(
        "INSERT INTO keys(id, project_id, profile_id, purpose, wrapped_material, nonce, created_at)
         VALUES (
           'lk_key_bad', 'lk_proj_test', NULL, 'profile-secret',
           x'01', x'000000000000000000000000000000000000000000000000', 1
         )",
        [],
    );

    assert!(result.is_err());
    Ok(())
}
