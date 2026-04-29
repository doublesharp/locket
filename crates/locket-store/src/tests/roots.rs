use std::error::Error;

use crate::ProjectRootRecord;

use super::open_initialized_store;

#[test]
fn trust_project_root_upserts_and_checks_root_hash() -> Result<(), Box<dyn Error>> {
    let test_store = open_initialized_store()?;
    test_store.store.insert_project_if_absent("lk_proj_test", "test", 100)?;

    let root_hash = [7_u8; 32];
    assert!(!test_store.store.project_root_is_trusted("lk_proj_test", &root_hash)?);

    test_store.store.trust_project_root("lk_proj_test", &root_hash, Some("/tmp/app"), 200)?;
    assert!(test_store.store.project_root_is_trusted("lk_proj_test", &root_hash)?);

    test_store.store.trust_project_root("lk_proj_test", &root_hash, Some("/tmp/app2"), 300)?;
    let row_count = test_store.store.connection().query_row(
        "SELECT COUNT(*) FROM project_roots WHERE project_id = 'lk_proj_test'",
        [],
        |row| row.get::<_, i64>(0),
    )?;
    assert_eq!(row_count, 1);
    assert_eq!(
        test_store.store.list_project_roots("lk_proj_test")?,
        vec![ProjectRootRecord {
            project_id: "lk_proj_test".to_owned(),
            root_hash,
            display_path: Some("/tmp/app2".to_owned()),
            created_at: 200,
            last_seen_at: Some(300),
        }]
    );
    assert!(test_store.store.untrust_project_root("lk_proj_test", &root_hash)?);
    assert!(!test_store.store.untrust_project_root("lk_proj_test", &root_hash)?);
    assert!(!test_store.store.project_root_is_trusted("lk_proj_test", &root_hash)?);

    Ok(())
}
