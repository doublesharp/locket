use std::error::Error;

use crate::ProjectRecord;

use super::open_initialized_store;

#[test]
fn project_insert_if_absent_is_idempotent() -> Result<(), Box<dyn Error>> {
    let test_store = open_initialized_store()?;

    let inserted = test_store.store.insert_project_if_absent("lk_proj_test", "test", 100)?;
    assert!(inserted);

    let inserted = test_store.store.insert_project_if_absent("lk_proj_test", "changed", 200)?;
    assert!(!inserted);

    assert_eq!(
        test_store.store.get_project("lk_proj_test")?,
        Some(ProjectRecord {
            id: "lk_proj_test".to_owned(),
            name: "test".to_owned(),
            created_at: 100,
        })
    );
    assert_eq!(test_store.store.get_project("lk_proj_missing")?, None);

    Ok(())
}
