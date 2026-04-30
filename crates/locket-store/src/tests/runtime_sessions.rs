use std::error::Error;
use std::str::FromStr;

use crate::RuntimeSessionSecretNameRetention;

use super::{insert_project_profile, open_initialized_store, test_runtime_session};

#[test]
fn runtime_sessions_insert_complete_and_list_incomplete() -> Result<(), Box<dyn Error>> {
    let test_store = open_initialized_store()?;
    insert_project_profile(&test_store.store)?;

    let first = test_runtime_session("lk_sess_first", 100);
    let second = test_runtime_session("lk_sess_second", 200);
    test_store.store.insert_runtime_session(&first)?;
    test_store.store.insert_runtime_session(&second)?;

    assert_eq!(
        test_store.store.list_incomplete_runtime_sessions("lk_proj_test")?,
        vec![first, second.clone()]
    );

    assert!(test_store.store.mark_runtime_session_completed(
        "lk_sess_first",
        150,
        Some(0),
        Some(2)
    )?);
    assert!(!test_store.store.mark_runtime_session_completed(
        "lk_sess_first",
        160,
        Some(1),
        Some(3)
    )?);
    assert_eq!(test_store.store.list_incomplete_runtime_sessions("lk_proj_test")?, vec![second]);

    let completed = test_store.store.connection().query_row(
        "SELECT ended_at, exit_status, policy_name, process_id, process_start_time,
                spawn_audit_sequence, completion_audit_sequence
         FROM runtime_sessions
         WHERE id = 'lk_sess_first'",
        [],
        |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i32>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, u32>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, u64>(5)?,
                row.get::<_, u64>(6)?,
            ))
        },
    )?;
    assert_eq!(completed, (150, 0, "dev".to_owned(), 42, 90, 1, 2));

    Ok(())
}

#[test]
fn runtime_session_secret_names_are_names_only_and_pruned_alone() -> Result<(), Box<dyn Error>> {
    let test_store = open_initialized_store()?;
    insert_project_profile(&test_store.store)?;

    let mut expired = test_runtime_session("lk_sess_expired", 100);
    expired.secret_names = vec!["DATABASE_URL".to_owned()];
    let secret_value = "postgres://user:password@example.local/db";
    test_store.store.insert_runtime_session(&expired)?;

    let raw_secret_names = test_store.store.connection().query_row(
        "SELECT secret_names_json FROM runtime_sessions WHERE id = 'lk_sess_expired'",
        [],
        |row| row.get::<_, String>(0),
    )?;
    assert_eq!(raw_secret_names, r#"["DATABASE_URL"]"#);
    assert!(!raw_secret_names.contains(secret_value));

    assert_eq!(
        test_store.store.list_runtime_sessions_with_expired_secret_names("lk_proj_test", 100)?,
        vec![expired]
    );

    let pruned = test_store.store.prune_runtime_session_secret_names("lk_proj_test", 100)?;
    assert_eq!(pruned, 1);
    assert!(
        test_store
            .store
            .list_runtime_sessions_with_expired_secret_names("lk_proj_test", 100)?
            .is_empty()
    );

    let preserved = test_store.store.connection().query_row(
        "SELECT policy_name, process_id, process_start_time, started_at, ended_at,
                exit_status, secret_names_json, spawn_audit_sequence,
                completion_audit_sequence
         FROM runtime_sessions
         WHERE id = 'lk_sess_expired'",
        [],
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, u32>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, Option<i64>>(4)?,
                row.get::<_, Option<i32>>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, u64>(7)?,
                row.get::<_, Option<u64>>(8)?,
            ))
        },
    )?;
    assert_eq!(preserved, ("dev".to_owned(), 42, 90, 100, None, None, "[]".to_owned(), 1, None));

    Ok(())
}

#[test]
fn runtime_session_retention_off_filters_names_before_storage() -> Result<(), Box<dyn Error>> {
    let test_store = open_initialized_store()?;
    insert_project_profile(&test_store.store)?;

    let retention = RuntimeSessionSecretNameRetention::from_str("off")?;
    let mut session = test_runtime_session("lk_sess_off", 100);
    session.secret_names =
        retention.secret_names_for_storage(&["DATABASE_URL".to_owned(), "API_TOKEN".to_owned()]);
    test_store.store.insert_runtime_session(&session)?;

    let raw_secret_names = test_store.store.connection().query_row(
        "SELECT secret_names_json FROM runtime_sessions WHERE id = 'lk_sess_off'",
        [],
        |row| row.get::<_, String>(0),
    )?;
    assert_eq!(raw_secret_names, "[]");
    match RuntimeSessionSecretNameRetention::from_str("90d")? {
        RuntimeSessionSecretNameRetention::RetainFor(duration) => {
            assert_eq!(duration.as_secs(), RuntimeSessionSecretNameRetention::DEFAULT_SECONDS);
        }
        RuntimeSessionSecretNameRetention::Off => return Err("90d should retain names".into()),
    }

    Ok(())
}

#[test]
fn runtime_session_retention_uses_duration_grammar() -> Result<(), Box<dyn Error>> {
    for value in ["0s", "1h30m", "1.5h", "1H", " 1h", "1h "] {
        assert!(
            RuntimeSessionSecretNameRetention::from_str(value).is_err(),
            "{value} should be invalid"
        );
    }

    match RuntimeSessionSecretNameRetention::from_str("2w")? {
        RuntimeSessionSecretNameRetention::RetainFor(duration) => {
            assert_eq!(duration.as_secs(), 14 * 24 * 60 * 60);
            assert_eq!(duration.to_string(), "2w");
        }
        RuntimeSessionSecretNameRetention::Off => return Err("2w should retain names".into()),
    }
    Ok(())
}
