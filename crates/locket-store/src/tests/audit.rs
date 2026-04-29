use std::error::Error;

use serde_json::json;

use crate::{AuditContext, AuditWrite, StoreError};

use super::{
    insert_project_profile, open_initialized_store, test_secret, test_secret_blob,
    test_secret_fingerprint, test_secret_version,
};

#[test]
fn audited_secret_create_appends_hmac_chained_row() -> Result<(), Box<dyn Error>> {
    let mut test_store = open_initialized_store()?;
    insert_project_profile(&test_store.store)?;
    let metadata = json!({
        "schema_version": 1,
        "action": "SET",
        "status": "SUCCESS",
        "secret_name": "DATABASE_URL",
        "profile_id": "lk_prof_test",
        "source": "user-local",
        "version": 1,
    });
    let audit = AuditWrite {
        project_id: "lk_proj_test",
        profile_id: Some("lk_prof_test"),
        action: "SET",
        status: "SUCCESS",
        secret_name: Some("DATABASE_URL"),
        command: None,
        metadata_json: &metadata,
        timestamp: 100,
    };

    test_store.store.create_active_secret_with_audit(
        &test_secret(),
        &test_secret_version(),
        &test_secret_blob(),
        &test_secret_fingerprint(),
        Some(AuditContext { key: &[42; 32], write: &audit }),
    )?;

    let row = test_store.store.connection().query_row(
        "SELECT sequence, action, secret_name, previous_hmac, hmac, metadata_json
         FROM audit_log
         WHERE project_id = 'lk_proj_test'",
        [],
        |row| {
            Ok((
                row.get::<_, u64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, Vec<u8>>(4)?,
                row.get::<_, String>(5)?,
            ))
        },
    )?;

    assert_eq!(row.0, 1);
    assert_eq!(row.1, "SET");
    assert_eq!(row.2, "DATABASE_URL");
    assert_eq!(row.3, vec![0; 32]);
    assert_eq!(row.4.len(), 32);
    assert!(row.5.contains("\"secret_name\":\"DATABASE_URL\""));
    assert!(!row.5.contains("postgres://"));

    let verified =
        test_store.store.verify_audit_chain_and_append("lk_proj_test", &[42; 32], 200)?;
    assert_eq!(verified, 1);
    let audit_rows = test_store.store.connection().query_row(
        "SELECT COUNT(*) FROM audit_log WHERE project_id = 'lk_proj_test'",
        [],
        |row| row.get::<_, i64>(0),
    )?;
    assert_eq!(audit_rows, 2);
    let verify_metadata = test_store.store.connection().query_row(
        "SELECT metadata_json
         FROM audit_log
         WHERE project_id = 'lk_proj_test' AND action = 'AUDIT_VERIFY'",
        [],
        |row| row.get::<_, String>(0),
    )?;
    let verify_metadata: serde_json::Value = serde_json::from_str(&verify_metadata)?;
    assert_eq!(verify_metadata["check_names"], json!(["audit_hmac_chain"]));
    assert_eq!(verify_metadata["pass_count"], 1);
    assert_eq!(verify_metadata["warn_count"], 0);
    assert_eq!(verify_metadata["fail_count"], 0);
    assert_eq!(verify_metadata["skip_count"], 0);
    assert_eq!(verify_metadata["rows_verified"], 1);

    Ok(())
}

#[test]
fn audit_rows_since_filters_profile_and_timestamp() -> Result<(), Box<dyn Error>> {
    let mut test_store = open_initialized_store()?;
    insert_project_profile(&test_store.store)?;
    let metadata = json!({
        "schema_version": 1,
        "status": "SUCCESS",
    });
    let set_audit = AuditWrite {
        project_id: "lk_proj_test",
        profile_id: Some("lk_prof_test"),
        action: "SET",
        status: "SUCCESS",
        secret_name: Some("DATABASE_URL"),
        command: None,
        metadata_json: &metadata,
        timestamp: 100,
    };
    let project_audit = AuditWrite {
        project_id: "lk_proj_test",
        profile_id: None,
        action: "DOCTOR",
        status: "SUCCESS",
        secret_name: None,
        command: Some("doctor"),
        metadata_json: &metadata,
        timestamp: 200,
    };
    let rotate_audit = AuditWrite {
        project_id: "lk_proj_test",
        profile_id: Some("lk_prof_test"),
        action: "ROTATE",
        status: "SUCCESS",
        secret_name: Some("DATABASE_URL"),
        command: None,
        metadata_json: &metadata,
        timestamp: 300,
    };

    test_store.store.append_audit(&[42; 32], &set_audit)?;
    test_store.store.append_audit(&[42; 32], &project_audit)?;
    test_store.store.append_audit(&[42; 32], &rotate_audit)?;

    let rows = test_store.store.list_audit_rows_since("lk_proj_test", "lk_prof_test", 150)?;

    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].sequence, 3);
    assert_eq!(rows[0].timestamp, 300);
    assert_eq!(rows[0].action, "ROTATE");
    assert_eq!(rows[0].secret_name.as_deref(), Some("DATABASE_URL"));
    Ok(())
}

#[test]
fn audit_verify_reports_first_break_without_appending_success() -> Result<(), Box<dyn Error>> {
    let mut test_store = open_initialized_store()?;
    insert_project_profile(&test_store.store)?;
    let metadata = json!({
        "schema_version": 1,
        "action": "SET",
        "status": "SUCCESS",
        "secret_name": "DATABASE_URL",
        "profile_id": "lk_prof_test",
        "source": "user-local",
        "version": 1,
    });
    let audit = AuditWrite {
        project_id: "lk_proj_test",
        profile_id: Some("lk_prof_test"),
        action: "SET",
        status: "SUCCESS",
        secret_name: Some("DATABASE_URL"),
        command: None,
        metadata_json: &metadata,
        timestamp: 100,
    };

    test_store.store.append_audit(&[42; 32], &audit)?;
    test_store.store.connection().execute(
        "UPDATE audit_log SET action = 'DELETE'
         WHERE project_id = 'lk_proj_test' AND sequence = 1",
        [],
    )?;

    match test_store.store.verify_audit_chain_and_append("lk_proj_test", &[42; 32], 200) {
        Err(StoreError::AuditIntegrity { sequence, reason }) => {
            assert_eq!(sequence, 1);
            assert_eq!(reason, "row hmac mismatch");
        }
        Ok(verified) => {
            return Err(format!("tampered row unexpectedly verified {verified} rows").into());
        }
        Err(other) => return Err(format!("expected audit integrity error, got {other}").into()),
    }
    let audit_rows = test_store.store.connection().query_row(
        "SELECT COUNT(*) FROM audit_log WHERE project_id = 'lk_proj_test'",
        [],
        |row| row.get::<_, i64>(0),
    )?;
    assert_eq!(audit_rows, 1);

    Ok(())
}
