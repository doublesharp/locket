use std::error::Error;

use tempfile::tempdir;

use crate::{SCHEMA_VERSION, Store, StoreError};

use super::open_initialized_store;

#[test]
fn creates_schema_and_records_migration() -> Result<(), Box<dyn Error>> {
    let test_store = open_initialized_store()?;
    let connection = test_store.store.connection();

    for table in [
        "projects",
        "profiles",
        "secrets",
        "secret_versions",
        "blobs",
        "keys",
        "devices",
        "passkey_credentials",
        "project_roots",
        "directory_grants",
        "audit_log",
        "fingerprints",
        "runtime_sessions",
        "schema_migrations",
        "automation_client_nonces",
    ] {
        let exists = connection.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
            [table],
            |row| row.get::<_, i64>(0),
        )?;
        assert_eq!(exists, 1, "{table} should exist");
    }

    let schema_version =
        connection
            .query_row("SELECT version FROM schema_migrations", [], |row| row.get::<_, u32>(0))?;
    assert_eq!(schema_version, SCHEMA_VERSION);

    let foreign_keys =
        connection.query_row("PRAGMA foreign_keys", [], |row| row.get::<_, i64>(0))?;
    assert_eq!(foreign_keys, 1);

    Ok(())
}

#[test]
fn schema_initialization_is_idempotent() -> Result<(), Box<dyn Error>> {
    let mut test_store = open_initialized_store()?;

    test_store.store.initialize_schema()?;

    let migration_rows = test_store.store.connection().query_row(
        "SELECT COUNT(*) FROM schema_migrations WHERE version = ?1",
        [i64::from(SCHEMA_VERSION)],
        |row| row.get::<_, i64>(0),
    )?;
    assert_eq!(migration_rows, 1);

    Ok(())
}

#[test]
fn schema_initialization_rejects_newer_existing_version() -> Result<(), Box<dyn Error>> {
    let directory = tempdir()?;
    let path = directory.path().join("store.db");
    let mut store = Store::open(path)?;
    store.connection().execute(
        "CREATE TABLE schema_migrations (
           version INTEGER PRIMARY KEY,
           applied_at INTEGER NOT NULL
         )",
        [],
    )?;
    store.connection().execute(
        "INSERT INTO schema_migrations(version, applied_at) VALUES (?1, 1)",
        [i64::from(SCHEMA_VERSION) + 1],
    )?;

    let result = store.initialize_schema();

    match result {
        Err(StoreError::UnsupportedSchema { found, supported }) => {
            assert_eq!(found, i64::from(SCHEMA_VERSION) + 1);
            assert_eq!(supported, SCHEMA_VERSION);
        }
        other => return Err(format!("unexpected schema result: {other:?}").into()),
    }
    Ok(())
}

#[test]
fn store_errors_map_to_stable_locket_failures() {
    let unsupported = StoreError::UnsupportedSchema { found: 2, supported: SCHEMA_VERSION };
    assert_eq!(unsupported.locket_error(), locket_core::LocketError::SchemaNewerThanBinary);

    let audit = StoreError::AuditIntegrity { sequence: 1, reason: "row hmac mismatch".to_owned() };
    assert_eq!(audit.locket_error(), locket_core::LocketError::AuditIntegrityFailed);

    let busy = StoreError::Sqlite(rusqlite::Error::SqliteFailure(
        rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_BUSY),
        None,
    ));
    assert_eq!(busy.locket_error(), locket_core::LocketError::StorageBusy);

    let corrupt = StoreError::Sqlite(rusqlite::Error::SqliteFailure(
        rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_CORRUPT),
        None,
    ));
    assert_eq!(corrupt.locket_error(), locket_core::LocketError::CorruptDb);
}

#[test]
fn foreign_keys_are_enforced() -> Result<(), Box<dyn Error>> {
    let test_store = open_initialized_store()?;

    let result = test_store.store.connection().execute(
        "INSERT INTO profiles(id, project_id, name, dangerous, created_at)
         VALUES ('lk_prof_orphan', 'lk_proj_missing', 'orphan', 0, 1)",
        [],
    );

    assert!(result.is_err());
    Ok(())
}
