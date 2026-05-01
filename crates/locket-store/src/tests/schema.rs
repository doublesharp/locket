use std::error::Error;

use tempfile::tempdir;

use crate::{AUDIT_ACTION_SCHEMA_MIGRATE, SCHEMA_VERSION, Store, StoreError};

use super::{insert_project_profile, open_initialized_store};

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
        "automation_clients",
        "automation_client_private_key_refs",
        "automation_client_nonces",
        "teams",
        "team_members",
        "team_invites",
        "command_policies",
        "project_roots",
        "directory_grants",
        "audit_log",
        "imported_audit_chains",
        "fingerprints",
        "runtime_sessions",
        "schema_migrations",
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

    let rp_id_column = connection.query_row(
        "SELECT COUNT(*) FROM pragma_table_info('passkey_credentials')
         WHERE name = 'webauthn_relying_party_id'
           AND type = 'TEXT'
           AND \"notnull\" = 1
           AND dflt_value = '''locket.localhost'''",
        [],
        |row| row.get::<_, i64>(0),
    )?;
    assert_eq!(rp_id_column, 1, "passkey credentials must persist the WebAuthn RP ID");

    let foreign_keys =
        connection.query_row("PRAGMA foreign_keys", [], |row| row.get::<_, i64>(0))?;
    assert_eq!(foreign_keys, 1);

    Ok(())
}

#[test]
fn automation_private_key_refs_enforce_metadata_only_storage() -> Result<(), Box<dyn Error>> {
    let test_store = open_initialized_store()?;
    let connection = test_store.store.connection();

    insert_schema_project(connection)?;
    insert_schema_automation_client(connection)?;
    connection.execute(
        "INSERT INTO automation_client_private_key_refs(
           client_id, storage, keychain_service, keychain_account, metadata_json, created_at,
           updated_at
         )
         VALUES (
           'lk_client_schema', 'os-keychain', 'locket', 'lk_client_schema', '{}', 1, 1
         )",
        [],
    )?;

    let bad_key_ref = connection.execute(
        "INSERT INTO automation_client_private_key_refs(
           client_id, storage, keychain_service, keychain_account, local_path_hash, created_at,
           updated_at
         )
         VALUES (
           'lk_client_missing', 'os-keychain', 'locket', 'missing', 'path-hash', 1, 1
         )",
        [],
    );
    assert!(bad_key_ref.is_err());

    Ok(())
}

#[test]
fn team_required_tables_enforce_metadata_constraints() -> Result<(), Box<dyn Error>> {
    let test_store = open_initialized_store()?;
    let connection = test_store.store.connection();

    insert_schema_project(connection)?;
    connection.execute(
        "INSERT INTO teams(id, project_id, name, created_at, updated_at)
         VALUES ('lk_team_schema', 'lk_proj_schema', 'app-team', 1, 1)",
        [],
    )?;
    connection.execute(
        "INSERT INTO team_members(id, team_id, display_name, role, joined_at)
         VALUES ('lk_member_schema', 'lk_team_schema', 'Alice', 'owner', 1)",
        [],
    )?;
    connection.execute(
        "INSERT INTO devices(
           id, project_id, name, signing_public_key, sealing_public_key, fingerprint,
           safety_words_json, local, created_at
         )
         VALUES (
           'lk_dev_schema', 'lk_proj_schema', 'workstation', zeroblob(32), zeroblob(32),
           'fp-schema', '[]', 0, 1
         )",
        [],
    )?;
    connection.execute(
        "INSERT INTO team_members(id, team_id, device_id, display_name, role, joined_at)
         VALUES ('lk_member_device_schema', 'lk_team_schema', 'lk_dev_schema', 'Alice laptop',
                 'developer', 1)",
        [],
    )?;
    connection.execute("DELETE FROM devices WHERE id = 'lk_dev_schema'", [])?;
    let cleared_device_id: Option<String> = connection.query_row(
        "SELECT device_id FROM team_members WHERE id = 'lk_member_device_schema'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(cleared_device_id, None, "device retirement must retain member history");

    connection.execute(
        "INSERT INTO team_invites(
           id, team_id, issuer_member_id, recipient_device_fingerprint, role, profiles_json,
           nonce, created_at, expires_at
         )
         VALUES (
           'lk_invite_schema', 'lk_team_schema', 'lk_member_schema', 'recipient-fp',
           'developer', '[\"dev\"]', zeroblob(24), 1, 2
         )",
        [],
    )?;

    let bad_invite_json = connection.execute(
        "INSERT INTO team_invites(
           id, team_id, recipient_device_fingerprint, role, profiles_json, nonce, created_at,
           expires_at
         )
         VALUES (
           'lk_invite_bad_json', 'lk_team_schema', 'recipient-fp', 'developer',
           'not-json', zeroblob(24), 1, 2
         )",
        [],
    );
    assert!(bad_invite_json.is_err());

    Ok(())
}

#[test]
fn policy_and_imported_audit_tables_enforce_metadata_constraints() -> Result<(), Box<dyn Error>> {
    let test_store = open_initialized_store()?;
    let connection = test_store.store.connection();

    insert_schema_project(connection)?;
    connection.execute(
        "INSERT INTO command_policies(
           project_id, name, policy_json, normalized_json, created_at, updated_at
         )
         VALUES ('lk_proj_schema', 'dev', '{\"argv\":[\"true\"]}', '{\"argv\":[\"true\"]}', 1, 1)",
        [],
    )?;

    let bad_policy_json = connection.execute(
        "INSERT INTO command_policies(
           project_id, name, policy_json, normalized_json, created_at, updated_at
         )
         VALUES ('lk_proj_schema', 'bad', 'not-json', '{}', 1, 1)",
        [],
    );
    assert!(bad_policy_json.is_err());

    connection.execute(
        "INSERT INTO imported_audit_chains(
           id, project_id, source_device_fingerprint, bundle_digest, checkpoint_sequence,
           checkpoint_hmac, encrypted_rows, nonce, aad_schema_version, imported_at
         )
         VALUES (
           'lk_chain_schema', 'lk_proj_schema', 'device-fp', zeroblob(32), 1, zeroblob(32),
           zeroblob(16), zeroblob(24), 1, 1
         )",
        [],
    )?;

    let bad_imported_chain = connection.execute(
        "INSERT INTO imported_audit_chains(
           id, project_id, source_device_fingerprint, bundle_digest, checkpoint_sequence,
           checkpoint_hmac, encrypted_rows, nonce, aad_schema_version, imported_at
         )
         VALUES (
           'lk_chain_bad', 'lk_proj_schema', 'device-fp', zeroblob(16), 1, zeroblob(32),
           zeroblob(16), zeroblob(24), 1, 1
         )",
        [],
    );
    assert!(bad_imported_chain.is_err());

    Ok(())
}

fn insert_schema_project(connection: &rusqlite::Connection) -> Result<(), Box<dyn Error>> {
    connection.execute(
        "INSERT INTO projects(id, name, created_at) VALUES ('lk_proj_schema', 'app', 1)",
        [],
    )?;
    Ok(())
}

fn insert_schema_automation_client(
    connection: &rusqlite::Connection,
) -> Result<(), Box<dyn Error>> {
    connection.execute(
        "INSERT INTO automation_clients(
           id, project_id, name, public_key, fingerprint, storage, allowed_actions_json,
           allowed_policies_json, created_at
         )
         VALUES (
           'lk_client_schema', 'lk_proj_schema', 'ci', zeroblob(32), 'fp',
           'external', '[]', '[]', 1
         )",
        [],
    )?;
    Ok(())
}

#[test]
fn schema_initialization_is_idempotent() -> Result<(), Box<dyn Error>> {
    let mut test_store = open_initialized_store()?;

    assert_eq!(test_store.store.current_schema_version()?, Some(i64::from(SCHEMA_VERSION)));
    let outcome = test_store.store.initialize_schema()?;
    assert!(!outcome.advanced(), "no-op initialize must not advance the ledger");
    assert!(outcome.applied_steps.is_empty());
    assert_eq!(outcome.before, Some(SCHEMA_VERSION));
    assert_eq!(outcome.after, SCHEMA_VERSION);

    let migration_rows = test_store.store.connection().query_row(
        "SELECT COUNT(*) FROM schema_migrations WHERE version = ?1",
        [i64::from(SCHEMA_VERSION)],
        |row| row.get::<_, i64>(0),
    )?;
    assert_eq!(migration_rows, 1);

    Ok(())
}

#[test]
fn fresh_initialize_reports_pending_schema_migration() -> Result<(), Box<dyn Error>> {
    let directory = tempdir()?;
    let path = directory.path().join("store.db");
    let mut store = Store::open(path)?;

    let outcome = store.initialize_schema()?;
    assert!(outcome.advanced(), "fresh store must advance the ledger");
    assert_eq!(outcome.before, None);
    assert_eq!(outcome.after, SCHEMA_VERSION);
    assert_eq!(outcome.applied_steps.as_slice(), &["schema.bootstrap_v1"]);

    Ok(())
}

#[test]
fn record_schema_migrate_audit_skips_when_no_steps_applied() -> Result<(), Box<dyn Error>> {
    let mut test_store = open_initialized_store()?;
    insert_project_profile(&test_store.store)?;

    let outcome = test_store.store.initialize_schema()?;
    assert!(!outcome.advanced());

    let wrote = test_store.store.record_schema_migrate_audit(
        "lk_proj_test",
        &[42; 32],
        &outcome,
        1_700_000_000_000_000_000,
    )?;
    assert!(!wrote, "no row must be written when no steps were applied");

    let actions = test_store.store.list_recent_audit_actions("lk_proj_test", 8)?;
    assert!(actions.is_empty(), "no audit rows must be written");

    Ok(())
}

#[test]
fn record_schema_migrate_audit_writes_row_for_advancement() -> Result<(), Box<dyn Error>> {
    let mut test_store = open_initialized_store()?;
    insert_project_profile(&test_store.store)?;

    // Simulate the fresh-initialize outcome (`before = None`, `after = 1`)
    // produced when the schema bootstrap actually advanced the ledger. The
    // outcome is constructed directly because v1 is the only schema family
    // and the ledger created during fresh initialization has no project
    // context yet to consume the row.
    let outcome = crate::SchemaMigrationOutcome {
        before: None,
        after: SCHEMA_VERSION,
        applied_steps: vec!["schema.bootstrap_v1"],
    };

    let wrote = test_store.store.record_schema_migrate_audit(
        "lk_proj_test",
        &[42; 32],
        &outcome,
        1_700_000_000_000_000_000,
    )?;
    assert!(wrote, "advancement must produce one audit row");

    let actions = test_store.store.list_recent_audit_actions("lk_proj_test", 8)?;
    assert_eq!(actions.as_slice(), &[AUDIT_ACTION_SCHEMA_MIGRATE.to_owned()]);

    let metadata_json: String = test_store.store.connection().query_row(
        "SELECT metadata_json FROM audit_log
         WHERE project_id = ?1 AND action = ?2
         ORDER BY sequence DESC
         LIMIT 1",
        ["lk_proj_test", AUDIT_ACTION_SCHEMA_MIGRATE],
        |row| row.get::<_, String>(0),
    )?;
    let metadata: serde_json::Value = serde_json::from_str(&metadata_json)?;
    assert_eq!(metadata["schema_versions"]["before"], serde_json::Value::Null);
    assert_eq!(metadata["schema_versions"]["after"], 1);
    assert_eq!(metadata["migration_count"], 1);
    assert_eq!(metadata["check_names"][0], "schema.bootstrap_v1");
    assert_eq!(metadata["status"], "SUCCESS");

    Ok(())
}

#[test]
fn record_schema_migrate_audit_writes_row_for_stale_schema() -> Result<(), Box<dyn Error>> {
    let mut test_store = open_initialized_store()?;
    insert_project_profile(&test_store.store)?;

    let outcome = crate::SchemaMigrationOutcome {
        before: Some(0),
        after: SCHEMA_VERSION,
        applied_steps: vec!["schema.bootstrap_v1"],
    };

    let wrote = test_store.store.record_schema_migrate_audit(
        "lk_proj_test",
        &[42; 32],
        &outcome,
        1_700_000_000_000_000_001,
    )?;
    assert!(wrote);

    let metadata_json: String = test_store.store.connection().query_row(
        "SELECT metadata_json FROM audit_log
         WHERE project_id = ?1 AND action = ?2
         ORDER BY sequence DESC
         LIMIT 1",
        ["lk_proj_test", AUDIT_ACTION_SCHEMA_MIGRATE],
        |row| row.get::<_, String>(0),
    )?;
    let metadata: serde_json::Value = serde_json::from_str(&metadata_json)?;
    assert_eq!(metadata["schema_versions"]["before"], 0);
    assert_eq!(metadata["schema_versions"]["after"], SCHEMA_VERSION);
    assert_eq!(metadata["migration_count"], 1);

    Ok(())
}

#[test]
fn current_schema_version_reports_absent_migration_ledger() -> Result<(), Box<dyn Error>> {
    let directory = tempdir()?;
    let path = directory.path().join("store.db");
    let store = Store::open(path)?;

    assert_eq!(store.current_schema_version()?, None);
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

#[test]
fn schema_migrate_audit_action_constant_matches_spec() {
    assert_eq!(AUDIT_ACTION_SCHEMA_MIGRATE, "SCHEMA_MIGRATE");
}

#[test]
fn wal_journal_mode_is_enabled() -> Result<(), Box<dyn Error>> {
    let test_store = open_initialized_store()?;

    let journal_mode =
        test_store
            .store
            .connection()
            .query_row("PRAGMA journal_mode", [], |row| row.get::<_, String>(0))?;

    // WAL mode reports "wal" after enabling.
    assert_eq!(journal_mode, "wal");
    Ok(())
}

#[test]
fn schema_migrations_applied_at_is_positive_integer() -> Result<(), Box<dyn Error>> {
    let test_store = open_initialized_store()?;

    let applied_at = test_store.store.connection().query_row(
        "SELECT applied_at FROM schema_migrations WHERE version = ?1",
        [i64::from(SCHEMA_VERSION)],
        |row| row.get::<_, i64>(0),
    )?;

    assert!(applied_at > 0, "applied_at should be a positive Unix nanoseconds timestamp");
    Ok(())
}

#[test]
fn schema_version_constant_is_one() {
    assert_eq!(SCHEMA_VERSION, 1);
}

#[test]
fn newer_schema_version_blocks_initialization_before_any_tables_are_created()
-> Result<(), Box<dyn Error>> {
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

    // The rest of the v1 tables are absent — verify the check fires before DDL.
    let result = store.initialize_schema();

    assert!(matches!(
        result,
        Err(StoreError::UnsupportedSchema { found, .. }) if found == i64::from(SCHEMA_VERSION) + 1
    ));

    let projects_absent = store.connection().query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'projects'",
        [],
        |row| row.get::<_, i64>(0),
    )?;
    assert_eq!(projects_absent, 0, "rollback must leave other tables absent");

    Ok(())
}
