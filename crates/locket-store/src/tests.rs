use std::error::Error;
use std::str::FromStr;

use serde_json::json;
use tempfile::{TempDir, tempdir};

use crate::{
    AuditContext, AuditWrite, AutomationClientNonceRecord, AutomationClientRecord, DeviceRecord,
    DirectoryGrantRecord, KeyRecord, PasskeyCredentialRecord, ProfileRecord, ProjectRecord,
    ProjectRootRecord, RuntimeSessionRecord, RuntimeSessionSecretNameRetention, SCHEMA_VERSION,
    SecretBlobRecord, SecretFingerprintRecord, SecretRecord, SecretVersionRecord, Store,
    StoreError,
};

struct TestStore {
    _directory: TempDir,
    store: Store,
}

fn open_initialized_store() -> Result<TestStore, Box<dyn Error>> {
    let directory = tempdir()?;
    let path = directory.path().join("store.db");

    let mut store = Store::open(path)?;
    store.initialize_schema()?;

    Ok(TestStore { _directory: directory, store })
}

fn insert_project_profile(store: &Store) -> Result<(), Box<dyn Error>> {
    let connection = store.connection();
    connection.execute(
        "INSERT INTO projects(id, name, created_at) VALUES ('lk_proj_test', 'test', 1)",
        [],
    )?;

    connection.execute(
        "INSERT INTO profiles(id, project_id, name, dangerous, created_at)
         VALUES ('lk_prof_test', 'lk_proj_test', 'default', 0, 1)",
        [],
    )?;

    Ok(())
}

fn insert_project_profile_secret(store: &Store) -> Result<(), Box<dyn Error>> {
    insert_project_profile(store)?;

    let connection = store.connection();
    connection.execute(
        "INSERT INTO secrets(
           id, project_id, profile_id, name, source, origin, required,
           current_version, state, created_at, updated_at
         )
         VALUES (
           'lk_sec_test', 'lk_proj_test', 'lk_prof_test', 'DATABASE_URL',
           'user-local', 'manual', 1, 1, 'active', 1, 1
         )",
        [],
    )?;

    Ok(())
}

fn test_secret() -> SecretRecord {
    SecretRecord {
        id: "lk_sec_test".to_owned(),
        project_id: "lk_proj_test".to_owned(),
        profile_id: "lk_prof_test".to_owned(),
        name: "DATABASE_URL".to_owned(),
        source: "user-local".to_owned(),
        origin: "manual".to_owned(),
        current_version: 1,
        state: "active".to_owned(),
        created_at: 100,
        updated_at: 100,
        last_rotated_at: None,
        deleted_at: None,
    }
}

fn test_secret_version() -> SecretVersionRecord {
    SecretVersionRecord {
        secret_id: "lk_sec_test".to_owned(),
        version: 1,
        source: "user-local".to_owned(),
        origin: "manual".to_owned(),
        state: "current".to_owned(),
        created_at: 100,
        deprecated_at: None,
        grace_until: None,
        purged_at: None,
    }
}

fn test_secret_blob() -> SecretBlobRecord {
    SecretBlobRecord {
        secret_id: "lk_sec_test".to_owned(),
        version: 1,
        encrypted_dek: vec![1, 2, 3, 4],
        ciphertext: vec![5, 6, 7, 8],
        value_nonce: [9; 24],
        aad_schema_version: 1,
        created_at: 100,
    }
}

fn test_secret_fingerprint() -> SecretFingerprintRecord {
    SecretFingerprintRecord {
        secret_id: "lk_sec_test".to_owned(),
        version: 1,
        fingerprint: vec![10, 11, 12, 13],
        created_at: 100,
    }
}

fn test_runtime_session(id: &str, started_at: i64) -> RuntimeSessionRecord {
    RuntimeSessionRecord {
        id: id.to_owned(),
        project_id: "lk_proj_test".to_owned(),
        profile_id: "lk_prof_test".to_owned(),
        policy_name: Some("dev".to_owned()),
        process_id: 42,
        process_start_time: started_at - 10,
        started_at,
        ended_at: None,
        exit_status: None,
        secret_names: vec!["DATABASE_URL".to_owned(), "API_TOKEN".to_owned()],
        spawn_audit_sequence: Some(1),
        completion_audit_sequence: None,
    }
}

fn test_device() -> DeviceRecord {
    DeviceRecord {
        id: "lk_dev_test".to_owned(),
        project_id: "lk_proj_test".to_owned(),
        name: "work-laptop".to_owned(),
        signing_public_key: vec![1; 32],
        sealing_public_key: vec![2; 32],
        fingerprint: "ab".repeat(32),
        safety_words: vec!["amber".to_owned(), "river".to_owned(), "north".to_owned()],
        local: true,
        created_at: 100,
        last_seen_at: Some(100),
        revoked_at: None,
    }
}

fn test_passkey_credential() -> PasskeyCredentialRecord {
    PasskeyCredentialRecord {
        id: "lk_passkey_test".to_owned(),
        project_id: "lk_proj_test".to_owned(),
        label: "work-laptop".to_owned(),
        credential_id: vec![0xab, 0xcd, 0xef, 0x12, 0x34, 0x56],
        transports: vec!["internal".to_owned(), "usb".to_owned()],
        prf_capable: true,
        backup_eligible: Some(true),
        backup_state: Some(false),
        created_at: 100,
        last_used_at: Some(150),
        revoked_at: None,
    }
}

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

#[test]
fn profile_insert_if_absent_handles_duplicate_id_and_name() -> Result<(), Box<dyn Error>> {
    let test_store = open_initialized_store()?;
    test_store.store.insert_project_if_absent("lk_proj_test", "test", 100)?;

    let inserted = test_store.store.insert_profile_if_absent(
        "lk_prof_default",
        "lk_proj_test",
        "default",
        false,
        200,
    )?;
    assert!(inserted);

    let inserted = test_store.store.insert_profile_if_absent(
        "lk_prof_default",
        "lk_proj_test",
        "other",
        true,
        300,
    )?;
    assert!(!inserted);

    let inserted = test_store.store.insert_profile_if_absent(
        "lk_prof_duplicate_name",
        "lk_proj_test",
        "default",
        true,
        400,
    )?;
    assert!(!inserted);

    assert_eq!(
        test_store.store.get_profile_by_name("lk_proj_test", "default")?,
        Some(ProfileRecord {
            id: "lk_prof_default".to_owned(),
            project_id: "lk_proj_test".to_owned(),
            name: "default".to_owned(),
            dangerous: false,
            created_at: 200,
        })
    );
    assert_eq!(test_store.store.get_profile_by_name("lk_proj_test", "missing")?, None);

    Ok(())
}

#[test]
fn list_profiles_orders_by_name() -> Result<(), Box<dyn Error>> {
    let test_store = open_initialized_store()?;
    test_store.store.insert_project_if_absent("lk_proj_test", "test", 100)?;
    test_store.store.insert_project_if_absent("lk_proj_other", "other", 100)?;

    test_store.store.insert_profile_if_absent("lk_prof_zed", "lk_proj_test", "zed", false, 300)?;
    test_store.store.insert_profile_if_absent(
        "lk_prof_alpha",
        "lk_proj_test",
        "alpha",
        true,
        100,
    )?;
    test_store.store.insert_profile_if_absent(
        "lk_prof_middle",
        "lk_proj_test",
        "middle",
        false,
        200,
    )?;
    test_store.store.insert_profile_if_absent(
        "lk_prof_other",
        "lk_proj_other",
        "aardvark",
        false,
        100,
    )?;

    let profiles = test_store.store.list_profiles("lk_proj_test")?;
    let names = profiles.iter().map(|profile| profile.name.as_str()).collect::<Vec<_>>();
    assert_eq!(names, ["alpha", "middle", "zed"]);
    assert_eq!(profiles[0].id, "lk_prof_alpha");
    assert!(profiles[0].dangerous);

    Ok(())
}

#[test]
fn profile_dangerous_marker_updates() -> Result<(), Box<dyn Error>> {
    let test_store = open_initialized_store()?;
    test_store.store.insert_project_if_absent("lk_proj_test", "test", 100)?;
    test_store.store.insert_profile_if_absent(
        "lk_prof_default",
        "lk_proj_test",
        "default",
        false,
        200,
    )?;

    assert!(test_store.store.set_profile_dangerous("lk_proj_test", "default", true)?);
    assert!(
        test_store
            .store
            .get_profile_by_name("lk_proj_test", "default")?
            .ok_or("profile should exist")?
            .dangerous
    );

    assert!(test_store.store.set_profile_dangerous("lk_proj_test", "default", false)?);
    assert!(
        !test_store
            .store
            .get_profile_by_name("lk_proj_test", "default")?
            .ok_or("profile should exist")?
            .dangerous
    );
    assert!(!test_store.store.set_profile_dangerous("lk_proj_test", "missing", true)?);

    Ok(())
}

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

#[test]
fn automation_clients_store_public_metadata_and_revocation() -> Result<(), Box<dyn Error>> {
    let test_store = open_initialized_store()?;
    test_store.store.insert_project_if_absent("lk_proj_test", "test", 100)?;
    let client = AutomationClientRecord {
        id: "lk_client_test".to_owned(),
        project_id: "lk_proj_test".to_owned(),
        name: "ci".to_owned(),
        public_key: vec![7; 32],
        fingerprint: "6b86b273ff34fce1".to_owned(),
        storage: "external".to_owned(),
        allowed_actions: vec!["run-policy".to_owned(), "redact".to_owned()],
        allowed_policies: vec!["test".to_owned()],
        created_at: 200,
        last_used_at: None,
        revoked_at: None,
    };

    test_store.store.insert_automation_client(&client)?;
    let clients = test_store.store.list_automation_clients("lk_proj_test", false)?;
    assert_eq!(clients, vec![client]);
    let by_name = test_store
        .store
        .get_automation_client("lk_proj_test", "ci")?
        .ok_or("client should exist")?;
    assert_eq!(by_name.id, "lk_client_test");

    assert!(test_store.store.revoke_automation_client("lk_proj_test", "lk_client_test", 300)?);
    assert!(test_store.store.list_automation_clients("lk_proj_test", false)?.is_empty());
    let revoked = test_store.store.list_automation_clients("lk_proj_test", true)?;
    assert_eq!(revoked[0].revoked_at, Some(300));
    assert!(!test_store.store.revoke_automation_client("lk_proj_test", "lk_client_test", 400)?);
    Ok(())
}

#[test]
fn automation_client_nonces_are_unique_and_prunable() -> Result<(), Box<dyn Error>> {
    let test_store = open_initialized_store()?;
    test_store.store.insert_project_if_absent("lk_proj_test", "test", 100)?;
    test_store.store.insert_automation_client(&AutomationClientRecord {
        id: "lk_client_test".to_owned(),
        project_id: "lk_proj_test".to_owned(),
        name: "ci".to_owned(),
        public_key: vec![7; 32],
        fingerprint: "fingerprint".to_owned(),
        storage: "external".to_owned(),
        allowed_actions: vec!["run-policy".to_owned()],
        allowed_policies: vec!["test".to_owned()],
        created_at: 200,
        last_used_at: None,
        revoked_at: None,
    })?;
    let nonce = AutomationClientNonceRecord {
        client_id: "lk_client_test".to_owned(),
        nonce: [9; 24],
        request_timestamp: 210,
        seen_at: 220,
        expires_at: 230,
    };

    test_store.store.insert_automation_client_nonce(&nonce)?;
    assert!(test_store.store.insert_automation_client_nonce(&nonce).is_err());
    assert_eq!(test_store.store.prune_automation_client_nonces(229)?, 0);
    assert_eq!(test_store.store.prune_automation_client_nonces(230)?, 1);
    Ok(())
}

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
fn create_secret_lists_blob_and_fingerprint() -> Result<(), Box<dyn Error>> {
    let mut test_store = open_initialized_store()?;
    insert_project_profile(&test_store.store)?;

    let secret = test_secret();
    let version = test_secret_version();
    let blob = test_secret_blob();
    let fingerprint = test_secret_fingerprint();
    test_store.store.create_active_secret(&secret, &version, &blob, &fingerprint)?;

    assert_eq!(
        test_store.store.get_active_secret(
            "lk_proj_test",
            "lk_prof_test",
            "DATABASE_URL",
            "user-local"
        )?,
        Some(secret.clone())
    );
    assert_eq!(
        test_store.store.list_active_secrets_by_profile("lk_proj_test", "lk_prof_test")?,
        vec![secret]
    );
    assert_eq!(test_store.store.get_blob("lk_sec_test", 1)?, Some(blob));

    let stored_fingerprint = test_store.store.connection().query_row(
        "SELECT fingerprint FROM fingerprints WHERE secret_id = 'lk_sec_test' AND version = 1",
        [],
        |row| row.get::<_, Vec<u8>>(0),
    )?;
    assert_eq!(stored_fingerprint, fingerprint.fingerprint);

    Ok(())
}

#[test]
fn create_secret_rolls_back_when_version_source_mismatches() -> Result<(), Box<dyn Error>> {
    let mut test_store = open_initialized_store()?;
    insert_project_profile(&test_store.store)?;
    let version =
        SecretVersionRecord { source: "team-managed".to_owned(), ..test_secret_version() };

    let result = test_store.store.create_active_secret(
        &test_secret(),
        &version,
        &test_secret_blob(),
        &test_secret_fingerprint(),
    );

    assert!(result.is_err());
    assert_eq!(
        test_store.store.get_secret_by_source(
            "lk_proj_test",
            "lk_prof_test",
            "DATABASE_URL",
            "user-local",
        )?,
        None
    );
    let version_rows = test_store.store.connection().query_row(
        "SELECT COUNT(*) FROM secret_versions WHERE secret_id = 'lk_sec_test'",
        [],
        |row| row.get::<_, i64>(0),
    )?;
    let blob_rows = test_store.store.connection().query_row(
        "SELECT COUNT(*) FROM blobs WHERE secret_id = 'lk_sec_test'",
        [],
        |row| row.get::<_, i64>(0),
    )?;
    let fingerprint_rows = test_store.store.connection().query_row(
        "SELECT COUNT(*) FROM fingerprints WHERE secret_id = 'lk_sec_test'",
        [],
        |row| row.get::<_, i64>(0),
    )?;
    assert_eq!(version_rows, 0);
    assert_eq!(blob_rows, 0);
    assert_eq!(fingerprint_rows, 0);

    Ok(())
}

#[test]
fn secret_metadata_update_changes_metadata_columns() -> Result<(), Box<dyn Error>> {
    let mut test_store = open_initialized_store()?;
    insert_project_profile(&test_store.store)?;
    test_store.store.create_active_secret(
        &test_secret(),
        &test_secret_version(),
        &test_secret_blob(),
        &test_secret_fingerprint(),
    )?;

    assert!(test_store.store.update_secret_metadata(
        "lk_sec_test",
        Some("database connection"),
        Some("platform"),
        Some(&["database".to_owned(), "prod".to_owned()]),
        Some(true),
    )?);

    let row = test_store.store.connection().query_row(
        "SELECT description, owner, tags_json, required, updated_at
         FROM secrets
         WHERE id = 'lk_sec_test'",
        [],
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, bool>(3)?,
                row.get::<_, i64>(4)?,
            ))
        },
    )?;
    assert_eq!(
        row,
        (
            "database connection".to_owned(),
            "platform".to_owned(),
            "[\"database\",\"prod\"]".to_owned(),
            true,
            100,
        )
    );
    assert!(!test_store.store.update_secret_metadata(
        "lk_sec_missing",
        Some("missing"),
        None,
        None,
        None,
    )?);

    Ok(())
}

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

#[test]
fn tombstone_secret_hides_it_from_active_queries() -> Result<(), Box<dyn Error>> {
    let mut test_store = open_initialized_store()?;
    insert_project_profile(&test_store.store)?;

    test_store.store.create_active_secret(
        &test_secret(),
        &test_secret_version(),
        &test_secret_blob(),
        &test_secret_fingerprint(),
    )?;
    test_store.store.tombstone_secret("lk_sec_test", 300)?;

    assert_eq!(
        test_store.store.get_active_secret(
            "lk_proj_test",
            "lk_prof_test",
            "DATABASE_URL",
            "user-local"
        )?,
        None
    );
    assert!(
        test_store.store.list_active_secrets_by_profile("lk_proj_test", "lk_prof_test")?.is_empty()
    );

    let deleted_at = test_store.store.connection().query_row(
        "SELECT deleted_at FROM secrets WHERE id = 'lk_sec_test' AND state = 'deleted'",
        [],
        |row| row.get::<_, i64>(0),
    )?;
    assert_eq!(deleted_at, 300);

    Ok(())
}

#[test]
fn rotate_secret_advances_current_and_deprecates_prior() -> Result<(), Box<dyn Error>> {
    let mut test_store = open_initialized_store()?;
    insert_project_profile(&test_store.store)?;
    test_store.store.create_active_secret(
        &test_secret(),
        &test_secret_version(),
        &test_secret_blob(),
        &test_secret_fingerprint(),
    )?;

    test_store.store.rotate_secret(
        &test_secret(),
        &SecretVersionRecord { version: 2, created_at: 400, ..test_secret_version() },
        &SecretBlobRecord { version: 2, created_at: 400, ..test_secret_blob() },
        &SecretFingerprintRecord { version: 2, created_at: 400, ..test_secret_fingerprint() },
        300,
        Some(500),
    )?;

    let secret = test_store
        .store
        .get_active_secret("lk_proj_test", "lk_prof_test", "DATABASE_URL", "user-local")?
        .ok_or("active secret should exist")?;
    assert_eq!(secret.current_version, 2);
    assert_eq!(secret.last_rotated_at, Some(400));

    let versions = test_store.store.list_secret_versions("lk_sec_test")?;
    assert_eq!(versions.len(), 2);
    assert_eq!(versions[0].state, "deprecated");
    assert_eq!(versions[0].deprecated_at, Some(300));
    assert_eq!(versions[0].grace_until, Some(500));
    assert_eq!(versions[1].state, "current");
    assert_eq!(versions[1].version, 2);

    Ok(())
}

#[test]
fn purge_secret_versions_removes_material_but_keeps_version_rows() -> Result<(), Box<dyn Error>> {
    let mut test_store = open_initialized_store()?;
    insert_project_profile(&test_store.store)?;
    test_store.store.create_active_secret(
        &test_secret(),
        &test_secret_version(),
        &test_secret_blob(),
        &test_secret_fingerprint(),
    )?;
    test_store.store.rotate_secret(
        &test_secret(),
        &SecretVersionRecord { version: 2, created_at: 400, ..test_secret_version() },
        &SecretBlobRecord { version: 2, created_at: 400, ..test_secret_blob() },
        &SecretFingerprintRecord { version: 2, created_at: 400, ..test_secret_fingerprint() },
        300,
        Some(500),
    )?;

    assert!(test_store.store.purge_secret_version("lk_sec_test", 1, 600)?);
    assert!(!test_store.store.purge_secret_version("lk_sec_test", 1, 700)?);

    let versions = test_store.store.list_secret_versions("lk_sec_test")?;
    assert_eq!(versions[0].state, "purged");
    assert_eq!(versions[0].grace_until, None);
    assert_eq!(versions[0].purged_at, Some(600));
    assert_eq!(versions[1].state, "current");
    assert_eq!(test_store.store.get_blob("lk_sec_test", 1)?, None);
    assert!(test_store.store.get_blob("lk_sec_test", 2)?.is_some());

    let fingerprint_rows = test_store.store.connection().query_row(
        "SELECT COUNT(*) FROM fingerprints WHERE secret_id = 'lk_sec_test' AND version = 1",
        [],
        |row| row.get::<_, i64>(0),
    )?;
    assert_eq!(fingerprint_rows, 0);

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

#[test]
fn secret_version_range_constraints_are_enforced() -> Result<(), Box<dyn Error>> {
    let test_store = open_initialized_store()?;
    insert_project_profile_secret(&test_store.store)?;

    for version in [0_i64, 4_294_967_296_i64] {
        let result = test_store.store.connection().execute(
            "INSERT INTO secret_versions(
               secret_id, version, source, origin, state, created_at
             )
             VALUES ('lk_sec_test', ?1, 'user-local', 'manual', 'current', 1)",
            [version],
        );
        assert!(result.is_err(), "version {version} should be rejected");
    }

    let rows = test_store.store.connection().execute(
        "INSERT INTO secret_versions(secret_id, version, source, origin, state, created_at)
         VALUES ('lk_sec_test', 1, 'user-local', 'manual', 'current', 1)",
        [],
    )?;
    assert_eq!(rows, 1);

    Ok(())
}
