use std::error::Error;

use crate::{SecretBlobRecord, SecretFingerprintRecord, SecretVersionRecord};

use super::{
    insert_project_profile, insert_project_profile_secret, open_initialized_store, test_secret,
    test_secret_blob, test_secret_fingerprint, test_secret_version,
};

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
fn active_secret_metadata_uses_source_precedence_ordering() -> Result<(), Box<dyn Error>> {
    let test_store = open_initialized_store()?;
    insert_project_profile(&test_store.store)?;

    for (id, name, source, required, current_version) in [
        ("lk_sec_team", "DATABASE_URL", "team-managed", true, 1),
        ("lk_sec_machine", "DATABASE_URL", "machine-local", false, 3),
        ("lk_sec_user", "DATABASE_URL", "user-local", false, 2),
        ("lk_sec_api", "API_TOKEN", "user-local", true, 1),
        ("lk_sec_deleted", "Z_DELETED", "machine-local", false, 4),
    ] {
        let state = if id == "lk_sec_deleted" { "deleted" } else { "active" };
        test_store.store.connection().execute(
            "INSERT INTO secrets(
               id, project_id, profile_id, name, source, origin, required,
               current_version, state, created_at, updated_at, last_rotated_at, deleted_at
             )
             VALUES (?1, 'lk_proj_test', 'lk_prof_test', ?2, ?3, 'manual', ?4, ?5, ?6, 100, 200, 300, NULL)",
            rusqlite::params![id, name, source, required, current_version, state],
        )?;
    }

    let rows =
        test_store.store.list_active_secret_metadata_by_profile("lk_proj_test", "lk_prof_test")?;

    let ordered = rows
        .iter()
        .map(|row| (row.name.as_str(), row.source.as_str(), row.source_precedence))
        .collect::<Vec<_>>();
    assert_eq!(
        ordered,
        vec![
            ("API_TOKEN", "user-local", 2),
            ("DATABASE_URL", "machine-local", 3),
            ("DATABASE_URL", "user-local", 2),
            ("DATABASE_URL", "team-managed", 1),
        ]
    );
    assert_eq!(rows[0].required, true);
    assert_eq!(rows[1].current_version, 3);
    assert_eq!(rows[1].last_rotated_at, Some(300));
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
