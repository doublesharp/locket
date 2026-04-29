//! `SQLite` storage layer for Locket.

use std::path::Path;
use std::time::Duration;

use rusqlite::{Connection, OptionalExtension, params};
use thiserror::Error;

/// Current storage schema version.
pub const SCHEMA_VERSION: u32 = 1;

const BUSY_TIMEOUT_MS: u64 = 5_000;

/// SQLite-backed Locket store.
#[derive(Debug)]
pub struct Store {
    connection: Connection,
}

/// Metadata for a stored project.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectRecord {
    /// Project identifier.
    pub id: String,
    /// Human-readable project name.
    pub name: String,
    /// Creation timestamp in nanoseconds since the Unix epoch.
    pub created_at: i64,
}

/// Metadata for a stored profile.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProfileRecord {
    /// Profile identifier.
    pub id: String,
    /// Parent project identifier.
    pub project_id: String,
    /// Human-readable profile name.
    pub name: String,
    /// Whether the profile is marked dangerous.
    pub dangerous: bool,
    /// Creation timestamp in nanoseconds since the Unix epoch.
    pub created_at: i64,
}

impl Store {
    /// Opens a `SQLite` store at `path` and configures connection-level safety pragmas.
    ///
    /// The connection enables foreign key enforcement, requests WAL journaling where
    /// `SQLite` supports it, and configures a 5000 ms busy timeout.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` cannot open or configure the store.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let connection = Connection::open(path)?;
        configure_connection(&connection)?;
        Ok(Self { connection })
    }

    /// Runs the idempotent v1 schema bootstrap.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::UnsupportedSchema`] when the database has already been
    /// migrated by a newer Locket binary. Returns [`StoreError::Sqlite`] for `SQLite`
    /// failures while creating or recording the schema.
    pub fn initialize_schema(&mut self) -> Result<(), StoreError> {
        initialize_schema(&mut self.connection)
    }

    /// Returns the underlying `SQLite` connection.
    #[must_use]
    pub const fn connection(&self) -> &Connection {
        &self.connection
    }

    /// Returns the underlying `SQLite` connection mutably.
    #[must_use]
    pub const fn connection_mut(&mut self) -> &mut Connection {
        &mut self.connection
    }

    /// Inserts a project metadata row when `id` does not already exist.
    ///
    /// Returns `true` when the project was inserted and `false` when a project
    /// with the same `id` already existed.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` rejects the insert.
    pub fn insert_project_if_absent(
        &self,
        id: &str,
        name: &str,
        created_at: i64,
    ) -> Result<bool, StoreError> {
        self.connection.execute(
            "INSERT OR IGNORE INTO projects(id, name, created_at) VALUES (?1, ?2, ?3)",
            (id, name, created_at),
        )?;

        Ok(self.connection.changes() == 1)
    }

    /// Returns project metadata by id.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` cannot query the project row.
    pub fn get_project(&self, id: &str) -> Result<Option<ProjectRecord>, StoreError> {
        self.connection
            .query_row(
                "SELECT id, name, created_at FROM projects WHERE id = ?1",
                [id],
                project_record_from_row,
            )
            .optional()
            .map_err(StoreError::from)
    }

    /// Inserts a profile metadata row when `id` and `(project_id, name)` are absent.
    ///
    /// Returns `true` when the profile was inserted and `false` when either the
    /// profile id or the project-scoped profile name already existed.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` rejects the insert, including
    /// when `project_id` does not reference an existing project.
    pub fn insert_profile_if_absent(
        &self,
        id: &str,
        project_id: &str,
        name: &str,
        dangerous: bool,
        created_at: i64,
    ) -> Result<bool, StoreError> {
        self.connection.execute(
            "INSERT OR IGNORE INTO profiles(id, project_id, name, dangerous, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            (id, project_id, name, dangerous, created_at),
        )?;

        Ok(self.connection.changes() == 1)
    }

    /// Lists project profile metadata ordered by profile name.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` cannot query profile rows.
    pub fn list_profiles(&self, project_id: &str) -> Result<Vec<ProfileRecord>, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT id, project_id, name, dangerous, created_at
             FROM profiles
             WHERE project_id = ?1
             ORDER BY name",
        )?;
        let profiles = statement
            .query_map([project_id], profile_record_from_row)?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(profiles)
    }

    /// Returns profile metadata by project id and profile name.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` cannot query the profile row.
    pub fn get_profile_by_name(
        &self,
        project_id: &str,
        name: &str,
    ) -> Result<Option<ProfileRecord>, StoreError> {
        self.connection
            .query_row(
                "SELECT id, project_id, name, dangerous, created_at
                 FROM profiles
                 WHERE project_id = ?1 AND name = ?2",
                (project_id, name),
                profile_record_from_row,
            )
            .optional()
            .map_err(StoreError::from)
    }

    /// Records or refreshes trust for a project root hash.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` rejects the write.
    pub fn trust_project_root(
        &self,
        project_id: &str,
        root_hash: &[u8; 32],
        display_path: Option<&str>,
        timestamp: i64,
    ) -> Result<(), StoreError> {
        self.connection.execute(
            "INSERT INTO project_roots(project_id, root_hash, display_path, created_at, last_seen_at)
             VALUES (?1, ?2, ?3, ?4, ?4)
             ON CONFLICT(project_id, root_hash) DO UPDATE SET
               display_path = excluded.display_path,
               last_seen_at = excluded.last_seen_at",
            params![project_id, root_hash.as_slice(), display_path, timestamp],
        )?;

        Ok(())
    }

    /// Returns whether a root hash is trusted for a project.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` cannot query the root row.
    pub fn project_root_is_trusted(
        &self,
        project_id: &str,
        root_hash: &[u8; 32],
    ) -> Result<bool, StoreError> {
        let row_count = self.connection.query_row(
            "SELECT COUNT(*) FROM project_roots WHERE project_id = ?1 AND root_hash = ?2",
            params![project_id, root_hash.as_slice()],
            |row| row.get::<_, i64>(0),
        )?;

        Ok(row_count > 0)
    }
}

fn project_record_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ProjectRecord> {
    Ok(ProjectRecord { id: row.get(0)?, name: row.get(1)?, created_at: row.get(2)? })
}

fn profile_record_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ProfileRecord> {
    Ok(ProfileRecord {
        id: row.get(0)?,
        project_id: row.get(1)?,
        name: row.get(2)?,
        dangerous: row.get(3)?,
        created_at: row.get(4)?,
    })
}

/// Error returned by the storage layer.
#[derive(Debug, Error)]
pub enum StoreError {
    /// `SQLite` returned an error.
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),

    /// The database schema is newer than this binary can read.
    #[error(
        "database schema version {found} is newer than supported schema version {supported}; upgrade Locket"
    )]
    UnsupportedSchema {
        /// Newer schema version found in the database.
        found: i64,
        /// Maximum schema version this binary supports.
        supported: u32,
    },
}

fn configure_connection(connection: &Connection) -> Result<(), rusqlite::Error> {
    connection.busy_timeout(Duration::from_millis(BUSY_TIMEOUT_MS))?;
    connection.pragma_update(None, "foreign_keys", "ON")?;
    connection.pragma_update(None, "journal_mode", "WAL")?;
    Ok(())
}

fn initialize_schema(connection: &mut Connection) -> Result<(), StoreError> {
    if let Some(version) = current_schema_version(connection)? {
        fail_on_newer_schema(version)?;
    }

    let transaction = connection.transaction()?;
    transaction.execute_batch(SCHEMA_SQL)?;
    transaction.execute(
        "INSERT OR IGNORE INTO schema_migrations(version, applied_at)
         VALUES (?1, CAST(strftime('%s', 'now') AS INTEGER) * 1000000000)",
        [i64::from(SCHEMA_VERSION)],
    )?;
    transaction.commit()?;

    if let Some(version) = current_schema_version(connection)? {
        fail_on_newer_schema(version)?;
    }

    Ok(())
}

fn current_schema_version(connection: &Connection) -> Result<Option<i64>, StoreError> {
    let migrations_exists = connection
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'schema_migrations'",
            [],
            |_| Ok(()),
        )
        .optional()?
        .is_some();

    if !migrations_exists {
        return Ok(None);
    }

    let version =
        connection.query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
            row.get::<_, Option<i64>>(0)
        })?;

    Ok(version)
}

const fn fail_on_newer_schema(version: i64) -> Result<(), StoreError> {
    if version > SCHEMA_VERSION as i64 {
        return Err(StoreError::UnsupportedSchema { found: version, supported: SCHEMA_VERSION });
    }

    Ok(())
}

const SCHEMA_SQL: &str = r"
CREATE TABLE IF NOT EXISTS projects (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  user_verification_policy_json TEXT NOT NULL DEFAULT '{}',
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS profiles (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  dangerous INTEGER NOT NULL CHECK (dangerous IN (0, 1)),
  created_at INTEGER NOT NULL,
  UNIQUE (project_id, name)
);

CREATE TABLE IF NOT EXISTS project_roots (
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  root_hash BLOB NOT NULL CHECK (length(root_hash) = 32),
  display_path TEXT,
  created_at INTEGER NOT NULL,
  last_seen_at INTEGER,
  PRIMARY KEY (project_id, root_hash)
);

CREATE INDEX IF NOT EXISTS project_roots_root_hash_idx
  ON project_roots(root_hash);

CREATE TABLE IF NOT EXISTS secrets (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  profile_id TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  description TEXT,
  owner TEXT,
  source TEXT NOT NULL CHECK (source IN ('team-managed', 'user-local', 'machine-local')),
  origin TEXT NOT NULL CHECK (origin IN ('manual', 'imported', 'team-accept', 'profile-copy')),
  tags_json TEXT NOT NULL DEFAULT '[]',
  required INTEGER NOT NULL CHECK (required IN (0, 1)),
  current_version INTEGER NOT NULL CHECK (current_version >= 1 AND current_version <= 4294967295),
  state TEXT NOT NULL CHECK (state IN ('active', 'deleted')),
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  last_rotated_at INTEGER,
  deleted_at INTEGER,
  UNIQUE (project_id, profile_id, name, source)
);

CREATE INDEX IF NOT EXISTS secrets_project_profile_name_idx
  ON secrets(project_id, profile_id, name);

CREATE TABLE IF NOT EXISTS secret_versions (
  secret_id TEXT NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
  version INTEGER NOT NULL CHECK (version >= 1 AND version <= 4294967295),
  source TEXT NOT NULL CHECK (source IN ('team-managed', 'user-local', 'machine-local')),
  origin TEXT NOT NULL CHECK (origin IN ('manual', 'imported', 'team-accept', 'profile-copy')),
  state TEXT NOT NULL CHECK (state IN ('current', 'deprecated', 'purged')),
  created_at INTEGER NOT NULL,
  deprecated_at INTEGER,
  grace_until INTEGER,
  purged_at INTEGER,
  PRIMARY KEY (secret_id, version)
);

CREATE TRIGGER IF NOT EXISTS secret_versions_source_matches_secret_insert
BEFORE INSERT ON secret_versions
FOR EACH ROW
WHEN NEW.source != (SELECT source FROM secrets WHERE id = NEW.secret_id)
BEGIN
  SELECT RAISE(ABORT, 'secret_versions.source must match secrets.source');
END;

CREATE TRIGGER IF NOT EXISTS secret_versions_source_matches_secret_update
BEFORE UPDATE OF secret_id, source ON secret_versions
FOR EACH ROW
WHEN NEW.source != (SELECT source FROM secrets WHERE id = NEW.secret_id)
BEGIN
  SELECT RAISE(ABORT, 'secret_versions.source must match secrets.source');
END;

CREATE TABLE IF NOT EXISTS blobs (
  secret_id TEXT NOT NULL,
  version INTEGER NOT NULL,
  encrypted_dek BLOB NOT NULL,
  ciphertext BLOB NOT NULL,
  value_nonce BLOB NOT NULL CHECK (length(value_nonce) = 24),
  aad_schema_version INTEGER NOT NULL CHECK (aad_schema_version >= 1),
  created_at INTEGER NOT NULL,
  PRIMARY KEY (secret_id, version),
  FOREIGN KEY (secret_id, version)
    REFERENCES secret_versions(secret_id, version)
    ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS fingerprints (
  secret_id TEXT NOT NULL,
  version INTEGER NOT NULL CHECK (version >= 1 AND version <= 4294967295),
  fingerprint BLOB NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (secret_id, version),
  FOREIGN KEY (secret_id, version)
    REFERENCES secret_versions(secret_id, version)
    ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS keys (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  profile_id TEXT REFERENCES profiles(id) ON DELETE CASCADE,
  purpose TEXT NOT NULL CHECK (purpose IN ('project-metadata', 'project-audit', 'profile-secret', 'profile-fingerprint')),
  wrapped_material BLOB NOT NULL,
  nonce BLOB NOT NULL CHECK (length(nonce) = 24),
  created_at INTEGER NOT NULL,
  CHECK (
    (profile_id IS NULL AND purpose IN ('project-metadata', 'project-audit'))
    OR
    (profile_id IS NOT NULL AND purpose IN ('profile-secret', 'profile-fingerprint'))
  )
);

CREATE UNIQUE INDEX IF NOT EXISTS keys_project_scope_unique
  ON keys(project_id, purpose)
  WHERE profile_id IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS keys_profile_scope_unique
  ON keys(project_id, profile_id, purpose)
  WHERE profile_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS audit_log (
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  sequence INTEGER NOT NULL CHECK (sequence >= 1),
  schema_version INTEGER NOT NULL CHECK (schema_version >= 1 AND schema_version <= 4294967295),
  timestamp INTEGER NOT NULL,
  profile_id TEXT REFERENCES profiles(id) ON DELETE SET NULL,
  action TEXT NOT NULL,
  status TEXT NOT NULL,
  metadata_json TEXT NOT NULL,
  secret_name TEXT,
  command TEXT,
  previous_hmac BLOB CHECK (previous_hmac IS NULL OR length(previous_hmac) = 32),
  hmac BLOB NOT NULL CHECK (length(hmac) = 32),
  PRIMARY KEY (project_id, sequence)
);

CREATE TABLE IF NOT EXISTS automation_clients (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  revoked_at INTEGER
);

CREATE TABLE IF NOT EXISTS automation_client_nonces (
  client_id TEXT NOT NULL REFERENCES automation_clients(id) ON DELETE CASCADE,
  nonce BLOB NOT NULL CHECK (length(nonce) = 24),
  request_timestamp INTEGER NOT NULL,
  seen_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  PRIMARY KEY (client_id, nonce)
);

CREATE TABLE IF NOT EXISTS schema_migrations (
  version INTEGER PRIMARY KEY CHECK (version >= 1 AND version <= 4294967295),
  applied_at INTEGER NOT NULL
);
";

#[cfg(test)]
mod tests {
    use std::error::Error;

    use tempfile::{TempDir, tempdir};

    use super::{ProfileRecord, ProjectRecord, SCHEMA_VERSION, Store};

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

    fn insert_project_profile_secret(store: &Store) -> Result<(), Box<dyn Error>> {
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
            "project_roots",
            "audit_log",
            "fingerprints",
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
            connection.query_row("SELECT version FROM schema_migrations", [], |row| {
                row.get::<_, u32>(0)
            })?;
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

        test_store.store.insert_profile_if_absent(
            "lk_prof_zed",
            "lk_proj_test",
            "zed",
            false,
            300,
        )?;
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
}
