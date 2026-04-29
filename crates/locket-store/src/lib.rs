//! `SQLite` storage layer for Locket.

use std::path::Path;
use std::time::Duration;

use hmac::{Hmac, Mac};
use locket_core::{
    AUDIT_HMAC_LEN, AuditCanonicalizationError, AuditHmacInput, Timestamp, audit_hmac_v1_bytes,
    canonical_json_string,
};
use rusqlite::types::Type;
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde_json::{Value, json};
use sha2::Sha256;
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

/// Metadata for a trusted project root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectRootRecord {
    /// Parent project identifier.
    pub project_id: String,
    /// SHA-256 hash of the canonical root path.
    pub root_hash: [u8; 32],
    /// Last known display path for the root.
    pub display_path: Option<String>,
    /// Creation timestamp in nanoseconds since the Unix epoch.
    pub created_at: i64,
    /// Last-seen timestamp in nanoseconds since the Unix epoch.
    pub last_seen_at: Option<i64>,
}

/// Durable metadata-only directory consent for shell/editor integrations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectoryGrantRecord {
    /// Stable metadata identifier for this consent row.
    pub grant_id: String,
    /// Parent project identifier.
    pub project_id: String,
    /// Profile this durable consent applies to.
    pub profile_id: String,
    /// Trusted project root hash.
    pub root_hash: [u8; 32],
    /// Granted directory hash.
    pub directory_hash: [u8; 32],
    /// Persisted grant scope string.
    pub grant_scope: String,
    /// Last known display path for the granted directory.
    pub display_path: Option<String>,
    /// Creation timestamp in nanoseconds since the Unix epoch.
    pub created_at: i64,
    /// Last update timestamp in nanoseconds since the Unix epoch.
    pub updated_at: i64,
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

/// Wrapped project/profile key material.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyRecord {
    /// Key identifier.
    pub id: String,
    /// Parent project identifier.
    pub project_id: String,
    /// Optional parent profile identifier for profile-scoped keys.
    pub profile_id: Option<String>,
    /// Persisted key purpose string.
    pub purpose: String,
    /// Encrypted key material.
    pub wrapped_material: Vec<u8>,
    /// Nonce used to wrap the key material.
    pub nonce: [u8; 24],
    /// Creation timestamp in nanoseconds since the Unix epoch.
    pub created_at: i64,
}

/// Secret metadata row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecretRecord {
    /// Secret identifier.
    pub id: String,
    /// Parent project identifier.
    pub project_id: String,
    /// Parent profile identifier.
    pub profile_id: String,
    /// Secret name.
    pub name: String,
    /// Persisted secret source string.
    pub source: String,
    /// Persisted secret origin string.
    pub origin: String,
    /// Current secret version.
    pub current_version: u32,
    /// Persisted secret state string.
    pub state: String,
    /// Creation timestamp in nanoseconds since the Unix epoch.
    pub created_at: i64,
    /// Last metadata update timestamp in nanoseconds since the Unix epoch.
    pub updated_at: i64,
    /// Last rotation timestamp in nanoseconds since the Unix epoch.
    pub last_rotated_at: Option<i64>,
    /// Tombstone timestamp in nanoseconds since the Unix epoch.
    pub deleted_at: Option<i64>,
}

/// Secret version metadata row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecretVersionRecord {
    /// Parent secret identifier.
    pub secret_id: String,
    /// Version number.
    pub version: u32,
    /// Persisted secret source string.
    pub source: String,
    /// Persisted secret origin string.
    pub origin: String,
    /// Persisted version state string.
    pub state: String,
    /// Creation timestamp in nanoseconds since the Unix epoch.
    pub created_at: i64,
    /// Deprecation timestamp in nanoseconds since the Unix epoch.
    pub deprecated_at: Option<i64>,
    /// Grace-window expiration timestamp in nanoseconds since the Unix epoch.
    pub grace_until: Option<i64>,
    /// Purge timestamp in nanoseconds since the Unix epoch.
    pub purged_at: Option<i64>,
}

/// Encrypted secret value row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecretBlobRecord {
    /// Parent secret identifier.
    pub secret_id: String,
    /// Version number.
    pub version: u32,
    /// Encrypted data-encryption key bytes.
    pub encrypted_dek: Vec<u8>,
    /// Encrypted secret value bytes.
    pub ciphertext: Vec<u8>,
    /// Nonce used for the value ciphertext.
    pub value_nonce: [u8; 24],
    /// AAD schema version.
    pub aad_schema_version: u16,
    /// Creation timestamp in nanoseconds since the Unix epoch.
    pub created_at: i64,
}

/// Keyed secret fingerprint row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecretFingerprintRecord {
    /// Parent secret identifier.
    pub secret_id: String,
    /// Version number.
    pub version: u32,
    /// Keyed fingerprint bytes.
    pub fingerprint: Vec<u8>,
    /// Creation timestamp in nanoseconds since the Unix epoch.
    pub created_at: i64,
}

/// Metadata applied to the version being superseded by rotation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VersionDeprecation {
    /// Deprecation timestamp in nanoseconds since the Unix epoch.
    pub deprecated_at: i64,
    /// Optional grace-window expiration timestamp.
    pub grace_until: Option<i64>,
}

/// Target lifecycle operation for a profile copy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecretCopyTarget<'a> {
    /// Create a new target secret row at version 1.
    Create(&'a SecretRecord),
    /// Rotate an existing active target secret.
    Rotate {
        /// Existing active target secret.
        secret: &'a SecretRecord,
        /// Metadata to apply to the superseded target version.
        deprecation: VersionDeprecation,
    },
}

/// HMAC-covered audit row to append.
#[derive(Debug)]
pub struct AuditWrite<'a> {
    /// Parent project identifier.
    pub project_id: &'a str,
    /// Optional profile identifier.
    pub profile_id: Option<&'a str>,
    /// Audit action string.
    pub action: &'a str,
    /// Audit status string.
    pub status: &'a str,
    /// Optional query convenience secret name.
    pub secret_name: Option<&'a str>,
    /// Optional query convenience command string.
    pub command: Option<&'a str>,
    /// HMAC-covered metadata object.
    pub metadata_json: &'a Value,
    /// Event timestamp in nanoseconds since the Unix epoch.
    pub timestamp: i64,
}

/// Audit key plus row payload for transaction-scoped appends.
#[derive(Clone, Copy, Debug)]
pub struct AuditContext<'a> {
    /// Unwrapped project audit key.
    pub key: &'a [u8],
    /// Audit row payload.
    pub write: &'a AuditWrite<'a>,
}

#[derive(Debug)]
struct StoredAuditRow {
    sequence: u64,
    schema_version: u16,
    timestamp: i64,
    project_id: String,
    profile_id: Option<String>,
    action: String,
    status: String,
    metadata_json: String,
    previous_hmac: [u8; AUDIT_HMAC_LEN],
    hmac: [u8; AUDIT_HMAC_LEN],
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

    /// Appends one metadata-only audit row to the project audit chain.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when the audit row cannot be canonicalized, signed,
    /// or inserted.
    pub fn append_audit(
        &mut self,
        audit_key: &[u8],
        audit: &AuditWrite<'_>,
    ) -> Result<(), StoreError> {
        let transaction = self.connection.transaction()?;
        append_audit(&transaction, audit_key, audit)?;
        transaction.commit()?;
        Ok(())
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

    /// Updates the dangerous marker for a profile by project id and profile name.
    ///
    /// Returns `true` when a profile row was updated and `false` when no matching
    /// profile exists.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` rejects the update.
    pub fn set_profile_dangerous(
        &self,
        project_id: &str,
        name: &str,
        dangerous: bool,
    ) -> Result<bool, StoreError> {
        self.connection.execute(
            "UPDATE profiles
             SET dangerous = ?3
             WHERE project_id = ?1 AND name = ?2",
            (project_id, name, dangerous),
        )?;

        Ok(self.connection.changes() == 1)
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

    /// Lists trusted roots for a project ordered by creation time.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` cannot query trusted root rows.
    pub fn list_project_roots(
        &self,
        project_id: &str,
    ) -> Result<Vec<ProjectRootRecord>, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT project_id, root_hash, display_path, created_at, last_seen_at
             FROM project_roots
             WHERE project_id = ?1
             ORDER BY created_at, root_hash",
        )?;
        let roots = statement
            .query_map([project_id], project_root_record_from_row)?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(roots)
    }

    /// Removes a trusted root from a project.
    ///
    /// Returns `true` when a root was removed and `false` when no matching root existed.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` rejects the delete.
    pub fn untrust_project_root(
        &self,
        project_id: &str,
        root_hash: &[u8; 32],
    ) -> Result<bool, StoreError> {
        self.connection.execute(
            "DELETE FROM project_roots WHERE project_id = ?1 AND root_hash = ?2",
            params![project_id, root_hash.as_slice()],
        )?;

        Ok(self.connection.changes() == 1)
    }

    /// Records or refreshes durable directory consent for a project/profile.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` rejects the write.
    pub fn allow_directory_grant(&self, grant: &DirectoryGrantRecord) -> Result<(), StoreError> {
        self.connection.execute(
            "INSERT INTO directory_grants(
               grant_id, project_id, profile_id, root_hash, directory_hash, grant_scope,
               display_path, created_at, updated_at
             )
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT(project_id, profile_id, root_hash, directory_hash, grant_scope)
             DO UPDATE SET
               display_path = excluded.display_path,
               updated_at = excluded.updated_at",
            params![
                grant.grant_id.as_str(),
                grant.project_id.as_str(),
                grant.profile_id.as_str(),
                grant.root_hash.as_slice(),
                grant.directory_hash.as_slice(),
                grant.grant_scope.as_str(),
                grant.display_path.as_deref(),
                grant.created_at,
                grant.updated_at,
            ],
        )?;

        Ok(())
    }

    /// Returns a durable directory grant for an exact scope.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` cannot query the grant row.
    pub fn get_directory_grant(
        &self,
        project_id: &str,
        profile_id: &str,
        root_hash: &[u8; 32],
        directory_hash: &[u8; 32],
        grant_scope: &str,
    ) -> Result<Option<DirectoryGrantRecord>, StoreError> {
        Ok(self
            .connection
            .query_row(
                "SELECT grant_id, project_id, profile_id, root_hash, directory_hash,
                        grant_scope, display_path, created_at, updated_at
                 FROM directory_grants
                 WHERE project_id = ?1
                   AND profile_id = ?2
                   AND root_hash = ?3
                   AND directory_hash = ?4
                   AND grant_scope = ?5",
                params![
                    project_id,
                    profile_id,
                    root_hash.as_slice(),
                    directory_hash.as_slice(),
                    grant_scope,
                ],
                directory_grant_record_from_row,
            )
            .optional()?)
    }

    /// Removes a durable directory grant for an exact project/profile/root scope.
    ///
    /// Returns `true` when a grant was removed and `false` when no matching grant existed.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` rejects the delete.
    pub fn deny_directory_grant(
        &self,
        project_id: &str,
        profile_id: &str,
        root_hash: &[u8; 32],
        directory_hash: &[u8; 32],
        grant_scope: &str,
    ) -> Result<bool, StoreError> {
        self.connection.execute(
            "DELETE FROM directory_grants
             WHERE project_id = ?1
               AND profile_id = ?2
               AND root_hash = ?3
               AND directory_hash = ?4
               AND grant_scope = ?5",
            params![
                project_id,
                profile_id,
                root_hash.as_slice(),
                directory_hash.as_slice(),
                grant_scope,
            ],
        )?;

        Ok(self.connection.changes() == 1)
    }

    /// Removes every durable directory grant for a project.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` rejects the delete.
    pub fn deny_all_directory_grants(&self, project_id: &str) -> Result<usize, StoreError> {
        self.connection
            .execute("DELETE FROM directory_grants WHERE project_id = ?1", [project_id])
            .map_err(StoreError::from)
    }

    /// Inserts wrapped key material.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` rejects the insert, including
    /// uniqueness, foreign-key, and key-scope constraint failures.
    pub fn insert_key(&self, key: &KeyRecord) -> Result<(), StoreError> {
        self.connection.execute(
            "INSERT INTO keys(id, project_id, profile_id, purpose, wrapped_material, nonce, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                key.id.as_str(),
                key.project_id.as_str(),
                key.profile_id.as_deref(),
                key.purpose.as_str(),
                key.wrapped_material.as_slice(),
                key.nonce.as_slice(),
                key.created_at,
            ],
        )?;

        Ok(())
    }

    /// Returns wrapped key material by id.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` cannot query the key row.
    pub fn get_key(&self, id: &str) -> Result<Option<KeyRecord>, StoreError> {
        self.connection
            .query_row(
                "SELECT id, project_id, profile_id, purpose, wrapped_material, nonce, created_at
                 FROM keys
                 WHERE id = ?1",
                [id],
                key_record_from_row,
            )
            .optional()
            .map_err(StoreError::from)
    }

    /// Returns wrapped key material by project/profile scope and purpose.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` cannot query the key row.
    pub fn get_key_by_scope(
        &self,
        project_id: &str,
        profile_id: Option<&str>,
        purpose: &str,
    ) -> Result<Option<KeyRecord>, StoreError> {
        self.connection
            .query_row(
                "SELECT id, project_id, profile_id, purpose, wrapped_material, nonce, created_at
                 FROM keys
                 WHERE project_id = ?1 AND profile_id IS ?2 AND purpose = ?3",
                params![project_id, profile_id, purpose],
                key_record_from_row,
            )
            .optional()
            .map_err(StoreError::from)
    }

    /// Creates a secret, its initial version, encrypted blob, and keyed fingerprint atomically.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` rejects any insert. The
    /// transaction is rolled back when any row fails to insert.
    pub fn create_active_secret(
        &mut self,
        secret: &SecretRecord,
        version: &SecretVersionRecord,
        blob: &SecretBlobRecord,
        fingerprint: &SecretFingerprintRecord,
    ) -> Result<(), StoreError> {
        self.create_active_secret_with_audit(secret, version, blob, fingerprint, None)
    }

    /// Creates a secret and optionally appends the matching audit row in the same transaction.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when `SQLite` rejects a row or audit canonicalization fails.
    pub fn create_active_secret_with_audit(
        &mut self,
        secret: &SecretRecord,
        version: &SecretVersionRecord,
        blob: &SecretBlobRecord,
        fingerprint: &SecretFingerprintRecord,
        audit: Option<AuditContext<'_>>,
    ) -> Result<(), StoreError> {
        let transaction = self.connection.transaction()?;
        transaction.execute(
            "INSERT INTO secrets(
               id, project_id, profile_id, name, source, origin, required,
               current_version, state, created_at, updated_at, last_rotated_at, deleted_at
             )
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                secret.id.as_str(),
                secret.project_id.as_str(),
                secret.profile_id.as_str(),
                secret.name.as_str(),
                secret.source.as_str(),
                secret.origin.as_str(),
                secret.current_version,
                secret.state.as_str(),
                secret.created_at,
                secret.updated_at,
                secret.last_rotated_at,
                secret.deleted_at,
            ],
        )?;
        transaction.execute(
            "INSERT INTO secret_versions(
               secret_id, version, source, origin, state, created_at,
               deprecated_at, grace_until, purged_at
             )
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                version.secret_id.as_str(),
                version.version,
                version.source.as_str(),
                version.origin.as_str(),
                version.state.as_str(),
                version.created_at,
                version.deprecated_at,
                version.grace_until,
                version.purged_at,
            ],
        )?;
        transaction.execute(
            "INSERT INTO blobs(
               secret_id, version, encrypted_dek, ciphertext, value_nonce,
               aad_schema_version, created_at
             )
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                blob.secret_id.as_str(),
                blob.version,
                blob.encrypted_dek.as_slice(),
                blob.ciphertext.as_slice(),
                blob.value_nonce.as_slice(),
                blob.aad_schema_version,
                blob.created_at,
            ],
        )?;
        transaction.execute(
            "INSERT INTO fingerprints(secret_id, version, fingerprint, created_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                fingerprint.secret_id.as_str(),
                fingerprint.version,
                fingerprint.fingerprint.as_slice(),
                fingerprint.created_at,
            ],
        )?;
        append_optional_audit(&transaction, audit)?;
        transaction.commit()?;

        Ok(())
    }

    /// Returns an active secret by project/profile/name/source.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` cannot query the secret row.
    pub fn get_active_secret(
        &self,
        project_id: &str,
        profile_id: &str,
        name: &str,
        source: &str,
    ) -> Result<Option<SecretRecord>, StoreError> {
        self.connection
            .query_row(
                "SELECT id, project_id, profile_id, name, source, origin, current_version, state,
                        created_at, updated_at, last_rotated_at, deleted_at
                 FROM secrets
                 WHERE project_id = ?1
                   AND profile_id = ?2
                   AND name = ?3
                   AND source = ?4
                   AND state = 'active'",
                (project_id, profile_id, name, source),
                secret_record_from_row,
            )
            .optional()
            .map_err(StoreError::from)
    }

    /// Returns a secret by project/profile/name/source regardless of active or deleted state.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` cannot query the secret row.
    pub fn get_secret_by_source(
        &self,
        project_id: &str,
        profile_id: &str,
        name: &str,
        source: &str,
    ) -> Result<Option<SecretRecord>, StoreError> {
        self.connection
            .query_row(
                "SELECT id, project_id, profile_id, name, source, origin, current_version, state,
                        created_at, updated_at, last_rotated_at, deleted_at
                 FROM secrets
                 WHERE project_id = ?1
                   AND profile_id = ?2
                   AND name = ?3
                   AND source = ?4",
                (project_id, profile_id, name, source),
                secret_record_from_row,
            )
            .optional()
            .map_err(StoreError::from)
    }

    /// Lists secrets for a project/profile/name across all sources and states.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` cannot query secret rows.
    pub fn list_secrets_by_name(
        &self,
        project_id: &str,
        profile_id: &str,
        name: &str,
    ) -> Result<Vec<SecretRecord>, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT id, project_id, profile_id, name, source, origin, current_version, state,
                    created_at, updated_at, last_rotated_at, deleted_at
             FROM secrets
             WHERE project_id = ?1 AND profile_id = ?2 AND name = ?3
             ORDER BY name, source",
        )?;
        let secrets = statement
            .query_map((project_id, profile_id, name), secret_record_from_row)?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(secrets)
    }

    /// Lists active secrets for a profile ordered by name and source.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` cannot query secret rows.
    pub fn list_active_secrets_by_profile(
        &self,
        project_id: &str,
        profile_id: &str,
    ) -> Result<Vec<SecretRecord>, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT id, project_id, profile_id, name, source, origin, current_version, state,
                    created_at, updated_at, last_rotated_at, deleted_at
             FROM secrets
             WHERE project_id = ?1 AND profile_id = ?2 AND state = 'active'
             ORDER BY name, source",
        )?;
        let secrets = statement
            .query_map((project_id, profile_id), secret_record_from_row)?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(secrets)
    }

    /// Lists all secrets for a profile ordered by name and source.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` cannot query secret rows.
    pub fn list_secrets_by_profile(
        &self,
        project_id: &str,
        profile_id: &str,
    ) -> Result<Vec<SecretRecord>, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT id, project_id, profile_id, name, source, origin, current_version, state,
                    created_at, updated_at, last_rotated_at, deleted_at
             FROM secrets
             WHERE project_id = ?1 AND profile_id = ?2
             ORDER BY name, source",
        )?;
        let secrets = statement
            .query_map((project_id, profile_id), secret_record_from_row)?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(secrets)
    }

    /// Lists version metadata for a secret ordered by version.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` cannot query version rows.
    pub fn list_secret_versions(
        &self,
        secret_id: &str,
    ) -> Result<Vec<SecretVersionRecord>, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT secret_id, version, source, origin, state, created_at,
                    deprecated_at, grace_until, purged_at
             FROM secret_versions
             WHERE secret_id = ?1
             ORDER BY version",
        )?;
        let versions = statement
            .query_map([secret_id], secret_version_record_from_row)?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(versions)
    }

    /// Returns version metadata for a secret version.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` cannot query the version row.
    pub fn get_secret_version(
        &self,
        secret_id: &str,
        version: u32,
    ) -> Result<Option<SecretVersionRecord>, StoreError> {
        self.connection
            .query_row(
                "SELECT secret_id, version, source, origin, state, created_at,
                        deprecated_at, grace_until, purged_at
                 FROM secret_versions
                 WHERE secret_id = ?1 AND version = ?2",
                params![secret_id, version],
                secret_version_record_from_row,
            )
            .optional()
            .map_err(StoreError::from)
    }

    /// Updates mutable metadata fields on an active secret without changing secret material.
    ///
    /// `None` keeps the existing field. `tags` replaces the whole tag list when
    /// present.
    ///
    /// Returns `true` when an active secret row was updated and `false` when no
    /// matching active secret exists.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` rejects the update.
    pub fn update_secret_metadata(
        &self,
        secret_id: &str,
        description: Option<&str>,
        owner: Option<&str>,
        tags: Option<&[String]>,
        required: Option<bool>,
    ) -> Result<bool, StoreError> {
        let tags_json = tags.map(|tags| {
            let tags = tags.iter().map(|tag| Value::String(tag.clone())).collect::<Vec<_>>();
            canonical_json_string(Some(&Value::Array(tags)))
        });
        self.connection.execute(
            "UPDATE secrets
             SET description = COALESCE(?2, description),
                 owner = COALESCE(?3, owner),
                 tags_json = COALESCE(?4, tags_json),
                 required = COALESCE(?5, required)
             WHERE id = ?1 AND state = 'active'",
            params![secret_id, description, owner, tags_json.as_deref(), required,],
        )?;

        Ok(self.connection.changes() == 1)
    }

    /// Rotates a secret by deprecating the current version and inserting the new current version.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` rejects any update or insert.
    /// The transaction is rolled back when any row fails.
    pub fn rotate_secret(
        &mut self,
        secret: &SecretRecord,
        new_version: &SecretVersionRecord,
        blob: &SecretBlobRecord,
        fingerprint: &SecretFingerprintRecord,
        deprecated_at: i64,
        grace_until: Option<i64>,
    ) -> Result<(), StoreError> {
        self.rotate_secret_with_audit(
            secret,
            new_version,
            blob,
            fingerprint,
            VersionDeprecation { deprecated_at, grace_until },
            None,
        )
    }

    /// Rotates a secret and optionally appends the matching audit row in the same transaction.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when `SQLite` rejects a row or audit canonicalization fails.
    pub fn rotate_secret_with_audit(
        &mut self,
        secret: &SecretRecord,
        new_version: &SecretVersionRecord,
        blob: &SecretBlobRecord,
        fingerprint: &SecretFingerprintRecord,
        deprecation: VersionDeprecation,
        audit: Option<AuditContext<'_>>,
    ) -> Result<(), StoreError> {
        let transaction = self.connection.transaction()?;
        transaction.execute(
            "UPDATE secret_versions
             SET state = 'deprecated', deprecated_at = ?3, grace_until = ?4
             WHERE secret_id = ?1 AND version = ?2 AND state = 'current'",
            params![
                secret.id.as_str(),
                secret.current_version,
                deprecation.deprecated_at,
                deprecation.grace_until,
            ],
        )?;
        transaction.execute(
            "INSERT INTO secret_versions(
               secret_id, version, source, origin, state, created_at,
               deprecated_at, grace_until, purged_at
             )
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                new_version.secret_id.as_str(),
                new_version.version,
                new_version.source.as_str(),
                new_version.origin.as_str(),
                new_version.state.as_str(),
                new_version.created_at,
                new_version.deprecated_at,
                new_version.grace_until,
                new_version.purged_at,
            ],
        )?;
        transaction.execute(
            "INSERT INTO blobs(
               secret_id, version, encrypted_dek, ciphertext, value_nonce,
               aad_schema_version, created_at
             )
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                blob.secret_id.as_str(),
                blob.version,
                blob.encrypted_dek.as_slice(),
                blob.ciphertext.as_slice(),
                blob.value_nonce.as_slice(),
                blob.aad_schema_version,
                blob.created_at,
            ],
        )?;
        transaction.execute(
            "INSERT INTO fingerprints(secret_id, version, fingerprint, created_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                fingerprint.secret_id.as_str(),
                fingerprint.version,
                fingerprint.fingerprint.as_slice(),
                fingerprint.created_at,
            ],
        )?;
        transaction.execute(
            "UPDATE secrets
             SET current_version = ?2, updated_at = ?3, last_rotated_at = ?3
             WHERE id = ?1 AND state = 'active'",
            params![secret.id.as_str(), new_version.version, new_version.created_at],
        )?;
        append_optional_audit(&transaction, audit)?;
        transaction.commit()?;

        Ok(())
    }

    /// Copies secret material into a target source by creating or rotating it.
    ///
    /// The copied plaintext is supplied only as already-encrypted target material. The secret
    /// lifecycle update and optional `SECRET_COPY` audit append happen in one transaction.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when `SQLite` rejects a row or audit canonicalization fails.
    pub fn copy_secret_with_audit(
        &mut self,
        target: SecretCopyTarget<'_>,
        new_version: &SecretVersionRecord,
        blob: &SecretBlobRecord,
        fingerprint: &SecretFingerprintRecord,
        audit: Option<AuditContext<'_>>,
    ) -> Result<(), StoreError> {
        let transaction = self.connection.transaction()?;
        match target {
            SecretCopyTarget::Create(secret) => {
                transaction.execute(
                    "INSERT INTO secrets(
                       id, project_id, profile_id, name, source, origin, required,
                       current_version, state, created_at, updated_at, last_rotated_at, deleted_at
                     )
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, ?7, ?8, ?9, ?10, ?11, ?12)",
                    params![
                        secret.id.as_str(),
                        secret.project_id.as_str(),
                        secret.profile_id.as_str(),
                        secret.name.as_str(),
                        secret.source.as_str(),
                        secret.origin.as_str(),
                        secret.current_version,
                        secret.state.as_str(),
                        secret.created_at,
                        secret.updated_at,
                        secret.last_rotated_at,
                        secret.deleted_at,
                    ],
                )?;
            }
            SecretCopyTarget::Rotate { secret, deprecation } => {
                transaction.execute(
                    "UPDATE secret_versions
                     SET state = 'deprecated', deprecated_at = ?3, grace_until = ?4
                     WHERE secret_id = ?1 AND version = ?2 AND state = 'current'",
                    params![
                        secret.id.as_str(),
                        secret.current_version,
                        deprecation.deprecated_at,
                        deprecation.grace_until,
                    ],
                )?;
            }
        }
        transaction.execute(
            "INSERT INTO secret_versions(
               secret_id, version, source, origin, state, created_at,
               deprecated_at, grace_until, purged_at
             )
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                new_version.secret_id.as_str(),
                new_version.version,
                new_version.source.as_str(),
                new_version.origin.as_str(),
                new_version.state.as_str(),
                new_version.created_at,
                new_version.deprecated_at,
                new_version.grace_until,
                new_version.purged_at,
            ],
        )?;
        transaction.execute(
            "INSERT INTO blobs(
               secret_id, version, encrypted_dek, ciphertext, value_nonce,
               aad_schema_version, created_at
             )
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                blob.secret_id.as_str(),
                blob.version,
                blob.encrypted_dek.as_slice(),
                blob.ciphertext.as_slice(),
                blob.value_nonce.as_slice(),
                blob.aad_schema_version,
                blob.created_at,
            ],
        )?;
        transaction.execute(
            "INSERT INTO fingerprints(secret_id, version, fingerprint, created_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                fingerprint.secret_id.as_str(),
                fingerprint.version,
                fingerprint.fingerprint.as_slice(),
                fingerprint.created_at,
            ],
        )?;
        if let SecretCopyTarget::Rotate { secret, .. } = target {
            transaction.execute(
                "UPDATE secrets
                 SET current_version = ?2, updated_at = ?3, last_rotated_at = ?3
                 WHERE id = ?1 AND state = 'active'",
                params![secret.id.as_str(), new_version.version, new_version.created_at],
            )?;
        }
        append_optional_audit(&transaction, audit)?;
        transaction.commit()?;

        Ok(())
    }

    /// Purges encrypted material and fingerprints for one version.
    ///
    /// Returns `true` when material was newly purged and `false` when the
    /// version was already purged.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` rejects the updates.
    pub fn purge_secret_version(
        &mut self,
        secret_id: &str,
        version: u32,
        purged_at: i64,
    ) -> Result<bool, StoreError> {
        self.purge_secret_versions(secret_id, &[version], purged_at)
    }

    /// Purges encrypted material and fingerprints for multiple versions atomically.
    ///
    /// Returns `true` when at least one version was newly purged and `false`
    /// when all selected versions were already purged.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` rejects the updates.
    pub fn purge_secret_versions(
        &mut self,
        secret_id: &str,
        versions: &[u32],
        purged_at: i64,
    ) -> Result<bool, StoreError> {
        self.purge_secret_versions_with_audit(secret_id, versions, purged_at, None)
    }

    /// Purges versions and optionally appends a `PURGE` audit row when material changed.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when `SQLite` rejects a row or audit canonicalization fails.
    pub fn purge_secret_versions_with_audit(
        &mut self,
        secret_id: &str,
        versions: &[u32],
        purged_at: i64,
        audit: Option<AuditContext<'_>>,
    ) -> Result<bool, StoreError> {
        let transaction = self.connection.transaction()?;
        let mut changed_any = false;
        for version in versions {
            let changed = transaction.execute(
                "UPDATE secret_versions
                 SET state = 'purged', grace_until = NULL, purged_at = ?3
                 WHERE secret_id = ?1 AND version = ?2 AND state != 'purged'",
                params![secret_id, version, purged_at],
            )?;
            if changed == 0 {
                continue;
            }
            changed_any = true;
            transaction.execute(
                "DELETE FROM blobs WHERE secret_id = ?1 AND version = ?2",
                params![secret_id, version],
            )?;
            transaction.execute(
                "DELETE FROM fingerprints WHERE secret_id = ?1 AND version = ?2",
                params![secret_id, version],
            )?;
        }
        if !changed_any {
            transaction.commit()?;
            return Ok(false);
        }
        append_optional_audit(&transaction, audit)?;
        transaction.commit()?;

        Ok(true)
    }

    /// Tombstones a secret by id.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` rejects the update.
    pub fn tombstone_secret(&self, id: &str, deleted_at: i64) -> Result<(), StoreError> {
        self.tombstone_secret_with_audit(id, deleted_at, None)
    }

    /// Tombstones a secret and optionally appends the matching audit row in the same transaction.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when `SQLite` rejects a row or audit canonicalization fails.
    pub fn tombstone_secret_with_audit(
        &self,
        id: &str,
        deleted_at: i64,
        audit: Option<AuditContext<'_>>,
    ) -> Result<(), StoreError> {
        let transaction = self.connection.unchecked_transaction()?;
        transaction.execute(
            "UPDATE secrets
             SET state = 'deleted', deleted_at = ?2, updated_at = ?2
             WHERE id = ?1",
            (id, deleted_at),
        )?;
        append_optional_audit(&transaction, audit)?;
        transaction.commit()?;

        Ok(())
    }

    /// Returns an encrypted blob by secret id and version.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` cannot query the blob row.
    pub fn get_blob(
        &self,
        secret_id: &str,
        version: u32,
    ) -> Result<Option<SecretBlobRecord>, StoreError> {
        self.connection
            .query_row(
                "SELECT secret_id, version, encrypted_dek, ciphertext, value_nonce,
                        aad_schema_version, created_at
                 FROM blobs
                 WHERE secret_id = ?1 AND version = ?2",
                params![secret_id, version],
                secret_blob_record_from_row,
            )
            .optional()
            .map_err(StoreError::from)
    }

    /// Verifies the local audit HMAC chain and appends an `AUDIT_VERIFY` row on success.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::AuditIntegrity`] for the first detected chain break.
    /// Returns other [`StoreError`] values for database, parsing, or HMAC construction failures.
    pub fn verify_audit_chain_and_append(
        &mut self,
        project_id: &str,
        audit_key: &[u8],
        timestamp: i64,
    ) -> Result<u64, StoreError> {
        let transaction = self.connection.transaction()?;
        let rows = read_audit_rows(&transaction, project_id)?;
        let mut expected_sequence = 1_u64;
        let mut previous_hmac = [0; AUDIT_HMAC_LEN];

        for row in &rows {
            if row.sequence != expected_sequence {
                return Err(StoreError::AuditIntegrity {
                    sequence: expected_sequence,
                    reason: "sequence gap or reordering".to_owned(),
                });
            }
            if row.previous_hmac != previous_hmac {
                return Err(StoreError::AuditIntegrity {
                    sequence: row.sequence,
                    reason: "previous_hmac mismatch".to_owned(),
                });
            }
            let metadata = serde_json::from_str::<Value>(&row.metadata_json).map_err(|error| {
                StoreError::AuditIntegrity {
                    sequence: row.sequence,
                    reason: format!("metadata_json is not valid JSON: {error}"),
                }
            })?;
            let input = AuditHmacInput {
                schema_version: row.schema_version,
                sequence: row.sequence,
                timestamp: Timestamp::from_unix_nanos(row.timestamp),
                project_id: Some(&row.project_id),
                profile_id: row.profile_id.as_deref(),
                action: &row.action,
                status: &row.status,
                metadata_json: Some(&metadata),
                previous_hmac: Some(&row.previous_hmac),
            };
            let canonical = audit_hmac_v1_bytes(&input)?;
            let mut mac = Hmac::<Sha256>::new_from_slice(audit_key)
                .map_err(|_| StoreError::InvalidAuditKeyLength { actual: audit_key.len() })?;
            mac.update(&canonical);
            let expected_hmac = mac.finalize().into_bytes();
            if expected_hmac.as_slice() != row.hmac.as_slice() {
                return Err(StoreError::AuditIntegrity {
                    sequence: row.sequence,
                    reason: "row hmac mismatch".to_owned(),
                });
            }

            previous_hmac = row.hmac;
            expected_sequence += 1;
        }

        let rows_verified = rows.len() as u64;
        let metadata = json!({
            "schema_version": 1,
            "action": "AUDIT_VERIFY",
            "status": "SUCCESS",
            "rows_verified": rows_verified,
        });
        let audit = AuditWrite {
            project_id,
            profile_id: None,
            action: "AUDIT_VERIFY",
            status: "SUCCESS",
            secret_name: None,
            command: None,
            metadata_json: &metadata,
            timestamp,
        };
        append_audit(&transaction, audit_key, &audit)?;
        transaction.commit()?;

        Ok(rows_verified)
    }
}

fn project_record_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ProjectRecord> {
    Ok(ProjectRecord { id: row.get(0)?, name: row.get(1)?, created_at: row.get(2)? })
}

fn project_root_record_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ProjectRootRecord> {
    Ok(ProjectRootRecord {
        project_id: row.get(0)?,
        root_hash: root_hash_from_row(row, 1, "project_roots.root_hash")?,
        display_path: row.get(2)?,
        created_at: row.get(3)?,
        last_seen_at: row.get(4)?,
    })
}

fn directory_grant_record_from_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<DirectoryGrantRecord> {
    Ok(DirectoryGrantRecord {
        grant_id: row.get(0)?,
        project_id: row.get(1)?,
        profile_id: row.get(2)?,
        root_hash: root_hash_from_row(row, 3, "directory_grants.root_hash")?,
        directory_hash: root_hash_from_row(row, 4, "directory_grants.directory_hash")?,
        grant_scope: row.get(5)?,
        display_path: row.get(6)?,
        created_at: row.get(7)?,
        updated_at: row.get(8)?,
    })
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

fn key_record_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<KeyRecord> {
    Ok(KeyRecord {
        id: row.get(0)?,
        project_id: row.get(1)?,
        profile_id: row.get(2)?,
        purpose: row.get(3)?,
        wrapped_material: row.get(4)?,
        nonce: nonce_from_row(row, 5, "keys.nonce")?,
        created_at: row.get(6)?,
    })
}

fn secret_record_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<SecretRecord> {
    Ok(SecretRecord {
        id: row.get(0)?,
        project_id: row.get(1)?,
        profile_id: row.get(2)?,
        name: row.get(3)?,
        source: row.get(4)?,
        origin: row.get(5)?,
        current_version: row.get(6)?,
        state: row.get(7)?,
        created_at: row.get(8)?,
        updated_at: row.get(9)?,
        last_rotated_at: row.get(10)?,
        deleted_at: row.get(11)?,
    })
}

fn secret_version_record_from_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<SecretVersionRecord> {
    Ok(SecretVersionRecord {
        secret_id: row.get(0)?,
        version: row.get(1)?,
        source: row.get(2)?,
        origin: row.get(3)?,
        state: row.get(4)?,
        created_at: row.get(5)?,
        deprecated_at: row.get(6)?,
        grace_until: row.get(7)?,
        purged_at: row.get(8)?,
    })
}

fn secret_blob_record_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<SecretBlobRecord> {
    Ok(SecretBlobRecord {
        secret_id: row.get(0)?,
        version: row.get(1)?,
        encrypted_dek: row.get(2)?,
        ciphertext: row.get(3)?,
        value_nonce: nonce_from_row(row, 4, "blobs.value_nonce")?,
        aad_schema_version: row.get(5)?,
        created_at: row.get(6)?,
    })
}

fn root_hash_from_row(
    row: &rusqlite::Row<'_>,
    column: usize,
    field: &'static str,
) -> rusqlite::Result<[u8; 32]> {
    let bytes: Vec<u8> = row.get(column)?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        rusqlite::Error::FromSqlConversionFailure(
            column,
            Type::Blob,
            Box::new(InvalidFixedBytesLength { field, expected: 32, actual: bytes.len() }),
        )
    })
}

fn nonce_from_row(
    row: &rusqlite::Row<'_>,
    column: usize,
    field: &'static str,
) -> rusqlite::Result<[u8; 24]> {
    let bytes: Vec<u8> = row.get(column)?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        rusqlite::Error::FromSqlConversionFailure(
            column,
            Type::Blob,
            Box::new(InvalidNonceLength { field, actual: bytes.len() }),
        )
    })
}

fn append_optional_audit(
    transaction: &Transaction<'_>,
    audit: Option<AuditContext<'_>>,
) -> Result<(), StoreError> {
    if let Some(audit) = audit {
        append_audit(transaction, audit.key, audit.write)?;
    }
    Ok(())
}

fn read_audit_rows(
    transaction: &Transaction<'_>,
    project_id: &str,
) -> Result<Vec<StoredAuditRow>, StoreError> {
    let mut statement = transaction.prepare(
        "SELECT sequence, schema_version, timestamp, project_id, profile_id,
                action, status, metadata_json, previous_hmac, hmac
         FROM audit_log
         WHERE project_id = ?1
         ORDER BY sequence",
    )?;
    let rows = statement
        .query_map([project_id], |row| {
            let previous_hmac = row.get::<_, Vec<u8>>(8)?;
            let hmac = row.get::<_, Vec<u8>>(9)?;
            Ok((
                row.get::<_, u64>(0)?,
                row.get::<_, u16>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, String>(7)?,
                previous_hmac,
                hmac,
            ))
        })?
        .map(|row| {
            let (
                sequence,
                schema_version,
                timestamp,
                project_id,
                profile_id,
                action,
                status,
                metadata_json,
                previous_hmac,
                hmac,
            ) = row?;
            Ok(StoredAuditRow {
                sequence,
                schema_version,
                timestamp,
                project_id,
                profile_id,
                action,
                status,
                metadata_json,
                previous_hmac: hmac_vec_to_array(sequence, previous_hmac)?,
                hmac: hmac_vec_to_array(sequence, hmac)?,
            })
        })
        .collect::<Result<Vec<_>, StoreError>>()?;

    Ok(rows)
}

fn hmac_vec_to_array(sequence: u64, value: Vec<u8>) -> Result<[u8; AUDIT_HMAC_LEN], StoreError> {
    value.try_into().map_err(|bytes: Vec<u8>| StoreError::AuditIntegrity {
        sequence,
        reason: format!("invalid hmac length {}", bytes.len()),
    })
}

fn append_audit(
    transaction: &Transaction<'_>,
    audit_key: &[u8],
    audit: &AuditWrite<'_>,
) -> Result<(), StoreError> {
    let previous = transaction
        .query_row(
            "SELECT sequence, hmac
             FROM audit_log
             WHERE project_id = ?1
             ORDER BY sequence DESC
             LIMIT 1",
            [audit.project_id],
            |row| Ok((row.get::<_, u64>(0)?, row.get::<_, Vec<u8>>(1)?)),
        )
        .optional()?;
    let (sequence, previous_hmac) = match previous {
        Some((sequence, hmac)) => {
            let previous_hmac = hmac.try_into().map_err(|bytes: Vec<u8>| {
                StoreError::InvalidAuditHmacLength { actual: bytes.len() }
            })?;
            (sequence + 1, previous_hmac)
        }
        None => (1, [0; AUDIT_HMAC_LEN]),
    };

    let input = AuditHmacInput {
        schema_version: 1,
        sequence,
        timestamp: Timestamp::from_unix_nanos(audit.timestamp),
        project_id: Some(audit.project_id),
        profile_id: audit.profile_id,
        action: audit.action,
        status: audit.status,
        metadata_json: Some(audit.metadata_json),
        previous_hmac: Some(&previous_hmac),
    };
    let canonical = audit_hmac_v1_bytes(&input)?;
    let mut mac = Hmac::<Sha256>::new_from_slice(audit_key)
        .map_err(|_| StoreError::InvalidAuditKeyLength { actual: audit_key.len() })?;
    mac.update(&canonical);
    let hmac = mac.finalize().into_bytes();
    let metadata_json = canonical_json_string(Some(audit.metadata_json));

    transaction.execute(
        "INSERT INTO audit_log(
           project_id, sequence, schema_version, timestamp, profile_id, action,
           status, metadata_json, secret_name, command, previous_hmac, hmac
         )
         VALUES (?1, ?2, 1, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            audit.project_id,
            sequence,
            audit.timestamp,
            audit.profile_id,
            audit.action,
            audit.status,
            metadata_json,
            audit.secret_name,
            audit.command,
            previous_hmac.as_slice(),
            hmac.as_slice(),
        ],
    )?;

    Ok(())
}

#[derive(Debug, Error)]
#[error("{field} must be {expected} bytes, got {actual}")]
struct InvalidFixedBytesLength {
    field: &'static str,
    expected: usize,
    actual: usize,
}

#[derive(Debug, Error)]
#[error("{field} must be 24 bytes, got {actual}")]
struct InvalidNonceLength {
    field: &'static str,
    actual: usize,
}

/// Error returned by the storage layer.
#[derive(Debug, Error)]
pub enum StoreError {
    /// `SQLite` returned an error.
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),

    /// Audit HMAC canonicalization failed.
    #[error(transparent)]
    AuditCanonicalization(#[from] AuditCanonicalizationError),

    /// Audit HMAC key length was invalid.
    #[error("audit HMAC key must be non-empty, got {actual}")]
    InvalidAuditKeyLength {
        /// Actual key length in bytes.
        actual: usize,
    },

    /// Stored audit HMAC length was invalid.
    #[error("audit HMAC must be 32 bytes, got {actual}")]
    InvalidAuditHmacLength {
        /// Actual HMAC length in bytes.
        actual: usize,
    },

    /// Audit chain verification failed.
    #[error("audit integrity failed at sequence {sequence}: {reason}")]
    AuditIntegrity {
        /// Sequence number where verification failed.
        sequence: u64,
        /// Metadata-only failure reason.
        reason: String,
    },

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

CREATE TABLE IF NOT EXISTS directory_grants (
  grant_id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  profile_id TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
  root_hash BLOB NOT NULL CHECK (length(root_hash) = 32),
  directory_hash BLOB NOT NULL CHECK (length(directory_hash) = 32),
  grant_scope TEXT NOT NULL CHECK (grant_scope IN ('project-root')),
  display_path TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  UNIQUE (project_id, profile_id, root_hash, directory_hash, grant_scope)
);

CREATE INDEX IF NOT EXISTS directory_grants_project_root_idx
  ON directory_grants(project_id, root_hash);

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

    use serde_json::json;
    use tempfile::{TempDir, tempdir};

    use super::{
        AuditContext, AuditWrite, DirectoryGrantRecord, KeyRecord, ProfileRecord, ProjectRecord,
        ProjectRootRecord, SCHEMA_VERSION, SecretBlobRecord, SecretFingerprintRecord, SecretRecord,
        SecretVersionRecord, Store, StoreError,
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
            "directory_grants",
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
        test_store.store.insert_profile_if_absent(
            "lk_prof_dev",
            "lk_proj_test",
            "dev",
            false,
            100,
        )?;
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
            test_store
                .store
                .list_active_secrets_by_profile("lk_proj_test", "lk_prof_test")?
                .is_empty()
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
    fn purge_secret_versions_removes_material_but_keeps_version_rows() -> Result<(), Box<dyn Error>>
    {
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
}
