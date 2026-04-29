//! `SQLite` storage layer for Locket.

use std::path::Path;

use locket_core::canonical_json_string;
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::Value;

mod audit;
mod device;
mod error;
mod grants;
mod keys;
mod passkey;
mod profile;
mod project;
mod roots;
mod row;
mod runtime_session;
mod schema;

pub use audit::{AuditContext, AuditLogRecord, AuditWrite};
pub use device::DeviceRecord;
pub use error::StoreError;
pub use grants::DirectoryGrantRecord;
pub use keys::KeyRecord;
pub use passkey::PasskeyCredentialRecord;
pub use profile::ProfileRecord;
pub use project::ProjectRecord;
pub use roots::ProjectRootRecord;
pub use runtime_session::{
    AutomationClientNonceRecord, AutomationClientRecord, InvalidRuntimeSessionSecretNameRetention,
    RuntimeSessionRecord, RuntimeSessionSecretNameRetention,
};
pub use schema::SCHEMA_VERSION;

use audit::append_optional_audit;
use row::nonce_from_row;

/// SQLite-backed Locket store.
#[derive(Debug)]
pub struct Store {
    connection: Connection,
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

/// Mutable secret metadata update plus optional timestamp/audit context.
#[derive(Clone, Copy, Debug, Default)]
pub struct SecretMetadataUpdate<'a> {
    /// Optional description replacement.
    pub description: Option<&'a str>,
    /// Optional owner replacement.
    pub owner: Option<&'a str>,
    /// Optional full tag-list replacement.
    pub tags: Option<&'a [String]>,
    /// Optional required flag replacement.
    pub required: Option<bool>,
    /// Optional `updated_at` replacement.
    pub updated_at: Option<i64>,
    /// Optional audit row appended in the same transaction when the update matches.
    pub audit: Option<AuditContext<'a>>,
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
        schema::configure_connection(&connection)?;
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
        schema::initialize_schema(&mut self.connection)
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

    /// Runs `SQLite`'s metadata-only integrity check.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` cannot execute the check.
    pub fn integrity_check(&self) -> Result<Vec<String>, StoreError> {
        let mut statement = self.connection.prepare("PRAGMA integrity_check")?;
        let rows = statement
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
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
        self.update_secret_metadata_with_options(
            secret_id,
            SecretMetadataUpdate {
                description,
                owner,
                tags,
                required,
                updated_at: None,
                audit: None,
            },
        )
    }

    /// Updates mutable secret metadata and optionally records a metadata-only audit row atomically.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when `SQLite` rejects the update or audit canonicalization fails.
    pub fn update_secret_metadata_with_options(
        &self,
        secret_id: &str,
        update: SecretMetadataUpdate<'_>,
    ) -> Result<bool, StoreError> {
        let tags_json = update.tags.map(|tags| {
            let tags = tags.iter().map(|tag| Value::String(tag.clone())).collect::<Vec<_>>();
            canonical_json_string(Some(&Value::Array(tags)))
        });
        let transaction = self.connection.unchecked_transaction()?;
        transaction.execute(
            "UPDATE secrets
             SET description = COALESCE(?2, description),
                 owner = COALESCE(?3, owner),
                 tags_json = COALESCE(?4, tags_json),
                 required = COALESCE(?5, required),
                 updated_at = COALESCE(?6, updated_at)
             WHERE id = ?1 AND state = 'active'",
            params![
                secret_id,
                update.description,
                update.owner,
                tags_json.as_deref(),
                update.required,
                update.updated_at,
            ],
        )?;
        let changed = transaction.changes() == 1;
        if changed {
            append_optional_audit(&transaction, update.audit)?;
        }
        transaction.commit()?;

        Ok(changed)
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

#[cfg(test)]
mod tests;
