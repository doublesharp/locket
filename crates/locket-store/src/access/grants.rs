//! Directory grant records and `Store` operations for shell/editor consent.

use rusqlite::{OptionalExtension, params};

use crate::Store;
use crate::error::StoreError;
use crate::row::root_hash_from_row;

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
    /// Optional team member id that authorized this grant.
    ///
    /// `None` for v1 shell installs that predate the team-member binding.
    pub granted_by: Option<String>,
    /// Creation timestamp in nanoseconds since the Unix epoch.
    pub created_at: i64,
    /// Last update timestamp in nanoseconds since the Unix epoch.
    pub updated_at: i64,
    /// Soft-revocation timestamp in nanoseconds since the Unix epoch.
    ///
    /// `None` means the grant is currently active. Set by deny operations
    /// instead of hard-deleting the row so audit chains keep referring to a
    /// stable `grant_id`.
    pub revoked_at: Option<i64>,
}

pub fn directory_grant_record_from_row(
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
        granted_by: row.get(7)?,
        created_at: row.get(8)?,
        updated_at: row.get(9)?,
        revoked_at: row.get(10)?,
    })
}

const DIRECTORY_GRANT_COLUMNS: &str = "grant_id, project_id, profile_id, root_hash, directory_hash, grant_scope, display_path, \
     granted_by, created_at, updated_at, revoked_at";

impl Store {
    /// Records or refreshes durable directory consent for a project/profile.
    ///
    /// If a previously-revoked row exists for this scope, it is revived by
    /// clearing `revoked_at` and refreshing `display_path`, `granted_by`, and
    /// `updated_at`. Otherwise a new row is inserted.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` rejects the write.
    pub fn allow_directory_grant(&self, grant: &DirectoryGrantRecord) -> Result<(), StoreError> {
        self.connection.execute(
            "INSERT INTO directory_grants(
               grant_id, project_id, profile_id, root_hash, directory_hash, grant_scope,
               display_path, granted_by, created_at, updated_at, revoked_at
             )
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
             ON CONFLICT(project_id, profile_id, root_hash, directory_hash, grant_scope)
             DO UPDATE SET
               display_path = excluded.display_path,
               granted_by = excluded.granted_by,
               updated_at = excluded.updated_at,
               revoked_at = NULL",
            params![
                grant.grant_id.as_str(),
                grant.project_id.as_str(),
                grant.profile_id.as_str(),
                grant.root_hash.as_slice(),
                grant.directory_hash.as_slice(),
                grant.grant_scope.as_str(),
                grant.display_path.as_deref(),
                grant.granted_by.as_deref(),
                grant.created_at,
                grant.updated_at,
                grant.revoked_at,
            ],
        )?;

        Ok(())
    }

    /// Returns the active durable directory grant for an exact scope.
    ///
    /// Revoked rows (`revoked_at IS NOT NULL`) are filtered out so callers
    /// see "no active grant" after a deny.
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
        let sql = format!(
            "SELECT {DIRECTORY_GRANT_COLUMNS}
             FROM directory_grants
             WHERE project_id = ?1
               AND profile_id = ?2
               AND root_hash = ?3
               AND directory_hash = ?4
               AND grant_scope = ?5
               AND revoked_at IS NULL"
        );
        Ok(self
            .connection
            .query_row(
                &sql,
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

    /// Returns any directory grant row (active or revoked) for an exact scope.
    ///
    /// Used by deny audit emission to capture the prior `granted_by` value.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` cannot query the row.
    pub fn get_directory_grant_any_state(
        &self,
        project_id: &str,
        profile_id: &str,
        root_hash: &[u8; 32],
        directory_hash: &[u8; 32],
        grant_scope: &str,
    ) -> Result<Option<DirectoryGrantRecord>, StoreError> {
        let sql = format!(
            "SELECT {DIRECTORY_GRANT_COLUMNS}
             FROM directory_grants
             WHERE project_id = ?1
               AND profile_id = ?2
               AND root_hash = ?3
               AND directory_hash = ?4
               AND grant_scope = ?5"
        );
        Ok(self
            .connection
            .query_row(
                &sql,
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

    /// Soft-revokes a durable directory grant by setting `revoked_at`.
    ///
    /// Returns `true` when an active grant transitioned to revoked, and
    /// `false` when no matching active grant existed (already revoked or
    /// absent).
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` rejects the update.
    pub fn deny_directory_grant(
        &self,
        project_id: &str,
        profile_id: &str,
        root_hash: &[u8; 32],
        directory_hash: &[u8; 32],
        grant_scope: &str,
        revoked_at: i64,
    ) -> Result<bool, StoreError> {
        self.connection.execute(
            "UPDATE directory_grants
             SET revoked_at = ?6, updated_at = ?6
             WHERE project_id = ?1
               AND profile_id = ?2
               AND root_hash = ?3
               AND directory_hash = ?4
               AND grant_scope = ?5
               AND revoked_at IS NULL",
            params![
                project_id,
                profile_id,
                root_hash.as_slice(),
                directory_hash.as_slice(),
                grant_scope,
                revoked_at,
            ],
        )?;

        Ok(self.connection.changes() == 1)
    }

    /// Soft-revokes every active durable directory grant for a project.
    ///
    /// Returns the number of rows transitioned from active to revoked.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` rejects the update.
    pub fn deny_all_directory_grants(
        &self,
        project_id: &str,
        revoked_at: i64,
    ) -> Result<usize, StoreError> {
        self.connection
            .execute(
                "UPDATE directory_grants
                 SET revoked_at = ?2, updated_at = ?2
                 WHERE project_id = ?1 AND revoked_at IS NULL",
                params![project_id, revoked_at],
            )
            .map_err(StoreError::from)
    }

    /// Soft-revokes every active durable directory grant for a trusted project root.
    ///
    /// Returns the number of rows transitioned from active to revoked.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` rejects the update.
    pub fn deny_directory_grants_for_root(
        &self,
        project_id: &str,
        root_hash: &[u8; 32],
        revoked_at: i64,
    ) -> Result<usize, StoreError> {
        self.connection
            .execute(
                "UPDATE directory_grants
                 SET revoked_at = ?3, updated_at = ?3
                 WHERE project_id = ?1 AND root_hash = ?2 AND revoked_at IS NULL",
                params![project_id, root_hash.as_slice(), revoked_at],
            )
            .map_err(StoreError::from)
    }

    /// Counts active durable directory grants scoped to a single project/profile.
    ///
    /// Used by metadata-only profile summaries (e.g., the `clear-dangerous`
    /// confirmation flow) so we can report how many grants will lose
    /// dangerous-profile gating without exposing the underlying paths.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` cannot query the count.
    pub fn count_directory_grants_for_profile(
        &self,
        project_id: &str,
        profile_id: &str,
    ) -> Result<u32, StoreError> {
        let count: i64 = self.connection.query_row(
            "SELECT COUNT(*) FROM directory_grants
             WHERE project_id = ?1 AND profile_id = ?2 AND revoked_at IS NULL",
            params![project_id, profile_id],
            |row| row.get(0),
        )?;
        Ok(u32::try_from(count.max(0)).unwrap_or(u32::MAX))
    }
}
