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
    /// Creation timestamp in nanoseconds since the Unix epoch.
    pub created_at: i64,
    /// Last update timestamp in nanoseconds since the Unix epoch.
    pub updated_at: i64,
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
        created_at: row.get(7)?,
        updated_at: row.get(8)?,
    })
}

impl Store {
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

    /// Removes every durable directory grant for a trusted project root.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` rejects the delete.
    pub fn deny_directory_grants_for_root(
        &self,
        project_id: &str,
        root_hash: &[u8; 32],
    ) -> Result<usize, StoreError> {
        self.connection
            .execute(
                "DELETE FROM directory_grants WHERE project_id = ?1 AND root_hash = ?2",
                params![project_id, root_hash.as_slice()],
            )
            .map_err(StoreError::from)
    }

    /// Counts durable directory grants scoped to a single project/profile.
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
             WHERE project_id = ?1 AND profile_id = ?2",
            params![project_id, profile_id],
            |row| row.get(0),
        )?;
        Ok(u32::try_from(count.max(0)).unwrap_or(u32::MAX))
    }
}
