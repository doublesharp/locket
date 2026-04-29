//! Profile metadata records and `Store` profile operations.

use rusqlite::OptionalExtension;

use crate::Store;
use crate::error::StoreError;

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

pub fn profile_record_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ProfileRecord> {
    Ok(ProfileRecord {
        id: row.get(0)?,
        project_id: row.get(1)?,
        name: row.get(2)?,
        dangerous: row.get(3)?,
        created_at: row.get(4)?,
    })
}

impl Store {
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
}
