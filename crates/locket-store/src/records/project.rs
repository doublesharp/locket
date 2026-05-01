//! Project metadata records and `Store` project operations.

use rusqlite::OptionalExtension;

use crate::Store;
use crate::error::StoreError;

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

pub fn project_record_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ProjectRecord> {
    Ok(ProjectRecord { id: row.get(0)?, name: row.get(1)?, created_at: row.get(2)? })
}

impl Store {
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

    /// Deletes a project and its cascading local metadata.
    ///
    /// Returns `true` when a project row was removed and `false` when it was
    /// already absent.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` rejects the delete.
    pub fn delete_project(&self, id: &str) -> Result<bool, StoreError> {
        self.connection.execute("DELETE FROM projects WHERE id = ?1", [id])?;
        Ok(self.connection.changes() > 0)
    }
}
