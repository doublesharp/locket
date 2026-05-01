//! Local command-policy index helpers.

use rusqlite::{OptionalExtension, params};
use serde_json::Value;

use crate::Store;
use crate::audit::{AuditContext, append_optional_audit};
use crate::error::StoreError;

/// Metadata-only cached command policy row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandPolicyIndexRecord {
    /// Parent project identifier.
    pub project_id: String,
    /// Policy name from `locket.toml`.
    pub name: String,
    /// Raw policy table serialized as JSON.
    pub policy_json: Value,
    /// Normalized policy projection serialized as JSON.
    pub normalized_json: Value,
    /// First insertion timestamp in nanoseconds since the Unix epoch.
    pub created_at: i64,
    /// Last refresh timestamp in nanoseconds since the Unix epoch.
    pub updated_at: i64,
}

fn command_policy_index_record_from_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<CommandPolicyIndexRecord> {
    let policy_json =
        serde_json::from_str::<Value>(&row.get::<_, String>(2)?).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                2,
                rusqlite::types::Type::Text,
                Box::new(error),
            )
        })?;
    let normalized_json =
        serde_json::from_str::<Value>(&row.get::<_, String>(3)?).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                3,
                rusqlite::types::Type::Text,
                Box::new(error),
            )
        })?;
    Ok(CommandPolicyIndexRecord {
        project_id: row.get(0)?,
        name: row.get(1)?,
        policy_json,
        normalized_json,
        created_at: row.get(4)?,
        updated_at: row.get(5)?,
    })
}

impl Store {
    /// Inserts or refreshes a cached command policy and optional audit row atomically.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when JSON serialization, `SQLite`, or audit append fails.
    pub fn upsert_command_policy_index(
        &mut self,
        project_id: &str,
        name: &str,
        policy_json: &Value,
        normalized_json: &Value,
        timestamp: i64,
        audit: Option<AuditContext<'_>>,
    ) -> Result<(), StoreError> {
        let policy_json = serde_json::to_string(policy_json)?;
        let normalized_json = serde_json::to_string(normalized_json)?;
        let transaction = self.connection.transaction()?;
        transaction.execute(
            "INSERT INTO command_policies(
               project_id, name, policy_json, normalized_json, created_at, updated_at
             )
             VALUES (?1, ?2, ?3, ?4, ?5, ?5)
             ON CONFLICT(project_id, name) DO UPDATE SET
               policy_json = excluded.policy_json,
               normalized_json = excluded.normalized_json,
               updated_at = excluded.updated_at",
            params![project_id, name, policy_json, normalized_json, timestamp],
        )?;
        append_optional_audit(&transaction, audit)?;
        transaction.commit()?;
        Ok(())
    }

    /// Deletes a cached command policy and optional audit row atomically.
    ///
    /// Returns `true` when a cache row was removed.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when `SQLite` or audit append fails.
    pub fn delete_command_policy_index(
        &mut self,
        project_id: &str,
        name: &str,
        audit: Option<AuditContext<'_>>,
    ) -> Result<bool, StoreError> {
        let transaction = self.connection.transaction()?;
        transaction.execute(
            "DELETE FROM command_policies WHERE project_id = ?1 AND name = ?2",
            params![project_id, name],
        )?;
        let deleted = transaction.changes() > 0;
        append_optional_audit(&transaction, audit)?;
        transaction.commit()?;
        Ok(deleted)
    }

    /// Returns one cached command policy row.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when `SQLite` cannot query or decode the row.
    pub fn get_command_policy_index(
        &self,
        project_id: &str,
        name: &str,
    ) -> Result<Option<CommandPolicyIndexRecord>, StoreError> {
        self.connection
            .query_row(
                "SELECT project_id, name, policy_json, normalized_json, created_at, updated_at
                 FROM command_policies
                 WHERE project_id = ?1 AND name = ?2",
                params![project_id, name],
                command_policy_index_record_from_row,
            )
            .optional()
            .map_err(StoreError::from)
    }
}
