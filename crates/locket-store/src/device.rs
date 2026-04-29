//! Trusted device records and `Store` device operations.

use rusqlite::types::Type;
use rusqlite::{OptionalExtension, params};

use crate::Store;
use crate::error::StoreError;

/// Trusted device public metadata row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceRecord {
    /// Device identifier.
    pub id: String,
    /// Parent project identifier.
    pub project_id: String,
    /// Human-readable device name.
    pub name: String,
    /// Ed25519 signing public key bytes.
    pub signing_public_key: Vec<u8>,
    /// X25519 sealing public key bytes.
    pub sealing_public_key: Vec<u8>,
    /// Lowercase hex SHA-256 fingerprint.
    pub fingerprint: String,
    /// Safety words as metadata-only display strings.
    pub safety_words: Vec<String>,
    /// Whether this row represents the current local machine's device identity.
    pub local: bool,
    /// Creation timestamp in nanoseconds since the Unix epoch.
    pub created_at: i64,
    /// Last-seen timestamp in nanoseconds since the Unix epoch.
    pub last_seen_at: Option<i64>,
    /// Revocation timestamp in nanoseconds since the Unix epoch.
    pub revoked_at: Option<i64>,
}

fn device_record_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<DeviceRecord> {
    let safety_words_json = row.get::<_, String>(6)?;
    let safety_words =
        serde_json::from_str::<Vec<String>>(&safety_words_json).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(6, Type::Text, Box::new(error))
        })?;
    Ok(DeviceRecord {
        id: row.get(0)?,
        project_id: row.get(1)?,
        name: row.get(2)?,
        signing_public_key: row.get(3)?,
        sealing_public_key: row.get(4)?,
        fingerprint: row.get(5)?,
        safety_words,
        local: row.get(7)?,
        created_at: row.get(8)?,
        last_seen_at: row.get(9)?,
        revoked_at: row.get(10)?,
    })
}

impl Store {
    /// Inserts a trusted device public metadata row.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` rejects the insert.
    pub fn insert_device(&self, device: &DeviceRecord) -> Result<(), StoreError> {
        let safety_words_json = serde_json::to_string(&device.safety_words)?;
        self.connection.execute(
            "INSERT INTO devices(
               id, project_id, name, signing_public_key, sealing_public_key, fingerprint,
               safety_words_json, local, created_at, last_seen_at, revoked_at
             )
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                device.id.as_str(),
                device.project_id.as_str(),
                device.name.as_str(),
                device.signing_public_key.as_slice(),
                device.sealing_public_key.as_slice(),
                device.fingerprint.as_str(),
                safety_words_json.as_str(),
                device.local,
                device.created_at,
                device.last_seen_at,
                device.revoked_at,
            ],
        )?;

        Ok(())
    }

    /// Lists trusted devices for a project ordered by creation time.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` cannot query device rows.
    pub fn list_devices(
        &self,
        project_id: &str,
        include_revoked: bool,
    ) -> Result<Vec<DeviceRecord>, StoreError> {
        let sql = if include_revoked {
            "SELECT id, project_id, name, signing_public_key, sealing_public_key, fingerprint,
                    safety_words_json, local, created_at, last_seen_at, revoked_at
             FROM devices
             WHERE project_id = ?1
             ORDER BY created_at, id"
        } else {
            "SELECT id, project_id, name, signing_public_key, sealing_public_key, fingerprint,
                    safety_words_json, local, created_at, last_seen_at, revoked_at
             FROM devices
             WHERE project_id = ?1 AND revoked_at IS NULL
             ORDER BY created_at, id"
        };
        let mut statement = self.connection.prepare(sql)?;
        let devices = statement
            .query_map([project_id], device_record_from_row)?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(devices)
    }

    /// Returns the active local device row for a project.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` cannot query device rows.
    pub fn get_active_local_device(
        &self,
        project_id: &str,
    ) -> Result<Option<DeviceRecord>, StoreError> {
        Ok(self
            .connection
            .query_row(
                "SELECT id, project_id, name, signing_public_key, sealing_public_key, fingerprint,
                        safety_words_json, local, created_at, last_seen_at, revoked_at
                 FROM devices
                 WHERE project_id = ?1 AND local = 1 AND revoked_at IS NULL
                 ORDER BY created_at DESC
                 LIMIT 1",
                [project_id],
                device_record_from_row,
            )
            .optional()?)
    }

    /// Finds a device by id, name, or fingerprint for a project.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` cannot query device rows.
    pub fn find_device(
        &self,
        project_id: &str,
        selector: &str,
    ) -> Result<Option<DeviceRecord>, StoreError> {
        Ok(self
            .connection
            .query_row(
                "SELECT id, project_id, name, signing_public_key, sealing_public_key, fingerprint,
                        safety_words_json, local, created_at, last_seen_at, revoked_at
                 FROM devices
                 WHERE project_id = ?1
                   AND (id = ?2 OR name = ?2 OR fingerprint = lower(?2))
                 ORDER BY revoked_at IS NULL DESC, created_at DESC
                 LIMIT 1",
                params![project_id, selector],
                device_record_from_row,
            )
            .optional()?)
    }

    /// Marks a device revoked.
    ///
    /// Returns `true` when a row changed.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` rejects the update.
    pub fn revoke_device(
        &self,
        project_id: &str,
        device_id: &str,
        revoked_at: i64,
    ) -> Result<bool, StoreError> {
        self.connection.execute(
            "UPDATE devices
             SET revoked_at = ?3
             WHERE project_id = ?1 AND id = ?2 AND revoked_at IS NULL",
            params![project_id, device_id, revoked_at],
        )?;

        Ok(self.connection.changes() == 1)
    }
}
