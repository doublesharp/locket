//! `SQLite` storage layer for Locket.

// age 0.11 enters through locket-core and carries older transitive crates
// alongside workspace versions. The sealed-bundle dependency owns that skew.
#![allow(clippy::multiple_crate_versions)]

use std::path::Path;

use rusqlite::Connection;

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
mod secret;
mod team;

pub use audit::{AUDIT_METADATA_JSON_LIMIT, AuditContext, AuditLogRecord, AuditWrite};
pub use device::DeviceRecord;
pub use error::StoreError;
pub use grants::DirectoryGrantRecord;
pub use keys::KeyRecord;
pub use passkey::{DEFAULT_WEBAUTHN_RELYING_PARTY_ID, PasskeyCredentialRecord};
pub use profile::ProfileRecord;
pub use project::ProjectRecord;
pub use roots::ProjectRootRecord;
pub use runtime_session::{
    AutomationClientNonceRecord, AutomationClientRecord, InvalidRuntimeSessionSecretNameRetention,
    RuntimeSessionRecord, RuntimeSessionSecretNameRetention,
};
pub use schema::{AUDIT_ACTION_SCHEMA_MIGRATE, SCHEMA_VERSION};
pub use secret::{
    SecretBlobRecord, SecretCopyTarget, SecretFingerprintRecord, SecretMetadataUpdate,
    SecretRecord, SecretVersionRecord, VersionDeprecation,
};
pub use team::{PendingTeamInviteRecord, TeamInviteRecord, TeamMemberListRecord, TeamRecord};

/// SQLite-backed Locket store.
#[derive(Debug)]
pub struct Store {
    connection: Connection,
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
}

#[cfg(test)]
mod tests;
