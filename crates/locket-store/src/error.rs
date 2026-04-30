//! Storage-layer error types.

use locket_core::{AuditCanonicalizationError, LocketError};
use thiserror::Error;

#[derive(Debug, Error)]
#[error("{field} must be {expected} bytes, got {actual}")]
pub struct InvalidFixedBytesLength {
    pub field: &'static str,
    pub expected: usize,
    pub actual: usize,
}

#[derive(Debug, Error)]
#[error("{field} must be 24 bytes, got {actual}")]
pub struct InvalidNonceLength {
    pub field: &'static str,
    pub actual: usize,
}

/// Error returned by the storage layer.
#[derive(Debug, Error)]
pub enum StoreError {
    /// `SQLite` returned an error.
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),

    /// JSON metadata encoding failed.
    #[error(transparent)]
    Json(#[from] serde_json::Error),

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

    /// Serialized `metadata_json` exceeded the per-row spec cap.
    #[error(
        "audit metadata_json is {actual} bytes; the per-row cap is {limit} bytes (action {action})"
    )]
    AuditMetadataTooLarge {
        /// Action name from the rejected `AuditWrite`.
        action: String,
        /// Serialized JSON byte length the writer attempted to insert.
        actual: usize,
        /// Spec-defined per-row cap (64 KiB).
        limit: usize,
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

impl StoreError {
    /// Returns the stable high-level Locket failure represented by this store error.
    #[must_use]
    pub fn locket_error(&self) -> LocketError {
        match self {
            Self::Sqlite(error) => sqlite_locket_error(error),
            Self::UnsupportedSchema { .. } => LocketError::SchemaNewerThanBinary,
            Self::AuditIntegrity { .. }
            | Self::InvalidAuditHmacLength { .. }
            | Self::InvalidAuditKeyLength { .. }
            | Self::AuditCanonicalization(_) => LocketError::AuditIntegrityFailed,
            Self::AuditMetadataTooLarge { .. } => LocketError::MetadataInvalid,
            Self::Json(_) => LocketError::CorruptDb,
        }
    }
}

fn sqlite_locket_error(error: &rusqlite::Error) -> LocketError {
    match error.sqlite_error_code() {
        Some(rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked) => {
            LocketError::StorageBusy
        }
        Some(rusqlite::ErrorCode::DatabaseCorrupt | rusqlite::ErrorCode::NotADatabase) => {
            LocketError::CorruptDb
        }
        _ => LocketError::CorruptDb,
    }
}
