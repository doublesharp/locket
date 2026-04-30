//! Audit-log row types, append/verify helpers, and `Store` audit methods.

use hmac::{Hmac, Mac};
use locket_core::{
    AUDIT_HMAC_LEN, AuditHmacInput, Timestamp, audit_hmac_v1_bytes, canonical_json_string,
};
use rusqlite::{OptionalExtension, Transaction, params};
use serde_json::{Value, json};
use sha2::Sha256;

use crate::Store;
use crate::error::StoreError;

/// Maximum serialized `metadata_json` byte length per audit row.
///
/// `docs/specs/audit.md` and `docs/specs/data-model.md` cap each
/// row's metadata at 64 KiB. The append path enforces this before
/// writing so the chain never contains an unbounded row.
pub const AUDIT_METADATA_JSON_LIMIT: usize = 64 * 1024;

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

/// Metadata-only audit row returned for reporting.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditLogRecord {
    /// Project-scoped audit sequence.
    pub sequence: u64,
    /// Event timestamp in nanoseconds since the Unix epoch.
    pub timestamp: i64,
    /// Optional profile identifier.
    pub profile_id: Option<String>,
    /// Audit action string.
    pub action: String,
    /// Audit status string.
    pub status: String,
    /// Optional query convenience secret name.
    pub secret_name: Option<String>,
    /// Optional query convenience command string.
    pub command: Option<String>,
}

/// Stored row material for structural verification of an imported audit chain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImportedAuditChainRow {
    /// Sequence number from the source project's audit chain.
    pub sequence: u64,
    /// Stored previous-row HMAC from the imported row.
    pub previous_hmac: [u8; AUDIT_HMAC_LEN],
    /// Stored row HMAC from the imported row.
    pub hmac: [u8; AUDIT_HMAC_LEN],
}

/// Summary returned after imported audit-chain structural verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImportedAuditChainVerification {
    /// Number of imported rows verified.
    pub rows_verified: u64,
    /// Checkpoint sequence the imported chain was verified against.
    pub checkpoint_sequence: u64,
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

pub fn audit_log_record_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<AuditLogRecord> {
    Ok(AuditLogRecord {
        sequence: row.get(0)?,
        timestamp: row.get(1)?,
        profile_id: row.get(2)?,
        action: row.get(3)?,
        status: row.get(4)?,
        secret_name: row.get(5)?,
        command: row.get(6)?,
    })
}

pub fn append_optional_audit(
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

/// Verifies imported remote audit rows against their plaintext bundle checkpoint.
///
/// The source project's audit key is never exported in sealed bundles, so this
/// check verifies only structural continuity and the final checkpoint match.
pub fn verify_imported_audit_chain_structure(
    rows: &[ImportedAuditChainRow],
    checkpoint_sequence: u64,
    checkpoint_hmac: &[u8; AUDIT_HMAC_LEN],
) -> Result<ImportedAuditChainVerification, StoreError> {
    let mut expected_sequence = 1_u64;
    let mut previous_hmac = [0; AUDIT_HMAC_LEN];

    for row in rows {
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

        previous_hmac = row.hmac;
        expected_sequence += 1;
    }

    let Some(final_row) = rows.last() else {
        return Err(StoreError::AuditIntegrity {
            sequence: 1,
            reason: "imported audit chain is empty".to_owned(),
        });
    };
    if final_row.sequence != checkpoint_sequence {
        return Err(StoreError::AuditIntegrity {
            sequence: final_row.sequence,
            reason: "checkpoint_sequence mismatch".to_owned(),
        });
    }
    if final_row.hmac != *checkpoint_hmac {
        return Err(StoreError::AuditIntegrity {
            sequence: final_row.sequence,
            reason: "checkpoint_hmac mismatch".to_owned(),
        });
    }

    Ok(ImportedAuditChainVerification { rows_verified: rows.len() as u64, checkpoint_sequence })
}

pub fn append_audit(
    transaction: &Transaction<'_>,
    audit_key: &[u8],
    audit: &AuditWrite<'_>,
) -> Result<(), StoreError> {
    let metadata_json = canonical_json_string(Some(audit.metadata_json));
    if metadata_json.len() > AUDIT_METADATA_JSON_LIMIT {
        return Err(StoreError::AuditMetadataTooLarge {
            action: audit.action.to_owned(),
            actual: metadata_json.len(),
            limit: AUDIT_METADATA_JSON_LIMIT,
        });
    }
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

impl Store {
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

    /// Lists recent metadata-only audit action names for a project.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` cannot query audit rows.
    pub fn list_recent_audit_actions(
        &self,
        project_id: &str,
        limit: u32,
    ) -> Result<Vec<String>, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT action
             FROM audit_log
             WHERE project_id = ?1
             ORDER BY sequence DESC
             LIMIT ?2",
        )?;
        let mut actions = statement
            .query_map((project_id, limit), |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        actions.reverse();
        Ok(actions)
    }

    /// Lists metadata-only audit rows for a profile since the supplied timestamp.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` cannot query audit rows.
    pub fn list_audit_rows_since(
        &self,
        project_id: &str,
        profile_id: &str,
        since: i64,
    ) -> Result<Vec<AuditLogRecord>, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT sequence, timestamp, profile_id, action, status, secret_name, command
             FROM audit_log
             WHERE project_id = ?1 AND profile_id = ?2 AND timestamp >= ?3
             ORDER BY timestamp, sequence",
        )?;
        let rows = statement
            .query_map((project_id, profile_id, since), audit_log_record_from_row)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
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
            "check_names": ["audit_hmac_chain"],
            "pass_count": 1,
            "warn_count": 0,
            "fail_count": 0,
            "skip_count": 0,
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
