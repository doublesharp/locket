//! Passkey/WebAuthn credential records and `Store` operations.

use rusqlite::params;
use rusqlite::types::Type;

use crate::Store;
use crate::error::StoreError;

/// Default `WebAuthn` relying party id for optional PRF credentials.
pub const DEFAULT_WEBAUTHN_RELYING_PARTY_ID: &str = "locket.localhost";

/// Passkey/WebAuthn credential public metadata row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PasskeyCredentialRecord {
    /// Credential metadata identifier.
    pub id: String,
    /// Parent project identifier.
    pub project_id: String,
    /// Human-readable authenticator label.
    pub label: String,
    /// Public `WebAuthn` credential id bytes. Never private key material.
    pub credential_id: Vec<u8>,
    /// Transport hints exposed by the platform/authenticator.
    pub transports: Vec<String>,
    /// Whether PRF/hmac-secret key-wrapping is supported.
    pub prf_capable: bool,
    /// `WebAuthn` relying party id used when this credential was registered.
    pub webauthn_relying_party_id: String,
    /// Whether the authenticator reported backup eligibility.
    pub backup_eligible: Option<bool>,
    /// Whether the authenticator reported backup state.
    pub backup_state: Option<bool>,
    /// Creation timestamp in nanoseconds since the Unix epoch.
    pub created_at: i64,
    /// Last-use timestamp in nanoseconds since the Unix epoch.
    pub last_used_at: Option<i64>,
    /// Revocation timestamp in nanoseconds since the Unix epoch.
    pub revoked_at: Option<i64>,
}

fn passkey_credential_from_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<PasskeyCredentialRecord> {
    let transports_json = row.get::<_, String>(4)?;
    let transports = serde_json::from_str::<Vec<String>>(&transports_json).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(4, Type::Text, Box::new(error))
    })?;
    Ok(PasskeyCredentialRecord {
        id: row.get(0)?,
        project_id: row.get(1)?,
        label: row.get(2)?,
        credential_id: row.get(3)?,
        transports,
        prf_capable: row.get(5)?,
        webauthn_relying_party_id: row.get(6)?,
        backup_eligible: row.get(7)?,
        backup_state: row.get(8)?,
        created_at: row.get(9)?,
        last_used_at: row.get(10)?,
        revoked_at: row.get(11)?,
    })
}

impl Store {
    /// Inserts a passkey credential public metadata row.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` rejects the insert or
    /// [`StoreError::Json`] when transport metadata cannot be encoded.
    pub fn insert_passkey_credential(
        &self,
        credential: &PasskeyCredentialRecord,
    ) -> Result<(), StoreError> {
        let transports_json = serde_json::to_string(&credential.transports)?;
        self.connection.execute(
            "INSERT INTO passkey_credentials(
               id, project_id, label, credential_id, transports_json, prf_capable,
               webauthn_relying_party_id, backup_eligible, backup_state, created_at,
               last_used_at, revoked_at
             )
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                credential.id.as_str(),
                credential.project_id.as_str(),
                credential.label.as_str(),
                credential.credential_id.as_slice(),
                transports_json.as_str(),
                credential.prf_capable,
                credential.webauthn_relying_party_id.as_str(),
                credential.backup_eligible,
                credential.backup_state,
                credential.created_at,
                credential.last_used_at,
                credential.revoked_at,
            ],
        )?;

        Ok(())
    }

    /// Lists passkey credential metadata for a project ordered by creation time.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` cannot query rows.
    pub fn list_passkey_credentials(
        &self,
        project_id: &str,
        include_revoked: bool,
    ) -> Result<Vec<PasskeyCredentialRecord>, StoreError> {
        let sql = if include_revoked {
            "SELECT id, project_id, label, credential_id, transports_json, prf_capable,
                    webauthn_relying_party_id, backup_eligible, backup_state, created_at,
                    last_used_at, revoked_at
             FROM passkey_credentials
             WHERE project_id = ?1
             ORDER BY created_at, id"
        } else {
            "SELECT id, project_id, label, credential_id, transports_json, prf_capable,
                    webauthn_relying_party_id, backup_eligible, backup_state, created_at,
                    last_used_at, revoked_at
             FROM passkey_credentials
             WHERE project_id = ?1 AND revoked_at IS NULL
             ORDER BY created_at, id"
        };
        let mut statement = self.connection.prepare(sql)?;
        let credentials = statement
            .query_map([project_id], passkey_credential_from_row)?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(credentials)
    }

    /// Finds passkey credential metadata by label, id, or lowercase/uppercase credential-id hex prefix.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` cannot query rows.
    pub fn find_passkey_credentials(
        &self,
        project_id: &str,
        selector: &str,
    ) -> Result<Vec<PasskeyCredentialRecord>, StoreError> {
        let selector = selector.trim();
        let credential_hex_prefix = selector.strip_prefix("0x").unwrap_or(selector).to_uppercase();
        let mut statement = self.connection.prepare(
            "SELECT id, project_id, label, credential_id, transports_json, prf_capable,
                    webauthn_relying_party_id, backup_eligible, backup_state, created_at,
                    last_used_at, revoked_at
             FROM passkey_credentials
             WHERE project_id = ?1
               AND (label = ?2 OR id = ?2 OR hex(credential_id) LIKE (?3 || '%'))
             ORDER BY revoked_at IS NULL DESC, created_at DESC, id",
        )?;
        let credentials = statement
            .query_map(
                params![project_id, selector, credential_hex_prefix],
                passkey_credential_from_row,
            )?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(credentials)
    }

    /// Marks a passkey credential revoked.
    ///
    /// Returns `true` when a row changed.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` rejects the update.
    pub fn revoke_passkey_credential(
        &self,
        project_id: &str,
        credential_id: &str,
        revoked_at: i64,
    ) -> Result<bool, StoreError> {
        self.connection.execute(
            "UPDATE passkey_credentials
             SET revoked_at = ?3
             WHERE project_id = ?1 AND id = ?2 AND revoked_at IS NULL",
            params![project_id, credential_id, revoked_at],
        )?;

        Ok(self.connection.changes() == 1)
    }
}
