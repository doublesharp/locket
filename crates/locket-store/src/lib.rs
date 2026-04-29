//! `SQLite` storage layer for Locket.

use std::path::Path;
use std::str::FromStr;

use locket_core::{Duration as LocketDuration, canonical_json_string};
use rusqlite::types::Type;
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Value, json};
use thiserror::Error;

mod audit;
mod error;
mod grants;
mod profile;
mod project;
mod roots;
mod row;
mod schema;

pub use audit::{AuditContext, AuditLogRecord, AuditWrite};
pub use error::StoreError;
pub use grants::DirectoryGrantRecord;
pub use profile::ProfileRecord;
pub use project::ProjectRecord;
pub use roots::ProjectRootRecord;
pub use schema::SCHEMA_VERSION;

use audit::append_optional_audit;
use row::nonce_from_row;

/// SQLite-backed Locket store.
#[derive(Debug)]
pub struct Store {
    connection: Connection,
}

/// Wrapped project/profile key material.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyRecord {
    /// Key identifier.
    pub id: String,
    /// Parent project identifier.
    pub project_id: String,
    /// Optional parent profile identifier for profile-scoped keys.
    pub profile_id: Option<String>,
    /// Persisted key purpose string.
    pub purpose: String,
    /// Encrypted key material.
    pub wrapped_material: Vec<u8>,
    /// Nonce used to wrap the key material.
    pub nonce: [u8; 24],
    /// Creation timestamp in nanoseconds since the Unix epoch.
    pub created_at: i64,
}

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

/// Secret metadata row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecretRecord {
    /// Secret identifier.
    pub id: String,
    /// Parent project identifier.
    pub project_id: String,
    /// Parent profile identifier.
    pub profile_id: String,
    /// Secret name.
    pub name: String,
    /// Persisted secret source string.
    pub source: String,
    /// Persisted secret origin string.
    pub origin: String,
    /// Current secret version.
    pub current_version: u32,
    /// Persisted secret state string.
    pub state: String,
    /// Creation timestamp in nanoseconds since the Unix epoch.
    pub created_at: i64,
    /// Last metadata update timestamp in nanoseconds since the Unix epoch.
    pub updated_at: i64,
    /// Last rotation timestamp in nanoseconds since the Unix epoch.
    pub last_rotated_at: Option<i64>,
    /// Tombstone timestamp in nanoseconds since the Unix epoch.
    pub deleted_at: Option<i64>,
}

/// Secret version metadata row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecretVersionRecord {
    /// Parent secret identifier.
    pub secret_id: String,
    /// Version number.
    pub version: u32,
    /// Persisted secret source string.
    pub source: String,
    /// Persisted secret origin string.
    pub origin: String,
    /// Persisted version state string.
    pub state: String,
    /// Creation timestamp in nanoseconds since the Unix epoch.
    pub created_at: i64,
    /// Deprecation timestamp in nanoseconds since the Unix epoch.
    pub deprecated_at: Option<i64>,
    /// Grace-window expiration timestamp in nanoseconds since the Unix epoch.
    pub grace_until: Option<i64>,
    /// Purge timestamp in nanoseconds since the Unix epoch.
    pub purged_at: Option<i64>,
}

/// Encrypted secret value row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecretBlobRecord {
    /// Parent secret identifier.
    pub secret_id: String,
    /// Version number.
    pub version: u32,
    /// Encrypted data-encryption key bytes.
    pub encrypted_dek: Vec<u8>,
    /// Encrypted secret value bytes.
    pub ciphertext: Vec<u8>,
    /// Nonce used for the value ciphertext.
    pub value_nonce: [u8; 24],
    /// AAD schema version.
    pub aad_schema_version: u16,
    /// Creation timestamp in nanoseconds since the Unix epoch.
    pub created_at: i64,
}

/// Keyed secret fingerprint row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecretFingerprintRecord {
    /// Parent secret identifier.
    pub secret_id: String,
    /// Version number.
    pub version: u32,
    /// Keyed fingerprint bytes.
    pub fingerprint: Vec<u8>,
    /// Creation timestamp in nanoseconds since the Unix epoch.
    pub created_at: i64,
}

/// Metadata-only runtime process/session row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeSessionRecord {
    /// Runtime session identifier.
    pub id: String,
    /// Parent project identifier.
    pub project_id: String,
    /// Parent profile identifier.
    pub profile_id: String,
    /// Optional policy name used to authorize the session.
    pub policy_name: Option<String>,
    /// Runtime process id.
    pub process_id: u32,
    /// Process start timestamp in nanoseconds since the Unix epoch.
    pub process_start_time: i64,
    /// Session start timestamp in nanoseconds since the Unix epoch.
    pub started_at: i64,
    /// Session end timestamp in nanoseconds since the Unix epoch.
    pub ended_at: Option<i64>,
    /// Process exit status when known.
    pub exit_status: Option<i32>,
    /// Sensitive metadata names only; never secret values.
    pub secret_names: Vec<String>,
    /// Optional project-scoped audit sequence for the spawn event.
    pub spawn_audit_sequence: Option<u64>,
    /// Optional project-scoped audit sequence for the completion event.
    pub completion_audit_sequence: Option<u64>,
}

/// Public metadata for a registered automation client.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AutomationClientRecord {
    /// Automation-client identifier.
    pub id: String,
    /// Parent project identifier.
    pub project_id: String,
    /// Human-readable client name.
    pub name: String,
    /// Ed25519 public key bytes.
    pub public_key: Vec<u8>,
    /// Stable public-key fingerprint.
    pub fingerprint: String,
    /// Persisted private-key storage mode metadata.
    pub storage: String,
    /// Allowed agent action strings.
    pub allowed_actions: Vec<String>,
    /// Allowed command-policy names.
    pub allowed_policies: Vec<String>,
    /// Creation timestamp in nanoseconds since the Unix epoch.
    pub created_at: i64,
    /// Last successful use timestamp in nanoseconds since the Unix epoch.
    pub last_used_at: Option<i64>,
    /// Revocation timestamp in nanoseconds since the Unix epoch.
    pub revoked_at: Option<i64>,
}

/// Recently seen automation-client challenge nonce.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AutomationClientNonceRecord {
    /// Parent automation-client identifier.
    pub client_id: String,
    /// Agent-issued challenge nonce.
    pub nonce: [u8; 24],
    /// Request timestamp in nanoseconds since the Unix epoch.
    pub request_timestamp: i64,
    /// Timestamp when the nonce was observed.
    pub seen_at: i64,
    /// Timestamp after which the nonce can be pruned.
    pub expires_at: i64,
}

/// Retention behavior for `runtime_sessions.secret_names`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RuntimeSessionSecretNameRetention {
    /// Store secret names on new runtime-session rows and prune them after this duration.
    RetainFor(LocketDuration),
    /// Do not store secret names on new runtime-session rows.
    Off,
}

impl RuntimeSessionSecretNameRetention {
    /// Default `runtime.session_secret_name_retention` value in seconds.
    pub const DEFAULT_SECONDS: u64 = 90 * 24 * 60 * 60;

    /// Returns the default 90-day retention behavior.
    #[must_use]
    pub const fn default_retention() -> Self {
        Self::RetainFor(LocketDuration::from_secs(Self::DEFAULT_SECONDS))
    }

    /// Filters the candidate names according to this retention mode.
    #[must_use]
    pub fn secret_names_for_storage(&self, secret_names: &[String]) -> Vec<String> {
        match self {
            Self::RetainFor(_) => secret_names.to_vec(),
            Self::Off => Vec::new(),
        }
    }
}

impl Default for RuntimeSessionSecretNameRetention {
    fn default() -> Self {
        Self::default_retention()
    }
}

impl FromStr for RuntimeSessionSecretNameRetention {
    type Err = InvalidRuntimeSessionSecretNameRetention;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value == "off" {
            return Ok(Self::Off);
        }

        Ok(Self::RetainFor(
            LocketDuration::from_str(value)
                .map_err(|_| InvalidRuntimeSessionSecretNameRetention)?,
        ))
    }
}

/// Invalid `runtime.session_secret_name_retention` value.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("runtime.session_secret_name_retention must be a duration or off")]
pub struct InvalidRuntimeSessionSecretNameRetention;

/// Metadata applied to the version being superseded by rotation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VersionDeprecation {
    /// Deprecation timestamp in nanoseconds since the Unix epoch.
    pub deprecated_at: i64,
    /// Optional grace-window expiration timestamp.
    pub grace_until: Option<i64>,
}

/// Target lifecycle operation for a profile copy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecretCopyTarget<'a> {
    /// Create a new target secret row at version 1.
    Create(&'a SecretRecord),
    /// Rotate an existing active target secret.
    Rotate {
        /// Existing active target secret.
        secret: &'a SecretRecord,
        /// Metadata to apply to the superseded target version.
        deprecation: VersionDeprecation,
    },
}

/// Mutable secret metadata update plus optional timestamp/audit context.
#[derive(Clone, Copy, Debug, Default)]
pub struct SecretMetadataUpdate<'a> {
    /// Optional description replacement.
    pub description: Option<&'a str>,
    /// Optional owner replacement.
    pub owner: Option<&'a str>,
    /// Optional full tag-list replacement.
    pub tags: Option<&'a [String]>,
    /// Optional required flag replacement.
    pub required: Option<bool>,
    /// Optional `updated_at` replacement.
    pub updated_at: Option<i64>,
    /// Optional audit row appended in the same transaction when the update matches.
    pub audit: Option<AuditContext<'a>>,
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

    /// Inserts a runtime-session row at process spawn time.
    ///
    /// `secret_names` are stored as names only for troubleshooting correlation. Callers
    /// should pass names filtered through [`RuntimeSessionSecretNameRetention`] when the
    /// configured retention mode is `off`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` rejects the insert.
    pub fn insert_runtime_session(&self, session: &RuntimeSessionRecord) -> Result<(), StoreError> {
        let secret_names_json = json!(&session.secret_names).to_string();
        self.connection.execute(
            "INSERT INTO runtime_sessions(
               id, project_id, profile_id, policy_name, process_id, process_start_time,
               started_at, ended_at, exit_status, secret_names_json,
               spawn_audit_sequence, completion_audit_sequence
             )
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                session.id.as_str(),
                session.project_id.as_str(),
                session.profile_id.as_str(),
                session.policy_name.as_deref(),
                session.process_id,
                session.process_start_time,
                session.started_at,
                session.ended_at,
                session.exit_status,
                secret_names_json,
                session.spawn_audit_sequence,
                session.completion_audit_sequence,
            ],
        )?;
        Ok(())
    }

    /// Marks a runtime session completed when the process exits.
    ///
    /// Returns `true` when an incomplete session was updated and `false` when the row
    /// was missing or already completed.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` rejects the update.
    pub fn mark_runtime_session_completed(
        &self,
        id: &str,
        ended_at: i64,
        exit_status: Option<i32>,
        completion_audit_sequence: Option<u64>,
    ) -> Result<bool, StoreError> {
        let updated = self.connection.execute(
            "UPDATE runtime_sessions
             SET ended_at = ?2,
                 exit_status = ?3,
                 completion_audit_sequence = ?4
             WHERE id = ?1 AND ended_at IS NULL",
            params![id, ended_at, exit_status, completion_audit_sequence],
        )?;
        Ok(updated > 0)
    }

    /// Lists runtime sessions that do not have completion metadata.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` cannot query the rows.
    pub fn list_incomplete_runtime_sessions(
        &self,
        project_id: &str,
    ) -> Result<Vec<RuntimeSessionRecord>, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT id, project_id, profile_id, policy_name, process_id, process_start_time,
                    started_at, ended_at, exit_status, secret_names_json,
                    spawn_audit_sequence, completion_audit_sequence
             FROM runtime_sessions
             WHERE project_id = ?1 AND ended_at IS NULL
             ORDER BY started_at, id",
        )?;
        statement
            .query_map([project_id], runtime_session_from_row)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::from)
    }

    /// Lists runtime sessions whose retained `secret_names` have passed the cutoff.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` cannot query the rows.
    pub fn list_runtime_sessions_with_expired_secret_names(
        &self,
        project_id: &str,
        started_before_or_at: i64,
    ) -> Result<Vec<RuntimeSessionRecord>, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT id, project_id, profile_id, policy_name, process_id, process_start_time,
                    started_at, ended_at, exit_status, secret_names_json,
                    spawn_audit_sequence, completion_audit_sequence
             FROM runtime_sessions
             WHERE project_id = ?1
               AND started_at <= ?2
               AND secret_names_json != '[]'
             ORDER BY started_at, id",
        )?;
        statement
            .query_map(params![project_id, started_before_or_at], runtime_session_from_row)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::from)
    }

    /// Prunes only the sensitive `secret_names` metadata for sessions at or before a cutoff.
    ///
    /// Session timing, process identity, policy name, exit status, and audit sequence
    /// linkage are preserved.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` rejects the update.
    pub fn prune_runtime_session_secret_names(
        &self,
        project_id: &str,
        started_before_or_at: i64,
    ) -> Result<usize, StoreError> {
        self.connection
            .execute(
                "UPDATE runtime_sessions
                 SET secret_names_json = '[]'
                 WHERE project_id = ?1
                   AND started_at <= ?2
                   AND secret_names_json != '[]'",
                params![project_id, started_before_or_at],
            )
            .map_err(StoreError::from)
    }

    /// Registers or refreshes public automation-client metadata.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` rejects the row.
    pub fn insert_automation_client(
        &self,
        client: &AutomationClientRecord,
    ) -> Result<(), StoreError> {
        let allowed_actions_json = json!(&client.allowed_actions).to_string();
        let allowed_policies_json = json!(&client.allowed_policies).to_string();
        self.connection.execute(
            "INSERT INTO automation_clients(
               id, project_id, name, public_key, fingerprint, storage,
               allowed_actions_json, allowed_policies_json, created_at, last_used_at, revoked_at
             )
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                client.id.as_str(),
                client.project_id.as_str(),
                client.name.as_str(),
                client.public_key.as_slice(),
                client.fingerprint.as_str(),
                client.storage.as_str(),
                allowed_actions_json,
                allowed_policies_json,
                client.created_at,
                client.last_used_at,
                client.revoked_at,
            ],
        )?;
        Ok(())
    }

    /// Lists automation-client metadata for a project.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when rows cannot be queried or parsed.
    pub fn list_automation_clients(
        &self,
        project_id: &str,
        include_revoked: bool,
    ) -> Result<Vec<AutomationClientRecord>, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT id, project_id, name, public_key, fingerprint, storage,
                    allowed_actions_json, allowed_policies_json, created_at, last_used_at, revoked_at
             FROM automation_clients
             WHERE project_id = ?1 AND (?2 OR revoked_at IS NULL)
             ORDER BY name, created_at, id",
        )?;
        statement
            .query_map(params![project_id, include_revoked], automation_client_from_row)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::from)
    }

    /// Returns one automation client by id or project-scoped name.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when the row cannot be queried or parsed.
    pub fn get_automation_client(
        &self,
        project_id: &str,
        client: &str,
    ) -> Result<Option<AutomationClientRecord>, StoreError> {
        self.connection
            .query_row(
                "SELECT id, project_id, name, public_key, fingerprint, storage,
                        allowed_actions_json, allowed_policies_json, created_at, last_used_at, revoked_at
                 FROM automation_clients
                 WHERE project_id = ?1 AND (id = ?2 OR name = ?2)
                 ORDER BY CASE WHEN id = ?2 THEN 0 ELSE 1 END, created_at
                 LIMIT 1",
                params![project_id, client],
                automation_client_from_row,
            )
            .optional()
            .map_err(StoreError::from)
    }

    /// Revokes an automation client by id.
    ///
    /// Returns `true` when an active client was revoked.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` rejects the update.
    pub fn revoke_automation_client(
        &self,
        project_id: &str,
        client_id: &str,
        revoked_at: i64,
    ) -> Result<bool, StoreError> {
        self.connection.execute(
            "UPDATE automation_clients
             SET revoked_at = ?3
             WHERE project_id = ?1 AND id = ?2 AND revoked_at IS NULL",
            params![project_id, client_id, revoked_at],
        )?;
        Ok(self.connection.changes() == 1)
    }

    /// Records an automation-client challenge nonce.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` rejects the nonce.
    pub fn insert_automation_client_nonce(
        &self,
        nonce: &AutomationClientNonceRecord,
    ) -> Result<(), StoreError> {
        self.connection.execute(
            "INSERT INTO automation_client_nonces(
               client_id, nonce, request_timestamp, seen_at, expires_at
             )
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                nonce.client_id.as_str(),
                nonce.nonce.as_slice(),
                nonce.request_timestamp,
                nonce.seen_at,
                nonce.expires_at,
            ],
        )?;
        Ok(())
    }

    /// Prunes expired automation-client nonces.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` rejects the delete.
    pub fn prune_automation_client_nonces(&self, now: i64) -> Result<usize, StoreError> {
        self.connection
            .execute("DELETE FROM automation_client_nonces WHERE expires_at <= ?1", [now])
            .map_err(StoreError::from)
    }

    /// Inserts wrapped key material.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` rejects the insert, including
    /// uniqueness, foreign-key, and key-scope constraint failures.
    pub fn insert_key(&self, key: &KeyRecord) -> Result<(), StoreError> {
        self.connection.execute(
            "INSERT INTO keys(id, project_id, profile_id, purpose, wrapped_material, nonce, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                key.id.as_str(),
                key.project_id.as_str(),
                key.profile_id.as_deref(),
                key.purpose.as_str(),
                key.wrapped_material.as_slice(),
                key.nonce.as_slice(),
                key.created_at,
            ],
        )?;

        Ok(())
    }

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
               backup_eligible, backup_state, created_at, last_used_at, revoked_at
             )
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                credential.id.as_str(),
                credential.project_id.as_str(),
                credential.label.as_str(),
                credential.credential_id.as_slice(),
                transports_json.as_str(),
                credential.prf_capable,
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
                    backup_eligible, backup_state, created_at, last_used_at, revoked_at
             FROM passkey_credentials
             WHERE project_id = ?1
             ORDER BY created_at, id"
        } else {
            "SELECT id, project_id, label, credential_id, transports_json, prf_capable,
                    backup_eligible, backup_state, created_at, last_used_at, revoked_at
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
                    backup_eligible, backup_state, created_at, last_used_at, revoked_at
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

    /// Returns wrapped key material by id.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` cannot query the key row.
    pub fn get_key(&self, id: &str) -> Result<Option<KeyRecord>, StoreError> {
        self.connection
            .query_row(
                "SELECT id, project_id, profile_id, purpose, wrapped_material, nonce, created_at
                 FROM keys
                 WHERE id = ?1",
                [id],
                key_record_from_row,
            )
            .optional()
            .map_err(StoreError::from)
    }

    /// Returns wrapped key material by project/profile scope and purpose.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` cannot query the key row.
    pub fn get_key_by_scope(
        &self,
        project_id: &str,
        profile_id: Option<&str>,
        purpose: &str,
    ) -> Result<Option<KeyRecord>, StoreError> {
        self.connection
            .query_row(
                "SELECT id, project_id, profile_id, purpose, wrapped_material, nonce, created_at
                 FROM keys
                 WHERE project_id = ?1 AND profile_id IS ?2 AND purpose = ?3",
                params![project_id, profile_id, purpose],
                key_record_from_row,
            )
            .optional()
            .map_err(StoreError::from)
    }

    /// Creates a secret, its initial version, encrypted blob, and keyed fingerprint atomically.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` rejects any insert. The
    /// transaction is rolled back when any row fails to insert.
    pub fn create_active_secret(
        &mut self,
        secret: &SecretRecord,
        version: &SecretVersionRecord,
        blob: &SecretBlobRecord,
        fingerprint: &SecretFingerprintRecord,
    ) -> Result<(), StoreError> {
        self.create_active_secret_with_audit(secret, version, blob, fingerprint, None)
    }

    /// Creates a secret and optionally appends the matching audit row in the same transaction.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when `SQLite` rejects a row or audit canonicalization fails.
    pub fn create_active_secret_with_audit(
        &mut self,
        secret: &SecretRecord,
        version: &SecretVersionRecord,
        blob: &SecretBlobRecord,
        fingerprint: &SecretFingerprintRecord,
        audit: Option<AuditContext<'_>>,
    ) -> Result<(), StoreError> {
        let transaction = self.connection.transaction()?;
        transaction.execute(
            "INSERT INTO secrets(
               id, project_id, profile_id, name, source, origin, required,
               current_version, state, created_at, updated_at, last_rotated_at, deleted_at
             )
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                secret.id.as_str(),
                secret.project_id.as_str(),
                secret.profile_id.as_str(),
                secret.name.as_str(),
                secret.source.as_str(),
                secret.origin.as_str(),
                secret.current_version,
                secret.state.as_str(),
                secret.created_at,
                secret.updated_at,
                secret.last_rotated_at,
                secret.deleted_at,
            ],
        )?;
        transaction.execute(
            "INSERT INTO secret_versions(
               secret_id, version, source, origin, state, created_at,
               deprecated_at, grace_until, purged_at
             )
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                version.secret_id.as_str(),
                version.version,
                version.source.as_str(),
                version.origin.as_str(),
                version.state.as_str(),
                version.created_at,
                version.deprecated_at,
                version.grace_until,
                version.purged_at,
            ],
        )?;
        transaction.execute(
            "INSERT INTO blobs(
               secret_id, version, encrypted_dek, ciphertext, value_nonce,
               aad_schema_version, created_at
             )
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                blob.secret_id.as_str(),
                blob.version,
                blob.encrypted_dek.as_slice(),
                blob.ciphertext.as_slice(),
                blob.value_nonce.as_slice(),
                blob.aad_schema_version,
                blob.created_at,
            ],
        )?;
        transaction.execute(
            "INSERT INTO fingerprints(secret_id, version, fingerprint, created_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                fingerprint.secret_id.as_str(),
                fingerprint.version,
                fingerprint.fingerprint.as_slice(),
                fingerprint.created_at,
            ],
        )?;
        append_optional_audit(&transaction, audit)?;
        transaction.commit()?;

        Ok(())
    }

    /// Returns an active secret by project/profile/name/source.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` cannot query the secret row.
    pub fn get_active_secret(
        &self,
        project_id: &str,
        profile_id: &str,
        name: &str,
        source: &str,
    ) -> Result<Option<SecretRecord>, StoreError> {
        self.connection
            .query_row(
                "SELECT id, project_id, profile_id, name, source, origin, current_version, state,
                        created_at, updated_at, last_rotated_at, deleted_at
                 FROM secrets
                 WHERE project_id = ?1
                   AND profile_id = ?2
                   AND name = ?3
                   AND source = ?4
                   AND state = 'active'",
                (project_id, profile_id, name, source),
                secret_record_from_row,
            )
            .optional()
            .map_err(StoreError::from)
    }

    /// Returns a secret by project/profile/name/source regardless of active or deleted state.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` cannot query the secret row.
    pub fn get_secret_by_source(
        &self,
        project_id: &str,
        profile_id: &str,
        name: &str,
        source: &str,
    ) -> Result<Option<SecretRecord>, StoreError> {
        self.connection
            .query_row(
                "SELECT id, project_id, profile_id, name, source, origin, current_version, state,
                        created_at, updated_at, last_rotated_at, deleted_at
                 FROM secrets
                 WHERE project_id = ?1
                   AND profile_id = ?2
                   AND name = ?3
                   AND source = ?4",
                (project_id, profile_id, name, source),
                secret_record_from_row,
            )
            .optional()
            .map_err(StoreError::from)
    }

    /// Lists secrets for a project/profile/name across all sources and states.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` cannot query secret rows.
    pub fn list_secrets_by_name(
        &self,
        project_id: &str,
        profile_id: &str,
        name: &str,
    ) -> Result<Vec<SecretRecord>, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT id, project_id, profile_id, name, source, origin, current_version, state,
                    created_at, updated_at, last_rotated_at, deleted_at
             FROM secrets
             WHERE project_id = ?1 AND profile_id = ?2 AND name = ?3
             ORDER BY name, source",
        )?;
        let secrets = statement
            .query_map((project_id, profile_id, name), secret_record_from_row)?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(secrets)
    }

    /// Lists active secrets for a profile ordered by name and source.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` cannot query secret rows.
    pub fn list_active_secrets_by_profile(
        &self,
        project_id: &str,
        profile_id: &str,
    ) -> Result<Vec<SecretRecord>, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT id, project_id, profile_id, name, source, origin, current_version, state,
                    created_at, updated_at, last_rotated_at, deleted_at
             FROM secrets
             WHERE project_id = ?1 AND profile_id = ?2 AND state = 'active'
             ORDER BY name, source",
        )?;
        let secrets = statement
            .query_map((project_id, profile_id), secret_record_from_row)?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(secrets)
    }

    /// Lists all secrets for a profile ordered by name and source.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` cannot query secret rows.
    pub fn list_secrets_by_profile(
        &self,
        project_id: &str,
        profile_id: &str,
    ) -> Result<Vec<SecretRecord>, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT id, project_id, profile_id, name, source, origin, current_version, state,
                    created_at, updated_at, last_rotated_at, deleted_at
             FROM secrets
             WHERE project_id = ?1 AND profile_id = ?2
             ORDER BY name, source",
        )?;
        let secrets = statement
            .query_map((project_id, profile_id), secret_record_from_row)?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(secrets)
    }

    /// Lists version metadata for a secret ordered by version.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` cannot query version rows.
    pub fn list_secret_versions(
        &self,
        secret_id: &str,
    ) -> Result<Vec<SecretVersionRecord>, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT secret_id, version, source, origin, state, created_at,
                    deprecated_at, grace_until, purged_at
             FROM secret_versions
             WHERE secret_id = ?1
             ORDER BY version",
        )?;
        let versions = statement
            .query_map([secret_id], secret_version_record_from_row)?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(versions)
    }

    /// Returns version metadata for a secret version.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` cannot query the version row.
    pub fn get_secret_version(
        &self,
        secret_id: &str,
        version: u32,
    ) -> Result<Option<SecretVersionRecord>, StoreError> {
        self.connection
            .query_row(
                "SELECT secret_id, version, source, origin, state, created_at,
                        deprecated_at, grace_until, purged_at
                 FROM secret_versions
                 WHERE secret_id = ?1 AND version = ?2",
                params![secret_id, version],
                secret_version_record_from_row,
            )
            .optional()
            .map_err(StoreError::from)
    }

    /// Updates mutable metadata fields on an active secret without changing secret material.
    ///
    /// `None` keeps the existing field. `tags` replaces the whole tag list when
    /// present.
    ///
    /// Returns `true` when an active secret row was updated and `false` when no
    /// matching active secret exists.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` rejects the update.
    pub fn update_secret_metadata(
        &self,
        secret_id: &str,
        description: Option<&str>,
        owner: Option<&str>,
        tags: Option<&[String]>,
        required: Option<bool>,
    ) -> Result<bool, StoreError> {
        self.update_secret_metadata_with_options(
            secret_id,
            SecretMetadataUpdate {
                description,
                owner,
                tags,
                required,
                updated_at: None,
                audit: None,
            },
        )
    }

    /// Updates mutable secret metadata and optionally records a metadata-only audit row atomically.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when `SQLite` rejects the update or audit canonicalization fails.
    pub fn update_secret_metadata_with_options(
        &self,
        secret_id: &str,
        update: SecretMetadataUpdate<'_>,
    ) -> Result<bool, StoreError> {
        let tags_json = update.tags.map(|tags| {
            let tags = tags.iter().map(|tag| Value::String(tag.clone())).collect::<Vec<_>>();
            canonical_json_string(Some(&Value::Array(tags)))
        });
        let transaction = self.connection.unchecked_transaction()?;
        transaction.execute(
            "UPDATE secrets
             SET description = COALESCE(?2, description),
                 owner = COALESCE(?3, owner),
                 tags_json = COALESCE(?4, tags_json),
                 required = COALESCE(?5, required),
                 updated_at = COALESCE(?6, updated_at)
             WHERE id = ?1 AND state = 'active'",
            params![
                secret_id,
                update.description,
                update.owner,
                tags_json.as_deref(),
                update.required,
                update.updated_at,
            ],
        )?;
        let changed = transaction.changes() == 1;
        if changed {
            append_optional_audit(&transaction, update.audit)?;
        }
        transaction.commit()?;

        Ok(changed)
    }

    /// Rotates a secret by deprecating the current version and inserting the new current version.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` rejects any update or insert.
    /// The transaction is rolled back when any row fails.
    pub fn rotate_secret(
        &mut self,
        secret: &SecretRecord,
        new_version: &SecretVersionRecord,
        blob: &SecretBlobRecord,
        fingerprint: &SecretFingerprintRecord,
        deprecated_at: i64,
        grace_until: Option<i64>,
    ) -> Result<(), StoreError> {
        self.rotate_secret_with_audit(
            secret,
            new_version,
            blob,
            fingerprint,
            VersionDeprecation { deprecated_at, grace_until },
            None,
        )
    }

    /// Rotates a secret and optionally appends the matching audit row in the same transaction.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when `SQLite` rejects a row or audit canonicalization fails.
    pub fn rotate_secret_with_audit(
        &mut self,
        secret: &SecretRecord,
        new_version: &SecretVersionRecord,
        blob: &SecretBlobRecord,
        fingerprint: &SecretFingerprintRecord,
        deprecation: VersionDeprecation,
        audit: Option<AuditContext<'_>>,
    ) -> Result<(), StoreError> {
        let transaction = self.connection.transaction()?;
        transaction.execute(
            "UPDATE secret_versions
             SET state = 'deprecated', deprecated_at = ?3, grace_until = ?4
             WHERE secret_id = ?1 AND version = ?2 AND state = 'current'",
            params![
                secret.id.as_str(),
                secret.current_version,
                deprecation.deprecated_at,
                deprecation.grace_until,
            ],
        )?;
        transaction.execute(
            "INSERT INTO secret_versions(
               secret_id, version, source, origin, state, created_at,
               deprecated_at, grace_until, purged_at
             )
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                new_version.secret_id.as_str(),
                new_version.version,
                new_version.source.as_str(),
                new_version.origin.as_str(),
                new_version.state.as_str(),
                new_version.created_at,
                new_version.deprecated_at,
                new_version.grace_until,
                new_version.purged_at,
            ],
        )?;
        transaction.execute(
            "INSERT INTO blobs(
               secret_id, version, encrypted_dek, ciphertext, value_nonce,
               aad_schema_version, created_at
             )
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                blob.secret_id.as_str(),
                blob.version,
                blob.encrypted_dek.as_slice(),
                blob.ciphertext.as_slice(),
                blob.value_nonce.as_slice(),
                blob.aad_schema_version,
                blob.created_at,
            ],
        )?;
        transaction.execute(
            "INSERT INTO fingerprints(secret_id, version, fingerprint, created_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                fingerprint.secret_id.as_str(),
                fingerprint.version,
                fingerprint.fingerprint.as_slice(),
                fingerprint.created_at,
            ],
        )?;
        transaction.execute(
            "UPDATE secrets
             SET current_version = ?2, updated_at = ?3, last_rotated_at = ?3
             WHERE id = ?1 AND state = 'active'",
            params![secret.id.as_str(), new_version.version, new_version.created_at],
        )?;
        append_optional_audit(&transaction, audit)?;
        transaction.commit()?;

        Ok(())
    }

    /// Copies secret material into a target source by creating or rotating it.
    ///
    /// The copied plaintext is supplied only as already-encrypted target material. The secret
    /// lifecycle update and optional `SECRET_COPY` audit append happen in one transaction.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when `SQLite` rejects a row or audit canonicalization fails.
    pub fn copy_secret_with_audit(
        &mut self,
        target: SecretCopyTarget<'_>,
        new_version: &SecretVersionRecord,
        blob: &SecretBlobRecord,
        fingerprint: &SecretFingerprintRecord,
        audit: Option<AuditContext<'_>>,
    ) -> Result<(), StoreError> {
        let transaction = self.connection.transaction()?;
        match target {
            SecretCopyTarget::Create(secret) => {
                transaction.execute(
                    "INSERT INTO secrets(
                       id, project_id, profile_id, name, source, origin, required,
                       current_version, state, created_at, updated_at, last_rotated_at, deleted_at
                     )
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, ?7, ?8, ?9, ?10, ?11, ?12)",
                    params![
                        secret.id.as_str(),
                        secret.project_id.as_str(),
                        secret.profile_id.as_str(),
                        secret.name.as_str(),
                        secret.source.as_str(),
                        secret.origin.as_str(),
                        secret.current_version,
                        secret.state.as_str(),
                        secret.created_at,
                        secret.updated_at,
                        secret.last_rotated_at,
                        secret.deleted_at,
                    ],
                )?;
            }
            SecretCopyTarget::Rotate { secret, deprecation } => {
                transaction.execute(
                    "UPDATE secret_versions
                     SET state = 'deprecated', deprecated_at = ?3, grace_until = ?4
                     WHERE secret_id = ?1 AND version = ?2 AND state = 'current'",
                    params![
                        secret.id.as_str(),
                        secret.current_version,
                        deprecation.deprecated_at,
                        deprecation.grace_until,
                    ],
                )?;
            }
        }
        transaction.execute(
            "INSERT INTO secret_versions(
               secret_id, version, source, origin, state, created_at,
               deprecated_at, grace_until, purged_at
             )
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                new_version.secret_id.as_str(),
                new_version.version,
                new_version.source.as_str(),
                new_version.origin.as_str(),
                new_version.state.as_str(),
                new_version.created_at,
                new_version.deprecated_at,
                new_version.grace_until,
                new_version.purged_at,
            ],
        )?;
        transaction.execute(
            "INSERT INTO blobs(
               secret_id, version, encrypted_dek, ciphertext, value_nonce,
               aad_schema_version, created_at
             )
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                blob.secret_id.as_str(),
                blob.version,
                blob.encrypted_dek.as_slice(),
                blob.ciphertext.as_slice(),
                blob.value_nonce.as_slice(),
                blob.aad_schema_version,
                blob.created_at,
            ],
        )?;
        transaction.execute(
            "INSERT INTO fingerprints(secret_id, version, fingerprint, created_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                fingerprint.secret_id.as_str(),
                fingerprint.version,
                fingerprint.fingerprint.as_slice(),
                fingerprint.created_at,
            ],
        )?;
        if let SecretCopyTarget::Rotate { secret, .. } = target {
            transaction.execute(
                "UPDATE secrets
                 SET current_version = ?2, updated_at = ?3, last_rotated_at = ?3
                 WHERE id = ?1 AND state = 'active'",
                params![secret.id.as_str(), new_version.version, new_version.created_at],
            )?;
        }
        append_optional_audit(&transaction, audit)?;
        transaction.commit()?;

        Ok(())
    }

    /// Purges encrypted material and fingerprints for one version.
    ///
    /// Returns `true` when material was newly purged and `false` when the
    /// version was already purged.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` rejects the updates.
    pub fn purge_secret_version(
        &mut self,
        secret_id: &str,
        version: u32,
        purged_at: i64,
    ) -> Result<bool, StoreError> {
        self.purge_secret_versions(secret_id, &[version], purged_at)
    }

    /// Purges encrypted material and fingerprints for multiple versions atomically.
    ///
    /// Returns `true` when at least one version was newly purged and `false`
    /// when all selected versions were already purged.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` rejects the updates.
    pub fn purge_secret_versions(
        &mut self,
        secret_id: &str,
        versions: &[u32],
        purged_at: i64,
    ) -> Result<bool, StoreError> {
        self.purge_secret_versions_with_audit(secret_id, versions, purged_at, None)
    }

    /// Purges versions and optionally appends a `PURGE` audit row when material changed.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when `SQLite` rejects a row or audit canonicalization fails.
    pub fn purge_secret_versions_with_audit(
        &mut self,
        secret_id: &str,
        versions: &[u32],
        purged_at: i64,
        audit: Option<AuditContext<'_>>,
    ) -> Result<bool, StoreError> {
        let transaction = self.connection.transaction()?;
        let mut changed_any = false;
        for version in versions {
            let changed = transaction.execute(
                "UPDATE secret_versions
                 SET state = 'purged', grace_until = NULL, purged_at = ?3
                 WHERE secret_id = ?1 AND version = ?2 AND state != 'purged'",
                params![secret_id, version, purged_at],
            )?;
            if changed == 0 {
                continue;
            }
            changed_any = true;
            transaction.execute(
                "DELETE FROM blobs WHERE secret_id = ?1 AND version = ?2",
                params![secret_id, version],
            )?;
            transaction.execute(
                "DELETE FROM fingerprints WHERE secret_id = ?1 AND version = ?2",
                params![secret_id, version],
            )?;
        }
        if !changed_any {
            transaction.commit()?;
            return Ok(false);
        }
        append_optional_audit(&transaction, audit)?;
        transaction.commit()?;

        Ok(true)
    }

    /// Tombstones a secret by id.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` rejects the update.
    pub fn tombstone_secret(&self, id: &str, deleted_at: i64) -> Result<(), StoreError> {
        self.tombstone_secret_with_audit(id, deleted_at, None)
    }

    /// Tombstones a secret and optionally appends the matching audit row in the same transaction.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when `SQLite` rejects a row or audit canonicalization fails.
    pub fn tombstone_secret_with_audit(
        &self,
        id: &str,
        deleted_at: i64,
        audit: Option<AuditContext<'_>>,
    ) -> Result<(), StoreError> {
        let transaction = self.connection.unchecked_transaction()?;
        transaction.execute(
            "UPDATE secrets
             SET state = 'deleted', deleted_at = ?2, updated_at = ?2
             WHERE id = ?1",
            (id, deleted_at),
        )?;
        append_optional_audit(&transaction, audit)?;
        transaction.commit()?;

        Ok(())
    }

    /// Returns an encrypted blob by secret id and version.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` cannot query the blob row.
    pub fn get_blob(
        &self,
        secret_id: &str,
        version: u32,
    ) -> Result<Option<SecretBlobRecord>, StoreError> {
        self.connection
            .query_row(
                "SELECT secret_id, version, encrypted_dek, ciphertext, value_nonce,
                        aad_schema_version, created_at
                 FROM blobs
                 WHERE secret_id = ?1 AND version = ?2",
                params![secret_id, version],
                secret_blob_record_from_row,
            )
            .optional()
            .map_err(StoreError::from)
    }
}

fn key_record_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<KeyRecord> {
    Ok(KeyRecord {
        id: row.get(0)?,
        project_id: row.get(1)?,
        profile_id: row.get(2)?,
        purpose: row.get(3)?,
        wrapped_material: row.get(4)?,
        nonce: nonce_from_row(row, 5, "keys.nonce")?,
        created_at: row.get(6)?,
    })
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

fn secret_record_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<SecretRecord> {
    Ok(SecretRecord {
        id: row.get(0)?,
        project_id: row.get(1)?,
        profile_id: row.get(2)?,
        name: row.get(3)?,
        source: row.get(4)?,
        origin: row.get(5)?,
        current_version: row.get(6)?,
        state: row.get(7)?,
        created_at: row.get(8)?,
        updated_at: row.get(9)?,
        last_rotated_at: row.get(10)?,
        deleted_at: row.get(11)?,
    })
}

fn secret_version_record_from_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<SecretVersionRecord> {
    Ok(SecretVersionRecord {
        secret_id: row.get(0)?,
        version: row.get(1)?,
        source: row.get(2)?,
        origin: row.get(3)?,
        state: row.get(4)?,
        created_at: row.get(5)?,
        deprecated_at: row.get(6)?,
        grace_until: row.get(7)?,
        purged_at: row.get(8)?,
    })
}

fn secret_blob_record_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<SecretBlobRecord> {
    Ok(SecretBlobRecord {
        secret_id: row.get(0)?,
        version: row.get(1)?,
        encrypted_dek: row.get(2)?,
        ciphertext: row.get(3)?,
        value_nonce: nonce_from_row(row, 4, "blobs.value_nonce")?,
        aad_schema_version: row.get(5)?,
        created_at: row.get(6)?,
    })
}

fn runtime_session_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RuntimeSessionRecord> {
    let secret_names_json = row.get::<_, String>(9)?;
    let secret_names =
        serde_json::from_str::<Vec<String>>(&secret_names_json).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(9, Type::Text, Box::new(error))
        })?;
    Ok(RuntimeSessionRecord {
        id: row.get(0)?,
        project_id: row.get(1)?,
        profile_id: row.get(2)?,
        policy_name: row.get(3)?,
        process_id: row.get(4)?,
        process_start_time: row.get(5)?,
        started_at: row.get(6)?,
        ended_at: row.get(7)?,
        exit_status: row.get(8)?,
        secret_names,
        spawn_audit_sequence: row.get(10)?,
        completion_audit_sequence: row.get(11)?,
    })
}

fn automation_client_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<AutomationClientRecord> {
    let allowed_actions_json = row.get::<_, String>(6)?;
    let allowed_actions =
        serde_json::from_str::<Vec<String>>(&allowed_actions_json).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(6, Type::Text, Box::new(error))
        })?;
    let allowed_policies_json = row.get::<_, String>(7)?;
    let allowed_policies =
        serde_json::from_str::<Vec<String>>(&allowed_policies_json).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(7, Type::Text, Box::new(error))
        })?;
    Ok(AutomationClientRecord {
        id: row.get(0)?,
        project_id: row.get(1)?,
        name: row.get(2)?,
        public_key: row.get(3)?,
        fingerprint: row.get(4)?,
        storage: row.get(5)?,
        allowed_actions,
        allowed_policies,
        created_at: row.get(8)?,
        last_used_at: row.get(9)?,
        revoked_at: row.get(10)?,
    })
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
        backup_eligible: row.get(6)?,
        backup_state: row.get(7)?,
        created_at: row.get(8)?,
        last_used_at: row.get(9)?,
        revoked_at: row.get(10)?,
    })
}

#[cfg(test)]
mod tests;
