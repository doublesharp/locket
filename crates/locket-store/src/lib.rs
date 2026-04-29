//! `SQLite` storage layer for Locket.

use std::path::Path;
use std::str::FromStr;
use std::time::Duration;

use hmac::{Hmac, Mac};
use locket_core::{
    AUDIT_HMAC_LEN, AuditCanonicalizationError, AuditHmacInput, Duration as LocketDuration,
    LocketError, Timestamp, audit_hmac_v1_bytes, canonical_json_string,
};
use rusqlite::types::Type;
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde_json::{Value, json};
use sha2::Sha256;
use thiserror::Error;

/// Current storage schema version.
pub const SCHEMA_VERSION: u32 = 1;

const BUSY_TIMEOUT_MS: u64 = 5_000;

/// SQLite-backed Locket store.
#[derive(Debug)]
pub struct Store {
    connection: Connection,
}

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

/// Metadata for a trusted project root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectRootRecord {
    /// Parent project identifier.
    pub project_id: String,
    /// SHA-256 hash of the canonical root path.
    pub root_hash: [u8; 32],
    /// Last known display path for the root.
    pub display_path: Option<String>,
    /// Creation timestamp in nanoseconds since the Unix epoch.
    pub created_at: i64,
    /// Last-seen timestamp in nanoseconds since the Unix epoch.
    pub last_seen_at: Option<i64>,
}

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
        configure_connection(&connection)?;
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
        initialize_schema(&mut self.connection)
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

    /// Records or refreshes trust for a project root hash.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` rejects the write.
    pub fn trust_project_root(
        &self,
        project_id: &str,
        root_hash: &[u8; 32],
        display_path: Option<&str>,
        timestamp: i64,
    ) -> Result<(), StoreError> {
        self.connection.execute(
            "INSERT INTO project_roots(project_id, root_hash, display_path, created_at, last_seen_at)
             VALUES (?1, ?2, ?3, ?4, ?4)
             ON CONFLICT(project_id, root_hash) DO UPDATE SET
               display_path = excluded.display_path,
               last_seen_at = excluded.last_seen_at",
            params![project_id, root_hash.as_slice(), display_path, timestamp],
        )?;

        Ok(())
    }

    /// Returns whether a root hash is trusted for a project.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` cannot query the root row.
    pub fn project_root_is_trusted(
        &self,
        project_id: &str,
        root_hash: &[u8; 32],
    ) -> Result<bool, StoreError> {
        let row_count = self.connection.query_row(
            "SELECT COUNT(*) FROM project_roots WHERE project_id = ?1 AND root_hash = ?2",
            params![project_id, root_hash.as_slice()],
            |row| row.get::<_, i64>(0),
        )?;

        Ok(row_count > 0)
    }

    /// Lists trusted roots for a project ordered by creation time.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` cannot query trusted root rows.
    pub fn list_project_roots(
        &self,
        project_id: &str,
    ) -> Result<Vec<ProjectRootRecord>, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT project_id, root_hash, display_path, created_at, last_seen_at
             FROM project_roots
             WHERE project_id = ?1
             ORDER BY created_at, root_hash",
        )?;
        let roots = statement
            .query_map([project_id], project_root_record_from_row)?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(roots)
    }

    /// Removes a trusted root from a project.
    ///
    /// Returns `true` when a root was removed and `false` when no matching root existed.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` rejects the delete.
    pub fn untrust_project_root(
        &self,
        project_id: &str,
        root_hash: &[u8; 32],
    ) -> Result<bool, StoreError> {
        self.connection.execute(
            "DELETE FROM project_roots WHERE project_id = ?1 AND root_hash = ?2",
            params![project_id, root_hash.as_slice()],
        )?;

        Ok(self.connection.changes() == 1)
    }

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

fn project_record_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ProjectRecord> {
    Ok(ProjectRecord { id: row.get(0)?, name: row.get(1)?, created_at: row.get(2)? })
}

fn project_root_record_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ProjectRootRecord> {
    Ok(ProjectRootRecord {
        project_id: row.get(0)?,
        root_hash: root_hash_from_row(row, 1, "project_roots.root_hash")?,
        display_path: row.get(2)?,
        created_at: row.get(3)?,
        last_seen_at: row.get(4)?,
    })
}

fn directory_grant_record_from_row(
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

fn profile_record_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ProfileRecord> {
    Ok(ProfileRecord {
        id: row.get(0)?,
        project_id: row.get(1)?,
        name: row.get(2)?,
        dangerous: row.get(3)?,
        created_at: row.get(4)?,
    })
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

fn audit_log_record_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<AuditLogRecord> {
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

fn root_hash_from_row(
    row: &rusqlite::Row<'_>,
    column: usize,
    field: &'static str,
) -> rusqlite::Result<[u8; 32]> {
    let bytes: Vec<u8> = row.get(column)?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        rusqlite::Error::FromSqlConversionFailure(
            column,
            Type::Blob,
            Box::new(InvalidFixedBytesLength { field, expected: 32, actual: bytes.len() }),
        )
    })
}

fn nonce_from_row(
    row: &rusqlite::Row<'_>,
    column: usize,
    field: &'static str,
) -> rusqlite::Result<[u8; 24]> {
    let bytes: Vec<u8> = row.get(column)?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        rusqlite::Error::FromSqlConversionFailure(
            column,
            Type::Blob,
            Box::new(InvalidNonceLength { field, actual: bytes.len() }),
        )
    })
}

fn append_optional_audit(
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

fn append_audit(
    transaction: &Transaction<'_>,
    audit_key: &[u8],
    audit: &AuditWrite<'_>,
) -> Result<(), StoreError> {
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
    let metadata_json = canonical_json_string(Some(audit.metadata_json));

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

#[derive(Debug, Error)]
#[error("{field} must be {expected} bytes, got {actual}")]
struct InvalidFixedBytesLength {
    field: &'static str,
    expected: usize,
    actual: usize,
}

#[derive(Debug, Error)]
#[error("{field} must be 24 bytes, got {actual}")]
struct InvalidNonceLength {
    field: &'static str,
    actual: usize,
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

fn configure_connection(connection: &Connection) -> Result<(), rusqlite::Error> {
    connection.busy_timeout(Duration::from_millis(BUSY_TIMEOUT_MS))?;
    connection.pragma_update(None, "foreign_keys", "ON")?;
    connection.pragma_update(None, "journal_mode", "WAL")?;
    Ok(())
}

fn initialize_schema(connection: &mut Connection) -> Result<(), StoreError> {
    if let Some(version) = current_schema_version(connection)? {
        fail_on_newer_schema(version)?;
    }

    let transaction = connection.transaction()?;
    transaction.execute_batch(SCHEMA_SQL)?;
    transaction.execute(
        "INSERT OR IGNORE INTO schema_migrations(version, applied_at)
         VALUES (?1, CAST(strftime('%s', 'now') AS INTEGER) * 1000000000)",
        [i64::from(SCHEMA_VERSION)],
    )?;
    transaction.commit()?;

    if let Some(version) = current_schema_version(connection)? {
        fail_on_newer_schema(version)?;
    }

    Ok(())
}

fn current_schema_version(connection: &Connection) -> Result<Option<i64>, StoreError> {
    let migrations_exists = connection
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'schema_migrations'",
            [],
            |_| Ok(()),
        )
        .optional()?
        .is_some();

    if !migrations_exists {
        return Ok(None);
    }

    let version =
        connection.query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
            row.get::<_, Option<i64>>(0)
        })?;

    Ok(version)
}

const fn fail_on_newer_schema(version: i64) -> Result<(), StoreError> {
    if version > SCHEMA_VERSION as i64 {
        return Err(StoreError::UnsupportedSchema { found: version, supported: SCHEMA_VERSION });
    }

    Ok(())
}

const SCHEMA_SQL: &str = r"
CREATE TABLE IF NOT EXISTS projects (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  user_verification_policy_json TEXT NOT NULL DEFAULT '{}',
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS profiles (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  dangerous INTEGER NOT NULL CHECK (dangerous IN (0, 1)),
  created_at INTEGER NOT NULL,
  UNIQUE (project_id, name)
);

CREATE TABLE IF NOT EXISTS project_roots (
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  root_hash BLOB NOT NULL CHECK (length(root_hash) = 32),
  display_path TEXT,
  created_at INTEGER NOT NULL,
  last_seen_at INTEGER,
  PRIMARY KEY (project_id, root_hash)
);

CREATE INDEX IF NOT EXISTS project_roots_root_hash_idx
  ON project_roots(root_hash);

CREATE TABLE IF NOT EXISTS directory_grants (
  grant_id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  profile_id TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
  root_hash BLOB NOT NULL CHECK (length(root_hash) = 32),
  directory_hash BLOB NOT NULL CHECK (length(directory_hash) = 32),
  grant_scope TEXT NOT NULL CHECK (grant_scope IN ('project-root')),
  display_path TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  UNIQUE (project_id, profile_id, root_hash, directory_hash, grant_scope)
);

CREATE INDEX IF NOT EXISTS directory_grants_project_root_idx
  ON directory_grants(project_id, root_hash);

CREATE TABLE IF NOT EXISTS secrets (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  profile_id TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  description TEXT,
  owner TEXT,
  source TEXT NOT NULL CHECK (source IN ('team-managed', 'user-local', 'machine-local')),
  origin TEXT NOT NULL CHECK (origin IN ('manual', 'imported', 'team-accept', 'profile-copy')),
  tags_json TEXT NOT NULL DEFAULT '[]',
  required INTEGER NOT NULL CHECK (required IN (0, 1)),
  current_version INTEGER NOT NULL CHECK (current_version >= 1 AND current_version <= 4294967295),
  state TEXT NOT NULL CHECK (state IN ('active', 'deleted')),
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  last_rotated_at INTEGER,
  deleted_at INTEGER,
  UNIQUE (project_id, profile_id, name, source)
);

CREATE INDEX IF NOT EXISTS secrets_project_profile_name_idx
  ON secrets(project_id, profile_id, name);

CREATE TABLE IF NOT EXISTS secret_versions (
  secret_id TEXT NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
  version INTEGER NOT NULL CHECK (version >= 1 AND version <= 4294967295),
  source TEXT NOT NULL CHECK (source IN ('team-managed', 'user-local', 'machine-local')),
  origin TEXT NOT NULL CHECK (origin IN ('manual', 'imported', 'team-accept', 'profile-copy')),
  state TEXT NOT NULL CHECK (state IN ('current', 'deprecated', 'purged')),
  created_at INTEGER NOT NULL,
  deprecated_at INTEGER,
  grace_until INTEGER,
  purged_at INTEGER,
  PRIMARY KEY (secret_id, version)
);

CREATE TRIGGER IF NOT EXISTS secret_versions_source_matches_secret_insert
BEFORE INSERT ON secret_versions
FOR EACH ROW
WHEN NEW.source != (SELECT source FROM secrets WHERE id = NEW.secret_id)
BEGIN
  SELECT RAISE(ABORT, 'secret_versions.source must match secrets.source');
END;

CREATE TRIGGER IF NOT EXISTS secret_versions_source_matches_secret_update
BEFORE UPDATE OF secret_id, source ON secret_versions
FOR EACH ROW
WHEN NEW.source != (SELECT source FROM secrets WHERE id = NEW.secret_id)
BEGIN
  SELECT RAISE(ABORT, 'secret_versions.source must match secrets.source');
END;

CREATE TABLE IF NOT EXISTS blobs (
  secret_id TEXT NOT NULL,
  version INTEGER NOT NULL,
  encrypted_dek BLOB NOT NULL,
  ciphertext BLOB NOT NULL,
  value_nonce BLOB NOT NULL CHECK (length(value_nonce) = 24),
  aad_schema_version INTEGER NOT NULL CHECK (aad_schema_version >= 1),
  created_at INTEGER NOT NULL,
  PRIMARY KEY (secret_id, version),
  FOREIGN KEY (secret_id, version)
    REFERENCES secret_versions(secret_id, version)
    ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS fingerprints (
  secret_id TEXT NOT NULL,
  version INTEGER NOT NULL CHECK (version >= 1 AND version <= 4294967295),
  fingerprint BLOB NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (secret_id, version),
  FOREIGN KEY (secret_id, version)
    REFERENCES secret_versions(secret_id, version)
    ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS keys (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  profile_id TEXT REFERENCES profiles(id) ON DELETE CASCADE,
  purpose TEXT NOT NULL CHECK (purpose IN ('project-metadata', 'project-audit', 'profile-secret', 'profile-fingerprint')),
  wrapped_material BLOB NOT NULL,
  nonce BLOB NOT NULL CHECK (length(nonce) = 24),
  created_at INTEGER NOT NULL,
  CHECK (
    (profile_id IS NULL AND purpose IN ('project-metadata', 'project-audit'))
    OR
    (profile_id IS NOT NULL AND purpose IN ('profile-secret', 'profile-fingerprint'))
  )
);

CREATE UNIQUE INDEX IF NOT EXISTS keys_project_scope_unique
  ON keys(project_id, purpose)
  WHERE profile_id IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS keys_profile_scope_unique
  ON keys(project_id, profile_id, purpose)
  WHERE profile_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS devices (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  signing_public_key BLOB NOT NULL CHECK (length(signing_public_key) = 32),
  sealing_public_key BLOB NOT NULL CHECK (length(sealing_public_key) = 32),
  fingerprint TEXT NOT NULL,
  safety_words_json TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(safety_words_json)),
  local INTEGER NOT NULL CHECK (local IN (0, 1)),
  created_at INTEGER NOT NULL,
  last_seen_at INTEGER,
  revoked_at INTEGER
);

CREATE UNIQUE INDEX IF NOT EXISTS devices_active_name_unique_idx
  ON devices(project_id, name)
  WHERE revoked_at IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS devices_active_fingerprint_unique_idx
  ON devices(project_id, fingerprint)
  WHERE revoked_at IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS devices_one_active_local_idx
  ON devices(project_id)
  WHERE local = 1 AND revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS passkey_credentials (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  label TEXT NOT NULL,
  credential_id BLOB NOT NULL CHECK (length(credential_id) > 0),
  transports_json TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(transports_json)),
  prf_capable INTEGER NOT NULL CHECK (prf_capable IN (0, 1)),
  backup_eligible INTEGER CHECK (backup_eligible IN (0, 1)),
  backup_state INTEGER CHECK (backup_state IN (0, 1)),
  created_at INTEGER NOT NULL,
  last_used_at INTEGER,
  revoked_at INTEGER,
  UNIQUE (project_id, label),
  UNIQUE (project_id, credential_id)
);

CREATE INDEX IF NOT EXISTS passkey_credentials_project_revoked_idx
  ON passkey_credentials(project_id, revoked_at);

CREATE TABLE IF NOT EXISTS audit_log (
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  sequence INTEGER NOT NULL CHECK (sequence >= 1),
  schema_version INTEGER NOT NULL CHECK (schema_version >= 1 AND schema_version <= 4294967295),
  timestamp INTEGER NOT NULL,
  profile_id TEXT REFERENCES profiles(id) ON DELETE SET NULL,
  action TEXT NOT NULL,
  status TEXT NOT NULL,
  metadata_json TEXT NOT NULL,
  secret_name TEXT,
  command TEXT,
  previous_hmac BLOB CHECK (previous_hmac IS NULL OR length(previous_hmac) = 32),
  hmac BLOB NOT NULL CHECK (length(hmac) = 32),
  PRIMARY KEY (project_id, sequence)
);

CREATE TABLE IF NOT EXISTS runtime_sessions (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  profile_id TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
  policy_name TEXT,
  process_id INTEGER NOT NULL CHECK (process_id >= 0 AND process_id <= 4294967295),
  process_start_time INTEGER NOT NULL,
  started_at INTEGER NOT NULL,
  ended_at INTEGER,
  exit_status INTEGER,
  secret_names_json TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(secret_names_json)),
  spawn_audit_sequence INTEGER CHECK (spawn_audit_sequence IS NULL OR spawn_audit_sequence >= 1),
  completion_audit_sequence INTEGER CHECK (
    completion_audit_sequence IS NULL OR completion_audit_sequence >= 1
  ),
  CHECK (ended_at IS NULL OR ended_at >= started_at),
  CHECK ((ended_at IS NULL AND exit_status IS NULL) OR ended_at IS NOT NULL)
);

CREATE INDEX IF NOT EXISTS runtime_sessions_project_incomplete_idx
  ON runtime_sessions(project_id, started_at)
  WHERE ended_at IS NULL;

CREATE INDEX IF NOT EXISTS runtime_sessions_project_secret_names_retention_idx
  ON runtime_sessions(project_id, started_at)
  WHERE secret_names_json != '[]';

CREATE INDEX IF NOT EXISTS runtime_sessions_process_identity_idx
  ON runtime_sessions(process_id, process_start_time);

CREATE TABLE IF NOT EXISTS automation_clients (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  public_key BLOB NOT NULL CHECK (length(public_key) = 32),
  fingerprint TEXT NOT NULL,
  storage TEXT NOT NULL CHECK (storage IN ('external', 'os-keychain', 'wrapped-local-file')),
  allowed_actions_json TEXT NOT NULL CHECK (json_valid(allowed_actions_json)),
  allowed_policies_json TEXT NOT NULL CHECK (json_valid(allowed_policies_json)),
  created_at INTEGER NOT NULL,
  last_used_at INTEGER,
  revoked_at INTEGER,
  UNIQUE (project_id, name),
  UNIQUE (project_id, fingerprint)
);

CREATE INDEX IF NOT EXISTS automation_clients_project_active_idx
  ON automation_clients(project_id, name)
  WHERE revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS automation_client_nonces (
  client_id TEXT NOT NULL REFERENCES automation_clients(id) ON DELETE CASCADE,
  nonce BLOB NOT NULL CHECK (length(nonce) = 24),
  request_timestamp INTEGER NOT NULL,
  seen_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  PRIMARY KEY (client_id, nonce)
);

CREATE TABLE IF NOT EXISTS schema_migrations (
  version INTEGER PRIMARY KEY CHECK (version >= 1 AND version <= 4294967295),
  applied_at INTEGER NOT NULL
);
";

#[cfg(test)]
mod tests;
