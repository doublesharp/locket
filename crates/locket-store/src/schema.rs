//! `SQLite` schema bootstrap and connection configuration.

use std::time::Duration;

use rusqlite::{Connection, OptionalExtension};

use crate::error::StoreError;

/// Current storage schema version.
pub const SCHEMA_VERSION: u32 = 1;

/// Audit action written for each schema migration step when project context is available.
pub const AUDIT_ACTION_SCHEMA_MIGRATE: &str = "SCHEMA_MIGRATE";

const BUSY_TIMEOUT_MS: u64 = 5_000;

pub fn configure_connection(connection: &Connection) -> Result<(), rusqlite::Error> {
    connection.busy_timeout(Duration::from_millis(BUSY_TIMEOUT_MS))?;
    connection.pragma_update(None, "foreign_keys", "ON")?;
    connection.pragma_update(None, "journal_mode", "WAL")?;
    Ok(())
}

pub fn initialize_schema(connection: &mut Connection) -> Result<(), StoreError> {
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

pub fn current_schema_version(connection: &Connection) -> Result<Option<i64>, StoreError> {
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
  webauthn_relying_party_id TEXT NOT NULL DEFAULT 'locket.localhost',
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

CREATE TABLE IF NOT EXISTS teams (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  UNIQUE (project_id, name)
);

CREATE UNIQUE INDEX IF NOT EXISTS teams_one_per_project_idx
  ON teams(project_id);

-- `team_members.device_id`:
--   `docs/specs/storage.md` (lines 26-51) lists `team_members` as a
--   required table without dictating an FK rule. The `TeamMember` model
--   in `docs/specs/data-model.md` describes a member with
--   `trusted_devices: Vec<DeviceId>`; v1 SQLite stores the active
--   trusted device per row and uses the partial unique index
--   `team_members_active_device_idx` plus extra rows to express the
--   1-to-many relationship without a join table. Deleting a `device`
--   row clears `device_id` to NULL (`ON DELETE SET NULL`) so the
--   audit-relevant member row survives device retirement and the unique
--   active-device index does not block re-binding the member to a new
--   device. This matches the spec intent.
CREATE TABLE IF NOT EXISTS team_members (
  id TEXT PRIMARY KEY,
  team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
  device_id TEXT REFERENCES devices(id) ON DELETE SET NULL,
  display_name TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('owner', 'maintainer', 'developer', 'read-only')),
  joined_at INTEGER NOT NULL,
  removed_at INTEGER,
  CHECK (removed_at IS NULL OR removed_at >= joined_at),
  UNIQUE (team_id, display_name)
);

CREATE UNIQUE INDEX IF NOT EXISTS team_members_active_device_idx
  ON team_members(team_id, device_id)
  WHERE device_id IS NOT NULL AND removed_at IS NULL;

CREATE INDEX IF NOT EXISTS team_members_team_role_idx
  ON team_members(team_id, role)
  WHERE removed_at IS NULL;

CREATE TABLE IF NOT EXISTS team_invites (
  id TEXT PRIMARY KEY,
  team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
  issuer_member_id TEXT REFERENCES team_members(id) ON DELETE SET NULL,
  recipient_device_fingerprint TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('owner', 'maintainer', 'developer', 'read-only')),
  profiles_json TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(profiles_json)),
  nonce BLOB NOT NULL CHECK (length(nonce) = 24),
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  accepted_at INTEGER,
  revoked_at INTEGER,
  CHECK (expires_at > created_at),
  CHECK (accepted_at IS NULL OR accepted_at >= created_at),
  CHECK (revoked_at IS NULL OR revoked_at >= created_at)
);

CREATE INDEX IF NOT EXISTS team_invites_team_status_idx
  ON team_invites(team_id, expires_at, accepted_at, revoked_at);

CREATE TABLE IF NOT EXISTS command_policies (
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  policy_json TEXT NOT NULL CHECK (json_valid(policy_json)),
  normalized_json TEXT NOT NULL CHECK (json_valid(normalized_json)),
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (project_id, name)
);

CREATE INDEX IF NOT EXISTS command_policies_project_updated_idx
  ON command_policies(project_id, updated_at);

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

CREATE TABLE IF NOT EXISTS imported_audit_chains (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  source_device_fingerprint TEXT NOT NULL,
  bundle_digest BLOB NOT NULL CHECK (length(bundle_digest) = 32),
  checkpoint_sequence INTEGER NOT NULL CHECK (checkpoint_sequence >= 1),
  checkpoint_hmac BLOB NOT NULL CHECK (length(checkpoint_hmac) = 32),
  encrypted_rows BLOB NOT NULL,
  nonce BLOB NOT NULL CHECK (length(nonce) = 24),
  aad_schema_version INTEGER NOT NULL CHECK (aad_schema_version >= 1),
  imported_at INTEGER NOT NULL,
  UNIQUE (project_id, source_device_fingerprint, bundle_digest)
);

CREATE INDEX IF NOT EXISTS imported_audit_chains_conflict_idx
  ON imported_audit_chains(project_id, bundle_digest, checkpoint_sequence);

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

CREATE TABLE IF NOT EXISTS automation_client_private_key_refs (
  client_id TEXT PRIMARY KEY REFERENCES automation_clients(id) ON DELETE CASCADE,
  storage TEXT NOT NULL CHECK (storage IN ('os-keychain', 'wrapped-local-file')),
  keychain_service TEXT,
  keychain_account TEXT,
  local_path_hash TEXT,
  metadata_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata_json)),
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  CHECK (
    (
      storage = 'os-keychain'
      AND keychain_service IS NOT NULL
      AND keychain_account IS NOT NULL
      AND local_path_hash IS NULL
    )
    OR
    (
      storage = 'wrapped-local-file'
      AND keychain_service IS NULL
      AND keychain_account IS NULL
      AND local_path_hash IS NOT NULL
    )
  )
);

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
