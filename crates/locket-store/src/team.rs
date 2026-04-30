//! Team metadata records and listing operations.

use rusqlite::types::Type;
use rusqlite::{OptionalExtension, params};

use crate::Store;
use crate::error::StoreError;

/// Team metadata row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TeamRecord {
    /// Team identifier.
    pub id: String,
    /// Parent project identifier.
    pub project_id: String,
    /// Human-readable team name.
    pub name: String,
    /// Creation timestamp in nanoseconds since the Unix epoch.
    pub created_at: i64,
    /// Update timestamp in nanoseconds since the Unix epoch.
    pub updated_at: i64,
}

/// Team member metadata plus derived trusted-device count.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TeamMemberListRecord {
    /// Member identifier.
    pub id: String,
    /// Human-readable member display name.
    pub display_name: String,
    /// Team role label.
    pub role: String,
    /// Number of currently trusted devices for this member.
    pub trusted_device_count: i64,
    /// Join timestamp in nanoseconds since the Unix epoch.
    pub joined_at: i64,
    /// Removal timestamp in nanoseconds since the Unix epoch.
    pub removed_at: Option<i64>,
}

/// Pending invite metadata for team listings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingTeamInviteRecord {
    /// Invite identifier.
    pub id: String,
    /// Invited role label.
    pub role: String,
    /// Profile names included in the invite metadata.
    pub profiles: Vec<String>,
    /// Recipient device fingerprint metadata.
    pub recipient_device_fingerprint: String,
    /// Creation timestamp in nanoseconds since the Unix epoch.
    pub created_at: i64,
    /// Expiration timestamp in nanoseconds since the Unix epoch.
    pub expires_at: i64,
}

fn team_record_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<TeamRecord> {
    Ok(TeamRecord {
        id: row.get(0)?,
        project_id: row.get(1)?,
        name: row.get(2)?,
        created_at: row.get(3)?,
        updated_at: row.get(4)?,
    })
}

fn team_member_list_record_from_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<TeamMemberListRecord> {
    Ok(TeamMemberListRecord {
        id: row.get(0)?,
        display_name: row.get(1)?,
        role: row.get(2)?,
        trusted_device_count: row.get(3)?,
        joined_at: row.get(4)?,
        removed_at: row.get(5)?,
    })
}

fn pending_team_invite_record_from_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<PendingTeamInviteRecord> {
    let profiles_json = row.get::<_, String>(2)?;
    let profiles = serde_json::from_str::<Vec<String>>(&profiles_json).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(2, Type::Text, Box::new(error))
    })?;
    Ok(PendingTeamInviteRecord {
        id: row.get(0)?,
        role: row.get(1)?,
        profiles,
        recipient_device_fingerprint: row.get(3)?,
        created_at: row.get(4)?,
        expires_at: row.get(5)?,
    })
}

impl Store {
    /// Inserts a team metadata row.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` rejects the insert; in
    /// particular, a second insert for a project the
    /// `teams_one_per_project_idx` already covers fails with a unique-constraint
    /// error.
    pub fn insert_team(&self, team: &TeamRecord) -> Result<(), StoreError> {
        self.connection.execute(
            "INSERT INTO teams(id, project_id, name, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                team.id.as_str(),
                team.project_id.as_str(),
                team.name.as_str(),
                team.created_at,
                team.updated_at,
            ],
        )?;
        Ok(())
    }

    /// Returns the team metadata row for a project.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` cannot query the team row.
    pub fn get_team_by_project(&self, project_id: &str) -> Result<Option<TeamRecord>, StoreError> {
        self.connection
            .query_row(
                "SELECT id, project_id, name, created_at, updated_at
                 FROM teams
                 WHERE project_id = ?1
                 LIMIT 1",
                [project_id],
                team_record_from_row,
            )
            .optional()
            .map_err(StoreError::from)
    }

    /// Lists all team members for a team with a derived trusted-device count.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` cannot query member rows.
    pub fn list_team_members(
        &self,
        team_id: &str,
    ) -> Result<Vec<TeamMemberListRecord>, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT
               m.id,
               m.display_name,
               m.role,
               COUNT(d.id) AS trusted_device_count,
               m.joined_at,
               m.removed_at
             FROM team_members m
             LEFT JOIN devices d ON d.id = m.device_id AND d.revoked_at IS NULL
             WHERE m.team_id = ?1
             GROUP BY m.id, m.display_name, m.role, m.joined_at, m.removed_at
             ORDER BY m.joined_at, m.id",
        )?;
        let members = statement
            .query_map([team_id], team_member_list_record_from_row)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(members)
    }

    /// Returns the team member record for a team by display name or id.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` cannot query the member row.
    pub fn get_team_member(
        &self,
        team_id: &str,
        name_or_id: &str,
    ) -> Result<Option<TeamMemberListRecord>, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT
               m.id,
               m.display_name,
               m.role,
               COUNT(d.id) AS trusted_device_count,
               m.joined_at,
               m.removed_at
             FROM team_members m
             LEFT JOIN devices d ON d.id = m.device_id AND d.revoked_at IS NULL
             WHERE m.team_id = ?1
               AND (m.id = ?2 OR m.display_name = ?2)
             GROUP BY m.id, m.display_name, m.role, m.joined_at, m.removed_at
             LIMIT 1",
        )?;
        statement
            .query_row(params![team_id, name_or_id], team_member_list_record_from_row)
            .optional()
            .map_err(StoreError::from)
    }

    /// Returns the count of active (non-removed) owners for a team.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` cannot query the count.
    pub fn count_active_owners(&self, team_id: &str) -> Result<i64, StoreError> {
        self.connection
            .query_row(
                "SELECT COUNT(*) FROM team_members
                 WHERE team_id = ?1 AND role = 'owner' AND removed_at IS NULL",
                [team_id],
                |row| row.get(0),
            )
            .map_err(StoreError::from)
    }

    /// Sets `removed_at` for a team member (soft-delete).
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` cannot update the row.
    pub fn remove_team_member(&self, member_id: &str, removed_at: i64) -> Result<(), StoreError> {
        self.connection.execute(
            "UPDATE team_members SET removed_at = ?1 WHERE id = ?2 AND removed_at IS NULL",
            params![removed_at, member_id],
        )?;
        Ok(())
    }

    /// Marks a team invite as accepted, returning [`StoreError::InviteReplayDetected`]
    /// when the invite has already been accepted or revoked.
    ///
    /// The check-and-set runs in a single SQLite UPDATE statement so two
    /// concurrent acceptances cannot both succeed: the second one finds
    /// `accepted_at IS NOT NULL` and the conditional UPDATE affects zero
    /// rows.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::InviteReplayDetected`] when the invite is
    /// already accepted or revoked, [`StoreError::InviteNotFound`] when no
    /// row matches `invite_id`, or [`StoreError::Sqlite`] for other
    /// `SQLite` failures.
    pub fn mark_invite_accepted(
        &self,
        invite_id: &str,
        accepted_at: i64,
    ) -> Result<(), StoreError> {
        let exists: Option<(Option<i64>, Option<i64>)> = self
            .connection
            .query_row(
                "SELECT accepted_at, revoked_at FROM team_invites WHERE id = ?1",
                [invite_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let Some((existing_accepted_at, revoked_at)) = exists else {
            return Err(StoreError::InviteNotFound { invite_id: invite_id.to_owned() });
        };
        if existing_accepted_at.is_some() || revoked_at.is_some() {
            return Err(StoreError::InviteReplayDetected { invite_id: invite_id.to_owned() });
        }
        let updated = self.connection.execute(
            "UPDATE team_invites
                SET accepted_at = ?1
              WHERE id = ?2
                AND accepted_at IS NULL
                AND revoked_at IS NULL",
            params![accepted_at, invite_id],
        )?;
        if updated == 0 {
            // Lost the race against another acceptance: SELECT saw the
            // row clean, but UPDATE affected zero rows because another
            // transaction set accepted_at first.
            return Err(StoreError::InviteReplayDetected { invite_id: invite_id.to_owned() });
        }
        Ok(())
    }

    /// Lists pending, non-expired team invites for a team.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlite`] when `SQLite` cannot query invite rows.
    pub fn list_pending_team_invites(
        &self,
        team_id: &str,
        now: i64,
    ) -> Result<Vec<PendingTeamInviteRecord>, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT
               id,
               role,
               profiles_json,
               recipient_device_fingerprint,
               created_at,
               expires_at
             FROM team_invites
             WHERE team_id = ?1
               AND accepted_at IS NULL
               AND revoked_at IS NULL
               AND expires_at > ?2
             ORDER BY created_at, id",
        )?;
        let invites = statement
            .query_map(params![team_id, now], pending_team_invite_record_from_row)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(invites)
    }
}
