//! Shared selection rules for CLI and agent sealed bundles.
use crate::{SecretRecord, SecretVersionRecord, Store, StoreError};

impl Store {
    /// Selects rows for explicit sharing. Personal sources and historical versions require opt-in.
    ///
    /// # Errors
    /// Returns a storage error if secret metadata or versions cannot be read.
    #[allow(clippy::type_complexity)]
    pub fn select_bundle_secrets(
        &self,
        project_id: &str,
        profile_id: &str,
        include_personal: bool,
        include_history: bool,
    ) -> Result<Vec<(SecretRecord, Vec<SecretVersionRecord>)>, StoreError> {
        let mut selected = Vec::new();
        for secret in self.list_secrets_by_profile(project_id, profile_id)? {
            if (!include_history && (secret.state != "active" || secret.deleted_at.is_some()))
                || (!include_personal && secret.source != "team-managed")
            {
                continue;
            }
            let versions = self
                .list_secret_versions(&secret.id)?
                .into_iter()
                .filter(|version| {
                    (include_personal || version.source == "team-managed")
                        && (include_history || version.version == secret.current_version)
                        && version.purged_at.is_none()
                })
                .collect::<Vec<_>>();
            if versions.iter().any(|v| v.version == secret.current_version)
                || (include_history && !versions.is_empty())
            {
                selected.push((secret, versions));
            }
        }
        Ok(selected)
    }
    /// Rejects recipients whose sealing key belongs to a revoked device or removed member.
    ///
    /// # Errors
    /// Returns a storage error if revocation metadata cannot be read.
    pub fn bundle_recipient_is_denied(
        &self,
        project_id: &str,
        sealing_key: &[u8; 32],
    ) -> Result<bool, StoreError> {
        let count: i64 = self.connection().query_row("SELECT COUNT(*) FROM devices d WHERE d.project_id = ?1 AND d.sealing_public_key = ?2 AND (d.revoked_at IS NOT NULL OR EXISTS (SELECT 1 FROM team_members m WHERE m.device_id = d.id AND m.removed_at IS NOT NULL))", rusqlite::params![project_id, sealing_key.as_slice()], |row| row.get(0))?;
        Ok(count > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn default_sharing_excludes_personal_sources_and_history()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let mut store = Store::open(directory.path().join("store.db"))?;
        store.initialize_schema()?;
        store.insert_project_if_absent("project", "project", 1)?;
        store.connection().execute("INSERT INTO profiles(id,project_id,name,dangerous,created_at) VALUES ('profile','project','dev',0,1)", [])?;
        for (n, source) in ["team-managed", "user-local", "machine-local"].iter().enumerate() {
            let id = format!("secret{n}");
            store.connection().execute("INSERT INTO secrets(id,project_id,profile_id,name,source,origin,required,current_version,state,created_at,updated_at) VALUES (?1,'project','profile',?1,?2,'manual',0,2,'active',1,2)", rusqlite::params![id, source])?;
            for version in 1..=2 {
                store.connection().execute("INSERT INTO secret_versions(secret_id,version,source,origin,state,created_at) VALUES (?1,?2,?3,'manual',?4,1)", rusqlite::params![id, version, source, if version == 1 {"deprecated"} else {"current"}])?;
            }
        }
        let selected = store.select_bundle_secrets("project", "profile", false, false)?;
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].0.source, "team-managed");
        assert_eq!(selected[0].1.len(), 1);
        assert_eq!(selected[0].1[0].version, 2);
        let personal = store.select_bundle_secrets("project", "profile", true, false)?;
        assert_eq!(personal.len(), 3);
        assert!(personal.iter().all(|(_, versions)| versions.len() == 1));
        let history = store.select_bundle_secrets("project", "profile", false, true)?;
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].1.len(), 2);
        assert_eq!(
            store
                .select_bundle_secrets("project", "profile", true, true)?
                .iter()
                .map(|(_, v)| v.len())
                .sum::<usize>(),
            6
        );
        store.connection().execute(
            "UPDATE secrets SET state = 'deleted', deleted_at = 3 WHERE id = 'secret0'",
            [],
        )?;
        assert_eq!(
            store.select_bundle_secrets("project", "profile", false, false)?,
            Vec::<(SecretRecord, Vec<SecretVersionRecord>)>::new()
        );
        assert_eq!(store.select_bundle_secrets("project", "profile", false, true)?.len(), 1);
        Ok(())
    }
}
