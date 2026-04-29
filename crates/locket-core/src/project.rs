//! Project metadata configuration for `locket.toml`.

use serde::{Deserialize, Serialize};

use crate::id::ProjectId;
use crate::profile_name::ProfileName;

/// Supported `locket.toml` schema version.
pub const PROJECT_CONFIG_SCHEMA_VERSION: u16 = 1;

/// Metadata stored in a project's `locket.toml`.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProjectConfig {
    /// Version of the `locket.toml` schema.
    pub schema_version: u16,
    /// Stable opaque project identifier.
    pub project_id: ProjectId,
    /// Human-readable project name.
    pub name: String,
    /// Name of the default local profile.
    pub default_profile: ProfileName,
}

impl ProjectConfig {
    /// Creates a project config using the current schema version.
    #[must_use]
    pub const fn new(project_id: ProjectId, name: String, default_profile: ProfileName) -> Self {
        Self { schema_version: PROJECT_CONFIG_SCHEMA_VERSION, project_id, name, default_profile }
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use super::{PROJECT_CONFIG_SCHEMA_VERSION, ProjectConfig};
    use crate::{ProfileName, ProjectId};

    #[test]
    fn constructs_current_schema_project_config() -> Result<(), Box<dyn Error>> {
        let project_id = ProjectId::new("lk_proj_abc")?;
        let default_profile = ProfileName::new("default")?;

        let config = ProjectConfig::new(project_id, "example".to_owned(), default_profile);

        assert_eq!(config.schema_version, PROJECT_CONFIG_SCHEMA_VERSION);
        assert_eq!(config.name, "example");
        Ok(())
    }

    #[test]
    fn round_trips_through_serde() -> Result<(), Box<dyn Error>> {
        let project_id = ProjectId::new("lk_proj_0123456789abcdef")?;
        let default_profile = ProfileName::new("default")?;
        let config = ProjectConfig::new(project_id, "example".to_owned(), default_profile);

        let serialized = serde_json::to_string(&config)?;

        assert!(serialized.contains("\"schema_version\":1"));
        assert!(serialized.contains("\"project_id\":\"lk_proj_0123456789abcdef\""));
        assert!(serialized.contains("\"name\":\"example\""));
        assert!(serialized.contains("\"default_profile\":\"default\""));

        let deserialized = serde_json::from_str::<ProjectConfig>(&serialized)?;
        assert_eq!(deserialized, config);
        Ok(())
    }
}
