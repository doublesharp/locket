//! Onboarding helpers for template-backed project creation.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use locket_core::{PolicyDocument, ProfileName, ProjectConfig, ProjectId, SecretName};
use serde::Deserialize;
use toml::{Table, Value};

use crate::{CliError, metadata_invalid_error};

const BUILT_IN_BASIC_TEMPLATE: &str = r#"
name = "locket-project"
default_profile = "dev"
profiles = ["dev"]
expected_secrets = ["DATABASE_URL"]

[commands.dev]
argv = ["sh", "-c", "echo configure commands.dev for this project"]
required_secrets = ["DATABASE_URL"]
"#;

const SECRET_VALUE_KEYS: [&str; 6] =
    ["secret", "secrets", "secret_value", "secret_values", "value", "values"];

#[derive(Debug, Deserialize)]
struct RawTemplate {
    name: Option<String>,
    default_profile: Option<String>,
    profiles: Option<Vec<String>>,
    expected_secrets: Option<Vec<String>>,
}

#[derive(Debug)]
pub struct ProjectTemplate {
    pub source: TemplateSource,
    pub name: String,
    pub default_profile: ProfileName,
    pub profiles: Vec<ProfileName>,
    pub expected_secrets: BTreeSet<String>,
    commands: Option<Value>,
}

#[derive(Debug)]
pub enum TemplateSource {
    Local(PathBuf),
    BuiltIn,
}

impl TemplateSource {
    pub fn label(&self) -> String {
        match self {
            Self::Local(path) => format!("local:{}", path.display()),
            Self::BuiltIn => "built-in".to_owned(),
        }
    }
}

impl ProjectTemplate {
    pub fn command_count(&self) -> usize {
        self.commands.as_ref().and_then(Value::as_table).map_or(0, Table::len)
    }

    pub fn render_project_config(&self, project_name: String) -> Result<String, CliError> {
        let config = ProjectConfig::new(
            ProjectId::generate().map_err(|_| CliError::Time)?,
            project_name,
            self.default_profile.clone(),
        );
        let mut root = toml::Value::try_from(&config)
            .map_err(CliError::TomlSer)?
            .as_table()
            .cloned()
            .ok_or_else(|| metadata_invalid_error("project config did not serialize to a table"))?;
        if let Some(commands) = &self.commands {
            root.insert("commands".to_owned(), commands.clone());
        }
        let rendered = toml::to_string_pretty(&root)?;
        PolicyDocument::from_toml_str(&rendered).map_err(|error| {
            metadata_invalid_error(format!("invalid template command policy: {error}"))
        })?;
        Ok(rendered)
    }
}

pub fn load_project_template(template_dir: &Path, name: &str) -> Result<ProjectTemplate, CliError> {
    validate_template_name(name)?;
    let local_path = template_dir.join(format!("{name}.toml"));
    if local_path.exists() {
        let text = fs::read_to_string(&local_path)?;
        return parse_project_template(&text, TemplateSource::Local(local_path));
    }
    if name == "basic" {
        return parse_project_template(BUILT_IN_BASIC_TEMPLATE, TemplateSource::BuiltIn);
    }
    Err(metadata_invalid_error(format!(
        "unknown template {name:?}; expected a local template at {} or built-in template \"basic\"",
        local_path.display()
    )))
}

fn parse_project_template(text: &str, source: TemplateSource) -> Result<ProjectTemplate, CliError> {
    let value = toml::from_str::<Value>(text)?;
    reject_secret_value_keys(&value)?;
    let raw = toml::from_str::<RawTemplate>(text)?;
    let default_profile = ProfileName::new(raw.default_profile.unwrap_or_else(|| "dev".to_owned()))
        .map_err(|_| metadata_invalid_error("template default_profile is invalid"))?;
    let mut profiles = BTreeSet::new();
    profiles.insert(default_profile.clone());
    for profile in raw.profiles.unwrap_or_default() {
        profiles.insert(
            ProfileName::new(profile)
                .map_err(|_| metadata_invalid_error("template profile name is invalid"))?,
        );
    }
    let mut expected_secrets = BTreeSet::new();
    for secret in raw.expected_secrets.unwrap_or_default() {
        let secret_name = SecretName::new(secret)
            .map_err(|_| metadata_invalid_error("template expected secret name is invalid"))?;
        expected_secrets.insert(secret_name.into_string());
    }
    let commands = value.as_table().and_then(|table| table.get("commands")).cloned();
    Ok(ProjectTemplate {
        source,
        name: raw.name.unwrap_or_else(|| "locket-project".to_owned()),
        default_profile,
        profiles: profiles.into_iter().collect(),
        expected_secrets,
        commands,
    })
}

fn validate_template_name(name: &str) -> Result<(), CliError> {
    if name.is_empty()
        || !name.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(metadata_invalid_error(
            "template name must contain only ASCII letters, numbers, '-' or '_'",
        ));
    }
    Ok(())
}

fn reject_secret_value_keys(value: &Value) -> Result<(), CliError> {
    match value {
        Value::Table(table) => {
            for (key, child) in table {
                if SECRET_VALUE_KEYS.iter().any(|blocked| key == blocked) {
                    return Err(metadata_invalid_error(
                        "templates must not contain secret value fields",
                    ));
                }
                reject_secret_value_keys(child)?;
            }
        }
        Value::Array(values) => {
            for child in values {
                reject_secret_value_keys(child)?;
            }
        }
        _ => {}
    }
    Ok(())
}
