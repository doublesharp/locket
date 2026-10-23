//! Resolve Docker's destination from the environment actually given to the child.

use std::io::Read as _;
use std::path::{Path, PathBuf};

use locket_exec::EnvMap;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::CliError;
use crate::runtime::error::metadata_invalid_error;

fn invalid_context() -> CliError {
    metadata_invalid_error(
        "Cannot determine the Docker endpoint. Check Docker context configuration before injecting secrets.",
    )
}

fn env_value<'a>(env: &'a EnvMap, name: &str) -> Option<&'a str> {
    env.get(name).map(|value| value.as_str()).filter(|value| !value.is_empty())
}

fn read_config(path: &Path) -> Result<Option<Value>, CliError> {
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(invalid_context()),
    };
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    file.take(1_048_577).read_to_end(&mut bytes).map_err(|_| invalid_context())?;
    if bytes.len() > 1_048_576 {
        return Err(invalid_context());
    }
    let value: Value = serde_json::from_slice(&bytes).map_err(|_| invalid_context())?;
    if !value.is_object() {
        return Err(invalid_context());
    }
    Ok(Some(value))
}

pub(super) fn resolve_endpoint(env: &EnvMap, cwd: &Path) -> Result<String, CliError> {
    let config_dir = if let Some(config) = env_value(env, "DOCKER_CONFIG") {
        PathBuf::from(config)
    } else {
        let home_variable = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
        let home = env_value(env, home_variable)
            .map(PathBuf::from)
            .or_else(|| directories::BaseDirs::new().map(|dirs| dirs.home_dir().to_path_buf()))
            .ok_or_else(invalid_context)?;
        home.join(".docker")
    };
    let config_dir = if config_dir.is_absolute() { config_dir } else { cwd.join(config_dir) };
    // Context selection overrides DOCKER_HOST in the documented CLI contract.
    // Local invocations are pinned with an explicit --host after validation.
    let context = if let Some(context) = env_value(env, "DOCKER_CONTEXT") {
        context.to_owned()
    } else if let Some(host) = env_value(env, "DOCKER_HOST") {
        return Ok(host.to_owned());
    } else {
        match read_config(&config_dir.join("config.json"))? {
            None => String::new(),
            Some(config) => match config.get("currentContext") {
                None | Some(Value::Null) => String::new(),
                Some(Value::String(name)) => name.clone(),
                Some(_) => return Err(invalid_context()),
            },
        }
    };
    if context.is_empty() || context == "default" {
        if let Some(host) = env_value(env, "DOCKER_HOST") {
            return Ok(host.to_owned());
        }
        return Ok(if env_value(env, "DOCKER_TLS").is_some()
            || env_value(env, "DOCKER_TLS_VERIFY").is_some()
        {
            "tcp://localhost:2376"
        } else if cfg!(windows) {
            "npipe:////./pipe/docker_engine"
        } else {
            "unix:///var/run/docker.sock"
        }
        .to_owned());
    }
    let id = data_encoding::HEXLOWER.encode(&Sha256::digest(context.as_bytes()));
    let metadata = read_config(&config_dir.join("contexts/meta").join(id).join("meta.json"))?
        .ok_or_else(invalid_context)?;
    if metadata.get("Name").and_then(Value::as_str) != Some(context.as_str()) {
        return Err(invalid_context());
    }
    metadata
        .pointer("/Endpoints/docker/Host")
        .and_then(Value::as_str)
        .filter(|host| !host.is_empty())
        .map(str::to_owned)
        .ok_or_else(invalid_context)
}

pub(super) fn validate_destination_arguments(argv: &[String]) -> Result<(), CliError> {
    // Docker and its Compose plugin parse global flags only before the first
    // subcommand (cli/cobra.go HandleGlobalFlags, SetInterspersed(false)).
    // Require the helper's fixed prefix so no caller-supplied global option can
    // override the checked destination. Later flags belong to the subcommand
    // or container, including container options named --host or --context.
    if argv.first().map(String::as_str) != Some("docker")
        || !matches!(argv.get(1).map(String::as_str), Some("run" | "compose"))
    {
        return Err(metadata_invalid_error(
            "Docker helpers require 'docker run' or 'docker compose' before pass-through arguments. Global Docker destination flags are not supported; explicitly inherit DOCKER_HOST or DOCKER_CONTEXT in the policy instead.",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_env(config: &Path) -> EnvMap {
        EnvMap::from([("DOCKER_CONFIG".into(), locket_exec::env_value(config.to_string_lossy()))])
    }

    fn save_context(config: &Path, name: &str, metadata: &str) -> std::io::Result<PathBuf> {
        let id = data_encoding::HEXLOWER.encode(&Sha256::digest(name.as_bytes()));
        let directory = config.join("contexts/meta").join(id);
        std::fs::create_dir_all(&directory)?;
        let path = directory.join("meta.json");
        std::fs::write(&path, metadata)?;
        Ok(path)
    }

    #[test]
    fn endpoint_selection_uses_context_host_saved_context_and_platform_default()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let config = directory.path();
        save_context(
            config,
            "saved",
            r#"{"Name":"saved","Endpoints":{"docker":{"Host":"ssh://saved"}}}"#,
        )?;
        save_context(
            config,
            "selected",
            r#"{"Name":"selected","Endpoints":{"docker":{"Host":"unix:///selected.sock"}}}"#,
        )?;
        std::fs::write(config.join("config.json"), r#"{"currentContext":"saved"}"#)?;
        let mut env = fixture_env(config);
        assert_eq!(resolve_endpoint(&env, config)?, "ssh://saved");
        env.insert("DOCKER_HOST".into(), locket_exec::env_value("tcp://host:2376"));
        assert_eq!(resolve_endpoint(&env, config)?, "tcp://host:2376");
        env.insert("DOCKER_CONTEXT".into(), locket_exec::env_value("selected"));
        assert_eq!(resolve_endpoint(&env, config)?, "unix:///selected.sock");
        env.insert("DOCKER_CONTEXT".into(), locket_exec::env_value("default"));
        assert_eq!(resolve_endpoint(&env, config)?, "tcp://host:2376");
        env.remove("DOCKER_HOST");
        assert_eq!(
            resolve_endpoint(&env, config)?,
            if cfg!(windows) {
                "npipe:////./pipe/docker_engine"
            } else {
                "unix:///var/run/docker.sock"
            }
        );
        for name in ["DOCKER_TLS", "DOCKER_TLS_VERIFY"] {
            env.insert(name.into(), locket_exec::env_value("1"));
            assert_eq!(resolve_endpoint(&env, config)?, "tcp://localhost:2376");
            env.remove(name);
        }
        Ok(())
    }

    #[test]
    fn malformed_or_oversized_config_and_missing_context_fail_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let config = directory.path();
        let env = fixture_env(config);
        for contents in [
            "not json",
            "[]",
            "null",
            "1",
            r#"{"currentContext":42}"#,
            r#"{"currentContext":"missing"}"#,
        ] {
            std::fs::write(config.join("config.json"), contents)?;
            assert!(resolve_endpoint(&env, config).is_err(), "invalid config {contents}");
        }
        std::fs::write(config.join("config.json"), vec![b' '; 1_048_577])?;
        assert!(resolve_endpoint(&env, config).is_err());
        std::fs::write(config.join("config.json"), r#"{"currentContext":"selected"}"#)?;
        for contents in [
            "[]",
            r#"{"Name":"other","Endpoints":{"docker":{"Host":"unix:///socket"}}}"#,
            r#"{"Name":"selected","Endpoints":{"docker":{"Host":""}}}"#,
            r#"{"Name":"selected","Endpoints":{"docker":{"Host":5}}}"#,
            r#"{"Name":"selected","Endpoints":{}}"#,
        ] {
            save_context(config, "selected", contents)?;
            assert!(resolve_endpoint(&env, config).is_err());
        }
        let path = save_context(config, "selected", "{}")?;
        std::fs::write(path, vec![b' '; 1_048_577])?;
        assert!(resolve_endpoint(&env, config).is_err());
        Ok(())
    }

    #[test]
    fn config_path_uses_final_home_and_resolves_relative_to_child_cwd()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let home = directory.path().join("child-home");
        let config = home.join(".docker");
        std::fs::create_dir_all(&config)?;
        save_context(
            &config,
            "selected",
            r#"{"Name":"selected","Endpoints":{"docker":{"Host":"unix:///child.sock"}}}"#,
        )?;
        std::fs::write(config.join("config.json"), r#"{"currentContext":"selected"}"#)?;
        let home_name = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
        let env =
            EnvMap::from([(home_name.into(), locket_exec::env_value(home.to_string_lossy()))]);
        assert_eq!(resolve_endpoint(&env, directory.path())?, "unix:///child.sock");
        let env = fixture_env(Path::new("child-home/.docker"));
        assert_eq!(resolve_endpoint(&env, directory.path())?, "unix:///child.sock");
        Ok(())
    }

    #[test]
    fn destination_arguments_reject_global_prefix_but_preserve_container_arguments()
    -> Result<(), CliError> {
        for flag in [
            "--host=ssh://remote",
            "--context=remote",
            "--config=elsewhere",
            "-Hssh://remote",
            "-cremote",
            "-DHssh://remote",
        ] {
            let argv = ["docker".to_owned(), flag.to_owned(), "run".to_owned(), "app".to_owned()];
            assert!(validate_destination_arguments(&argv).is_err(), "global flag {flag}");
        }
        for args in [
            vec![
                "docker",
                "run",
                "--rm",
                "-c",
                "1024",
                "alpine",
                "curl",
                "--host",
                "container-host",
                "-Hheader",
            ],
            vec![
                "docker",
                "compose",
                "run",
                "web",
                "tool",
                "--context=container",
                "--config=app.json",
            ],
        ] {
            validate_destination_arguments(
                &args.into_iter().map(str::to_owned).collect::<Vec<_>>(),
            )?;
        }
        Ok(())
    }
}
