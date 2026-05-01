//! Docker and Compose helpers for Locket.

// age 0.11 enters through locket-core and carries older transitive crates
// alongside workspace versions. The sealed-bundle dependency owns that skew.
#![allow(clippy::multiple_crate_versions)]

use locket_core::EnvMap;
use thiserror::Error;

/// Default policy for remote Docker contexts.
pub const DEFAULT_ALLOW_REMOTE_DOCKER: bool = false;

/// Docker endpoint class for local-secret injection policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DockerContextClass {
    /// Local Docker daemon or platform pipe/socket.
    Local,
    /// Remote Docker endpoint such as TCP or SSH.
    Remote,
    /// Endpoint could not be classified from available metadata.
    Unknown,
}

/// Docker helper delivery mode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DockerDeliveryMode {
    /// Values stay in the Docker client process environment and Docker receives
    /// only variable names as command-line flags.
    EnvironmentNames,
    /// Values are written to an ephemeral env file by a higher layer.
    EphemeralEnvFile,
}

/// Prepared Docker invocation metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DockerInjectionPlan {
    /// Original Docker argv plus safe env-name flags.
    pub argv: Vec<String>,
    /// Environment supplied to the Docker or Compose client process.
    pub env: EnvMap,
    /// Secret names injected into `env`.
    pub injected_names: Vec<String>,
    /// Delivery mode used by the helper.
    pub delivery_mode: DockerDeliveryMode,
    /// Classified Docker endpoint.
    pub context_class: DockerContextClass,
}

/// Error returned while preparing Docker/Compose injection.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum DockerError {
    /// The target Docker context is remote and policy did not allow it.
    #[error("remote Docker context is not allowed for secret injection")]
    RemoteContextDenied,
    /// No Docker or Compose argv was supplied.
    #[error("empty Docker command")]
    EmptyCommand,
    /// The argv does not look like the expected Docker command family.
    #[error("unexpected Docker command: {program}")]
    UnexpectedCommand {
        /// First argv element.
        program: String,
    },
}

/// Classifies a Docker endpoint string such as `DOCKER_HOST`.
///
/// Missing endpoint information is treated as local because the Docker CLI
/// defaults to the platform-local socket/pipe.
#[must_use]
pub fn classify_docker_endpoint(endpoint: Option<&str>) -> DockerContextClass {
    let Some(endpoint) = endpoint.filter(|value| !value.trim().is_empty()) else {
        return DockerContextClass::Local;
    };
    let normalized = endpoint.trim().to_ascii_lowercase();
    if normalized.starts_with("unix://")
        || normalized.starts_with("npipe://")
        || normalized.starts_with("fd://")
    {
        DockerContextClass::Local
    } else if normalized.starts_with("tcp://")
        || normalized.starts_with("ssh://")
        || normalized.starts_with("http://")
        || normalized.starts_with("https://")
    {
        DockerContextClass::Remote
    } else {
        DockerContextClass::Unknown
    }
}

/// Prepares a `docker run` invocation so Docker reads secrets from its own
/// process environment by name.
///
/// Secret values are placed only in the returned environment map. The returned
/// argv contains `--env KEY` pairs, never `KEY=value`.
///
/// # Errors
///
/// Returns [`DockerError::EmptyCommand`] for empty argv,
/// [`DockerError::UnexpectedCommand`] when the command is not `docker`, and
/// [`DockerError::RemoteContextDenied`] when a remote endpoint is detected
/// without explicit policy permission.
pub fn prepare_docker_run(
    argv: &[String],
    base_env: &EnvMap,
    locket_env: &EnvMap,
    endpoint: Option<&str>,
    allow_remote: bool,
) -> Result<DockerInjectionPlan, DockerError> {
    validate_remote(endpoint, allow_remote)?;
    validate_program(argv, "docker")?;
    validate_subcommand(argv, "run")?;

    let mut prepared_argv = Vec::with_capacity(argv.len() + locket_env.len() * 2);
    prepared_argv.extend(argv.iter().take(2).cloned());
    let injected_names = sorted_names(locket_env);
    for name in &injected_names {
        prepared_argv.push("--env".to_owned());
        prepared_argv.push(name.clone());
    }
    prepared_argv.extend(argv.iter().skip(2).cloned());

    Ok(DockerInjectionPlan {
        argv: prepared_argv,
        env: merged_env(base_env, locket_env),
        injected_names,
        delivery_mode: DockerDeliveryMode::EnvironmentNames,
        context_class: classify_docker_endpoint(endpoint),
    })
}

/// Prepares a Docker Compose invocation by injecting values into the Compose
/// client process environment.
///
/// # Errors
///
/// Returns [`DockerError::EmptyCommand`] for empty argv,
/// [`DockerError::UnexpectedCommand`] when the command is not `docker`, and
/// [`DockerError::RemoteContextDenied`] when a remote endpoint is detected
/// without explicit policy permission.
pub fn prepare_compose(
    argv: &[String],
    base_env: &EnvMap,
    locket_env: &EnvMap,
    endpoint: Option<&str>,
    allow_remote: bool,
) -> Result<DockerInjectionPlan, DockerError> {
    validate_remote(endpoint, allow_remote)?;
    validate_program(argv, "docker")?;
    validate_subcommand(argv, "compose")?;
    let injected_names = sorted_names(locket_env);

    Ok(DockerInjectionPlan {
        argv: argv.to_vec(),
        env: merged_env(base_env, locket_env),
        injected_names,
        delivery_mode: DockerDeliveryMode::EnvironmentNames,
        context_class: classify_docker_endpoint(endpoint),
    })
}

fn validate_remote(endpoint: Option<&str>, allow_remote: bool) -> Result<(), DockerError> {
    if classify_docker_endpoint(endpoint) == DockerContextClass::Remote && !allow_remote {
        return Err(DockerError::RemoteContextDenied);
    }
    Ok(())
}

fn validate_program(argv: &[String], expected: &str) -> Result<(), DockerError> {
    let Some(program) = argv.first() else {
        return Err(DockerError::EmptyCommand);
    };
    if program != expected {
        return Err(DockerError::UnexpectedCommand { program: program.clone() });
    }
    Ok(())
}

fn validate_subcommand(argv: &[String], expected: &str) -> Result<(), DockerError> {
    let Some(subcommand) = argv.get(1) else {
        return Err(DockerError::UnexpectedCommand { program: argv[0].clone() });
    };
    if subcommand != expected {
        return Err(DockerError::UnexpectedCommand {
            program: format!("{} {subcommand}", argv[0]),
        });
    }
    Ok(())
}

fn merged_env(base_env: &EnvMap, locket_env: &EnvMap) -> EnvMap {
    let mut env = base_env.clone();
    env.extend(locket_env.clone());
    env
}

fn sorted_names(locket_env: &EnvMap) -> Vec<String> {
    locket_env.keys().cloned().collect()
}

#[cfg(test)]
mod tests {
    use super::{
        DockerContextClass, DockerDeliveryMode, DockerError, classify_docker_endpoint,
        prepare_compose, prepare_docker_run,
    };
    use locket_core::EnvMap;

    fn env(values: &[(&str, &str)]) -> EnvMap {
        values
            .iter()
            .map(|(name, value)| ((*name).to_owned(), locket_core::env_value(*value)))
            .collect()
    }

    #[test]
    fn classifies_local_and_remote_endpoints() {
        assert_eq!(classify_docker_endpoint(None), DockerContextClass::Local);
        assert_eq!(classify_docker_endpoint(Some("   ")), DockerContextClass::Local);
        assert_eq!(
            classify_docker_endpoint(Some("unix:///var/run/docker.sock")),
            DockerContextClass::Local
        );
        assert_eq!(
            classify_docker_endpoint(Some("npipe:////./pipe/docker_engine")),
            DockerContextClass::Local
        );
        assert_eq!(
            classify_docker_endpoint(Some("tcp://example.com:2376")),
            DockerContextClass::Remote
        );
        assert_eq!(classify_docker_endpoint(Some("ssh://builder")), DockerContextClass::Remote);
        assert_eq!(
            classify_docker_endpoint(Some("HTTPS://builder.example")),
            DockerContextClass::Remote
        );
        assert_eq!(classify_docker_endpoint(Some("desktop-linux")), DockerContextClass::Unknown);
    }

    #[test]
    fn docker_run_uses_env_names_without_values_in_argv() -> Result<(), DockerError> {
        let argv = vec!["docker".to_owned(), "run".to_owned(), "postgres".to_owned()];
        let locket_env = env(&[("DATABASE_URL", "postgres://secret"), ("API_KEY", "hidden")]);

        let plan = prepare_docker_run(&argv, &EnvMap::new(), &locket_env, None, false)?;

        assert_eq!(plan.delivery_mode, DockerDeliveryMode::EnvironmentNames);
        assert_eq!(plan.injected_names, ["API_KEY", "DATABASE_URL"]);
        assert_eq!(
            plan.env.get("DATABASE_URL").map(|value| value.as_str()),
            Some("postgres://secret")
        );
        assert!(plan.argv.windows(2).any(|pair| pair == ["--env", "API_KEY"]));
        assert!(plan.argv.windows(2).any(|pair| pair == ["--env", "DATABASE_URL"]));
        assert!(!plan.argv.iter().any(|item| item.contains("postgres://secret")));
        assert!(!plan.argv.iter().any(|item| item.contains("hidden")));
        Ok(())
    }

    #[test]
    fn compose_injects_environment_without_adding_env_flags() -> Result<(), DockerError> {
        let argv = vec!["docker".to_owned(), "compose".to_owned(), "up".to_owned()];
        let base_env = env(&[("PATH", "/bin")]);
        let locket_env = env(&[("DATABASE_URL", "postgres://secret")]);

        let plan = prepare_compose(&argv, &base_env, &locket_env, None, false)?;

        assert_eq!(plan.argv, argv);
        assert_eq!(plan.env.get("PATH").map(|value| value.as_str()), Some("/bin"));
        assert_eq!(
            plan.env.get("DATABASE_URL").map(|value| value.as_str()),
            Some("postgres://secret")
        );
        assert_eq!(plan.injected_names, ["DATABASE_URL"]);
        Ok(())
    }

    #[test]
    fn remote_context_requires_explicit_policy() {
        let argv = vec!["docker".to_owned(), "run".to_owned(), "app".to_owned()];
        let result = prepare_docker_run(
            &argv,
            &EnvMap::new(),
            &EnvMap::new(),
            Some("tcp://host:2376"),
            false,
        );

        assert_eq!(result, Err(DockerError::RemoteContextDenied));
    }

    #[test]
    fn allowed_remote_context_is_recorded_in_plan() -> Result<(), DockerError> {
        let argv = vec!["docker".to_owned(), "run".to_owned(), "app".to_owned()];

        let plan =
            prepare_docker_run(&argv, &EnvMap::new(), &EnvMap::new(), Some("ssh://builder"), true)?;

        assert_eq!(plan.context_class, DockerContextClass::Remote);
        Ok(())
    }

    #[test]
    fn locket_environment_overrides_base_environment() -> Result<(), DockerError> {
        let argv =
            vec!["docker".to_owned(), "compose".to_owned(), "run".to_owned(), "app".to_owned()];
        let base_env = env(&[("TOKEN", "base"), ("PATH", "/bin")]);
        let locket_env = env(&[("TOKEN", "locket")]);

        let plan = prepare_compose(&argv, &base_env, &locket_env, None, false)?;

        assert_eq!(plan.env.get("TOKEN").map(|value| value.as_str()), Some("locket"));
        assert_eq!(plan.env.get("PATH").map(|value| value.as_str()), Some("/bin"));
        assert_eq!(plan.injected_names, ["TOKEN"]);
        Ok(())
    }

    #[test]
    fn docker_canary_values_stay_out_of_argv_and_metadata() -> Result<(), DockerError> {
        let canary = "lk-canary-docker-value-1234567890abcdef";
        let argv = vec!["docker".to_owned(), "run".to_owned(), "--rm".to_owned(), "app".to_owned()];
        let locket_env = env(&[("DATABASE_URL", canary), ("API_TOKEN", "safe-value")]);

        let run_plan = prepare_docker_run(&argv, &EnvMap::new(), &locket_env, None, false)?;
        let compose_plan = prepare_compose(
            &["docker".to_owned(), "compose".to_owned(), "up".to_owned()],
            &EnvMap::new(),
            &locket_env,
            None,
            false,
        )?;

        let safe_surfaces = [
            run_plan.argv.join(" "),
            run_plan.injected_names.join(","),
            compose_plan.argv.join(" "),
            compose_plan.injected_names.join(","),
        ];
        for surface in safe_surfaces {
            assert!(!surface.contains(canary));
        }
        assert_eq!(run_plan.env.get("DATABASE_URL").map(|value| value.as_str()), Some(canary));
        assert_eq!(compose_plan.env.get("DATABASE_URL").map(|value| value.as_str()), Some(canary));
        Ok(())
    }

    #[test]
    fn validates_docker_program() {
        let argv = vec!["podman".to_owned(), "run".to_owned(), "app".to_owned()];
        let result = prepare_docker_run(&argv, &EnvMap::new(), &EnvMap::new(), None, false);

        assert_eq!(result, Err(DockerError::UnexpectedCommand { program: "podman".to_owned() }));
    }

    #[test]
    fn validates_empty_docker_command() {
        let result = prepare_compose(&[], &EnvMap::new(), &EnvMap::new(), None, false);

        assert_eq!(result, Err(DockerError::EmptyCommand));
    }
}
