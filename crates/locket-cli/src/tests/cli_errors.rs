#[allow(unused_imports)]
use super::*;

#[test]
fn cli_error_exit_codes_follow_reserved_spec_ranges() {
    assert_eq!(crate::CliError::Config("bad input".to_owned()).exit_code(), 64);
    assert_eq!(crate::CliError::ChildExit(42).exit_code(), 42);
    assert_eq!(
        crate::CliError::Crypto(locket_crypto::CryptoError::InvalidSecretValue).exit_code(),
        64
    );
    assert_eq!(
        crate::CliError::Crypto(locket_crypto::CryptoError::InvalidWrappedKey).exit_code(),
        90
    );
    assert_eq!(
        crate::CliError::Store(locket_store::StoreError::UnsupportedSchema {
            found: 2,
            supported: 1,
        })
        .exit_code(),
        92
    );
    assert_eq!(
        crate::CliError::Store(locket_store::StoreError::AuditIntegrity {
            sequence: 1,
            reason: "row hmac mismatch".to_owned(),
        })
        .exit_code(),
        93
    );
    assert_eq!(
        crate::CliError::Platform(locket_platform::PlatformError::MasterKeyNotFound).exit_code(),
        72
    );
    assert_eq!(
        crate::CliError::Platform(locket_platform::PlatformError::LocalUserVerificationFailed)
            .exit_code(),
        74
    );
    assert_eq!(
        crate::CliError::Platform(locket_platform::PlatformError::InvalidPassphrase).exit_code(),
        72
    );
}

#[test]
fn exec_prepare_environment_conflict_exits_66() -> Result<(), Box<dyn std::error::Error>> {
    let mut request = locket_exec::ExecutionRequest::strict(vec!["tool".to_owned()]);
    request.external_env =
        std::iter::once(("DATABASE_URL".to_owned(), "external".to_owned())).collect();
    request.locket_env =
        std::iter::once(("DATABASE_URL".to_owned(), "locket".to_owned())).collect();
    request.override_mode = locket_exec::EnvOverrideMode::Error;

    let Err(error) =
        locket_exec::prepare_execution(&request).map_err(crate::runtime::error::exec_prepare_error)
    else {
        return Err("environment conflict should fail before spawn".into());
    };

    assert_eq!(error.exit_code(), 66);
    assert!(error.to_string().contains("environment variable conflict"));
    Ok(())
}

#[test]
fn secret_deleted_errors_exit_76() {
    let error = crate::secret_deleted_error("secret source is deleted");

    assert_eq!(error.exit_code(), 76);
    assert_eq!(error.to_string(), "secret source is deleted");
}

#[test]
fn project_root_untrusted_exits_71() {
    let error = crate::project_root_untrusted_error();

    assert_eq!(error.exit_code(), 71);
    assert!(error.to_string().contains("ProjectRootNotTrusted"));
}

#[test]
fn exec_passthrough_preserves_child_exit_code() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    let args = test_secret_write_args("DATABASE_URL");
    crate::set_secret_value(&context, &args, "postgres://localhost/app", "manual", 1_000)?;

    let mut exec_output = Vec::new();
    let result = run_with_context(
        Cli::try_parse_from([
            "locket",
            "exec",
            "--secret",
            "DATABASE_URL",
            "--",
            "/bin/sh",
            "-c",
            "exit 7",
        ])?,
        &context,
        &mut exec_output,
    );

    let Err(error) = result else {
        return Err("exec should return the child exit status as an error".into());
    };
    assert_eq!(error.exit_code(), 7);
    assert!(matches!(error, crate::CliError::ChildExit(7)));
    Ok(())
}
