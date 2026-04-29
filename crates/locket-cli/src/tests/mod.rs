use clap::Parser;
use locket_platform::{
    MasterKeyStore, MemoryMasterKeyStore, PassphraseFallbackMasterKeyStore, PlatformError,
};
use serde_json::json;
use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command as TestCommand;
use std::sync::Arc;
use tempfile::tempdir;

use super::{Cli, RuntimeContext, run_with_context};

#[derive(Debug)]
struct StaticPassphraseReader {
    passphrase: String,
}

impl StaticPassphraseReader {
    fn new(passphrase: &str) -> Self {
        Self { passphrase: passphrase.to_owned() }
    }
}

impl super::PassphraseReader for StaticPassphraseReader {
    fn existing_passphrase(&self) -> Result<zeroize::Zeroizing<String>, super::CliError> {
        Ok(zeroize::Zeroizing::new(self.passphrase.clone()))
    }

    fn new_passphrase(&self) -> Result<zeroize::Zeroizing<String>, super::CliError> {
        Ok(zeroize::Zeroizing::new(self.passphrase.clone()))
    }
}

#[derive(Debug)]
struct StaticRecoveryCodeReader {
    code: String,
}

impl StaticRecoveryCodeReader {
    fn new(code: &str) -> Self {
        Self { code: code.to_owned() }
    }
}

impl super::RecoveryCodeReader for StaticRecoveryCodeReader {
    fn read_recovery_code(
        &self,
        _prompt: &str,
    ) -> Result<zeroize::Zeroizing<String>, super::CliError> {
        Ok(zeroize::Zeroizing::new(self.code.clone()))
    }
}

#[derive(Debug)]
struct StaticConfirmationReader {
    confirmation: String,
    init_confirmation: Option<String>,
}

impl StaticConfirmationReader {
    fn new(confirmation: &str) -> Self {
        Self { confirmation: confirmation.to_owned(), init_confirmation: Some("app\n".to_owned()) }
    }
}

impl super::ConfirmationReader for StaticConfirmationReader {
    fn read_confirmation(&self, prompt: &str) -> Result<String, super::CliError> {
        if prompt == "init recovery code"
            && let Some(confirmation) = &self.init_confirmation
        {
            return Ok(confirmation.clone());
        }
        Ok(self.confirmation.clone())
    }
}

#[derive(Debug)]
struct StaticSecretValueReader {
    value: String,
}

impl StaticSecretValueReader {
    fn new(value: &str) -> Self {
        Self { value: value.to_owned() }
    }
}

impl super::SecretValueReader for StaticSecretValueReader {
    fn read_secret_value(
        &self,
        _prompt: &str,
    ) -> Result<zeroize::Zeroizing<String>, super::CliError> {
        super::validate_secret_value(zeroize::Zeroizing::new(self.value.clone()))
    }
}

#[derive(Debug)]
struct FailingSecretValueReader;

impl super::SecretValueReader for FailingSecretValueReader {
    fn read_secret_value(
        &self,
        _prompt: &str,
    ) -> Result<zeroize::Zeroizing<String>, super::CliError> {
        Err(super::CliError::Config("secret reader was called".to_owned()))
    }
}

#[derive(Debug, Default)]
struct UnavailableMasterKeyStore;

impl MasterKeyStore for UnavailableMasterKeyStore {
    fn store_master_key(
        &self,
        _project_id: &str,
        _master_key: &locket_crypto::KeyBytes,
    ) -> Result<(), PlatformError> {
        Err(PlatformError::MasterKeyNotFound)
    }

    fn load_master_key(
        &self,
        _project_id: &str,
    ) -> Result<zeroize::Zeroizing<locket_crypto::KeyBytes>, PlatformError> {
        Err(PlatformError::MasterKeyNotFound)
    }

    fn delete_master_key(&self, _project_id: &str) -> Result<(), PlatformError> {
        Ok(())
    }
}

#[derive(Debug, Default)]
struct StaleLoadingMasterKeyStore;

impl MasterKeyStore for StaleLoadingMasterKeyStore {
    fn store_master_key(
        &self,
        _project_id: &str,
        _master_key: &locket_crypto::KeyBytes,
    ) -> Result<(), PlatformError> {
        Ok(())
    }

    fn load_master_key(
        &self,
        _project_id: &str,
    ) -> Result<zeroize::Zeroizing<locket_crypto::KeyBytes>, PlatformError> {
        Ok(zeroize::Zeroizing::new([99; locket_crypto::KEY_LEN]))
    }

    fn delete_master_key(&self, _project_id: &str) -> Result<(), PlatformError> {
        Ok(())
    }
}

fn test_context(directory: &tempfile::TempDir) -> RuntimeContext {
    test_context_with_key_store(directory, Arc::new(MemoryMasterKeyStore::default()))
}

fn test_context_with_confirmation(
    directory: &tempfile::TempDir,
    confirmation: &str,
) -> RuntimeContext {
    test_context_with_key_store_and_confirmation(
        directory,
        Arc::new(MemoryMasterKeyStore::default()),
        confirmation,
    )
}

fn test_context_with_key_store(
    directory: &tempfile::TempDir,
    key_store: Arc<dyn MasterKeyStore + Send + Sync>,
) -> RuntimeContext {
    test_context_with_key_store_confirmation_and_secret(directory, key_store, "app\n", "secret")
}

fn test_context_with_key_store_and_confirmation(
    directory: &tempfile::TempDir,
    key_store: Arc<dyn MasterKeyStore + Send + Sync>,
    confirmation: &str,
) -> RuntimeContext {
    test_context_with_key_store_confirmation_and_secret(
        directory,
        key_store,
        confirmation,
        "secret",
    )
}

fn test_context_with_secret_value(
    directory: &tempfile::TempDir,
    secret_value: &str,
) -> RuntimeContext {
    test_context_with_key_store_confirmation_and_secret(
        directory,
        Arc::new(MemoryMasterKeyStore::default()),
        "app\n",
        secret_value,
    )
}

fn test_context_with_failing_secret_reader(directory: &tempfile::TempDir) -> RuntimeContext {
    let mut context = test_context(directory);
    context.secret_value_reader = Arc::new(FailingSecretValueReader);
    context
}

fn test_context_with_key_store_confirmation_and_secret(
    directory: &tempfile::TempDir,
    key_store: Arc<dyn MasterKeyStore + Send + Sync>,
    confirmation: &str,
    secret_value: &str,
) -> RuntimeContext {
    RuntimeContext {
        cwd: directory.path().to_path_buf(),
        store_path: directory.path().join("store.db"),
        config_path: directory.path().join("config.toml"),
        template_dir: directory.path().join(".locket").join("templates"),
        key_store,
        passphrase_store: PassphraseFallbackMasterKeyStore::new(
            directory.path().join("passphrase-fallback"),
        ),
        passphrase_reader: Arc::new(StaticPassphraseReader::new("test fallback passphrase")),
        recovery_code_reader: Arc::new(StaticRecoveryCodeReader::new("")),
        confirmation_reader: Arc::new(StaticConfirmationReader::new(confirmation)),
        secret_value_reader: Arc::new(StaticSecretValueReader::new(secret_value)),
    }
}

fn context_with_confirmation(context: &RuntimeContext, confirmation: &str) -> RuntimeContext {
    RuntimeContext {
        confirmation_reader: Arc::new(StaticConfirmationReader::new(confirmation)),
        ..context.clone()
    }
}

fn context_with_recovery_code(context: &RuntimeContext, code: &str) -> RuntimeContext {
    RuntimeContext {
        recovery_code_reader: Arc::new(StaticRecoveryCodeReader::new(code)),
        ..context.clone()
    }
}

fn test_secret_write_args(key: &str) -> super::SecretWriteArgs {
    super::SecretWriteArgs {
        key: key.to_owned(),
        source: super::SourceArg { source: Some(super::SecretSourceArg::UserLocal) },
        metadata: super::SecretMetadataFlags {
            description: None,
            owner: None,
            tags: Vec::new(),
            required: false,
            optional: false,
        },
    }
}

fn test_secret_write_args_for_source(
    key: &str,
    source: super::SecretSourceArg,
) -> super::SecretWriteArgs {
    let mut args = test_secret_write_args(key);
    args.source.source = Some(source);
    args
}

fn test_rotate_args(key: &str, grace_ttl: Option<&str>) -> super::RotateArgs {
    super::RotateArgs {
        key: key.to_owned(),
        source: super::SourceArg { source: Some(super::SecretSourceArg::UserLocal) },
        metadata: super::SecretMetadataFlags {
            description: None,
            owner: None,
            tags: Vec::new(),
            required: false,
            optional: false,
        },
        grace_ttl: grace_ttl.map(ToOwned::to_owned),
    }
}

fn run_git(directory: &Path, args: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
    let output = TestCommand::new("git").arg("-C").arg(directory).args(args).output()?;
    assert!(output.status.success(), "git failed: {}", String::from_utf8_lossy(&output.stderr));
    Ok(())
}

fn assert_lifecycle_audit_log(
    directory: &tempfile::TempDir,
) -> Result<(), Box<dyn std::error::Error>> {
    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let mut statement = store
        .connection()
        .prepare("SELECT action, metadata_json FROM audit_log ORDER BY sequence")?;
    let rows = statement
        .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))?
        .collect::<Result<Vec<_>, _>>()?;
    let actions = rows.iter().map(|(action, _)| action.as_str()).collect::<Vec<_>>();
    assert_eq!(
        actions,
        ["INIT", "SET", "ROTATE", "REVEAL", "PURGE", "DELETE", "PURGE", "AUDIT_VERIFY"]
    );
    for (_, metadata) in rows {
        assert!(!metadata.contains("postgres://localhost/old"));
        assert!(!metadata.contains("postgres://localhost/new"));
    }
    Ok(())
}

fn assert_error_contains<T>(result: Result<T, super::CliError>, expected: &str) {
    assert!(result.is_err(), "expected error containing {expected:?}");
    if let Err(error) = result {
        assert!(error.to_string().contains(expected), "{error}");
    }
}

#[test]
fn cli_error_exit_codes_follow_reserved_spec_ranges() {
    assert_eq!(super::CliError::Config("bad input".to_owned()).exit_code(), 64);
    assert_eq!(super::CliError::ChildExit(42).exit_code(), 42);
    assert_eq!(
        super::CliError::Crypto(locket_crypto::CryptoError::InvalidSecretValue).exit_code(),
        64
    );
    assert_eq!(
        super::CliError::Crypto(locket_crypto::CryptoError::InvalidWrappedKey).exit_code(),
        90
    );
    assert_eq!(
        super::CliError::Store(locket_store::StoreError::UnsupportedSchema {
            found: 2,
            supported: 1,
        })
        .exit_code(),
        92
    );
    assert_eq!(
        super::CliError::Store(locket_store::StoreError::AuditIntegrity {
            sequence: 1,
            reason: "row hmac mismatch".to_owned(),
        })
        .exit_code(),
        93
    );
    assert_eq!(
        super::CliError::Platform(locket_platform::PlatformError::MasterKeyNotFound).exit_code(),
        72
    );
    assert_eq!(
        super::CliError::Platform(locket_platform::PlatformError::LocalUserVerificationFailed)
            .exit_code(),
        74
    );
    assert_eq!(
        super::CliError::Platform(locket_platform::PlatformError::InvalidPassphrase).exit_code(),
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

    let Err(error) = locket_exec::prepare_execution(&request).map_err(super::exec_prepare_error)
    else {
        return Err("environment conflict should fail before spawn".into());
    };

    assert_eq!(error.exit_code(), 66);
    assert!(error.to_string().contains("environment variable conflict"));
    Ok(())
}

#[test]
fn secret_deleted_errors_exit_76() {
    let error = super::secret_deleted_error("secret source is deleted");

    assert_eq!(error.exit_code(), 76);
    assert_eq!(error.to_string(), "secret source is deleted");
}

#[test]
fn project_root_untrusted_exits_71() {
    let error = super::project_root_untrusted_error();

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
    super::set_secret_value(&context, &args, "postgres://localhost/app", "manual", 1_000)?;

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
    assert!(matches!(error, super::CliError::ChildExit(7)));
    Ok(())
}

fn recovery_code_from_output(output: &str) -> Result<&str, Box<dyn std::error::Error>> {
    output
        .lines()
        .find(|line| {
            line.len() == 38
                && line.matches('-').count() == 4
                && locket_crypto::recovery_code_decode(line).is_ok()
        })
        .ok_or_else(|| format!("missing recovery code line in output: {output:?}").into())
}

fn read_debug_bundle_json(path: &Path) -> Result<String, Box<dyn std::error::Error>> {
    let file = fs::File::open(path)?;
    let decoder = flate2::read::GzDecoder::new(file);
    let mut archive = tar::Archive::new(decoder);
    for entry in archive.entries()? {
        let mut entry = entry?;
        if entry.path()?.as_ref() == Path::new("bundle.json") {
            let mut contents = String::new();
            entry.read_to_string(&mut contents)?;
            return Ok(contents);
        }
    }
    Err("bundle.json missing from debug bundle".into())
}

#[test]
fn env_import_parser_handles_exports_quotes_comments_and_invalid_lines() {
    let entries = super::parse_env_import(
        "# ignored\n\
         export DATABASE_URL='postgres://localhost/app'\n\
         OPENAI_API_KEY=\"sk_test_sample\"\n\
         INVALID-NAME=value\n\
         MISSING_EQUALS\n\
         NULL_BYTE=bad\0value\n\
         MULTILINE=\"first\n\
         second\"\n",
    );

    assert_eq!(entries.len(), 7);
    let first = match &entries[0] {
        super::EnvImportEntry::Secret { key, value } => Some((key.as_str(), value.as_str())),
        super::EnvImportEntry::Invalid => None,
    };
    let second = match &entries[1] {
        super::EnvImportEntry::Secret { key, value } => Some((key.as_str(), value.as_str())),
        super::EnvImportEntry::Invalid => None,
    };
    assert_eq!(first, Some(("DATABASE_URL", "postgres://localhost/app")));
    assert_eq!(second, Some(("OPENAI_API_KEY", "sk_test_sample")));
    assert!(matches!(&entries[2], super::EnvImportEntry::Invalid));
    assert!(matches!(&entries[3], super::EnvImportEntry::Invalid));
    assert!(matches!(&entries[4], super::EnvImportEntry::Invalid));
    assert!(matches!(&entries[5], super::EnvImportEntry::Invalid));
    assert!(matches!(&entries[6], super::EnvImportEntry::Invalid));
}

#[test]
fn root_hash_parser_accepts_prefixed_mixed_case_hex_and_rejects_bad_input()
-> Result<(), Box<dyn std::error::Error>> {
    let parsed = super::parse_root_hash(&format!("0x{}", "Aa".repeat(32)))?;

    assert_eq!(parsed, [0xaa; 32]);
    assert_error_contains(super::parse_root_hash("abcd").map(|_| ()), "64 hex characters");
    assert_error_contains(
        super::parse_root_hash(&format!("{}0g", "00".repeat(31))).map(|_| ()),
        "hex encoded",
    );
    Ok(())
}

#[test]
fn grace_ttl_parser_handles_absent_values_caps_and_timestamp_overflow()
-> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(super::grace_until_from_args(None, 1_000)?, None);
    assert_eq!(super::grace_until_from_args(Some("24h"), 1_000)?, Some(86_400_000_001_000),);
    assert_error_contains(super::grace_until_from_args(Some("8d"), 1_000).map(|_| ()), "7d cap");
    assert!(matches!(
        super::grace_until_from_args(Some("1s"), i64::MAX - 10),
        Err(super::CliError::Time)
    ));
    Ok(())
}

#[test]
fn secret_value_reader_preserves_piped_values_and_rejects_invalid_input()
-> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        super::read_secret_value_from_reader(b"postgres://localhost/app\n".as_slice())?.as_str(),
        "postgres://localhost/app"
    );
    assert_eq!(
        super::read_secret_value_from_reader(b"postgres://localhost/app\r\n".as_slice())?.as_str(),
        "postgres://localhost/app"
    );
    assert_eq!(
        super::read_secret_value_from_reader(b"line1\nline2".as_slice())?.as_str(),
        "line1\nline2"
    );
    assert_eq!(
        super::read_secret_value_from_reader(b"line1\nline2\n".as_slice())?.as_str(),
        "line1\nline2"
    );
    assert_eq!(
        super::read_secret_value_from_reader(b"line1\nline2\n\n".as_slice())?.as_str(),
        "line1\nline2\n"
    );

    assert_error_contains(
        super::read_secret_value_from_reader(b"".as_slice()).map(|_| ()),
        "secret value cannot be empty",
    );
    assert_error_contains(
        super::read_secret_value_from_reader(b"\n".as_slice()).map(|_| ()),
        "secret value cannot be empty",
    );
    assert_error_contains(
        super::read_secret_value_from_reader(b"one\0two".as_slice()).map(|_| ()),
        "NUL bytes",
    );
    assert_error_contains(
        super::read_secret_value_from_reader(&[0xff][..]).map(|_| ()),
        "valid UTF-8",
    );
    Ok(())
}

#[test]
fn parses_bare_status() {
    let cli = Cli::try_parse_from(["locket"]);
    assert!(cli.is_ok());
}

#[test]
fn parses_core_secret_commands() {
    for args in [
        ["locket", "init", "--name", "app"].as_slice(),
        &["locket", "set", "DATABASE_URL", "--source", "user-local"],
        &["locket", "import", ".env", "--source", "user-local"],
        &["locket", "get", "DATABASE_URL", "--copy"],
        &["locket", "get", "DATABASE_URL", "--reveal", "--force"],
        &["locket", "rm", "DATABASE_URL"],
        &["locket", "purge", "DATABASE_URL", "--all-versions"],
        &["locket", "rotate", "DATABASE_URL", "--grace-ttl", "24h"],
        &["locket", "lock"],
        &["locket", "unlock", "--verify-user"],
        &["locket", "meta", "DATABASE_URL", "--owner", "platform", "--required"],
        &["locket", "history", "DATABASE_URL"],
        &["locket", "diff", "dev", "staging"],
        &[
            "locket",
            "copy",
            "DATABASE_URL",
            "--from",
            "dev",
            "--to",
            "staging",
            "--from-source",
            "user-local",
            "--to-source",
            "machine-local",
        ],
        &["locket", "audit", "verify"],
        &["locket", "recover", "--force"],
        &["locket", "recovery", "rotate"],
        &["locket", "doctor"],
        &["locket", "debug", "bundle", "--redacted"],
        &["locket", "debug", "bundle", "--redacted", "--output", "bundle.json"],
        &["locket", "exec", "--secret", "DATABASE_URL", "--", "/bin/sh", "-c", "true"],
        &["locket", "config", "list"],
        &["locket", "config", "get", "privacy.redact_names"],
        &["locket", "config", "set", "privacy.redact_names", "true"],
        &["locket", "config", "unset", "privacy.redact_names"],
        &["locket", "passkey", "register"],
        &["locket", "passkey", "list", "--all"],
        &["locket", "passkey", "remove", "work-laptop"],
        &["locket", "device", "init"],
        &["locket", "device", "init", "--force"],
        &["locket", "device", "pubkey"],
        &["locket", "device", "add", "work-laptop", "--device", "lkdev1_abc"],
        &["locket", "device", "list", "--all"],
        &["locket", "device", "remove", "work-laptop", "--force"],
        &["locket", "client", "create", "ci", "--action", "run-policy", "--policy", "dev"],
        &[
            "locket", "client", "add", "ci", "--pubkey", "00", "--action", "redact", "--policy",
            "dev",
        ],
        &["locket", "client", "list", "--all"],
        &["locket", "client", "revoke", "ci"],
        &[
            "locket",
            "export",
            "--sealed",
            "--recipient",
            "lkdev1_abc",
            "--profile",
            "dev",
            "--include-audit",
            "--output",
            "bundle.locket-bundle",
        ],
        &["locket", "import-bundle", "bundle.locket-bundle", "--accept-local"],
        &["locket", "bundle", "verify", "bundle.locket-bundle"],
        &["locket", "new", "--from-template", "basic"],
        &["locket", "bootstrap"],
        &["locket", "completion", "bash"],
    ] {
        assert!(Cli::try_parse_from(args).is_ok(), "{args:?}");
    }
}

#[test]
fn get_force_requires_reveal() {
    assert!(Cli::try_parse_from(["locket", "get", "DATABASE_URL", "--force"]).is_err());
}

#[test]
fn clipboard_command_selection_uses_first_available_candidate() {
    static COMMANDS: &[super::ClipboardCommand] = &[
        super::ClipboardCommand { program: "missing", args: &[] },
        super::ClipboardCommand { program: "present", args: &["--clipboard"] },
    ];

    let selected = super::select_clipboard_command(COMMANDS, |program| program == "present");

    assert_eq!(selected.map(|command| command.program), Some("present"));
    assert_eq!(selected.map(|command| command.args), Some(["--clipboard"].as_slice()));
}

#[test]
fn clipboard_copy_reports_unavailable_without_value_leakage()
-> Result<(), Box<dyn std::error::Error>> {
    static COMMANDS: &[super::ClipboardCommand] = &[];

    let result =
        super::copy_secret_to_clipboard_with("postgres://localhost/app", COMMANDS, |_| false);
    let error = result.err().ok_or("expected unavailable clipboard command")?;

    assert_eq!(error, "clipboard command unavailable");
    assert!(!error.contains("postgres://localhost/app"));
    Ok(())
}

#[test]
fn parses_profile_project_and_agent_commands() {
    for args in [
        ["locket", "profile", "create", "dev"].as_slice(),
        &["locket", "profile", "mark-dangerous", "prod"],
        &["locket", "project", "trust-root"],
        &["locket", "project", "list-roots"],
        &["locket", "project", "untrust-root", "abc123"],
        &["locket", "shellenv"],
        &["locket", "shellenv", "--shell", "zsh"],
        &["locket", "hook"],
        &["locket", "hook", "--install"],
        &["locket", "completion", "bash"],
        &["locket", "completion", "zsh"],
        &["locket", "completion", "fish"],
        &["locket", "completion", "elvish"],
        &["locket", "completion", "powershell"],
        &["locket", "allow"],
        &["locket", "deny"],
        &["locket", "deny", "--all"],
        &["locket", "agent", "start"],
        &["locket", "agent", "status"],
        &["locket", "agent", "stop"],
        &["locket", "agent", "logs"],
        &["locket", "agent", "logs", "--lines", "10", "--since", "1700000000"],
        &["locket", "agent", "logs", "--since", "2024-01-01T00:00:00Z"],
        &["locket", "agent", "logs", "--follow"],
        &["locket", "doctor"],
        &["locket", "debug", "bundle", "--redacted"],
        &["locket", "policy", "add", "dev", "--", "pnpm", "dev"],
        &["locket", "policy", "allow", "dev", "DATABASE_URL"],
        &["locket", "policy", "require", "dev", "API_KEY"],
        &["locket", "policy", "delete", "dev", "--yes"],
        &["locket", "policy", "doctor"],
    ] {
        assert!(Cli::try_parse_from(args).is_ok(), "{args:?}");
    }
}

#[test]
fn parses_scan_and_redaction_commands() {
    for args in [
        ["locket", "scan", "--staged", "--require-known"].as_slice(),
        &["locket", "redact", "--stdin", "--redact-names"],
        &["locket", "context", "--redact-names"],
        &["locket", "ai-safe", "--pattern-only", "--", "npm", "test"],
        &["locket", "install-hooks"],
    ] {
        assert!(Cli::try_parse_from(args).is_ok(), "{args:?}");
    }
}

#[test]
fn completion_command_generates_scripts_without_project() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();

    run_with_context(
        Cli::try_parse_from(["locket", "completion", "bash"])?,
        &context,
        &mut output,
    )?;

    let output = String::from_utf8(output)?;
    assert!(output.contains("_locket()"));
    assert!(output.contains("complete -F _locket"));
    assert!(output.contains("completion"));
    assert!(!directory.path().join("locket.toml").exists());
    Ok(())
}

#[test]
fn client_add_list_and_revoke_are_metadata_only() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    run_with_context(
        Cli::try_parse_from(["locket", "policy", "add", "ci", "--", "cargo", "test"])?,
        &context,
        &mut Vec::new(),
    )?;
    let public_key = "11".repeat(32);
    let mut add_output = Vec::new();
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "client",
            "add",
            "ci_bot",
            "--pubkey",
            &public_key,
            "--action",
            "run-policy",
            "--action",
            "redact",
            "--policy",
            "ci",
        ])?,
        &context,
        &mut add_output,
    )?;

    let add_output = String::from_utf8(add_output)?;
    assert!(add_output.contains("client: ci_bot"));
    assert!(add_output.contains("private_key_material: never displayed"));
    assert!(!add_output.contains(&public_key));

    let mut list_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "client", "list"])?,
        &context,
        &mut list_output,
    )?;
    let list_output = String::from_utf8(list_output)?;
    assert!(list_output.contains("ci_bot"));
    assert!(list_output.contains("actions=redact,run-policy"));
    assert!(list_output.contains("policies=ci"));
    assert!(list_output.contains("private_key_material: never displayed"));
    assert!(!list_output.contains(&public_key));

    let mut revoke_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "client", "revoke", "ci_bot"])?,
        &context,
        &mut revoke_output,
    )?;
    let revoke_output = String::from_utf8(revoke_output)?;
    assert!(revoke_output.contains("revoked_at:"));

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let resolved = super::resolve_project(&context.cwd)?.ok_or("project should resolve")?;
    assert!(store.list_automation_clients(resolved.config.project_id.as_str(), false)?.is_empty());
    assert!(
        store.list_automation_clients(resolved.config.project_id.as_str(), true)?[0]
            .revoked_at
            .is_some()
    );
    let mut statement = store
        .connection()
        .prepare("SELECT action, metadata_json FROM audit_log ORDER BY sequence")?;
    let rows = statement
        .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))?
        .collect::<Result<Vec<_>, _>>()?;
    assert!(rows.iter().any(|(action, _)| action == "CLIENT_ADD"));
    assert!(rows.iter().any(|(action, _)| action == "CLIENT_REVOKE"));
    for (_, metadata) in rows {
        assert!(!metadata.contains(&public_key));
    }
    Ok(())
}

#[test]
fn client_rejects_unsupported_actions_and_missing_policies()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    let public_key = "22".repeat(32);
    assert_error_contains(
        run_with_context(
            Cli::try_parse_from([
                "locket",
                "client",
                "add",
                "ci_bot",
                "--pubkey",
                &public_key,
                "--action",
                "reveal",
                "--policy",
                "ci",
            ])?,
            &context,
            &mut Vec::new(),
        ),
        "InvalidPolicy",
    );
    assert_error_contains(
        run_with_context(
            Cli::try_parse_from([
                "locket",
                "client",
                "add",
                "ci_bot",
                "--pubkey",
                &public_key,
                "--action",
                "run-policy",
            ])?,
            &context,
            &mut Vec::new(),
        ),
        "at least one --policy",
    );
    Ok(())
}

#[test]
#[allow(clippy::too_many_lines)]
fn sealed_bundle_export_verify_and_import_are_metadata_only()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    let args = test_secret_write_args("DATABASE_URL");
    super::set_secret_value(&context, &args, "postgres://bundle-secret", "manual", 1_000)?;

    let mut device_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "device", "init"])?,
        &context,
        &mut device_output,
    )?;
    let descriptor = String::from_utf8(device_output)?
        .lines()
        .find_map(|line| line.strip_prefix("descriptor: "))
        .ok_or("missing descriptor")?
        .to_owned();
    let bundle_path = directory.path().join("dev.locket-bundle");

    let mut export_output = Vec::new();
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "export",
            "--sealed",
            "--recipient",
            &descriptor,
            "--profile",
            "dev",
            "--include-audit",
            "--output",
            bundle_path.to_str().ok_or("utf8 path")?,
        ])?,
        &context,
        &mut export_output,
    )?;
    let export_output = String::from_utf8(export_output)?;
    assert!(export_output.contains("bundle: exported"));
    assert!(export_output.contains("active_secret_count: 1"));
    assert!(export_output.contains("metadata_only: yes"));
    let bundle_text = fs::read_to_string(&bundle_path)?;
    assert!(bundle_text.contains("LOCKET-BUNDLE-V1"));
    assert!(!bundle_text.contains("postgres://bundle-secret"));
    assert!(!bundle_text.contains("DATABASE_URL"));

    let mut verify_output = Vec::new();
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "bundle",
            "verify",
            bundle_path.to_str().ok_or("utf8 path")?,
        ])?,
        &context,
        &mut verify_output,
    )?;
    let verify_output = String::from_utf8(verify_output)?;
    assert!(verify_output.contains("bundle: valid"));
    assert!(verify_output.contains("decryptable_by_this_device: no"));

    let mut import_output = Vec::new();
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "import-bundle",
            bundle_path.to_str().ok_or("utf8 path")?,
            "--accept-local",
            "--include-audit",
        ])?,
        &context,
        &mut import_output,
    )?;
    let import_output = String::from_utf8(import_output)?;
    assert!(import_output.contains("bundle: verified"));
    assert!(import_output.contains("import: not_applied"));
    assert!(import_output.contains("metadata_only: yes"));

    assert_error_contains(
        run_with_context(
            Cli::try_parse_from([
                "locket",
                "export",
                "--sealed",
                "--recipient",
                &descriptor,
                "--profile",
                "dev",
                "--output",
                bundle_path.to_str().ok_or("utf8 path")?,
            ])?,
            &context,
            &mut Vec::new(),
        ),
        "bundle output already exists",
    );

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let mut statement = store
        .connection()
        .prepare("SELECT action, metadata_json FROM audit_log ORDER BY sequence")?;
    let rows = statement
        .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))?
        .collect::<Result<Vec<_>, _>>()?;
    assert!(rows.iter().any(|(action, _)| action == "BACKUP_EXPORT"));
    assert!(rows.iter().any(|(action, _)| action == "BACKUP_IMPORT"));
    for (_, metadata) in rows {
        assert!(!metadata.contains("postgres://bundle-secret"));
    }
    Ok(())
}

#[test]
fn bundle_verify_rejects_tampered_digest() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    let mut device_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "device", "init"])?,
        &context,
        &mut device_output,
    )?;
    let descriptor = String::from_utf8(device_output)?
        .lines()
        .find_map(|line| line.strip_prefix("descriptor: "))
        .ok_or("missing descriptor")?
        .to_owned();
    let bundle_path = directory.path().join("tampered.locket-bundle");
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "export",
            "--sealed",
            "--recipient",
            &descriptor,
            "--output",
            bundle_path.to_str().ok_or("utf8 path")?,
        ])?,
        &context,
        &mut Vec::new(),
    )?;
    let tampered = fs::read_to_string(&bundle_path)?.replacen(
        "\"active_secret_count\": 0",
        "\"active_secret_count\": 1",
        1,
    );
    fs::write(&bundle_path, tampered)?;
    let result = run_with_context(
        Cli::try_parse_from([
            "locket",
            "bundle",
            "verify",
            bundle_path.to_str().ok_or("utf8 path")?,
        ])?,
        &context,
        &mut Vec::new(),
    );
    assert_error_contains(result, "manifest digest mismatch");
    assert_eq!(super::CliError::BundleVerification("failed".to_owned()).exit_code(), 110);
    Ok(())
}

#[test]
fn status_reports_not_initialized_without_project() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();

    run_with_context(Cli::try_parse_from(["locket"])?, &context, &mut output)?;

    let output = String::from_utf8(output)?;
    assert!(output.contains("not initialized"));
    assert!(output.contains("next_action: run locket init"));
    Ok(())
}

#[test]
fn status_reports_metadata_summary_and_next_action() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut init_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut init_output,
    )?;

    std::fs::write(directory.path().join("leak.txt"), "token=sk_test_sampleTokenValue123\n")?;
    let resolved = super::resolve_project(&context.cwd)?.ok_or("project should resolve")?;
    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let profile = store
        .get_profile_by_name(resolved.config.project_id.as_str(), "dev")?
        .ok_or("default profile should exist")?;
    store.insert_runtime_session(&locket_store::RuntimeSessionRecord {
        id: "lk_sess_status".to_owned(),
        project_id: resolved.config.project_id.to_string(),
        profile_id: profile.id,
        policy_name: Some("dev".to_owned()),
        process_id: 42,
        process_start_time: 900,
        started_at: 1_000,
        ended_at: None,
        exit_status: None,
        secret_names: vec!["API_KEY".to_owned()],
        spawn_audit_sequence: None,
        completion_audit_sequence: None,
    })?;

    let mut output = Vec::new();
    run_with_context(Cli::try_parse_from(["locket", "status"])?, &context, &mut output)?;

    let output = String::from_utf8(output)?;
    assert!(output.contains("project: app"));
    assert!(output.contains("default_profile: dev"));
    assert!(output.contains("active_profile: dev"));
    assert!(output.contains("lock_state: locked"));
    assert!(output.contains("agent_state: unavailable"));
    assert!(output.contains("running_sessions: 1"));
    assert!(output.contains("scan_warnings: 1"), "{output}");
    assert!(output.contains("trusted_root: yes"));
    assert!(output.contains("metadata_only: yes"));
    assert!(output.contains("next_action: run locket scan"));
    assert!(!output.contains("sk_test_sampleTokenValue123"));
    Ok(())
}

#[test]
fn status_redacts_project_and_profile_names_from_privacy_config()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut init_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut init_output,
    )?;
    let mut config_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "config", "set", "privacy.redact_names", "true"])?,
        &context,
        &mut config_output,
    )?;

    let mut output = Vec::new();
    run_with_context(Cli::try_parse_from(["locket", "status"])?, &context, &mut output)?;

    let output = String::from_utf8(output)?;
    assert!(output.contains("project: project-"));
    assert!(output.contains("project_id: project-"));
    assert!(output.contains("default_profile: profile-"));
    assert!(output.contains("active_profile: profile-"));
    assert!(!output.contains("project: app"));
    assert!(!output.contains("default_profile: dev"));
    assert!(!output.contains("active_profile: dev"));
    Ok(())
}

#[test]
fn completion_generates_shell_script() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();

    run_with_context(
        Cli::try_parse_from(["locket", "completion", "bash"])?,
        &context,
        &mut output,
    )?;

    let output = String::from_utf8(output)?;
    assert!(output.contains("_locket"));
    assert!(output.contains("bootstrap"));
    Ok(())
}

#[test]
fn new_from_builtin_template_initializes_metadata_only_project()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();

    run_with_context(
        Cli::try_parse_from(["locket", "new", "--from-template", "basic"])?,
        &context,
        &mut output,
    )?;

    let output = String::from_utf8(output)?;
    assert!(output.contains("template: basic"));
    assert!(output.contains("template_source: built-in"));
    assert!(output.contains("secrets: not written"));
    assert!(!output.contains("postgres://"));
    let config = std::fs::read_to_string(directory.path().join("locket.toml"))?;
    assert!(config.contains("[commands.dev]"));
    let example = std::fs::read_to_string(directory.path().join(".env.example"))?;
    assert!(example.contains("DATABASE_URL="));
    Ok(())
}

#[test]
fn new_from_local_template_and_bootstrap_report_checklist() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempdir()?;
    let context = test_context(&directory);
    let templates_dir = context.template_dir.clone();
    std::fs::create_dir_all(&templates_dir)?;
    std::fs::write(
        templates_dir.join("web.toml"),
        r#"
name = "web-app"
default_profile = "dev"
profiles = ["dev", "staging"]
expected_secrets = ["DATABASE_URL", "API_KEY"]

[commands.test]
argv = ["cargo", "test"]
optional_secrets = ["API_KEY"]
"#,
    )?;

    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "new", "--from-template", "web"])?,
        &context,
        &mut output,
    )?;
    let output = String::from_utf8(output)?;
    assert!(output.contains("template_source: local:"));
    assert!(output.contains("profiles: 2"));
    assert!(output.contains("expected_secrets: 2"));
    assert!(output.contains("commands: 1"));

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let config = super::read_project_config(&directory.path().join("locket.toml"))?;
    let profiles = store.list_profiles(config.project_id.as_str())?;
    assert_eq!(profiles.len(), 2);

    let mut bootstrap_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "bootstrap"])?,
        &context,
        &mut bootstrap_output,
    )?;
    let bootstrap_output = String::from_utf8(bootstrap_output)?;
    assert!(bootstrap_output.contains("project: web-app"));
    assert!(bootstrap_output.contains("profile: dev"));
    assert!(bootstrap_output.contains(".env.example: yes"));
    assert!(bootstrap_output.contains("trusted_root: yes"));
    assert!(bootstrap_output.contains("metadata_only: yes"));
    assert!(bootstrap_output.contains("- none"));
    assert!(bootstrap_output.contains("team: solo"));
    assert!(bootstrap_output.contains("policies: 1"));
    assert!(bootstrap_output.contains("smoke_policy: none"));
    assert!(bootstrap_output.contains("pre_commit_hook: not_git_repo"));
    assert!(!bootstrap_output.contains("postgres://"));
    Ok(())
}

#[test]
fn bootstrap_reports_smoke_policy_and_writes_audit_row() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let templates_dir = context.template_dir.clone();
    std::fs::create_dir_all(&templates_dir)?;
    std::fs::write(
        templates_dir.join("api.toml"),
        r#"
name = "api"
default_profile = "dev"
profiles = ["dev"]

[commands.smoke]
argv = ["cargo", "test"]
"#,
    )?;
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "new", "--from-template", "api"])?,
        &context,
        &mut output,
    )?;

    let toml_path = directory.path().join("locket.toml");
    let mut toml_content = std::fs::read_to_string(&toml_path)?;
    toml_content.push_str("\n[bootstrap]\nsmoke_policy = \"smoke\"\n");
    std::fs::write(&toml_path, &toml_content)?;

    let mut bootstrap_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "bootstrap"])?,
        &context,
        &mut bootstrap_output,
    )?;
    let bootstrap_output = String::from_utf8(bootstrap_output)?;
    assert!(bootstrap_output.contains("smoke_policy: configured (smoke)"));
    assert!(bootstrap_output.contains("policies: 1"));
    assert!(bootstrap_output.contains("- none"));

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let bootstrap_audit = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'BOOTSTRAP'",
        [],
        |row| row.get::<_, String>(0),
    )?;
    assert!(bootstrap_audit.contains("\"action\":\"BOOTSTRAP\""));
    assert!(bootstrap_audit.contains("\"smoke_policy_configured\":true"));
    assert!(bootstrap_audit.contains("\"team_status\":\"solo\""));
    Ok(())
}

#[test]
fn bootstrap_reports_missing_smoke_policy() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let templates_dir = context.template_dir.clone();
    std::fs::create_dir_all(&templates_dir)?;
    std::fs::write(
        templates_dir.join("plain.toml"),
        r#"
name = "plain"
default_profile = "dev"
profiles = ["dev"]
"#,
    )?;
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "new", "--from-template", "plain"])?,
        &context,
        &mut output,
    )?;

    let toml_path = directory.path().join("locket.toml");
    let mut toml_content = std::fs::read_to_string(&toml_path)?;
    toml_content.push_str("\n[bootstrap]\nsmoke_policy = \"missing\"\n");
    std::fs::write(&toml_path, &toml_content)?;

    let mut bootstrap_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "bootstrap"])?,
        &context,
        &mut bootstrap_output,
    )?;
    let bootstrap_output = String::from_utf8(bootstrap_output)?;
    assert!(bootstrap_output.contains("smoke_policy: missing (missing)"));
    assert!(bootstrap_output.contains("- run locket policy add missing"));
    Ok(())
}

#[test]
fn new_rejects_template_with_invalid_expected_secret_name() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempdir()?;
    let context = test_context(&directory);
    std::fs::create_dir_all(&context.template_dir)?;
    std::fs::write(
        context.template_dir.join("bad.toml"),
        r#"
name = "bad-app"
expected_secrets = ["database-url"]
"#,
    )?;
    let mut output = Vec::new();

    assert_error_contains(
        run_with_context(
            Cli::try_parse_from(["locket", "new", "--from-template", "bad"])?,
            &context,
            &mut output,
        ),
        "template expected secret name is invalid",
    );
    assert!(!directory.path().join("locket.toml").exists());
    Ok(())
}

#[test]
fn new_unknown_template_is_config_error() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();

    assert_error_contains(
        run_with_context(
            Cli::try_parse_from(["locket", "new", "--from-template", "missing"])?,
            &context,
            &mut output,
        ),
        "unknown template",
    );
    Ok(())
}

#[test]
fn emit_example_uses_all_profiles_rewrites_managed_block_and_audits()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;

    let dev_args = test_secret_write_args("DATABASE_URL");
    super::set_secret_value(&context, &dev_args, "postgres://localhost/app", "manual", 1_000)?;
    let mut create_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "profile", "create", "staging"])?,
        &context,
        &mut create_output,
    )?;
    let mut use_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "use", "staging"])?,
        &context,
        &mut use_output,
    )?;
    let staging_args = test_secret_write_args("API_KEY");
    super::set_secret_value(&context, &staging_args, "sk_test_sample", "manual", 2_000)?;

    let example_path = directory.path().join(".env.example");
    std::fs::write(
        &example_path,
        "HEADER=kept\n# --- BEGIN LOCKET MANAGED ---\nOLD_SECRET=\n# --- END LOCKET MANAGED ---\nFOOTER=kept\n",
    )?;

    let mut emit_output = Vec::new();
    run_with_context(Cli::try_parse_from(["locket", "emit-example"])?, &context, &mut emit_output)?;

    let example = std::fs::read_to_string(&example_path)?;
    assert!(example.contains("HEADER=kept"));
    assert!(example.contains("FOOTER=kept"));
    assert!(example.contains("API_KEY="));
    assert!(example.contains("DATABASE_URL="));
    assert!(!example.contains("OLD_SECRET="));
    assert!(!example.contains("postgres://localhost/app"));
    assert!(!example.contains("sk_test_sample"));

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'EXAMPLE_EMIT'",
        [],
        |row| row.get(0),
    )?;
    assert!(metadata.contains("\"secret_name_count\":2"));
    assert!(metadata.contains("\"path_kind\":\"project_env_example\""));
    assert!(metadata.contains("\"marker_only\":true"));
    assert!(!metadata.contains("DATABASE_URL"));
    assert!(!metadata.contains("postgres://localhost/app"));
    Ok(())
}

#[test]
fn automatic_example_refresh_respects_user_and_project_config()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;

    let mut config_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "config", "set", "example.auto_refresh", "false"])?,
        &context,
        &mut config_output,
    )?;
    std::fs::write(directory.path().join("import.env"), "USER_DISABLED=value\n")?;
    let mut import_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "import", "import.env"])?,
        &context,
        &mut import_output,
    )?;
    let example = std::fs::read_to_string(directory.path().join(".env.example"))?;
    assert!(!example.contains("USER_DISABLED="));

    let mut emit_output = Vec::new();
    run_with_context(Cli::try_parse_from(["locket", "emit-example"])?, &context, &mut emit_output)?;
    let example = std::fs::read_to_string(directory.path().join(".env.example"))?;
    assert!(example.contains("USER_DISABLED="));

    let mut config_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "config", "set", "example.auto_refresh", "true"])?,
        &context,
        &mut config_output,
    )?;
    let locket_toml_path = directory.path().join("locket.toml");
    let mut locket_toml = std::fs::read_to_string(&locket_toml_path)?;
    locket_toml.push_str("\n[example]\nauto_refresh = false\n");
    std::fs::write(&locket_toml_path, locket_toml)?;

    std::fs::write(directory.path().join("import2.env"), "PROJECT_DISABLED=value\n")?;
    let mut import_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "import", "import2.env"])?,
        &context,
        &mut import_output,
    )?;
    let example = std::fs::read_to_string(directory.path().join(".env.example"))?;
    assert!(example.contains("USER_DISABLED="));
    assert!(!example.contains("PROJECT_DISABLED="));
    Ok(())
}

#[test]
fn automatic_example_refresh_refuses_unmanaged_example_file()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;

    let example_path = directory.path().join(".env.example");
    std::fs::write(&example_path, "MANUAL=kept\n")?;
    let mut names = BTreeSet::new();
    names.insert("DATABASE_URL".to_owned());

    assert_error_contains(
        super::write_example_block(directory.path(), &names).map(|_| ()),
        "refusing automatic overwrite",
    );
    assert_eq!(std::fs::read_to_string(&example_path)?, "MANUAL=kept\n");
    Ok(())
}

#[test]
fn init_creates_project_metadata_files_and_profiles() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();

    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;

    assert!(directory.path().join("locket.toml").exists());
    assert!(directory.path().join(".gitignore").exists());
    assert!(directory.path().join(".env.example").exists());

    let mut profiles_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "profile", "list"])?,
        &context,
        &mut profiles_output,
    )?;
    let profiles_output = String::from_utf8(profiles_output)?;
    assert!(profiles_output.contains("* dev"));

    let mut create_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "profile", "create", "staging"])?,
        &context,
        &mut create_output,
    )?;
    let mut use_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "use", "staging"])?,
        &context,
        &mut use_output,
    )?;
    assert!(String::from_utf8(use_output)?.contains("active profile: staging"));

    let mut profiles_after_use = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "profile", "list"])?,
        &context,
        &mut profiles_after_use,
    )?;
    assert!(String::from_utf8(profiles_after_use)?.contains("* staging"));
    Ok(())
}

#[test]
fn device_commands_initialize_describe_add_list_and_revoke_metadata_only()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();

    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    output.clear();

    run_with_context(Cli::try_parse_from(["locket", "device", "init"])?, &context, &mut output)?;
    let init_output = String::from_utf8(output.clone())?;
    assert!(init_output.contains("device: initialized"));
    assert!(init_output.contains("metadata_only: yes"));
    let descriptor = init_output
        .lines()
        .find_map(|line| line.strip_prefix("descriptor: "))
        .ok_or("missing descriptor")?
        .to_owned();
    let local_device_id = init_output
        .lines()
        .find_map(|line| line.strip_prefix("device_id: "))
        .ok_or("missing device id")?
        .to_owned();
    assert!(descriptor.starts_with("lkdev1_"));

    output.clear();
    run_with_context(Cli::try_parse_from(["locket", "device", "pubkey"])?, &context, &mut output)?;
    let pubkey_output = String::from_utf8(output.clone())?;
    assert!(pubkey_output.contains(&descriptor));
    assert!(!pubkey_output.contains("private"));

    let remote_device = super::DeviceRecord {
        id: "lk_dev_remote".to_owned(),
        project_id: "lk_proj_external".to_owned(),
        name: "remote".to_owned(),
        signing_public_key: vec![7; 32],
        sealing_public_key: vec![8; 32],
        fingerprint: super::device_fingerprint_hex(&[7; 32], &[8; 32]),
        safety_words: vec!["amber".to_owned(), "basil".to_owned(), "cedar".to_owned()],
        local: false,
        created_at: 1,
        last_seen_at: None,
        revoked_at: None,
    };
    let remote_descriptor = super::encode_device_descriptor(&remote_device)?;

    output.clear();
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "device",
            "add",
            "teammate-laptop",
            "--device",
            &remote_descriptor,
        ])?,
        &context,
        &mut output,
    )?;
    let add_output = String::from_utf8(output.clone())?;
    assert!(add_output.contains("device: added"));
    assert!(!add_output.contains("private"));

    output.clear();
    run_with_context(Cli::try_parse_from(["locket", "device", "list"])?, &context, &mut output)?;
    let list_output = String::from_utf8(output.clone())?;
    assert!(list_output.contains("local"));
    assert!(list_output.contains("teammate-laptop"));

    output.clear();
    let remove_without_force = run_with_context(
        Cli::try_parse_from(["locket", "device", "remove", local_device_id.as_str()])?,
        &context,
        &mut output,
    );
    assert_error_contains(remove_without_force, "requires --force");

    output.clear();
    run_with_context(
        Cli::try_parse_from(["locket", "device", "remove", "teammate-laptop"])?,
        &context,
        &mut output,
    )?;
    assert!(String::from_utf8(output.clone())?.contains("device: revoked"));

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let device_audits = store.connection().query_row(
        "SELECT COUNT(*) FROM audit_log WHERE action IN ('DEVICE_ADD', 'DEVICE_REVOKE')",
        [],
        |row| row.get::<_, i64>(0),
    )?;
    assert_eq!(device_audits, 3);
    drop(local_device_id);
    Ok(())
}

#[test]
fn init_writes_recovery_envelope_and_metadata_only_audit() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();

    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;

    let output = String::from_utf8(output)?;
    let recovery_code = recovery_code_from_output(&output)?;
    assert!(output.contains("recovery_code_init: success"));
    assert!(output.contains("terminal scrollback may retain this code"));
    assert!(output.contains("metadata_only: yes"));
    assert!(directory.path().join(".locket/recovery/kdf.toml").exists());
    assert!(directory.path().join(".locket/recovery/envelope.bin").exists());

    let store = super::open_store(&context)?;
    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'INIT'",
        [],
        |row| row.get(0),
    )?;
    assert!(metadata.contains("\"recovery_code_displayed\":true"));
    assert!(metadata.contains("\"generated_files\":[\".gitignore\",\".env.example\"]"));
    assert!(!metadata.contains(recovery_code));
    Ok(())
}

#[test]
fn device_init_force_replaces_active_local_device() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();

    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    output.clear();

    run_with_context(Cli::try_parse_from(["locket", "device", "init"])?, &context, &mut output)?;
    let init_output = String::from_utf8(output.clone())?;
    let local_device_id = init_output
        .lines()
        .find_map(|line| line.strip_prefix("device_id: "))
        .ok_or("missing device id")?
        .to_owned();

    output.clear();
    run_with_context(
        Cli::try_parse_from(["locket", "device", "init", "--force"])?,
        &context,
        &mut output,
    )?;
    let forced_init_output = String::from_utf8(output.clone())?;
    assert!(forced_init_output.contains("device: initialized"));
    assert!(forced_init_output.contains("metadata_only: yes"));
    assert!(!forced_init_output.contains(&local_device_id));

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let project_id: String =
        store.connection().query_row("SELECT id FROM projects LIMIT 1", [], |row| row.get(0))?;
    let active_devices = store.list_devices(&project_id, false)?;
    assert_eq!(active_devices.len(), 1);
    assert_ne!(active_devices[0].id, local_device_id);
    Ok(())
}

#[test]
fn init_existing_complete_project_is_idempotent_without_new_rows_or_recovery_code()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    let first_output = String::from_utf8(output)?;
    let first_recovery_code = recovery_code_from_output(&first_output)?.to_owned();
    let store = super::open_store(&context)?;
    let audit_rows_before: i64 =
        store.connection().query_row("SELECT COUNT(*) FROM audit_log", [], |row| row.get(0))?;

    let mut rerun_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "ignored", "--profile", "prod"])?,
        &context_with_confirmation(&context, "wrong\n"),
        &mut rerun_output,
    )?;

    let rerun_output = String::from_utf8(rerun_output)?;
    assert!(rerun_output.contains("project already initialized"));
    assert!(!rerun_output.contains("recovery_code"));
    assert!(!rerun_output.contains(&first_recovery_code));
    let audit_rows_after: i64 =
        store.connection().query_row("SELECT COUNT(*) FROM audit_log", [], |row| row.get(0))?;
    assert_eq!(audit_rows_after, audit_rows_before);
    Ok(())
}

#[test]
fn init_resumes_valid_locket_toml_without_store_project_and_creates_keys()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let config = locket_core::ProjectConfig::new(
        locket_core::ProjectId::generate()?,
        "app".to_owned(),
        locket_core::ProfileName::new("dev".to_owned())?,
    );
    super::write_project_config(&directory.path().join("locket.toml"), &config)?;

    let mut output = Vec::new();
    run_with_context(Cli::try_parse_from(["locket", "init"])?, &context, &mut output)?;

    let output = String::from_utf8(output)?;
    assert!(output.contains("resumed locket project"));
    assert!(output.contains(config.project_id.as_str()));
    assert!(output.contains("recovery_code_init: success"));
    let store = super::open_store(&context)?;
    assert!(store.get_project(config.project_id.as_str())?.is_some());
    let profile =
        store.get_profile_by_name(config.project_id.as_str(), "dev")?.ok_or("profile missing")?;
    assert!(
        store
            .get_key_by_scope(
                config.project_id.as_str(),
                None,
                locket_crypto::KeyPurpose::ProjectMetadata.as_str(),
            )?
            .is_some()
    );
    assert!(
        store
            .get_key_by_scope(
                config.project_id.as_str(),
                None,
                locket_crypto::KeyPurpose::Audit.as_str(),
            )?
            .is_some()
    );
    assert!(
        store
            .get_key_by_scope(
                config.project_id.as_str(),
                Some(&profile.id),
                locket_crypto::KeyPurpose::ProfileSecret.as_str(),
            )?
            .is_some()
    );
    assert!(
        store
            .get_key_by_scope(
                config.project_id.as_str(),
                Some(&profile.id),
                locket_crypto::KeyPurpose::ProfileFingerprint.as_str(),
            )?
            .is_some()
    );
    Ok(())
}

#[test]
fn init_failure_on_unmanaged_env_example_rolls_back_owned_changes()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    std::fs::write(directory.path().join(".env.example"), "MANUAL=kept\n")?;
    let mut output = Vec::new();

    let result = run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    );

    assert_error_contains(result, "refusing silent overwrite");
    assert!(!directory.path().join("locket.toml").exists());
    assert!(!directory.path().join(".gitignore").exists());
    assert_eq!(std::fs::read_to_string(directory.path().join(".env.example"))?, "MANUAL=kept\n");
    assert!(!directory.path().join(".locket/recovery/kdf.toml").exists());
    assert!(!directory.path().join(".locket/recovery/envelope.bin").exists());
    let store = super::open_store(&context)?;
    let project_count: i64 =
        store.connection().query_row("SELECT COUNT(*) FROM projects", [], |row| row.get(0))?;
    assert_eq!(project_count, 0);
    Ok(())
}

#[test]
fn init_rejects_unsupported_locket_toml_schema_without_rewriting_file()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let config = locket_core::ProjectConfig::new(
        locket_core::ProjectId::generate()?,
        "app".to_owned(),
        locket_core::ProfileName::new("dev".to_owned())?,
    );
    let config_path = directory.path().join("locket.toml");
    super::write_project_config(&config_path, &config)?;
    let unsupported = std::fs::read_to_string(&config_path)?
        .replace("schema_version = 1", "schema_version = 999");
    std::fs::write(&config_path, &unsupported)?;

    let result =
        run_with_context(Cli::try_parse_from(["locket", "init"])?, &context, &mut Vec::new());

    assert_error_contains(result, "unsupported locket.toml schema_version 999");
    assert_eq!(std::fs::read_to_string(config_path)?, unsupported);
    Ok(())
}

#[test]
fn policy_commands_update_locket_toml_without_duplicates_and_audit_metadata()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();

    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    output.clear();

    run_with_context(
        Cli::try_parse_from(["locket", "policy", "add", "dev", "--", "pnpm", "dev"])?,
        &context,
        &mut output,
    )?;
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "policy",
            "allow",
            "dev",
            "DATABASE_URL",
            "DATABASE_URL",
            "API_KEY",
        ])?,
        &context,
        &mut output,
    )?;
    run_with_context(
        Cli::try_parse_from(["locket", "policy", "require", "dev", "API_KEY", "API_KEY"])?,
        &context,
        &mut output,
    )?;

    let output = String::from_utf8(output)?;
    assert!(output.contains("metadata_only: yes"));
    assert!(!output.contains("pnpm"));

    let policy_text = std::fs::read_to_string(directory.path().join("locket.toml"))?;
    let document = locket_core::PolicyDocument::from_toml_str(&policy_text)?;
    let policy = document.commands.get("dev").ok_or("missing dev policy")?;
    assert_eq!(
        policy.optional_secrets.iter().map(ToString::to_string).collect::<Vec<_>>(),
        ["DATABASE_URL"]
    );
    assert_eq!(
        policy.required_secrets.iter().map(ToString::to_string).collect::<Vec<_>>(),
        ["API_KEY"]
    );
    assert_eq!(
        policy.allowed_secrets.iter().map(ToString::to_string).collect::<Vec<_>>(),
        ["API_KEY", "DATABASE_URL"]
    );

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let mut statement = store.connection().prepare(
        "SELECT metadata_json FROM audit_log WHERE action = 'POLICY_UPDATE' ORDER BY sequence",
    )?;
    let rows =
        statement.query_map([], |row| row.get::<_, String>(0))?.collect::<Result<Vec<_>, _>>()?;
    assert_eq!(rows.len(), 3);
    assert!(rows.iter().any(|row| row.contains("\"operation\":\"add\"")));
    assert!(rows.iter().any(|row| row.contains("\"operation\":\"allow\"")));
    assert!(rows.iter().any(|row| row.contains("\"operation\":\"require\"")));
    assert!(rows.iter().all(|row| !row.contains("pnpm")));

    let mut doctor_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "policy", "doctor"])?,
        &context,
        &mut doctor_output,
    )?;
    let doctor_output = String::from_utf8(doctor_output)?;
    assert!(doctor_output.contains("policy_doctor: ok"));
    assert!(doctor_output.contains("metadata_only: yes"));

    assert_error_contains(
        run_with_context(
            Cli::try_parse_from(["locket", "policy", "delete", "dev"])?,
            &context,
            &mut Vec::new(),
        ),
        "--yes",
    );
    run_with_context(
        Cli::try_parse_from(["locket", "policy", "delete", "dev", "--yes"])?,
        &context,
        &mut Vec::new(),
    )?;
    let policy_text = std::fs::read_to_string(directory.path().join("locket.toml"))?;
    let document = locket_core::PolicyDocument::from_toml_str(&policy_text)?;
    assert!(!document.commands.contains_key("dev"));
    Ok(())
}

#[test]
fn policy_doctor_rejects_invalid_policy_document() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);

    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    std::fs::write(
        directory.path().join("locket.toml"),
        r#"
schema_version = 1
project_id = "lk_proj_0123456789abcdef"
name = "app"
default_profile = "dev"

[commands.dev]
argv = []
"#,
    )?;

    assert_error_contains(
        run_with_context(
            Cli::try_parse_from(["locket", "policy", "doctor"])?,
            &context,
            &mut Vec::new(),
        ),
        "argv",
    );
    Ok(())
}

#[test]
fn profile_mark_dangerous_writes_profile_change_audit_with_prior_flags()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let key_store: Arc<dyn MasterKeyStore + Send + Sync> =
        Arc::new(MemoryMasterKeyStore::default());
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &test_context_with_key_store(&directory, Arc::clone(&key_store)),
        &mut Vec::new(),
    )?;
    let mark_context =
        test_context_with_key_store_and_confirmation(&directory, Arc::clone(&key_store), "dev\n");
    run_with_context(
        Cli::try_parse_from(["locket", "profile", "mark-dangerous", "dev"])?,
        &mark_context,
        &mut Vec::new(),
    )?;

    let store = super::open_store(&mark_context)?;
    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'PROFILE_CHANGE'
         ORDER BY sequence DESC LIMIT 1",
        [],
        |row| row.get(0),
    )?;
    assert!(metadata.contains("\"operation\":\"set_dangerous\""));
    assert!(metadata.contains("\"prior_dangerous\":false"));
    assert!(metadata.contains("\"new_dangerous\":true"));
    assert!(metadata.contains("\"profile_name\":\"dev\""));
    Ok(())
}

#[test]
fn profile_mark_dangerous_rejects_wrong_typed_confirmation()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let key_store: Arc<dyn MasterKeyStore + Send + Sync> =
        Arc::new(MemoryMasterKeyStore::default());
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &test_context_with_key_store(&directory, Arc::clone(&key_store)),
        &mut Vec::new(),
    )?;
    let bad_context =
        test_context_with_key_store_and_confirmation(&directory, Arc::clone(&key_store), "wrong\n");
    let mut output = Vec::new();
    let result = run_with_context(
        Cli::try_parse_from(["locket", "profile", "mark-dangerous", "dev"])?,
        &bad_context,
        &mut output,
    );
    assert_error_contains(result, "confirmation did not match");
    let store = super::open_store(&bad_context)?;
    let project_id: String =
        store.connection().query_row("SELECT id FROM projects LIMIT 1", [], |row| row.get(0))?;
    let profile = store.get_profile_by_name(&project_id, "dev")?.ok_or("profile missing")?;
    assert!(!profile.dangerous, "rejected confirmation must not flip flag");
    Ok(())
}

#[test]
fn profile_clear_dangerous_requires_clear_prefix_in_confirmation()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let key_store: Arc<dyn MasterKeyStore + Send + Sync> =
        Arc::new(MemoryMasterKeyStore::default());
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &test_context_with_key_store(&directory, Arc::clone(&key_store)),
        &mut Vec::new(),
    )?;
    run_with_context(
        Cli::try_parse_from(["locket", "profile", "mark-dangerous", "dev"])?,
        &test_context_with_key_store_and_confirmation(&directory, Arc::clone(&key_store), "dev\n"),
        &mut Vec::new(),
    )?;

    let bare_name_context =
        test_context_with_key_store_and_confirmation(&directory, Arc::clone(&key_store), "dev\n");
    let mut output = Vec::new();
    let result = run_with_context(
        Cli::try_parse_from(["locket", "profile", "clear-dangerous", "dev"])?,
        &bare_name_context,
        &mut output,
    );
    assert_error_contains(result, "confirmation did not match");

    let prefix_context = test_context_with_key_store_and_confirmation(
        &directory,
        Arc::clone(&key_store),
        "clear dev\n",
    );
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "profile", "clear-dangerous", "dev"])?,
        &prefix_context,
        &mut output,
    )?;
    assert!(String::from_utf8(output)?.contains("dangerous=not-dangerous"));
    Ok(())
}

#[test]
fn profile_mark_dangerous_is_no_op_when_already_dangerous() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempdir()?;
    let key_store: Arc<dyn MasterKeyStore + Send + Sync> =
        Arc::new(MemoryMasterKeyStore::default());
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &test_context_with_key_store(&directory, Arc::clone(&key_store)),
        &mut Vec::new(),
    )?;
    run_with_context(
        Cli::try_parse_from(["locket", "profile", "mark-dangerous", "dev"])?,
        &test_context_with_key_store_and_confirmation(&directory, Arc::clone(&key_store), "dev\n"),
        &mut Vec::new(),
    )?;
    let no_confirmation_context = test_context_with_key_store_and_confirmation(
        &directory,
        Arc::clone(&key_store),
        "should-not-be-read\n",
    );
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "profile", "mark-dangerous", "dev"])?,
        &no_confirmation_context,
        &mut output,
    )?;
    let output = String::from_utf8(output)?;
    assert!(output.contains("dangerous=dangerous unchanged"));
    let store = super::open_store(&no_confirmation_context)?;
    let count: i64 = store.connection().query_row(
        "SELECT COUNT(*) FROM audit_log WHERE action = 'PROFILE_CHANGE'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(count, 1, "no-op mark must not append a new audit row");
    Ok(())
}

#[test]
fn profile_mark_dangerous_unknown_profile_errors_without_audit()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let key_store: Arc<dyn MasterKeyStore + Send + Sync> =
        Arc::new(MemoryMasterKeyStore::default());
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &test_context_with_key_store(&directory, Arc::clone(&key_store)),
        &mut Vec::new(),
    )?;
    let context = test_context_with_key_store_and_confirmation(
        &directory,
        Arc::clone(&key_store),
        "missing\n",
    );
    let mut output = Vec::new();
    let result = run_with_context(
        Cli::try_parse_from(["locket", "profile", "mark-dangerous", "missing"])?,
        &context,
        &mut output,
    );
    assert_error_contains(result, "profile not found");
    let store = super::open_store(&context)?;
    let count: i64 = store.connection().query_row(
        "SELECT COUNT(*) FROM audit_log WHERE action = 'PROFILE_CHANGE'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(count, 0);
    Ok(())
}

#[test]
fn profile_dangerous_marking_updates_metadata_only() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let key_store: Arc<dyn MasterKeyStore + Send + Sync> =
        Arc::new(MemoryMasterKeyStore::default());
    let init_context = test_context_with_key_store(&directory, Arc::clone(&key_store));
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &init_context,
        &mut output,
    )?;

    let mark_context =
        test_context_with_key_store_and_confirmation(&directory, Arc::clone(&key_store), "dev\n");
    let mut mark_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "profile", "mark-dangerous", "dev"])?,
        &mark_context,
        &mut mark_output,
    )?;
    let mark_output = String::from_utf8(mark_output)?;
    assert!(mark_output.contains("dangerous=dangerous"));
    assert!(mark_output.contains("metadata_only: yes"));
    assert!(mark_output.contains("active_secrets: 0"));
    assert!(mark_output.contains("directory_grants: 0"));
    assert!(mark_output.contains("prior=not-dangerous"));

    let mut list_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "profile", "list"])?,
        &mark_context,
        &mut list_output,
    )?;
    let list_output = String::from_utf8(list_output)?;
    assert!(list_output.contains("* dev"));
    assert!(list_output.contains("dangerous"));

    let clear_context = test_context_with_key_store_and_confirmation(
        &directory,
        Arc::clone(&key_store),
        "clear dev\n",
    );
    let mut clear_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "profile", "clear-dangerous", "dev"])?,
        &clear_context,
        &mut clear_output,
    )?;
    let clear_output = String::from_utf8(clear_output)?;
    assert!(clear_output.contains("dangerous=not-dangerous"));
    assert!(clear_output.contains("prior=dangerous"));
    let mut list_after_clear = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "profile", "list"])?,
        &clear_context,
        &mut list_after_clear,
    )?;
    assert!(!String::from_utf8(list_after_clear)?.contains("dangerous"));
    Ok(())
}

#[test]
fn project_root_commands_manage_trusted_roots() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;

    let mut list_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "project", "list-roots"])?,
        &context,
        &mut list_output,
    )?;
    let list_output = String::from_utf8(list_output)?;
    assert!(list_output.contains("display_path:"));
    let root_hash = list_output
        .lines()
        .find_map(|line| line.strip_prefix("root_hash: "))
        .ok_or("root hash should be listed")?
        .to_owned();
    assert_eq!(root_hash.len(), 64);

    let mut trust_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "project", "trust-root"])?,
        &context,
        &mut trust_output,
    )?;
    let trust_output = String::from_utf8(trust_output)?;
    assert!(trust_output.contains("canonical_path:"));
    assert!(trust_output.contains("trusted root already present"));

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let trusted_row_count: u32 =
        store.connection().query_row("SELECT COUNT(*) FROM project_roots", [], |row| row.get(0))?;
    assert_eq!(trusted_row_count, 1);

    let mut failed_trust_output = Vec::new();
    let failed_trust_context = context_with_confirmation(&context, "wrong\n");
    let failed_trust = run_with_context(
        Cli::try_parse_from(["locket", "project", "trust-root"])?,
        &failed_trust_context,
        &mut failed_trust_output,
    );
    assert_error_contains(failed_trust, "confirmation did not match project name");
    let trusted_row_count_after_failed_confirm: u32 =
        store.connection().query_row("SELECT COUNT(*) FROM project_roots", [], |row| row.get(0))?;
    assert_eq!(trusted_row_count_after_failed_confirm, 1);

    let mut untrust_output = Vec::new();
    let untrust_context = context_with_confirmation(&context, &format!("{root_hash}\n"));
    run_with_context(
        Cli::try_parse_from(["locket", "project", "untrust-root", root_hash.as_str()])?,
        &untrust_context,
        &mut untrust_output,
    )?;
    let untrust_output = String::from_utf8(untrust_output)?;
    assert!(untrust_output.contains("trusted root removed"));
    assert!(untrust_output.contains("directory_grants_revoked: 0"));

    let mut status_output = Vec::new();
    run_with_context(Cli::try_parse_from(["locket", "status"])?, &context, &mut status_output)?;
    assert!(String::from_utf8(status_output)?.contains("trusted_root: no"));

    let mut relist_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "project", "list-roots"])?,
        &context,
        &mut relist_output,
    )?;
    assert!(String::from_utf8(relist_output)?.contains("no trusted roots"));

    let mut retrust_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "project", "trust-root"])?,
        &context,
        &mut retrust_output,
    )?;
    assert!(String::from_utf8(retrust_output)?.contains("trusted root added"));

    let audit_actions: Vec<String> = {
        let mut statement = store
            .connection()
            .prepare("SELECT metadata_json FROM audit_log WHERE action = 'TRUST_ROOT'")?;
        statement.query_map([], |row| row.get::<_, String>(0))?.collect::<Result<Vec<_>, _>>()?
    };
    assert_eq!(audit_actions.len(), 3);
    assert!(audit_actions.iter().any(|metadata| metadata.contains("\"operation\":\"refresh\"")));
    assert!(audit_actions.iter().any(|metadata| metadata.contains("\"operation\":\"untrust\"")));
    assert!(audit_actions.iter().any(|metadata| metadata.contains("\"operation\":\"trust\"")));
    Ok(())
}

#[test]
fn shell_snippets_are_metadata_only() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    let args = test_secret_write_args("DATABASE_URL");
    super::set_secret_value(&context, &args, "postgres://localhost/app", "manual", 1_000)?;

    let mut shellenv_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "shellenv", "--shell", "bash"])?,
        &context,
        &mut shellenv_output,
    )?;
    let shellenv_output = String::from_utf8(shellenv_output)?;
    assert!(shellenv_output.contains(super::SHELL_HOOK_BEGIN));
    assert!(shellenv_output.contains("__LOCKET_SHELLENV_SOURCED"));
    assert!(!shellenv_output.contains("postgres://localhost/app"));
    assert!(!shellenv_output.contains("grant_id"));
    assert!(!shellenv_output.contains("token"));

    let mut hook_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "hook", "--shell", "zsh"])?,
        &context,
        &mut hook_output,
    )?;
    let hook_output = String::from_utf8(hook_output)?;
    assert!(hook_output.contains(super::SHELL_HOOK_BEGIN));
    assert!(hook_output.contains("locket.toml"));
    assert!(!hook_output.contains("postgres://localhost/app"));
    assert!(!hook_output.contains("grant_id"));
    assert!(!hook_output.contains("token"));

    let mut install_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "hook", "--install"])?,
        &context,
        &mut install_output,
    )?;
    let install_output = String::from_utf8(install_output)?;
    assert!(install_output.contains("hook install: no-op"));
    assert!(install_output.contains("metadata_only: yes"));
    assert!(!install_output.contains("postgres://localhost/app"));
    Ok(())
}

#[test]
fn allow_and_deny_manage_profile_scoped_directory_grants() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    let args = test_secret_write_args("DATABASE_URL");
    super::set_secret_value(&context, &args, "postgres://localhost/app", "manual", 1_000)?;

    let mut allow_output = Vec::new();
    run_with_context(Cli::try_parse_from(["locket", "allow"])?, &context, &mut allow_output)?;
    let allow_output = String::from_utf8(allow_output)?;
    assert!(allow_output.contains("directory grant allowed"));
    assert!(allow_output.contains("metadata_only: yes"));
    assert!(!allow_output.contains("postgres://localhost/app"));

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let grant_count: u32 =
        store
            .connection()
            .query_row("SELECT COUNT(*) FROM directory_grants", [], |row| row.get(0))?;
    assert_eq!(grant_count, 1);
    let dev_profile_id: String =
        store
            .connection()
            .query_row("SELECT profile_id FROM directory_grants", [], |row| row.get(0))?;

    let mut create_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "profile", "create", "staging"])?,
        &context,
        &mut create_output,
    )?;
    let mut use_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "use", "staging"])?,
        &context,
        &mut use_output,
    )?;

    let mut staging_deny_output = Vec::new();
    run_with_context(Cli::try_parse_from(["locket", "deny"])?, &context, &mut staging_deny_output)?;
    assert!(String::from_utf8(staging_deny_output)?.contains("directory grant not found"));
    let grant_count_after_staging_deny: u32 = store.connection().query_row(
        "SELECT COUNT(*) FROM directory_grants WHERE profile_id = ?1",
        [dev_profile_id.as_str()],
        |row| row.get(0),
    )?;
    assert_eq!(grant_count_after_staging_deny, 1);

    let mut deny_all_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "deny", "--all"])?,
        &context,
        &mut deny_all_output,
    )?;
    let deny_all_output = String::from_utf8(deny_all_output)?;
    assert!(deny_all_output.contains("directory grants revoked: 1"));
    assert!(!deny_all_output.contains("postgres://localhost/app"));
    let remaining: u32 =
        store
            .connection()
            .query_row("SELECT COUNT(*) FROM directory_grants", [], |row| row.get(0))?;
    assert_eq!(remaining, 0);
    Ok(())
}

#[test]
fn allow_writes_allow_directory_audit_row() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;

    run_with_context(Cli::try_parse_from(["locket", "allow"])?, &context, &mut Vec::new())?;

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'ALLOW_DIRECTORY' ORDER BY sequence DESC LIMIT 1",
        [],
        |row| row.get(0),
    )?;
    assert!(metadata.contains("\"action\":\"ALLOW_DIRECTORY\""));
    assert!(metadata.contains("\"status\":\"SUCCESS\""));
    assert!(metadata.contains("\"grant_id\":"));
    assert!(metadata.contains("\"grant_scope\":\"project-root\""));
    assert!(metadata.contains("\"root_hash\":"));
    assert!(metadata.contains("\"directory_hash\":"));
    assert!(metadata.contains("\"prior_grant\":null"));
    assert!(metadata.contains("\"result_state\":\"created\""));

    // Re-allow records prior_grant metadata and result_state = "replaced".
    run_with_context(Cli::try_parse_from(["locket", "allow"])?, &context, &mut Vec::new())?;
    let metadata2: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'ALLOW_DIRECTORY' ORDER BY sequence DESC LIMIT 1",
        [],
        |row| row.get(0),
    )?;
    assert!(metadata2.contains("\"result_state\":\"replaced\""));
    assert!(metadata2.contains("\"prior_grant\":{"));
    assert!(metadata2.contains("\"grant_id\":"));
    assert!(metadata2.contains("\"created_at\":"));
    Ok(())
}

#[test]
fn deny_writes_deny_directory_audit_row_with_prior_grant() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    run_with_context(Cli::try_parse_from(["locket", "allow"])?, &context, &mut Vec::new())?;

    run_with_context(Cli::try_parse_from(["locket", "deny"])?, &context, &mut Vec::new())?;

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'DENY_DIRECTORY' ORDER BY sequence DESC LIMIT 1",
        [],
        |row| row.get(0),
    )?;
    assert!(metadata.contains("\"action\":\"DENY_DIRECTORY\""));
    assert!(metadata.contains("\"status\":\"SUCCESS\""));
    assert!(metadata.contains("\"grant_scope\":\"project-root\""));
    assert!(metadata.contains("\"prior_grant\":{"));
    assert!(metadata.contains("\"result_state\":\"removed\""));

    // Deny again with no grant present records absent state and null prior_grant.
    run_with_context(Cli::try_parse_from(["locket", "deny"])?, &context, &mut Vec::new())?;
    let metadata2: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'DENY_DIRECTORY' ORDER BY sequence DESC LIMIT 1",
        [],
        |row| row.get(0),
    )?;
    assert!(metadata2.contains("\"result_state\":\"absent\""));
    assert!(metadata2.contains("\"prior_grant\":null"));
    Ok(())
}

#[test]
fn deny_all_writes_deny_directory_audit_row_with_revoked_count()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    run_with_context(Cli::try_parse_from(["locket", "allow"])?, &context, &mut Vec::new())?;
    run_with_context(
        Cli::try_parse_from(["locket", "profile", "create", "staging"])?,
        &context,
        &mut Vec::new(),
    )?;
    run_with_context(
        Cli::try_parse_from(["locket", "use", "staging"])?,
        &context,
        &mut Vec::new(),
    )?;
    run_with_context(Cli::try_parse_from(["locket", "allow"])?, &context, &mut Vec::new())?;

    run_with_context(Cli::try_parse_from(["locket", "deny", "--all"])?, &context, &mut Vec::new())?;

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'DENY_DIRECTORY' ORDER BY sequence DESC LIMIT 1",
        [],
        |row| row.get(0),
    )?;
    assert!(metadata.contains("\"action\":\"DENY_DIRECTORY\""));
    assert!(metadata.contains("\"grant_scope\":\"all\""));
    assert!(metadata.contains("\"revoked_count\":2"));
    assert!(metadata.contains("\"result_state\":\"all\""));
    Ok(())
}

#[test]
fn allow_requires_trusted_project_root() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    let args = test_secret_write_args("DATABASE_URL");
    super::set_secret_value(&context, &args, "postgres://localhost/app", "manual", 1_000)?;
    std::fs::OpenOptions::new()
        .append(true)
        .open(directory.path().join("locket.toml"))?
        .write_all(
            br#"
[commands.env_check]
argv = ["/bin/sh", "-c", "true"]
required_secrets = ["DATABASE_URL"]
"#,
        )?;

    let mut roots_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "project", "list-roots"])?,
        &context,
        &mut roots_output,
    )?;
    let root_hash = String::from_utf8(roots_output)?
        .lines()
        .find_map(|line| line.strip_prefix("root_hash: "))
        .ok_or("root hash should be listed")?
        .to_owned();
    let mut untrust_output = Vec::new();
    let untrust_context = context_with_confirmation(&context, &format!("{root_hash}\n"));
    run_with_context(
        Cli::try_parse_from(["locket", "project", "untrust-root", root_hash.as_str()])?,
        &untrust_context,
        &mut untrust_output,
    )?;

    let mut allow_output = Vec::new();
    let Err(error) =
        run_with_context(Cli::try_parse_from(["locket", "allow"])?, &context, &mut allow_output)
    else {
        return Err("allow should fail for untrusted roots".into());
    };
    assert_eq!(error.exit_code(), 71);
    assert!(error.to_string().contains("ProjectRootNotTrusted"));

    let mut list_output = Vec::new();
    let list_result =
        run_with_context(Cli::try_parse_from(["locket", "list"])?, &context, &mut list_output);
    assert_error_contains(list_result, "ProjectRootNotTrusted");

    let mut get_output = Vec::new();
    let get_result = run_with_context(
        Cli::try_parse_from(["locket", "get", "DATABASE_URL", "--reveal", "--force"])?,
        &context,
        &mut get_output,
    );
    assert_error_contains(get_result, "ProjectRootNotTrusted");

    let missing_args = test_secret_write_args("API_KEY");
    assert_error_contains(
        super::set_secret_value(&context, &missing_args, "sk_test", "manual", 2_000),
        "ProjectRootNotTrusted",
    );

    let mut run_output = Vec::new();
    let run_result = run_with_context(
        Cli::try_parse_from(["locket", "run", "env_check"])?,
        &context,
        &mut run_output,
    );
    assert_error_contains(run_result, "ProjectRootNotTrusted");

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let grant_count: u32 =
        store
            .connection()
            .query_row("SELECT COUNT(*) FROM directory_grants", [], |row| row.get(0))?;
    assert_eq!(grant_count, 0);
    Ok(())
}

#[test]
fn untrust_root_requires_hash_confirmation_and_revokes_directory_grants()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;

    let mut allow_output = Vec::new();
    run_with_context(Cli::try_parse_from(["locket", "allow"])?, &context, &mut allow_output)?;
    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let grant_count: u32 =
        store
            .connection()
            .query_row("SELECT COUNT(*) FROM directory_grants", [], |row| row.get(0))?;
    assert_eq!(grant_count, 1);

    let mut roots_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "project", "list-roots"])?,
        &context,
        &mut roots_output,
    )?;
    let root_hash = String::from_utf8(roots_output)?
        .lines()
        .find_map(|line| line.strip_prefix("root_hash: "))
        .ok_or("root hash should be listed")?
        .to_owned();

    let failed_context = context_with_confirmation(&context, "wrong\n");
    let mut failed_output = Vec::new();
    let failed = run_with_context(
        Cli::try_parse_from(["locket", "project", "untrust-root", root_hash.as_str()])?,
        &failed_context,
        &mut failed_output,
    );
    assert_error_contains(failed, "confirmation did not match root hash");
    let grant_count_after_failed_confirm: u32 =
        store
            .connection()
            .query_row("SELECT COUNT(*) FROM directory_grants", [], |row| row.get(0))?;
    assert_eq!(grant_count_after_failed_confirm, 1);

    let untrust_context = context_with_confirmation(&context, &format!("{root_hash}\n"));
    let mut untrust_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "project", "untrust-root", root_hash.as_str()])?,
        &untrust_context,
        &mut untrust_output,
    )?;
    let untrust_output = String::from_utf8(untrust_output)?;
    assert!(untrust_output.contains("directory_grants_revoked: 1"));
    let remaining_grants: u32 =
        store
            .connection()
            .query_row("SELECT COUNT(*) FROM directory_grants", [], |row| row.get(0))?;
    assert_eq!(remaining_grants, 0);
    Ok(())
}

#[test]
fn agent_commands_report_metadata_only_unavailable_state() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempdir()?;
    let context = test_context(&directory);

    let mut status_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "agent", "status"])?,
        &context,
        &mut status_output,
    )?;
    let status_output = String::from_utf8(status_output)?;
    assert!(status_output.contains("agent: unavailable"));
    assert!(status_output.contains("running: no"));

    let mut start_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "agent", "start"])?,
        &context,
        &mut start_output,
    )?;
    let start_output = String::from_utf8(start_output)?;
    assert!(start_output.contains("daemon not available in this build"));
    assert!(start_output.contains("socket:"));

    let mut stop_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "agent", "stop"])?,
        &context,
        &mut stop_output,
    )?;
    assert!(String::from_utf8(stop_output)?.contains("agent: stopped"));

    let mut logs_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "agent", "logs"])?,
        &context,
        &mut logs_output,
    )?;
    let logs_output = String::from_utf8(logs_output)?;
    assert!(logs_output.contains("\"action\":\"start\""));
    assert!(logs_output.contains("\"action\":\"stop\""));
    assert!(!logs_output.contains("secret"));

    let mut limited_logs_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "agent", "logs", "--lines", "1"])?,
        &context,
        &mut limited_logs_output,
    )?;
    let limited_logs_output = String::from_utf8(limited_logs_output)?;
    assert!(limited_logs_output.contains("\"action\":\"stop\""));
    assert!(!limited_logs_output.contains("\"action\":\"start\""));
    Ok(())
}

#[test]
fn agent_logs_filter_redact_rotate_and_harden_local_files() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempdir()?;
    let context = test_context(&directory);
    let base = 1_700_000_000_i64 * super::NANOS_PER_SECOND;
    super::prepare_agent_log_dir(&context)?;
    let log_path = super::agent_log_path(&context);
    let old_path = super::agent_rotated_log_path(&context, 1);
    fs::write(
        &old_path,
        format!(
            "{}\n",
            json!({
                "timestamp": base,
                "action": "old",
                "message": "older",
            })
        ),
    )?;
    fs::write(
        &log_path,
        format!(
            "{}\n{}\n",
            json!({
                "timestamp": base + super::NANOS_PER_SECOND,
                "action": "token",
                "message": "sk_test_sampleTokenValue123",
                "path": directory.path().join("project/.env").display().to_string(),
                "grant_token": "grant-token-value",
                "env": {"DATABASE_URL": "postgres://localhost/app"},
            }),
            json!({
                "timestamp": "2024-01-01T00:00:02Z",
                "action": "new",
                "message": "done",
            }),
        ),
    )?;

    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "agent", "logs", "--since", "2023-11-14T22:13:21Z"])?,
        &context,
        &mut output,
    )?;
    let output = String::from_utf8(output)?;
    assert!(!output.contains("\"action\":\"old\""));
    assert!(output.contains("\"action\":\"token\""));
    assert!(output.contains("\"action\":\"new\""));
    assert!(output.contains("lk_redacted_PROVIDER_TOKEN"));
    assert!(output.contains("path_hash"));
    assert!(!output.contains("sk_test_sampleTokenValue123"));
    assert!(!output.contains(directory.path().to_string_lossy().as_ref()));
    assert!(!output.contains("grant-token-value"));
    assert!(!output.contains("postgres://localhost/app"));

    let mut unix_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "agent", "logs", "--since", "1700000001"])?,
        &context,
        &mut unix_output,
    )?;
    assert!(!String::from_utf8(unix_output)?.contains("\"action\":\"old\""));

    fs::write(&log_path, "x".repeat(usize::try_from(super::AGENT_LOG_MAX_BYTES)? + 1))?;
    super::append_agent_log(&context, "rotated", "ok", "safe")?;
    assert!(super::agent_rotated_log_path(&context, 1).exists());
    assert!(fs::read_to_string(&log_path)?.contains("\"action\":\"rotated\""));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs::metadata(&log_path)?.permissions().mode() & 0o777, 0o600);
        assert_eq!(
            fs::metadata(super::agent_data_dir(&context))?.permissions().mode() & 0o777,
            0o700
        );
    }
    Ok(())
}

#[test]
fn agent_logs_rejects_excessive_line_count() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    let result = run_with_context(
        Cli::try_parse_from(["locket", "agent", "logs", "--lines", "10001"])?,
        &context,
        &mut output,
    );
    assert_error_contains(result, "capped at 10000");
    Ok(())
}

#[test]
fn doctor_reports_locked_safe_diagnostics_and_exit_codes() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempdir()?;
    let context = test_context(&directory);

    let mut missing_output = Vec::new();
    let code = run_with_context(
        Cli::try_parse_from(["locket", "doctor"])?,
        &context,
        &mut missing_output,
    )?;
    assert_eq!(code, 1);
    let missing_output = String::from_utf8(missing_output)?;
    assert!(missing_output.contains("fail project_resolution"));
    assert!(missing_output.contains("pass store_open_schema_bootstrap"));

    let mut init_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut init_output,
    )?;
    run_git(directory.path(), &["init"])?;
    let mut hook_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "install-hooks"])?,
        &context,
        &mut hook_output,
    )?;

    let mut doctor_output = Vec::new();
    let code =
        run_with_context(Cli::try_parse_from(["locket", "doctor"])?, &context, &mut doctor_output)?;
    assert_eq!(code, 0);
    let doctor_output = String::from_utf8(doctor_output)?;
    assert!(doctor_output.contains("pass locket_toml_parseability"));
    assert!(doctor_output.contains("pass sqlite_integrity"));
    assert!(doctor_output.contains("pass trusted_roots"));
    assert!(doctor_output.contains("skip audit_hmac_verification"));
    assert!(doctor_output.contains("summary:"));

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let doctor_metadata = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'DOCTOR'",
        [],
        |row| row.get::<_, String>(0),
    )?;
    let doctor_metadata: serde_json::Value = serde_json::from_str(&doctor_metadata)?;
    assert_eq!(doctor_metadata["action"], "DOCTOR");
    assert_eq!(doctor_metadata["status"], "SUCCESS");
    assert_eq!(doctor_metadata["fail_count"], 0);
    assert_eq!(doctor_metadata["skip_count"], 5);
    assert!(
        doctor_metadata["check_names"]
            .as_array()
            .is_some_and(|names| names.iter().any(|name| name == "sqlite_integrity"))
    );
    assert!(!doctor_metadata.to_string().contains(directory.path().to_string_lossy().as_ref()));
    Ok(())
}

#[test]
fn debug_bundle_redacted_writes_metadata_only_summary() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut init_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut init_output,
    )?;
    let output_path = directory.path().join("bundle.tar.gz");

    let mut bundle_output = Vec::new();
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "debug",
            "bundle",
            "--redacted",
            "--output",
            output_path.to_str().ok_or("utf8 path")?,
        ])?,
        &context,
        &mut bundle_output,
    )?;
    assert!(String::from_utf8(bundle_output)?.contains("redacted: yes"));

    let bundle = read_debug_bundle_json(&output_path)?;
    assert!(bundle.contains("\"redacted\": true"));
    assert!(bundle.contains("\"project\""));
    assert!(bundle.contains("\"diagnostics\""));
    assert!(bundle.contains("\"store_path_hash\""));
    assert!(!bundle.contains(directory.path().to_string_lossy().as_ref()));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mode = fs::metadata(&output_path)?.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
    Ok(())
}

#[test]
fn debug_bundle_default_output_uses_user_diagnostics_dir() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut init_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut init_output,
    )?;

    let mut bundle_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "debug", "bundle", "--redacted"])?,
        &context,
        &mut bundle_output,
    )?;
    let bundle_output = String::from_utf8(bundle_output)?;
    let path_line = bundle_output
        .lines()
        .find_map(|line| line.strip_prefix("debug_bundle: "))
        .ok_or("missing debug bundle path")?;
    let output_path = PathBuf::from(path_line);
    assert!(output_path.starts_with(directory.path().join("diagnostics")));
    assert_eq!(output_path.extension().and_then(OsStr::to_str), Some("gz"));
    assert!(!output_path.starts_with(directory.path().join(".git")));
    assert!(bundle_output.contains("redacted: yes"));

    let bundle = read_debug_bundle_json(&output_path)?;
    assert!(bundle.contains("\"redacted\": true"));
    assert!(!bundle.contains(directory.path().to_string_lossy().as_ref()));
    Ok(())
}

#[test]
fn debug_bundle_refuses_to_overwrite_existing_output() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let output_path = directory.path().join("existing.tar.gz");
    fs::write(&output_path, "existing")?;

    let mut bundle_output = Vec::new();
    let result = run_with_context(
        Cli::try_parse_from([
            "locket",
            "debug",
            "bundle",
            "--redacted",
            "--output",
            output_path.to_str().ok_or("utf8 path")?,
        ])?,
        &context,
        &mut bundle_output,
    );
    assert_error_contains(result.map(|_| ()), "debug bundle output already exists");
    assert_eq!(fs::read_to_string(output_path)?, "existing");
    Ok(())
}

#[test]
fn config_commands_manage_allowlisted_non_secret_preferences()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);

    let mut empty_list = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "config", "list"])?,
        &context,
        &mut empty_list,
    )?;
    assert_eq!(String::from_utf8(empty_list)?, "no config values\n");

    let mut set_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "config", "set", "privacy.redact_names", "true"])?,
        &context,
        &mut set_output,
    )?;
    assert_eq!(String::from_utf8(set_output)?, "set privacy.redact_names\n");

    let config_file = std::fs::read_to_string(directory.path().join("config.toml"))?;
    assert!(config_file.contains("[privacy]"));
    assert!(config_file.contains("redact_names = true"));

    let mut get_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "config", "get", "privacy.redact_names"])?,
        &context,
        &mut get_output,
    )?;
    assert_eq!(String::from_utf8(get_output)?, "true\n");

    let mut duration_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "config", "set", "reveal.ttl", "5m"])?,
        &context,
        &mut duration_output,
    )?;
    assert_eq!(String::from_utf8(duration_output)?, "set reveal.ttl\n");

    let mut list_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "config", "list"])?,
        &context,
        &mut list_output,
    )?;
    let list_output = String::from_utf8(list_output)?;
    assert!(list_output.contains("privacy.redact_names=true"));
    assert!(list_output.contains("reveal.ttl=5m"));

    let mut agent_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "config", "set", "agent.autostart", "false"])?,
        &context,
        &mut agent_output,
    )?;
    assert_eq!(String::from_utf8(agent_output)?, "set agent.autostart\n");

    let mut refresh_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "config", "set", "example.auto_refresh", "false"])?,
        &context,
        &mut refresh_output,
    )?;
    assert_eq!(String::from_utf8(refresh_output)?, "set example.auto_refresh\n");

    let mut retention_output = Vec::new();
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "config",
            "set",
            "runtime.session_secret_name_retention",
            "off",
        ])?,
        &context,
        &mut retention_output,
    )?;
    assert_eq!(String::from_utf8(retention_output)?, "set runtime.session_secret_name_retention\n");

    let mut unset_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "config", "unset", "privacy.redact_names"])?,
        &context,
        &mut unset_output,
    )?;
    assert_eq!(String::from_utf8(unset_output)?, "unset privacy.redact_names\n");

    let mut get_unset_output = Vec::new();
    let result = run_with_context(
        Cli::try_parse_from(["locket", "config", "get", "privacy.redact_names"])?,
        &context,
        &mut get_unset_output,
    );
    assert_error_contains(result, "config key is not set");
    Ok(())
}

#[test]
fn config_commands_manage_documented_non_secret_preferences()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);

    for (key, value) in [
        ("ui.theme", "dark"),
        ("ui.density", "compact"),
        ("editor.default", "vim"),
        ("agent.unlock_ttl", "15m"),
        ("rotation.max_grace_ttl", "30d"),
        ("shell.integration", "prompt-only"),
        ("updates.channel", "stable"),
        ("updates.manifest_url", "https://updates.example.test/manifest.json"),
        ("user_verification_required_for.unlock", "true"),
        ("user_verification_required_for.dangerous_profile_switch", "true"),
    ] {
        let mut output = Vec::new();
        run_with_context(
            Cli::try_parse_from(["locket", "config", "set", key, value])?,
            &context,
            &mut output,
        )?;
        assert_eq!(String::from_utf8(output)?, format!("set {key}\n"));
    }

    let mut list_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "config", "list"])?,
        &context,
        &mut list_output,
    )?;
    let list_output = String::from_utf8(list_output)?;
    assert!(list_output.contains("ui.theme=dark"));
    assert!(list_output.contains("editor.default=vim"));
    assert!(
        list_output.contains("updates.manifest_url=https://updates.example.test/manifest.json")
    );
    assert!(list_output.contains("user_verification_required_for.unlock=true"));
    Ok(())
}

#[test]
fn config_set_rejects_unknown_keys_invalid_values_and_secret_like_values()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);

    let mut output = Vec::new();
    let unknown = run_with_context(
        Cli::try_parse_from(["locket", "config", "set", "provider.token", "false"])?,
        &context,
        &mut output,
    );
    assert_error_contains(unknown, "unsupported config key");

    let mut output = Vec::new();
    let invalid_bool = run_with_context(
        Cli::try_parse_from(["locket", "config", "set", "agent.autostart", "yes"])?,
        &context,
        &mut output,
    );
    assert_error_contains(invalid_bool, "true or false");

    let mut output = Vec::new();
    let oversized_ttl = run_with_context(
        Cli::try_parse_from(["locket", "config", "set", "reveal.ttl", "6m"])?,
        &context,
        &mut output,
    );
    assert_error_contains(oversized_ttl, "5m or less");

    let mut output = Vec::new();
    let invalid_retention = run_with_context(
        Cli::try_parse_from([
            "locket",
            "config",
            "set",
            "runtime.session_secret_name_retention",
            "forever",
        ])?,
        &context,
        &mut output,
    );
    assert_error_contains(invalid_retention, "duration or off");

    let mut output = Vec::new();
    let invalid_theme = run_with_context(
        Cli::try_parse_from(["locket", "config", "set", "ui.theme", "purple"])?,
        &context,
        &mut output,
    );
    assert_error_contains(invalid_theme, "system, light, or dark");

    let mut output = Vec::new();
    let invalid_editor = run_with_context(
        Cli::try_parse_from(["locket", "config", "set", "editor.default", "~/bin/editor"])?,
        &context,
        &mut output,
    );
    assert_error_contains(invalid_editor, "shell expansion");

    let mut output = Vec::new();
    let invalid_rotation = run_with_context(
        Cli::try_parse_from(["locket", "config", "set", "rotation.max_grace_ttl", "31d"])?,
        &context,
        &mut output,
    );
    assert_error_contains(invalid_rotation, "30d or less");

    let mut output = Vec::new();
    let invalid_shell = run_with_context(
        Cli::try_parse_from(["locket", "config", "set", "shell.integration", "always"])?,
        &context,
        &mut output,
    );
    assert_error_contains(invalid_shell, "off, prompt-only, or hook");

    let mut output = Vec::new();
    let invalid_manifest = run_with_context(
        Cli::try_parse_from([
            "locket",
            "config",
            "set",
            "updates.manifest_url",
            "http://updates.example.test/manifest.json",
        ])?,
        &context,
        &mut output,
    );
    assert_error_contains(invalid_manifest, "HTTPS URL");

    let mut output = Vec::new();
    let token = run_with_context(
        Cli::try_parse_from([
            "locket",
            "config",
            "set",
            "reveal.ttl",
            "sk_test_sampleTokenValue123",
        ])?,
        &context,
        &mut output,
    );
    assert_error_contains(token, "looks like a secret");
    assert!(!directory.path().join("config.toml").exists());
    Ok(())
}

#[test]
fn config_get_and_list_reject_malformed_stored_values() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    fs::write(directory.path().join("config.toml"), "[privacy]\nredact_names = \"yes\"\n")?;

    let mut get_output = Vec::new();
    let get = run_with_context(
        Cli::try_parse_from(["locket", "config", "get", "privacy.redact_names"])?,
        &context,
        &mut get_output,
    );
    assert_error_contains(get, "invalid stored config value for privacy.redact_names");

    let mut list_output = Vec::new();
    let list = run_with_context(
        Cli::try_parse_from(["locket", "config", "list"])?,
        &context,
        &mut list_output,
    );
    assert_error_contains(list, "invalid stored config value for privacy.redact_names");
    Ok(())
}

#[test]
fn config_security_relevant_updates_write_metadata_only_audit_when_project_exists()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut init_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut init_output,
    )?;

    let mut set_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "config", "set", "agent.autostart", "true"])?,
        &context,
        &mut set_output,
    )?;

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'CONFIG_UPDATE'",
        [],
        |row| row.get(0),
    )?;
    assert!(metadata.contains("\"key\":\"agent.autostart\""));
    assert!(metadata.contains("\"operation\":\"set\""));
    assert!(!metadata.contains("true"));
    Ok(())
}

#[test]
fn passkey_register_is_unavailable_without_writing_metadata()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);

    let mut register_output = Vec::new();
    let register = run_with_context(
        Cli::try_parse_from(["locket", "passkey", "register"])?,
        &context,
        &mut register_output,
    );
    assert_error_contains(register, "not available");
    assert!(register_output.is_empty());
    Ok(())
}

#[test]
fn passkey_list_and_remove_use_project_store_and_audit() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context_with_confirmation(&directory, "work-laptop\n");
    let mut init_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut init_output,
    )?;
    let resolved = super::resolve_project(&context.cwd)?.ok_or("project should resolve")?;
    let project_id = resolved.config.project_id.to_string();
    let credential = locket_store::PasskeyCredentialRecord {
        id: "lk_passkey_test".to_owned(),
        project_id: project_id.clone(),
        label: "work-laptop".to_owned(),
        credential_id: vec![0xab, 0xcd, 0xef, 0x12, 0x34, 0x56],
        transports: vec!["internal".to_owned(), "usb".to_owned()],
        prf_capable: true,
        backup_eligible: Some(true),
        backup_state: Some(false),
        created_at: 100,
        last_used_at: Some(200),
        revoked_at: None,
    };
    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    store.insert_passkey_credential(&credential)?;

    let mut list_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "passkey", "list"])?,
        &context,
        &mut list_output,
    )?;
    let list_output = String::from_utf8(list_output)?;
    assert!(list_output.contains("work-laptop"));
    assert!(list_output.contains("credential_id_prefix=abcdef123456"));
    assert!(list_output.contains("transports=internal,usb"));
    assert!(list_output.contains("prf=yes"));
    assert!(list_output.contains("private_key_material: never displayed"));

    let mut remove_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "passkey", "remove", "work-laptop"])?,
        &context,
        &mut remove_output,
    )?;
    let remove_output = String::from_utf8(remove_output)?;
    assert!(remove_output.contains("passkey: revoked"));
    assert!(remove_output.contains("passkey_id: lk_passkey_test"));
    assert!(!remove_output.contains("abcdef123456abcdef"));

    let active = store.list_passkey_credentials(&project_id, false)?;
    assert!(active.is_empty());
    let all = store.list_passkey_credentials(&project_id, true)?;
    assert_eq!(all.len(), 1);
    assert!(all[0].revoked_at.is_some());
    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'PASSKEY_REMOVE'",
        [],
        |row| row.get(0),
    )?;
    assert!(metadata.contains("\"credential_id_prefix\":\"abcdef123456\""));
    assert!(!metadata.contains("abcdef123456abcdef"));
    Ok(())
}

#[test]
fn lock_and_unlock_use_direct_metadata_only_mode() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);

    let mut lock_output = Vec::new();
    run_with_context(Cli::try_parse_from(["locket", "lock"])?, &context, &mut lock_output)?;
    let lock_output = String::from_utf8(lock_output)?;
    assert!(lock_output.contains("no agent-held keys"));
    assert!(lock_output.contains("metadata_only: yes"));

    let mut init_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut init_output,
    )?;
    let mut unlock_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "unlock", "--verify-user"])?,
        &context,
        &mut unlock_output,
    )?;
    let unlock_output = String::from_utf8(unlock_output)?;
    assert!(unlock_output.contains("metadata-only direct CLI unlock succeeded"));
    assert!(unlock_output.contains("cached_keys: no"));
    assert!(unlock_output.contains("platform user verification is not implemented"));
    Ok(())
}

#[test]
fn passphrase_fallback_covers_init_unlock_and_decrypt() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context_with_key_store(&directory, Arc::new(UnavailableMasterKeyStore));

    let mut init_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut init_output,
    )?;
    assert!(String::from_utf8(init_output)?.contains("master_key_source: passphrase-fallback"));
    let fallback_files = std::fs::read_dir(directory.path().join("passphrase-fallback"))?
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(fallback_files.len(), 1);

    let mut unlock_output = Vec::new();
    run_with_context(Cli::try_parse_from(["locket", "unlock"])?, &context, &mut unlock_output)?;
    let unlock_output = String::from_utf8(unlock_output)?;
    assert!(unlock_output.contains("unlock_source: passphrase-fallback"));

    let args = test_secret_write_args("DATABASE_URL");
    super::set_secret_value(&context, &args, "postgres://localhost/app", "manual", 1_000)?;
    let mut reveal_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "get", "DATABASE_URL", "--reveal", "--force"])?,
        &context,
        &mut reveal_output,
    )?;
    assert_eq!(String::from_utf8(reveal_output)?, "postgres://localhost/app\n");
    Ok(())
}

#[test]
fn passphrase_fallback_covers_stale_os_key_material() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let fallback_context =
        test_context_with_key_store(&directory, Arc::new(UnavailableMasterKeyStore));

    let mut init_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &fallback_context,
        &mut init_output,
    )?;
    let args = test_secret_write_args("DATABASE_URL");
    super::set_secret_value(&fallback_context, &args, "postgres://localhost/app", "manual", 1_000)?;

    let stale_context =
        test_context_with_key_store(&directory, Arc::new(StaleLoadingMasterKeyStore));

    let mut unlock_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "unlock"])?,
        &stale_context,
        &mut unlock_output,
    )?;
    assert!(String::from_utf8(unlock_output)?.contains("unlock_source: passphrase-fallback"));

    let mut reveal_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "get", "DATABASE_URL", "--reveal", "--force"])?,
        &stale_context,
        &mut reveal_output,
    )?;
    assert_eq!(String::from_utf8(reveal_output)?, "postgres://localhost/app\n");

    let mut create_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "profile", "create", "prod"])?,
        &stale_context,
        &mut create_output,
    )?;
    let mut use_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "use", "prod"])?,
        &fallback_context,
        &mut use_output,
    )?;
    let args = test_secret_write_args("API_TOKEN");
    super::set_secret_value(&fallback_context, &args, "prod-token", "manual", 2_000)?;

    let mut prod_reveal_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "get", "API_TOKEN", "--reveal", "--force"])?,
        &fallback_context,
        &mut prod_reveal_output,
    )?;
    assert_eq!(String::from_utf8(prod_reveal_output)?, "prod-token\n");
    Ok(())
}

#[test]
fn recovery_rotate_creates_envelope_and_recover_restores_master_key()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let original_key_store = Arc::new(MemoryMasterKeyStore::default());
    let context = test_context_with_key_store(&directory, original_key_store);
    let mut init_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut init_output,
    )?;
    let init_output = String::from_utf8(init_output)?;
    let initial_recovery_code = recovery_code_from_output(&init_output)?.to_owned();
    let args = test_secret_write_args("DATABASE_URL");
    super::set_secret_value(&context, &args, "postgres://localhost/app", "manual", 1_000)?;

    let rotate_context = context_with_recovery_code(&context, &initial_recovery_code);
    let mut rotate_output = Vec::new();
    super::recovery_rotate_command(&rotate_context, &mut rotate_output)?;
    let rotate_output = String::from_utf8(rotate_output)?;
    assert!(rotate_output.contains("recovery_code_rotate: success"));
    assert!(rotate_output.contains("shown once"));
    assert!(rotate_output.contains("metadata_only: yes"));
    assert!(!rotate_output.contains("postgres://localhost/app"));
    let recovery_code = recovery_code_from_output(&rotate_output)?;
    let recovery_code_bytes = locket_crypto::recovery_code_decode(recovery_code)?;

    let recovery_dir = directory.path().join(".locket/recovery");
    assert!(recovery_dir.join("kdf.toml").exists());
    assert!(recovery_dir.join("envelope.bin").exists());

    let recovered_key_store = Arc::new(MemoryMasterKeyStore::default());
    let recovered_context = test_context_with_key_store(&directory, recovered_key_store.clone());
    let resolved = super::require_project(&recovered_context)?;
    let kdf = locket_platform::load_recovery_kdf_toml(&super::recovery_dir(&resolved))?;
    let envelope = locket_platform::load_recovery_envelope(&super::recovery_dir(&resolved))?;
    let mut recover_output = Vec::new();
    super::restore_from_recovery_code(
        &recovered_context,
        &mut recover_output,
        &resolved,
        &kdf,
        &envelope,
        &recovery_code_bytes,
        false,
    )?;
    let recover_output = String::from_utf8(recover_output)?;
    assert!(recover_output.contains("recovered: master_key"));
    assert!(recover_output.contains("metadata_only: yes"));
    assert!(!recover_output.contains("postgres://localhost/app"));
    assert!(recovered_key_store.load_master_key(resolved.config.project_id.as_str()).is_ok());

    let mut get_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "get", "DATABASE_URL", "--reveal", "--force"])?,
        &recovered_context,
        &mut get_output,
    )?;
    assert_eq!(String::from_utf8(get_output)?, "postgres://localhost/app\n");
    Ok(())
}

#[test]
fn install_hooks_requires_confirmation_for_unmanaged_hook() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempdir()?;
    let context = test_context_with_confirmation(&directory, "wrong\n");
    let hooks_dir = directory.path().join(".git/hooks");
    std::fs::create_dir_all(&hooks_dir)?;
    std::fs::write(hooks_dir.join("pre-commit"), "echo existing\n")?;

    let mut init_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut init_output,
    )?;

    let mut install_output = Vec::new();
    let result = run_with_context(
        Cli::try_parse_from(["locket", "install-hooks"])?,
        &context,
        &mut install_output,
    );
    assert_error_contains(result, "confirmation did not match");
    let install_output = String::from_utf8(install_output)?;
    assert!(install_output.contains("pre_commit_hook: unmanaged"));
    assert!(install_output.contains("metadata_only: yes"));
    assert!(install_output.contains("type project name 'app'"));
    assert!(!install_output.contains("echo existing"));
    assert_eq!(std::fs::read_to_string(hooks_dir.join("pre-commit"))?, "echo existing\n");

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let hook_installs: u32 = store.connection().query_row(
        "SELECT COUNT(*) FROM audit_log WHERE action = 'HOOK_INSTALL'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(hook_installs, 0);
    Ok(())
}

#[test]
fn install_hooks_confirms_unmanaged_hook_and_preserves_existing_hook()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context_with_confirmation(&directory, "app\n");
    let hooks_dir = directory.path().join(".git/hooks");
    std::fs::create_dir_all(&hooks_dir)?;
    std::fs::write(hooks_dir.join("pre-commit"), "#!/bin/sh\necho existing\n")?;

    let mut init_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut init_output,
    )?;

    let mut install_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "install-hooks"])?,
        &context,
        &mut install_output,
    )?;
    let install_output = String::from_utf8(install_output)?;
    assert!(install_output.contains("pre_commit_hook: unmanaged"));
    assert!(install_output.contains("hook_change: prepended-after-confirmation"));
    assert!(install_output.contains("hook: locket scan --staged"));
    assert!(install_output.contains("secrets: not written"));
    assert!(!install_output.contains("echo existing"));

    let hook = std::fs::read_to_string(hooks_dir.join("pre-commit"))?;
    assert!(hook.starts_with("#!/bin/sh\n\n"));
    assert!(hook.contains("locket scan --staged"));
    assert!(hook.contains(super::HOOK_END));
    assert!(hook.contains("echo existing"));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(hooks_dir.join("pre-commit"))?.permissions().mode();
        assert_eq!(mode & 0o700, 0o700);
    }

    let mut reinstall_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "install-hooks"])?,
        &context,
        &mut reinstall_output,
    )?;
    assert!(String::from_utf8(reinstall_output)?.contains("hook_change: unchanged"));
    let reinstalled_hook = std::fs::read_to_string(hooks_dir.join("pre-commit"))?;
    assert_eq!(reinstalled_hook, hook);
    assert_eq!(reinstalled_hook.matches(super::HOOK_BEGIN).count(), 1);
    assert_eq!(reinstalled_hook.matches(super::HOOK_END).count(), 1);

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let hook_installs: u32 = store.connection().query_row(
        "SELECT COUNT(*) FROM audit_log WHERE action = 'HOOK_INSTALL'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(hook_installs, 2);
    Ok(())
}

#[test]
fn install_hooks_creates_missing_hook_without_confirmation()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context_with_confirmation(&directory, "wrong\n");
    let hooks_dir = directory.path().join(".git/hooks");
    std::fs::create_dir_all(&hooks_dir)?;

    let mut init_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut init_output,
    )?;

    let mut install_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "install-hooks"])?,
        &context,
        &mut install_output,
    )?;
    let install_output = String::from_utf8(install_output)?;
    assert!(install_output.contains("hook_change: created"));
    assert!(!install_output.contains("pre_commit_hook: unmanaged"));

    let hook = std::fs::read_to_string(hooks_dir.join("pre-commit"))?;
    assert!(hook.starts_with("#!/bin/sh"));
    assert!(hook.contains(super::HOOK_BEGIN));
    assert!(hook.contains("locket scan --staged"));
    assert!(hook.contains(super::HOOK_END));

    let stale_managed = hook.replace("locket scan --staged", "locket scan --staged --old");
    std::fs::write(hooks_dir.join("pre-commit"), stale_managed)?;
    let mut reinstall_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "install-hooks"])?,
        &context,
        &mut reinstall_output,
    )?;
    assert!(String::from_utf8(reinstall_output)?.contains("hook_change: rewrote-managed-block"));
    let rewritten_hook = std::fs::read_to_string(hooks_dir.join("pre-commit"))?;
    assert!(rewritten_hook.contains("locket scan --staged"));
    assert!(!rewritten_hook.contains("--old"));
    Ok(())
}

#[test]
fn set_command_reads_secure_secret_value_without_leaking_it()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context_with_secret_value(&directory, "postgres://localhost/prompt");
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;

    let mut set_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "set", "DATABASE_URL"])?,
        &context,
        &mut set_output,
    )?;
    let set_output = String::from_utf8(set_output)?;
    assert!(set_output.contains("set DATABASE_URL"));
    assert!(!set_output.contains("postgres://localhost/prompt"));

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'SET'",
        [],
        |row| row.get(0),
    )?;
    assert!(!metadata.contains("postgres://localhost/prompt"));

    let mut reveal_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "get", "DATABASE_URL", "--reveal", "--force"])?,
        &context,
        &mut reveal_output,
    )?;
    assert_eq!(String::from_utf8(reveal_output)?, "postgres://localhost/prompt\n");
    Ok(())
}

#[test]
fn set_command_rejects_empty_secure_secret_before_writing() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempdir()?;
    let context = test_context_with_secret_value(&directory, "");
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;

    let result = run_with_context(
        Cli::try_parse_from(["locket", "set", "DATABASE_URL"])?,
        &context,
        &mut Vec::new(),
    );
    assert_error_contains(result, "secret value cannot be empty");

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let set_count: u32 = store.connection().query_row(
        "SELECT COUNT(*) FROM audit_log WHERE action = 'SET'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(set_count, 0);
    Ok(())
}

#[test]
fn set_command_preflights_source_conflicts_before_reading_secret()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context_with_failing_secret_reader(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    let args =
        test_secret_write_args_for_source("DATABASE_URL", super::SecretSourceArg::MachineLocal);
    super::set_secret_value(&context, &args, "postgres://localhost/machine", "manual", 1_000)?;

    let result = run_with_context(
        Cli::try_parse_from(["locket", "set", "DATABASE_URL"])?,
        &context,
        &mut Vec::new(),
    );
    assert_error_contains(result, "pass --source");
    Ok(())
}

#[test]
fn rotate_command_reads_secure_secret_value_without_leaking_it()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context_with_secret_value(&directory, "postgres://localhost/new");
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    let args = test_secret_write_args("DATABASE_URL");
    super::set_secret_value(&context, &args, "postgres://localhost/old", "manual", 1_000)?;

    let mut rotate_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "rotate", "DATABASE_URL"])?,
        &context,
        &mut rotate_output,
    )?;
    let rotate_output = String::from_utf8(rotate_output)?;
    assert!(rotate_output.contains("rotated DATABASE_URL"));
    assert!(rotate_output.contains("version=2"));
    assert!(!rotate_output.contains("postgres://localhost/new"));
    assert!(!rotate_output.contains("postgres://localhost/old"));

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'ROTATE'",
        [],
        |row| row.get(0),
    )?;
    assert!(!metadata.contains("postgres://localhost/new"));
    assert!(!metadata.contains("postgres://localhost/old"));

    let mut reveal_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "get", "DATABASE_URL", "--reveal", "--force"])?,
        &context,
        &mut reveal_output,
    )?;
    assert_eq!(String::from_utf8(reveal_output)?, "postgres://localhost/new\n");
    Ok(())
}

#[test]
fn rotate_command_preflights_source_ambiguity_before_reading_secret()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context_with_failing_secret_reader(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    let user_args = test_secret_write_args("DATABASE_URL");
    super::set_secret_value(&context, &user_args, "postgres://localhost/user", "manual", 1_000)?;
    let machine_args =
        test_secret_write_args_for_source("DATABASE_URL", super::SecretSourceArg::MachineLocal);
    super::set_secret_value(
        &context,
        &machine_args,
        "postgres://localhost/machine",
        "manual",
        2_000,
    )?;

    let result = run_with_context(
        Cli::try_parse_from(["locket", "rotate", "DATABASE_URL"])?,
        &context,
        &mut Vec::new(),
    );
    assert_error_contains(result, "multiple sources");
    Ok(())
}

#[test]
fn set_list_get_and_rm_secret_value() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;

    let args = super::SecretWriteArgs {
        key: "DATABASE_URL".to_owned(),
        source: super::SourceArg { source: Some(super::SecretSourceArg::UserLocal) },
        metadata: super::SecretMetadataFlags {
            description: None,
            owner: None,
            tags: Vec::new(),
            required: false,
            optional: false,
        },
    };
    super::set_secret_value(&context, &args, "postgres://localhost/app", "manual", 1_000)?;

    let mut list_output = Vec::new();
    run_with_context(Cli::try_parse_from(["locket", "list"])?, &context, &mut list_output)?;
    let list_output = String::from_utf8(list_output)?;
    assert!(list_output.contains("DATABASE_URL"));
    assert!(!list_output.contains("postgres://localhost/app"));

    let mut get_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "get", "DATABASE_URL"])?,
        &context,
        &mut get_output,
    )?;
    let get_output = String::from_utf8(get_output)?;
    assert!(get_output.contains("version=1"));
    assert!(!get_output.contains("postgres://localhost/app"));

    let mut reveal_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "get", "DATABASE_URL", "--reveal", "--force"])?,
        &context,
        &mut reveal_output,
    )?;
    assert_eq!(String::from_utf8(reveal_output)?, "postgres://localhost/app\n");

    let mut rm_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "rm", "DATABASE_URL"])?,
        &context,
        &mut rm_output,
    )?;
    let mut list_after_rm = Vec::new();
    run_with_context(Cli::try_parse_from(["locket", "list"])?, &context, &mut list_after_rm)?;
    assert!(String::from_utf8(list_after_rm)?.contains("no secrets"));
    Ok(())
}

#[test]
fn get_copy_writes_metadata_only_audit_without_value_leakage()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    let args = test_secret_write_args("DATABASE_URL");
    super::set_secret_value(&context, &args, "postgres://localhost/app", "manual", 1_000)?;

    let copy_args =
        super::GetArgs { key: "DATABASE_URL".to_owned(), reveal: false, force: false, copy: true };
    let mut copy_output = Vec::new();
    super::get_command_with_clipboard(&context, &mut copy_output, &copy_args, |value| {
        assert_eq!(value, "postgres://localhost/app");
        Ok(())
    })?;
    let copy_output = String::from_utf8(copy_output)?;
    assert!(copy_output.contains("metadata_only=yes"));
    assert!(copy_output.contains("clipboard_clear_supported=no"));
    assert!(!copy_output.contains("postgres://localhost/app"));

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'COPY'",
        [],
        |row| row.get(0),
    )?;
    assert!(metadata.contains("\"access_mode\":\"clipboard\""));
    assert!(metadata.contains("\"ttl_seconds\":60"));
    assert!(metadata.contains("\"clipboard_clear_supported\":false"));
    assert!(metadata.contains("\"secret_name\":\"DATABASE_URL\""));
    assert!(!metadata.contains("postgres://localhost/app"));
    Ok(())
}

#[test]
fn get_copy_unavailable_audits_unsupported_state_without_value_leakage()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    let args = test_secret_write_args("DATABASE_URL");
    super::set_secret_value(&context, &args, "postgres://localhost/app", "manual", 1_000)?;

    let copy_args =
        super::GetArgs { key: "DATABASE_URL".to_owned(), reveal: false, force: false, copy: true };
    let mut copy_output = Vec::new();
    let result =
        super::get_command_with_clipboard(&context, &mut copy_output, &copy_args, |_value| {
            Err("clipboard command unavailable".to_owned())
        });
    assert_error_contains(result, "clipboard command unavailable");
    let copy_output = String::from_utf8(copy_output)?;
    assert!(copy_output.contains("clipboard TTL clearing is unsupported"));
    assert!(!copy_output.contains("postgres://localhost/app"));

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'COPY'",
        [],
        |row| row.get(0),
    )?;
    assert!(metadata.contains("\"status\":\"FAILED\""));
    assert!(metadata.contains("\"clipboard_supported\":false"));
    assert!(metadata.contains("\"unsupported_reason\":\"clipboard command unavailable\""));
    assert!(!metadata.contains("postgres://localhost/app"));
    Ok(())
}

#[test]
fn reveal_requires_force_for_noninteractive_stdout_and_audits_force()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    let args = test_secret_write_args("DATABASE_URL");
    super::set_secret_value(&context, &args, "postgres://localhost/app", "manual", 1_000)?;

    let mut reveal_output = Vec::new();
    let result = run_with_context(
        Cli::try_parse_from(["locket", "get", "DATABASE_URL", "--reveal"])?,
        &context,
        &mut reveal_output,
    );
    assert_error_contains(result.map(|_| ()), "requires an interactive terminal");

    let mut forced_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "get", "DATABASE_URL", "--reveal", "--force"])?,
        &context,
        &mut forced_output,
    )?;
    assert_eq!(String::from_utf8(forced_output)?, "postgres://localhost/app\n");

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'REVEAL'",
        [],
        |row| row.get(0),
    )?;
    assert!(metadata.contains("\"force\":true"));
    assert!(metadata.contains("\"access_mode\":\"stdout\""));
    assert!(!metadata.contains("postgres://localhost/app"));
    Ok(())
}

#[test]
fn meta_updates_secret_metadata_without_printing_values() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    let args = test_secret_write_args("DATABASE_URL");
    super::set_secret_value(&context, &args, "postgres://localhost/app", "manual", 1_000)?;

    let mut meta_output = Vec::new();
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "meta",
            "DATABASE_URL",
            "--description",
            "primary database",
            "--owner",
            "platform",
            "--tag",
            "database",
            "--tag",
            "prod",
            "--required",
        ])?,
        &context,
        &mut meta_output,
    )?;
    let meta_output = String::from_utf8(meta_output)?;
    assert!(meta_output.contains("metadata updated DATABASE_URL"));
    assert!(meta_output.contains("updated_fields: description,owner,tags,required"));
    assert!(meta_output.contains("metadata_only: yes"));
    assert!(!meta_output.contains("postgres://localhost/app"));

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let row = store.connection().query_row(
        "SELECT description, owner, tags_json, required, updated_at
         FROM secrets
         WHERE name = 'DATABASE_URL'",
        [],
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, bool>(3)?,
                row.get::<_, i64>(4)?,
            ))
        },
    )?;
    assert_eq!(row.0, "primary database");
    assert_eq!(row.1, "platform");
    assert_eq!(row.2, "[\"database\",\"prod\"]");
    assert!(row.3);
    assert_eq!(row.4, 1_000);

    let audit_metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'SECRET_META_UPDATE'",
        [],
        |row| row.get(0),
    )?;
    assert!(
        audit_metadata
            .contains("\"updated_fields\":[\"description\",\"owner\",\"tags\",\"required\"]")
    );
    assert!(audit_metadata.contains("\"updated_field_count\":4"));
    assert!(audit_metadata.contains("\"tag_update_count\":2"));
    assert!(audit_metadata.contains("\"required_update\":true"));
    assert!(!audit_metadata.contains("primary database"));
    assert!(!audit_metadata.contains("platform"));
    assert!(!audit_metadata.contains("postgres://localhost/app"));
    Ok(())
}

#[test]
fn meta_rejects_secret_like_metadata_without_storing_value()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    let args = test_secret_write_args("DATABASE_URL");
    super::set_secret_value(&context, &args, "postgres://localhost/app", "manual", 1_000)?;

    let provider = "sk_test_sampleTokenValue123";
    let result = run_with_context(
        Cli::try_parse_from(["locket", "meta", "DATABASE_URL", "--description", provider])?,
        &context,
        &mut Vec::new(),
    );
    assert_error_contains(result, "metadata field description looks like a secret");

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let row = store.connection().query_row(
        "SELECT description, updated_at FROM secrets WHERE name = 'DATABASE_URL'",
        [],
        |row| Ok((row.get::<_, Option<String>>(0)?, row.get::<_, i64>(1)?)),
    )?;
    assert_eq!(row, (None, 1_000));

    let audit_metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log
         WHERE action = 'SECRET_META_UPDATE' AND status = 'FAILED'",
        [],
        |row| row.get(0),
    )?;
    assert!(audit_metadata.contains("\"failure_reason\":\"metadata_privacy_validation\""));
    assert!(!audit_metadata.contains(provider));
    assert!(!audit_metadata.contains("postgres://localhost/app"));
    Ok(())
}

#[test]
fn meta_rejects_known_secret_value_metadata() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    let args = test_secret_write_args("DATABASE_URL");
    super::set_secret_value(&context, &args, "postgres://localhost/app", "manual", 1_000)?;

    let result = run_with_context(
        Cli::try_parse_from([
            "locket",
            "meta",
            "DATABASE_URL",
            "--owner",
            "postgres://localhost/app",
        ])?,
        &context,
        &mut Vec::new(),
    );
    assert_error_contains(result, "metadata field owner matches an existing secret value");

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let owner: Option<String> = store.connection().query_row(
        "SELECT owner FROM secrets WHERE name = 'DATABASE_URL'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(owner, None);

    let audit_metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log
         WHERE action = 'SECRET_META_UPDATE' AND status = 'FAILED'",
        [],
        |row| row.get(0),
    )?;
    assert!(!audit_metadata.contains("postgres://localhost/app"));
    Ok(())
}

#[test]
fn meta_rejects_control_character_metadata() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    let args = test_secret_write_args("DATABASE_URL");
    super::set_secret_value(&context, &args, "postgres://localhost/app", "manual", 1_000)?;

    let result = run_with_context(
        Cli::try_parse_from(["locket", "meta", "DATABASE_URL", "--tag", "prod\u{1b}[31m"])?,
        &context,
        &mut Vec::new(),
    );
    assert_error_contains(result, "metadata field tag contains control characters");
    Ok(())
}

#[test]
fn meta_requires_source_for_multiple_active_sources_and_updates_explicit_source()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    let user_args = test_secret_write_args("DATABASE_URL");
    super::set_secret_value(&context, &user_args, "postgres://localhost/user", "manual", 1_000)?;
    let machine_args = super::SecretWriteArgs {
        key: "DATABASE_URL".to_owned(),
        source: super::SourceArg { source: Some(super::SecretSourceArg::MachineLocal) },
        metadata: super::SecretMetadataFlags {
            description: None,
            owner: None,
            tags: Vec::new(),
            required: false,
            optional: false,
        },
    };
    super::set_secret_value(
        &context,
        &machine_args,
        "postgres://localhost/machine",
        "manual",
        2_000,
    )?;

    let ambiguous = run_with_context(
        Cli::try_parse_from([
            "locket",
            "meta",
            "DATABASE_URL",
            "--description",
            "ambiguous database",
        ])?,
        &context,
        &mut Vec::new(),
    );
    assert_error_contains(ambiguous, "multiple sources exist for this secret");

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let versions_before: i64 =
        store
            .connection()
            .query_row("SELECT COUNT(*) FROM secret_versions", [], |row| row.get(0))?;

    let mut meta_output = Vec::new();
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "meta",
            "DATABASE_URL",
            "--source",
            "machine-local",
            "--description",
            "machine database",
        ])?,
        &context,
        &mut meta_output,
    )?;
    let meta_output = String::from_utf8(meta_output)?;
    assert!(meta_output.contains("source=machine-local"));
    assert!(!meta_output.contains("postgres://localhost"));

    let descriptions = store.connection().query_row(
        "SELECT
            MAX(CASE WHEN source = 'user-local' THEN description END),
            MAX(CASE WHEN source = 'machine-local' THEN description END)
         FROM secrets
         WHERE name = 'DATABASE_URL'",
        [],
        |row| Ok((row.get::<_, Option<String>>(0)?, row.get::<_, Option<String>>(1)?)),
    )?;
    assert_eq!(descriptions.0, None);
    assert_eq!(descriptions.1.as_deref(), Some("machine database"));
    let versions_after: i64 =
        store
            .connection()
            .query_row("SELECT COUNT(*) FROM secret_versions", [], |row| row.get(0))?;
    assert_eq!(versions_after, versions_before);

    let audit_metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log
         WHERE action = 'SECRET_META_UPDATE' AND status = 'SUCCESS'",
        [],
        |row| row.get(0),
    )?;
    assert!(audit_metadata.contains("\"source\":\"machine-local\""));
    assert!(!audit_metadata.contains("machine database"));
    assert!(!audit_metadata.contains("postgres://localhost"));
    Ok(())
}

#[test]
fn diff_reports_profile_metadata_only_differences() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    let db_args = test_secret_write_args("DATABASE_URL");
    super::set_secret_value(&context, &db_args, "postgres://localhost/dev-old", "manual", 1_000)?;
    let rotate_args = test_rotate_args("DATABASE_URL", None);
    super::rotate_secret_value(
        &context,
        &rotate_args,
        "postgres://localhost/dev-new",
        2_000,
        None,
    )?;

    let mut create_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "profile", "create", "staging"])?,
        &context,
        &mut create_output,
    )?;
    let mut use_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "use", "staging"])?,
        &context,
        &mut use_output,
    )?;
    super::set_secret_value(&context, &db_args, "postgres://localhost/staging", "manual", 3_000)?;
    let api_args = test_secret_write_args("API_KEY");
    super::set_secret_value(&context, &api_args, "sk_test_sample", "manual", 4_000)?;

    let mut diff_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "diff", "dev", "staging"])?,
        &context,
        &mut diff_output,
    )?;
    let diff_output = String::from_utf8(diff_output)?;
    assert!(diff_output.contains("changed DATABASE_URL source=user-local"));
    assert!(diff_output.contains("dev_version=2"));
    assert!(diff_output.contains("staging_version=1"));
    assert!(diff_output.contains("only staging: API_KEY source=user-local version=1"));
    assert!(!diff_output.contains("postgres://localhost"));
    assert!(!diff_output.contains("sk_test_sample"));

    let mut empty_diff_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "diff", "staging", "staging"])?,
        &context,
        &mut empty_diff_output,
    )?;
    assert_eq!(String::from_utf8(empty_diff_output)?, "no differences\n");
    Ok(())
}

#[test]
fn diff_since_reports_active_profile_metadata_only_changes()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    let db_args = test_secret_write_args("DATABASE_URL");
    super::set_secret_value(&context, &db_args, "postgres://localhost/dev-old", "manual", 1_000)?;
    let rotate_args = test_rotate_args("DATABASE_URL", None);
    super::rotate_secret_value(
        &context,
        &rotate_args,
        "postgres://localhost/dev-new",
        2_000,
        None,
    )?;

    let mut diff_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "diff", "--since", "1970-01-01T00:00:00Z"])?,
        &context,
        &mut diff_output,
    )?;
    let diff_output = String::from_utf8(diff_output)?;
    assert!(diff_output.contains("profile: dev"));
    assert!(diff_output.contains("metadata_only: yes"));
    assert!(
        diff_output
            .contains("changed DATABASE_URL source=user-local state=active current_version=2")
    );
    assert!(diff_output.contains(
        "version DATABASE_URL source=user-local v1 state=deprecated created_at=1000 deprecated_at=2000"
    ));
    assert!(
        diff_output
            .contains("version DATABASE_URL source=user-local v2 state=current created_at=2000")
    );
    assert!(!diff_output.contains("postgres://localhost"));

    let mut empty_diff_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "diff", "--since", "1970-01-01T00:00:01Z"])?,
        &context,
        &mut empty_diff_output,
    )?;
    assert_eq!(String::from_utf8(empty_diff_output)?, "no differences\n");
    Ok(())
}

#[test]
fn diff_since_rejects_profile_arguments() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;

    let result = run_with_context(
        Cli::try_parse_from([
            "locket",
            "diff",
            "--since",
            "1970-01-01T00:00:00Z",
            "dev",
            "staging",
        ])?,
        &context,
        &mut Vec::new(),
    );
    assert_error_contains(result, "diff --since uses the active profile");
    Ok(())
}

#[test]
fn diff_since_reports_only_active_profile() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    let dev_args = test_secret_write_args("DEV_ONLY");
    super::set_secret_value(&context, &dev_args, "dev-secret-value", "manual", 1_000)?;

    let mut create_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "profile", "create", "staging"])?,
        &context,
        &mut create_output,
    )?;
    let mut use_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "use", "staging"])?,
        &context,
        &mut use_output,
    )?;
    let staging_args = test_secret_write_args("STAGING_ONLY");
    super::set_secret_value(&context, &staging_args, "staging-secret-value", "manual", 2_000)?;

    let mut diff_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "diff", "--since", "1970-01-01T00:00:00Z"])?,
        &context,
        &mut diff_output,
    )?;
    let diff_output = String::from_utf8(diff_output)?;
    assert!(diff_output.contains("profile: staging"));
    assert!(diff_output.contains("changed STAGING_ONLY source=user-local"));
    assert!(!diff_output.contains("DEV_ONLY"));
    assert!(!diff_output.contains("dev-secret-value"));
    assert!(!diff_output.contains("staging-secret-value"));
    Ok(())
}

#[test]
fn diff_since_ignores_access_audit_rows() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    let db_args = test_secret_write_args("DATABASE_URL");
    super::set_secret_value(&context, &db_args, "postgres://localhost/dev", "manual", 1_000)?;

    let copy_args =
        super::GetArgs { key: "DATABASE_URL".to_owned(), reveal: false, force: false, copy: true };
    let mut copy_output = Vec::new();
    super::get_command_with_clipboard(&context, &mut copy_output, &copy_args, |_value| Ok(()))?;

    let mut diff_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "diff", "--since", "1970-01-01T00:00:01Z"])?,
        &context,
        &mut diff_output,
    )?;
    assert_eq!(String::from_utf8(diff_output)?, "no differences\n");
    Ok(())
}

#[test]
fn diff_since_reports_metadata_updates() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    let db_args = test_secret_write_args("DATABASE_URL");
    super::set_secret_value(&context, &db_args, "postgres://localhost/dev", "manual", 1_000)?;

    let mut meta_output = Vec::new();
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "meta",
            "DATABASE_URL",
            "--description",
            "primary database",
        ])?,
        &context,
        &mut meta_output,
    )?;

    let mut diff_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "diff", "--since", "1970-01-01T00:00:01Z"])?,
        &context,
        &mut diff_output,
    )?;
    let diff_output = String::from_utf8(diff_output)?;
    assert!(diff_output.contains("action=SECRET_META_UPDATE"));
    assert!(!diff_output.contains("changed DATABASE_URL source=user-local"));
    assert!(!diff_output.contains("postgres://localhost"));
    assert!(!diff_output.contains("primary database"));
    Ok(())
}

#[test]
fn diff_since_parses_iso_offsets_and_fractional_nanos() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(super::resolve_diff_since(Path::new("."), "1970-01-01T00:00:00.000000001Z")?, 1);
    assert_eq!(
        super::resolve_diff_since(Path::new("."), "1969-12-31T16:00:00.000000001-08:00")?,
        1
    );
    assert_eq!(super::resolve_diff_since(Path::new("."), "1970-01-01")?, 0);
    assert_error_contains(
        super::resolve_diff_since(Path::new("."), "2024-02-30T00:00:00Z"),
        "invalid ISO date/time",
    );
    Ok(())
}

#[test]
fn diff_since_resolves_git_revision_with_direct_args() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    run_git(directory.path(), &["init"])?;
    run_git(directory.path(), &["config", "user.email", "locket@example.test"])?;
    run_git(directory.path(), &["config", "user.name", "Locket Test"])?;
    run_git(directory.path(), &["commit", "--allow-empty", "-m", "baseline"])?;

    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    let args = test_secret_write_args("API_TOKEN");
    super::set_secret_value(
        &context,
        &args,
        "sk_test_diff_since_git",
        "manual",
        super::now_unix_nanos()?,
    )?;

    let mut diff_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "diff", "--since", "HEAD"])?,
        &context,
        &mut diff_output,
    )?;
    let diff_output = String::from_utf8(diff_output)?;
    assert!(diff_output.contains("changed API_TOKEN source=user-local"));
    assert!(!diff_output.contains("sk_test_diff_since_git"));

    let invalid = run_with_context(
        Cli::try_parse_from(["locket", "diff", "--since", "not-a-real-rev"])?,
        &context,
        &mut Vec::new(),
    );
    assert_error_contains(invalid, "could not resolve diff --since value");
    Ok(())
}

#[test]
fn copy_creates_missing_target_profile_secret_without_leaking_value()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    let set_args = test_secret_write_args("DATABASE_URL");
    super::set_secret_value(&context, &set_args, "postgres://localhost/dev-copy", "manual", 1_000)?;
    let mut create_profile_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "profile", "create", "staging"])?,
        &context,
        &mut create_profile_output,
    )?;

    let mut copy_output = Vec::new();
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "copy",
            "DATABASE_URL",
            "--from",
            "dev",
            "--to",
            "staging",
        ])?,
        &context,
        &mut copy_output,
    )?;
    let copy_output = String::from_utf8(copy_output)?;
    assert!(copy_output.contains("operation=create"));
    assert!(copy_output.contains("version=1"));
    assert!(copy_output.contains("metadata_only=yes"));
    assert!(!copy_output.contains("postgres://localhost/dev-copy"));

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let project_id: String =
        store.connection().query_row("SELECT id FROM projects LIMIT 1", [], |row| row.get(0))?;
    let staging =
        store.get_profile_by_name(&project_id, "staging")?.ok_or("staging profile should exist")?;
    let secret = store
        .get_secret_by_source(&staging.project_id, &staging.id, "DATABASE_URL", "user-local")?
        .ok_or("target secret should exist")?;
    assert_eq!(secret.current_version, 1);
    assert_eq!(secret.origin, "profile-copy");
    assert_eq!(secret.last_rotated_at, None);
    let versions = store.list_secret_versions(&secret.id)?;
    assert_eq!(versions.len(), 1);
    assert_eq!(versions[0].state, "current");
    assert_eq!(versions[0].origin, "profile-copy");

    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'SECRET_COPY'",
        [],
        |row| row.get(0),
    )?;
    assert!(metadata.contains("\"target_version\":1"));
    assert!(!metadata.contains("postgres://localhost/dev-copy"));

    let mut use_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "use", "staging"])?,
        &context,
        &mut use_output,
    )?;
    let mut reveal_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "get", "DATABASE_URL", "--reveal", "--force"])?,
        &context,
        &mut reveal_output,
    )?;
    assert_eq!(String::from_utf8(reveal_output)?, "postgres://localhost/dev-copy\n");
    Ok(())
}

#[test]
fn copy_rotates_existing_target_with_no_grace_and_no_value_leakage()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    let set_args = test_secret_write_args("DATABASE_URL");
    super::set_secret_value(&context, &set_args, "postgres://localhost/source", "manual", 1_000)?;
    let mut create_profile_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "profile", "create", "staging"])?,
        &context,
        &mut create_profile_output,
    )?;
    let mut use_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "use", "staging"])?,
        &context,
        &mut use_output,
    )?;
    super::set_secret_value(
        &context,
        &set_args,
        "postgres://localhost/target-old",
        "manual",
        2_000,
    )?;

    let copy_args = super::CopyArgs {
        key: "DATABASE_URL".to_owned(),
        from: "dev".to_owned(),
        to: "staging".to_owned(),
        from_source: None,
        to_source: None,
    };
    let result = super::copy_secret_value(&context, &copy_args, 3_000)?;
    assert_eq!(result.operation, "rotate");
    assert_eq!(result.target_version, 2);

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let project_id: String =
        store.connection().query_row("SELECT id FROM projects LIMIT 1", [], |row| row.get(0))?;
    let staging =
        store.get_profile_by_name(&project_id, "staging")?.ok_or("staging profile should exist")?;
    let secret = store
        .get_secret_by_source(&project_id, &staging.id, "DATABASE_URL", "user-local")?
        .ok_or("target secret should exist")?;
    assert_eq!(secret.current_version, 2);
    assert_eq!(secret.last_rotated_at, Some(3_000));
    let versions = store.list_secret_versions(&secret.id)?;
    assert_eq!(versions.len(), 2);
    assert_eq!(versions[0].state, "deprecated");
    assert_eq!(versions[0].deprecated_at, Some(3_000));
    assert_eq!(versions[0].grace_until, None);
    assert_eq!(versions[1].state, "current");
    assert_eq!(versions[1].origin, "profile-copy");

    let mut history_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "history", "DATABASE_URL", "--profile", "staging"])?,
        &context,
        &mut history_output,
    )?;
    let history_output = String::from_utf8(history_output)?;
    assert!(history_output.contains("v1 state=deprecated"));
    assert!(history_output.contains("grace_until=-"));
    assert!(history_output.contains("v2 state=current"));
    assert!(!history_output.contains("postgres://localhost/source"));
    assert!(!history_output.contains("postgres://localhost/target-old"));

    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'SECRET_COPY'",
        [],
        |row| row.get(0),
    )?;
    assert!(metadata.contains("\"prior_target_version\":1"));
    assert!(metadata.contains("\"target_version\":2"));
    assert!(!metadata.contains("postgres://localhost/source"));
    assert!(!metadata.contains("postgres://localhost/target-old"));

    let mut reveal_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "get", "DATABASE_URL", "--reveal", "--force"])?,
        &context,
        &mut reveal_output,
    )?;
    assert_eq!(String::from_utf8(reveal_output)?, "postgres://localhost/source\n");
    Ok(())
}

#[test]
fn copy_picks_highest_precedence_source_when_unambiguous() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    let user_local_args = test_secret_write_args("API_KEY");
    super::set_secret_value(&context, &user_local_args, "user-value", "manual", 1_000)?;
    let machine_local_args = super::SecretWriteArgs {
        key: "API_KEY".to_owned(),
        source: super::SourceArg { source: Some(super::SecretSourceArg::MachineLocal) },
        metadata: super::SecretMetadataFlags {
            description: None,
            owner: None,
            tags: Vec::new(),
            required: false,
            optional: false,
        },
    };
    super::set_secret_value(&context, &machine_local_args, "machine-value", "manual", 1_500)?;
    run_with_context(
        Cli::try_parse_from(["locket", "profile", "create", "staging"])?,
        &context,
        &mut Vec::new(),
    )?;

    let copy_args = super::CopyArgs {
        key: "API_KEY".to_owned(),
        from: "dev".to_owned(),
        to: "staging".to_owned(),
        from_source: None,
        to_source: None,
    };
    let result = super::copy_secret_value(&context, &copy_args, 2_000)?;
    assert_eq!(result.from_source, "machine-local");
    // Spec: when --to-source omitted and the from-source is absent in the target profile,
    // copy falls back to user-local.
    assert_eq!(result.to_source, "user-local");
    assert_eq!(result.operation, "create");
    assert_eq!(result.target_version, 1);
    assert_eq!(result.prior_target_version, None);
    Ok(())
}

#[test]
fn copy_resolves_explicit_from_source_over_default_precedence()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    let user_local_args = test_secret_write_args("API_KEY");
    super::set_secret_value(&context, &user_local_args, "user-value", "manual", 1_000)?;
    let machine_local_args = super::SecretWriteArgs {
        key: "API_KEY".to_owned(),
        source: super::SourceArg { source: Some(super::SecretSourceArg::MachineLocal) },
        metadata: super::SecretMetadataFlags {
            description: None,
            owner: None,
            tags: Vec::new(),
            required: false,
            optional: false,
        },
    };
    super::set_secret_value(&context, &machine_local_args, "machine-value", "manual", 1_500)?;
    run_with_context(
        Cli::try_parse_from(["locket", "profile", "create", "staging"])?,
        &context,
        &mut Vec::new(),
    )?;

    let copy_args = super::CopyArgs {
        key: "API_KEY".to_owned(),
        from: "dev".to_owned(),
        to: "staging".to_owned(),
        from_source: Some(super::SecretSourceArg::UserLocal),
        to_source: None,
    };
    let result = super::copy_secret_value(&context, &copy_args, 2_000)?;
    assert_eq!(result.from_source, "user-local");
    assert_eq!(result.to_source, "user-local");
    assert_eq!(result.from_version, 1);
    Ok(())
}

#[test]
fn copy_to_source_falls_back_to_user_local_when_target_missing()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    let machine_local_args = super::SecretWriteArgs {
        key: "API_KEY".to_owned(),
        source: super::SourceArg { source: Some(super::SecretSourceArg::MachineLocal) },
        metadata: super::SecretMetadataFlags {
            description: None,
            owner: None,
            tags: Vec::new(),
            required: false,
            optional: false,
        },
    };
    super::set_secret_value(&context, &machine_local_args, "machine-value", "manual", 1_000)?;
    run_with_context(
        Cli::try_parse_from(["locket", "profile", "create", "staging"])?,
        &context,
        &mut Vec::new(),
    )?;

    let copy_args = super::CopyArgs {
        key: "API_KEY".to_owned(),
        from: "dev".to_owned(),
        to: "staging".to_owned(),
        from_source: None,
        to_source: None,
    };
    let result = super::copy_secret_value(&context, &copy_args, 2_000)?;
    assert_eq!(result.from_source, "machine-local");
    assert_eq!(result.to_source, "user-local");
    assert_eq!(result.operation, "create");
    Ok(())
}

#[test]
fn copy_rejects_same_profile_and_same_source() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    let args = test_secret_write_args("API_KEY");
    super::set_secret_value(&context, &args, "value", "manual", 1_000)?;

    let copy_args = super::CopyArgs {
        key: "API_KEY".to_owned(),
        from: "dev".to_owned(),
        to: "dev".to_owned(),
        from_source: Some(super::SecretSourceArg::UserLocal),
        to_source: Some(super::SecretSourceArg::UserLocal),
    };
    assert_error_contains(super::copy_secret_value(&context, &copy_args, 2_000), "use rotate");
    Ok(())
}

#[test]
fn copy_within_same_profile_to_different_source_is_allowed()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    let args = test_secret_write_args("API_KEY");
    super::set_secret_value(&context, &args, "value", "manual", 1_000)?;

    let copy_args = super::CopyArgs {
        key: "API_KEY".to_owned(),
        from: "dev".to_owned(),
        to: "dev".to_owned(),
        from_source: Some(super::SecretSourceArg::UserLocal),
        to_source: Some(super::SecretSourceArg::MachineLocal),
    };
    let result = super::copy_secret_value(&context, &copy_args, 2_000)?;
    assert_eq!(result.from_source, "user-local");
    assert_eq!(result.to_source, "machine-local");
    assert_eq!(result.operation, "create");
    Ok(())
}

#[test]
fn copy_to_deleted_target_source_fails_with_secret_deleted()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    let args = test_secret_write_args("API_KEY");
    super::set_secret_value(&context, &args, "source-value", "manual", 1_000)?;
    run_with_context(
        Cli::try_parse_from(["locket", "profile", "create", "staging"])?,
        &context,
        &mut Vec::new(),
    )?;
    run_with_context(
        Cli::try_parse_from(["locket", "use", "staging"])?,
        &context,
        &mut Vec::new(),
    )?;
    super::set_secret_value(&context, &args, "target-value", "manual", 1_500)?;
    run_with_context(Cli::try_parse_from(["locket", "rm", "API_KEY"])?, &context, &mut Vec::new())?;
    run_with_context(Cli::try_parse_from(["locket", "use", "dev"])?, &context, &mut Vec::new())?;

    let copy_args = super::CopyArgs {
        key: "API_KEY".to_owned(),
        from: "dev".to_owned(),
        to: "staging".to_owned(),
        from_source: None,
        to_source: None,
    };
    assert_error_contains(super::copy_secret_value(&context, &copy_args, 2_000), "SecretDeleted");
    Ok(())
}

#[test]
fn copy_from_deleted_source_secret_fails() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    let args = test_secret_write_args("API_KEY");
    super::set_secret_value(&context, &args, "value", "manual", 1_000)?;
    run_with_context(Cli::try_parse_from(["locket", "rm", "API_KEY"])?, &context, &mut Vec::new())?;
    run_with_context(
        Cli::try_parse_from(["locket", "profile", "create", "staging"])?,
        &context,
        &mut Vec::new(),
    )?;

    let copy_args = super::CopyArgs {
        key: "API_KEY".to_owned(),
        from: "dev".to_owned(),
        to: "staging".to_owned(),
        from_source: Some(super::SecretSourceArg::UserLocal),
        to_source: None,
    };
    assert_error_contains(
        super::copy_secret_value(&context, &copy_args, 2_000),
        "secret source is deleted",
    );
    Ok(())
}

#[test]
fn copy_refreshes_env_example_after_creating_secret_in_target_profile()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    let args = test_secret_write_args("API_KEY");
    super::set_secret_value(&context, &args, "initial-value", "manual", 1_000)?;
    // Mirror the `set` CLI's example-refresh side-effect.
    super::refresh_example_for_project_if_enabled(&context)?;
    run_with_context(
        Cli::try_parse_from(["locket", "profile", "create", "staging"])?,
        &context,
        &mut Vec::new(),
    )?;

    // Confirm the project example contains the source secret name before copy.
    let example_path = directory.path().join(".env.example");
    let before = fs::read_to_string(&example_path)?;
    assert!(before.contains("API_KEY="), "before-copy example missing API_KEY: {before}");

    run_with_context(
        Cli::try_parse_from(["locket", "copy", "API_KEY", "--from", "dev", "--to", "staging"])?,
        &context,
        &mut Vec::new(),
    )?;

    let after = fs::read_to_string(&example_path)?;
    // The example collects names from all profiles in the project, so API_KEY remains.
    assert!(after.contains("API_KEY="));
    // No plaintext value leaks into the example file.
    assert!(!after.contains("initial-value"));
    Ok(())
}

#[test]
fn copy_command_output_includes_prior_target_version_on_rotate()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    let args = test_secret_write_args("API_KEY");
    super::set_secret_value(&context, &args, "source-value", "manual", 1_000)?;
    run_with_context(
        Cli::try_parse_from(["locket", "profile", "create", "staging"])?,
        &context,
        &mut Vec::new(),
    )?;
    run_with_context(
        Cli::try_parse_from(["locket", "use", "staging"])?,
        &context,
        &mut Vec::new(),
    )?;
    super::set_secret_value(&context, &args, "target-value", "manual", 1_500)?;
    run_with_context(Cli::try_parse_from(["locket", "use", "dev"])?, &context, &mut Vec::new())?;

    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "copy", "API_KEY", "--from", "dev", "--to", "staging"])?,
        &context,
        &mut output,
    )?;
    let output = String::from_utf8(output)?;
    assert!(output.contains("operation=rotate"));
    assert!(output.contains("prior_target_version=1"));
    assert!(output.contains("version=2"));
    assert!(output.contains("from_version=1"));
    // Ensure no plaintext leaks.
    assert!(!output.contains("source-value"));
    assert!(!output.contains("target-value"));
    Ok(())
}

#[test]
fn copy_command_output_uses_dash_for_prior_target_version_on_create()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    let args = test_secret_write_args("API_KEY");
    super::set_secret_value(&context, &args, "value", "manual", 1_000)?;
    run_with_context(
        Cli::try_parse_from(["locket", "profile", "create", "staging"])?,
        &context,
        &mut Vec::new(),
    )?;

    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "copy", "API_KEY", "--from", "dev", "--to", "staging"])?,
        &context,
        &mut output,
    )?;
    let output = String::from_utf8(output)?;
    assert!(output.contains("operation=create"));
    assert!(output.contains("prior_target_version=-"));
    assert!(output.contains("version=1"));
    assert!(output.contains("from_version=1"));
    Ok(())
}

#[test]
fn rotate_history_and_purge_keep_values_hidden() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;

    let set_args = test_secret_write_args("DATABASE_URL");
    super::set_secret_value(&context, &set_args, "postgres://localhost/old", "manual", 1_000)?;

    let rotate_args = test_rotate_args("DATABASE_URL", Some("24h"));
    let grace_until = super::grace_until_from_args(rotate_args.grace_ttl.as_deref(), 2_000)?;
    let (_source, version) = super::rotate_secret_value(
        &context,
        &rotate_args,
        "postgres://localhost/new",
        2_000,
        grace_until,
    )?;
    assert_eq!(version, 2);

    let mut get_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "get", "DATABASE_URL"])?,
        &context,
        &mut get_output,
    )?;
    let get_output = String::from_utf8(get_output)?;
    assert!(get_output.contains("version=2"));
    assert!(!get_output.contains("postgres://localhost/new"));

    let mut reveal_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "get", "DATABASE_URL", "--reveal", "--force"])?,
        &context,
        &mut reveal_output,
    )?;
    assert_eq!(String::from_utf8(reveal_output)?, "postgres://localhost/new\n");

    let mut history_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "history", "DATABASE_URL"])?,
        &context,
        &mut history_output,
    )?;
    let history_output = String::from_utf8(history_output)?;
    assert!(history_output.contains("v1 state=deprecated"));
    assert!(history_output.contains("v2 state=current"));
    assert!(history_output.contains("grace_until="));
    assert!(!history_output.contains("postgres://localhost/old"));
    assert!(!history_output.contains("postgres://localhost/new"));

    let purge_args = ["locket", "purge", "DATABASE_URL", "--version", "1", "--force"];
    let mut purge_output = Vec::new();
    run_with_context(Cli::try_parse_from(purge_args)?, &context, &mut purge_output)?;
    assert!(String::from_utf8(purge_output)?.contains("versions=1"));

    let mut history_after_purge = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "history", "DATABASE_URL"])?,
        &context,
        &mut history_after_purge,
    )?;
    let history_after_purge = String::from_utf8(history_after_purge)?;
    assert!(history_after_purge.contains("v1 state=purged"));
    assert!(history_after_purge.contains("v2 state=current"));

    let invalid_purge_args = ["locket", "purge", "DATABASE_URL", "--version", "2", "--force"];
    let mut invalid_purge_output = Vec::new();
    let invalid_purge = run_with_context(
        Cli::try_parse_from(invalid_purge_args)?,
        &context,
        &mut invalid_purge_output,
    );
    assert!(invalid_purge.is_err());

    let mut rm_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "rm", "DATABASE_URL"])?,
        &context,
        &mut rm_output,
    )?;
    let purge_all_args = ["locket", "purge", "DATABASE_URL", "--all-versions", "--force"];
    let mut purge_all_output = Vec::new();
    run_with_context(Cli::try_parse_from(purge_all_args)?, &context, &mut purge_all_output)?;
    assert!(String::from_utf8(purge_all_output)?.contains("versions=1,2"));

    let mut audit_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "audit", "verify"])?,
        &context,
        &mut audit_output,
    )?;
    assert!(String::from_utf8(audit_output)?.contains("verified 7 row(s)"));

    assert_lifecycle_audit_log(&directory)?;
    Ok(())
}

#[test]
fn purge_requires_typed_confirmation_of_full_scope() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let key_store: Arc<dyn MasterKeyStore + Send + Sync> =
        Arc::new(MemoryMasterKeyStore::default());
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &test_context_with_key_store(&directory, Arc::clone(&key_store)),
        &mut Vec::new(),
    )?;
    let setup_context = test_context_with_key_store(&directory, Arc::clone(&key_store));
    let set_args = test_secret_write_args("DATABASE_URL");
    super::set_secret_value(
        &setup_context,
        &set_args,
        "postgres://localhost/old",
        "manual",
        1_000,
    )?;
    let rotate_args = test_rotate_args("DATABASE_URL", Some("24h"));
    let grace_until = super::grace_until_from_args(rotate_args.grace_ttl.as_deref(), 2_000)?;
    super::rotate_secret_value(
        &setup_context,
        &rotate_args,
        "postgres://localhost/new",
        2_000,
        grace_until,
    )?;

    let bad_context = test_context_with_key_store_and_confirmation(
        &directory,
        Arc::clone(&key_store),
        "purge dev/user-local/DATABASE_URL/v2\n",
    );
    let mut bad_output = Vec::new();
    let result = run_with_context(
        Cli::try_parse_from(["locket", "purge", "DATABASE_URL", "--version", "1"])?,
        &bad_context,
        &mut bad_output,
    );
    assert_error_contains(result, "confirmation did not match");
    let bad_output = String::from_utf8(bad_output)?;
    assert!(bad_output.contains("purge_profile: dev"));
    assert!(bad_output.contains("purge_source: user-local"));
    assert!(bad_output.contains("purge_secret: DATABASE_URL"));
    assert!(bad_output.contains("purge_version_scope: v1"));
    assert!(bad_output.contains("metadata_only: yes"));

    let good_context = test_context_with_key_store_and_confirmation(
        &directory,
        Arc::clone(&key_store),
        "purge dev/user-local/DATABASE_URL/v1\n",
    );
    let mut good_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "purge", "DATABASE_URL", "--version", "1"])?,
        &good_context,
        &mut good_output,
    )?;
    let good_output = String::from_utf8(good_output)?;
    assert!(good_output.contains("purged DATABASE_URL"));
    assert!(good_output.contains("versions=1"));

    Ok(())
}

#[test]
fn purge_force_skips_confirmation_prompt() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    let set_args = test_secret_write_args("API_KEY");
    super::set_secret_value(&context, &set_args, "tok-v1", "manual", 1_000)?;
    let rotate_args = test_rotate_args("API_KEY", Some("24h"));
    let grace = super::grace_until_from_args(rotate_args.grace_ttl.as_deref(), 2_000)?;
    super::rotate_secret_value(&context, &rotate_args, "tok-v2", 2_000, grace)?;

    let mut force_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "purge", "API_KEY", "--version", "1", "--force"])?,
        &context,
        &mut force_output,
    )?;
    let force_output = String::from_utf8(force_output)?;
    assert!(force_output.contains("purged API_KEY"));
    assert!(!force_output.contains("type 'purge"));
    Ok(())
}

#[test]
fn purge_already_purged_skips_confirmation_and_writes_no_audit()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let key_store: Arc<dyn MasterKeyStore + Send + Sync> =
        Arc::new(MemoryMasterKeyStore::default());
    let context = test_context_with_key_store(&directory, Arc::clone(&key_store));
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    let set_args = test_secret_write_args("API_KEY");
    super::set_secret_value(&context, &set_args, "tok-v1", "manual", 1_000)?;
    let rotate_args = test_rotate_args("API_KEY", Some("24h"));
    let grace = super::grace_until_from_args(rotate_args.grace_ttl.as_deref(), 2_000)?;
    super::rotate_secret_value(&context, &rotate_args, "tok-v2", 2_000, grace)?;

    run_with_context(
        Cli::try_parse_from(["locket", "purge", "API_KEY", "--version", "1", "--force"])?,
        &context,
        &mut Vec::new(),
    )?;
    let store_pre = super::open_store(&context)?;
    let count_before: i64 = store_pre.connection().query_row(
        "SELECT COUNT(*) FROM audit_log WHERE action = 'PURGE'",
        [],
        |row| row.get(0),
    )?;
    drop(store_pre);

    let no_confirm_context = test_context_with_key_store_and_confirmation(
        &directory,
        Arc::clone(&key_store),
        "should-not-be-read\n",
    );
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "purge", "API_KEY", "--version", "1"])?,
        &no_confirm_context,
        &mut output,
    )?;
    let output = String::from_utf8(output)?;
    assert!(output.contains("already purged"));
    let store_post = super::open_store(&no_confirm_context)?;
    let count_after: i64 = store_post.connection().query_row(
        "SELECT COUNT(*) FROM audit_log WHERE action = 'PURGE'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(count_before, count_after, "no-op purge must not write audit");
    Ok(())
}

#[test]
fn history_filters_by_source_state_limit_and_renders_iso_timestamps()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;

    let user_local = test_secret_write_args("DATABASE_URL");
    super::set_secret_value(&context, &user_local, "postgres://localhost/u-v1", "manual", 1_000)?;
    let rotate_user = test_rotate_args("DATABASE_URL", Some("24h"));
    let grace_user = super::grace_until_from_args(rotate_user.grace_ttl.as_deref(), 2_000)?;
    super::rotate_secret_value(
        &context,
        &rotate_user,
        "postgres://localhost/u-v2",
        2_000,
        grace_user,
    )?;

    let mut machine_local = test_secret_write_args("DATABASE_URL");
    machine_local.source = super::SourceArg { source: Some(super::SecretSourceArg::MachineLocal) };
    super::set_secret_value(
        &context,
        &machine_local,
        "postgres://localhost/m-v1",
        "manual",
        3_000,
    )?;

    let mut all_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "history", "DATABASE_URL"])?,
        &context,
        &mut all_output,
    )?;
    let all_output = String::from_utf8(all_output)?;
    assert!(all_output.contains("history DATABASE_URL profile=dev"));
    assert!(all_output.contains("source=user-local"));
    assert!(all_output.contains("source=machine-local"));
    assert!(all_output.contains("v1 state=deprecated"));
    assert!(all_output.contains("v2 state=current"));
    assert!(all_output.contains("created_at=1000(1970-01-01T00:00:00.000001000Z)"));
    assert!(!all_output.contains("postgres://"));

    let mut user_only = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "history", "DATABASE_URL", "--source", "user-local"])?,
        &context,
        &mut user_only,
    )?;
    let user_only = String::from_utf8(user_only)?;
    assert!(user_only.contains("source=user-local"));
    assert!(!user_only.contains("source=machine-local"));

    let mut current_only = Vec::new();
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "history",
            "DATABASE_URL",
            "--source",
            "user-local",
            "--state",
            "current",
        ])?,
        &context,
        &mut current_only,
    )?;
    let current_only = String::from_utf8(current_only)?;
    assert!(current_only.contains("v2 state=current"));
    assert!(!current_only.contains("v1 state=deprecated"));

    let mut limit_one = Vec::new();
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "history",
            "DATABASE_URL",
            "--source",
            "user-local",
            "--limit",
            "1",
        ])?,
        &context,
        &mut limit_one,
    )?;
    let limit_one = String::from_utf8(limit_one)?;
    let version_lines = limit_one.matches("\n  v").count();
    assert_eq!(version_lines, 1, "limit=1 should print exactly one version line");

    Ok(())
}

#[test]
fn history_state_filter_prints_no_versions_notice_and_exits_ok()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    let args = test_secret_write_args("API_TOKEN");
    super::set_secret_value(&context, &args, "tok-v1", "manual", 1_000)?;

    let mut history_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "history", "API_TOKEN", "--state", "purged"])?,
        &context,
        &mut history_output,
    )?;
    let history_output = String::from_utf8(history_output)?;
    assert!(history_output.contains("history: no versions"));
    assert!(!history_output.contains("v1"));
    Ok(())
}

#[test]
fn history_unknown_source_fails_without_listing_other_sources()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    let args = test_secret_write_args("API_TOKEN");
    super::set_secret_value(&context, &args, "tok-v1", "manual", 1_000)?;

    let mut history_output = Vec::new();
    let result = run_with_context(
        Cli::try_parse_from(["locket", "history", "API_TOKEN", "--source", "team-managed"])?,
        &context,
        &mut history_output,
    );
    assert!(result.is_err(), "missing source should error");
    assert!(history_output.is_empty());
    Ok(())
}

#[test]
fn history_missing_key_errors_with_secret_not_found() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    let mut history_output = Vec::new();
    let result = run_with_context(
        Cli::try_parse_from(["locket", "history", "NOPE_TOKEN"])?,
        &context,
        &mut history_output,
    );
    assert_error_contains(result, "secret not found");
    Ok(())
}

#[test]
fn unix_nanos_to_rfc3339_renders_known_timestamps() {
    assert_eq!(super::unix_nanos_to_rfc3339(0), Some("1970-01-01T00:00:00.000000000Z".to_owned()));
    assert_eq!(
        super::unix_nanos_to_rfc3339(1_700_000_000_000_000_000),
        Some("2023-11-14T22:13:20.000000000Z".to_owned())
    );
    assert_eq!(super::unix_nanos_to_rfc3339(-1), None);
}

#[test]
fn import_env_encrypts_values_and_refreshes_example() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    std::fs::write(
        directory.path().join(".env"),
        "DATABASE_URL=postgres://localhost/app\nINVALID-NAME=value\nOPENAI_API_KEY='sk_test_sample'\n",
    )?;

    let mut import_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "import", ".env"])?,
        &context,
        &mut import_output,
    )?;
    let import_output = String::from_utf8(import_output)?;
    assert!(import_output.contains("imported: 2"));
    assert!(import_output.contains("invalid: 1"));
    assert!(import_output.contains("profile: dev"));
    assert!(import_output.contains("source: user-local"));
    assert!(import_output.contains("missing_in_profile: none"));
    assert!(import_output.contains("delete_env_prompt: skipped_noninteractive"));
    assert!(import_output.contains("delete_env: kept"));
    assert!(import_output.contains("metadata_only: yes"));
    assert!(!import_output.contains("postgres://localhost/app"));

    let example = std::fs::read_to_string(directory.path().join(".env.example"))?;
    assert!(example.contains("DATABASE_URL="));
    assert!(example.contains("OPENAI_API_KEY="));
    assert!(!example.contains("postgres://localhost/app"));

    std::fs::write(directory.path().join(".env"), "DATABASE_URL=postgres://localhost/new\n")?;
    let mut overwrite_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "import", ".env", "--overwrite"])?,
        &context,
        &mut overwrite_output,
    )?;
    let overwrite_output = String::from_utf8(overwrite_output)?;
    assert!(overwrite_output.contains("overwritten: 1"));
    assert!(!overwrite_output.contains("postgres://localhost/new"));

    let mut reveal_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "get", "DATABASE_URL", "--reveal", "--force"])?,
        &context,
        &mut reveal_output,
    )?;
    assert_eq!(String::from_utf8(reveal_output)?, "postgres://localhost/new\n");
    Ok(())
}

#[test]
fn import_env_targets_named_profile_and_reports_parity() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    run_with_context(
        Cli::try_parse_from(["locket", "profile", "create", "staging"])?,
        &context,
        &mut Vec::new(),
    )?;
    std::fs::write(directory.path().join(".env"), "API_KEY=sk_test_stagingImport123\n")?;

    let mut import_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "import", ".env", "--profile", "staging"])?,
        &context,
        &mut import_output,
    )?;

    let import_output = String::from_utf8(import_output)?;
    assert!(import_output.contains("imported: 1"));
    assert!(import_output.contains("profile: staging"));
    assert!(import_output.contains("env_names: 1"));
    assert!(import_output.contains("profile_names: 1"));
    assert!(import_output.contains("missing_in_profile: none"));
    assert!(import_output.contains("extra_in_profile: none"));
    assert!(import_output.contains("delete_env_prompt: skipped_noninteractive"));
    assert!(!import_output.contains("sk_test_stagingImport123"));

    let resolved = super::resolve_project(&context.cwd)?.ok_or("project should resolve")?;
    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let staging = store
        .get_profile_by_name(resolved.config.project_id.as_str(), "staging")?
        .ok_or("staging profile should exist")?;
    let secret = store
        .get_secret_by_source(
            resolved.config.project_id.as_str(),
            &staging.id,
            "API_KEY",
            "user-local",
        )?
        .ok_or("imported secret should exist")?;
    assert_eq!(secret.origin, "imported");
    assert_eq!(secret.current_version, 1);
    let audit_metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'IMPORT'",
        [],
        |row| row.get(0),
    )?;
    assert!(audit_metadata.contains("\"secret_name\":\"API_KEY\""));
    assert!(audit_metadata.contains(&staging.id));
    assert!(!audit_metadata.contains("sk_test_stagingImport123"));
    Ok(())
}

#[test]
fn import_overwrite_to_dangerous_profile_requires_confirmation_before_rotation()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let key_store: Arc<dyn MasterKeyStore + Send + Sync> =
        Arc::new(MemoryMasterKeyStore::default());
    let context = test_context_with_key_store(&directory, Arc::clone(&key_store));
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    run_with_context(
        Cli::try_parse_from(["locket", "profile", "create", "prod"])?,
        &context,
        &mut Vec::new(),
    )?;
    let mark_context =
        test_context_with_key_store_and_confirmation(&directory, Arc::clone(&key_store), "prod\n");
    run_with_context(
        Cli::try_parse_from(["locket", "profile", "mark-dangerous", "prod"])?,
        &mark_context,
        &mut Vec::new(),
    )?;
    std::fs::write(directory.path().join(".env"), "API_KEY=sk_test_prodOriginal123\n")?;
    run_with_context(
        Cli::try_parse_from(["locket", "import", ".env", "--profile", "prod"])?,
        &context,
        &mut Vec::new(),
    )?;

    std::fs::write(directory.path().join(".env"), "API_KEY=sk_test_prodRotated123\n")?;
    let mut overwrite_output = Vec::new();
    assert_error_contains(
        run_with_context(
            Cli::try_parse_from(["locket", "import", ".env", "--profile", "prod", "--overwrite"])?,
            &context,
            &mut overwrite_output,
        ),
        "dangerous profile",
    );
    let overwrite_output = String::from_utf8(overwrite_output)?;
    assert!(overwrite_output.contains("dangerous_profile: prod"));
    assert!(!overwrite_output.contains("sk_test_prodRotated123"));

    let resolved = super::resolve_project(&context.cwd)?.ok_or("project should resolve")?;
    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let prod = store
        .get_profile_by_name(resolved.config.project_id.as_str(), "prod")?
        .ok_or("prod profile should exist")?;
    let secret = store
        .get_secret_by_source(
            resolved.config.project_id.as_str(),
            &prod.id,
            "API_KEY",
            "user-local",
        )?
        .ok_or("prod import should exist")?;
    assert_eq!(secret.current_version, 1);
    Ok(())
}

#[test]
fn exec_all_force_injects_active_profile_secrets_and_writes_audit()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    let db = test_secret_write_args("DATABASE_URL");
    super::set_secret_value(&context, &db, "postgres://localhost/app", "manual", 1_000)?;
    let api = test_secret_write_args("API_KEY");
    super::set_secret_value(&context, &api, "tok-v1", "manual", 2_000)?;

    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "exec",
            "--all",
            "--force",
            "--",
            "/bin/sh",
            "-c",
            "test \"$DATABASE_URL\" = \"postgres://localhost/app\" \
             && test \"$API_KEY\" = \"tok-v1\"",
        ])?,
        &context,
        &mut output,
    )?;
    assert!(String::from_utf8(output)?.is_empty());

    let store = super::open_store(&context)?;
    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'EXEC'
         ORDER BY sequence DESC LIMIT 1",
        [],
        |row| row.get(0),
    )?;
    assert!(metadata.contains("\"action\":\"EXEC\""));
    assert!(metadata.contains("\"all_mode\":true"));
    assert!(metadata.contains("\"argv_program\":\"/bin/sh\""));
    assert!(metadata.contains("\"arg_count\":3"));
    assert!(metadata.contains("\"API_KEY\""));
    assert!(metadata.contains("\"DATABASE_URL\""));
    assert!(!metadata.contains("postgres://localhost/app"));
    assert!(!metadata.contains("tok-v1"));
    Ok(())
}

#[test]
fn exec_all_requires_typed_confirmation_when_not_forced() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempdir()?;
    let key_store: Arc<dyn MasterKeyStore + Send + Sync> =
        Arc::new(MemoryMasterKeyStore::default());
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &test_context_with_key_store(&directory, Arc::clone(&key_store)),
        &mut Vec::new(),
    )?;
    let setup = test_context_with_key_store(&directory, Arc::clone(&key_store));
    let db = test_secret_write_args("DATABASE_URL");
    super::set_secret_value(&setup, &db, "postgres://localhost/app", "manual", 1_000)?;

    let bad_context =
        test_context_with_key_store_and_confirmation(&directory, Arc::clone(&key_store), "wrong\n");
    let mut output = Vec::new();
    let result = run_with_context(
        Cli::try_parse_from(["locket", "exec", "--all", "--", "/bin/sh", "-c", "true"])?,
        &bad_context,
        &mut output,
    );
    assert_error_contains(result, "confirmation did not match exec --all scope");
    let output = String::from_utf8(output)?;
    assert!(output.contains("exec_profile: dev"));
    assert!(output.contains("exec_argv_program: /bin/sh"));
    assert!(output.contains("exec_secret_count: 1"));
    assert!(output.contains("exec_secret_names: DATABASE_URL"));
    assert!(output.contains("metadata_only: yes"));

    let good_context = test_context_with_key_store_and_confirmation(
        &directory,
        Arc::clone(&key_store),
        "exec --all dev\n",
    );
    let mut good_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "exec", "--all", "--", "/bin/sh", "-c", "true"])?,
        &good_context,
        &mut good_output,
    )?;
    Ok(())
}

#[test]
fn exec_without_secrets_or_all_errors() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    let mut output = Vec::new();
    let result = run_with_context(
        Cli::try_parse_from(["locket", "exec", "--", "/bin/sh", "-c", "true"])?,
        &context,
        &mut output,
    );
    assert_error_contains(result, "exec requires --all or at least one --secret");
    Ok(())
}

#[test]
fn exec_all_and_secret_flags_are_mutually_exclusive() {
    let result = Cli::try_parse_from([
        "locket",
        "exec",
        "--all",
        "--secret",
        "DATABASE_URL",
        "--",
        "/bin/sh",
        "-c",
        "true",
    ]);
    assert!(result.is_err(), "clap should reject combining --all and --secret");
}

#[test]
fn exec_injects_secret_into_child_scope() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    let args = super::SecretWriteArgs {
        key: "DATABASE_URL".to_owned(),
        source: super::SourceArg { source: Some(super::SecretSourceArg::UserLocal) },
        metadata: super::SecretMetadataFlags {
            description: None,
            owner: None,
            tags: Vec::new(),
            required: false,
            optional: false,
        },
    };
    super::set_secret_value(&context, &args, "postgres://localhost/app", "manual", 1_000)?;

    let mut exec_output = Vec::new();
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "exec",
            "--secret",
            "DATABASE_URL",
            "--",
            "/bin/sh",
            "-c",
            "test \"$DATABASE_URL\" = \"postgres://localhost/app\"",
        ])?,
        &context,
        &mut exec_output,
    )?;

    assert!(String::from_utf8(exec_output)?.is_empty());
    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let session = store.connection().query_row(
        "SELECT policy_name, ended_at IS NOT NULL, exit_status, secret_names_json
         FROM runtime_sessions",
        [],
        |row| {
            Ok((
                row.get::<_, Option<String>>(0)?,
                row.get::<_, bool>(1)?,
                row.get::<_, Option<i32>>(2)?,
                row.get::<_, String>(3)?,
            ))
        },
    )?;
    assert_eq!(session.0, None);
    assert!(session.1);
    assert_eq!(session.2, Some(0));
    assert_eq!(session.3, "[\"DATABASE_URL\"]");
    assert!(!session.3.contains("postgres://localhost/app"));
    Ok(())
}

#[test]
fn run_policy_injects_required_and_optional_secrets_without_printing_values()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    let db_args = test_secret_write_args("DATABASE_URL");
    super::set_secret_value(&context, &db_args, "postgres://localhost/app", "manual", 1_000)?;
    let api_args = test_secret_write_args("OPENAI_API_KEY");
    super::set_secret_value(&context, &api_args, "sk_test_policy_value", "manual", 2_000)?;

    std::fs::OpenOptions::new()
        .append(true)
        .open(directory.path().join("locket.toml"))?
        .write_all(
            br#"
[commands.env_check]
argv = ["/bin/sh", "-c", "printf 'DATABASE_URL=%s\nOPENAI_API_KEY=%s\n' \"${DATABASE_URL:+present}\" \"${OPENAI_API_KEY:+present}\" > env-presence.txt"]
required_secrets = ["DATABASE_URL"]
optional_secrets = ["OPENAI_API_KEY"]
env_mode = "strict"
inherit_env = ["PATH"]
"#,
        )?;

    let mut inspect_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "env", "inspect", "--policy", "env_check"])?,
        &context,
        &mut inspect_output,
    )?;
    let inspect_output = String::from_utf8(inspect_output)?;
    assert!(inspect_output.contains("secret DATABASE_URL kind=required sources=user-local"));
    assert!(inspect_output.contains("secret OPENAI_API_KEY kind=optional sources=user-local"));
    assert!(inspect_output.contains("decision=inject"));
    assert!(!inspect_output.contains("postgres://localhost/app"));
    assert!(!inspect_output.contains("sk_test_policy_value"));

    let mut run_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "run", "env_check"])?,
        &context,
        &mut run_output,
    )?;
    assert!(String::from_utf8(run_output)?.is_empty());
    let presence = std::fs::read_to_string(directory.path().join("env-presence.txt"))?;
    assert_eq!(presence, "DATABASE_URL=present\nOPENAI_API_KEY=present\n");
    assert!(!presence.contains("postgres://localhost/app"));
    assert!(!presence.contains("sk_test_policy_value"));
    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let session = store.connection().query_row(
        "SELECT policy_name, ended_at IS NOT NULL, exit_status, secret_names_json
         FROM runtime_sessions",
        [],
        |row| {
            Ok((
                row.get::<_, Option<String>>(0)?,
                row.get::<_, bool>(1)?,
                row.get::<_, Option<i32>>(2)?,
                row.get::<_, String>(3)?,
            ))
        },
    )?;
    assert_eq!(session.0.as_deref(), Some("env_check"));
    assert!(session.1);
    assert_eq!(session.2, Some(0));
    assert_eq!(session.3, "[\"DATABASE_URL\",\"OPENAI_API_KEY\"]");
    Ok(())
}

#[test]
fn docker_policy_plan_and_audit_are_metadata_only() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    let db_args = test_secret_write_args("DATABASE_URL");
    super::set_secret_value(&context, &db_args, "postgres://localhost/app", "manual", 1_000)?;
    let api_args = test_secret_write_args("API_KEY");
    super::set_secret_value(&context, &api_args, "sk_test_docker_value", "manual", 2_000)?;

    std::fs::OpenOptions::new()
        .append(true)
        .open(directory.path().join("locket.toml"))?
        .write_all(
            br#"
[commands.docker_app]
argv = ["docker", "run", "app"]
required_secrets = ["DATABASE_URL"]
optional_secrets = ["API_KEY"]
env_mode = "strict"
inherit_env = ["PATH"]
"#,
        )?;

    let parsed = Cli::try_parse_from([
        "locket",
        "env",
        "docker",
        "--policy",
        "docker_app",
        "--",
        "docker",
        "run",
        "alpine",
    ])?;
    assert!(matches!(
        parsed.command,
        Some(super::Command::Env { command: super::EnvCommand::Docker(_) })
    ));

    let parent_env = std::iter::once(("PATH".to_owned(), "/bin".to_owned())).collect();
    let docker_argv = vec!["docker".to_owned(), "run".to_owned(), "alpine".to_owned()];
    let prepared =
        super::prepare_docker_policy_execution(&context, "docker_app", &docker_argv, parent_env)?;
    assert_eq!(prepared.execution.program, "docker");
    assert!(prepared.plan.argv.windows(2).any(|pair| pair == ["--env", "API_KEY"]));
    assert!(prepared.plan.argv.windows(2).any(|pair| pair == ["--env", "DATABASE_URL"]));
    let argv_text = prepared.plan.argv.join(" ");
    assert!(!argv_text.contains("postgres://localhost/app"));
    assert!(!argv_text.contains("sk_test_docker_value"));

    let metadata = super::docker_policy_audit_metadata(&prepared, "SUCCESS");
    let metadata_text = metadata.to_string();
    assert!(metadata_text.contains("DATABASE_URL"));
    assert!(metadata_text.contains("API_KEY"));
    assert!(metadata_text.contains("environment_names"));
    assert!(metadata_text.contains("\"argv_program\":\"docker\""));
    assert!(!metadata_text.contains("postgres://localhost/app"));
    assert!(!metadata_text.contains("sk_test_docker_value"));

    super::write_docker_policy_audit_if_available(&context, &prepared, "SUCCESS")?;
    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let audit_metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'RUN'",
        [],
        |row| row.get(0),
    )?;
    assert!(audit_metadata.contains("DATABASE_URL"));
    assert!(audit_metadata.contains("API_KEY"));
    assert!(!audit_metadata.contains("postgres://localhost/app"));
    assert!(!audit_metadata.contains("sk_test_docker_value"));
    Ok(())
}

#[test]
fn compose_policy_plan_supports_options_and_denies_remote_by_default()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    let api_args = test_secret_write_args("API_KEY");
    super::set_secret_value(&context, &api_args, "sk_test_compose_value", "manual", 1_000)?;

    std::fs::OpenOptions::new()
        .append(true)
        .open(directory.path().join("locket.toml"))?
        .write_all(
            br#"
[commands.compose_app]
argv = ["docker", "compose", "up"]
required_secrets = ["API_KEY"]
env_mode = "strict"
inherit_env = ["PATH"]
"#,
        )?;

    let parsed = Cli::try_parse_from([
        "locket",
        "compose",
        "run",
        "--policy",
        "compose_app",
        "--project-directory",
        ".",
        "--profile",
        "web",
        "--",
        "docker",
        "compose",
        "up",
    ])?;
    assert!(matches!(
        parsed.command,
        Some(super::Command::Compose { command: super::ComposeCommand::Run(_) })
    ));

    let argv = super::compose_argv_with_options(
        vec!["docker".to_owned(), "compose".to_owned(), "up".to_owned()],
        Some(Path::new(".")),
        &["web".to_owned()],
    )?;
    assert_eq!(argv, ["docker", "compose", "--project-directory", ".", "--profile", "web", "up"]);
    let parent_env = std::iter::once(("PATH".to_owned(), "/bin".to_owned())).collect();
    let prepared =
        super::prepare_compose_policy_execution(&context, "compose_app", &argv, parent_env)?;
    assert_eq!(
        prepared.plan.argv,
        prepared.execution.args.iter().fold(
            vec![prepared.execution.program.clone()],
            |mut values, arg| {
                values.push(arg.clone());
                values
            }
        )
    );
    assert_eq!(prepared.plan.injected_names, ["API_KEY"]);
    assert!(!prepared.plan.argv.join(" ").contains("sk_test_compose_value"));
    assert_eq!(
        prepared.execution.env.get("API_KEY").map(String::as_str),
        Some("sk_test_compose_value")
    );

    let remote_env =
        std::iter::once(("DOCKER_HOST".to_owned(), "ssh://builder".to_owned())).collect();
    let remote_argv = vec!["docker".to_owned(), "compose".to_owned(), "up".to_owned()];
    let Err(error) =
        super::prepare_compose_policy_execution(&context, "compose_app", &remote_argv, remote_env)
    else {
        return Err("remote Docker context should be denied".into());
    };
    let message = error.to_string();
    assert!(message.contains("remote Docker context is denied by default"));
    assert!(!message.contains("sk_test_compose_value"));
    Ok(())
}

#[test]
fn context_reports_metadata_only_summaries_without_values() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    let db_args = test_secret_write_args("DATABASE_URL");
    super::set_secret_value(&context, &db_args, "postgres://localhost/app", "manual", 1_000)?;
    let api_args = test_secret_write_args("OPENAI_API_KEY");
    super::set_secret_value(&context, &api_args, "sk_test_context_value", "manual", 2_000)?;

    std::fs::OpenOptions::new()
        .append(true)
        .open(directory.path().join("locket.toml"))?
        .write_all(
            br#"
[commands.env_check]
argv = ["/bin/sh", "-c", "true"]
required_secrets = ["DATABASE_URL"]
optional_secrets = ["MISSING_ONLY", "OPENAI_API_KEY"]
confirm = true
require_user_verification = true
"#,
        )?;

    let locked_context = test_context_with_key_store(
        &directory,
        std::sync::Arc::new(MemoryMasterKeyStore::default()),
    );
    let mut context_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "context"])?,
        &locked_context,
        &mut context_output,
    )?;

    let context_output = String::from_utf8(context_output)?;
    assert!(context_output.contains("Project: app"));
    assert!(context_output.contains("Profile: dev"));
    assert!(context_output.contains("- dev active=yes dangerous=no secrets=2"));
    assert!(context_output.contains(
        "- DATABASE_URL profiles=dev,policy:env_check sources=policy-required,user-local"
    ));
    assert!(context_output.contains(
        "- OPENAI_API_KEY profiles=dev,policy:env_check sources=policy-optional,user-local"
    ));
    assert!(
        context_output.contains("- MISSING_ONLY profiles=policy:env_check sources=policy-optional")
    );
    assert!(context_output.contains("- env_check type=argv"));
    assert!(context_output.contains("required=DATABASE_URL"));
    assert!(context_output.contains("optional=MISSING_ONLY,OPENAI_API_KEY"));
    assert!(context_output.contains("confirm=yes verify_user=yes"));
    assert!(context_output.contains("No secret values included."));
    assert!(context_output.contains("metadata_only: yes"));
    assert!(!context_output.contains("postgres://localhost/app"));
    assert!(!context_output.contains("sk_test_context_value"));
    Ok(())
}

#[test]
fn context_redacts_names_from_flag_or_privacy_config() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    let db_args = test_secret_write_args("DATABASE_URL");
    super::set_secret_value(&context, &db_args, "postgres://localhost/app", "manual", 1_000)?;
    std::fs::OpenOptions::new()
        .append(true)
        .open(directory.path().join("locket.toml"))?
        .write_all(
            br#"
[commands.env_check]
argv = ["/bin/sh", "-c", "true"]
required_secrets = ["DATABASE_URL"]
"#,
        )?;

    let mut flag_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "context", "--redact-names"])?,
        &context,
        &mut flag_output,
    )?;
    let flag_output = String::from_utf8(flag_output)?;
    assert!(flag_output.contains("Project: project-"));
    assert!(flag_output.contains("Profile: profile-"));
    assert!(flag_output.contains("secret-"));
    assert!(flag_output.contains("policy-"));
    assert!(!flag_output.contains("Project: app"));
    assert!(!flag_output.contains("Profile: dev"));
    assert!(!flag_output.contains("DATABASE_URL"));
    assert!(!flag_output.contains("env_check"));
    assert!(!flag_output.contains("postgres://localhost/app"));

    let mut config_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "config", "set", "privacy.redact_names", "true"])?,
        &context,
        &mut config_output,
    )?;
    let mut configured_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "context"])?,
        &context,
        &mut configured_output,
    )?;
    let configured_output = String::from_utf8(configured_output)?;
    assert!(configured_output.contains("Project: project-"));
    assert!(!configured_output.contains("DATABASE_URL"));
    assert!(!configured_output.contains("env_check"));
    Ok(())
}

#[test]
fn scan_reports_metadata_only_provider_findings() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let sample_path = directory.path().join("sample.txt");
    std::fs::write(&sample_path, "token=sk_test_sampleTokenValue123\n")?;
    let context = test_context(&directory);
    let mut output = Vec::new();

    run_with_context(
        Cli::try_parse_from(["locket", "scan", "sample.txt"])?,
        &context,
        &mut output,
    )?;

    let output = String::from_utf8(output)?;
    assert!(output.contains("provider-token-pattern"));
    assert!(!output.contains("sk_test_sampleTokenValue123"));
    Ok(())
}

#[test]
fn scan_staged_requires_git_worktree() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();

    let result = run_with_context(
        Cli::try_parse_from(["locket", "scan", "--staged"])?,
        &context,
        &mut output,
    );

    assert!(result.is_err());
    if let Err(error) = result {
        assert_eq!(error.exit_code(), 64);
        assert!(error.to_string().contains("git worktree required"));
    }
    Ok(())
}

#[test]
fn scan_respects_locketignore_for_project_scan() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut init_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut init_output,
    )?;
    std::fs::write(directory.path().join(".locketignore"), "ignored.txt\n")?;
    std::fs::write(directory.path().join("ignored.txt"), "token=sk_test_sampleTokenValue123\n")?;
    std::fs::write(directory.path().join("visible.txt"), "token=sk_test_visibleTokenValue123\n")?;

    let mut scan_output = Vec::new();
    run_with_context(Cli::try_parse_from(["locket", "scan"])?, &context, &mut scan_output)?;

    let scan_output = String::from_utf8(scan_output)?;
    assert!(scan_output.contains("visible.txt:1:7: provider-token-pattern"));
    assert!(!scan_output.contains("ignored.txt"));
    assert!(!scan_output.contains("sk_test_sampleTokenValue123"));
    assert!(!scan_output.contains("sk_test_visibleTokenValue123"));
    Ok(())
}

#[test]
fn scan_inline_suppression_drops_high_entropy_finding_and_writes_audit_row()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut init_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut init_output,
    )?;

    let entropy_token = "Z9a$kLmN2pQx7R!sT4vW8yB3cD6eF";
    std::fs::write(
        directory.path().join("notes.txt"),
        format!("token={entropy_token} # locket-allow: known fixture\n"),
    )?;

    let mut scan_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "scan", "notes.txt"])?,
        &context,
        &mut scan_output,
    )?;

    let scan_output = String::from_utf8(scan_output)?;
    assert!(scan_output.contains("scan: no findings"));
    assert!(scan_output.contains("scan: 1 suppressed finding(s)"));
    assert!(scan_output.contains("high-entropy suppressed reason=known fixture"));
    assert!(!scan_output.contains(entropy_token));

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let mut statement = store.connection().prepare(
        "SELECT status, metadata_json FROM audit_log WHERE action = 'SCAN' ORDER BY sequence",
    )?;
    let rows = statement
        .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))?
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(rows.len(), 1);
    let (status, metadata) = &rows[0];
    assert_eq!(status, "SUPPRESSED");
    assert!(metadata.contains("\"rule_id\":\"high-entropy\""));
    assert!(metadata.contains("\"reason\":\"known fixture\""));
    assert!(metadata.contains("notes.txt"));
    assert!(!metadata.contains(entropy_token));
    Ok(())
}

#[test]
fn scan_inline_suppression_does_not_silence_known_secret_match()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut init_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut init_output,
    )?;
    let args = test_secret_write_args("DATABASE_URL");
    super::set_secret_value(&context, &args, "known-secret-value", "manual", 1_000)?;
    std::fs::write(
        directory.path().join("leak.txt"),
        "db=known-secret-value # locket-allow: try to hide it\n",
    )?;

    let mut scan_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "scan", "--require-known", "leak.txt"])?,
        &context,
        &mut scan_output,
    )?;

    let scan_output = String::from_utf8(scan_output)?;
    assert!(scan_output.contains("leak.txt:1:4: known-secret"));
    assert!(scan_output.contains("scan: 1 finding(s)"));
    assert!(!scan_output.contains("scan: 1 suppressed"));
    assert!(!scan_output.contains("known-secret-value"));
    Ok(())
}

#[test]
fn scan_inline_suppression_audit_omits_when_no_suppression_present()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut init_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut init_output,
    )?;
    std::fs::write(directory.path().join("notes.txt"), "token=sk_test_sampleTokenValue123\n")?;

    let mut scan_output = Vec::new();
    run_with_context(Cli::try_parse_from(["locket", "scan"])?, &context, &mut scan_output)?;

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let scan_rows: u32 = store.connection().query_row(
        "SELECT COUNT(*) FROM audit_log WHERE action = 'SCAN'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(scan_rows, 0);
    Ok(())
}

#[test]
fn scan_require_known_matches_vault_values_without_printing_them()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    let args = test_secret_write_args("DATABASE_URL");
    super::set_secret_value(&context, &args, "known-secret-value", "manual", 1_000)?;
    std::fs::write(directory.path().join("sample.txt"), "db=known-secret-value\n")?;

    let mut scan_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "scan", "--require-known", "sample.txt"])?,
        &context,
        &mut scan_output,
    )?;

    let scan_output = String::from_utf8(scan_output)?;
    assert!(scan_output.contains("known-secret"));
    assert!(scan_output.contains("known-value coverage checked 1 value(s)"));
    assert!(!scan_output.contains("known-secret-value"));
    Ok(())
}

#[test]
fn scan_staged_uses_index_content_without_printing_known_values()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    run_git(directory.path(), &["init"])?;
    let context = test_context(&directory);
    let mut init_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut init_output,
    )?;
    let args = test_secret_write_args("DATABASE_URL");
    super::set_secret_value(&context, &args, "known-secret-value", "manual", 1_000)?;
    let sample_path = directory.path().join("sample.txt");
    std::fs::write(&sample_path, "db=known-secret-value\n")?;
    run_git(directory.path(), &["add", "sample.txt"])?;
    std::fs::write(&sample_path, "db=redacted-in-working-tree\n")?;

    let mut scan_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "scan", "--staged", "--require-known"])?,
        &context,
        &mut scan_output,
    )?;

    let scan_output = String::from_utf8(scan_output)?;
    assert!(scan_output.contains("sample.txt:1:4: known-secret"));
    assert!(scan_output.contains("known-value coverage checked 1 value(s)"));
    assert!(!scan_output.contains("known-secret-value"));
    assert!(!scan_output.contains("redacted-in-working-tree"));
    Ok(())
}

#[test]
fn redact_replaces_provider_tokens() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let sample_path = directory.path().join("sample.log");
    std::fs::write(&sample_path, "token=ghp_sampleTokenValue123\n")?;
    let context = test_context(&directory);
    let mut output = Vec::new();

    run_with_context(
        Cli::try_parse_from(["locket", "redact", "sample.log"])?,
        &context,
        &mut output,
    )?;

    let output = String::from_utf8(output)?;
    assert!(output.contains("lk_redacted_PROVIDER_TOKEN"));
    assert!(!output.contains("ghp_sampleTokenValue123"));
    Ok(())
}

#[test]
fn redact_replaces_active_and_grace_known_values() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;

    let set_args = test_secret_write_args("DATABASE_URL");
    super::set_secret_value(&context, &set_args, "postgres://localhost/old", "manual", 1_000)?;
    let timestamp = super::now_unix_nanos()?;
    let rotate_args = test_rotate_args("DATABASE_URL", Some("24h"));
    let grace_until = super::grace_until_from_args(rotate_args.grace_ttl.as_deref(), timestamp)?;
    super::rotate_secret_value(
        &context,
        &rotate_args,
        "postgres://localhost/new",
        timestamp,
        grace_until,
    )?;

    std::fs::write(
        directory.path().join("sample.log"),
        "old=postgres://localhost/old\nnew=postgres://localhost/new\n",
    )?;
    let mut redact_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "redact", "sample.log"])?,
        &context,
        &mut redact_output,
    )?;

    let redact_output = String::from_utf8(redact_output)?;
    assert_eq!(redact_output.matches("lk_redacted_DATABASE_URL").count(), 2);
    assert!(!redact_output.contains("postgres://localhost/old"));
    assert!(!redact_output.contains("postgres://localhost/new"));
    Ok(())
}

#[test]
fn redact_names_uses_privacy_alias_for_known_values() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    let args = test_secret_write_args("DATABASE_URL");
    super::set_secret_value(&context, &args, "postgres://localhost/app", "manual", 1_000)?;
    std::fs::write(directory.path().join("sample.log"), "db=postgres://localhost/app\n")?;

    let mut redact_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "redact", "--redact-names", "sample.log"])?,
        &context,
        &mut redact_output,
    )?;

    let redact_output = String::from_utf8(redact_output)?;
    assert!(redact_output.contains("lk_redacted_secret-"));
    assert!(!redact_output.contains("lk_redacted_DATABASE_URL"));
    assert!(!redact_output.contains("postgres://localhost/app"));
    Ok(())
}

#[test]
fn redact_writes_audit_row_with_counts_and_names() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    let args = test_secret_write_args("DATABASE_URL");
    super::set_secret_value(&context, &args, "postgres://localhost/app", "manual", 1_000)?;
    std::fs::write(directory.path().join("sample.log"), "db=postgres://localhost/app\n")?;

    let mut redact_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "redact", "sample.log"])?,
        &context,
        &mut redact_output,
    )?;

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'REDACT'",
        [],
        |row| row.get(0),
    )?;
    assert!(metadata.contains("\"action\":\"REDACT\""));
    assert!(metadata.contains("\"input_kind\":\"file\""));
    assert!(metadata.contains("\"known_coverage_active\":true"));
    assert!(metadata.contains("\"DATABASE_URL\""));
    assert!(metadata.contains("\"known_secret_value\""));
    assert!(!metadata.contains("postgres://"));
    Ok(())
}

#[test]
fn redact_require_known_without_project_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    std::fs::write(directory.path().join("sample.log"), "anything\n")?;

    let mut redact_output = Vec::new();
    let result = run_with_context(
        Cli::try_parse_from(["locket", "redact", "--require-known", "sample.log"])?,
        &context,
        &mut redact_output,
    );
    let Err(super::CliError::Config(message)) = result else {
        return Err(format!("expected CliError::Config, got {result:?}").into());
    };
    assert!(message.contains("known-value redaction"));
    Ok(())
}

#[test]
fn redact_warns_when_known_coverage_skipped_without_project()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    std::fs::write(directory.path().join("sample.log"), "abcdef\n")?;

    let mut redact_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "redact", "sample.log"])?,
        &context,
        &mut redact_output,
    )?;

    let coverage = super::collect_redaction_values_for_redact(
        &context,
        None,
        false,
        false,
        super::now_unix_nanos()?,
    )?;
    assert!(!coverage.known_coverage_active);
    assert!(coverage.skipped_message.is_some());
    Ok(())
}

fn test_project_id_and_master_key(
    context: &RuntimeContext,
) -> Result<(String, locket_crypto::KeyBytes), Box<dyn std::error::Error>> {
    let resolved = super::require_project(context)?;
    let project_id = resolved.config.project_id.as_str().to_owned();
    let master_key = *context.key_store.load_master_key(&project_id)?;
    Ok((project_id, master_key))
}

fn setup_recovery_envelope(
    context: &RuntimeContext,
    project_id: &str,
    master_key: &locket_crypto::KeyBytes,
) -> Result<
    (super::RecoveryKdfToml, super::RecoveryEnvelope, [u8; locket_crypto::RECOVERY_CODE_BYTES]),
    Box<dyn std::error::Error>,
> {
    let code_bytes = locket_crypto::generate_recovery_code_bytes()?;
    let salt = locket_crypto::generate_recovery_salt()?;
    let kdf = super::RecoveryKdfToml::new_v1("lk_kdf_test".to_owned(), &salt, 1_000);
    let unwrap_root =
        locket_crypto::derive_recovery_key_v1(&code_bytes, &salt, kdf.to_crypto_params())?;
    let entry = super::seal_recovery_envelope_entry(
        &unwrap_root,
        &kdf.kdf_profile_id,
        "master_key",
        project_id,
        master_key,
    )?;
    let envelope = super::RecoveryEnvelope {
        kdf_profile_id: kdf.kdf_profile_id.clone(),
        created_at_unix_nanos: 1_000,
        entries: vec![entry],
    };
    let recovery_dir = context.cwd.join(".locket").join("recovery");
    super::save_recovery_kdf_toml(&recovery_dir, &kdf)?;
    super::save_recovery_envelope(&recovery_dir, &envelope)?;
    Ok((kdf, envelope, code_bytes))
}

#[test]
fn recovery_restore_rejects_mismatched_kdf_profile() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut init_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut init_output,
    )?;
    let resolved = super::require_project(&context)?;
    let (project_id, master_key) = test_project_id_and_master_key(&context)?;
    let (kdf, mut envelope, code_bytes) =
        setup_recovery_envelope(&context, &project_id, &master_key)?;
    envelope.kdf_profile_id = "lk_kdf_other".to_owned();

    let result = super::restore_from_recovery_code(
        &context,
        &mut Vec::new(),
        &resolved,
        &kdf,
        &envelope,
        &code_bytes,
        true,
    );

    assert_error_contains(result, "kdf profile mismatch");
    Ok(())
}

#[test]
fn recovery_restore_recovers_master_key_from_envelope() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut init_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut init_output,
    )?;
    let resolved = super::require_project(&context)?;
    let (project_id, master_key) = test_project_id_and_master_key(&context)?;
    let (kdf, envelope, code_bytes) = setup_recovery_envelope(&context, &project_id, &master_key)?;
    context.key_store.delete_master_key(&project_id)?;

    let mut recover_output = Vec::new();
    super::restore_from_recovery_code(
        &context,
        &mut recover_output,
        &resolved,
        &kdf,
        &envelope,
        &code_bytes,
        false,
    )?;

    assert_eq!(*context.key_store.load_master_key(&project_id)?, master_key);
    let recover_output = String::from_utf8(recover_output)?;
    assert!(recover_output.contains("recovered: master_key"));
    assert!(recover_output.contains("metadata_only: yes"));
    Ok(())
}

#[test]
fn recovery_rotate_creates_envelope_and_prints_full_code() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut init_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut init_output,
    )?;
    let init_output = String::from_utf8(init_output)?;
    let initial_recovery_code = recovery_code_from_output(&init_output)?.to_owned();
    let (project_id, master_key) = test_project_id_and_master_key(&context)?;

    let rotate_context = context_with_recovery_code(&context, &initial_recovery_code);
    let mut rotate_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "recovery", "rotate"])?,
        &rotate_context,
        &mut rotate_output,
    )?;

    let rotate_output = String::from_utf8(rotate_output)?;
    assert!(rotate_output.contains("recovery_code_rotate: success"));
    assert!(rotate_output.contains("metadata_only: yes"));
    let code_line = recovery_code_from_output(&rotate_output)?;
    let code_bytes = locket_crypto::recovery_code_decode(code_line)?;
    let recovery_dir = directory.path().join(".locket").join("recovery");
    let kdf = super::load_recovery_kdf_toml(&recovery_dir)?;
    let envelope = super::load_recovery_envelope(&recovery_dir)?;
    assert_eq!(envelope.kdf_profile_id, kdf.kdf_profile_id);

    context.key_store.delete_master_key(&project_id)?;
    let resolved = super::require_project(&context)?;
    super::restore_from_recovery_code(
        &context,
        &mut Vec::new(),
        &resolved,
        &kdf,
        &envelope,
        &code_bytes,
        false,
    )?;
    assert_eq!(*context.key_store.load_master_key(&project_id)?, master_key);

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'RECOVERY_ROTATE'",
        [],
        |row| row.get(0),
    )?;
    assert!(metadata.contains("\"kdf_profile_id\""));
    assert!(!metadata.contains(code_line));
    Ok(())
}

#[test]
fn ai_safe_redacts_child_output_and_transcript() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    let args = test_secret_write_args("DATABASE_URL");
    super::set_secret_value(&context, &args, "postgres://localhost/app", "manual", 1_000)?;

    let mut ai_safe_output = Vec::new();
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "ai-safe",
            "--output",
            "transcript.log",
            "--",
            "/bin/sh",
            "-c",
            "printf 'db=postgres://localhost/app\n'; printf 'err=postgres://localhost/app\n' >&2",
        ])?,
        &context,
        &mut ai_safe_output,
    )?;

    let ai_safe_output = String::from_utf8(ai_safe_output)?;
    let transcript = std::fs::read_to_string(directory.path().join("transcript.log"))?;
    assert!(ai_safe_output.contains("lk_redacted_DATABASE_URL"));
    assert!(transcript.contains("lk_redacted_DATABASE_URL"));
    assert!(transcript.contains("[stdout timestamp="));
    assert!(transcript.contains("[stderr timestamp="));
    assert!(!ai_safe_output.contains("postgres://localhost/app"));
    assert!(!transcript.contains("postgres://localhost/app"));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mode = std::fs::metadata(directory.path().join("transcript.log"))?.permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'REDACT'",
        [],
        |row| row.get(0),
    )?;
    let metadata: serde_json::Value = serde_json::from_str(&metadata)?;
    assert_eq!(metadata["scope"], "ai-safe");
    assert_eq!(metadata["pattern_only"], false);
    assert_eq!(metadata["known_value_coverage"], true);
    assert_eq!(metadata["output_destinations"]["transcript"], true);
    assert_eq!(metadata["redacted_secret_names"], json!(["DATABASE_URL"]));
    assert_eq!(metadata["finding_counts"]["known_secret_value"], 2);
    assert!(!metadata.to_string().contains("postgres://localhost/app"));
    Ok(())
}

#[test]
fn ai_safe_redacts_known_secret_across_partial_line_flush_boundary() {
    let secret = "SPLIT_SECRET_VALUE";
    let redactions = vec![super::KnownSecretRedaction {
        value: zeroize::Zeroizing::new(secret.to_owned()),
        marker: "lk_redacted_SPLIT_SECRET".to_owned(),
        secret_name: Some("SPLIT_SECRET".to_owned()),
    }];
    let mut redactor = super::AiSafeStreamRedactor::new(&redactions);
    let prefix_len = super::AI_SAFE_PARTIAL_LINE_MAX_BYTES - 5;
    let mut first = vec![b'a'; prefix_len];
    first.extend_from_slice(&secret.as_bytes()[..5]);

    let first_chunks =
        redactor.push(super::AiSafeRawChunk { stream: super::AiSafeStream::Stdout, bytes: first });
    let first_text = first_chunks.iter().map(|chunk| chunk.text.as_str()).collect::<String>();
    assert!(!first_text.contains(&secret[..5]));

    let mut second = secret.as_bytes()[5..].to_vec();
    second.push(b'\n');
    let mut chunks =
        redactor.push(super::AiSafeRawChunk { stream: super::AiSafeStream::Stdout, bytes: second });
    chunks.extend(redactor.finish());
    let text = chunks.iter().map(|chunk| chunk.text.as_str()).collect::<String>();

    assert!(text.contains("lk_redacted_SPLIT_SECRET"));
    assert!(!text.contains(secret));
}

#[test]
fn ai_safe_fails_closed_when_locked_unless_pattern_only() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    let args = test_secret_write_args("DATABASE_URL");
    super::set_secret_value(&context, &args, "postgres://localhost/app", "manual", 1_000)?;
    let (project_id, _) = test_project_id_and_master_key(&context)?;
    context.key_store.delete_master_key(&project_id)?;

    let mut default_output = Vec::new();
    let default_result = run_with_context(
        Cli::try_parse_from(["locket", "ai-safe", "--", "/bin/sh", "-c", "touch spawned-default"])?,
        &context,
        &mut default_output,
    );
    assert_error_contains(default_result, "UnlockRequired");
    assert!(!directory.path().join("spawned-default").exists());

    let mut pattern_output = Vec::new();
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "ai-safe",
            "--pattern-only",
            "--",
            "/bin/sh",
            "-c",
            "printf 'token=sk_test_sampleTokenValue123\n'; touch spawned-pattern",
        ])?,
        &context,
        &mut pattern_output,
    )?;
    let pattern_output = String::from_utf8(pattern_output)?;
    assert!(pattern_output.contains("lk_redacted_PROVIDER_TOKEN"));
    assert!(!pattern_output.contains("sk_test_sampleTokenValue123"));
    assert!(directory.path().join("spawned-pattern").exists());
    Ok(())
}

#[test]
fn ai_safe_uses_privacy_config_aliases_but_audits_exact_names()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    run_with_context(
        Cli::try_parse_from(["locket", "config", "set", "privacy.redact_names", "true"])?,
        &context,
        &mut Vec::new(),
    )?;
    let args = test_secret_write_args("DATABASE_URL");
    super::set_secret_value(&context, &args, "postgres://localhost/app", "manual", 1_000)?;

    let mut ai_safe_output = Vec::new();
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "ai-safe",
            "--",
            "/bin/sh",
            "-c",
            "printf 'db=postgres://localhost/app\n'",
        ])?,
        &context,
        &mut ai_safe_output,
    )?;
    let ai_safe_output = String::from_utf8(ai_safe_output)?;
    assert!(ai_safe_output.contains("lk_redacted_secret-"));
    assert!(!ai_safe_output.contains("lk_redacted_DATABASE_URL"));
    assert!(!ai_safe_output.contains("postgres://localhost/app"));

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'REDACT'",
        [],
        |row| row.get(0),
    )?;
    let metadata: serde_json::Value = serde_json::from_str(&metadata)?;
    assert_eq!(metadata["redact_names"], true);
    assert_eq!(metadata["redacted_secret_names"], json!(["DATABASE_URL"]));
    assert!(!metadata.to_string().contains("postgres://localhost/app"));
    Ok(())
}

#[test]
fn ai_safe_transcript_force_repairs_permissions_and_child_exit_is_forwarded()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let transcript_path = directory.path().join("transcript.log");
    std::fs::write(&transcript_path, "old\n")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mut permissions = std::fs::metadata(&transcript_path)?.permissions();
        permissions.set_mode(0o644);
        std::fs::set_permissions(&transcript_path, permissions)?;
    }

    let mut no_force_output = Vec::new();
    let no_force_result = run_with_context(
        Cli::try_parse_from([
            "locket",
            "ai-safe",
            "--pattern-only",
            "--output",
            "transcript.log",
            "--",
            "/bin/sh",
            "-c",
            "true",
        ])?,
        &context,
        &mut no_force_output,
    );
    assert!(no_force_result.is_err());

    let mut forced_output = Vec::new();
    let forced_result = run_with_context(
        Cli::try_parse_from([
            "locket",
            "ai-safe",
            "--pattern-only",
            "--force",
            "--output",
            "transcript.log",
            "--",
            "/bin/sh",
            "-c",
            "printf 'token=sk_test_sampleTokenValue123'; exit 7",
        ])?,
        &context,
        &mut forced_output,
    );
    let Err(error) = forced_result else {
        return Err("ai-safe should forward child exit status".into());
    };
    assert_eq!(error.exit_code(), 7);
    let forced_output = String::from_utf8(forced_output)?;
    let transcript = std::fs::read_to_string(&transcript_path)?;
    assert!(forced_output.contains("lk_redacted_PROVIDER_TOKEN"));
    assert!(transcript.contains("lk_redacted_PROVIDER_TOKEN"));
    assert!(!transcript.contains("sk_test_sampleTokenValue123"));
    assert!(!transcript.contains("old"));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mode = std::fs::metadata(&transcript_path)?.permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    Ok(())
}
