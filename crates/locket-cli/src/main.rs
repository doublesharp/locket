//! Locket command-line entry point.

pub(crate) mod diagnostics;
mod onboarding;
mod policy_authoring;

use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use clap_complete::Shell as CompletionShell;
use directories::{BaseDirs, ProjectDirs};
use ignore::{WalkBuilder, gitignore::GitignoreBuilder};
use locket_core::{
    CommandPolicy, CommandSpec, Duration as LocketDuration, ExternalEnvSource, KeyId,
    PolicyDocument, ProfileId, ProfileName, ProjectConfig, ProjectId, SecretId, SecretName,
};
use locket_crypto::{
    EncryptedSecretValue, HkdfWrapInfo, KeyPurpose, KeyWrapAad, KeyWrapPurpose, WrappedKeyMaterial,
    decrypt_secret_value_v1, derive_recovery_key_v1, derive_wrapping_key_v1,
    encrypt_secret_value_v1, generate_key, generate_recovery_code_bytes, generate_recovery_salt,
    key_wrap_aad_v1, open_recovery_entry_v1, recovery_code_decode, recovery_code_encode,
    seal_recovery_entry_v1, secret_blob_aad_v1, secret_fingerprint_v1, unwrap_key_material_v1,
    wrap_key_material_v1,
};
use locket_platform::{
    KeyringMasterKeyStore, MasterKeyStore, PassphraseFallbackMasterKeyStore, RecoveryEnvelope,
    RecoveryEnvelopeEntry, RecoveryKdfToml, load_recovery_envelope, load_recovery_kdf_toml,
    save_recovery_envelope, save_recovery_kdf_toml,
};
use locket_scan::{
    FindingKind, KnownRedaction, ScanFinding, redact_text, redact_text_with_known_values, scan_text,
};
use locket_store::{
    AuditContext, AuditLogRecord, AuditWrite, DirectoryGrantRecord, KeyRecord, ProfileRecord,
    RuntimeSessionSecretNameRetention, SecretBlobRecord, SecretCopyTarget, SecretFingerprintRecord,
    SecretMetadataUpdate, SecretRecord, SecretVersionRecord, Store, StoreError, VersionDeprecation,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::ffi::OsStr;
use std::fmt::{self, Display};
use std::fs;
use std::io::{self, IsTerminal, Read, Seek, SeekFrom, Write};
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command as ProcessCommand, ExitCode as ProcessExitCode, Stdio};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration as StdDuration, SystemTime, UNIX_EPOCH};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use policy_authoring::PolicyCommand;

const LOCKET_TOML: &str = "locket.toml";
const CONFIG_TOML: &str = "config.toml";
const EXAMPLE_FILE: &str = ".env.example";
const GITIGNORE_FILE: &str = ".gitignore";
const LOCKETIGNORE_FILE: &str = ".locketignore";
const EXAMPLE_BEGIN: &str = "# --- BEGIN LOCKET MANAGED ---";
const EXAMPLE_END: &str = "# --- END LOCKET MANAGED ---";
const HOOK_BEGIN: &str = "# --- BEGIN LOCKET PRE-COMMIT ---";
const HOOK_END: &str = "# --- END LOCKET PRE-COMMIT ---";
const SHELL_HOOK_BEGIN: &str = "# --- BEGIN LOCKET SHELL HOOK ---";
const SHELL_HOOK_END: &str = "# --- END LOCKET SHELL HOOK ---";
const DIRECTORY_GRANT_SCOPE_PROJECT_ROOT: &str = "project-root";
const GITIGNORE_ENTRIES: [&str; 4] = [".env", ".env.*", ".locket.local", ".locketignore"];
const DEFAULT_MAX_GRACE_TTL_SECONDS: u64 = 7 * 24 * 60 * 60;
const NANOS_PER_SECOND: i64 = 1_000_000_000;
const AGENT_LOG_MAX_BYTES: u64 = 1024 * 1024;
const AGENT_LOG_RETAINED_FILES: u8 = 5;
const AGENT_LOG_FOLLOW_SLEEP_MS: u64 = 250;

#[derive(Debug, Parser)]
#[command(name = "locket", version, about = "Local-first secrets control plane")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Show metadata-only status.
    Status,
    /// Initialize a Locket project from a template.
    New(NewArgs),
    /// Show metadata-only onboarding checklist.
    Bootstrap,
    /// Generate shell completions.
    Completion(CompletionArgs),
    /// Run locked-safe local diagnostics.
    Doctor,
    /// Create metadata-only debug artifacts.
    Debug {
        /// Debug command.
        #[command(subcommand)]
        command: DebugCommand,
    },
    /// Initialize a Locket project.
    Init(InitArgs),
    /// Store a new secret.
    Set(SecretWriteArgs),
    /// Import secrets from an env file.
    Import(ImportArgs),
    /// Get secret metadata, reveal, or copy.
    Get(GetArgs),
    /// Tombstone a secret source.
    Rm(SourceKeyArgs),
    /// Destructively purge encrypted versions.
    Purge(PurgeArgs),
    /// List secrets.
    List(ListArgs),
    /// Execute a child process with scoped injection.
    Exec(ExecArgs),
    /// Execute a named command policy from locket.toml.
    Run(RunArgs),
    /// Inspect runtime environment decisions.
    Env {
        /// Environment command.
        #[command(subcommand)]
        command: EnvCommand,
    },
    /// Execute Docker Compose with scoped policy injection.
    Compose {
        /// Compose command.
        #[command(subcommand)]
        command: ComposeCommand,
    },
    /// Lock local agent-held keys.
    Lock,
    /// Unlock the local vault.
    Unlock(UnlockArgs),
    /// Manage profiles.
    Profile {
        /// Profile command.
        #[command(subcommand)]
        command: ProfileCommand,
    },
    /// Author command policies in locket.toml.
    Policy {
        /// Policy command.
        #[command(subcommand)]
        command: PolicyCommand,
    },
    /// Switch active profile.
    Use(ProfileNameArgs),
    /// Manage trusted project roots.
    Project {
        /// Project command.
        #[command(subcommand)]
        command: ProjectCommand,
    },
    /// Emit shell rc integration.
    Shellenv(ShellenvArgs),
    /// Emit or install a metadata-only shell hook.
    Hook(HookArgs),
    /// Allow shell integration for the trusted project root and active profile.
    Allow,
    /// Revoke shell integration consent for the active profile or project.
    Deny(DenyArgs),
    /// Regenerate .env.example.
    EmitExample,
    /// Install Git hooks.
    InstallHooks,
    /// Scan project files.
    Scan(ScanArgs),
    /// Redact a file or stdin.
    Redact(RedactArgs),
    /// Emit AI-safe context metadata.
    Context(RedactNamesArgs),
    /// Capture and redact command output.
    AiSafe(AiSafeArgs),
    /// Rotate a secret value.
    Rotate(RotateArgs),
    /// Update secret metadata.
    Meta(SecretMetaArgs),
    /// Show secret version history.
    History(HistoryArgs),
    /// Show metadata-only differences.
    Diff(DiffArgs),
    /// Copy a secret between profiles without revealing its value.
    Copy(CopyArgs),
    /// Audit log operations.
    Audit {
        /// Audit command.
        #[command(subcommand)]
        command: AuditCommand,
    },
    /// Manage the local agent.
    Agent {
        /// Agent command.
        #[command(subcommand)]
        command: AgentCommand,
    },
    /// Manage non-secret user preferences.
    Config {
        /// Config command.
        #[command(subcommand)]
        command: ConfigCommand,
    },
    /// Manage passkey authenticators.
    Passkey {
        /// Passkey command.
        #[command(subcommand)]
        command: PasskeyCommand,
    },
    /// Restore vault access from a recovery code.
    Recover(RecoverArgs),
    /// Manage recovery codes.
    Recovery {
        /// Recovery command.
        #[command(subcommand)]
        command: RecoveryCommand,
    },
}

#[derive(Debug, Args)]
struct InitArgs {
    /// Project display name.
    #[arg(long)]
    name: Option<String>,
    /// Initial profile name.
    #[arg(long)]
    profile: Option<String>,
}

#[derive(Debug, Args)]
struct NewArgs {
    /// Local or built-in template name.
    #[arg(long)]
    from_template: String,
}

#[derive(Debug, Clone, Copy, Args)]
struct CompletionArgs {
    /// Shell to generate completions for.
    #[arg(value_enum)]
    shell: CompletionShell,
}

#[derive(Debug, Args)]
struct SecretWriteArgs {
    /// Secret key name.
    key: String,
    #[command(flatten)]
    source: SourceArg,
    #[command(flatten)]
    metadata: SecretMetadataFlags,
}

#[derive(Debug, Args)]
struct ImportArgs {
    /// Env file to import.
    file: String,
    /// Profile to import into.
    #[arg(long)]
    profile: Option<String>,
    /// Runtime source to target.
    #[arg(long, value_enum)]
    source: Option<SecretSourceArg>,
    /// Rotate duplicate keys instead of skipping them.
    #[arg(long)]
    overwrite: bool,
}

#[derive(Debug, Args)]
struct GetArgs {
    /// Secret key name.
    key: String,
    /// Reveal the value to stdout after policy gates.
    #[arg(long, conflicts_with = "copy")]
    reveal: bool,
    /// Allow reveal when stdout is not an interactive terminal.
    #[arg(long, requires = "reveal")]
    force: bool,
    /// Copy the value to clipboard after policy gates.
    #[arg(long)]
    copy: bool,
}

#[derive(Debug, Args)]
struct SourceKeyArgs {
    /// Secret key name.
    key: String,
    #[command(flatten)]
    source: SourceArg,
}

#[derive(Debug, Args)]
struct PurgeArgs {
    /// Secret key name.
    key: String,
    #[command(flatten)]
    source: SourceArg,
    /// Purge a specific version.
    #[arg(long, conflicts_with = "all_versions")]
    version: Option<u32>,
    /// Purge every version for a deleted source.
    #[arg(long)]
    all_versions: bool,
}

#[derive(Debug, Args)]
struct ListArgs {
    /// Include deleted sources and deprecated version counts.
    #[arg(long)]
    all: bool,
}

#[derive(Debug, Args)]
struct ExecArgs {
    /// Secret name to inject. May be repeated.
    #[arg(long = "secret")]
    secrets: Vec<String>,
    /// Inject every active profile secret after confirmation.
    #[arg(long)]
    all: bool,
    /// Command and arguments after `--`.
    #[arg(last = true, required = true)]
    command: Vec<String>,
}

#[derive(Debug, Args)]
struct RunArgs {
    /// Command policy name from [commands.<policy>].
    policy: String,
}

#[derive(Debug, Subcommand)]
enum EnvCommand {
    /// Show metadata-only policy environment decisions.
    Inspect(EnvInspectArgs),
    /// Execute docker run with policy-backed environment injection.
    Docker(EnvDockerArgs),
}

#[derive(Debug, Args)]
struct EnvInspectArgs {
    /// Command policy name from [commands.<policy>].
    #[arg(long)]
    policy: String,
}

#[derive(Debug, Args)]
struct EnvDockerArgs {
    /// Command policy name from [commands.<policy>].
    #[arg(long)]
    policy: String,
    /// Docker command and arguments after `--`.
    #[arg(last = true, required = true)]
    command: Vec<String>,
}

#[derive(Debug, Subcommand)]
enum ComposeCommand {
    /// Execute docker compose with policy-backed environment injection.
    Run(ComposeRunArgs),
}

#[derive(Debug, Args)]
struct ComposeRunArgs {
    /// Command policy name from [commands.<policy>].
    #[arg(long)]
    policy: String,
    /// Compose project directory to pass to docker compose.
    #[arg(long)]
    project_directory: Option<PathBuf>,
    /// Compose profile to pass to docker compose. May be repeated.
    #[arg(long)]
    profile: Vec<String>,
    /// Docker Compose command and arguments after `--`.
    #[arg(last = true, required = true)]
    command: Vec<String>,
}

#[derive(Debug, Args)]
struct UnlockArgs {
    /// Require local user verification before unlock.
    #[arg(long)]
    verify_user: bool,
}

#[derive(Debug, Subcommand)]
enum ProfileCommand {
    /// Create a profile.
    Create(ProfileNameArgs),
    /// List profiles.
    List,
    /// Mark a profile as dangerous.
    MarkDangerous(ProfileNameArgs),
    /// Clear dangerous-profile marking.
    ClearDangerous(ProfileNameArgs),
}

#[derive(Debug, Args)]
struct ProfileNameArgs {
    /// Profile name.
    profile: String,
}

#[derive(Debug, Args)]
struct ShellenvArgs {
    /// Shell syntax to emit.
    #[arg(long, value_enum)]
    shell: Option<ShellArg>,
}

#[derive(Debug, Args)]
struct HookArgs {
    /// Shell syntax to emit.
    #[arg(long, value_enum)]
    shell: Option<ShellArg>,
    /// Describe installation status. Full agent-backed install is not available in this build.
    #[arg(long)]
    install: bool,
}

#[derive(Debug, Args)]
struct DenyArgs {
    /// Revoke every durable directory grant for this project across profiles.
    #[arg(long)]
    all: bool,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ShellArg {
    /// Bourne Again Shell syntax.
    Bash,
    /// Z shell syntax.
    Zsh,
    /// Fish shell syntax.
    Fish,
}

#[derive(Debug, Subcommand)]
enum ProjectCommand {
    /// Trust the current project root.
    TrustRoot,
    /// List trusted roots.
    ListRoots,
    /// Remove a trusted root.
    UntrustRoot {
        /// Trusted root hash.
        root_hash: String,
    },
}

#[derive(Debug, Args)]
struct ScanArgs {
    /// Scan staged Git content.
    #[arg(long)]
    staged: bool,
    /// Require known-value coverage.
    #[arg(long)]
    require_known: bool,
    /// Ignore .gitignore rules.
    #[arg(long)]
    no_gitignore: bool,
    /// Optional path to scan.
    path: Option<String>,
}

#[derive(Debug, Args)]
struct RedactArgs {
    /// File to redact.
    file: Option<String>,
    /// Read from stdin.
    #[arg(long, conflicts_with = "file")]
    stdin: bool,
    #[command(flatten)]
    redact_names: RedactNamesArgs,
}

#[derive(Debug, Args)]
struct RedactNamesArgs {
    /// Use privacy aliases instead of secret names.
    #[arg(long)]
    redact_names: bool,
}

#[derive(Debug, Args)]
struct AiSafeArgs {
    /// Use pattern-only redaction without known-value coverage.
    #[arg(long)]
    pattern_only: bool,
    /// Combined redacted transcript path.
    #[arg(long)]
    output: Option<String>,
    /// Overwrite an existing transcript path after confirmation.
    #[arg(long)]
    force: bool,
    #[command(flatten)]
    redact_names: RedactNamesArgs,
    /// Command and arguments after `--`.
    #[arg(last = true, required = true)]
    command: Vec<String>,
}

#[derive(Debug, Args)]
struct RotateArgs {
    /// Secret key name.
    key: String,
    #[command(flatten)]
    source: SourceArg,
    #[command(flatten)]
    metadata: SecretMetadataFlags,
    /// Grace TTL for the prior version.
    #[arg(long)]
    grace_ttl: Option<String>,
}

#[derive(Debug, Args)]
struct SecretMetaArgs {
    /// Secret key name.
    key: String,
    #[command(flatten)]
    source: SourceArg,
    #[command(flatten)]
    metadata: SecretMetadataFlags,
}

#[derive(Debug, Args)]
struct HistoryArgs {
    /// Secret key name.
    key: String,
    /// Profile to inspect.
    #[arg(long)]
    profile: Option<String>,
}

#[derive(Debug, Args)]
struct DiffArgs {
    /// First profile, unless --since is used.
    profile_a: Option<String>,
    /// Second profile, unless --since is used.
    profile_b: Option<String>,
    /// Show changes since an ISO date or Git revision.
    #[arg(long)]
    since: Option<String>,
}

#[derive(Debug, Args)]
struct CopyArgs {
    /// Secret key name.
    key: String,
    /// Source profile name.
    #[arg(long)]
    from: String,
    /// Target profile name.
    #[arg(long)]
    to: String,
    /// Runtime source to copy from.
    #[arg(long, value_enum)]
    from_source: Option<SecretSourceArg>,
    /// Runtime source to copy to.
    #[arg(long, value_enum)]
    to_source: Option<SecretSourceArg>,
}

#[derive(Clone, Debug, Subcommand)]
enum AgentCommand {
    /// Start the local agent.
    Start,
    /// Print agent status.
    Status,
    /// Stop the local agent.
    Stop,
    /// Print redacted agent logs.
    Logs(AgentLogsArgs),
}

#[derive(Clone, Debug, Args)]
struct AgentLogsArgs {
    /// Number of lines to print.
    #[arg(long, default_value_t = 200)]
    lines: usize,
    /// RFC 3339 UTC timestamp or Unix timestamp in seconds/nanoseconds to filter from.
    #[arg(long)]
    since: Option<String>,
    /// Stream new log entries until interrupted.
    #[arg(long)]
    follow: bool,
}

#[derive(Debug, Subcommand)]
enum DebugCommand {
    /// Emit a redacted metadata-only support bundle summary.
    Bundle(DebugBundleArgs),
}

#[derive(Debug, Args)]
struct DebugBundleArgs {
    /// Confirm that only redacted metadata may be emitted.
    #[arg(long)]
    redacted: bool,
    /// Write bundle summary to this path instead of stdout.
    #[arg(long)]
    output: Option<String>,
}

#[derive(Clone, Copy, Debug, Subcommand)]
enum AuditCommand {
    /// Verify the local audit HMAC chain.
    Verify,
}

#[derive(Debug, Subcommand)]
enum ConfigCommand {
    /// List configured non-secret preferences.
    List,
    /// Get a configured non-secret preference.
    Get(ConfigKeyArgs),
    /// Set a non-secret preference.
    Set(ConfigSetArgs),
    /// Unset a non-secret preference.
    Unset(ConfigKeyArgs),
}

#[derive(Debug, Args)]
struct ConfigKeyArgs {
    /// Config key.
    key: String,
}

#[derive(Debug, Args)]
struct ConfigSetArgs {
    /// Config key.
    key: String,
    /// Config value.
    value: String,
}

#[derive(Debug, Subcommand)]
enum PasskeyCommand {
    /// Register a passkey authenticator.
    Register,
    /// List passkey authenticators.
    List(PasskeyListArgs),
    /// Remove a passkey authenticator.
    Remove {
        /// Passkey label or credential id prefix.
        passkey: String,
    },
}

#[derive(Debug, Args)]
struct PasskeyListArgs {
    /// Include revoked credentials.
    #[arg(long)]
    all: bool,
}

#[derive(Debug, Args)]
struct RecoverArgs {
    /// Overwrite an existing master key entry.
    #[arg(long)]
    force: bool,
}

#[derive(Clone, Copy, Debug, Subcommand)]
enum RecoveryCommand {
    /// Rotate the recovery code.
    Rotate,
}

#[derive(Debug, Args)]
struct SourceArg {
    /// Runtime source to target.
    #[arg(long, value_enum)]
    source: Option<SecretSourceArg>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum SecretSourceArg {
    /// Team-managed source.
    TeamManaged,
    /// User-local source.
    UserLocal,
    /// Machine-local source.
    MachineLocal,
}

#[derive(Debug, Args)]
struct SecretMetadataFlags {
    /// Metadata description.
    #[arg(long)]
    description: Option<String>,
    /// Metadata owner.
    #[arg(long)]
    owner: Option<String>,
    /// Metadata tag. May be repeated.
    #[arg(long = "tag")]
    tags: Vec<String>,
    /// Mark secret required.
    #[arg(long, conflicts_with = "optional")]
    required: bool,
    /// Mark secret optional.
    #[arg(long)]
    optional: bool,
}

fn main() -> ProcessExitCode {
    let cli = Cli::parse();
    if let Some(Command::Completion(args)) = &cli.command {
        let mut output = io::stdout();
        return match completion_command(&mut output, args.shell) {
            Ok(()) => ProcessExitCode::SUCCESS,
            Err(error) => write_error_and_exit(&error),
        };
    }

    let context = match RuntimeContext::default() {
        Ok(context) => context,
        Err(error) => {
            return write_error_and_exit(&error);
        }
    };

    let mut output = io::stdout();
    match run_with_context(cli, &context, &mut output) {
        Ok(code) => ProcessExitCode::from(code),
        Err(error) => write_error_and_exit(&error),
    }
}

fn write_error_and_exit(error: &CliError) -> ProcessExitCode {
    let mut stderr = io::stderr();
    let _ignored = writeln!(stderr, "locket: {error}");
    ProcessExitCode::from(error.exit_code())
}

fn run_with_context(
    cli: Cli,
    context: &RuntimeContext,
    output: &mut impl Write,
) -> Result<u8, CliError> {
    let command = cli.command.unwrap_or(Command::Status);

    match command {
        Command::Status => status(context, output)?,
        Command::New(args) => new_command(context, output, &args)?,
        Command::Bootstrap => bootstrap_command(context, output)?,
        Command::Completion(args) => completion_command(output, args.shell)?,
        Command::Doctor => return diagnostics::doctor_command(context, output),
        Command::Debug { command } => debug_command(context, output, command)?,
        Command::Init(args) => init(context, output, args)?,
        Command::Set(args) => set_command(context, output, &args)?,
        Command::Import(args) => import_command(context, output, &args)?,
        Command::Get(args) => get_command(context, output, &args)?,
        Command::Rm(args) => rm_command(context, output, &args)?,
        Command::Purge(args) => purge_command(context, output, &args)?,
        Command::List(args) => list_command(context, output, &args)?,
        Command::Exec(args) => exec_command(context, output, &args)?,
        Command::Run(args) => run_command(context, output, &args)?,
        Command::Env { command } => env_command(context, output, command)?,
        Command::Compose { command } => compose_command(context, output, command)?,
        Command::Rotate(args) => rotate_command(context, output, &args)?,
        Command::Meta(args) => meta_command(context, output, &args)?,
        Command::History(args) => history_command(context, output, &args)?,
        Command::Diff(args) => diff_command(context, output, &args)?,
        Command::Copy(args) => copy_command(context, output, &args)?,
        Command::Audit { command } => audit_command(context, output, command)?,
        Command::Lock => lock_command(context, output)?,
        Command::Unlock(args) => unlock_command(context, output, &args)?,
        Command::EmitExample => emit_example_command(context, output)?,
        Command::InstallHooks => install_hooks_command(context, output)?,
        Command::Profile { command } => profile_command(context, output, command)?,
        Command::Policy { command } => policy_authoring::command(context, output, command)?,
        Command::Project { command } => project_command(context, output, command)?,
        Command::Shellenv(args) => shellenv_command(output, &args)?,
        Command::Hook(args) => hook_command(output, &args)?,
        Command::Allow => allow_command(context, output)?,
        Command::Deny(args) => deny_command(context, output, &args)?,
        Command::Agent { command } => agent_command(context, output, command)?,
        Command::Use(args) => use_profile_command(context, output, args)?,
        Command::Scan(args) => scan_command(context, output, args)?,
        Command::Redact(args) => redact_command(context, output, args)?,
        Command::Context(args) => context_command(context, output, &args)?,
        Command::AiSafe(args) => ai_safe_command(context, output, &args)?,
        Command::Config { command } => config_command(context, output, command)?,
        Command::Passkey { command } => passkey_command(output, command)?,
        Command::Recover(args) => recover_command(context, output, &args)?,
        Command::Recovery { command } => recovery_command(context, output, command)?,
    }

    Ok(0)
}

fn completion_command(output: &mut impl Write, shell: CompletionShell) -> Result<(), CliError> {
    let mut command = Cli::command();
    let mut buffer = Vec::new();
    clap_complete::generate(shell, &mut command, "locket", &mut buffer);
    output.write_all(&buffer)?;
    Ok(())
}

#[derive(Clone)]
struct RuntimeContext {
    cwd: PathBuf,
    store_path: PathBuf,
    config_path: PathBuf,
    template_dir: PathBuf,
    key_store: Arc<dyn MasterKeyStore + Send + Sync>,
    passphrase_store: PassphraseFallbackMasterKeyStore,
    passphrase_reader: Arc<dyn PassphraseReader + Send + Sync>,
    confirmation_reader: Arc<dyn ConfirmationReader + Send + Sync>,
}

impl RuntimeContext {
    fn default() -> Result<Self, CliError> {
        let cwd = std::env::current_dir()?;
        let Some(project_dirs) = ProjectDirs::from("dev", "0xdoublesharp", "Locket") else {
            return Err(CliError::Config("could not resolve a local data directory".to_owned()));
        };
        let Some(base_dirs) = BaseDirs::new() else {
            return Err(CliError::Config("could not resolve a local home directory".to_owned()));
        };
        let data_dir = project_dirs.data_dir();
        let config_dir = project_dirs.config_dir();
        fs::create_dir_all(data_dir)?;
        fs::create_dir_all(config_dir)?;
        Ok(Self {
            cwd,
            store_path: data_dir.join("store.db"),
            config_path: config_dir.join(CONFIG_TOML),
            template_dir: base_dirs.home_dir().join(".locket").join("templates"),
            key_store: Arc::new(KeyringMasterKeyStore),
            passphrase_store: PassphraseFallbackMasterKeyStore::new(
                data_dir.join("passphrase-fallback"),
            ),
            passphrase_reader: Arc::new(EnvOrPromptPassphraseReader),
            confirmation_reader: Arc::new(StdinConfirmationReader),
        })
    }
}

trait ConfirmationReader {
    fn read_confirmation(&self, prompt: &str) -> Result<String, CliError>;
}

#[derive(Debug, Clone, Copy)]
struct StdinConfirmationReader;

impl ConfirmationReader for StdinConfirmationReader {
    fn read_confirmation(&self, prompt: &str) -> Result<String, CliError> {
        if !io::stdin().is_terminal() {
            return Err(CliError::Config(format!("{prompt} requires interactive confirmation")));
        }
        let mut confirmation = String::new();
        io::stdin().read_line(&mut confirmation)?;
        Ok(confirmation)
    }
}

trait PassphraseReader {
    fn existing_passphrase(&self) -> Result<zeroize::Zeroizing<String>, CliError>;

    fn new_passphrase(&self) -> Result<zeroize::Zeroizing<String>, CliError>;
}

#[derive(Debug, Clone, Copy)]
struct EnvOrPromptPassphraseReader;

impl PassphraseReader for EnvOrPromptPassphraseReader {
    fn existing_passphrase(&self) -> Result<zeroize::Zeroizing<String>, CliError> {
        require_interactive_passphrase("passphrase fallback unlock")?;
        read_hidden_passphrase("locket passphrase: ")
    }

    fn new_passphrase(&self) -> Result<zeroize::Zeroizing<String>, CliError> {
        require_interactive_passphrase("passphrase fallback setup")?;
        let first = read_hidden_passphrase("new locket passphrase: ")?;
        let second = read_hidden_passphrase("confirm locket passphrase: ")?;
        if *first != *second {
            return Err(CliError::Config("passphrases did not match".to_owned()));
        }
        Ok(first)
    }
}

fn require_interactive_passphrase(reason: &str) -> Result<(), CliError> {
    if io::stdin().is_terminal() && io::stderr().is_terminal() {
        Ok(())
    } else {
        Err(CliError::Config(format!("{reason} requires an interactive TTY")))
    }
}

fn read_hidden_passphrase(prompt: &str) -> Result<zeroize::Zeroizing<String>, CliError> {
    let passphrase = zeroize::Zeroizing::new(rpassword::prompt_password(prompt)?);
    if passphrase.is_empty() {
        return Err(CliError::Config("passphrase must not be empty".to_owned()));
    }
    Ok(passphrase)
}

#[derive(Debug)]
enum CliError {
    Config(String),
    ChildExit(u8),
    Io(io::Error),
    Store(StoreError),
    TomlDe(toml::de::Error),
    TomlSer(toml::ser::Error),
    Crypto(locket_crypto::CryptoError),
    Platform(locket_platform::PlatformError),
    Time,
}

impl CliError {
    const fn exit_code(&self) -> u8 {
        match self {
            Self::Config(_) | Self::TomlDe(_) | Self::TomlSer(_) => 64,
            Self::ChildExit(code) => *code,
            Self::Platform(locket_platform::PlatformError::MasterKeyNotFound) => 72,
            Self::Store(StoreError::AuditIntegrity { .. }) => 93,
            Self::Io(_) | Self::Store(_) | Self::Crypto(_) | Self::Platform(_) | Self::Time => 90,
        }
    }
}

impl Display for CliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(message) => formatter.write_str(message),
            Self::ChildExit(code) => write!(formatter, "child process exited with code {code}"),
            Self::Io(error) => error.fmt(formatter),
            Self::Store(error) => error.fmt(formatter),
            Self::TomlDe(error) => error.fmt(formatter),
            Self::TomlSer(error) => error.fmt(formatter),
            Self::Crypto(error) => error.fmt(formatter),
            Self::Platform(error) => error.fmt(formatter),
            Self::Time => formatter.write_str("system time is before the Unix epoch"),
        }
    }
}

impl Error for CliError {}

impl From<io::Error> for CliError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<StoreError> for CliError {
    fn from(value: StoreError) -> Self {
        Self::Store(value)
    }
}

impl From<toml::de::Error> for CliError {
    fn from(value: toml::de::Error) -> Self {
        Self::TomlDe(value)
    }
}

impl From<toml::ser::Error> for CliError {
    fn from(value: toml::ser::Error) -> Self {
        Self::TomlSer(value)
    }
}

impl From<locket_crypto::CryptoError> for CliError {
    fn from(value: locket_crypto::CryptoError) -> Self {
        Self::Crypto(value)
    }
}

impl From<locket_platform::PlatformError> for CliError {
    fn from(value: locket_platform::PlatformError) -> Self {
        Self::Platform(value)
    }
}

fn status(context: &RuntimeContext, output: &mut impl Write) -> Result<(), CliError> {
    let Some(resolved) = resolve_project(&context.cwd)? else {
        writeln!(output, "locket: not initialized")?;
        writeln!(output, "next_action: run locket init")?;
        return Ok(());
    };

    let store = open_store(context)?;
    let project = store.get_project(resolved.config.project_id.as_str())?;
    let root_hash = root_hash(&resolved.root)?;
    let trusted = store.project_root_is_trusted(resolved.config.project_id.as_str(), &root_hash)?;
    let profile = store.get_profile_by_name(
        resolved.config.project_id.as_str(),
        resolved.config.default_profile.as_str(),
    )?;
    let redact_names = status_privacy_redact_names_enabled(context)?;
    let project_label = status_project_label(&resolved, redact_names);
    let profile_label = status_profile_label(
        profile.as_ref(),
        resolved.config.default_profile.as_str(),
        redact_names,
    );
    let running_sessions =
        store.list_incomplete_runtime_sessions(resolved.config.project_id.as_str())?.len();
    let scan_warning_count = status_scan_warning_count(&resolved.root)?;
    let example_exists = resolved.root.join(EXAMPLE_FILE).exists();
    let next_action = status_next_action(
        project.as_ref(),
        profile.as_ref(),
        trusted,
        example_exists,
        scan_warning_count,
    );

    writeln!(output, "project: {project_label}")?;
    writeln!(
        output,
        "project_id: {}",
        status_project_id_label(resolved.config.project_id.as_str(), redact_names)
    )?;
    writeln!(output, "root: {}", resolved.root.display())?;
    writeln!(output, "default_profile: {profile_label}")?;
    writeln!(output, "active_profile: {profile_label}")?;
    writeln!(output, "lock_state: {}", status_lock_state(project.as_ref(), profile.as_ref()))?;
    writeln!(output, "agent: unavailable")?;
    writeln!(output, "agent_state: unavailable")?;
    writeln!(output, "running_sessions: {running_sessions}")?;
    writeln!(output, "scan_warnings: {scan_warning_count}")?;
    writeln!(output, "store: {}", if project.is_some() { "ready" } else { "partial" })?;
    writeln!(output, "trusted_root: {}", if trusted { "yes" } else { "no" })?;
    writeln!(output, "profile: {}", if profile.is_some() { "ready" } else { "missing" })?;
    writeln!(output, "metadata_only: yes")?;
    writeln!(output, "next_action: {next_action}")?;
    Ok(())
}

fn status_privacy_redact_names_enabled(context: &RuntimeContext) -> Result<bool, CliError> {
    let config = read_user_config(context)?;
    Ok(config_bool_value(&config, "privacy.redact_names")?.unwrap_or(false))
}

fn status_project_label(resolved: &ResolvedProject, redact_names: bool) -> String {
    if redact_names {
        privacy_alias("project", resolved.config.project_id.as_str())
    } else {
        resolved.config.name.clone()
    }
}

fn status_project_id_label(project_id: &str, redact_names: bool) -> String {
    if redact_names { privacy_alias("project", project_id) } else { project_id.to_owned() }
}

fn status_profile_label(
    profile: Option<&ProfileRecord>,
    default_profile: &str,
    redact_names: bool,
) -> String {
    if redact_names {
        let profile_id = profile.map_or(default_profile, |profile| profile.id.as_str());
        privacy_alias("profile", profile_id)
    } else {
        default_profile.to_owned()
    }
}

const fn status_lock_state(
    project: Option<&locket_store::ProjectRecord>,
    profile: Option<&ProfileRecord>,
) -> &'static str {
    if project.is_none() || profile.is_none() { "unavailable" } else { "locked" }
}

fn status_scan_warning_count(root: &Path) -> Result<usize, CliError> {
    let mut findings = Vec::new();
    scan_path(root, root, &[], true, &mut findings)?;
    findings.retain(|finding| !matches!(finding.path_label.as_str(), LOCKET_TOML | EXAMPLE_FILE));
    Ok(findings.len())
}

const fn status_next_action(
    project: Option<&locket_store::ProjectRecord>,
    profile: Option<&ProfileRecord>,
    trusted_root: bool,
    example_exists: bool,
    scan_warning_count: usize,
) -> &'static str {
    if project.is_none() || profile.is_none() {
        "run locket init to resume local metadata setup"
    } else if !trusted_root {
        "run locket project trust-root"
    } else if !example_exists {
        "run locket emit-example"
    } else if scan_warning_count > 0 {
        "run locket scan"
    } else {
        "none"
    }
}

fn new_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &NewArgs,
) -> Result<(), CliError> {
    if resolve_project(&context.cwd)?.is_some() {
        return Err(CliError::Config("project already initialized".to_owned()));
    }
    let config_path = context.cwd.join(LOCKET_TOML);
    if config_path.exists() {
        return Err(CliError::Config(
            "locket.toml already exists but could not be resolved".to_owned(),
        ));
    }

    let template = onboarding::load_project_template(&context.template_dir, &args.from_template)?;
    let rendered = template.render_project_config(template.name.clone())?;
    fs::write(&config_path, rendered)?;
    let config = read_project_config(&config_path)?;
    let store = open_store(context)?;
    let timestamp = now_unix_nanos()?;
    let mut master_key_source = MasterKeySource::OsKeyStore;

    if let Err(error) = (|| -> Result<(), CliError> {
        ensure_project_metadata(&store, &config, timestamp)?;
        master_key_source = initialize_project_keys(context, &store, &config, timestamp)?;
        ensure_template_profiles(context, &store, &config, &template, timestamp)?;
        trust_root(&store, &config, &context.cwd, timestamp)?;
        ensure_gitignore(&context.cwd)?;
        write_example_block(&context.cwd, &template.expected_secrets)?;
        Ok(())
    })() {
        let _ignored = fs::remove_file(&config_path);
        return Err(error);
    }

    writeln!(output, "initialized locket project {}", config.project_id)?;
    writeln!(output, "template: {}", args.from_template)?;
    writeln!(output, "template_source: {}", template.source.label())?;
    writeln!(output, "default_profile: {}", config.default_profile)?;
    writeln!(output, "master_key_source: {}", master_key_source.as_str())?;
    writeln!(output, "profiles: {}", template.profiles.len())?;
    writeln!(output, "expected_secrets: {}", template.expected_secrets.len())?;
    writeln!(output, "commands: {}", template.command_count())?;
    writeln!(output, "secrets: not written")?;
    Ok(())
}

fn bootstrap_command(context: &RuntimeContext, output: &mut impl Write) -> Result<(), CliError> {
    let resolved = require_project(context)?;
    let store = open_store(context)?;
    let project = store.get_project(resolved.config.project_id.as_str())?;
    let profile = store.get_profile_by_name(
        resolved.config.project_id.as_str(),
        resolved.config.default_profile.as_str(),
    )?;
    let root_hash = root_hash(&resolved.root)?;
    let trusted_root =
        store.project_root_is_trusted(resolved.config.project_id.as_str(), &root_hash)?;
    let example_exists = resolved.root.join(EXAMPLE_FILE).exists();

    writeln!(output, "project: {}", resolved.config.name)?;
    writeln!(output, "project_id: {}", resolved.config.project_id)?;
    writeln!(output, "profile: {}", resolved.config.default_profile)?;
    writeln!(output, "profile_ready: {}", if profile.is_some() { "yes" } else { "no" })?;
    writeln!(output, "store_project: {}", if project.is_some() { "yes" } else { "no" })?;
    writeln!(output, ".env.example: {}", if example_exists { "yes" } else { "no" })?;
    writeln!(output, "trusted_root: {}", if trusted_root { "yes" } else { "no" })?;
    writeln!(output, "metadata_only: yes")?;
    writeln!(output, "next_actions:")?;
    if project.is_none() || profile.is_none() {
        writeln!(output, "- run locket init to resume local metadata setup")?;
    }
    if !example_exists {
        writeln!(output, "- run locket emit-example")?;
    }
    if !trusted_root {
        writeln!(output, "- run locket project trust-root")?;
    }
    if project.is_some() && profile.is_some() && example_exists && trusted_root {
        writeln!(output, "- none")?;
    }
    Ok(())
}

fn init(context: &RuntimeContext, output: &mut impl Write, args: InitArgs) -> Result<(), CliError> {
    let store = open_store(context)?;
    let timestamp = now_unix_nanos()?;

    if let Some(resolved) = resolve_project(&context.cwd)? {
        ensure_project_metadata(&store, &resolved.config, timestamp)?;
        trust_root(&store, &resolved.config, &resolved.root, timestamp)?;
        ensure_gitignore(&resolved.root)?;
        ensure_example_file(&resolved.root)?;
        writeln!(output, "locket: project already initialized ({})", resolved.config.project_id)?;
        return Ok(());
    }

    let profile_name = match args.profile {
        Some(profile) => ProfileName::new(profile)
            .map_err(|_| CliError::Config("invalid profile name".to_owned()))?,
        None => ProfileName::new("dev")
            .map_err(|_| CliError::Config("invalid profile name".to_owned()))?,
    };
    let project_name = args.name.unwrap_or_else(|| fallback_project_name(&context.cwd));
    let config = ProjectConfig::new(
        ProjectId::generate().map_err(|_| CliError::Time)?,
        project_name,
        profile_name,
    );

    let config_path = context.cwd.join(LOCKET_TOML);
    if config_path.exists() {
        return Err(CliError::Config(
            "locket.toml already exists but could not be resolved".to_owned(),
        ));
    }

    write_project_config(&config_path, &config)?;
    let mut master_key_source = MasterKeySource::OsKeyStore;
    if let Err(error) = (|| -> Result<(), CliError> {
        ensure_project_metadata(&store, &config, timestamp)?;
        master_key_source = initialize_project_keys(context, &store, &config, timestamp)?;
        trust_root(&store, &config, &context.cwd, timestamp)?;
        ensure_gitignore(&context.cwd)?;
        ensure_example_file(&context.cwd)?;
        Ok(())
    })() {
        let _ignored = fs::remove_file(&config_path);
        return Err(error);
    }

    writeln!(output, "initialized locket project {}", config.project_id)?;
    writeln!(output, "default_profile: {}", config.default_profile)?;
    writeln!(output, "master_key_source: {}", master_key_source.as_str())?;
    Ok(())
}

fn set_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &SecretWriteArgs,
) -> Result<(), CliError> {
    let value = read_secret_value_from_stdin()?;
    set_secret_value(context, args, &value, "manual", now_unix_nanos()?)?;
    refresh_example_for_project_if_enabled(context)?;
    let source = source_arg_to_str(args.source.source.unwrap_or(SecretSourceArg::UserLocal));
    writeln!(output, "set {} ({source})", args.key)?;
    Ok(())
}

fn import_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &ImportArgs,
) -> Result<(), CliError> {
    let resolved = require_project(context)?;
    let mut store = open_store(context)?;
    let profile = import_target_profile(&store, &resolved, args.profile.as_deref())?;
    if args.overwrite && profile.dangerous {
        confirm_dangerous_import_overwrite(output, &profile)?;
    }
    let path = absolutize(&context.cwd, Path::new(&args.file));
    let env_file_text = fs::read_to_string(&path)?;
    let source = args.source.unwrap_or(SecretSourceArg::UserLocal);
    let source_name = source_arg_to_str(source);
    let parsed = parse_env_import(&env_file_text);
    let env_names = parsed
        .iter()
        .filter_map(|entry| match entry {
            EnvImportEntry::Secret { key, .. } => Some(key.clone()),
            EnvImportEntry::Invalid => None,
        })
        .collect::<BTreeSet<_>>();
    let mut imported = 0_u32;
    let mut overwritten = 0_u32;
    let mut skipped = 0_u32;
    let mut invalid = 0_u32;
    let mut skipped_names = BTreeSet::new();

    for entry in parsed {
        match entry {
            EnvImportEntry::Secret { key, value } => {
                match set_secret_value_in_profile(
                    context,
                    &mut store,
                    SecretWriteRequest {
                        resolved: &resolved,
                        profile: &profile,
                        key: &key,
                        source: source_name,
                        value: &value,
                        origin: "imported",
                        audit_action: "IMPORT",
                        timestamp: now_unix_nanos()?,
                    },
                ) {
                    Ok(()) => imported += 1,
                    Err(CliError::Config(message))
                        if message.contains("already exists") && args.overwrite =>
                    {
                        rotate_import_secret_value_in_profile(
                            context,
                            &mut store,
                            ImportRotateRequest {
                                resolved: &resolved,
                                profile: &profile,
                                key: &key,
                                source: source_name,
                                value: &value,
                                timestamp: now_unix_nanos()?,
                            },
                        )?;
                        overwritten += 1;
                    }
                    Err(CliError::Config(message)) if message.contains("already exists") => {
                        skipped += 1;
                        skipped_names.insert(key);
                    }
                    Err(error) => return Err(error),
                }
            }
            EnvImportEntry::Invalid => invalid += 1,
        }
    }

    refresh_example_for_project_if_enabled(context)?;
    ensure_gitignore(&resolved.root)?;
    let profile_names =
        active_profile_secret_names(&store, resolved.config.project_id.as_str(), &profile.id)?;
    let missing_in_profile = env_names.difference(&profile_names).cloned().collect::<BTreeSet<_>>();
    let extra_in_profile = profile_names.difference(&env_names).cloned().collect::<BTreeSet<_>>();
    writeln!(output, "imported: {imported}")?;
    writeln!(output, "overwritten: {overwritten}")?;
    writeln!(output, "skipped: {skipped}")?;
    writeln!(output, "invalid: {invalid}")?;
    writeln!(output, "profile: {}", profile.name)?;
    writeln!(output, "source: {source_name}")?;
    writeln!(output, "env_names: {}", env_names.len())?;
    writeln!(output, "profile_names: {}", profile_names.len())?;
    writeln!(output, "skipped_names: {}", format_name_set(&skipped_names))?;
    writeln!(output, "missing_in_profile: {}", format_name_set(&missing_in_profile))?;
    writeln!(output, "extra_in_profile: {}", format_name_set(&extra_in_profile))?;
    write_env_delete_prompt(output, &path)?;
    writeln!(output, "metadata_only: yes")?;
    Ok(())
}

fn import_target_profile(
    store: &Store,
    resolved: &ResolvedProject,
    profile_name: Option<&str>,
) -> Result<ProfileRecord, CliError> {
    let profile_name = profile_name.unwrap_or(resolved.config.default_profile.as_str());
    let profile_name = ProfileName::new(profile_name.to_owned())
        .map_err(|_| CliError::Config("invalid profile name".to_owned()))?;
    store
        .get_profile_by_name(resolved.config.project_id.as_str(), profile_name.as_str())?
        .ok_or_else(|| CliError::Config("profile not found".to_owned()))
}

fn confirm_dangerous_import_overwrite(
    output: &mut impl Write,
    profile: &ProfileRecord,
) -> Result<(), CliError> {
    writeln!(output, "dangerous_profile: {}", profile.name)?;
    writeln!(output, "metadata_only: yes")?;
    if !io::stdin().is_terminal() {
        return Err(CliError::Config(
            "import --overwrite targets a dangerous profile and requires interactive confirmation"
                .to_owned(),
        ));
    }
    writeln!(output, "type '{}' to confirm dangerous import overwrite", profile.name)?;
    let mut confirmation = String::new();
    io::stdin().read_line(&mut confirmation)?;
    if confirmation.trim_end() != profile.name {
        return Err(CliError::Config("confirmation did not match".to_owned()));
    }
    Ok(())
}

fn active_profile_secret_names(
    store: &Store,
    project_id: &str,
    profile_id: &str,
) -> Result<BTreeSet<String>, CliError> {
    Ok(store
        .list_active_secrets_by_profile(project_id, profile_id)?
        .into_iter()
        .map(|secret| secret.name)
        .collect())
}

fn format_name_set(names: &BTreeSet<String>) -> String {
    if names.is_empty() {
        "none".to_owned()
    } else {
        names.iter().cloned().collect::<Vec<_>>().join(",")
    }
}

fn write_env_delete_prompt(output: &mut impl Write, path: &Path) -> Result<(), CliError> {
    if path.file_name().and_then(OsStr::to_str) != Some(".env") {
        writeln!(output, "delete_env_prompt: not_applicable")?;
        return Ok(());
    }
    if !io::stdin().is_terminal() {
        writeln!(output, "delete_env_prompt: skipped_noninteractive")?;
        writeln!(output, "delete_env: kept")?;
        return Ok(());
    }
    writeln!(output, "delete_env_prompt: type 'delete .env' to remove the plaintext .env file")?;
    let mut confirmation = String::new();
    io::stdin().read_line(&mut confirmation)?;
    if confirmation.trim_end() == "delete .env" {
        fs::remove_file(path)?;
        writeln!(output, "delete_env: deleted")?;
    } else {
        writeln!(output, "delete_env: kept")?;
    }
    Ok(())
}

fn get_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &GetArgs,
) -> Result<(), CliError> {
    get_command_with_clipboard(context, output, args, copy_secret_to_clipboard)
}

fn get_command_with_clipboard(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &GetArgs,
    copy_to_clipboard: impl FnOnce(&str) -> Result<(), String>,
) -> Result<(), CliError> {
    let resolved_secret = resolve_active_secret(context, &args.key)?;
    if args.copy {
        let ttl_seconds = reveal_ttl_seconds(context)?;
        writeln!(output, "warning: clipboard TTL clearing is unsupported in this direct CLI path")?;
        let value = decrypt_current_secret(context, &resolved_secret)?;
        let result = copy_to_clipboard(value.as_str());
        let status = if result.is_ok() { "SUCCESS" } else { "FAILED" };
        let unsupported_reason = result.as_ref().err().map(String::as_str);
        write_value_access_audit_if_available(&ValueAccessAudit {
            context,
            resolved: &resolved_secret,
            action: "COPY",
            status,
            access_mode: "clipboard",
            ttl_seconds: Some(ttl_seconds),
            force: false,
            clipboard_supported: Some(result.is_ok()),
            clipboard_clear_supported: Some(false),
            unsupported_reason,
        })?;
        result.map_err(CliError::Config)?;
        writeln!(
            output,
            "copied {} source={} version={} ttl_seconds={} clipboard_clear_supported=no metadata_only=yes",
            resolved_secret.secret.name,
            resolved_secret.secret.source,
            resolved_secret.secret.current_version,
            ttl_seconds
        )?;
        return Ok(());
    }
    if args.reveal {
        if !args.force && !io::stdout().is_terminal() {
            return Err(CliError::Config(
                "get --reveal requires an interactive terminal; pass --force for noninteractive stdout"
                    .to_owned(),
            ));
        }
        let value = decrypt_current_secret(context, &resolved_secret)?;
        write_value_access_audit_if_available(&ValueAccessAudit {
            context,
            resolved: &resolved_secret,
            action: "REVEAL",
            status: "SUCCESS",
            access_mode: "stdout",
            ttl_seconds: None,
            force: args.force,
            clipboard_supported: None,
            clipboard_clear_supported: None,
            unsupported_reason: None,
        })?;
        writeln!(output, "{}", value.as_str())?;
        return Ok(());
    }

    writeln!(
        output,
        "{} source={} version={}",
        resolved_secret.secret.name,
        resolved_secret.secret.source,
        resolved_secret.secret.current_version
    )?;
    Ok(())
}

fn rm_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &SourceKeyArgs,
) -> Result<(), CliError> {
    let source = source_arg_to_str(args.source.source.unwrap_or(SecretSourceArg::UserLocal));
    let resolved = require_project(context)?;
    let store = open_store(context)?;
    let profile = default_profile(&store, &resolved.config)?;
    let Some(secret) = store.get_active_secret(
        resolved.config.project_id.as_str(),
        &profile.id,
        &args.key,
        source,
    )?
    else {
        return Err(CliError::Config("secret not found".to_owned()));
    };
    let timestamp = now_unix_nanos()?;
    let audit_key =
        load_project_key(context, &store, resolved.config.project_id.as_str(), KeyPurpose::Audit)?;
    let metadata = secret_audit_metadata(
        "DELETE",
        &secret.name,
        &profile.id,
        source,
        Some(secret.current_version),
    );
    let audit = AuditWrite {
        project_id: resolved.config.project_id.as_str(),
        profile_id: Some(&profile.id),
        action: "DELETE",
        status: "SUCCESS",
        secret_name: Some(&secret.name),
        command: None,
        metadata_json: &metadata,
        timestamp,
    };
    store.tombstone_secret_with_audit(
        &secret.id,
        timestamp,
        Some(AuditContext { key: audit_key.as_ref(), write: &audit }),
    )?;
    refresh_example_for_project_if_enabled(context)?;
    writeln!(output, "removed {} ({source})", args.key)?;
    Ok(())
}

fn rotate_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &RotateArgs,
) -> Result<(), CliError> {
    let timestamp = now_unix_nanos()?;
    let grace_until = grace_until_from_args(args.grace_ttl.as_deref(), timestamp)?;
    let value = read_secret_value_from_stdin()?;
    let (source, version) = rotate_secret_value(context, args, &value, timestamp, grace_until)?;
    refresh_example_for_project_if_enabled(context)?;
    writeln!(output, "rotated {} ({source}) version={version}", args.key)?;
    Ok(())
}

fn copy_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &CopyArgs,
) -> Result<(), CliError> {
    let result = copy_secret_value(context, args, now_unix_nanos()?)?;
    refresh_example_for_project_if_enabled(context)?;
    writeln!(
        output,
        "copied {} from={} source={} to={} target_source={} version={} operation={} metadata_only=yes",
        args.key,
        result.from_profile,
        result.from_source,
        result.to_profile,
        result.to_source,
        result.target_version,
        result.operation,
    )?;
    Ok(())
}

fn purge_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &PurgeArgs,
) -> Result<(), CliError> {
    if args.version.is_none() && !args.all_versions {
        return Err(CliError::Config("purge requires --version N or --all-versions".to_owned()));
    }

    let secret = resolve_secret_for_source(context, &args.key, args.source.source)?;
    let mut store = open_store(context)?;
    let versions = store.list_secret_versions(&secret.secret.id)?;
    if versions.is_empty() {
        writeln!(output, "purge: no versions")?;
        return Ok(());
    }

    let target_versions = if args.all_versions {
        if secret.secret.state != "deleted" {
            return Err(CliError::Config(
                "purge --all-versions requires a deleted source; run rm first".to_owned(),
            ));
        }
        versions.iter().map(|version| version.version).collect::<Vec<_>>()
    } else {
        let Some(version) = args.version else {
            return Err(CliError::Config("purge requires --version N".to_owned()));
        };
        let Some(record) = versions.iter().find(|record| record.version == version) else {
            return Err(CliError::Config("secret version not found".to_owned()));
        };
        if secret.secret.state == "active"
            && version == secret.secret.current_version
            && record.state == "current"
        {
            return Err(CliError::Config(
                "cannot purge the current version of an active source".to_owned(),
            ));
        }
        vec![version]
    };

    let timestamp = now_unix_nanos()?;
    let audit_key = load_project_key(
        context,
        &store,
        secret.project.config.project_id.as_str(),
        KeyPurpose::Audit,
    )?;
    let metadata = json!({
        "schema_version": 1,
        "action": "PURGE",
        "status": "SUCCESS",
        "secret_name": &secret.secret.name,
        "profile_id": &secret.profile.id,
        "source": &secret.secret.source,
        "versions": &target_versions,
    });
    let audit = AuditWrite {
        project_id: secret.project.config.project_id.as_str(),
        profile_id: Some(&secret.profile.id),
        action: "PURGE",
        status: "SUCCESS",
        secret_name: Some(&secret.secret.name),
        command: None,
        metadata_json: &metadata,
        timestamp,
    };
    let changed = store.purge_secret_versions_with_audit(
        &secret.secret.id,
        &target_versions,
        timestamp,
        Some(AuditContext { key: audit_key.as_ref(), write: &audit }),
    )?;
    refresh_example_for_project_if_enabled(context)?;
    if changed {
        writeln!(
            output,
            "purged {} ({}) versions={}",
            secret.secret.name,
            secret.secret.source,
            format_versions(&target_versions)
        )?;
    } else {
        writeln!(
            output,
            "purge: {} ({}) already purged",
            secret.secret.name, secret.secret.source
        )?;
    }
    Ok(())
}

fn history_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &HistoryArgs,
) -> Result<(), CliError> {
    let name = SecretName::new(args.key.clone())
        .map_err(|_| CliError::Config("invalid secret name".to_owned()))?;
    let resolved = require_project(context)?;
    let store = open_store(context)?;
    let profile = if let Some(profile_name) = &args.profile {
        store
            .get_profile_by_name(resolved.config.project_id.as_str(), profile_name)?
            .ok_or_else(|| CliError::Config("profile not found".to_owned()))?
    } else {
        default_profile(&store, &resolved.config)?
    };
    let secrets = store.list_secrets_by_name(
        resolved.config.project_id.as_str(),
        &profile.id,
        name.as_str(),
    )?;
    if secrets.is_empty() {
        return Err(CliError::Config("secret not found".to_owned()));
    }

    let mut displayed = 0_u32;
    for secret in secrets {
        writeln!(
            output,
            "{} source={} state={} current_version={}",
            secret.name, secret.source, secret.state, secret.current_version
        )?;
        for version in store.list_secret_versions(&secret.id)? {
            displayed += 1;
            writeln!(
                output,
                "  v{} state={} created_at={} deprecated_at={} grace_until={} purged_at={}",
                version.version,
                version.state,
                version.created_at,
                optional_i64(version.deprecated_at),
                optional_i64(version.grace_until),
                optional_i64(version.purged_at)
            )?;
        }
    }
    if displayed == 0 {
        writeln!(output, "history: no versions")?;
    }
    Ok(())
}

fn list_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &ListArgs,
) -> Result<(), CliError> {
    let resolved = require_project(context)?;
    let store = open_store(context)?;
    let profile = default_profile(&store, &resolved.config)?;
    let secrets = if args.all {
        store.list_secrets_by_profile(resolved.config.project_id.as_str(), &profile.id)?
    } else {
        store.list_active_secrets_by_profile(resolved.config.project_id.as_str(), &profile.id)?
    };
    if secrets.is_empty() {
        writeln!(output, "no secrets")?;
        return Ok(());
    }
    for secret in secrets {
        writeln!(
            output,
            "{} source={} version={} state={}",
            secret.name, secret.source, secret.current_version, secret.state
        )?;
    }
    Ok(())
}

fn exec_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &ExecArgs,
) -> Result<(), CliError> {
    if args.all {
        return Err(CliError::Config(
            "exec --all confirmation is not wired in this build yet".to_owned(),
        ));
    }
    if args.secrets.is_empty() {
        return Err(CliError::Config(
            "exec requires at least one --secret in this build".to_owned(),
        ));
    }

    let mut locket_env = locket_exec::EnvMap::new();
    for key in &args.secrets {
        let resolved = resolve_active_secret(context, key)?;
        let value = decrypt_current_secret(context, &resolved)?;
        locket_env.insert(resolved.secret.name, value.as_str().to_owned());
    }

    let request = locket_exec::ExecutionRequest {
        argv: args.command.clone(),
        parent_env: std::env::vars().collect(),
        inherit_env: vec!["PATH".to_owned()],
        external_env: locket_exec::EnvMap::new(),
        locket_env,
        env_mode: locket_exec::EnvMode::Strict,
        override_mode: locket_exec::EnvOverrideMode::Locket,
    };
    let prepared = locket_exec::prepare_execution(&request)
        .map_err(|error| CliError::Config(error.to_string()))?;
    let status = prepared.command().status()?;
    if status.success() {
        return Ok(());
    }

    writeln!(output, "child exited with status {status}")?;
    Err(CliError::Config("child process failed".to_owned()))
}

fn run_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    run_args: &RunArgs,
) -> Result<(), CliError> {
    let resolved = require_project(context)?;
    let policy = load_command_policy(&resolved, &run_args.policy)?;

    if matches!(policy.command, CommandSpec::Shell(_)) {
        writeln!(output, "policy {}: shell execution is not implemented", policy.name)?;
        return Err(CliError::Config(
            "shell policy execution is not wired in this build".to_owned(),
        ));
    }
    if policy.confirm {
        return Err(CliError::Config("policy confirmation is not wired in this build".to_owned()));
    }
    if policy.require_user_verification {
        return Err(CliError::Config(
            "policy user verification is not wired in this build".to_owned(),
        ));
    }
    if !policy.external_env_sources.is_empty() {
        return Err(CliError::Config(
            "policy external environment sources are not wired in this build".to_owned(),
        ));
    }

    let store = open_store(context)?;
    let profile = default_profile(&store, &resolved.config)?;
    let selections = policy_secret_selections(&store, &resolved, &profile, &policy)?;
    let missing_required = selections
        .iter()
        .filter(|selection| selection.required && selection.selected.is_none())
        .map(|selection| selection.name.as_str())
        .collect::<Vec<_>>();
    if !missing_required.is_empty() {
        return Err(CliError::Config(format!(
            "required secret(s) missing: {}",
            missing_required.join(",")
        )));
    }

    let mut locket_env = locket_exec::EnvMap::new();
    for selection in &selections {
        if let Some(secret) = &selection.selected {
            let value = decrypt_secret_version(
                context,
                &store,
                resolved.config.project_id.as_str(),
                &profile.id,
                secret,
                secret.current_version,
            )?;
            locket_env.insert(secret.name.clone(), value.as_str().to_owned());
        }
    }

    let command_argv = match &policy.command {
        CommandSpec::Argv(arguments) => arguments.clone(),
        CommandSpec::Shell(_) => unreachable!("shell policies are rejected before decryption"),
    };
    let request = locket_exec::ExecutionRequest {
        argv: command_argv,
        parent_env: std::env::vars().collect(),
        inherit_env: policy.inherit_env.clone(),
        external_env: locket_exec::EnvMap::new(),
        locket_env,
        env_mode: policy.env_mode,
        override_mode: policy.override_behavior,
    };
    let prepared = locket_exec::prepare_execution(&request)
        .map_err(|error| CliError::Config(error.to_string()))?;
    let status = prepared.command().current_dir(&context.cwd).status()?;
    let audit_status = if status.success() { "SUCCESS" } else { "FAILED" };
    write_runtime_policy_audit_if_available(
        context,
        &resolved,
        &profile,
        &policy,
        audit_status,
        &selections,
    )?;
    if status.success() {
        return Ok(());
    }

    writeln!(output, "child exited with status {status}")?;
    Err(CliError::ChildExit(status.code().and_then(|code| u8::try_from(code).ok()).unwrap_or(1)))
}

fn env_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    command: EnvCommand,
) -> Result<(), CliError> {
    match command {
        EnvCommand::Inspect(args) => env_inspect_command(context, output, &args),
        EnvCommand::Docker(args) => docker_policy_command(context, output, &args),
    }
}

fn compose_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    command: ComposeCommand,
) -> Result<(), CliError> {
    match command {
        ComposeCommand::Run(args) => compose_policy_command(context, output, &args),
    }
}

fn env_inspect_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &EnvInspectArgs,
) -> Result<(), CliError> {
    let resolved = require_project(context)?;
    let policy = load_command_policy(&resolved, &args.policy)?;
    let store = open_store(context)?;
    let profile = default_profile(&store, &resolved.config)?;
    let selections = policy_secret_selections(&store, &resolved, &profile, &policy)?;
    let parent_env = std::env::vars().collect::<locket_exec::EnvMap>();

    writeln!(output, "policy {}", policy.name)?;
    writeln!(output, "command_type={}", command_type(&policy.command))?;
    writeln!(output, "env_mode={}", policy.env_mode)?;
    writeln!(output, "override={}", policy.override_behavior)?;
    for source in &policy.external_env_sources {
        writeln!(
            output,
            "external_source {} decision=not-implemented",
            external_env_source_label(source)
        )?;
    }

    for selection in &selections {
        let sources = if selection.sources.is_empty() {
            "none".to_owned()
        } else {
            selection.sources.join(",")
        };
        let selected = selection.selected.as_ref().map_or("none", |secret| secret.source.as_str());
        let conflicts = inspect_conflicts(selection, &parent_env, &policy);
        let decision = inspect_decision(selection, &parent_env, &policy);
        writeln!(
            output,
            "secret {} kind={} sources={} selected={} conflicts={} decision={}",
            selection.name,
            if selection.required { "required" } else { "optional" },
            sources,
            selected,
            conflicts,
            decision
        )?;
    }
    Ok(())
}

fn docker_policy_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &EnvDockerArgs,
) -> Result<(), CliError> {
    let parent_env = std::env::vars().collect::<locket_exec::EnvMap>();
    let prepared =
        prepare_docker_policy_execution(context, &args.policy, &args.command, parent_env)?;
    let status = prepared.execution.command().current_dir(&context.cwd).status()?;
    let audit_status = if status.success() { "SUCCESS" } else { "FAILED" };
    write_docker_policy_audit_if_available(context, &prepared, audit_status)?;
    if status.success() {
        return Ok(());
    }

    writeln!(output, "child exited with status {status}")?;
    Err(CliError::ChildExit(status.code().and_then(|code| u8::try_from(code).ok()).unwrap_or(1)))
}

fn compose_policy_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &ComposeRunArgs,
) -> Result<(), CliError> {
    let parent_env = std::env::vars().collect::<locket_exec::EnvMap>();
    let compose_args = compose_argv_with_options(
        args.command.clone(),
        args.project_directory.as_deref(),
        &args.profile,
    )?;
    let prepared =
        prepare_compose_policy_execution(context, &args.policy, &compose_args, parent_env)?;
    let status = prepared.execution.command().current_dir(&context.cwd).status()?;
    let audit_status = if status.success() { "SUCCESS" } else { "FAILED" };
    write_docker_policy_audit_if_available(context, &prepared, audit_status)?;
    if status.success() {
        return Ok(());
    }

    writeln!(output, "child exited with status {status}")?;
    Err(CliError::ChildExit(status.code().and_then(|code| u8::try_from(code).ok()).unwrap_or(1)))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DockerHelperKind {
    DockerRun,
    Compose,
}

#[derive(Debug)]
struct PreparedDockerPolicyExecution {
    resolved: ResolvedProject,
    profile: ProfileRecord,
    policy: CommandPolicy,
    execution: locket_exec::PreparedExecution,
    plan: locket_docker::DockerInjectionPlan,
    helper_kind: DockerHelperKind,
}

fn prepare_docker_policy_execution(
    context: &RuntimeContext,
    policy_name: &str,
    argv: &[String],
    parent_env: locket_exec::EnvMap,
) -> Result<PreparedDockerPolicyExecution, CliError> {
    prepare_docker_helper_policy_execution(
        context,
        policy_name,
        argv,
        parent_env,
        DockerHelperKind::DockerRun,
    )
}

fn prepare_compose_policy_execution(
    context: &RuntimeContext,
    policy_name: &str,
    argv: &[String],
    parent_env: locket_exec::EnvMap,
) -> Result<PreparedDockerPolicyExecution, CliError> {
    prepare_docker_helper_policy_execution(
        context,
        policy_name,
        argv,
        parent_env,
        DockerHelperKind::Compose,
    )
}

fn prepare_docker_helper_policy_execution(
    context: &RuntimeContext,
    policy_name: &str,
    argv: &[String],
    parent_env: locket_exec::EnvMap,
    helper_kind: DockerHelperKind,
) -> Result<PreparedDockerPolicyExecution, CliError> {
    let resolved = require_project(context)?;
    let policy = load_command_policy(&resolved, policy_name)?;
    ensure_runtime_policy_supported(&policy)?;
    let (profile, selections, locket_env) = resolve_policy_locket_env(context, &resolved, &policy)?;
    let endpoint = parent_env.get("DOCKER_HOST").map(String::as_str);
    let plan = match helper_kind {
        DockerHelperKind::DockerRun => locket_docker::prepare_docker_run(
            argv,
            &locket_exec::EnvMap::new(),
            &locket_env,
            endpoint,
            policy.allow_remote_docker,
        ),
        DockerHelperKind::Compose => locket_docker::prepare_compose(
            argv,
            &locket_exec::EnvMap::new(),
            &locket_env,
            endpoint,
            policy.allow_remote_docker,
        ),
    }
    .map_err(docker_error)?;
    let request = locket_exec::ExecutionRequest {
        argv: plan.argv.clone(),
        parent_env,
        inherit_env: policy.inherit_env.clone(),
        external_env: locket_exec::EnvMap::new(),
        locket_env,
        env_mode: policy.env_mode,
        override_mode: policy.override_behavior,
    };
    let execution = locket_exec::prepare_execution(&request)
        .map_err(|error| CliError::Config(error.to_string()))?;
    debug_assert_eq!(
        plan.injected_names.len(),
        selections.iter().filter(|s| s.selected.is_some()).count()
    );

    Ok(PreparedDockerPolicyExecution { resolved, profile, policy, execution, plan, helper_kind })
}

fn ensure_runtime_policy_supported(policy: &CommandPolicy) -> Result<(), CliError> {
    if matches!(policy.command, CommandSpec::Shell(_)) {
        return Err(CliError::Config(
            "shell policy execution is not wired in this build".to_owned(),
        ));
    }
    if policy.confirm {
        return Err(CliError::Config("policy confirmation is not wired in this build".to_owned()));
    }
    if policy.require_user_verification {
        return Err(CliError::Config(
            "policy user verification is not wired in this build".to_owned(),
        ));
    }
    if !policy.external_env_sources.is_empty() {
        return Err(CliError::Config(
            "policy external environment sources are not wired in this build".to_owned(),
        ));
    }
    Ok(())
}

fn resolve_policy_locket_env(
    context: &RuntimeContext,
    resolved: &ResolvedProject,
    policy: &CommandPolicy,
) -> Result<(ProfileRecord, Vec<PolicySecretSelection>, locket_exec::EnvMap), CliError> {
    let store = open_store(context)?;
    let profile = default_profile(&store, &resolved.config)?;
    let selections = policy_secret_selections(&store, resolved, &profile, policy)?;
    let missing_required = selections
        .iter()
        .filter(|selection| selection.required && selection.selected.is_none())
        .map(|selection| selection.name.as_str())
        .collect::<Vec<_>>();
    if !missing_required.is_empty() {
        return Err(CliError::Config(format!(
            "required secret(s) missing: {}",
            missing_required.join(",")
        )));
    }

    let mut locket_env = locket_exec::EnvMap::new();
    for selection in &selections {
        if let Some(secret) = &selection.selected {
            let value = decrypt_secret_version(
                context,
                &store,
                resolved.config.project_id.as_str(),
                &profile.id,
                secret,
                secret.current_version,
            )?;
            locket_env.insert(secret.name.clone(), value.as_str().to_owned());
        }
    }
    Ok((profile, selections, locket_env))
}

fn compose_argv_with_options(
    argv: Vec<String>,
    project_directory: Option<&Path>,
    profiles: &[String],
) -> Result<Vec<String>, CliError> {
    if argv.len() < 2
        || argv.first().map(String::as_str) != Some("docker")
        || argv.get(1).map(String::as_str) != Some("compose")
    {
        return Ok(argv);
    }
    let mut prepared = Vec::with_capacity(argv.len() + 2 + profiles.len() * 2);
    prepared.push(argv[0].clone());
    prepared.push(argv[1].clone());
    if let Some(project_directory) = project_directory {
        prepared.push("--project-directory".to_owned());
        prepared.push(project_directory.to_string_lossy().into_owned());
    }
    for profile in profiles {
        if profile.is_empty() {
            return Err(CliError::Config("compose profile must not be empty".to_owned()));
        }
        prepared.push("--profile".to_owned());
        prepared.push(profile.clone());
    }
    prepared.extend(argv.into_iter().skip(2));
    Ok(prepared)
}

fn docker_error(error: locket_docker::DockerError) -> CliError {
    match error {
        locket_docker::DockerError::RemoteContextDenied => CliError::Config(
            "remote Docker context is denied by default; policy allow_remote_docker support is default-deny unless explicitly enabled"
                .to_owned(),
        ),
        other => CliError::Config(other.to_string()),
    }
}

fn audit_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    command: AuditCommand,
) -> Result<(), CliError> {
    match command {
        AuditCommand::Verify => {
            let resolved = require_project(context)?;
            let mut store = open_store(context)?;
            let audit_key = load_project_key(
                context,
                &store,
                resolved.config.project_id.as_str(),
                KeyPurpose::Audit,
            )?;
            let rows = store.verify_audit_chain_and_append(
                resolved.config.project_id.as_str(),
                audit_key.as_ref(),
                now_unix_nanos()?,
            )?;
            writeln!(output, "audit: verified {rows} row(s)")?;
            Ok(())
        }
    }
}

fn debug_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    command: DebugCommand,
) -> Result<(), CliError> {
    match command {
        DebugCommand::Bundle(args) => diagnostics::debug_bundle_command(
            context,
            output,
            args.redacted,
            args.output.as_deref(),
        ),
    }
}

fn config_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    command: ConfigCommand,
) -> Result<(), CliError> {
    match command {
        ConfigCommand::List => config_list_command(context, output),
        ConfigCommand::Get(args) => config_get_command(context, output, &args.key),
        ConfigCommand::Set(args) => config_set_command(context, output, &args.key, &args.value),
        ConfigCommand::Unset(args) => config_unset_command(context, output, &args.key),
    }
}

fn config_list_command(context: &RuntimeContext, output: &mut impl Write) -> Result<(), CliError> {
    let config = read_user_config(context)?;
    let mut listed = 0_u32;
    for spec in CONFIG_KEY_SPECS {
        if let Some(value) = config_get_value(&config, spec.key) {
            validate_stored_config_value(spec, value)?;
            writeln!(output, "{}={}", spec.key, format_config_value(value))?;
            listed += 1;
        }
    }
    if listed == 0 {
        writeln!(output, "no config values")?;
    }
    Ok(())
}

fn config_get_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    key: &str,
) -> Result<(), CliError> {
    let spec = validate_config_key(key)?;
    let config = read_user_config(context)?;
    let value = config_get_value(&config, key)
        .ok_or_else(|| CliError::Config("config key is not set".to_owned()))?;
    validate_stored_config_value(spec, value)?;
    writeln!(output, "{}", format_config_value(value))?;
    Ok(())
}

fn config_set_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    key: &str,
    value: &str,
) -> Result<(), CliError> {
    let spec = validate_config_key(key)?;
    validate_config_value_not_secret_like(value)?;
    let parsed = parse_config_value(spec, value)?;
    let mut config = read_user_config(context)?;
    config_set_value(&mut config, key, parsed)?;
    write_user_config(context, &config)?;
    if spec.audit {
        write_config_update_audit_if_available(context, key, "set")?;
    }
    writeln!(output, "set {key}")?;
    Ok(())
}

fn config_unset_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    key: &str,
) -> Result<(), CliError> {
    let spec = validate_config_key(key)?;
    let mut config = read_user_config(context)?;
    config_unset_value(&mut config, key)?;
    write_user_config(context, &config)?;
    if spec.audit {
        write_config_update_audit_if_available(context, key, "unset")?;
    }
    writeln!(output, "unset {key}")?;
    Ok(())
}

fn passkey_command(output: &mut impl Write, command: PasskeyCommand) -> Result<(), CliError> {
    match command {
        PasskeyCommand::Register => Err(CliError::Config(
            "passkey registration is not available in this build; no credential metadata was written"
                .to_owned(),
        )),
        PasskeyCommand::List(args) => {
            writeln!(output, "passkey: platform unavailable in this build")?;
            writeln!(output, "credentials: none")?;
            writeln!(output, "include_revoked: {}", if args.all { "yes" } else { "no" })?;
            writeln!(output, "private_key_material: never displayed")?;
            Ok(())
        }
        PasskeyCommand::Remove { passkey } => {
            if passkey.trim().is_empty() {
                return Err(CliError::Config("passkey identifier cannot be empty".to_owned()));
            }
            Err(CliError::Config(
                "passkey removal is not available in this build; no credential metadata was changed"
                    .to_owned(),
            ))
        }
    }
}

fn profile_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    command: ProfileCommand,
) -> Result<(), CliError> {
    match command {
        ProfileCommand::List => list_profiles(context, output),
        ProfileCommand::Create(args) => create_profile(context, output, args),
        ProfileCommand::MarkDangerous(args) => set_profile_dangerous(context, output, args, true),
        ProfileCommand::ClearDangerous(args) => set_profile_dangerous(context, output, args, false),
    }
}

fn project_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    command: ProjectCommand,
) -> Result<(), CliError> {
    match command {
        ProjectCommand::TrustRoot => trust_root_command(context, output),
        ProjectCommand::ListRoots => list_roots_command(context, output),
        ProjectCommand::UntrustRoot { root_hash } => {
            untrust_root_command(context, output, &root_hash)
        }
    }
}

fn trust_root_command(context: &RuntimeContext, output: &mut impl Write) -> Result<(), CliError> {
    let resolved = require_project(context)?;
    let store = open_store(context)?;
    ensure_project_exists(&store, resolved.config.project_id.as_str())?;

    let hash = root_hash(&resolved.root)?;
    let was_trusted = store.project_root_is_trusted(resolved.config.project_id.as_str(), &hash)?;
    let timestamp = now_unix_nanos()?;
    let display_path = resolved.root.to_string_lossy();
    store.trust_project_root(
        resolved.config.project_id.as_str(),
        &hash,
        Some(display_path.as_ref()),
        timestamp,
    )?;

    writeln!(
        output,
        "{}",
        if was_trusted { "trusted root already present" } else { "trusted root added" }
    )?;
    writeln!(output, "project_id: {}", resolved.config.project_id)?;
    writeln!(output, "root_hash: {}", format_hex(&hash))?;
    writeln!(output, "display_path: {}", resolved.root.display())?;
    writeln!(output, "last_seen_at: {timestamp}")?;
    Ok(())
}

fn list_roots_command(context: &RuntimeContext, output: &mut impl Write) -> Result<(), CliError> {
    let resolved = require_project(context)?;
    let store = open_store(context)?;
    ensure_project_exists(&store, resolved.config.project_id.as_str())?;

    let roots = store.list_project_roots(resolved.config.project_id.as_str())?;
    if roots.is_empty() {
        writeln!(output, "no trusted roots")?;
        return Ok(());
    }

    for root in roots {
        writeln!(output, "root_hash: {}", format_hex(&root.root_hash))?;
        writeln!(output, "display_path: {}", root.display_path.as_deref().unwrap_or("-"))?;
        writeln!(output, "created_at: {}", root.created_at)?;
        writeln!(output, "last_seen_at: {}", optional_i64(root.last_seen_at))?;
    }
    Ok(())
}

fn untrust_root_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    root_hash: &str,
) -> Result<(), CliError> {
    let resolved = require_project(context)?;
    let store = open_store(context)?;
    ensure_project_exists(&store, resolved.config.project_id.as_str())?;

    let hash = parse_root_hash(root_hash)?;
    let removed = store.untrust_project_root(resolved.config.project_id.as_str(), &hash)?;
    writeln!(
        output,
        "{}",
        if removed { "trusted root removed" } else { "trusted root not found" }
    )?;
    writeln!(output, "project_id: {}", resolved.config.project_id)?;
    writeln!(output, "root_hash: {}", format_hex(&hash))?;
    Ok(())
}

fn shellenv_command(output: &mut impl Write, args: &ShellenvArgs) -> Result<(), CliError> {
    let shell = args.shell.unwrap_or_else(detect_shell);
    write_shellenv_snippet(output, shell)
}

fn hook_command(output: &mut impl Write, args: &HookArgs) -> Result<(), CliError> {
    let shell = args.shell.unwrap_or_else(detect_shell);
    if args.install {
        writeln!(output, "hook install: no-op")?;
        writeln!(output, "agent: unavailable")?;
        writeln!(
            output,
            "reason: full agent-backed shell grant installation is not available in this build"
        )?;
        writeln!(output, "metadata_only: yes")?;
        return Ok(());
    }

    write_shell_hook_snippet(output, shell)
}

fn allow_command(context: &RuntimeContext, output: &mut impl Write) -> Result<(), CliError> {
    let resolved = require_project(context)?;
    let store = open_store(context)?;
    ensure_project_exists(&store, resolved.config.project_id.as_str())?;
    let profile = default_profile(&store, &resolved.config)?;
    let root_hash = root_hash(&resolved.root)?;
    if !store.project_root_is_trusted(resolved.config.project_id.as_str(), &root_hash)? {
        return Err(CliError::Config(
            "ProjectRootNotTrusted: current project root is not trusted; run locket project trust-root"
                .to_owned(),
        ));
    }

    let timestamp = now_unix_nanos()?;
    let directory_hash = root_hash;
    let display_path = resolved.root.to_string_lossy().to_string();
    let grant = DirectoryGrantRecord {
        grant_id: directory_grant_id(
            resolved.config.project_id.as_str(),
            &profile.id,
            &root_hash,
            &directory_hash,
            DIRECTORY_GRANT_SCOPE_PROJECT_ROOT,
        ),
        project_id: resolved.config.project_id.as_str().to_owned(),
        profile_id: profile.id.clone(),
        root_hash,
        directory_hash,
        grant_scope: DIRECTORY_GRANT_SCOPE_PROJECT_ROOT.to_owned(),
        display_path: Some(display_path),
        created_at: timestamp,
        updated_at: timestamp,
    };

    let existed = store
        .get_directory_grant(
            resolved.config.project_id.as_str(),
            &profile.id,
            &root_hash,
            &directory_hash,
            DIRECTORY_GRANT_SCOPE_PROJECT_ROOT,
        )?
        .is_some();
    store.allow_directory_grant(&grant)?;

    writeln!(
        output,
        "{}",
        if existed { "directory grant already present" } else { "directory grant allowed" }
    )?;
    writeln!(output, "project_id: {}", resolved.config.project_id)?;
    writeln!(output, "profile_id: {}", profile.id)?;
    writeln!(output, "grant_scope: {}", grant.grant_scope)?;
    writeln!(output, "root_hash: {}", format_hex(&root_hash))?;
    writeln!(output, "directory_hash: {}", format_hex(&directory_hash))?;
    writeln!(output, "metadata_only: yes")?;
    writeln!(output, "live_grant: unavailable")?;
    Ok(())
}

fn deny_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &DenyArgs,
) -> Result<(), CliError> {
    let resolved = require_project(context)?;
    let store = open_store(context)?;
    ensure_project_exists(&store, resolved.config.project_id.as_str())?;

    if args.all {
        let removed = store.deny_all_directory_grants(resolved.config.project_id.as_str())?;
        writeln!(output, "directory grants revoked: {removed}")?;
        writeln!(output, "project_id: {}", resolved.config.project_id)?;
        writeln!(output, "metadata_only: yes")?;
        writeln!(output, "live_grants: unavailable")?;
        return Ok(());
    }

    let profile = default_profile(&store, &resolved.config)?;
    let root_hash = root_hash(&resolved.root)?;
    let directory_hash = root_hash;
    let removed = store.deny_directory_grant(
        resolved.config.project_id.as_str(),
        &profile.id,
        &root_hash,
        &directory_hash,
        DIRECTORY_GRANT_SCOPE_PROJECT_ROOT,
    )?;

    writeln!(
        output,
        "{}",
        if removed { "directory grant revoked" } else { "directory grant not found" }
    )?;
    writeln!(output, "project_id: {}", resolved.config.project_id)?;
    writeln!(output, "profile_id: {}", profile.id)?;
    writeln!(output, "grant_scope: {DIRECTORY_GRANT_SCOPE_PROJECT_ROOT}")?;
    writeln!(output, "root_hash: {}", format_hex(&root_hash))?;
    writeln!(output, "metadata_only: yes")?;
    writeln!(output, "live_grant: unavailable")?;
    Ok(())
}

fn list_profiles(context: &RuntimeContext, output: &mut impl Write) -> Result<(), CliError> {
    let resolved = require_project(context)?;
    let store = open_store(context)?;
    let profiles = store.list_profiles(resolved.config.project_id.as_str())?;

    if profiles.is_empty() {
        writeln!(output, "no profiles")?;
        return Ok(());
    }

    for profile in profiles {
        let marker =
            if profile.name == resolved.config.default_profile.as_str() { "*" } else { " " };
        let dangerous = if profile.dangerous { " dangerous" } else { "" };
        writeln!(output, "{marker} {} ({}){dangerous}", profile.name, profile.id)?;
    }

    Ok(())
}

fn create_profile(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: ProfileNameArgs,
) -> Result<(), CliError> {
    let resolved = require_project(context)?;
    let profile_name = ProfileName::new(args.profile)
        .map_err(|_| CliError::Config("invalid profile name".to_owned()))?;
    let store = open_store(context)?;

    if store
        .get_profile_by_name(resolved.config.project_id.as_str(), profile_name.as_str())?
        .is_some()
    {
        return Err(CliError::Config("profile already exists".to_owned()));
    }

    let profile_id = ProfileId::generate().map_err(|_| CliError::Time)?;
    let inserted = store.insert_profile_if_absent(
        profile_id.as_str(),
        resolved.config.project_id.as_str(),
        profile_name.as_str(),
        false,
        now_unix_nanos()?,
    )?;
    if !inserted {
        return Err(CliError::Config("profile already exists".to_owned()));
    }
    initialize_profile_keys(
        context,
        &store,
        &resolved.config,
        profile_id.as_str(),
        now_unix_nanos()?,
    )?;

    writeln!(output, "created profile {profile_name} ({profile_id})")?;
    Ok(())
}

fn set_profile_dangerous(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: ProfileNameArgs,
    dangerous: bool,
) -> Result<(), CliError> {
    let resolved = require_project(context)?;
    let profile_name = ProfileName::new(args.profile)
        .map_err(|_| CliError::Config("invalid profile name".to_owned()))?;
    let store = open_store(context)?;
    let Some(profile) =
        store.get_profile_by_name(resolved.config.project_id.as_str(), profile_name.as_str())?
    else {
        return Err(CliError::Config("profile not found".to_owned()));
    };

    store.set_profile_dangerous(
        resolved.config.project_id.as_str(),
        profile_name.as_str(),
        dangerous,
    )?;
    let state = if dangerous { "dangerous" } else { "not-dangerous" };
    writeln!(output, "profile {} ({}) dangerous={state}", profile.name, profile.id)?;
    Ok(())
}

fn use_profile_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: ProfileNameArgs,
) -> Result<(), CliError> {
    let profile_name = ProfileName::new(args.profile)
        .map_err(|_| CliError::Config("invalid profile name".to_owned()))?;
    let mut resolved = require_project(context)?;
    let store = open_store(context)?;
    let profile = store
        .get_profile_by_name(resolved.config.project_id.as_str(), profile_name.as_str())?
        .ok_or_else(|| CliError::Config("profile not found".to_owned()))?;
    resolved.config.default_profile = profile_name;
    write_project_config(&resolved.root.join(LOCKET_TOML), &resolved.config)?;
    writeln!(output, "active profile: {} ({})", profile.name, profile.id)?;
    Ok(())
}

fn meta_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &SecretMetaArgs,
) -> Result<(), CliError> {
    if !metadata_flags_have_updates(&args.metadata) {
        return Err(CliError::Config("meta requires at least one metadata flag".to_owned()));
    }

    let resolved_secret = resolve_active_secret_for_source(context, &args.key, args.source.source)?;
    let store = open_store(context)?;
    let required = metadata_required_update(&args.metadata);
    let tags =
        if args.metadata.tags.is_empty() { None } else { Some(args.metadata.tags.as_slice()) };
    let timestamp = now_unix_nanos()?;
    let audit_key = load_project_key(
        context,
        &store,
        resolved_secret.project.config.project_id.as_str(),
        KeyPurpose::Audit,
    )?;
    let metadata = json!({
        "schema_version": 1,
        "action": "SECRET_META_UPDATE",
        "status": "SUCCESS",
        "secret_name": &resolved_secret.secret.name,
        "profile": &resolved_secret.profile.name,
        "profile_id": &resolved_secret.profile.id,
        "source": &resolved_secret.secret.source,
        "version": resolved_secret.secret.current_version,
        "updated_fields": metadata_update_field_names(&args.metadata),
    });
    let audit = AuditWrite {
        project_id: resolved_secret.project.config.project_id.as_str(),
        profile_id: Some(&resolved_secret.profile.id),
        action: "SECRET_META_UPDATE",
        status: "SUCCESS",
        secret_name: Some(&resolved_secret.secret.name),
        command: None,
        metadata_json: &metadata,
        timestamp,
    };
    let changed = store.update_secret_metadata_with_options(
        &resolved_secret.secret.id,
        SecretMetadataUpdate {
            description: args.metadata.description.as_deref(),
            owner: args.metadata.owner.as_deref(),
            tags,
            required,
            updated_at: Some(timestamp),
            audit: Some(AuditContext { key: audit_key.as_ref(), write: &audit }),
        },
    )?;
    if !changed {
        return Err(CliError::Config("secret not found".to_owned()));
    }

    writeln!(
        output,
        "metadata updated {} source={} version={}",
        resolved_secret.secret.name,
        resolved_secret.secret.source,
        resolved_secret.secret.current_version
    )?;
    Ok(())
}

fn diff_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &DiffArgs,
) -> Result<(), CliError> {
    if let Some(since) = &args.since {
        if args.profile_a.is_some() || args.profile_b.is_some() {
            return Err(CliError::Config(
                "diff --since uses the active profile and does not accept profile arguments"
                    .to_owned(),
            ));
        }
        return diff_since_command(context, output, since);
    }

    let profile_a = args
        .profile_a
        .as_deref()
        .ok_or_else(|| CliError::Config("diff requires two profile names".to_owned()))?;
    let profile_b = args
        .profile_b
        .as_deref()
        .ok_or_else(|| CliError::Config("diff requires two profile names".to_owned()))?;
    let lhs = ProfileName::new(profile_a.to_owned())
        .map_err(|_| CliError::Config("invalid profile name".to_owned()))?;
    let rhs = ProfileName::new(profile_b.to_owned())
        .map_err(|_| CliError::Config("invalid profile name".to_owned()))?;

    let resolved = require_project(context)?;
    let store = open_store(context)?;
    let profile_a = store
        .get_profile_by_name(resolved.config.project_id.as_str(), lhs.as_str())?
        .ok_or_else(|| CliError::Config("first profile not found".to_owned()))?;
    let profile_b = store
        .get_profile_by_name(resolved.config.project_id.as_str(), rhs.as_str())?
        .ok_or_else(|| CliError::Config("second profile not found".to_owned()))?;

    let lhs_secrets =
        active_secret_map(&store, resolved.config.project_id.as_str(), &profile_a.id)?;
    let rhs_secrets =
        active_secret_map(&store, resolved.config.project_id.as_str(), &profile_b.id)?;
    let keys = lhs_secrets.keys().chain(rhs_secrets.keys()).cloned().collect::<BTreeSet<_>>();
    let mut differences = 0_u32;

    for key in keys {
        match (lhs_secrets.get(&key), rhs_secrets.get(&key)) {
            (Some(left_record), Some(right_record))
                if left_record.current_version != right_record.current_version =>
            {
                differences += 1;
                writeln!(
                    output,
                    "changed {} source={} {}_version={} {}_version={}",
                    key.0,
                    key.1,
                    profile_a.name,
                    left_record.current_version,
                    profile_b.name,
                    right_record.current_version
                )?;
            }
            (Some(secret), None) => {
                differences += 1;
                writeln!(
                    output,
                    "only {}: {} source={} version={}",
                    profile_a.name, key.0, key.1, secret.current_version
                )?;
            }
            (None, Some(secret)) => {
                differences += 1;
                writeln!(
                    output,
                    "only {}: {} source={} version={}",
                    profile_b.name, key.0, key.1, secret.current_version
                )?;
            }
            _ => {}
        }
    }

    if differences == 0 {
        writeln!(output, "no differences")?;
    }
    Ok(())
}

fn diff_since_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    since: &str,
) -> Result<(), CliError> {
    let resolved = require_project(context)?;
    let store = open_store(context)?;
    let profile = default_profile(&store, &resolved.config)?;
    let since_nanos = resolve_diff_since(&resolved.root, since)?;
    let changes = collect_diff_since_changes(
        &store,
        resolved.config.project_id.as_str(),
        &profile.id,
        since_nanos,
    )?;

    if changes.is_empty() {
        writeln!(output, "no differences")?;
        return Ok(());
    }

    writeln!(output, "profile: {} ({})", profile.name, profile.id)?;
    writeln!(output, "since: {since}")?;
    writeln!(output, "since_unix_nanos: {since_nanos}")?;
    writeln!(output, "metadata_only: yes")?;
    for change in changes {
        writeln!(output, "{change}")?;
    }
    Ok(())
}

fn collect_diff_since_changes(
    store: &Store,
    project_id: &str,
    profile_id: &str,
    since_nanos: i64,
) -> Result<Vec<String>, CliError> {
    let mut changes = Vec::<DiffSinceChange>::new();
    for audit in store.list_audit_rows_since(project_id, profile_id, since_nanos)? {
        if audit.status != "SUCCESS" || !is_diff_since_mutating_audit_action(&audit.action) {
            continue;
        }
        changes.push(DiffSinceChange {
            timestamp: audit.timestamp,
            sequence: audit.sequence,
            text: diff_since_audit_line(&audit),
        });
    }
    for secret in store.list_secrets_by_profile(project_id, profile_id)? {
        let mut latest_secret_timestamp = latest_secret_change_timestamp(&secret, since_nanos);
        let versions = store.list_secret_versions(&secret.id)?;
        let mut version_changes = Vec::new();
        for version in versions {
            if let Some(timestamp) = latest_version_change_timestamp(&version, since_nanos) {
                latest_secret_timestamp =
                    Some(latest_secret_timestamp.map_or(timestamp, |latest| latest.max(timestamp)));
                version_changes.push(DiffSinceChange {
                    timestamp,
                    sequence: u64::MAX,
                    text: format!(
                    "version {} source={} v{} state={} created_at={} deprecated_at={} grace_until={} purged_at={}",
                    secret.name,
                    secret.source,
                    version.version,
                    version.state,
                    version.created_at,
                    format_optional_i64(version.deprecated_at),
                    format_optional_i64(version.grace_until),
                    format_optional_i64(version.purged_at)
                    ),
                });
            }
        }
        if let Some(timestamp) = latest_secret_timestamp {
            changes.push(DiffSinceChange {
                timestamp,
                sequence: u64::MAX,
                text: format!(
                "changed {} source={} state={} current_version={} created_at={} updated_at={} last_rotated_at={} deleted_at={}",
                secret.name,
                secret.source,
                secret.state,
                secret.current_version,
                secret.created_at,
                secret.updated_at,
                format_optional_i64(secret.last_rotated_at),
                format_optional_i64(secret.deleted_at)
                ),
            });
            changes.extend(version_changes);
        }
    }
    changes.sort_by(|left, right| {
        (left.timestamp, left.sequence, left.text.as_str()).cmp(&(
            right.timestamp,
            right.sequence,
            right.text.as_str(),
        ))
    });
    Ok(changes.into_iter().map(|change| change.text).collect())
}

fn is_diff_since_mutating_audit_action(action: &str) -> bool {
    matches!(action, "SET" | "ROTATE" | "DELETE" | "PURGE" | "SECRET_COPY" | "SECRET_META_UPDATE")
}

struct DiffSinceChange {
    timestamp: i64,
    sequence: u64,
    text: String,
}

fn latest_secret_change_timestamp(secret: &SecretRecord, since_nanos: i64) -> Option<i64> {
    [Some(secret.created_at), Some(secret.updated_at), secret.last_rotated_at, secret.deleted_at]
        .into_iter()
        .flatten()
        .filter(|timestamp| *timestamp >= since_nanos)
        .max()
}

fn latest_version_change_timestamp(version: &SecretVersionRecord, since_nanos: i64) -> Option<i64> {
    [Some(version.created_at), version.deprecated_at, version.grace_until, version.purged_at]
        .into_iter()
        .flatten()
        .filter(|timestamp| *timestamp >= since_nanos)
        .max()
}

fn diff_since_audit_line(audit: &AuditLogRecord) -> String {
    format!(
        "audit sequence={} action={} status={} secret={} command={} timestamp={}",
        audit.sequence,
        audit.action,
        audit.status,
        format_optional_str(audit.secret_name.as_deref()),
        format_optional_str(audit.command.as_deref()),
        audit.timestamp
    )
}

fn format_optional_i64(value: Option<i64>) -> String {
    value.map_or_else(|| "none".to_owned(), |value| value.to_string())
}

fn format_optional_str(value: Option<&str>) -> &str {
    value.unwrap_or("none")
}

fn emit_example_command(context: &RuntimeContext, output: &mut impl Write) -> Result<(), CliError> {
    let resolved = require_project(context)?;
    let mut store = open_store(context)?;
    let names = collect_example_secret_names(&store, &resolved)?;
    let result = write_example_block_for_emit(&resolved.root, &names, output)?;
    write_example_emit_audit(context, &mut store, &resolved, &result)?;
    writeln!(output, "updated {}", result.path.display())?;
    Ok(())
}

fn lock_command(context: &RuntimeContext, output: &mut impl Write) -> Result<(), CliError> {
    writeln!(output, "lock: no agent-held keys to clear")?;
    writeln!(output, "agent: unavailable")?;
    writeln!(output, "metadata_only: yes")?;
    if let Some(project) = resolve_project(&context.cwd)? {
        writeln!(output, "project_id: {}", project.config.project_id)?;
    }
    Ok(())
}

fn unlock_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &UnlockArgs,
) -> Result<(), CliError> {
    let resolved = require_project(context)?;
    let store = open_store(context)?;
    ensure_project_exists(&store, resolved.config.project_id.as_str())?;
    let profile = default_profile(&store, &resolved.config)?;
    let (_audit_key, source) = load_project_key_with_source(
        context,
        &store,
        resolved.config.project_id.as_str(),
        KeyPurpose::Audit,
    )?;

    writeln!(output, "unlock: metadata-only direct CLI unlock succeeded")?;
    writeln!(output, "project_id: {}", resolved.config.project_id)?;
    writeln!(output, "active_profile: {} ({})", resolved.config.default_profile, profile.id)?;
    writeln!(output, "unlock_source: {}", source.as_str())?;
    writeln!(output, "agent: unavailable")?;
    writeln!(output, "cached_keys: no")?;
    if args.verify_user {
        writeln!(
            output,
            "verify_user: requested, but platform user verification is not implemented in this build; no interactive verification was performed"
        )?;
    } else {
        writeln!(output, "verify_user: not requested")?;
    }
    Ok(())
}

fn install_hooks_command(
    context: &RuntimeContext,
    output: &mut impl Write,
) -> Result<(), CliError> {
    let resolved = require_project(context)?;
    let git_dir = git_dir_for_worktree(&resolved.root)?;
    let hooks_dir = git_dir.join("hooks");
    fs::create_dir_all(&hooks_dir)?;
    let hook_path = hooks_dir.join("pre-commit");
    let existing = match fs::read_to_string(&hook_path) {
        Ok(existing) => existing,
        Err(error) if error.kind() == io::ErrorKind::NotFound => String::new(),
        Err(error) => return Err(error.into()),
    };
    let plan = plan_pre_commit_hook(&existing)?;
    if plan.change == HookInstallChange::PrependUnmanaged {
        confirm_unmanaged_pre_commit_hook(
            context,
            output,
            resolved.config.name.as_str(),
            &hook_path,
            &existing,
        )?;
    }
    if plan.updated != existing {
        fs::write(&hook_path, plan.updated)?;
    }
    make_executable(&hook_path)?;
    write_hook_install_audit_if_available(context, &resolved)?;

    writeln!(output, "installed {}", hook_path.display())?;
    writeln!(output, "hook_change: {}", plan.change.as_str())?;
    writeln!(output, "hook: locket scan --staged")?;
    writeln!(output, "secrets: not written")?;
    Ok(())
}

fn managed_pre_commit_block() -> String {
    format!("{HOOK_BEGIN}\nlocket scan --staged\n{HOOK_END}\n")
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum HookInstallChange {
    Created,
    RewroteManaged,
    PrependUnmanaged,
    Unchanged,
}

impl HookInstallChange {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::RewroteManaged => "rewrote-managed-block",
            Self::PrependUnmanaged => "prepended-after-confirmation",
            Self::Unchanged => "unchanged",
        }
    }
}

#[derive(Debug)]
struct HookInstallPlan {
    updated: String,
    change: HookInstallChange,
}

fn plan_pre_commit_hook(existing: &str) -> Result<HookInstallPlan, CliError> {
    let block = managed_pre_commit_block();
    if existing.is_empty() {
        return Ok(HookInstallPlan {
            updated: format!("#!/bin/sh\n\n{block}"),
            change: HookInstallChange::Created,
        });
    }
    if let Some(begin) = existing.find(HOOK_BEGIN) {
        let Some(relative_end) = existing[begin..].find(HOOK_END) else {
            return Err(CliError::Config(
                ".git/hooks/pre-commit has an unterminated Locket pre-commit block".to_owned(),
            ));
        };
        let end = begin + relative_end + HOOK_END.len();
        let replace_end =
            if existing[end..].starts_with('\n') { end + '\n'.len_utf8() } else { end };
        let mut updated = String::new();
        updated.push_str(&existing[..begin]);
        updated.push_str(&block);
        updated.push_str(&existing[replace_end..]);
        let change = if updated == existing {
            HookInstallChange::Unchanged
        } else {
            HookInstallChange::RewroteManaged
        };
        return Ok(HookInstallPlan { updated, change });
    }

    let updated = if let Some(rest) = existing.strip_prefix("#!") {
        let Some(newline_index) = rest.find('\n') else {
            return Ok(HookInstallPlan {
                updated: format!("{existing}\n\n{block}"),
                change: HookInstallChange::PrependUnmanaged,
            });
        };
        let shebang_end = "#!".len() + newline_index + 1;
        let mut updated = String::new();
        updated.push_str(&existing[..shebang_end]);
        updated.push('\n');
        updated.push_str(&block);
        updated.push('\n');
        updated.push_str(&existing[shebang_end..]);
        updated
    } else {
        format!("{block}\n{existing}")
    };
    Ok(HookInstallPlan { updated, change: HookInstallChange::PrependUnmanaged })
}

fn confirm_unmanaged_pre_commit_hook(
    context: &RuntimeContext,
    output: &mut dyn Write,
    project_name: &str,
    hook_path: &Path,
    existing: &str,
) -> Result<(), CliError> {
    writeln!(output, "pre_commit_hook: unmanaged")?;
    writeln!(output, "path: {}", hook_path.display())?;
    writeln!(output, "existing_lines: {}", existing.lines().count())?;
    writeln!(output, "existing_bytes: {}", existing.len())?;
    writeln!(output, "metadata_only: yes")?;
    writeln!(output, "preview: prepend Locket managed block and preserve existing hook content")?;
    writeln!(output, "managed_begin: {HOOK_BEGIN}")?;
    writeln!(output, "managed_command: locket scan --staged")?;
    writeln!(output, "managed_end: {HOOK_END}")?;
    writeln!(output, "type project name '{project_name}' to confirm")?;
    let confirmation = context
        .confirmation_reader
        .read_confirmation("install-hooks unmanaged hook replacement")?;
    if confirmation.trim_end_matches(['\r', '\n']) != project_name {
        return Err(CliError::Config("confirmation did not match project name".to_owned()));
    }
    Ok(())
}

fn git_dir_for_worktree(start: &Path) -> Result<PathBuf, CliError> {
    let mut current = start.canonicalize()?;
    loop {
        let dot_git = current.join(".git");
        if let Ok(metadata) = fs::metadata(&dot_git) {
            if metadata.is_dir() {
                return Ok(dot_git);
            }

            let pointer = fs::read_to_string(&dot_git)?;
            let Some(path) = pointer.trim().strip_prefix("gitdir:") else {
                return Err(CliError::Config("unsupported .git worktree pointer".to_owned()));
            };
            let path = path.trim();
            return Ok(if Path::new(path).is_absolute() {
                PathBuf::from(path)
            } else {
                current.join(path)
            });
        }

        if !current.pop() {
            return Err(CliError::Config("git worktree required for install-hooks".to_owned()));
        }
    }
}

#[cfg(unix)]
fn make_executable(path: &Path) -> Result<(), CliError> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = fs::metadata(path)?;
    let mut permissions = metadata.permissions();
    permissions.set_mode(permissions.mode() | 0o700);
    fs::set_permissions(path, permissions)?;
    Ok(())
}

#[cfg(not(unix))]
fn make_executable(_path: &Path) -> Result<(), CliError> {
    Ok(())
}

fn write_hook_install_audit_if_available(
    context: &RuntimeContext,
    resolved: &ResolvedProject,
) -> Result<(), CliError> {
    let mut store = open_store(context)?;
    if store.get_project(resolved.config.project_id.as_str())?.is_none() {
        return Ok(());
    }
    let audit_key =
        load_project_key(context, &store, resolved.config.project_id.as_str(), KeyPurpose::Audit)?;
    let metadata = json!({
        "schema_version": 1,
        "action": "HOOK_INSTALL",
        "status": "SUCCESS",
        "hook": "pre-commit",
        "command": "locket scan --staged",
    });
    let audit = AuditWrite {
        project_id: resolved.config.project_id.as_str(),
        profile_id: None,
        action: "HOOK_INSTALL",
        status: "SUCCESS",
        secret_name: None,
        command: Some("install-hooks"),
        metadata_json: &metadata,
        timestamp: now_unix_nanos()?,
    };
    store.append_audit(audit_key.as_ref(), &audit)?;
    Ok(())
}

fn agent_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    command: AgentCommand,
) -> Result<(), CliError> {
    match command {
        AgentCommand::Start => agent_start_command(context, output),
        AgentCommand::Status => agent_status_command(context, output),
        AgentCommand::Stop => agent_stop_command(context, output),
        AgentCommand::Logs(args) => agent_logs_command(context, output, &args),
    }
}

fn agent_start_command(context: &RuntimeContext, output: &mut impl Write) -> Result<(), CliError> {
    fs::create_dir_all(agent_data_dir(context))?;
    append_agent_log(context, "start", "unavailable", "daemon not available in this build")?;
    writeln!(output, "agent: unavailable")?;
    writeln!(output, "running: no")?;
    writeln!(output, "start: daemon not available in this build")?;
    write_agent_paths(context, output)?;
    Ok(())
}

fn agent_status_command(context: &RuntimeContext, output: &mut impl Write) -> Result<(), CliError> {
    writeln!(output, "agent: unavailable")?;
    writeln!(output, "running: no")?;
    match read_agent_pid(context)? {
        Some(pid) => writeln!(output, "last_known_pid: {pid}")?,
        None => writeln!(output, "last_known_pid: -")?,
    }
    write_agent_paths(context, output)?;
    writeln!(output, "lock_state: unavailable")?;
    writeln!(output, "live_grants: unavailable")?;
    writeln!(output, "last_error: daemon not available in this build")?;
    if let Some(project) = resolve_project(&context.cwd)? {
        writeln!(output, "active_project_id: {}", project.config.project_id)?;
        writeln!(output, "active_profile: {}", project.config.default_profile)?;
    }
    Ok(())
}

fn agent_stop_command(context: &RuntimeContext, output: &mut impl Write) -> Result<(), CliError> {
    let pid_path = agent_pid_path(context);
    let removed_stale_pid = match fs::remove_file(&pid_path) {
        Ok(()) => true,
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(error) => return Err(error.into()),
    };
    append_agent_log(context, "stop", "stopped", "no daemon was running")?;
    writeln!(output, "agent: stopped")?;
    writeln!(output, "running: no")?;
    writeln!(output, "removed_stale_pid: {}", if removed_stale_pid { "yes" } else { "no" })?;
    write_agent_paths(context, output)?;
    Ok(())
}

fn agent_logs_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &AgentLogsArgs,
) -> Result<(), CliError> {
    if args.lines > 10_000 {
        return Err(CliError::Config("agent logs --lines is capped at 10000".to_owned()));
    }
    let since = args.since.as_deref().map(parse_agent_log_since).transpose()?;
    let lines = read_agent_log_lines(context, since)?;
    if lines.is_empty() {
        if !args.follow {
            writeln!(output, "no agent logs")?;
        }
    } else {
        for line in lines.iter().skip(lines.len().saturating_sub(args.lines)) {
            writeln!(output, "{}", sanitize_agent_log_line(line))?;
        }
    }
    if args.follow {
        follow_agent_logs(context, output, since)?;
    }
    Ok(())
}

fn parse_agent_log_since(value: &str) -> Result<i64, CliError> {
    if let Ok(timestamp) = value.parse::<i64>() {
        return Ok(normalize_log_since(timestamp));
    }
    let timestamp = OffsetDateTime::parse(value, &Rfc3339).map_err(|_| {
        CliError::Config("agent logs --since must be RFC3339 UTC or Unix seconds".to_owned())
    })?;
    timestamp.unix_timestamp_nanos().try_into().map_err(|_| CliError::Time)
}

const fn normalize_log_since(value: i64) -> i64 {
    if value.abs() < 10_000_000_000 { value.saturating_mul(NANOS_PER_SECOND) } else { value }
}

fn read_agent_log_lines(
    context: &RuntimeContext,
    since: Option<i64>,
) -> Result<Vec<String>, CliError> {
    let mut lines = Vec::new();
    for path in agent_log_paths_oldest_first(context) {
        let log_text = match fs::read_to_string(&path) {
            Ok(log_text) => log_text,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        lines.extend(
            log_text.lines().filter(|line| agent_log_line_is_since(line, since)).map(str::to_owned),
        );
    }
    Ok(lines)
}

fn agent_log_line_is_since(line: &str, since: Option<i64>) -> bool {
    let Some(since) = since else {
        return true;
    };
    serde_json::from_str::<Value>(line)
        .ok()
        .and_then(|value| agent_log_timestamp_nanos(value.get("timestamp")?))
        .is_some_and(|timestamp| timestamp >= since)
}

fn agent_log_timestamp_nanos(value: &Value) -> Option<i64> {
    if let Some(timestamp) = value.as_i64() {
        return Some(normalize_log_since(timestamp));
    }
    let timestamp = OffsetDateTime::parse(value.as_str()?, &Rfc3339).ok()?;
    timestamp.unix_timestamp_nanos().try_into().ok()
}

fn follow_agent_logs(
    context: &RuntimeContext,
    output: &mut impl Write,
    since: Option<i64>,
) -> Result<(), CliError> {
    prepare_agent_log_dir(context)?;
    let log_path = agent_log_path(context);
    let mut file = fs::OpenOptions::new().read(true).create(true).append(true).open(&log_path)?;
    set_user_only_file_permissions(&log_path)?;
    file.seek(SeekFrom::End(0))?;
    let mut pending = String::new();
    loop {
        let mut chunk = String::new();
        file.read_to_string(&mut chunk)?;
        if !chunk.is_empty() {
            pending.push_str(&chunk);
            while let Some(newline) = pending.find('\n') {
                let line = pending[..newline].to_owned();
                pending.drain(..=newline);
                if agent_log_line_is_since(&line, since) {
                    writeln!(output, "{}", sanitize_agent_log_line(&line))?;
                }
            }
        }
        std::thread::sleep(StdDuration::from_millis(AGENT_LOG_FOLLOW_SLEEP_MS));
    }
}

fn scan_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: ScanArgs,
) -> Result<(), CliError> {
    let project = resolve_project(&context.cwd)?;
    let git_root = if args.staged {
        Some(ensure_git_worktree(project.as_ref().map_or(&context.cwd, |project| &project.root))?)
    } else {
        None
    };
    if args.require_known && project.is_none() {
        return Err(CliError::Config(
            "known-value scanning requires a Locket project and unlocked vault".to_owned(),
        ));
    }
    if args.no_gitignore {
        writeln!(output, "scan: gitignore rules disabled")?;
    }

    let scan_root = args.path.map_or_else(
        || project.as_ref().map_or_else(|| context.cwd.clone(), |project| project.root.clone()),
        |path| absolutize(&context.cwd, Path::new(&path)),
    );
    let known_values = if args.require_known {
        let project = project.as_ref().ok_or_else(|| {
            CliError::Config("known-value scanning requires a project".to_owned())
        })?;
        collect_known_secret_values(context, project, now_unix_nanos()?)?
    } else {
        Vec::new()
    };

    let mut findings = Vec::new();
    if let Some(git_root) = git_root {
        scan_staged_path(&git_root, &known_values, &mut findings)?;
    } else {
        scan_path(&scan_root, &scan_root, &known_values, !args.no_gitignore, &mut findings)?;
    }
    for finding in &findings {
        writeln!(output, "{}", format_finding(finding))?;
    }

    if findings.is_empty() {
        writeln!(output, "scan: no findings")?;
    } else {
        writeln!(output, "scan: {} finding(s)", findings.len())?;
    }

    if args.require_known {
        writeln!(output, "scan: known-value coverage checked {} value(s)", known_values.len())?;
    }
    Ok(())
}

fn redact_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: RedactArgs,
) -> Result<(), CliError> {
    let input = if args.stdin {
        let mut input = String::new();
        io::stdin().read_to_string(&mut input)?;
        input
    } else if let Some(file) = args.file {
        fs::read_to_string(absolutize(&context.cwd, Path::new(&file)))?
    } else {
        return Err(CliError::Config("redact requires a file path or --stdin".to_owned()));
    };

    let known_redactions = collect_redaction_values_for_redact(
        context,
        args.redact_names.redact_names,
        now_unix_nanos()?,
    )?;
    let result = redact_input(&input, &known_redactions);
    write!(output, "{}", result.text)?;
    Ok(())
}

fn collect_redaction_values_for_redact(
    context: &RuntimeContext,
    redact_names: bool,
    timestamp: i64,
) -> Result<Vec<KnownSecretRedaction>, CliError> {
    let Some(project) = resolve_project(&context.cwd)? else {
        return Ok(Vec::new());
    };
    match collect_known_secret_redactions(context, &project, redact_names, timestamp) {
        Ok(redactions) => Ok(redactions),
        Err(error) => {
            let mut stderr = io::stderr();
            let _ignored = writeln!(stderr, "locket: known-value redaction skipped: {error}");
            Ok(Vec::new())
        }
    }
}

fn redact_input(
    input: &str,
    known_redactions: &[KnownSecretRedaction],
) -> locket_scan::RedactionResult {
    if known_redactions.is_empty() {
        return redact_text(input);
    }
    let known_values = known_redactions
        .iter()
        .map(|entry| KnownRedaction { value: entry.value.as_str(), marker: entry.marker.as_str() })
        .collect::<Vec<_>>();
    redact_text_with_known_values(input, &known_values)
}

fn ai_safe_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &AiSafeArgs,
) -> Result<(), CliError> {
    if args.command.is_empty() {
        return Err(CliError::Config("ai-safe requires a command after --".to_owned()));
    }

    let known_redactions = if args.pattern_only {
        let mut stderr = io::stderr();
        writeln!(
            stderr,
            "locket: ai-safe running with pattern-only redaction; known values are not loaded"
        )?;
        Vec::new()
    } else {
        let project = require_project(context)?;
        collect_known_secret_redactions(
            context,
            &project,
            args.redact_names.redact_names,
            now_unix_nanos()?,
        )?
    };

    let mut transcript = if let Some(path) = args.output.as_deref() {
        Some(open_ai_safe_transcript(&absolutize(&context.cwd, Path::new(path)), args.force)?)
    } else {
        None
    };

    let child_output = ProcessCommand::new(&args.command[0])
        .args(&args.command[1..])
        .current_dir(&context.cwd)
        .output()?;
    let stdout = String::from_utf8_lossy(&child_output.stdout);
    let stderr = String::from_utf8_lossy(&child_output.stderr);
    let redacted_stdout = redact_input(&stdout, &known_redactions);
    let redacted_stderr = redact_input(&stderr, &known_redactions);

    write!(output, "{}", redacted_stdout.text)?;
    io::stderr().write_all(redacted_stderr.text.as_bytes())?;

    if let Some(file) = transcript.as_mut() {
        write_ai_safe_transcript(file, &redacted_stdout.text, &redacted_stderr.text)?;
    }

    if child_output.status.success() {
        Ok(())
    } else {
        Err(CliError::ChildExit(
            child_output.status.code().and_then(|code| u8::try_from(code).ok()).unwrap_or(1),
        ))
    }
}

fn open_ai_safe_transcript(path: &Path, force: bool) -> Result<fs::File, CliError> {
    let mut options = fs::OpenOptions::new();
    options.write(true);
    if force {
        options.create(true).truncate(true);
    } else {
        options.create_new(true);
    }
    #[cfg(unix)]
    options.mode(0o600);

    Ok(options.open(path)?)
}

fn write_ai_safe_transcript(
    file: &mut impl Write,
    stdout: &str,
    stderr: &str,
) -> Result<(), CliError> {
    if !stdout.is_empty() {
        writeln!(file, "[stdout]")?;
        write!(file, "{stdout}")?;
        if !stdout.ends_with('\n') {
            writeln!(file)?;
        }
    }
    if !stderr.is_empty() {
        writeln!(file, "[stderr]")?;
        write!(file, "{stderr}")?;
        if !stderr.ends_with('\n') {
            writeln!(file)?;
        }
    }
    Ok(())
}

fn context_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &RedactNamesArgs,
) -> Result<(), CliError> {
    let resolved = require_project(context)?;
    let store = open_store(context)?;
    let redact_names = privacy_redact_names_enabled(context, args.redact_names)?;
    let profiles = store.list_profiles(resolved.config.project_id.as_str())?;
    let policy_document = read_policy_document(&resolved.root.join(LOCKET_TOML))?;
    let active_profile =
        profiles.iter().find(|profile| profile.name == resolved.config.default_profile.as_str());
    let active_profile_label = active_profile.map_or_else(
        || {
            if redact_names {
                privacy_alias("profile", resolved.config.default_profile.as_str())
            } else {
                resolved.config.default_profile.to_string()
            }
        },
        |profile| context_profile_label(profile, redact_names),
    );

    writeln!(output, "Project: {}", context_project_label(&resolved, redact_names))?;
    writeln!(output, "Profile: {active_profile_label}")?;
    writeln!(output, "Profiles:")?;
    if profiles.is_empty() {
        writeln!(output, "- none")?;
    }
    for profile in &profiles {
        let label = context_profile_label(profile, redact_names);
        let active = profile.name == resolved.config.default_profile.as_str();
        let secret_count = store
            .list_active_secrets_by_profile(resolved.config.project_id.as_str(), &profile.id)?
            .len();
        writeln!(
            output,
            "- {label} active={} dangerous={} secrets={secret_count}",
            yes_no(active),
            yes_no(profile.dangerous)
        )?;
    }

    let secret_summaries =
        context_secret_summaries(&store, &resolved, &profiles, &policy_document, redact_names)?;
    writeln!(output, "Secrets referenced:")?;
    if secret_summaries.is_empty() {
        writeln!(output, "- none")?;
    }
    for summary in secret_summaries {
        writeln!(
            output,
            "- {} profiles={} sources={}",
            summary.name,
            format_display_list(&summary.profiles),
            format_display_list(&summary.sources)
        )?;
    }

    writeln!(output, "Policies:")?;
    if policy_document.commands.is_empty() {
        writeln!(output, "- none")?;
    }
    for policy in policy_document.commands.values() {
        writeln!(
            output,
            "- {} type={} required={} optional={} confirm={} verify_user={}",
            context_policy_label(policy, redact_names),
            command_type(&policy.command),
            format_policy_secret_list(&policy.required_secrets, redact_names),
            format_policy_secret_list(&policy.optional_secrets, redact_names),
            yes_no(policy.confirm),
            yes_no(policy.require_user_verification)
        )?;
    }
    writeln!(output, "No secret values included.")?;
    writeln!(output, "metadata_only: yes")?;
    Ok(())
}

struct ContextSecretSummary {
    name: String,
    profiles: BTreeSet<String>,
    sources: BTreeSet<String>,
}

fn privacy_redact_names_enabled(
    context: &RuntimeContext,
    explicit: bool,
) -> Result<bool, CliError> {
    if explicit {
        return Ok(true);
    }
    let config = read_user_config(context)?;
    let Some(value) = config_get_value(&config, "privacy.redact_names") else {
        return Ok(false);
    };
    value
        .as_bool()
        .ok_or_else(|| CliError::Config("privacy.redact_names must be boolean".to_owned()))
}

fn context_project_label(resolved: &ResolvedProject, redact_names: bool) -> String {
    if redact_names {
        privacy_alias("project", resolved.config.project_id.as_str())
    } else {
        resolved.config.name.clone()
    }
}

fn context_profile_label(profile: &ProfileRecord, redact_names: bool) -> String {
    if redact_names { privacy_alias("profile", &profile.id) } else { profile.name.clone() }
}

fn context_secret_label(secret: &SecretRecord, redact_names: bool) -> String {
    if redact_names { privacy_alias("secret", &secret.name) } else { secret.name.clone() }
}

fn context_policy_label(policy: &CommandPolicy, redact_names: bool) -> String {
    if redact_names { privacy_alias("policy", &policy.name) } else { policy.name.clone() }
}

fn context_secret_summaries(
    store: &Store,
    resolved: &ResolvedProject,
    profiles: &[ProfileRecord],
    policy_document: &PolicyDocument,
    redact_names: bool,
) -> Result<Vec<ContextSecretSummary>, CliError> {
    let mut summaries = BTreeMap::<String, ContextSecretSummary>::new();
    for profile in profiles {
        let profile_label = context_profile_label(profile, redact_names);
        for secret in store
            .list_active_secrets_by_profile(resolved.config.project_id.as_str(), &profile.id)?
        {
            let label = context_secret_label(&secret, redact_names);
            let summary = summaries.entry(label.clone()).or_insert_with(|| ContextSecretSummary {
                name: label,
                profiles: BTreeSet::new(),
                sources: BTreeSet::new(),
            });
            summary.profiles.insert(profile_label.clone());
            summary.sources.insert(secret.source);
        }
    }
    for policy in policy_document.commands.values() {
        let policy_label = context_policy_label(policy, redact_names);
        for secret in &policy.required_secrets {
            let label = context_secret_name_label(secret, redact_names);
            let summary = summaries.entry(label.clone()).or_insert_with(|| ContextSecretSummary {
                name: label,
                profiles: BTreeSet::new(),
                sources: BTreeSet::new(),
            });
            summary.profiles.insert(format!("policy:{policy_label}"));
            summary.sources.insert("policy-required".to_owned());
        }
        for secret in &policy.optional_secrets {
            let label = context_secret_name_label(secret, redact_names);
            let summary = summaries.entry(label.clone()).or_insert_with(|| ContextSecretSummary {
                name: label,
                profiles: BTreeSet::new(),
                sources: BTreeSet::new(),
            });
            summary.profiles.insert(format!("policy:{policy_label}"));
            summary.sources.insert("policy-optional".to_owned());
        }
    }
    Ok(summaries.into_values().collect())
}

fn context_secret_name_label(secret: &SecretName, redact_names: bool) -> String {
    if redact_names { privacy_alias("secret", secret.as_str()) } else { secret.as_str().to_owned() }
}

fn format_policy_secret_list(secrets: &[SecretName], redact_names: bool) -> String {
    if secrets.is_empty() {
        return "none".to_owned();
    }
    let values = secrets
        .iter()
        .map(|secret| context_secret_name_label(secret, redact_names))
        .collect::<BTreeSet<_>>();
    format_display_list(&values)
}

fn format_display_list(values: &BTreeSet<String>) -> String {
    if values.is_empty() {
        "none".to_owned()
    } else {
        values.iter().cloned().collect::<Vec<_>>().join(",")
    }
}

const fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

fn ensure_project_metadata(
    store: &Store,
    config: &ProjectConfig,
    timestamp: i64,
) -> Result<(), CliError> {
    store.insert_project_if_absent(config.project_id.as_str(), &config.name, timestamp)?;
    if store
        .get_profile_by_name(config.project_id.as_str(), config.default_profile.as_str())?
        .is_none()
    {
        let profile_id = ProfileId::generate().map_err(|_| CliError::Time)?;
        store.insert_profile_if_absent(
            profile_id.as_str(),
            config.project_id.as_str(),
            config.default_profile.as_str(),
            false,
            timestamp,
        )?;
    }
    Ok(())
}

fn ensure_template_profiles(
    context: &RuntimeContext,
    store: &Store,
    config: &ProjectConfig,
    template: &onboarding::ProjectTemplate,
    timestamp: i64,
) -> Result<(), CliError> {
    for profile_name in &template.profiles {
        if store.get_profile_by_name(config.project_id.as_str(), profile_name.as_str())?.is_some() {
            continue;
        }
        let profile_id = ProfileId::generate().map_err(|_| CliError::Time)?;
        store.insert_profile_if_absent(
            profile_id.as_str(),
            config.project_id.as_str(),
            profile_name.as_str(),
            false,
            timestamp,
        )?;
        initialize_profile_keys(context, store, config, profile_id.as_str(), timestamp)?;
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MasterKeySource {
    OsKeyStore,
    PassphraseFallback,
}

impl MasterKeySource {
    const fn as_str(self) -> &'static str {
        match self {
            Self::OsKeyStore => "os-key-store",
            Self::PassphraseFallback => "passphrase-fallback",
        }
    }
}

fn store_master_key_with_fallback(
    context: &RuntimeContext,
    project_id: &str,
    master_key: &locket_crypto::KeyBytes,
    timestamp: i64,
) -> Result<MasterKeySource, CliError> {
    match context.key_store.store_master_key(project_id, master_key) {
        Ok(()) => Ok(MasterKeySource::OsKeyStore),
        Err(_primary_error) => {
            let passphrase = context.passphrase_reader.new_passphrase()?;
            context.passphrase_store.store_master_key(
                project_id,
                master_key,
                passphrase.as_bytes(),
                timestamp,
            )?;
            Ok(MasterKeySource::PassphraseFallback)
        }
    }
}

fn load_master_key(
    context: &RuntimeContext,
    project_id: &str,
) -> Result<(zeroize::Zeroizing<locket_crypto::KeyBytes>, MasterKeySource), CliError> {
    match context.key_store.load_master_key(project_id) {
        Ok(master_key) => Ok((master_key, MasterKeySource::OsKeyStore)),
        Err(primary_error) => {
            if !context.passphrase_store.contains_project(project_id)? {
                return Err(primary_error.into());
            }
            Ok((
                load_fallback_master_key(context, project_id)?,
                MasterKeySource::PassphraseFallback,
            ))
        }
    }
}

fn load_fallback_master_key(
    context: &RuntimeContext,
    project_id: &str,
) -> Result<zeroize::Zeroizing<locket_crypto::KeyBytes>, CliError> {
    let passphrase = context.passphrase_reader.existing_passphrase()?;
    Ok(context.passphrase_store.load_master_key(project_id, passphrase.as_bytes())?)
}

fn initialize_project_keys(
    context: &RuntimeContext,
    store: &Store,
    config: &ProjectConfig,
    timestamp: i64,
) -> Result<MasterKeySource, CliError> {
    let master_key = generate_key()?;
    let source = store_master_key_with_fallback(
        context,
        config.project_id.as_str(),
        &master_key,
        timestamp,
    )?;
    insert_wrapped_key(
        store,
        config.project_id.as_str(),
        None,
        KeyPurpose::ProjectMetadata,
        &master_key,
        timestamp,
    )?;
    insert_wrapped_key(
        store,
        config.project_id.as_str(),
        None,
        KeyPurpose::Audit,
        &master_key,
        timestamp,
    )?;
    let profile = default_profile(store, config)?;
    initialize_profile_keys_with_master(store, config, &profile.id, &master_key, timestamp)?;
    Ok(source)
}

fn initialize_profile_keys(
    context: &RuntimeContext,
    store: &Store,
    config: &ProjectConfig,
    profile_id: &str,
    timestamp: i64,
) -> Result<(), CliError> {
    let (master_key, _) = load_master_key_verified_by_project_key(
        context,
        store,
        config.project_id.as_str(),
        KeyPurpose::ProjectMetadata,
    )?;
    initialize_profile_keys_with_master(store, config, profile_id, &master_key, timestamp)
}

fn initialize_profile_keys_with_master(
    store: &Store,
    config: &ProjectConfig,
    profile_id: &str,
    master_key: &locket_crypto::KeyBytes,
    timestamp: i64,
) -> Result<(), CliError> {
    insert_wrapped_key(
        store,
        config.project_id.as_str(),
        Some(profile_id),
        KeyPurpose::ProfileSecret,
        master_key,
        timestamp,
    )?;
    insert_wrapped_key(
        store,
        config.project_id.as_str(),
        Some(profile_id),
        KeyPurpose::ProfileFingerprint,
        master_key,
        timestamp,
    )?;
    Ok(())
}

fn insert_wrapped_key(
    store: &Store,
    project_id: &str,
    profile_id: Option<&str>,
    purpose: KeyPurpose,
    master_key: &locket_crypto::KeyBytes,
    timestamp: i64,
) -> Result<(), CliError> {
    let key_id = KeyId::generate().map_err(|_| CliError::Time)?;
    let key_material = generate_key()?;
    let wrapping_key =
        derive_wrapping_key_v1(master_key, &HkdfWrapInfo::new(project_id, profile_id, purpose))?;
    let aad = key_wrap_aad_v1(&KeyWrapAad::new(
        project_id,
        key_id.as_str(),
        profile_id,
        0,
        KeyWrapPurpose::from(purpose),
    ))?;
    let wrapped = wrap_key_material_v1(&wrapping_key, &key_material, &aad)?;
    store.insert_key(&KeyRecord {
        id: key_id.into_string(),
        project_id: project_id.to_owned(),
        profile_id: profile_id.map(ToOwned::to_owned),
        purpose: purpose.as_str().to_owned(),
        wrapped_material: wrapped.ciphertext,
        nonce: wrapped.nonce,
        created_at: timestamp,
    })?;
    Ok(())
}

fn default_profile(store: &Store, config: &ProjectConfig) -> Result<ProfileRecord, CliError> {
    store
        .get_profile_by_name(config.project_id.as_str(), config.default_profile.as_str())?
        .ok_or_else(|| CliError::Config("default profile is missing".to_owned()))
}

fn set_secret_value(
    context: &RuntimeContext,
    args: &SecretWriteArgs,
    value: &str,
    origin: &str,
    timestamp: i64,
) -> Result<(), CliError> {
    let source = source_arg_to_str(args.source.source.unwrap_or(SecretSourceArg::UserLocal));
    let resolved = require_project(context)?;
    let mut store = open_store(context)?;
    let profile = default_profile(&store, &resolved.config)?;
    set_secret_value_in_profile(
        context,
        &mut store,
        SecretWriteRequest {
            resolved: &resolved,
            profile: &profile,
            key: &args.key,
            source,
            value,
            origin,
            audit_action: "SET",
            timestamp,
        },
    )
}

#[derive(Clone, Copy)]
struct SecretWriteRequest<'a> {
    resolved: &'a ResolvedProject,
    profile: &'a ProfileRecord,
    key: &'a str,
    source: &'a str,
    value: &'a str,
    origin: &'a str,
    audit_action: &'a str,
    timestamp: i64,
}

fn set_secret_value_in_profile(
    context: &RuntimeContext,
    store: &mut Store,
    request: SecretWriteRequest<'_>,
) -> Result<(), CliError> {
    let name = SecretName::new(request.key.to_owned())
        .map_err(|_| CliError::Config("invalid secret name".to_owned()))?;
    if let Some(existing) = store.get_secret_by_source(
        request.resolved.config.project_id.as_str(),
        &request.profile.id,
        name.as_str(),
        request.source,
    )? {
        if existing.state == "deleted" {
            return Err(CliError::Config(
                "secret source is deleted; v1 does not reactivate tombstones".to_owned(),
            ));
        }
        return Err(CliError::Config("secret already exists; use rotate".to_owned()));
    }

    let secret_id = SecretId::generate().map_err(|_| CliError::Time)?;
    let version = 1;
    let audit_key = load_project_key(
        context,
        store,
        request.resolved.config.project_id.as_str(),
        KeyPurpose::Audit,
    )?;
    let (encrypted, fingerprint) = encrypt_secret_version(
        context,
        store,
        SecretEncryptRequest {
            project_id: request.resolved.config.project_id.as_str(),
            profile_id: &request.profile.id,
            secret_id: secret_id.as_str(),
            secret_name: name.as_str(),
            version,
            value: request.value,
        },
    )?;
    let secret_id_string = secret_id.into_string();
    let metadata = secret_audit_metadata(
        request.audit_action,
        name.as_str(),
        &request.profile.id,
        request.source,
        Some(version),
    );
    let audit = AuditWrite {
        project_id: request.resolved.config.project_id.as_str(),
        profile_id: Some(&request.profile.id),
        action: request.audit_action,
        status: "SUCCESS",
        secret_name: Some(name.as_str()),
        command: None,
        metadata_json: &metadata,
        timestamp: request.timestamp,
    };

    store.create_active_secret_with_audit(
        &SecretRecord {
            id: secret_id_string.clone(),
            project_id: request.resolved.config.project_id.as_str().to_owned(),
            profile_id: request.profile.id.clone(),
            name: name.as_str().to_owned(),
            source: request.source.to_owned(),
            origin: request.origin.to_owned(),
            current_version: version,
            state: "active".to_owned(),
            created_at: request.timestamp,
            updated_at: request.timestamp,
            last_rotated_at: None,
            deleted_at: None,
        },
        &SecretVersionRecord {
            secret_id: secret_id_string.clone(),
            version,
            source: request.source.to_owned(),
            origin: request.origin.to_owned(),
            state: "current".to_owned(),
            created_at: request.timestamp,
            deprecated_at: None,
            grace_until: None,
            purged_at: None,
        },
        &SecretBlobRecord {
            secret_id: secret_id_string.clone(),
            version,
            encrypted_dek: encrypted.encrypted_dek,
            ciphertext: encrypted.ciphertext,
            value_nonce: encrypted.value_nonce,
            aad_schema_version: encrypted.aad_schema_version,
            created_at: request.timestamp,
        },
        &SecretFingerprintRecord {
            secret_id: secret_id_string,
            version,
            fingerprint,
            created_at: request.timestamp,
        },
        Some(AuditContext { key: audit_key.as_ref(), write: &audit }),
    )?;
    Ok(())
}

fn rotate_secret_value(
    context: &RuntimeContext,
    args: &RotateArgs,
    value: &str,
    timestamp: i64,
    grace_until: Option<i64>,
) -> Result<(String, u32), CliError> {
    let name = SecretName::new(args.key.clone())
        .map_err(|_| CliError::Config("invalid secret name".to_owned()))?;
    let resolved_secret =
        resolve_active_secret_for_source(context, name.as_str(), args.source.source)?;
    let new_version = resolved_secret
        .secret
        .current_version
        .checked_add(1)
        .ok_or_else(|| CliError::Config("secret version overflow".to_owned()))?;
    let mut store = open_store(context)?;
    let audit_key = load_project_key(
        context,
        &store,
        resolved_secret.project.config.project_id.as_str(),
        KeyPurpose::Audit,
    )?;
    let (encrypted, fingerprint) = encrypt_secret_version(
        context,
        &store,
        SecretEncryptRequest {
            project_id: resolved_secret.project.config.project_id.as_str(),
            profile_id: &resolved_secret.profile.id,
            secret_id: &resolved_secret.secret.id,
            secret_name: &resolved_secret.secret.name,
            version: new_version,
            value,
        },
    )?;
    let source = resolved_secret.secret.source.clone();
    let origin = resolved_secret.secret.origin.clone();
    let metadata = json!({
        "schema_version": 1,
        "action": "ROTATE",
        "status": "SUCCESS",
        "secret_name": &resolved_secret.secret.name,
        "profile_id": &resolved_secret.profile.id,
        "source": &source,
        "prior_version": resolved_secret.secret.current_version,
        "deprecated_version": resolved_secret.secret.current_version,
        "target_version": new_version,
        "deprecated_at": timestamp,
        "grace_until": grace_until,
    });
    let audit = AuditWrite {
        project_id: resolved_secret.project.config.project_id.as_str(),
        profile_id: Some(&resolved_secret.profile.id),
        action: "ROTATE",
        status: "SUCCESS",
        secret_name: Some(&resolved_secret.secret.name),
        command: None,
        metadata_json: &metadata,
        timestamp,
    };

    store.rotate_secret_with_audit(
        &resolved_secret.secret,
        &SecretVersionRecord {
            secret_id: resolved_secret.secret.id.clone(),
            version: new_version,
            source: source.clone(),
            origin,
            state: "current".to_owned(),
            created_at: timestamp,
            deprecated_at: None,
            grace_until: None,
            purged_at: None,
        },
        &SecretBlobRecord {
            secret_id: resolved_secret.secret.id.clone(),
            version: new_version,
            encrypted_dek: encrypted.encrypted_dek,
            ciphertext: encrypted.ciphertext,
            value_nonce: encrypted.value_nonce,
            aad_schema_version: encrypted.aad_schema_version,
            created_at: timestamp,
        },
        &SecretFingerprintRecord {
            secret_id: resolved_secret.secret.id.clone(),
            version: new_version,
            fingerprint,
            created_at: timestamp,
        },
        VersionDeprecation { deprecated_at: timestamp, grace_until },
        Some(AuditContext { key: audit_key.as_ref(), write: &audit }),
    )?;

    Ok((source, new_version))
}

#[derive(Clone, Copy)]
struct ImportRotateRequest<'a> {
    resolved: &'a ResolvedProject,
    profile: &'a ProfileRecord,
    key: &'a str,
    source: &'a str,
    value: &'a str,
    timestamp: i64,
}

fn rotate_import_secret_value_in_profile(
    context: &RuntimeContext,
    store: &mut Store,
    request: ImportRotateRequest<'_>,
) -> Result<u32, CliError> {
    let name = SecretName::new(request.key.to_owned())
        .map_err(|_| CliError::Config("invalid secret name".to_owned()))?;
    let secret = store
        .get_secret_by_source(
            request.resolved.config.project_id.as_str(),
            &request.profile.id,
            name.as_str(),
            request.source,
        )?
        .ok_or_else(|| CliError::Config("secret does not exist".to_owned()))?;
    if secret.state == "deleted" {
        return Err(CliError::Config("secret source is deleted".to_owned()));
    }
    let new_version = secret
        .current_version
        .checked_add(1)
        .ok_or_else(|| CliError::Config("secret version overflow".to_owned()))?;
    let audit_key = load_project_key(
        context,
        store,
        request.resolved.config.project_id.as_str(),
        KeyPurpose::Audit,
    )?;
    let (encrypted, fingerprint) = encrypt_secret_version(
        context,
        store,
        SecretEncryptRequest {
            project_id: request.resolved.config.project_id.as_str(),
            profile_id: &request.profile.id,
            secret_id: &secret.id,
            secret_name: &secret.name,
            version: new_version,
            value: request.value,
        },
    )?;
    let metadata = json!({
        "schema_version": 1,
        "action": "ROTATE",
        "status": "SUCCESS",
        "secret_name": &secret.name,
        "profile_id": &request.profile.id,
        "source": &secret.source,
        "prior_version": secret.current_version,
        "deprecated_version": secret.current_version,
        "target_version": new_version,
        "deprecated_at": request.timestamp,
        "grace_until": null,
    });
    let audit = AuditWrite {
        project_id: request.resolved.config.project_id.as_str(),
        profile_id: Some(&request.profile.id),
        action: "ROTATE",
        status: "SUCCESS",
        secret_name: Some(&secret.name),
        command: None,
        metadata_json: &metadata,
        timestamp: request.timestamp,
    };
    store.rotate_secret_with_audit(
        &secret,
        &SecretVersionRecord {
            secret_id: secret.id.clone(),
            version: new_version,
            source: secret.source.clone(),
            origin: "imported".to_owned(),
            state: "current".to_owned(),
            created_at: request.timestamp,
            deprecated_at: None,
            grace_until: None,
            purged_at: None,
        },
        &SecretBlobRecord {
            secret_id: secret.id.clone(),
            version: new_version,
            encrypted_dek: encrypted.encrypted_dek,
            ciphertext: encrypted.ciphertext,
            value_nonce: encrypted.value_nonce,
            aad_schema_version: encrypted.aad_schema_version,
            created_at: request.timestamp,
        },
        &SecretFingerprintRecord {
            secret_id: secret.id.clone(),
            version: new_version,
            fingerprint,
            created_at: request.timestamp,
        },
        VersionDeprecation { deprecated_at: request.timestamp, grace_until: None },
        Some(AuditContext { key: audit_key.as_ref(), write: &audit }),
    )?;
    Ok(new_version)
}

struct CopySecretResult {
    from_profile: String,
    to_profile: String,
    from_source: String,
    to_source: String,
    target_version: u32,
    operation: &'static str,
}

struct CopyTargetPlan {
    secret_id: String,
    version: u32,
    prior_version: Option<u32>,
    existing: Option<SecretRecord>,
}

struct CopySelection {
    from_profile: ProfileRecord,
    to_profile: ProfileRecord,
    source_secret: SecretRecord,
    from_source: String,
    to_source: String,
}

#[derive(Clone, Copy)]
struct CopyAuditMetadata<'a> {
    name: &'a str,
    from_profile: &'a ProfileRecord,
    from_source: &'a str,
    from_version: u32,
    to_profile: &'a ProfileRecord,
    to_source: &'a str,
    prior_target_version: Option<u32>,
    target_version: u32,
}

#[derive(Clone, Copy)]
struct CopyWriteRequest<'a> {
    target: &'a CopyTargetPlan,
    project_id: &'a str,
    to_profile_id: &'a str,
    name: &'a str,
    to_source: &'a str,
    timestamp: i64,
    version: &'a SecretVersionRecord,
    blob: &'a SecretBlobRecord,
    fingerprint: &'a SecretFingerprintRecord,
    audit: AuditContext<'a>,
}

fn copy_secret_value(
    context: &RuntimeContext,
    args: &CopyArgs,
    timestamp: i64,
) -> Result<CopySecretResult, CliError> {
    let name = SecretName::new(args.key.clone())
        .map_err(|_| CliError::Config("invalid secret name".to_owned()))?;
    let resolved = require_project(context)?;
    let mut store = open_store(context)?;
    let project_id = resolved.config.project_id.as_str();
    let selection = select_copy_profiles_and_sources(&store, project_id, name.as_str(), args)?;

    let target = plan_copy_target(
        &store,
        project_id,
        &selection.to_profile.id,
        name.as_str(),
        &selection.to_source,
    )?;
    let value = decrypt_secret_version(
        context,
        &store,
        project_id,
        &selection.from_profile.id,
        &selection.source_secret,
        selection.source_secret.current_version,
    )?;
    let audit_key = load_project_key(context, &store, project_id, KeyPurpose::Audit)?;
    let (encrypted, fingerprint) = encrypt_secret_version(
        context,
        &store,
        SecretEncryptRequest {
            project_id,
            profile_id: &selection.to_profile.id,
            secret_id: &target.secret_id,
            secret_name: name.as_str(),
            version: target.version,
            value: value.as_str(),
        },
    )?;
    let metadata = copy_audit_metadata(CopyAuditMetadata {
        name: name.as_str(),
        from_profile: &selection.from_profile,
        from_source: &selection.from_source,
        from_version: selection.source_secret.current_version,
        to_profile: &selection.to_profile,
        to_source: &selection.to_source,
        prior_target_version: target.prior_version,
        target_version: target.version,
    });
    let audit = AuditWrite {
        project_id,
        profile_id: Some(&selection.to_profile.id),
        action: "SECRET_COPY",
        status: "SUCCESS",
        secret_name: Some(name.as_str()),
        command: None,
        metadata_json: &metadata,
        timestamp,
    };
    let (version, blob, fingerprint) = copied_secret_records(
        &target.secret_id,
        target.version,
        &selection.to_source,
        encrypted,
        fingerprint,
        timestamp,
    );
    let operation = write_copied_secret(
        &mut store,
        CopyWriteRequest {
            target: &target,
            project_id,
            to_profile_id: &selection.to_profile.id,
            name: name.as_str(),
            to_source: &selection.to_source,
            timestamp,
            version: &version,
            blob: &blob,
            fingerprint: &fingerprint,
            audit: AuditContext { key: audit_key.as_ref(), write: &audit },
        },
    )?;

    Ok(CopySecretResult {
        from_profile: selection.from_profile.name,
        to_profile: selection.to_profile.name,
        from_source: selection.from_source,
        to_source: selection.to_source,
        target_version: target.version,
        operation,
    })
}

fn select_copy_profiles_and_sources(
    store: &Store,
    project_id: &str,
    name: &str,
    args: &CopyArgs,
) -> Result<CopySelection, CliError> {
    let from_profile_name = ProfileName::new(args.from.clone())
        .map_err(|_| CliError::Config("invalid source profile name".to_owned()))?;
    let to_profile_name = ProfileName::new(args.to.clone())
        .map_err(|_| CliError::Config("invalid target profile name".to_owned()))?;
    let from_profile = store
        .get_profile_by_name(project_id, from_profile_name.as_str())?
        .ok_or_else(|| CliError::Config("source profile not found".to_owned()))?;
    let to_profile = store
        .get_profile_by_name(project_id, to_profile_name.as_str())?
        .ok_or_else(|| CliError::Config("target profile not found".to_owned()))?;
    let source_secret =
        select_copy_source_secret(store, project_id, &from_profile.id, name, args.from_source)?;
    let from_source = source_secret.source.clone();
    let to_source = select_copy_target_source(
        store,
        project_id,
        &to_profile.id,
        name,
        &from_source,
        args.to_source,
    )?;
    if from_profile.id == to_profile.id && from_source == to_source {
        return Err(CliError::Config(
            "copy source and target are the same profile and source; use rotate".to_owned(),
        ));
    }
    Ok(CopySelection { from_profile, to_profile, source_secret, from_source, to_source })
}

fn copy_audit_metadata(request: CopyAuditMetadata<'_>) -> Value {
    json!({
        "schema_version": 1,
        "action": "SECRET_COPY",
        "status": "SUCCESS",
        "secret_name": request.name,
        "from_profile": &request.from_profile.name,
        "from_profile_id": &request.from_profile.id,
        "from_source": request.from_source,
        "from_version": request.from_version,
        "to_profile": &request.to_profile.name,
        "to_profile_id": &request.to_profile.id,
        "to_source": request.to_source,
        "prior_target_version": request.prior_target_version,
        "target_version": request.target_version,
    })
}

fn write_copied_secret(
    store: &mut Store,
    request: CopyWriteRequest<'_>,
) -> Result<&'static str, CliError> {
    if let Some(target_secret) = request.target.existing.as_ref() {
        store.copy_secret_with_audit(
            SecretCopyTarget::Rotate {
                secret: target_secret,
                deprecation: VersionDeprecation {
                    deprecated_at: request.timestamp,
                    grace_until: None,
                },
            },
            request.version,
            request.blob,
            request.fingerprint,
            Some(request.audit),
        )?;
        return Ok("rotate");
    }

    let secret = SecretRecord {
        id: request.target.secret_id.clone(),
        project_id: request.project_id.to_owned(),
        profile_id: request.to_profile_id.to_owned(),
        name: request.name.to_owned(),
        source: request.to_source.to_owned(),
        origin: "profile-copy".to_owned(),
        current_version: request.target.version,
        state: "active".to_owned(),
        created_at: request.timestamp,
        updated_at: request.timestamp,
        last_rotated_at: None,
        deleted_at: None,
    };
    store.copy_secret_with_audit(
        SecretCopyTarget::Create(&secret),
        request.version,
        request.blob,
        request.fingerprint,
        Some(request.audit),
    )?;
    Ok("create")
}

fn plan_copy_target(
    store: &Store,
    project_id: &str,
    profile_id: &str,
    name: &str,
    source: &str,
) -> Result<CopyTargetPlan, CliError> {
    let existing = store.get_secret_by_source(project_id, profile_id, name, source)?;
    if existing.as_ref().is_some_and(|secret| secret.state == "deleted") {
        return Err(CliError::Config("SecretDeleted: target secret source is deleted".to_owned()));
    }
    let prior_version = existing.as_ref().map(|secret| secret.current_version);
    let version = prior_version.map_or(Ok(1), |version| {
        version.checked_add(1).ok_or_else(|| CliError::Config("secret version overflow".to_owned()))
    })?;
    let secret_id = existing.as_ref().map_or_else(
        || SecretId::generate().map(SecretId::into_string).map_err(|_| CliError::Time),
        |secret| Ok(secret.id.clone()),
    )?;
    Ok(CopyTargetPlan { secret_id, version, prior_version, existing })
}

fn copied_secret_records(
    secret_id: &str,
    version: u32,
    source: &str,
    encrypted: EncryptedSecretValue,
    fingerprint: Vec<u8>,
    timestamp: i64,
) -> (SecretVersionRecord, SecretBlobRecord, SecretFingerprintRecord) {
    (
        SecretVersionRecord {
            secret_id: secret_id.to_owned(),
            version,
            source: source.to_owned(),
            origin: "profile-copy".to_owned(),
            state: "current".to_owned(),
            created_at: timestamp,
            deprecated_at: None,
            grace_until: None,
            purged_at: None,
        },
        SecretBlobRecord {
            secret_id: secret_id.to_owned(),
            version,
            encrypted_dek: encrypted.encrypted_dek,
            ciphertext: encrypted.ciphertext,
            value_nonce: encrypted.value_nonce,
            aad_schema_version: encrypted.aad_schema_version,
            created_at: timestamp,
        },
        SecretFingerprintRecord {
            secret_id: secret_id.to_owned(),
            version,
            fingerprint,
            created_at: timestamp,
        },
    )
}

#[derive(Clone, Copy)]
struct SecretEncryptRequest<'a> {
    project_id: &'a str,
    profile_id: &'a str,
    secret_id: &'a str,
    secret_name: &'a str,
    version: u32,
    value: &'a str,
}

fn encrypt_secret_version(
    context: &RuntimeContext,
    store: &Store,
    request: SecretEncryptRequest<'_>,
) -> Result<(EncryptedSecretValue, Vec<u8>), CliError> {
    let profile_secret_key = load_profile_key(
        context,
        store,
        request.project_id,
        request.profile_id,
        KeyPurpose::ProfileSecret,
    )?;
    let profile_fingerprint_key = load_profile_key(
        context,
        store,
        request.project_id,
        request.profile_id,
        KeyPurpose::ProfileFingerprint,
    )?;
    let value_aad = secret_blob_aad_v1(&locket_crypto::SecretBlobAad::new(
        request.project_id,
        request.profile_id,
        request.secret_id,
        request.secret_name,
        request.version,
    ))?;
    let wrap_aad = key_wrap_aad_v1(&KeyWrapAad::new(
        request.project_id,
        request.secret_id,
        Some(request.profile_id),
        request.version,
        KeyWrapPurpose::SecretDek,
    ))?;
    let encrypted =
        encrypt_secret_value_v1(&profile_secret_key, request.value, &value_aad, &wrap_aad)?;
    let fingerprint = secret_fingerprint_v1(&profile_fingerprint_key, request.value)?;
    Ok((encrypted, fingerprint.to_vec()))
}

fn load_profile_key(
    context: &RuntimeContext,
    store: &Store,
    project_id: &str,
    profile_id: &str,
    purpose: KeyPurpose,
) -> Result<zeroize::Zeroizing<locket_crypto::KeyBytes>, CliError> {
    let (master_key, source) = load_master_key(context, project_id)?;
    match load_profile_key_with_master(store, project_id, profile_id, purpose, &master_key) {
        Ok(key) => Ok(key),
        Err(error) if should_try_passphrase_fallback(source, &error) => {
            if !context.passphrase_store.contains_project(project_id)? {
                return Err(error);
            }
            let fallback_master_key = load_fallback_master_key(context, project_id)?;
            load_profile_key_with_master(
                store,
                project_id,
                profile_id,
                purpose,
                &fallback_master_key,
            )
        }
        Err(error) => Err(error),
    }
}

fn load_profile_key_with_master(
    store: &Store,
    project_id: &str,
    profile_id: &str,
    purpose: KeyPurpose,
    master_key: &locket_crypto::KeyBytes,
) -> Result<zeroize::Zeroizing<locket_crypto::KeyBytes>, CliError> {
    let record = store
        .get_key_by_scope(project_id, Some(profile_id), purpose.as_str())?
        .ok_or_else(|| CliError::Config("profile key is missing".to_owned()))?;
    let wrapping_key = derive_wrapping_key_v1(
        master_key,
        &HkdfWrapInfo::new(project_id, Some(profile_id), purpose),
    )?;
    let aad = key_wrap_aad_v1(&KeyWrapAad::new(
        project_id,
        &record.id,
        Some(profile_id),
        0,
        KeyWrapPurpose::from(purpose),
    ))?;
    let wrapped = WrappedKeyMaterial { ciphertext: record.wrapped_material, nonce: record.nonce };
    Ok(unwrap_key_material_v1(&wrapping_key, &wrapped, &aad)?)
}

fn load_project_key(
    context: &RuntimeContext,
    store: &Store,
    project_id: &str,
    purpose: KeyPurpose,
) -> Result<zeroize::Zeroizing<locket_crypto::KeyBytes>, CliError> {
    load_project_key_with_source(context, store, project_id, purpose).map(|(key, _)| key)
}

fn load_project_key_with_source(
    context: &RuntimeContext,
    store: &Store,
    project_id: &str,
    purpose: KeyPurpose,
) -> Result<(zeroize::Zeroizing<locket_crypto::KeyBytes>, MasterKeySource), CliError> {
    let (master_key, source) = load_master_key(context, project_id)?;
    match load_project_key_with_master(store, project_id, purpose, &master_key) {
        Ok(key) => Ok((key, source)),
        Err(error) if should_try_passphrase_fallback(source, &error) => {
            if !context.passphrase_store.contains_project(project_id)? {
                return Err(error);
            }
            let fallback_master_key = load_fallback_master_key(context, project_id)?;
            let key =
                load_project_key_with_master(store, project_id, purpose, &fallback_master_key)?;
            Ok((key, MasterKeySource::PassphraseFallback))
        }
        Err(error) => Err(error),
    }
}

fn load_master_key_verified_by_project_key(
    context: &RuntimeContext,
    store: &Store,
    project_id: &str,
    purpose: KeyPurpose,
) -> Result<(zeroize::Zeroizing<locket_crypto::KeyBytes>, MasterKeySource), CliError> {
    let (master_key, source) = load_master_key(context, project_id)?;
    match load_project_key_with_master(store, project_id, purpose, &master_key) {
        Ok(_) => Ok((master_key, source)),
        Err(error) if should_try_passphrase_fallback(source, &error) => {
            if !context.passphrase_store.contains_project(project_id)? {
                return Err(error);
            }
            let fallback_master_key = load_fallback_master_key(context, project_id)?;
            load_project_key_with_master(store, project_id, purpose, &fallback_master_key)?;
            Ok((fallback_master_key, MasterKeySource::PassphraseFallback))
        }
        Err(error) => Err(error),
    }
}

fn should_try_passphrase_fallback(source: MasterKeySource, error: &CliError) -> bool {
    source == MasterKeySource::OsKeyStore
        && matches!(
            error,
            CliError::Crypto(
                locket_crypto::CryptoError::DecryptionFailed
                    | locket_crypto::CryptoError::InvalidWrappedKey
            )
        )
}

fn load_project_key_with_master(
    store: &Store,
    project_id: &str,
    purpose: KeyPurpose,
    master_key: &locket_crypto::KeyBytes,
) -> Result<zeroize::Zeroizing<locket_crypto::KeyBytes>, CliError> {
    let record = store
        .get_key_by_scope(project_id, None, purpose.as_str())?
        .ok_or_else(|| CliError::Config("project key is missing".to_owned()))?;
    let wrapping_key =
        derive_wrapping_key_v1(master_key, &HkdfWrapInfo::new(project_id, None, purpose))?;
    let aad = key_wrap_aad_v1(&KeyWrapAad::new(
        project_id,
        &record.id,
        None,
        0,
        KeyWrapPurpose::from(purpose),
    ))?;
    let wrapped = WrappedKeyMaterial { ciphertext: record.wrapped_material, nonce: record.nonce };
    Ok(unwrap_key_material_v1(&wrapping_key, &wrapped, &aad)?)
}

fn secret_audit_metadata(
    action: &str,
    secret_name: &str,
    profile_id: &str,
    source: &str,
    version: Option<u32>,
) -> Value {
    json!({
        "schema_version": 1,
        "action": action,
        "status": "SUCCESS",
        "secret_name": secret_name,
        "profile_id": profile_id,
        "source": source,
        "version": version,
    })
}

struct ValueAccessAudit<'a> {
    context: &'a RuntimeContext,
    resolved: &'a ResolvedSecret,
    action: &'static str,
    status: &'static str,
    access_mode: &'static str,
    ttl_seconds: Option<u64>,
    force: bool,
    clipboard_supported: Option<bool>,
    clipboard_clear_supported: Option<bool>,
    unsupported_reason: Option<&'a str>,
}

fn write_value_access_audit_if_available(request: &ValueAccessAudit<'_>) -> Result<(), CliError> {
    let mut store = open_store(request.context)?;
    let project_id = request.resolved.project.config.project_id.as_str();
    if store.get_project(project_id)?.is_none() {
        return Ok(());
    }
    let Ok(audit_key) = load_project_key(request.context, &store, project_id, KeyPurpose::Audit)
    else {
        return Ok(());
    };
    let metadata = json!({
        "schema_version": 1,
        "action": request.action,
        "status": request.status,
        "secret_name": &request.resolved.secret.name,
        "profile": &request.resolved.profile.name,
        "profile_id": &request.resolved.profile.id,
        "source": &request.resolved.secret.source,
        "version": request.resolved.secret.current_version,
        "access_mode": request.access_mode,
        "ttl_seconds": request.ttl_seconds,
        "force": request.force,
        "clipboard_supported": request.clipboard_supported,
        "clipboard_clear_supported": request.clipboard_clear_supported,
        "unsupported_reason": request.unsupported_reason,
    });
    let audit = AuditWrite {
        project_id,
        profile_id: Some(&request.resolved.profile.id),
        action: request.action,
        status: request.status,
        secret_name: Some(&request.resolved.secret.name),
        command: Some("get"),
        metadata_json: &metadata,
        timestamp: now_unix_nanos()?,
    };
    store.append_audit(audit_key.as_ref(), &audit)?;
    Ok(())
}

fn reveal_ttl_seconds(context: &RuntimeContext) -> Result<u64, CliError> {
    let config = read_user_config(context)?;
    let Some(value) = config_get_value(&config, "reveal.ttl") else {
        return Ok(60);
    };
    let Some(value) = value.as_str() else {
        return Err(CliError::Config("reveal.ttl must be a duration".to_owned()));
    };
    let duration = LocketDuration::from_str(value)
        .map_err(|_| CliError::Config("invalid reveal.ttl duration".to_owned()))?;
    Ok(duration.as_secs().min(300))
}

#[derive(Debug, Eq, PartialEq)]
struct ClipboardCommand {
    program: &'static str,
    args: &'static [&'static str],
}

const CLIPBOARD_COMMANDS: &[ClipboardCommand] = if cfg!(target_os = "macos") {
    &[ClipboardCommand { program: "pbcopy", args: &[] }]
} else if cfg!(target_os = "windows") {
    &[ClipboardCommand { program: "clip", args: &[] }]
} else {
    &[
        ClipboardCommand { program: "wl-copy", args: &[] },
        ClipboardCommand { program: "xclip", args: &["-selection", "clipboard"] },
        ClipboardCommand { program: "xsel", args: &["--clipboard", "--input"] },
    ]
};

fn copy_secret_to_clipboard(value: &str) -> Result<(), String> {
    copy_secret_to_clipboard_with(value, CLIPBOARD_COMMANDS, command_exists)
}

fn copy_secret_to_clipboard_with(
    value: &str,
    commands: &'static [ClipboardCommand],
    exists: impl FnMut(&str) -> bool,
) -> Result<(), String> {
    let Some(command) = select_clipboard_command(commands, exists) else {
        return Err("clipboard command unavailable".to_owned());
    };
    let mut child = ProcessCommand::new(command.program)
        .args(command.args)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "clipboard command failed to start".to_owned())?;
    {
        let Some(mut stdin) = child.stdin.take() else {
            return Err("clipboard command stdin unavailable".to_owned());
        };
        stdin
            .write_all(value.as_bytes())
            .map_err(|_| "clipboard command rejected stdin".to_owned())?;
    }
    let status = child.wait().map_err(|_| "clipboard command did not finish".to_owned())?;
    if !status.success() {
        return Err("clipboard command failed".to_owned());
    }
    Ok(())
}

fn select_clipboard_command(
    commands: &'static [ClipboardCommand],
    mut exists: impl FnMut(&str) -> bool,
) -> Option<&'static ClipboardCommand> {
    commands.iter().find(|command| exists(command.program))
}

fn command_exists(program: &str) -> bool {
    let Some(paths) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&paths).any(|directory| command_exists_in_directory(&directory, program))
}

fn command_exists_in_directory(directory: &Path, program: &str) -> bool {
    let candidate = directory.join(program);
    if candidate.is_file() {
        return true;
    }
    if cfg!(target_os = "windows") {
        let Some(pathext) = std::env::var_os("PATHEXT") else {
            return false;
        };
        return std::env::split_paths(&pathext).any(|extension| {
            let extension = extension.to_string_lossy();
            directory.join(format!("{program}{extension}")).is_file()
        });
    }
    false
}

struct PolicySecretSelection {
    name: String,
    required: bool,
    sources: Vec<String>,
    selected: Option<SecretRecord>,
}

struct ResolvedSecret {
    project: ResolvedProject,
    profile: ProfileRecord,
    secret: SecretRecord,
}

fn resolve_active_secret(context: &RuntimeContext, key: &str) -> Result<ResolvedSecret, CliError> {
    let name = SecretName::new(key.to_owned())
        .map_err(|_| CliError::Config("invalid secret name".to_owned()))?;
    let project = require_project(context)?;
    let store = open_store(context)?;
    let profile = default_profile(&store, &project.config)?;
    let secrets =
        store.list_active_secrets_by_profile(project.config.project_id.as_str(), &profile.id)?;
    let secret = secrets
        .into_iter()
        .filter(|secret| secret.name == name.as_str())
        .max_by_key(|secret| source_precedence(&secret.source))
        .ok_or_else(|| CliError::Config("secret not found".to_owned()))?;
    Ok(ResolvedSecret { project, profile, secret })
}

fn resolve_active_secret_for_source(
    context: &RuntimeContext,
    key: &str,
    source: Option<SecretSourceArg>,
) -> Result<ResolvedSecret, CliError> {
    let resolved = resolve_secret_for_source(context, key, source)?;
    if resolved.secret.state == "deleted" {
        return Err(CliError::Config("secret source is deleted".to_owned()));
    }
    Ok(resolved)
}

fn resolve_secret_for_source(
    context: &RuntimeContext,
    key: &str,
    source: Option<SecretSourceArg>,
) -> Result<ResolvedSecret, CliError> {
    let name = SecretName::new(key.to_owned())
        .map_err(|_| CliError::Config("invalid secret name".to_owned()))?;
    let project = require_project(context)?;
    let store = open_store(context)?;
    let profile = default_profile(&store, &project.config)?;
    let secret = if let Some(source) = source {
        let source = source_arg_to_str(source);
        store
            .get_secret_by_source(
                project.config.project_id.as_str(),
                &profile.id,
                name.as_str(),
                source,
            )?
            .ok_or_else(|| CliError::Config("secret not found".to_owned()))?
    } else {
        let secrets = store.list_secrets_by_name(
            project.config.project_id.as_str(),
            &profile.id,
            name.as_str(),
        )?;
        match secrets.as_slice() {
            [] => return Err(CliError::Config("secret not found".to_owned())),
            [secret] => secret.clone(),
            _ => {
                return Err(CliError::Config(
                    "multiple sources exist for this secret; pass --source".to_owned(),
                ));
            }
        }
    };
    Ok(ResolvedSecret { project, profile, secret })
}

fn select_copy_source_secret(
    store: &Store,
    project_id: &str,
    profile_id: &str,
    name: &str,
    source: Option<SecretSourceArg>,
) -> Result<SecretRecord, CliError> {
    if let Some(source) = source {
        let source = source_arg_to_str(source);
        let secret = store
            .get_secret_by_source(project_id, profile_id, name, source)?
            .ok_or_else(|| CliError::Config("secret not found".to_owned()))?;
        if secret.state == "deleted" {
            return Err(CliError::Config("secret source is deleted".to_owned()));
        }
        return Ok(secret);
    }

    let active = store
        .list_secrets_by_name(project_id, profile_id, name)?
        .into_iter()
        .filter(|secret| secret.state == "active")
        .collect::<Vec<_>>();
    let highest = active
        .iter()
        .map(|secret| source_precedence(&secret.source))
        .max()
        .ok_or_else(|| CliError::Config("secret not found".to_owned()))?;
    let selected = active
        .iter()
        .filter(|secret| source_precedence(&secret.source) == highest)
        .collect::<Vec<_>>();
    match selected.as_slice() {
        [secret] => Ok((*secret).clone()),
        _ => Err(CliError::Config(
            "multiple source candidates have ambiguous precedence; pass --from-source".to_owned(),
        )),
    }
}

fn select_copy_target_source(
    store: &Store,
    project_id: &str,
    profile_id: &str,
    name: &str,
    from_source: &str,
    to_source: Option<SecretSourceArg>,
) -> Result<String, CliError> {
    if let Some(to_source) = to_source {
        return Ok(source_arg_to_str(to_source).to_owned());
    }
    if store.get_secret_by_source(project_id, profile_id, name, from_source)?.is_some() {
        return Ok(from_source.to_owned());
    }
    Ok(source_arg_to_str(SecretSourceArg::UserLocal).to_owned())
}

fn decrypt_current_secret(
    context: &RuntimeContext,
    resolved: &ResolvedSecret,
) -> Result<zeroize::Zeroizing<String>, CliError> {
    let store = open_store(context)?;
    decrypt_secret_version(
        context,
        &store,
        resolved.project.config.project_id.as_str(),
        &resolved.profile.id,
        &resolved.secret,
        resolved.secret.current_version,
    )
}

fn policy_secret_selections(
    store: &Store,
    resolved: &ResolvedProject,
    profile: &ProfileRecord,
    policy: &CommandPolicy,
) -> Result<Vec<PolicySecretSelection>, CliError> {
    let active_by_name =
        active_secrets_by_name(store, resolved.config.project_id.as_str(), &profile.id)?;
    let mut selections = Vec::new();
    for name in &policy.required_secrets {
        selections.push(policy_secret_selection(name.as_str(), true, &active_by_name));
    }
    for name in &policy.optional_secrets {
        selections.push(policy_secret_selection(name.as_str(), false, &active_by_name));
    }
    Ok(selections)
}

fn policy_secret_selection(
    name: &str,
    required: bool,
    active_by_name: &BTreeMap<String, Vec<SecretRecord>>,
) -> PolicySecretSelection {
    let secrets = active_by_name.get(name).cloned().unwrap_or_default();
    let sources = secrets
        .iter()
        .map(|secret| secret.source.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let selected = secrets.into_iter().max_by_key(|secret| source_precedence(&secret.source));
    PolicySecretSelection { name: name.to_owned(), required, sources, selected }
}

fn inspect_conflicts(
    selection: &PolicySecretSelection,
    parent_env: &locket_exec::EnvMap,
    policy: &CommandPolicy,
) -> String {
    let mut conflicts = Vec::new();
    if selection.sources.len() > 1 {
        conflicts.push("multiple-active-sources");
    }
    if parent_env_conflicts_with_secret(parent_env, policy, &selection.name) {
        conflicts.push("environment");
    }
    if conflicts.is_empty() { "none".to_owned() } else { conflicts.join(",") }
}

fn inspect_decision(
    selection: &PolicySecretSelection,
    parent_env: &locket_exec::EnvMap,
    policy: &CommandPolicy,
) -> &'static str {
    if selection.selected.is_none() {
        return if selection.required { "missing-required" } else { "skip-missing" };
    }
    if parent_env_conflicts_with_secret(parent_env, policy, &selection.name) {
        return match policy.override_behavior {
            locket_exec::EnvOverrideMode::Error => "error-conflict",
            locket_exec::EnvOverrideMode::Preserve => "preserve-existing",
            locket_exec::EnvOverrideMode::Locket => "inject-overwrite",
        };
    }
    "inject"
}

fn parent_env_conflicts_with_secret(
    parent_env: &locket_exec::EnvMap,
    policy: &CommandPolicy,
    name: &str,
) -> bool {
    if !parent_env.contains_key(name) {
        return false;
    }
    match policy.env_mode {
        locket_exec::EnvMode::Strict => {
            policy.inherit_env.iter().any(|inherited| inherited == name)
        }
        locket_exec::EnvMode::Minimal => {
            locket_exec::DEFAULT_SAFE_ALLOWLIST.contains(&name)
                || policy.inherit_env.iter().any(|inherited| inherited == name)
        }
        locket_exec::EnvMode::Merge | locket_exec::EnvMode::Passthrough => true,
    }
}

fn decrypt_secret_version(
    context: &RuntimeContext,
    store: &Store,
    project_id: &str,
    profile_id: &str,
    secret: &SecretRecord,
    version: u32,
) -> Result<zeroize::Zeroizing<String>, CliError> {
    let profile_secret_key =
        load_profile_key(context, store, project_id, profile_id, KeyPurpose::ProfileSecret)?;
    let blob = store
        .get_blob(&secret.id, version)?
        .ok_or_else(|| CliError::Config("secret blob is missing".to_owned()))?;
    let value_aad = secret_blob_aad_v1(&locket_crypto::SecretBlobAad::new(
        project_id,
        profile_id,
        &secret.id,
        &secret.name,
        version,
    ))?;
    let wrap_aad = key_wrap_aad_v1(&KeyWrapAad::new(
        project_id,
        &secret.id,
        Some(profile_id),
        version,
        KeyWrapPurpose::SecretDek,
    ))?;
    let encrypted = EncryptedSecretValue {
        encrypted_dek: blob.encrypted_dek,
        ciphertext: blob.ciphertext,
        value_nonce: blob.value_nonce,
        aad_schema_version: blob.aad_schema_version,
    };
    Ok(decrypt_secret_value_v1(&profile_secret_key, &encrypted, &value_aad, &wrap_aad)?)
}

fn collect_known_secret_values(
    context: &RuntimeContext,
    project: &ResolvedProject,
    timestamp: i64,
) -> Result<Vec<zeroize::Zeroizing<String>>, CliError> {
    let store = open_store(context)?;
    let mut values = Vec::new();
    for profile in store.list_profiles(project.config.project_id.as_str())? {
        for secret in
            store.list_secrets_by_profile(project.config.project_id.as_str(), &profile.id)?
        {
            for version in store.list_secret_versions(&secret.id)? {
                if should_scan_known_version(&secret, &version, timestamp)
                    && store.get_blob(&secret.id, version.version)?.is_some()
                {
                    values.push(decrypt_secret_version(
                        context,
                        &store,
                        project.config.project_id.as_str(),
                        &profile.id,
                        &secret,
                        version.version,
                    )?);
                }
            }
        }
    }
    Ok(values)
}

struct KnownSecretRedaction {
    value: zeroize::Zeroizing<String>,
    marker: String,
}

fn collect_known_secret_redactions(
    context: &RuntimeContext,
    project: &ResolvedProject,
    redact_names: bool,
    timestamp: i64,
) -> Result<Vec<KnownSecretRedaction>, CliError> {
    let store = open_store(context)?;
    let profile = default_profile(&store, &project.config)?;
    let mut values = Vec::new();
    for secret in store.list_secrets_by_profile(project.config.project_id.as_str(), &profile.id)? {
        let marker = known_secret_redaction_marker(&secret, redact_names);
        for version in store.list_secret_versions(&secret.id)? {
            if should_scan_known_version(&secret, &version, timestamp)
                && store.get_blob(&secret.id, version.version)?.is_some()
            {
                values.push(KnownSecretRedaction {
                    value: decrypt_secret_version(
                        context,
                        &store,
                        project.config.project_id.as_str(),
                        &profile.id,
                        &secret,
                        version.version,
                    )?,
                    marker: marker.clone(),
                });
            }
        }
    }
    Ok(values)
}

fn known_secret_redaction_marker(secret: &SecretRecord, redact_names: bool) -> String {
    let label =
        if redact_names { privacy_alias("secret", &secret.id) } else { secret.name.clone() };
    format!("lk_redacted_{label}")
}

fn privacy_alias(kind: &str, id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"locket-privacy-alias-v1");
    hasher.update(format!("kind:{kind};id:{id}").as_bytes());
    let digest = hasher.finalize();
    format!("{kind}-{:02x}{:02x}{:02x}{:02x}", digest[0], digest[1], digest[2], digest[3])
}

fn should_scan_known_version(
    secret: &SecretRecord,
    version: &SecretVersionRecord,
    timestamp: i64,
) -> bool {
    match version.state.as_str() {
        "current" => secret.state == "active" || version.version == secret.current_version,
        "deprecated" => version.grace_until.is_some_and(|grace_until| grace_until > timestamp),
        _ => false,
    }
}

fn trust_root(
    store: &Store,
    config: &ProjectConfig,
    root: &Path,
    timestamp: i64,
) -> Result<(), CliError> {
    let hash = root_hash(root)?;
    let display_path = root.to_string_lossy();
    store.trust_project_root(
        config.project_id.as_str(),
        &hash,
        Some(display_path.as_ref()),
        timestamp,
    )?;
    Ok(())
}

fn open_store(context: &RuntimeContext) -> Result<Store, CliError> {
    if let Some(parent) = context.store_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut store = Store::open(&context.store_path)?;
    store.initialize_schema()?;
    Ok(store)
}

fn ensure_project_exists(store: &Store, project_id: &str) -> Result<(), CliError> {
    if store.get_project(project_id)?.is_some() {
        return Ok(());
    }
    Err(CliError::Config(
        "project is not present in the local store; run locket init to resume setup".to_owned(),
    ))
}

fn agent_data_dir(context: &RuntimeContext) -> PathBuf {
    context.store_path.parent().map_or_else(|| context.cwd.clone(), Path::to_path_buf)
}

fn agent_socket_path(context: &RuntimeContext) -> PathBuf {
    agent_data_dir(context).join("agent.sock")
}

fn agent_pid_path(context: &RuntimeContext) -> PathBuf {
    agent_data_dir(context).join("agent.pid")
}

fn agent_log_path(context: &RuntimeContext) -> PathBuf {
    agent_data_dir(context).join("agent.log")
}

fn agent_rotated_log_path(context: &RuntimeContext, index: u8) -> PathBuf {
    agent_data_dir(context).join(format!("agent.log.{index}"))
}

fn agent_log_paths_oldest_first(context: &RuntimeContext) -> Vec<PathBuf> {
    let mut paths = (1..=AGENT_LOG_RETAINED_FILES)
        .rev()
        .map(|index| agent_rotated_log_path(context, index))
        .collect::<Vec<_>>();
    paths.push(agent_log_path(context));
    paths
}

fn write_agent_paths(context: &RuntimeContext, output: &mut impl Write) -> Result<(), CliError> {
    writeln!(output, "socket: {}", agent_socket_path(context).display())?;
    writeln!(output, "pid_file: {}", agent_pid_path(context).display())?;
    writeln!(output, "log_file: {}", agent_log_path(context).display())?;
    Ok(())
}

fn read_agent_pid(context: &RuntimeContext) -> Result<Option<String>, CliError> {
    match fs::read_to_string(agent_pid_path(context)) {
        Ok(pid) => {
            let pid = pid.trim();
            Ok(if pid.is_empty() { None } else { Some(pid.to_owned()) })
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn append_agent_log(
    context: &RuntimeContext,
    action: &str,
    status: &str,
    message: &str,
) -> Result<(), CliError> {
    prepare_agent_log_dir(context)?;
    rotate_agent_logs_if_needed(context)?;
    let entry = json!({
        "timestamp": now_unix_nanos()?,
        "severity": "info",
        "component": "agent",
        "action": action,
        "status": status,
        "message": sanitize_agent_log_value(Value::String(message.to_owned())),
    });
    let log_path = agent_log_path(context);
    let mut options = fs::OpenOptions::new();
    options.create(true).append(true);
    set_user_only_file_options(&mut options);
    let mut file = options.open(&log_path)?;
    writeln!(file, "{entry}")?;
    set_user_only_file_permissions(&log_path)?;
    Ok(())
}

fn prepare_agent_log_dir(context: &RuntimeContext) -> Result<(), CliError> {
    let data_dir = agent_data_dir(context);
    fs::create_dir_all(&data_dir)?;
    set_user_only_dir_permissions(&data_dir)?;
    Ok(())
}

fn rotate_agent_logs_if_needed(context: &RuntimeContext) -> Result<(), CliError> {
    let log_path = agent_log_path(context);
    let Ok(metadata) = fs::metadata(&log_path) else {
        return Ok(());
    };
    if metadata.len() < AGENT_LOG_MAX_BYTES {
        return Ok(());
    }
    let oldest = agent_rotated_log_path(context, AGENT_LOG_RETAINED_FILES);
    match fs::remove_file(oldest) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    for index in (1..AGENT_LOG_RETAINED_FILES).rev() {
        let from = agent_rotated_log_path(context, index);
        let to = agent_rotated_log_path(context, index + 1);
        match fs::rename(from, to) {
            Ok(()) => set_user_only_file_permissions(&agent_rotated_log_path(context, index + 1))?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    let rotated = agent_rotated_log_path(context, 1);
    fs::rename(&log_path, &rotated)?;
    set_user_only_file_permissions(&rotated)?;
    Ok(())
}

fn sanitize_agent_log_line(line: &str) -> String {
    serde_json::from_str::<Value>(line).map_or_else(
        |_| redact_text(line).text,
        |value| sanitize_agent_log_value(value).to_string(),
    )
}

fn sanitize_agent_log_value(value: Value) -> Value {
    match value {
        Value::Object(object) => {
            let mut sanitized = serde_json::Map::new();
            for (key, value) in object {
                if agent_log_key_is_forbidden(&key) {
                    continue;
                }
                if agent_log_key_is_path(&key) {
                    if let Some(path) = value.as_str() {
                        let path_hash = privacy_alias("path", path);
                        sanitized.insert(
                            format!("{key}_kind"),
                            Value::String(path_kind(path).to_owned()),
                        );
                        sanitized.insert(format!("{key}_hash"), Value::String(path_hash));
                    }
                    continue;
                }
                sanitized.insert(key, sanitize_agent_log_value(value));
            }
            Value::Object(sanitized)
        }
        Value::Array(values) => {
            Value::Array(values.into_iter().map(sanitize_agent_log_value).collect())
        }
        Value::String(value) => {
            if looks_like_full_path(&value) {
                Value::String(privacy_alias("path", &value))
            } else {
                Value::String(redact_text(&value).text)
            }
        }
        other => other,
    }
}

fn agent_log_key_is_forbidden(key: &str) -> bool {
    let normalized = key.to_ascii_lowercase();
    normalized.contains("secret")
        || normalized.contains("env")
        || normalized.contains("token")
        || normalized.contains("recovery")
        || normalized.contains("wrapped")
        || normalized.contains("private")
        || normalized.contains("credential")
        || normalized.contains("username")
        || normalized.contains("user_name")
        || normalized == "host"
        || normalized == "hostname"
}

fn agent_log_key_is_path(key: &str) -> bool {
    let normalized = key.to_ascii_lowercase();
    normalized == "path" || normalized.ends_with("_path") || normalized.contains("filesystem")
}

fn path_kind(path: &str) -> &'static str {
    if Path::new(path).is_absolute() { "absolute" } else { "relative" }
}

fn looks_like_full_path(value: &str) -> bool {
    Path::new(value).is_absolute()
        || value.contains("\\Users\\")
        || value.contains("\\Program Files\\")
        || value.contains(":/")
}

#[cfg(unix)]
fn set_user_only_file_options(options: &mut fs::OpenOptions) {
    options.mode(0o600);
}

#[cfg(not(unix))]
fn set_user_only_file_options(_options: &mut fs::OpenOptions) {}

#[cfg(unix)]
fn set_user_only_file_permissions(path: &Path) -> Result<(), CliError> {
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_user_only_file_permissions(_path: &Path) -> Result<(), CliError> {
    Ok(())
}

#[cfg(unix)]
fn set_user_only_dir_permissions(path: &Path) -> Result<(), CliError> {
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_user_only_dir_permissions(_path: &Path) -> Result<(), CliError> {
    Ok(())
}

#[derive(Clone, Debug)]
struct ResolvedProject {
    root: PathBuf,
    config: ProjectConfig,
}

fn require_project(context: &RuntimeContext) -> Result<ResolvedProject, CliError> {
    resolve_project(&context.cwd)?.ok_or_else(|| CliError::Config("project not found".to_owned()))
}

fn resolve_project(start: &Path) -> Result<Option<ResolvedProject>, CliError> {
    let mut current = start.canonicalize()?;
    loop {
        let candidate = current.join(LOCKET_TOML);
        if candidate.exists() {
            let config = read_project_config(&candidate)?;
            return Ok(Some(ResolvedProject { root: current, config }));
        }

        if !current.pop() {
            return Ok(None);
        }
    }
}

fn read_project_config(path: &Path) -> Result<ProjectConfig, CliError> {
    let content = fs::read_to_string(path)?;
    let config = toml::from_str::<ProjectConfig>(&content)?;
    Ok(config)
}

fn load_command_policy(
    resolved: &ResolvedProject,
    policy_name: &str,
) -> Result<CommandPolicy, CliError> {
    let policy_document = read_policy_document(&resolved.root.join(LOCKET_TOML))?;
    policy_document
        .commands
        .get(policy_name)
        .cloned()
        .ok_or_else(|| CliError::Config(format!("command policy not found: {policy_name}")))
}

fn read_policy_document(path: &Path) -> Result<PolicyDocument, CliError> {
    let content = fs::read_to_string(path)?;
    PolicyDocument::from_toml_str(&content).map_err(|error| CliError::Config(error.to_string()))
}

const fn command_type(command: &CommandSpec) -> &'static str {
    match command {
        CommandSpec::Argv(_) => "argv",
        CommandSpec::Shell(_) => "shell",
    }
}

fn external_env_source_label(source: &ExternalEnvSource) -> String {
    match source {
        ExternalEnvSource::Parent => "parent".to_owned(),
        ExternalEnvSource::File(path) => format!("file:{}", path.display()),
        ExternalEnvSource::Compose => "compose".to_owned(),
        ExternalEnvSource::Ide => "ide".to_owned(),
    }
}

fn write_project_config(path: &Path, config: &ProjectConfig) -> Result<(), CliError> {
    let content = toml::to_string_pretty(config)?;
    fs::write(path, content)?;
    Ok(())
}

#[derive(Clone, Copy)]
struct ConfigKeySpec {
    key: &'static str,
    kind: ConfigValueKind,
    audit: bool,
}

#[derive(Clone, Copy)]
enum ConfigValueKind {
    Bool,
    Duration,
    DurationMax { max_secs: u64, message: &'static str },
    Enum { values: &'static [&'static str], message: &'static str },
    EditorDefault,
    HttpsUrl,
    RuntimeSessionSecretNameRetention,
}

const UI_THEME_VALUES: &[&str] = &["system", "light", "dark"];
const UI_DENSITY_VALUES: &[&str] = &["comfortable", "compact"];
const SHELL_INTEGRATION_VALUES: &[&str] = &["off", "prompt-only", "hook"];
const UPDATES_CHANNEL_VALUES: &[&str] = &["off", "stable", "beta"];

const CONFIG_KEY_SPECS: &[ConfigKeySpec] = &[
    ConfigKeySpec {
        key: "ui.theme",
        kind: ConfigValueKind::Enum {
            values: UI_THEME_VALUES,
            message: "ui.theme must be system, light, or dark",
        },
        audit: false,
    },
    ConfigKeySpec {
        key: "ui.density",
        kind: ConfigValueKind::Enum {
            values: UI_DENSITY_VALUES,
            message: "ui.density must be comfortable or compact",
        },
        audit: false,
    },
    ConfigKeySpec { key: "privacy.redact_names", kind: ConfigValueKind::Bool, audit: false },
    ConfigKeySpec { key: "editor.default", kind: ConfigValueKind::EditorDefault, audit: false },
    ConfigKeySpec { key: "agent.autostart", kind: ConfigValueKind::Bool, audit: true },
    ConfigKeySpec { key: "agent.unlock_ttl", kind: ConfigValueKind::Duration, audit: true },
    ConfigKeySpec {
        key: "runtime.session_secret_name_retention",
        kind: ConfigValueKind::RuntimeSessionSecretNameRetention,
        audit: true,
    },
    ConfigKeySpec {
        key: "reveal.ttl",
        kind: ConfigValueKind::DurationMax {
            max_secs: 300,
            message: "reveal.ttl must be 5m or less",
        },
        audit: true,
    },
    ConfigKeySpec {
        key: "rotation.max_grace_ttl",
        kind: ConfigValueKind::DurationMax {
            max_secs: 30 * 24 * 60 * 60,
            message: "rotation.max_grace_ttl must be 30d or less",
        },
        audit: true,
    },
    ConfigKeySpec {
        key: "shell.integration",
        kind: ConfigValueKind::Enum {
            values: SHELL_INTEGRATION_VALUES,
            message: "shell.integration must be off, prompt-only, or hook",
        },
        audit: true,
    },
    ConfigKeySpec {
        key: "updates.channel",
        kind: ConfigValueKind::Enum {
            values: UPDATES_CHANNEL_VALUES,
            message: "updates.channel must be off, stable, or beta",
        },
        audit: true,
    },
    ConfigKeySpec { key: "updates.manifest_url", kind: ConfigValueKind::HttpsUrl, audit: true },
    ConfigKeySpec { key: "example.auto_refresh", kind: ConfigValueKind::Bool, audit: false },
    ConfigKeySpec {
        key: "user_verification_required_for.unlock",
        kind: ConfigValueKind::Bool,
        audit: true,
    },
    ConfigKeySpec {
        key: "user_verification_required_for.reveal",
        kind: ConfigValueKind::Bool,
        audit: true,
    },
    ConfigKeySpec {
        key: "user_verification_required_for.copy",
        kind: ConfigValueKind::Bool,
        audit: true,
    },
    ConfigKeySpec {
        key: "user_verification_required_for.dangerous_profile_switch",
        kind: ConfigValueKind::Bool,
        audit: true,
    },
    ConfigKeySpec {
        key: "user_verification_required_for.recovery",
        kind: ConfigValueKind::Bool,
        audit: true,
    },
    ConfigKeySpec {
        key: "user_verification_required_for.team_accept",
        kind: ConfigValueKind::Bool,
        audit: true,
    },
    ConfigKeySpec {
        key: "user_verification_required_for.device_register",
        kind: ConfigValueKind::Bool,
        audit: true,
    },
];

fn validate_config_key(key: &str) -> Result<&'static ConfigKeySpec, CliError> {
    CONFIG_KEY_SPECS
        .iter()
        .find(|spec| spec.key == key)
        .ok_or_else(|| CliError::Config("unsupported config key".to_owned()))
}

fn validate_config_value_not_secret_like(value: &str) -> Result<(), CliError> {
    let secret_like = scan_text(CONFIG_TOML, value).iter().any(|finding| {
        matches!(finding.kind, FindingKind::HighEntropy | FindingKind::ProviderTokenPattern)
    });
    if secret_like {
        return Err(CliError::Config(
            "config value looks like a secret; refusing to store it".to_owned(),
        ));
    }
    Ok(())
}

fn parse_config_value(spec: &ConfigKeySpec, value: &str) -> Result<toml::Value, CliError> {
    match spec.kind {
        ConfigValueKind::Bool => match value {
            "true" => Ok(toml::Value::Boolean(true)),
            "false" => Ok(toml::Value::Boolean(false)),
            _ => Err(CliError::Config("config value must be true or false".to_owned())),
        },
        ConfigValueKind::Duration => {
            LocketDuration::from_str(value)
                .map_err(|_| CliError::Config("invalid config duration".to_owned()))?;
            Ok(toml::Value::String(value.to_owned()))
        }
        ConfigValueKind::DurationMax { max_secs, message } => {
            let duration = LocketDuration::from_str(value)
                .map_err(|_| CliError::Config("invalid config duration".to_owned()))?;
            if duration.as_secs() > max_secs {
                return Err(CliError::Config(message.to_owned()));
            }
            Ok(toml::Value::String(value.to_owned()))
        }
        ConfigValueKind::Enum { values, message } => {
            if values.contains(&value) {
                Ok(toml::Value::String(value.to_owned()))
            } else {
                Err(CliError::Config(message.to_owned()))
            }
        }
        ConfigValueKind::EditorDefault => {
            validate_editor_default(value)?;
            Ok(toml::Value::String(value.to_owned()))
        }
        ConfigValueKind::HttpsUrl => {
            validate_https_url(value)?;
            Ok(toml::Value::String(value.to_owned()))
        }
        ConfigValueKind::RuntimeSessionSecretNameRetention => {
            RuntimeSessionSecretNameRetention::from_str(value).map_err(|_| {
                CliError::Config(
                    "runtime.session_secret_name_retention must be a duration or off".to_owned(),
                )
            })?;
            Ok(toml::Value::String(value.to_owned()))
        }
    }
}

fn validate_stored_config_value(spec: &ConfigKeySpec, value: &toml::Value) -> Result<(), CliError> {
    match spec.kind {
        ConfigValueKind::Bool => {
            if value.as_bool().is_some() {
                Ok(())
            } else {
                Err(invalid_stored_config_value(spec.key))
            }
        }
        ConfigValueKind::Duration
        | ConfigValueKind::DurationMax { .. }
        | ConfigValueKind::Enum { .. }
        | ConfigValueKind::EditorDefault
        | ConfigValueKind::HttpsUrl
        | ConfigValueKind::RuntimeSessionSecretNameRetention => {
            let Some(value) = value.as_str() else {
                return Err(invalid_stored_config_value(spec.key));
            };
            parse_config_value(spec, value)
                .map(|_| ())
                .map_err(|_| invalid_stored_config_value(spec.key))
        }
    }
}

fn invalid_stored_config_value(key: &str) -> CliError {
    CliError::Config(format!("invalid stored config value for {key}"))
}

fn validate_editor_default(value: &str) -> Result<(), CliError> {
    if value.is_empty() || value.chars().any(char::is_control) {
        return Err(CliError::Config(
            "editor.default must be a command name or absolute path".to_owned(),
        ));
    }
    if value.starts_with('~') || value.contains('$') || value.contains('`') {
        return Err(CliError::Config("editor.default must not use shell expansion".to_owned()));
    }
    if Path::new(value).is_absolute() {
        return Ok(());
    }
    let shell_meta = ['/', '\\', '|', '&', ';', '<', '>', '(', ')'];
    if value.chars().any(char::is_whitespace) || value.chars().any(|c| shell_meta.contains(&c)) {
        return Err(CliError::Config(
            "editor.default must be a command name or absolute path".to_owned(),
        ));
    }
    Ok(())
}

fn validate_https_url(value: &str) -> Result<(), CliError> {
    let Some(rest) = value.strip_prefix("https://") else {
        return Err(CliError::Config("updates.manifest_url must be an HTTPS URL".to_owned()));
    };
    if rest.is_empty()
        || value.chars().any(char::is_whitespace)
        || value.chars().any(char::is_control)
    {
        return Err(CliError::Config("updates.manifest_url must be an HTTPS URL".to_owned()));
    }
    let host = rest.split(['/', '?', '#']).next().unwrap_or_default();
    if host.is_empty() || host.starts_with(':') || host.contains('@') {
        return Err(CliError::Config("updates.manifest_url must be an HTTPS URL".to_owned()));
    }
    Ok(())
}

fn read_user_config(runtime: &RuntimeContext) -> Result<toml::Table, CliError> {
    let toml_text = match fs::read_to_string(&runtime.config_path) {
        Ok(toml_text) => toml_text,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(toml::Table::new()),
        Err(error) => return Err(error.into()),
    };
    Ok(toml::from_str::<toml::Table>(&toml_text)?)
}

fn write_user_config(runtime: &RuntimeContext, config: &toml::Table) -> Result<(), CliError> {
    if let Some(parent) = runtime.config_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let toml_text = toml::to_string_pretty(config)?;
    fs::write(&runtime.config_path, toml_text)?;
    Ok(())
}

fn config_get_value<'a>(config: &'a toml::Table, key: &str) -> Option<&'a toml::Value> {
    let (section, name) = split_config_key(key)?;
    config.get(section)?.as_table()?.get(name)
}

fn config_set_value(
    config: &mut toml::Table,
    key: &str,
    value: toml::Value,
) -> Result<(), CliError> {
    let (section, name) = split_config_key(key)
        .ok_or_else(|| CliError::Config("unsupported config key".to_owned()))?;
    let section_value =
        config.entry(section.to_owned()).or_insert_with(|| toml::Value::Table(toml::Table::new()));
    let Some(section_table) = section_value.as_table_mut() else {
        return Err(CliError::Config("config section is not a table".to_owned()));
    };
    section_table.insert(name.to_owned(), value);
    Ok(())
}

fn config_unset_value(config: &mut toml::Table, key: &str) -> Result<(), CliError> {
    let (section, name) = split_config_key(key)
        .ok_or_else(|| CliError::Config("unsupported config key".to_owned()))?;
    let should_remove_section = if let Some(section_value) = config.get_mut(section) {
        let Some(section_table) = section_value.as_table_mut() else {
            return Err(CliError::Config("config section is not a table".to_owned()));
        };
        section_table.remove(name);
        section_table.is_empty()
    } else {
        false
    };
    if should_remove_section {
        config.remove(section);
    }
    Ok(())
}

fn split_config_key(key: &str) -> Option<(&str, &str)> {
    let (section, name) = key.split_once('.')?;
    if section.is_empty() || name.is_empty() || name.contains('.') {
        return None;
    }
    Some((section, name))
}

fn format_config_value(value: &toml::Value) -> String {
    match value {
        toml::Value::Boolean(value) => value.to_string(),
        toml::Value::String(value) => value.clone(),
        _ => value.to_string(),
    }
}

fn write_config_update_audit_if_available(
    context: &RuntimeContext,
    key: &str,
    operation: &str,
) -> Result<(), CliError> {
    let Some(resolved) = resolve_project(&context.cwd)? else {
        return Ok(());
    };
    let mut store = open_store(context)?;
    if store.get_project(resolved.config.project_id.as_str())?.is_none() {
        return Ok(());
    }
    let Ok(audit_key) =
        load_project_key(context, &store, resolved.config.project_id.as_str(), KeyPurpose::Audit)
    else {
        return Ok(());
    };
    let metadata = json!({
        "schema_version": 1,
        "action": "CONFIG_UPDATE",
        "status": "SUCCESS",
        "operation": operation,
        "key": key,
        "value": "hidden",
    });
    let audit = AuditWrite {
        project_id: resolved.config.project_id.as_str(),
        profile_id: None,
        action: "CONFIG_UPDATE",
        status: "SUCCESS",
        secret_name: None,
        command: Some("config"),
        metadata_json: &metadata,
        timestamp: now_unix_nanos()?,
    };
    store.append_audit(audit_key.as_ref(), &audit)?;
    Ok(())
}

fn write_runtime_policy_audit_if_available(
    context: &RuntimeContext,
    resolved: &ResolvedProject,
    profile: &ProfileRecord,
    policy: &CommandPolicy,
    status: &str,
    selections: &[PolicySecretSelection],
) -> Result<(), CliError> {
    let mut store = open_store(context)?;
    if store.get_project(resolved.config.project_id.as_str())?.is_none() {
        return Ok(());
    }
    let Ok(audit_key) =
        load_project_key(context, &store, resolved.config.project_id.as_str(), KeyPurpose::Audit)
    else {
        return Ok(());
    };
    let secret_names = selections
        .iter()
        .filter(|selection| selection.selected.is_some())
        .map(|selection| selection.name.as_str())
        .collect::<Vec<_>>();
    let external_sources =
        policy.external_env_sources.iter().map(external_env_source_label).collect::<Vec<_>>();
    let metadata = json!({
        "schema_version": 1,
        "action": "RUN_POLICY",
        "status": status,
        "policy": policy.name,
        "command_type": command_type(&policy.command),
        "env_mode": policy.env_mode.to_string(),
        "override": policy.override_behavior.to_string(),
        "secret_names": secret_names,
        "external_env_sources": external_sources,
    });
    let audit = AuditWrite {
        project_id: resolved.config.project_id.as_str(),
        profile_id: Some(&profile.id),
        action: "RUN_POLICY",
        status,
        secret_name: None,
        command: Some("run"),
        metadata_json: &metadata,
        timestamp: now_unix_nanos()?,
    };
    store.append_audit(audit_key.as_ref(), &audit)?;
    Ok(())
}

fn write_docker_policy_audit_if_available(
    context: &RuntimeContext,
    prepared: &PreparedDockerPolicyExecution,
    status: &str,
) -> Result<(), CliError> {
    let mut store = open_store(context)?;
    if store.get_project(prepared.resolved.config.project_id.as_str())?.is_none() {
        return Ok(());
    }
    let Ok(audit_key) = load_project_key(
        context,
        &store,
        prepared.resolved.config.project_id.as_str(),
        KeyPurpose::Audit,
    ) else {
        return Ok(());
    };
    let metadata = docker_policy_audit_metadata(prepared, status);
    let audit = AuditWrite {
        project_id: prepared.resolved.config.project_id.as_str(),
        profile_id: Some(&prepared.profile.id),
        action: "RUN",
        status,
        secret_name: None,
        command: Some(docker_helper_command_label(prepared.helper_kind)),
        metadata_json: &metadata,
        timestamp: now_unix_nanos()?,
    };
    store.append_audit(audit_key.as_ref(), &audit)?;
    Ok(())
}

fn docker_policy_audit_metadata(prepared: &PreparedDockerPolicyExecution, status: &str) -> Value {
    json!({
        "schema_version": 1,
        "action": "RUN",
        "status": status,
        "policy": prepared.policy.name,
        "helper": docker_helper_command_label(prepared.helper_kind),
        "delivery_mode": docker_delivery_mode_label(prepared.plan.delivery_mode),
        "docker_context_class": docker_context_class_label(prepared.plan.context_class),
        "argv_program": prepared.plan.argv.first().map_or("", String::as_str),
        "arg_count": prepared.plan.argv.len(),
        "secret_names": prepared.plan.injected_names,
    })
}

const fn docker_helper_command_label(kind: DockerHelperKind) -> &'static str {
    match kind {
        DockerHelperKind::DockerRun => "env docker",
        DockerHelperKind::Compose => "compose run",
    }
}

const fn docker_delivery_mode_label(mode: locket_docker::DockerDeliveryMode) -> &'static str {
    match mode {
        locket_docker::DockerDeliveryMode::EnvironmentNames => "environment_names",
        locket_docker::DockerDeliveryMode::EphemeralEnvFile => "ephemeral_env_file",
    }
}

const fn docker_context_class_label(class: locket_docker::DockerContextClass) -> &'static str {
    match class {
        locket_docker::DockerContextClass::Local => "local",
        locket_docker::DockerContextClass::Remote => "remote",
        locket_docker::DockerContextClass::Unknown => "unknown",
    }
}

fn write_example_emit_audit(
    context: &RuntimeContext,
    store: &mut Store,
    resolved: &ResolvedProject,
    result: &ExampleWriteResult,
) -> Result<(), CliError> {
    if store.get_project(resolved.config.project_id.as_str())?.is_none() {
        return Ok(());
    }
    let audit_key =
        load_project_key(context, store, resolved.config.project_id.as_str(), KeyPurpose::Audit)?;
    let path_hash = Sha256::digest(EXAMPLE_FILE.as_bytes());
    let metadata = json!({
        "schema_version": 1,
        "action": "EXAMPLE_EMIT",
        "status": "SUCCESS",
        "path_kind": "project_env_example",
        "path_hash": format_hex(&path_hash),
        "secret_name_count": result.secret_name_count,
        "marker_only": !result.replaced_unmanaged,
        "replaced_unmanaged": result.replaced_unmanaged,
    });
    let audit = AuditWrite {
        project_id: resolved.config.project_id.as_str(),
        profile_id: None,
        action: "EXAMPLE_EMIT",
        status: "SUCCESS",
        secret_name: None,
        command: Some("emit-example"),
        metadata_json: &metadata,
        timestamp: now_unix_nanos()?,
    };
    store.append_audit(audit_key.as_ref(), &audit)?;
    Ok(())
}

fn ensure_gitignore(root: &Path) -> Result<(), CliError> {
    let path = root.join(GITIGNORE_FILE);
    let existing = match fs::read_to_string(&path) {
        Ok(content) => content,
        Err(error) if error.kind() == io::ErrorKind::NotFound => String::new(),
        Err(error) => return Err(error.into()),
    };

    let mut content = existing.clone();
    for entry in GITIGNORE_ENTRIES {
        if !existing.lines().any(|line| line.trim() == entry) {
            if !content.is_empty() && !content.ends_with('\n') {
                content.push('\n');
            }
            content.push_str(entry);
            content.push('\n');
        }
    }

    if content != existing {
        fs::write(path, content)?;
    }
    Ok(())
}

fn ensure_example_file(root: &Path) -> Result<(), CliError> {
    let path = root.join(EXAMPLE_FILE);
    let names = BTreeSet::new();
    let managed_block = managed_example_block(&names);
    let existing = match fs::read_to_string(&path) {
        Ok(content) => content,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::write(path, managed_block)?;
            return Ok(());
        }
        Err(error) => return Err(error.into()),
    };

    let Some(begin) = existing.find(EXAMPLE_BEGIN) else {
        return Err(CliError::Config(
            ".env.example exists without Locket managed markers; refusing silent overwrite"
                .to_owned(),
        ));
    };
    let Some(relative_end) = existing[begin..].find(EXAMPLE_END) else {
        return Err(CliError::Config(
            ".env.example has an unterminated Locket managed block".to_owned(),
        ));
    };
    let end = begin + relative_end + EXAMPLE_END.len();
    let mut updated = String::new();
    updated.push_str(&existing[..begin]);
    updated.push_str(&managed_block);
    updated.push_str(&existing[end..]);

    if updated != existing {
        fs::write(path, updated)?;
    }
    Ok(())
}

#[derive(Debug)]
struct ExampleWriteResult {
    path: PathBuf,
    secret_name_count: usize,
    replaced_unmanaged: bool,
}

fn refresh_example_for_project_if_enabled(context: &RuntimeContext) -> Result<(), CliError> {
    let resolved = require_project(context)?;
    if !example_auto_refresh_enabled(context, &resolved)? {
        return Ok(());
    }
    refresh_example_for_resolved(context, &resolved)?;
    Ok(())
}

fn example_auto_refresh_enabled(
    context: &RuntimeContext,
    resolved: &ResolvedProject,
) -> Result<bool, CliError> {
    let project_config = read_config_table(&resolved.root.join(LOCKET_TOML))?;
    if let Some(value) = config_bool_value(&project_config, "example.auto_refresh")? {
        return Ok(value);
    }
    let user_config = read_user_config(context)?;
    Ok(config_bool_value(&user_config, "example.auto_refresh")?.unwrap_or(true))
}

fn read_config_table(path: &Path) -> Result<toml::Table, CliError> {
    let text = fs::read_to_string(path)?;
    toml::from_str::<toml::Table>(&text).map_err(CliError::from)
}

fn config_bool_value(config: &toml::Table, key: &str) -> Result<Option<bool>, CliError> {
    let Some((section, name)) = split_config_key(key) else {
        return Err(CliError::Config("unsupported config key".to_owned()));
    };
    let Some(section_value) = config.get(section) else {
        return Ok(None);
    };
    let Some(section_table) = section_value.as_table() else {
        return Err(CliError::Config(format!("config section {section:?} must be a table")));
    };
    let Some(value) = section_table.get(name) else {
        return Ok(None);
    };
    value
        .as_bool()
        .map(Some)
        .ok_or_else(|| CliError::Config(format!("config key {key:?} must be boolean")))
}

fn refresh_example_for_resolved(
    context: &RuntimeContext,
    resolved: &ResolvedProject,
) -> Result<ExampleWriteResult, CliError> {
    let store = open_store(context)?;
    let names = collect_example_secret_names(&store, resolved)?;
    write_example_block(&resolved.root, &names)
}

fn collect_example_secret_names(
    store: &Store,
    resolved: &ResolvedProject,
) -> Result<BTreeSet<String>, CliError> {
    let mut names = BTreeSet::new();
    for profile in store.list_profiles(resolved.config.project_id.as_str())? {
        for secret in store
            .list_active_secrets_by_profile(resolved.config.project_id.as_str(), &profile.id)?
        {
            names.insert(secret.name);
        }
    }
    Ok(names)
}

fn write_example_block(
    root: &Path,
    names: &BTreeSet<String>,
) -> Result<ExampleWriteResult, CliError> {
    let path = root.join(EXAMPLE_FILE);
    write_example_block_with_policy(&path, names, UnmanagedExamplePolicy::Refuse, None)
}

fn write_example_block_for_emit(
    root: &Path,
    names: &BTreeSet<String>,
    output: &mut impl Write,
) -> Result<ExampleWriteResult, CliError> {
    let path = root.join(EXAMPLE_FILE);
    write_example_block_with_policy(
        &path,
        names,
        UnmanagedExamplePolicy::Confirm,
        Some(output as &mut dyn Write),
    )
}

#[derive(Clone, Copy)]
enum UnmanagedExamplePolicy {
    Refuse,
    Confirm,
}

fn write_example_block_with_policy(
    path: &Path,
    names: &BTreeSet<String>,
    unmanaged_policy: UnmanagedExamplePolicy,
    output: Option<&mut dyn Write>,
) -> Result<ExampleWriteResult, CliError> {
    let managed_block = managed_example_block(names);
    let existing = match fs::read_to_string(path) {
        Ok(content) => content,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::write(path, managed_block)?;
            return Ok(ExampleWriteResult {
                path: path.to_path_buf(),
                secret_name_count: names.len(),
                replaced_unmanaged: false,
            });
        }
        Err(error) => return Err(error.into()),
    };
    let Some(begin) = existing.find(EXAMPLE_BEGIN) else {
        return replace_unmanaged_example(path, names, &managed_block, unmanaged_policy, output);
    };
    let Some(relative_end) = existing[begin..].find(EXAMPLE_END) else {
        return Err(CliError::Config(
            ".env.example has an unterminated Locket managed block".to_owned(),
        ));
    };
    let end = begin + relative_end + EXAMPLE_END.len();
    let mut updated = String::new();
    updated.push_str(&existing[..begin]);
    updated.push_str(&managed_block);
    updated.push_str(&existing[end..]);
    if updated != existing {
        fs::write(path, updated)?;
    }
    Ok(ExampleWriteResult {
        path: path.to_path_buf(),
        secret_name_count: names.len(),
        replaced_unmanaged: false,
    })
}

fn replace_unmanaged_example(
    path: &Path,
    names: &BTreeSet<String>,
    managed_block: &str,
    unmanaged_policy: UnmanagedExamplePolicy,
    output: Option<&mut dyn Write>,
) -> Result<ExampleWriteResult, CliError> {
    match unmanaged_policy {
        UnmanagedExamplePolicy::Refuse => Err(CliError::Config(
            ".env.example exists without Locket managed markers; refusing automatic overwrite"
                .to_owned(),
        )),
        UnmanagedExamplePolicy::Confirm => {
            let Some(output) = output else {
                return Err(CliError::Config(
                    ".env.example replacement requires interactive confirmation".to_owned(),
                ));
            };
            writeln!(output, ".env.example: unmanaged")?;
            writeln!(output, "secret_name_count: {}", names.len())?;
            writeln!(output, "metadata_only: yes")?;
            if !io::stdin().is_terminal() {
                return Err(CliError::Config(
                    ".env.example replacement requires interactive confirmation".to_owned(),
                ));
            }
            writeln!(output, "type 'replace .env.example' to replace the unmanaged file")?;
            let mut confirmation = String::new();
            io::stdin().read_line(&mut confirmation)?;
            if confirmation.trim_end() != "replace .env.example" {
                return Err(CliError::Config("confirmation did not match".to_owned()));
            }
            fs::write(path, managed_block)?;
            Ok(ExampleWriteResult {
                path: path.to_path_buf(),
                secret_name_count: names.len(),
                replaced_unmanaged: true,
            })
        }
    }
}

fn managed_example_block(names: &BTreeSet<String>) -> String {
    let mut block = format!("{EXAMPLE_BEGIN}\n");
    for name in names {
        block.push_str(name);
        block.push_str("=\n");
    }
    block.push_str(EXAMPLE_END);
    block.push('\n');
    block
}

fn scan_path(
    root: &Path,
    path: &Path,
    known_values: &[zeroize::Zeroizing<String>],
    use_gitignore: bool,
    findings: &mut Vec<ScanFinding>,
) -> Result<(), CliError> {
    if path.is_dir() {
        let mut builder = WalkBuilder::new(path);
        builder
            .add_custom_ignore_filename(LOCKETIGNORE_FILE)
            .filter_entry(|entry| !should_skip_scan_path(entry.path()))
            .hidden(false)
            .git_ignore(use_gitignore)
            .git_global(use_gitignore)
            .git_exclude(use_gitignore);
        for entry in builder.build() {
            let entry = entry.map_err(|error| CliError::Config(error.to_string()))?;
            let child = entry.path();
            if child == path || !child.is_file() {
                continue;
            }
            scan_file(root, child, known_values, findings)?;
        }
        return Ok(());
    }

    scan_file(root, path, known_values, findings)
}

fn scan_file(
    root: &Path,
    path: &Path,
    known_values: &[zeroize::Zeroizing<String>],
    findings: &mut Vec<ScanFinding>,
) -> Result<(), CliError> {
    if !path.is_file() {
        return Ok(());
    }

    let label = path_label(root, path);
    match fs::read_to_string(path) {
        Ok(text) => {
            findings.extend(scan_text(&label, &text));
            findings.extend(scan_known_values(&label, &text, known_values));
        }
        Err(error) if error.kind() == io::ErrorKind::InvalidData => {
            findings.extend(scan_text(&label, ""));
        }
        Err(error) => return Err(error.into()),
    }

    Ok(())
}

fn scan_staged_path(
    git_root: &Path,
    known_values: &[zeroize::Zeroizing<String>],
    findings: &mut Vec<ScanFinding>,
) -> Result<(), CliError> {
    let locket_ignore = locket_ignore(git_root)?;
    let staged_paths =
        git_output(git_root, ["diff", "--cached", "--name-only", "-z", "--diff-filter=ACMRT"])?;

    for path_bytes in staged_paths.split(|byte| *byte == 0).filter(|path| !path.is_empty()) {
        let path = String::from_utf8_lossy(path_bytes);
        if locket_ignore.matched_path_or_any_parents(path.as_ref(), false).is_ignore() {
            continue;
        }
        if should_skip_scan_path(Path::new(path.as_ref())) {
            continue;
        }

        let spec = format!(":{path}");
        let object_type =
            String::from_utf8_lossy(&git_output(git_root, ["cat-file", "-t", &spec])?)
                .trim()
                .to_owned();
        if object_type != "blob" {
            continue;
        }

        let contents = git_output(git_root, ["cat-file", "-p", &spec])?;
        match String::from_utf8(contents) {
            Ok(text) => {
                findings.extend(scan_text(&path, &text));
                findings.extend(scan_known_values(&path, &text, known_values));
            }
            Err(_) => findings.extend(scan_text(&path, "")),
        }
    }

    Ok(())
}

fn locket_ignore(git_root: &Path) -> Result<ignore::gitignore::Gitignore, CliError> {
    let mut builder = GitignoreBuilder::new(git_root);
    let path = git_root.join(LOCKETIGNORE_FILE);
    if path.exists()
        && let Some(error) = builder.add(path)
    {
        return Err(CliError::Config(error.to_string()));
    }
    builder.build().map_err(|error| CliError::Config(error.to_string()))
}

fn scan_known_values(
    path_label: &str,
    text: &str,
    known_values: &[zeroize::Zeroizing<String>],
) -> Vec<ScanFinding> {
    let mut findings = Vec::new();
    for known_value in known_values {
        if known_value.is_empty() {
            continue;
        }
        let mut cursor = 0;
        while let Some(relative) = text[cursor..].find(known_value.as_str()) {
            let start = cursor + relative;
            let (line, column) = line_column_for_byte(text, start);
            findings.push(ScanFinding {
                path_label: path_label.to_owned(),
                line,
                column,
                token_length: known_value.len(),
                kind: FindingKind::KnownSecretValue,
            });
            cursor = start + known_value.len();
        }
    }
    findings
}

fn line_column_for_byte(text: &str, byte_index: usize) -> (usize, usize) {
    let mut line = 1;
    let mut column = 1;
    for (index, character) in text.char_indices() {
        if index >= byte_index {
            break;
        }
        if character == '\n' {
            line += 1;
            column = 1;
        } else {
            column += 1;
        }
    }
    (line, column)
}

fn should_skip_scan_path(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| matches!(name, ".git" | "target"))
}

fn path_label(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .ok()
        .filter(|relative| !relative.as_os_str().is_empty())
        .unwrap_or(path)
        .to_string_lossy()
        .into_owned()
}

fn format_finding(finding: &ScanFinding) -> String {
    format!(
        "{}:{}:{}: {} token_length={}",
        finding.path_label,
        finding.line,
        finding.column,
        finding_kind_label(finding.kind),
        finding.token_length
    )
}

const fn finding_kind_label(kind: FindingKind) -> &'static str {
    match kind {
        FindingKind::HighEntropy => "high-entropy",
        FindingKind::ProviderTokenPattern => "provider-token-pattern",
        FindingKind::EnvFileMarker => "env-file",
        FindingKind::KnownSecretValue => "known-secret",
    }
}

fn ensure_git_worktree(start: &Path) -> Result<PathBuf, CliError> {
    let mut current = start.canonicalize()?;
    loop {
        if current.join(".git").exists() {
            return Ok(current);
        }
        if !current.pop() {
            return Err(CliError::Config("git worktree required for --staged".to_owned()));
        }
    }
}

fn git_output<I, S>(git_root: &Path, args: I) -> Result<Vec<u8>, CliError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let output = ProcessCommand::new("git").arg("-C").arg(git_root).args(args).output()?;
    if output.status.success() {
        return Ok(output.stdout);
    }

    let message = String::from_utf8_lossy(&output.stderr);
    Err(CliError::Config(format!("git command failed: {}", message.trim())))
}

fn resolve_diff_since(project_root: &Path, value: &str) -> Result<i64, CliError> {
    if let Some(timestamp) = parse_iso8601_utc_nanos(value)? {
        return Ok(timestamp);
    }

    let output = git_output(project_root, ["log", "-1", "--format=%ct", value]).map_err(|error| {
        CliError::Config(format!(
            "could not resolve diff --since value {value:?} as an ISO date/time or Git revision: {error}"
        ))
    })?;
    let seconds = String::from_utf8_lossy(&output)
        .trim()
        .parse::<i64>()
        .map_err(|_| CliError::Config("git revision timestamp was not an integer".to_owned()))?;
    seconds.checked_mul(NANOS_PER_SECOND).ok_or(CliError::Time)
}

fn parse_iso8601_utc_nanos(value: &str) -> Result<Option<i64>, CliError> {
    let value = value.trim();
    if value.len() < 10 || !value.as_bytes().get(0..10).is_some_and(is_iso_date_prefix) {
        return Ok(None);
    }

    let year = parse_i32_digits(&value[0..4])?;
    let month = parse_u32_digits(&value[5..7])?;
    let day = parse_u32_digits(&value[8..10])?;
    validate_ymd(year, month, day)?;

    if value.len() == 10 {
        return unix_nanos_from_iso_parts((year, month, day), (0, 0, 0, 0), 0).map(Some);
    }

    let separator = value.as_bytes()[10];
    if !matches!(separator, b'T' | b't' | b' ') {
        return Ok(None);
    }

    let (time_part, offset_seconds) = split_iso_time_and_offset(&value[11..])?;
    let (hour, minute, second, fractional_nanos) = parse_iso_time(time_part)?;
    unix_nanos_from_iso_parts(
        (year, month, day),
        (hour, minute, second, fractional_nanos),
        offset_seconds,
    )
    .map(Some)
}

fn is_iso_date_prefix(bytes: &[u8]) -> bool {
    bytes.len() == 10
        && bytes[0..4].iter().all(u8::is_ascii_digit)
        && bytes[4] == b'-'
        && bytes[5..7].iter().all(u8::is_ascii_digit)
        && bytes[7] == b'-'
        && bytes[8..10].iter().all(u8::is_ascii_digit)
}

fn split_iso_time_and_offset(value: &str) -> Result<(&str, i64), CliError> {
    if let Some(time) = value.strip_suffix('Z').or_else(|| value.strip_suffix('z')) {
        return Ok((time, 0));
    }
    if let Some(index) = value
        .as_bytes()
        .iter()
        .enumerate()
        .skip(1)
        .find_map(|(index, byte)| matches!(byte, b'+' | b'-').then_some(index))
    {
        let offset = parse_iso_offset_seconds(&value[index..])?;
        return Ok((&value[..index], offset));
    }
    Ok((value, 0))
}

fn parse_iso_time(value: &str) -> Result<(u32, u32, u32, u32), CliError> {
    if value.len() < 8 || &value[2..3] != ":" || &value[5..6] != ":" {
        return Err(CliError::Config("invalid ISO date/time for diff --since".to_owned()));
    }
    let hour = parse_u32_digits(&value[0..2])?;
    let minute = parse_u32_digits(&value[3..5])?;
    let second = parse_u32_digits(&value[6..8])?;
    if hour > 23 || minute > 59 || second > 59 {
        return Err(CliError::Config("invalid ISO date/time for diff --since".to_owned()));
    }
    let fractional_nanos = if value.len() == 8 {
        0
    } else {
        if value.as_bytes().get(8) != Some(&b'.') {
            return Err(CliError::Config("invalid ISO date/time for diff --since".to_owned()));
        }
        parse_fractional_nanos(&value[9..])?
    };
    Ok((hour, minute, second, fractional_nanos))
}

fn parse_fractional_nanos(value: &str) -> Result<u32, CliError> {
    if value.is_empty() || !value.as_bytes().iter().all(u8::is_ascii_digit) {
        return Err(CliError::Config("invalid ISO date/time for diff --since".to_owned()));
    }
    let mut nanos = 0_u32;
    let mut scale = 100_000_000_u32;
    for byte in value.as_bytes().iter().take(9) {
        nanos += u32::from(byte - b'0') * scale;
        scale /= 10;
    }
    Ok(nanos)
}

fn parse_iso_offset_seconds(value: &str) -> Result<i64, CliError> {
    let sign = match value.as_bytes().first() {
        Some(b'+') => 1_i64,
        Some(b'-') => -1_i64,
        _ => return Err(CliError::Config("invalid ISO date/time for diff --since".to_owned())),
    };
    let offset = &value[1..];
    let (hours, minutes) = if offset.len() == 5 && &offset[2..3] == ":" {
        (parse_u32_digits(&offset[0..2])?, parse_u32_digits(&offset[3..5])?)
    } else if offset.len() == 4 {
        (parse_u32_digits(&offset[0..2])?, parse_u32_digits(&offset[2..4])?)
    } else {
        return Err(CliError::Config("invalid ISO date/time for diff --since".to_owned()));
    };
    if hours > 23 || minutes > 59 {
        return Err(CliError::Config("invalid ISO date/time for diff --since".to_owned()));
    }
    Ok(sign * i64::from(hours * 3600 + minutes * 60))
}

fn parse_i32_digits(value: &str) -> Result<i32, CliError> {
    if value.is_empty() || !value.as_bytes().iter().all(u8::is_ascii_digit) {
        return Err(CliError::Config("invalid ISO date/time for diff --since".to_owned()));
    }
    value
        .parse::<i32>()
        .map_err(|_| CliError::Config("invalid ISO date/time for diff --since".to_owned()))
}

fn parse_u32_digits(value: &str) -> Result<u32, CliError> {
    if value.is_empty() || !value.as_bytes().iter().all(u8::is_ascii_digit) {
        return Err(CliError::Config("invalid ISO date/time for diff --since".to_owned()));
    }
    value
        .parse::<u32>()
        .map_err(|_| CliError::Config("invalid ISO date/time for diff --since".to_owned()))
}

fn validate_ymd(year: i32, month: u32, day: u32) -> Result<(), CliError> {
    if !(1..=12).contains(&month) || day == 0 || day > days_in_month(year, month) {
        return Err(CliError::Config("invalid ISO date/time for diff --since".to_owned()));
    }
    Ok(())
}

const fn days_in_month(year: i32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

const fn is_leap_year(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

fn unix_nanos_from_iso_parts(
    date: (i32, u32, u32),
    time: (u32, u32, u32, u32),
    offset_seconds: i64,
) -> Result<i64, CliError> {
    let (year, month, day) = date;
    let (hour, minute, second, fractional_nanos) = time;
    let days = days_from_civil(year, month, day);
    let seconds = days
        .checked_mul(86_400)
        .and_then(|seconds| seconds.checked_add(i64::from(hour * 3_600 + minute * 60 + second)))
        .and_then(|seconds| seconds.checked_sub(offset_seconds))
        .ok_or(CliError::Time)?;
    seconds
        .checked_mul(NANOS_PER_SECOND)
        .and_then(|nanos| nanos.checked_add(i64::from(fractional_nanos)))
        .ok_or(CliError::Time)
}

fn days_from_civil(year: i32, month: u32, day: u32) -> i64 {
    let year = i64::from(year) - i64::from(month <= 2);
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let month = i64::from(month);
    let day = i64::from(day);
    let day_of_year = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

fn absolutize(cwd: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() { path.to_path_buf() } else { cwd.join(path) }
}

fn read_secret_value_from_stdin() -> Result<String, CliError> {
    let mut stdin = io::stdin();
    if stdin.is_terminal() {
        return Err(CliError::Config(
            "secure TTY prompt is not wired in this build; pipe secret value on stdin".to_owned(),
        ));
    }
    let mut value = String::new();
    stdin.read_to_string(&mut value)?;
    if value.ends_with('\n') {
        value.pop();
        if value.ends_with('\r') {
            value.pop();
        }
    }
    if value.is_empty() {
        return Err(CliError::Config("secret value cannot be empty".to_owned()));
    }
    Ok(value)
}

enum EnvImportEntry {
    Secret { key: String, value: String },
    Invalid,
}

fn parse_env_import(content: &str) -> Vec<EnvImportEntry> {
    content
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                return None;
            }
            Some(parse_env_line(trimmed))
        })
        .collect()
}

fn parse_env_line(line: &str) -> EnvImportEntry {
    let line = line.strip_prefix("export ").unwrap_or(line);
    let Some((key, value)) = line.split_once('=') else {
        return EnvImportEntry::Invalid;
    };
    let key = key.trim();
    if SecretName::new(key.to_owned()).is_err() {
        return EnvImportEntry::Invalid;
    }
    let raw_value = value.trim();
    if has_unmatched_env_quote(raw_value) {
        return EnvImportEntry::Invalid;
    }
    let value = unquote_env_value(raw_value);
    if value.contains('\0') {
        return EnvImportEntry::Invalid;
    }
    EnvImportEntry::Secret { key: key.to_owned(), value }
}

const fn has_unmatched_env_quote(value: &str) -> bool {
    let bytes = value.as_bytes();
    matches!(bytes.first(), Some(b'"')) && !matches!(bytes.last(), Some(b'"'))
        || matches!(bytes.first(), Some(b'\'')) && !matches!(bytes.last(), Some(b'\''))
}

fn unquote_env_value(value: &str) -> String {
    if value.len() >= 2 {
        let bytes = value.as_bytes();
        if matches!(
            (bytes.first(), bytes.last()),
            (Some(b'"'), Some(b'"')) | (Some(b'\''), Some(b'\''))
        ) {
            return value[1..value.len() - 1].to_owned();
        }
    }
    value.to_owned()
}

fn grace_until_from_args(value: Option<&str>, timestamp: i64) -> Result<Option<i64>, CliError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let duration = LocketDuration::from_str(value)
        .map_err(|_| CliError::Config("invalid grace TTL duration".to_owned()))?;
    if duration.as_secs() > DEFAULT_MAX_GRACE_TTL_SECONDS {
        return Err(CliError::Config("grace TTL exceeds the default 7d cap".to_owned()));
    }
    let nanos = i64::try_from(duration.as_secs())
        .ok()
        .and_then(|seconds| seconds.checked_mul(NANOS_PER_SECOND))
        .ok_or(CliError::Time)?;
    timestamp.checked_add(nanos).map(Some).ok_or(CliError::Time)
}

fn optional_i64(value: Option<i64>) -> String {
    value.map_or_else(|| "-".to_owned(), |value| value.to_string())
}

const fn metadata_flags_have_updates(metadata: &SecretMetadataFlags) -> bool {
    metadata.description.is_some()
        || metadata.owner.is_some()
        || !metadata.tags.is_empty()
        || metadata.required
        || metadata.optional
}

const fn metadata_required_update(metadata: &SecretMetadataFlags) -> Option<bool> {
    if metadata.required {
        Some(true)
    } else if metadata.optional {
        Some(false)
    } else {
        None
    }
}

fn metadata_update_field_names(metadata: &SecretMetadataFlags) -> Vec<&'static str> {
    let mut fields = Vec::new();
    if metadata.description.is_some() {
        fields.push("description");
    }
    if metadata.owner.is_some() {
        fields.push("owner");
    }
    if !metadata.tags.is_empty() {
        fields.push("tags");
    }
    if metadata.required || metadata.optional {
        fields.push("required");
    }
    fields
}

fn format_versions(versions: &[u32]) -> String {
    versions.iter().map(u32::to_string).collect::<Vec<_>>().join(",")
}

fn active_secret_map(
    store: &Store,
    project_id: &str,
    profile_id: &str,
) -> Result<BTreeMap<(String, String), SecretRecord>, CliError> {
    let secrets = store.list_active_secrets_by_profile(project_id, profile_id)?;
    Ok(secrets
        .into_iter()
        .map(|secret| ((secret.name.clone(), secret.source.clone()), secret))
        .collect())
}

fn active_secrets_by_name(
    store: &Store,
    project_id: &str,
    profile_id: &str,
) -> Result<BTreeMap<String, Vec<SecretRecord>>, CliError> {
    let mut by_name = BTreeMap::<String, Vec<SecretRecord>>::new();
    for secret in store.list_active_secrets_by_profile(project_id, profile_id)? {
        by_name.entry(secret.name.clone()).or_default().push(secret);
    }
    Ok(by_name)
}

const fn source_arg_to_str(source: SecretSourceArg) -> &'static str {
    match source {
        SecretSourceArg::TeamManaged => "team-managed",
        SecretSourceArg::UserLocal => "user-local",
        SecretSourceArg::MachineLocal => "machine-local",
    }
}

const fn source_precedence(source: &str) -> u8 {
    match source.as_bytes() {
        b"team-managed" => 1,
        b"user-local" => 2,
        b"machine-local" => 3,
        _ => 0,
    }
}

fn fallback_project_name(root: &Path) -> String {
    root.file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .map_or_else(|| "locket-project".to_owned(), ToOwned::to_owned)
}

fn detect_shell() -> ShellArg {
    std::env::var("SHELL").map_or(ShellArg::Bash, |shell| shell_arg_from_name(&shell))
}

fn shell_arg_from_name(shell: &str) -> ShellArg {
    let name = Path::new(shell).file_name().and_then(|name| name.to_str()).unwrap_or(shell);
    match name {
        "zsh" => ShellArg::Zsh,
        "fish" => ShellArg::Fish,
        _ => ShellArg::Bash,
    }
}

fn write_shellenv_snippet(output: &mut impl Write, shell: ShellArg) -> Result<(), CliError> {
    match shell {
        ShellArg::Bash | ShellArg::Zsh => {
            writeln!(output, "{SHELL_HOOK_BEGIN}")?;
            writeln!(output, "if [ -z \"${{__LOCKET_SHELLENV_SOURCED:-}}\" ]; then")?;
            writeln!(output, "  export __LOCKET_SHELLENV_SOURCED=1")?;
            writeln!(
                output,
                "  locket_prompt_segment() {{ locket status 2>/dev/null | sed -n 's/^project: //p; s/^default_profile: //p' | paste -sd ' / ' -; }}"
            )?;
            writeln!(output, "fi")?;
            writeln!(output, "{SHELL_HOOK_END}")?;
        }
        ShellArg::Fish => {
            writeln!(output, "{SHELL_HOOK_BEGIN}")?;
            writeln!(output, "if not set -q __LOCKET_SHELLENV_SOURCED")?;
            writeln!(output, "  set -gx __LOCKET_SHELLENV_SOURCED 1")?;
            writeln!(output, "  function locket_prompt_segment")?;
            writeln!(
                output,
                "    locket status 2>/dev/null | string match -r '^(project|default_profile): ' | string replace -r '^[^:]+: ' '' | string join ' / '"
            )?;
            writeln!(output, "  end")?;
            writeln!(output, "end")?;
            writeln!(output, "{SHELL_HOOK_END}")?;
        }
    }
    Ok(())
}

fn write_shell_hook_snippet(output: &mut impl Write, shell: ShellArg) -> Result<(), CliError> {
    match shell {
        ShellArg::Bash => {
            writeln!(output, "{SHELL_HOOK_BEGIN}")?;
            writeln!(output, "__locket_hook() {{")?;
            writeln!(output, "  local dir=\"$PWD\"")?;
            writeln!(output, "  while [ \"$dir\" != \"/\" ]; do")?;
            writeln!(output, "    if [ -f \"$dir/locket.toml\" ]; then")?;
            writeln!(output, "      locket hook --install >/dev/null 2>&1 || true")?;
            writeln!(output, "      return")?;
            writeln!(output, "    fi")?;
            writeln!(output, "    dir=\"${{dir%/*}}\"")?;
            writeln!(output, "    [ -n \"$dir\" ] || dir=\"/\"")?;
            writeln!(output, "  done")?;
            writeln!(output, "}}")?;
            output.write_all(
                br#"case ";${PROMPT_COMMAND:-};" in *';__locket_hook;'*) ;; *) PROMPT_COMMAND="__locket_hook;${PROMPT_COMMAND:-}" ;; esac
"#,
            )?;
            writeln!(output, "{SHELL_HOOK_END}")?;
        }
        ShellArg::Zsh => {
            writeln!(output, "{SHELL_HOOK_BEGIN}")?;
            writeln!(output, "__locket_hook() {{")?;
            writeln!(output, "  local dir=\"$PWD\"")?;
            writeln!(output, "  while [ \"$dir\" != \"/\" ]; do")?;
            writeln!(output, "    if [ -f \"$dir/locket.toml\" ]; then")?;
            writeln!(output, "      locket hook --install >/dev/null 2>&1 || true")?;
            writeln!(output, "      return")?;
            writeln!(output, "    fi")?;
            output.write_all(
                br#"    dir="${dir:h}"
"#,
            )?;
            writeln!(output, "  done")?;
            writeln!(output, "}}")?;
            writeln!(
                output,
                "if ! ((${{chpwd_functions[(I)__locket_hook]}})); then chpwd_functions+=(__locket_hook); fi"
            )?;
            writeln!(output, "__locket_hook")?;
            writeln!(output, "{SHELL_HOOK_END}")?;
        }
        ShellArg::Fish => {
            writeln!(output, "{SHELL_HOOK_BEGIN}")?;
            writeln!(output, "function __locket_hook --on-variable PWD")?;
            writeln!(output, "  set -l dir $PWD")?;
            writeln!(output, "  while test \"$dir\" != /")?;
            writeln!(output, "    if test -f \"$dir/locket.toml\"")?;
            writeln!(output, "      locket hook --install >/dev/null 2>&1; or true")?;
            writeln!(output, "      return")?;
            writeln!(output, "    end")?;
            writeln!(output, "    set dir (dirname \"$dir\")")?;
            writeln!(output, "  end")?;
            writeln!(output, "end")?;
            writeln!(output, "{SHELL_HOOK_END}")?;
        }
    }
    Ok(())
}

fn directory_grant_id(
    project_id: &str,
    profile_id: &str,
    root_hash: &[u8; 32],
    directory_hash: &[u8; 32],
    grant_scope: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"locket-directory-grant-v1");
    hasher.update(project_id.as_bytes());
    hasher.update(profile_id.as_bytes());
    hasher.update(root_hash);
    hasher.update(directory_hash);
    hasher.update(grant_scope.as_bytes());
    let digest = hasher.finalize();
    format!("lk_dgrant_{}", format_hex(&digest[..16]))
}

fn root_hash(root: &Path) -> Result<[u8; 32], CliError> {
    let canonical = root.canonicalize()?;
    let digest = Sha256::digest(canonical.to_string_lossy().as_bytes());
    let mut output = [0_u8; 32];
    output.copy_from_slice(&digest);
    Ok(output)
}

fn format_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn parse_root_hash(value: &str) -> Result<[u8; 32], CliError> {
    let value = value.strip_prefix("0x").unwrap_or(value);
    if value.len() != 64 {
        return Err(CliError::Config("root hash must be 64 hex characters".to_owned()));
    }
    let mut output = [0_u8; 32];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_nibble(chunk[0])?;
        let low = hex_nibble(chunk[1])?;
        output[index] = (high << 4) | low;
    }
    Ok(output)
}

fn hex_nibble(byte: u8) -> Result<u8, CliError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(CliError::Config("root hash must be hex encoded".to_owned())),
    }
}

fn recover_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &RecoverArgs,
) -> Result<(), CliError> {
    let resolved = require_project(context)?;
    let recovery_dir = recovery_dir(&resolved);
    let kdf = load_recovery_kdf_toml(&recovery_dir)
        .map_err(|error| CliError::Config(format!("recovery/kdf.toml: {error}")))?;
    let envelope = load_recovery_envelope(&recovery_dir)
        .map_err(|error| CliError::Config(format!("recovery/envelope.bin: {error}")))?;
    let code = read_recovery_code("recovery code")?;
    let code_bytes = recovery_code_decode(code.trim())?;
    restore_from_recovery_code(context, output, &resolved, &kdf, &envelope, &code_bytes, args.force)
}

fn recovery_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    command: RecoveryCommand,
) -> Result<(), CliError> {
    match command {
        RecoveryCommand::Rotate => recovery_rotate_command(context, output),
    }
}

fn recovery_rotate_command(
    context: &RuntimeContext,
    output: &mut impl Write,
) -> Result<(), CliError> {
    let resolved = require_project(context)?;
    let project_id = resolved.config.project_id.as_str();
    let recovery_dir = recovery_dir(&resolved);
    let timestamp = now_unix_nanos()?;
    let code_bytes = generate_recovery_code_bytes()?;
    let salt = generate_recovery_salt()?;
    let kdf_profile_id = format!("lk_kdf_{}", format_hex(&salt[..16]));
    let new_kdf = RecoveryKdfToml::new_v1(kdf_profile_id, &salt, timestamp);
    let new_root = derive_recovery_key_v1(&code_bytes, &salt, new_kdf.to_crypto_params())?;

    let entries = if recovery_dir.join("envelope.bin").exists() {
        let old_kdf = load_recovery_kdf_toml(&recovery_dir)
            .map_err(|error| CliError::Config(format!("recovery/kdf.toml: {error}")))?;
        let old_envelope = load_recovery_envelope(&recovery_dir)
            .map_err(|error| CliError::Config(format!("recovery/envelope.bin: {error}")))?;
        validate_recovery_metadata(project_id, &old_kdf, &old_envelope)?;
        let old_code = read_recovery_code("current recovery code")?;
        let old_code_bytes = recovery_code_decode(old_code.trim())?;
        let old_salt = old_kdf
            .decode_salt()
            .map_err(|error| CliError::Config(format!("recovery kdf salt: {error}")))?;
        let old_root =
            derive_recovery_key_v1(&old_code_bytes, &old_salt, old_kdf.to_crypto_params())?;
        rewrap_recovery_entries(
            &old_envelope,
            &old_kdf.kdf_profile_id,
            &old_root,
            &new_kdf,
            &new_root,
        )?
    } else {
        let (master_key, _source) = load_master_key(context, project_id)?;
        vec![seal_recovery_envelope_entry(
            &new_root,
            &new_kdf.kdf_profile_id,
            "master_key",
            project_id,
            master_key.as_ref(),
        )?]
    };

    let new_envelope = RecoveryEnvelope {
        kdf_profile_id: new_kdf.kdf_profile_id.clone(),
        created_at_unix_nanos: i128::from(timestamp),
        entries,
    };
    save_recovery_kdf_toml(&recovery_dir, &new_kdf)
        .map_err(|error| CliError::Config(format!("save recovery kdf: {error}")))?;
    save_recovery_envelope(&recovery_dir, &new_envelope)
        .map_err(|error| CliError::Config(format!("save recovery envelope: {error}")))?;
    write_recovery_rotate_audit(context, &resolved, &new_kdf.kdf_profile_id, timestamp)?;
    display_recovery_code(output, &code_bytes)
}

fn restore_from_recovery_code(
    context: &RuntimeContext,
    output: &mut impl Write,
    resolved: &ResolvedProject,
    kdf: &RecoveryKdfToml,
    envelope: &RecoveryEnvelope,
    code_bytes: &[u8; locket_crypto::RECOVERY_CODE_BYTES],
    force: bool,
) -> Result<(), CliError> {
    let project_id = resolved.config.project_id.as_str();
    validate_recovery_metadata(project_id, kdf, envelope)?;
    if !force {
        match context.key_store.load_master_key(project_id) {
            Ok(_) => {
                return Err(CliError::Config(
                    "master key already exists; use --force to overwrite".to_owned(),
                ));
            }
            Err(locket_platform::PlatformError::MasterKeyNotFound) => {}
            Err(error) => return Err(CliError::Platform(error)),
        }
    }

    let salt = kdf
        .decode_salt()
        .map_err(|error| CliError::Config(format!("recovery kdf salt: {error}")))?;
    let unwrap_root = derive_recovery_key_v1(code_bytes, &salt, kdf.to_crypto_params())?;
    let mut restored = 0usize;
    for entry in &envelope.entries {
        if entry.entry_kind != "master_key" {
            continue;
        }
        if entry.entry_id != project_id {
            return Err(CliError::Config("recovery envelope project id mismatch".to_owned()));
        }
        let plaintext = open_recovery_entry_v1(
            &unwrap_root,
            &kdf.kdf_profile_id,
            &entry.entry_kind,
            &entry.entry_id,
            &entry.nonce,
            &entry.ciphertext,
        )?;
        if plaintext.len() != locket_crypto::KEY_LEN {
            return Err(CliError::Crypto(locket_crypto::CryptoError::InvalidWrappedKey));
        }
        let mut master_key = zeroize::Zeroizing::new([0_u8; locket_crypto::KEY_LEN]);
        master_key.copy_from_slice(&plaintext);
        context.key_store.store_master_key(project_id, &master_key)?;
        restored += 1;
    }
    if restored == 0 {
        return Err(CliError::Config(
            "no master_key entries found in recovery envelope".to_owned(),
        ));
    }
    writeln!(output, "recovered: master_key")?;
    writeln!(output, "metadata_only: yes")?;
    Ok(())
}

fn validate_recovery_metadata(
    project_id: &str,
    kdf: &RecoveryKdfToml,
    envelope: &RecoveryEnvelope,
) -> Result<(), CliError> {
    kdf.validate()?;
    if envelope.kdf_profile_id != kdf.kdf_profile_id {
        return Err(CliError::Config("recovery envelope kdf profile mismatch".to_owned()));
    }
    if !envelope
        .entries
        .iter()
        .any(|entry| entry.entry_kind == "master_key" && entry.entry_id == project_id)
    {
        return Err(CliError::Config(
            "recovery envelope does not contain this project master key".to_owned(),
        ));
    }
    Ok(())
}

fn rewrap_recovery_entries(
    old_envelope: &RecoveryEnvelope,
    old_kdf_profile_id: &str,
    old_root: &locket_crypto::KeyBytes,
    new_kdf: &RecoveryKdfToml,
    new_root: &locket_crypto::KeyBytes,
) -> Result<Vec<RecoveryEnvelopeEntry>, CliError> {
    let mut entries = Vec::with_capacity(old_envelope.entries.len());
    for entry in &old_envelope.entries {
        let plaintext = open_recovery_entry_v1(
            old_root,
            old_kdf_profile_id,
            &entry.entry_kind,
            &entry.entry_id,
            &entry.nonce,
            &entry.ciphertext,
        )?;
        entries.push(seal_recovery_envelope_entry(
            new_root,
            &new_kdf.kdf_profile_id,
            &entry.entry_kind,
            &entry.entry_id,
            &plaintext,
        )?);
    }
    Ok(entries)
}

fn seal_recovery_envelope_entry(
    unwrap_root: &locket_crypto::KeyBytes,
    kdf_profile_id: &str,
    entry_kind: &str,
    entry_id: &str,
    plaintext: &[u8],
) -> Result<RecoveryEnvelopeEntry, CliError> {
    let (nonce, ciphertext) =
        seal_recovery_entry_v1(unwrap_root, kdf_profile_id, entry_kind, entry_id, plaintext)?;
    Ok(RecoveryEnvelopeEntry {
        entry_kind: entry_kind.to_owned(),
        entry_id: entry_id.to_owned(),
        nonce,
        ciphertext,
    })
}

fn recovery_dir(resolved: &ResolvedProject) -> PathBuf {
    resolved.root.join(".locket").join("recovery")
}

fn display_recovery_code(
    output: &mut impl Write,
    code_bytes: &[u8; locket_crypto::RECOVERY_CODE_BYTES],
) -> Result<(), CliError> {
    let encoded = recovery_code_encode(code_bytes);
    let code = std::str::from_utf8(&encoded)
        .map_err(|_| CliError::Crypto(locket_crypto::CryptoError::InvalidSecretValue))?;
    writeln!(output, "recovery_code_rotate: success")?;
    writeln!(output, "recovery_code (shown once, store securely):")?;
    writeln!(
        output,
        "{}-{}-{}-{}-{}",
        &code[0..8],
        &code[8..16],
        &code[16..24],
        &code[24..32],
        &code[32..34]
    )?;
    writeln!(output, "metadata_only: yes")?;
    Ok(())
}

fn read_recovery_code(prompt: &str) -> Result<zeroize::Zeroizing<String>, CliError> {
    if io::stdin().is_terminal() {
        let value = rpassword::prompt_password(format!("Enter {prompt}: "))?;
        return Ok(zeroize::Zeroizing::new(value));
    }
    let mut value = String::new();
    io::stdin().read_to_string(&mut value)?;
    Ok(zeroize::Zeroizing::new(value))
}

fn write_recovery_rotate_audit(
    context: &RuntimeContext,
    resolved: &ResolvedProject,
    kdf_profile_id: &str,
    timestamp: i64,
) -> Result<(), CliError> {
    let mut store = open_store(context)?;
    let audit_key =
        load_project_key(context, &store, resolved.config.project_id.as_str(), KeyPurpose::Audit)?;
    let metadata = json!({
        "schema_version": 1,
        "action": "RECOVERY_ROTATE",
        "status": "SUCCESS",
        "kdf_profile_id": kdf_profile_id,
    });
    let audit = AuditWrite {
        project_id: resolved.config.project_id.as_str(),
        profile_id: None,
        action: "RECOVERY_ROTATE",
        status: "SUCCESS",
        secret_name: None,
        command: Some("recovery rotate"),
        metadata_json: &metadata,
        timestamp,
    };
    store.append_audit(audit_key.as_ref(), &audit)?;
    Ok(())
}

fn now_unix_nanos() -> Result<i64, CliError> {
    let elapsed = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| CliError::Time)?;
    i64::try_from(elapsed.as_nanos()).map_err(|_| CliError::Time)
}

#[cfg(test)]
mod tests {
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
    struct StaticConfirmationReader {
        confirmation: String,
    }

    impl StaticConfirmationReader {
        fn new(confirmation: &str) -> Self {
            Self { confirmation: confirmation.to_owned() }
        }
    }

    impl super::ConfirmationReader for StaticConfirmationReader {
        fn read_confirmation(&self, _prompt: &str) -> Result<String, super::CliError> {
            Ok(self.confirmation.clone())
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
        test_context_with_key_store_and_confirmation(directory, key_store, "app\n")
    }

    fn test_context_with_key_store_and_confirmation(
        directory: &tempfile::TempDir,
        key_store: Arc<dyn MasterKeyStore + Send + Sync>,
        confirmation: &str,
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
            confirmation_reader: Arc::new(StaticConfirmationReader::new(confirmation)),
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
            ["SET", "ROTATE", "REVEAL", "PURGE", "DELETE", "PURGE", "AUDIT_VERIFY"]
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
        assert_error_contains(
            super::grace_until_from_args(Some("8d"), 1_000).map(|_| ()),
            "7d cap",
        );
        assert!(matches!(
            super::grace_until_from_args(Some("1s"), i64::MAX - 10),
            Err(super::CliError::Time)
        ));
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
    fn completion_command_generates_scripts_without_project()
    -> Result<(), Box<dyn std::error::Error>> {
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
    fn new_from_local_template_and_bootstrap_report_checklist()
    -> Result<(), Box<dyn std::error::Error>> {
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
        assert!(!bootstrap_output.contains("postgres://"));
        Ok(())
    }

    #[test]
    fn new_rejects_template_with_invalid_expected_secret_name()
    -> Result<(), Box<dyn std::error::Error>> {
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
        run_with_context(
            Cli::try_parse_from(["locket", "emit-example"])?,
            &context,
            &mut emit_output,
        )?;

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
        run_with_context(
            Cli::try_parse_from(["locket", "emit-example"])?,
            &context,
            &mut emit_output,
        )?;
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
    fn init_creates_project_metadata_files_and_profiles() -> Result<(), Box<dyn std::error::Error>>
    {
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
        let rows = statement
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
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
    fn profile_dangerous_marking_updates_metadata_only() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let context = test_context(&directory);
        let mut output = Vec::new();
        run_with_context(
            Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
            &context,
            &mut output,
        )?;

        let mut mark_output = Vec::new();
        run_with_context(
            Cli::try_parse_from(["locket", "profile", "mark-dangerous", "dev"])?,
            &context,
            &mut mark_output,
        )?;
        let mark_output = String::from_utf8(mark_output)?;
        assert!(mark_output.contains("dangerous=dangerous"));

        let mut list_output = Vec::new();
        run_with_context(
            Cli::try_parse_from(["locket", "profile", "list"])?,
            &context,
            &mut list_output,
        )?;
        let list_output = String::from_utf8(list_output)?;
        assert!(list_output.contains("* dev"));
        assert!(list_output.contains("dangerous"));

        let mut clear_output = Vec::new();
        run_with_context(
            Cli::try_parse_from(["locket", "profile", "clear-dangerous", "dev"])?,
            &context,
            &mut clear_output,
        )?;
        assert!(String::from_utf8(clear_output)?.contains("dangerous=not-dangerous"));
        let mut list_after_clear = Vec::new();
        run_with_context(
            Cli::try_parse_from(["locket", "profile", "list"])?,
            &context,
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
        assert!(String::from_utf8(trust_output)?.contains("trusted root already present"));

        let mut untrust_output = Vec::new();
        run_with_context(
            Cli::try_parse_from(["locket", "project", "untrust-root", root_hash.as_str()])?,
            &context,
            &mut untrust_output,
        )?;
        assert!(String::from_utf8(untrust_output)?.contains("trusted root removed"));

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
    fn allow_and_deny_manage_profile_scoped_directory_grants()
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
        run_with_context(
            Cli::try_parse_from(["locket", "deny"])?,
            &context,
            &mut staging_deny_output,
        )?;
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
    fn allow_requires_trusted_project_root() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let context = test_context(&directory);
        let mut output = Vec::new();
        run_with_context(
            Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
            &context,
            &mut output,
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
        run_with_context(
            Cli::try_parse_from(["locket", "project", "untrust-root", root_hash.as_str()])?,
            &context,
            &mut untrust_output,
        )?;

        let mut allow_output = Vec::new();
        let Err(error) = run_with_context(
            Cli::try_parse_from(["locket", "allow"])?,
            &context,
            &mut allow_output,
        ) else {
            return Err("allow should fail for untrusted roots".into());
        };
        assert!(error.to_string().contains("ProjectRootNotTrusted"));

        let store = locket_store::Store::open(directory.path().join("store.db"))?;
        let grant_count: u32 =
            store
                .connection()
                .query_row("SELECT COUNT(*) FROM directory_grants", [], |row| row.get(0))?;
        assert_eq!(grant_count, 0);
        Ok(())
    }

    #[test]
    fn agent_commands_report_metadata_only_unavailable_state()
    -> Result<(), Box<dyn std::error::Error>> {
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
    fn agent_logs_filter_redact_rotate_and_harden_local_files()
    -> Result<(), Box<dyn std::error::Error>> {
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
    fn doctor_reports_locked_safe_diagnostics_and_exit_codes()
    -> Result<(), Box<dyn std::error::Error>> {
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
        let code = run_with_context(
            Cli::try_parse_from(["locket", "doctor"])?,
            &context,
            &mut doctor_output,
        )?;
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
    fn debug_bundle_redacted_writes_metadata_only_summary() -> Result<(), Box<dyn std::error::Error>>
    {
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
    fn debug_bundle_default_output_uses_user_diagnostics_dir()
    -> Result<(), Box<dyn std::error::Error>> {
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
    fn debug_bundle_refuses_to_overwrite_existing_output() -> Result<(), Box<dyn std::error::Error>>
    {
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
        assert_eq!(
            String::from_utf8(retention_output)?,
            "set runtime.session_secret_name_retention\n"
        );

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
    fn config_get_and_list_reject_malformed_stored_values() -> Result<(), Box<dyn std::error::Error>>
    {
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
    fn passkey_commands_are_metadata_only_when_platform_is_unavailable()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let context = test_context(&directory);

        let mut list_output = Vec::new();
        run_with_context(
            Cli::try_parse_from(["locket", "passkey", "list", "--all"])?,
            &context,
            &mut list_output,
        )?;
        let list_output = String::from_utf8(list_output)?;
        assert!(list_output.contains("platform unavailable"));
        assert!(list_output.contains("credentials: none"));
        assert!(list_output.contains("private_key_material: never displayed"));

        let mut register_output = Vec::new();
        let register = run_with_context(
            Cli::try_parse_from(["locket", "passkey", "register"])?,
            &context,
            &mut register_output,
        );
        assert_error_contains(register, "not available");
        assert!(register_output.is_empty());

        let mut remove_output = Vec::new();
        let remove = run_with_context(
            Cli::try_parse_from(["locket", "passkey", "remove", "work-laptop"])?,
            &context,
            &mut remove_output,
        );
        assert_error_contains(remove, "not available");
        assert!(remove_output.is_empty());
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
    fn passphrase_fallback_covers_init_unlock_and_decrypt() -> Result<(), Box<dyn std::error::Error>>
    {
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
    fn passphrase_fallback_covers_stale_os_key_material() -> Result<(), Box<dyn std::error::Error>>
    {
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
        super::set_secret_value(
            &fallback_context,
            &args,
            "postgres://localhost/app",
            "manual",
            1_000,
        )?;

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
        let args = test_secret_write_args("DATABASE_URL");
        super::set_secret_value(&context, &args, "postgres://localhost/app", "manual", 1_000)?;

        let mut rotate_output = Vec::new();
        super::recovery_rotate_command(&context, &mut rotate_output)?;
        let rotate_output = String::from_utf8(rotate_output)?;
        assert!(rotate_output.contains("recovery_code_rotate: success"));
        assert!(rotate_output.contains("shown once"));
        assert!(rotate_output.contains("metadata_only: yes"));
        assert!(!rotate_output.contains("postgres://localhost/app"));
        let recovery_code = rotate_output
            .lines()
            .find(|line| {
                line.len() == 38
                    && line.chars().all(|character| {
                        character == '-'
                            || character.is_ascii_digit()
                            || character.is_ascii_uppercase()
                    })
            })
            .ok_or("recovery code line should be printed once")?;
        let recovery_code_bytes = locket_crypto::recovery_code_decode(recovery_code)?;

        let recovery_dir = directory.path().join(".locket/recovery");
        assert!(recovery_dir.join("kdf.toml").exists());
        assert!(recovery_dir.join("envelope.bin").exists());

        let recovered_key_store = Arc::new(MemoryMasterKeyStore::default());
        let recovered_context =
            test_context_with_key_store(&directory, recovered_key_store.clone());
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
    fn install_hooks_requires_confirmation_for_unmanaged_hook()
    -> Result<(), Box<dyn std::error::Error>> {
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
        assert!(
            String::from_utf8(reinstall_output)?.contains("hook_change: rewrote-managed-block")
        );
        let rewritten_hook = std::fs::read_to_string(hooks_dir.join("pre-commit"))?;
        assert!(rewritten_hook.contains("locket scan --staged"));
        assert!(!rewritten_hook.contains("--old"));
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

        let copy_args = super::GetArgs {
            key: "DATABASE_URL".to_owned(),
            reveal: false,
            force: false,
            copy: true,
        };
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

        let copy_args = super::GetArgs {
            key: "DATABASE_URL".to_owned(),
            reveal: false,
            force: false,
            copy: true,
        };
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
    fn meta_updates_secret_metadata_without_printing_values()
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
        assert!(row.4 > 1_000);

        let audit_metadata: String = store.connection().query_row(
            "SELECT metadata_json FROM audit_log WHERE action = 'SECRET_META_UPDATE'",
            [],
            |row| row.get(0),
        )?;
        assert!(
            audit_metadata
                .contains("\"updated_fields\":[\"description\",\"owner\",\"tags\",\"required\"]")
        );
        assert!(!audit_metadata.contains("primary database"));
        assert!(!audit_metadata.contains("platform"));
        assert!(!audit_metadata.contains("postgres://localhost/app"));
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
        super::set_secret_value(
            &context,
            &db_args,
            "postgres://localhost/dev-old",
            "manual",
            1_000,
        )?;
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
        super::set_secret_value(
            &context,
            &db_args,
            "postgres://localhost/staging",
            "manual",
            3_000,
        )?;
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
        super::set_secret_value(
            &context,
            &db_args,
            "postgres://localhost/dev-old",
            "manual",
            1_000,
        )?;
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
            diff_output.contains(
                "version DATABASE_URL source=user-local v2 state=current created_at=2000"
            )
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

        let copy_args = super::GetArgs {
            key: "DATABASE_URL".to_owned(),
            reveal: false,
            force: false,
            copy: true,
        };
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
        assert!(diff_output.contains("changed DATABASE_URL source=user-local"));
        assert!(!diff_output.contains("postgres://localhost"));
        assert!(!diff_output.contains("primary database"));
        Ok(())
    }

    #[test]
    fn diff_since_parses_iso_offsets_and_fractional_nanos() -> Result<(), Box<dyn std::error::Error>>
    {
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
    fn diff_since_resolves_git_revision_with_direct_args() -> Result<(), Box<dyn std::error::Error>>
    {
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
        super::set_secret_value(
            &context,
            &set_args,
            "postgres://localhost/dev-copy",
            "manual",
            1_000,
        )?;
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
            store
                .connection()
                .query_row("SELECT id FROM projects LIMIT 1", [], |row| row.get(0))?;
        let staging = store
            .get_profile_by_name(&project_id, "staging")?
            .ok_or("staging profile should exist")?;
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
        super::set_secret_value(
            &context,
            &set_args,
            "postgres://localhost/source",
            "manual",
            1_000,
        )?;
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
            store
                .connection()
                .query_row("SELECT id FROM projects LIMIT 1", [], |row| row.get(0))?;
        let staging = store
            .get_profile_by_name(&project_id, "staging")?
            .ok_or("staging profile should exist")?;
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

        let mut purge_output = Vec::new();
        run_with_context(
            Cli::try_parse_from(["locket", "purge", "DATABASE_URL", "--version", "1"])?,
            &context,
            &mut purge_output,
        )?;
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

        let mut invalid_purge_output = Vec::new();
        let invalid_purge = run_with_context(
            Cli::try_parse_from(["locket", "purge", "DATABASE_URL", "--version", "2"])?,
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
        let mut purge_all_output = Vec::new();
        run_with_context(
            Cli::try_parse_from(["locket", "purge", "DATABASE_URL", "--all-versions"])?,
            &context,
            &mut purge_all_output,
        )?;
        assert!(String::from_utf8(purge_all_output)?.contains("versions=1,2"));

        let mut audit_output = Vec::new();
        run_with_context(
            Cli::try_parse_from(["locket", "audit", "verify"])?,
            &context,
            &mut audit_output,
        )?;
        assert!(String::from_utf8(audit_output)?.contains("verified 6 row(s)"));

        assert_lifecycle_audit_log(&directory)?;
        Ok(())
    }

    #[test]
    fn import_env_encrypts_values_and_refreshes_example() -> Result<(), Box<dyn std::error::Error>>
    {
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
    fn import_env_targets_named_profile_and_reports_parity()
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
        let context = test_context(&directory);
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
        run_with_context(
            Cli::try_parse_from(["locket", "profile", "mark-dangerous", "prod"])?,
            &context,
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
                Cli::try_parse_from([
                    "locket",
                    "import",
                    ".env",
                    "--profile",
                    "prod",
                    "--overwrite",
                ])?,
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
        let prepared = super::prepare_docker_policy_execution(
            &context,
            "docker_app",
            &docker_argv,
            parent_env,
        )?;
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
        assert_eq!(
            argv,
            ["docker", "compose", "--project-directory", ".", "--profile", "web", "up"]
        );
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
        let Err(error) = super::prepare_compose_policy_execution(
            &context,
            "compose_app",
            &remote_argv,
            remote_env,
        ) else {
            return Err("remote Docker context should be denied".into());
        };
        let message = error.to_string();
        assert!(message.contains("remote Docker context is denied by default"));
        assert!(!message.contains("sk_test_compose_value"));
        Ok(())
    }

    #[test]
    fn context_reports_metadata_only_summaries_without_values()
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
            context_output
                .contains("- MISSING_ONLY profiles=policy:env_check sources=policy-optional")
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
    fn context_redacts_names_from_flag_or_privacy_config() -> Result<(), Box<dyn std::error::Error>>
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
        std::fs::write(
            directory.path().join("ignored.txt"),
            "token=sk_test_sampleTokenValue123\n",
        )?;
        std::fs::write(
            directory.path().join("visible.txt"),
            "token=sk_test_visibleTokenValue123\n",
        )?;

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
        let grace_until =
            super::grace_until_from_args(rotate_args.grace_ttl.as_deref(), timestamp)?;
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
    fn redact_names_uses_privacy_alias_for_known_values() -> Result<(), Box<dyn std::error::Error>>
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
    fn recovery_restore_recovers_master_key_from_envelope() -> Result<(), Box<dyn std::error::Error>>
    {
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
        let (kdf, envelope, code_bytes) =
            setup_recovery_envelope(&context, &project_id, &master_key)?;
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
    fn recovery_rotate_creates_envelope_and_prints_full_code()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let context = test_context(&directory);
        let mut init_output = Vec::new();
        run_with_context(
            Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
            &context,
            &mut init_output,
        )?;
        let (project_id, master_key) = test_project_id_and_master_key(&context)?;

        let mut rotate_output = Vec::new();
        run_with_context(
            Cli::try_parse_from(["locket", "recovery", "rotate"])?,
            &context,
            &mut rotate_output,
        )?;

        let rotate_output = String::from_utf8(rotate_output)?;
        assert!(rotate_output.contains("recovery_code_rotate: success"));
        assert!(rotate_output.contains("metadata_only: yes"));
        let code_line = rotate_output
            .lines()
            .find(|line| line.matches('-').count() == 4)
            .ok_or("missing recovery code line")?;
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
                "printf 'db=postgres://localhost/app\n'",
            ])?,
            &context,
            &mut ai_safe_output,
        )?;

        let ai_safe_output = String::from_utf8(ai_safe_output)?;
        let transcript = std::fs::read_to_string(directory.path().join("transcript.log"))?;
        assert!(ai_safe_output.contains("lk_redacted_DATABASE_URL"));
        assert!(transcript.contains("lk_redacted_DATABASE_URL"));
        assert!(!ai_safe_output.contains("postgres://localhost/app"));
        assert!(!transcript.contains("postgres://localhost/app"));
        Ok(())
    }
}
