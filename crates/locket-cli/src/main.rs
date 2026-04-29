//! Locket command-line entry point.

use clap::{Args, Parser, Subcommand, ValueEnum};
use directories::ProjectDirs;
use locket_core::{
    Duration as LocketDuration, KeyId, ProfileId, ProfileName, ProjectConfig, ProjectId, SecretId,
    SecretName,
};
use locket_crypto::{
    EncryptedSecretValue, HkdfWrapInfo, KeyPurpose, KeyWrapAad, KeyWrapPurpose, WrappedKeyMaterial,
    decrypt_secret_value_v1, derive_wrapping_key_v1, encrypt_secret_value_v1, generate_key,
    key_wrap_aad_v1, secret_blob_aad_v1, secret_fingerprint_v1, unwrap_key_material_v1,
    wrap_key_material_v1,
};
use locket_platform::{KeyringMasterKeyStore, MasterKeyStore};
use locket_scan::{
    FindingKind, KnownRedaction, ScanFinding, redact_text, redact_text_with_known_values, scan_text,
};
use locket_store::{
    AuditContext, AuditWrite, KeyRecord, ProfileRecord, SecretBlobRecord, SecretFingerprintRecord,
    SecretRecord, SecretVersionRecord, Store, StoreError, VersionDeprecation,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{self, Display};
use std::fs;
use std::io::{self, IsTerminal, Read, Write};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command as ProcessCommand, ExitCode as ProcessExitCode};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

const LOCKET_TOML: &str = "locket.toml";
const CONFIG_TOML: &str = "config.toml";
const EXAMPLE_FILE: &str = ".env.example";
const GITIGNORE_FILE: &str = ".gitignore";
const EXAMPLE_BEGIN: &str = "# --- BEGIN LOCKET MANAGED ---";
const EXAMPLE_END: &str = "# --- END LOCKET MANAGED ---";
const HOOK_BEGIN: &str = "# --- BEGIN LOCKET PRE-COMMIT ---";
const HOOK_END: &str = "# --- END LOCKET PRE-COMMIT ---";
const GITIGNORE_ENTRIES: [&str; 4] = [".env", ".env.*", ".locket.local", ".locketignore"];
const DEFAULT_MAX_GRACE_TTL_SECONDS: u64 = 7 * 24 * 60 * 60;
const NANOS_PER_SECOND: i64 = 1_000_000_000;

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
    /// Switch active profile.
    Use(ProfileNameArgs),
    /// Manage trusted project roots.
    Project {
        /// Project command.
        #[command(subcommand)]
        command: ProjectCommand,
    },
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

#[derive(Clone, Copy, Debug, Subcommand)]
enum AgentCommand {
    /// Start the local agent.
    Start,
    /// Print agent status.
    Status,
    /// Stop the local agent.
    Stop,
    /// Print redacted agent logs.
    Logs,
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
    let context = match RuntimeContext::default() {
        Ok(context) => context,
        Err(error) => {
            return write_error_and_exit(&error);
        }
    };

    let mut output = io::stdout();
    match run_with_context(cli, &context, &mut output) {
        Ok(()) => ProcessExitCode::SUCCESS,
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
) -> Result<(), CliError> {
    let command = cli.command.unwrap_or(Command::Status);

    match command {
        Command::Status => status(context, output)?,
        Command::Init(args) => init(context, output, args)?,
        Command::Set(args) => set_command(context, output, &args)?,
        Command::Import(args) => import_command(context, output, &args)?,
        Command::Get(args) => get_command(context, output, &args)?,
        Command::Rm(args) => rm_command(context, output, &args)?,
        Command::Purge(args) => purge_command(context, output, &args)?,
        Command::List(args) => list_command(context, output, &args)?,
        Command::Exec(args) => exec_command(context, output, &args)?,
        Command::Rotate(args) => rotate_command(context, output, &args)?,
        Command::Meta(args) => meta_command(context, output, &args)?,
        Command::History(args) => history_command(context, output, &args)?,
        Command::Diff(args) => diff_command(context, output, &args)?,
        Command::Audit { command } => audit_command(context, output, command)?,
        Command::Lock => lock_command(context, output)?,
        Command::Unlock(args) => unlock_command(context, output, &args)?,
        Command::EmitExample => emit_example_command(context, output)?,
        Command::InstallHooks => install_hooks_command(context, output)?,
        Command::Profile { command } => profile_command(context, output, command)?,
        Command::Project { command } => project_command(context, output, command)?,
        Command::Agent { command } => agent_command(context, output, command)?,
        Command::Use(args) => use_profile_command(context, output, args)?,
        Command::Scan(args) => scan_command(context, output, args)?,
        Command::Redact(args) => redact_command(context, output, args)?,
        Command::Context(args) => context_command(context, output, args)?,
        Command::AiSafe(args) => ai_safe_command(context, output, &args)?,
        Command::Config { command } => config_command(context, output, command)?,
        Command::Passkey { command } => passkey_command(output, command)?,
    }

    Ok(())
}

#[derive(Clone)]
struct RuntimeContext {
    cwd: PathBuf,
    store_path: PathBuf,
    config_path: PathBuf,
    key_store: Arc<dyn MasterKeyStore + Send + Sync>,
}

impl RuntimeContext {
    fn default() -> Result<Self, CliError> {
        let cwd = std::env::current_dir()?;
        let Some(project_dirs) = ProjectDirs::from("dev", "0xdoublesharp", "Locket") else {
            return Err(CliError::Config("could not resolve a local data directory".to_owned()));
        };
        let data_dir = project_dirs.data_dir();
        let config_dir = project_dirs.config_dir();
        fs::create_dir_all(data_dir)?;
        fs::create_dir_all(config_dir)?;
        Ok(Self {
            cwd,
            store_path: data_dir.join("store.db"),
            config_path: config_dir.join(CONFIG_TOML),
            key_store: Arc::new(KeyringMasterKeyStore),
        })
    }
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

    writeln!(output, "project: {}", resolved.config.name)?;
    writeln!(output, "project_id: {}", resolved.config.project_id)?;
    writeln!(output, "root: {}", resolved.root.display())?;
    writeln!(output, "default_profile: {}", resolved.config.default_profile)?;
    writeln!(output, "store: {}", if project.is_some() { "ready" } else { "partial" })?;
    writeln!(output, "trusted_root: {}", if trusted { "yes" } else { "no" })?;
    writeln!(output, "profile: {}", if profile.is_some() { "ready" } else { "missing" })?;
    writeln!(output, "agent: unavailable")?;
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
    if let Err(error) = (|| -> Result<(), CliError> {
        ensure_project_metadata(&store, &config, timestamp)?;
        initialize_project_keys(context, &store, &config, timestamp)?;
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
    Ok(())
}

fn set_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &SecretWriteArgs,
) -> Result<(), CliError> {
    let value = read_secret_value_from_stdin()?;
    set_secret_value(context, args, &value, "manual", now_unix_nanos()?)?;
    refresh_example_for_project(context)?;
    let source = source_arg_to_str(args.source.source.unwrap_or(SecretSourceArg::UserLocal));
    writeln!(output, "set {} ({source})", args.key)?;
    Ok(())
}

fn import_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &ImportArgs,
) -> Result<(), CliError> {
    if let Some(profile) = &args.profile {
        let resolved = require_project(context)?;
        if profile != resolved.config.default_profile.as_str() {
            return Err(CliError::Config(
                "import --profile currently supports only the active default profile".to_owned(),
            ));
        }
    }

    let path = absolutize(&context.cwd, Path::new(&args.file));
    let env_file_text = fs::read_to_string(path)?;
    let source = args.source.unwrap_or(SecretSourceArg::UserLocal);
    let parsed = parse_env_import(&env_file_text);
    let mut imported = 0_u32;
    let mut overwritten = 0_u32;
    let mut skipped = 0_u32;
    let mut invalid = 0_u32;

    for entry in parsed {
        match entry {
            EnvImportEntry::Secret { key, value } => {
                let write_args = SecretWriteArgs {
                    key: key.clone(),
                    source: SourceArg { source: Some(source) },
                    metadata: SecretMetadataFlags {
                        description: None,
                        owner: None,
                        tags: Vec::new(),
                        required: false,
                        optional: false,
                    },
                };
                match set_secret_value(context, &write_args, &value, "imported", now_unix_nanos()?)
                {
                    Ok(()) => imported += 1,
                    Err(CliError::Config(message))
                        if message.contains("already exists") && args.overwrite =>
                    {
                        let rotate_args = RotateArgs {
                            key,
                            source: SourceArg { source: Some(source) },
                            metadata: SecretMetadataFlags {
                                description: None,
                                owner: None,
                                tags: Vec::new(),
                                required: false,
                                optional: false,
                            },
                            grace_ttl: None,
                        };
                        rotate_secret_value(
                            context,
                            &rotate_args,
                            &value,
                            now_unix_nanos()?,
                            None,
                        )?;
                        overwritten += 1;
                    }
                    Err(CliError::Config(message)) if message.contains("already exists") => {
                        skipped += 1;
                    }
                    Err(error) => return Err(error),
                }
            }
            EnvImportEntry::Invalid => invalid += 1,
        }
    }

    refresh_example_for_project(context)?;
    ensure_gitignore(&require_project(context)?.root)?;
    writeln!(output, "imported: {imported}")?;
    writeln!(output, "overwritten: {overwritten}")?;
    writeln!(output, "skipped: {skipped}")?;
    writeln!(output, "invalid: {invalid}")?;
    Ok(())
}

fn get_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &GetArgs,
) -> Result<(), CliError> {
    let resolved_secret = resolve_active_secret(context, &args.key)?;
    if args.copy {
        return Err(CliError::Config("clipboard copy is not wired in this build yet".to_owned()));
    }
    if args.reveal {
        let value = decrypt_current_secret(context, &resolved_secret)?;
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
    refresh_example_for_project(context)?;
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
    refresh_example_for_project(context)?;
    writeln!(output, "rotated {} ({source}) version={version}", args.key)?;
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
    refresh_example_for_project(context)?;
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
    validate_config_key(key)?;
    let config = read_user_config(context)?;
    let value = config_get_value(&config, key)
        .ok_or_else(|| CliError::Config("config key is not set".to_owned()))?;
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
    let changed = store.update_secret_metadata(
        &resolved_secret.secret.id,
        args.metadata.description.as_deref(),
        args.metadata.owner.as_deref(),
        tags,
        required,
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
    if args.since.is_some() {
        return Err(CliError::Config("diff --since is not wired in this build yet".to_owned()));
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

fn emit_example_command(context: &RuntimeContext, output: &mut impl Write) -> Result<(), CliError> {
    let resolved = require_project(context)?;
    refresh_example_for_project(context)?;
    writeln!(output, "updated {}", resolved.root.join(EXAMPLE_FILE).display())?;
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
    let _master_key = context.key_store.load_master_key(resolved.config.project_id.as_str())?;
    load_project_key(context, &store, resolved.config.project_id.as_str(), KeyPurpose::Audit)?;

    writeln!(output, "unlock: metadata-only direct CLI unlock succeeded")?;
    writeln!(output, "project_id: {}", resolved.config.project_id)?;
    writeln!(output, "active_profile: {} ({})", resolved.config.default_profile, profile.id)?;
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
    let updated = upsert_pre_commit_hook(&existing)?;
    if updated != existing {
        fs::write(&hook_path, updated)?;
    }
    make_executable(&hook_path)?;
    write_hook_install_audit_if_available(context, &resolved)?;

    writeln!(output, "installed {}", hook_path.display())?;
    writeln!(output, "hook: locket scan --staged")?;
    writeln!(output, "secrets: not written")?;
    Ok(())
}

fn managed_pre_commit_block() -> String {
    format!("{HOOK_BEGIN}\nlocket scan --staged\n{HOOK_END}\n")
}

fn upsert_pre_commit_hook(existing: &str) -> Result<String, CliError> {
    let block = managed_pre_commit_block();
    if existing.is_empty() {
        return Ok(format!("#!/bin/sh\n\n{block}"));
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
        return Ok(updated);
    }

    if let Some(rest) = existing.strip_prefix("#!") {
        let Some(newline_index) = rest.find('\n') else {
            return Ok(format!("{existing}\n\n{block}"));
        };
        let shebang_end = "#!".len() + newline_index + 1;
        let mut updated = String::new();
        updated.push_str(&existing[..shebang_end]);
        updated.push('\n');
        updated.push_str(&block);
        updated.push('\n');
        updated.push_str(&existing[shebang_end..]);
        Ok(updated)
    } else {
        Ok(format!("{block}\n{existing}"))
    }
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
        AgentCommand::Logs => agent_logs_command(context, output),
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

fn agent_logs_command(context: &RuntimeContext, output: &mut impl Write) -> Result<(), CliError> {
    let log_path = agent_log_path(context);
    let log_text = match fs::read_to_string(&log_path) {
        Ok(log_text) => log_text,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            writeln!(output, "no agent logs")?;
            return Ok(());
        }
        Err(error) => return Err(error.into()),
    };

    let lines = log_text.lines().rev().take(200).collect::<Vec<_>>();
    for line in lines.iter().rev() {
        writeln!(output, "{line}")?;
    }
    Ok(())
}

fn scan_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: ScanArgs,
) -> Result<(), CliError> {
    if args.staged {
        ensure_git_worktree(&context.cwd)?;
        return Err(CliError::Config(
            "staged scan content is not wired in this build yet".to_owned(),
        ));
    }

    let project = resolve_project(&context.cwd)?;
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
    scan_path(&scan_root, &scan_root, &known_values, &mut findings)?;
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
    _args: RedactNamesArgs,
) -> Result<(), CliError> {
    let resolved = require_project(context)?;
    let store = open_store(context)?;
    let profiles = store.list_profiles(resolved.config.project_id.as_str())?;
    writeln!(output, "Secrets used:")?;
    writeln!(output, "profiles: {}", profiles.len())?;
    writeln!(output, "values: hidden")?;
    Ok(())
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

fn initialize_project_keys(
    context: &RuntimeContext,
    store: &Store,
    config: &ProjectConfig,
    timestamp: i64,
) -> Result<(), CliError> {
    let master_key = generate_key()?;
    context.key_store.store_master_key(config.project_id.as_str(), &master_key)?;
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
    initialize_profile_keys(context, store, config, &profile.id, timestamp)?;
    Ok(())
}

fn initialize_profile_keys(
    context: &RuntimeContext,
    store: &Store,
    config: &ProjectConfig,
    profile_id: &str,
    timestamp: i64,
) -> Result<(), CliError> {
    let master_key = context.key_store.load_master_key(config.project_id.as_str())?;
    insert_wrapped_key(
        store,
        config.project_id.as_str(),
        Some(profile_id),
        KeyPurpose::ProfileSecret,
        &master_key,
        timestamp,
    )?;
    insert_wrapped_key(
        store,
        config.project_id.as_str(),
        Some(profile_id),
        KeyPurpose::ProfileFingerprint,
        &master_key,
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
    let name = SecretName::new(args.key.clone())
        .map_err(|_| CliError::Config("invalid secret name".to_owned()))?;
    let source = source_arg_to_str(args.source.source.unwrap_or(SecretSourceArg::UserLocal));
    let resolved = require_project(context)?;
    let mut store = open_store(context)?;
    let profile = default_profile(&store, &resolved.config)?;
    let profile_id = profile.id;
    if let Some(existing) = store.get_secret_by_source(
        resolved.config.project_id.as_str(),
        &profile_id,
        name.as_str(),
        source,
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
    let audit_key =
        load_project_key(context, &store, resolved.config.project_id.as_str(), KeyPurpose::Audit)?;
    let (encrypted, fingerprint) = encrypt_secret_version(
        context,
        &store,
        SecretEncryptRequest {
            project_id: resolved.config.project_id.as_str(),
            profile_id: &profile_id,
            secret_id: secret_id.as_str(),
            secret_name: name.as_str(),
            version,
            value,
        },
    )?;
    let secret_id_string = secret_id.into_string();
    let metadata = secret_audit_metadata("SET", name.as_str(), &profile_id, source, Some(version));
    let audit = AuditWrite {
        project_id: resolved.config.project_id.as_str(),
        profile_id: Some(&profile_id),
        action: "SET",
        status: "SUCCESS",
        secret_name: Some(name.as_str()),
        command: None,
        metadata_json: &metadata,
        timestamp,
    };

    store.create_active_secret_with_audit(
        &SecretRecord {
            id: secret_id_string.clone(),
            project_id: resolved.config.project_id.as_str().to_owned(),
            profile_id: profile_id.clone(),
            name: name.as_str().to_owned(),
            source: source.to_owned(),
            origin: origin.to_owned(),
            current_version: version,
            state: "active".to_owned(),
            created_at: timestamp,
            updated_at: timestamp,
            last_rotated_at: None,
            deleted_at: None,
        },
        &SecretVersionRecord {
            secret_id: secret_id_string.clone(),
            version,
            source: source.to_owned(),
            origin: origin.to_owned(),
            state: "current".to_owned(),
            created_at: timestamp,
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
            created_at: timestamp,
        },
        &SecretFingerprintRecord {
            secret_id: secret_id_string,
            version,
            fingerprint,
            created_at: timestamp,
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
    let master_key = context.key_store.load_master_key(project_id)?;
    let record = store
        .get_key_by_scope(project_id, Some(profile_id), purpose.as_str())?
        .ok_or_else(|| CliError::Config("profile key is missing".to_owned()))?;
    let wrapping_key = derive_wrapping_key_v1(
        &master_key,
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
    let master_key = context.key_store.load_master_key(project_id)?;
    let record = store
        .get_key_by_scope(project_id, None, purpose.as_str())?
        .ok_or_else(|| CliError::Config("project key is missing".to_owned()))?;
    let wrapping_key =
        derive_wrapping_key_v1(&master_key, &HkdfWrapInfo::new(project_id, None, purpose))?;
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
    fs::create_dir_all(agent_data_dir(context))?;
    let entry = json!({
        "timestamp": now_unix_nanos()?,
        "severity": "info",
        "component": "agent",
        "action": action,
        "status": status,
        "message": message,
    });
    let mut file =
        fs::OpenOptions::new().create(true).append(true).open(agent_log_path(context))?;
    writeln!(file, "{entry}")?;
    Ok(())
}

#[derive(Debug)]
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
}

const CONFIG_KEY_SPECS: [ConfigKeySpec; 5] = [
    ConfigKeySpec { key: "privacy.redact_names", kind: ConfigValueKind::Bool, audit: false },
    ConfigKeySpec { key: "example.auto_refresh", kind: ConfigValueKind::Bool, audit: false },
    ConfigKeySpec { key: "agent.autostart", kind: ConfigValueKind::Bool, audit: true },
    ConfigKeySpec { key: "reveal.ttl", kind: ConfigValueKind::Duration, audit: true },
    ConfigKeySpec {
        key: "runtime.session_secret_name_retention",
        kind: ConfigValueKind::Duration,
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
    }
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

fn refresh_example_for_project(context: &RuntimeContext) -> Result<(), CliError> {
    let resolved = require_project(context)?;
    let store = open_store(context)?;
    let mut names = BTreeSet::new();
    for profile in store.list_profiles(resolved.config.project_id.as_str())? {
        for secret in store
            .list_active_secrets_by_profile(resolved.config.project_id.as_str(), &profile.id)?
        {
            names.insert(secret.name);
        }
    }
    write_example_block(&resolved.root, &names)
}

fn write_example_block(root: &Path, names: &BTreeSet<String>) -> Result<(), CliError> {
    let path = root.join(EXAMPLE_FILE);
    let managed_block = managed_example_block(names);
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
    findings: &mut Vec<ScanFinding>,
) -> Result<(), CliError> {
    if path.is_dir() {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let child = entry.path();
            if should_skip_scan_path(&child) {
                continue;
            }
            scan_path(root, &child, known_values, findings)?;
        }
        return Ok(());
    }

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

fn ensure_git_worktree(start: &Path) -> Result<(), CliError> {
    let mut current = start.canonicalize()?;
    loop {
        if current.join(".git").exists() {
            return Ok(());
        }
        if !current.pop() {
            return Err(CliError::Config("git worktree required for --staged".to_owned()));
        }
    }
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
    let value = unquote_env_value(value.trim());
    if value.contains('\0') {
        return EnvImportEntry::Invalid;
    }
    EnvImportEntry::Secret { key: key.to_owned(), value }
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

fn now_unix_nanos() -> Result<i64, CliError> {
    let elapsed = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| CliError::Time)?;
    i64::try_from(elapsed.as_nanos()).map_err(|_| CliError::Time)
}

#[cfg(test)]
mod tests {
    use clap::Parser;
    use locket_platform::MemoryMasterKeyStore;
    use tempfile::tempdir;

    use super::{Cli, RuntimeContext, run_with_context};

    fn test_context(directory: &tempfile::TempDir) -> RuntimeContext {
        RuntimeContext {
            cwd: directory.path().to_path_buf(),
            store_path: directory.path().join("store.db"),
            config_path: directory.path().join("config.toml"),
            key_store: std::sync::Arc::new(MemoryMasterKeyStore::default()),
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
        assert_eq!(actions, ["SET", "ROTATE", "PURGE", "DELETE", "PURGE", "AUDIT_VERIFY"]);
        for (_, metadata) in rows {
            assert!(!metadata.contains("postgres://localhost/old"));
            assert!(!metadata.contains("postgres://localhost/new"));
        }
        Ok(())
    }

    fn assert_error_contains(result: Result<(), super::CliError>, expected: &str) {
        assert!(result.is_err(), "expected error containing {expected:?}");
        if let Err(error) = result {
            assert!(error.to_string().contains(expected), "{error}");
        }
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
            &["locket", "rm", "DATABASE_URL"],
            &["locket", "purge", "DATABASE_URL", "--all-versions"],
            &["locket", "rotate", "DATABASE_URL", "--grace-ttl", "24h"],
            &["locket", "lock"],
            &["locket", "unlock", "--verify-user"],
            &["locket", "meta", "DATABASE_URL", "--owner", "platform", "--required"],
            &["locket", "history", "DATABASE_URL"],
            &["locket", "diff", "dev", "staging"],
            &["locket", "audit", "verify"],
            &["locket", "exec", "--secret", "DATABASE_URL", "--", "/bin/sh", "-c", "true"],
            &["locket", "config", "list"],
            &["locket", "config", "get", "privacy.redact_names"],
            &["locket", "config", "set", "privacy.redact_names", "true"],
            &["locket", "config", "unset", "privacy.redact_names"],
            &["locket", "passkey", "register"],
            &["locket", "passkey", "list", "--all"],
            &["locket", "passkey", "remove", "work-laptop"],
        ] {
            assert!(Cli::try_parse_from(args).is_ok(), "{args:?}");
        }
    }

    #[test]
    fn parses_profile_project_and_agent_commands() {
        for args in [
            ["locket", "profile", "create", "dev"].as_slice(),
            &["locket", "profile", "mark-dangerous", "prod"],
            &["locket", "project", "trust-root"],
            &["locket", "project", "list-roots"],
            &["locket", "project", "untrust-root", "abc123"],
            &["locket", "agent", "start"],
            &["locket", "agent", "status"],
            &["locket", "agent", "stop"],
            &["locket", "agent", "logs"],
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
    fn status_reports_not_initialized_without_project() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let context = test_context(&directory);
        let mut output = Vec::new();

        run_with_context(Cli::try_parse_from(["locket"])?, &context, &mut output)?;

        let output = String::from_utf8(output)?;
        assert!(output.contains("not initialized"));
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
    fn install_hooks_prepends_managed_block_and_preserves_existing_hook()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let context = test_context(&directory);
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
        run_with_context(
            Cli::try_parse_from(["locket", "install-hooks"])?,
            &context,
            &mut install_output,
        )?;
        let install_output = String::from_utf8(install_output)?;
        assert!(install_output.contains("hook: locket scan --staged"));
        assert!(install_output.contains("secrets: not written"));

        let hook = std::fs::read_to_string(hooks_dir.join("pre-commit"))?;
        assert!(hook.starts_with(super::HOOK_BEGIN));
        assert!(hook.contains("locket scan --staged"));
        assert!(hook.contains(super::HOOK_END));
        assert!(hook.contains("echo existing"));
        assert!(!hook.contains("secret-value"));

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
            Cli::try_parse_from(["locket", "get", "DATABASE_URL", "--reveal"])?,
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
        assert_eq!(
            row,
            (
                "primary database".to_owned(),
                "platform".to_owned(),
                "[\"database\",\"prod\"]".to_owned(),
                true,
                1_000,
            )
        );
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
            Cli::try_parse_from(["locket", "get", "DATABASE_URL", "--reveal"])?,
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
        assert!(String::from_utf8(audit_output)?.contains("verified 5 row(s)"));

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
            Cli::try_parse_from(["locket", "get", "DATABASE_URL", "--reveal"])?,
            &context,
            &mut reveal_output,
        )?;
        assert_eq!(String::from_utf8(reveal_output)?, "postgres://localhost/new\n");
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
