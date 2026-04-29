//! Locket command-line entry point.

use clap::{Args, Parser, Subcommand, ValueEnum};
use directories::ProjectDirs;
use locket_core::{KeyId, ProfileId, ProfileName, ProjectConfig, ProjectId, SecretId, SecretName};
use locket_crypto::{
    EncryptedSecretValue, HkdfWrapInfo, KeyPurpose, KeyWrapAad, KeyWrapPurpose, WrappedKeyMaterial,
    decrypt_secret_value_v1, derive_wrapping_key_v1, encrypt_secret_value_v1, generate_key,
    key_wrap_aad_v1, secret_blob_aad_v1, secret_fingerprint_v1, unwrap_key_material_v1,
    wrap_key_material_v1,
};
use locket_platform::{KeyringMasterKeyStore, MasterKeyStore};
use locket_scan::{FindingKind, ScanFinding, redact_text, scan_text};
use locket_store::{
    KeyRecord, ProfileRecord, SecretBlobRecord, SecretFingerprintRecord, SecretRecord,
    SecretVersionRecord, Store, StoreError,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::error::Error;
use std::fmt::{self, Display};
use std::fs;
use std::io::{self, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode as ProcessExitCode;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

const LOCKET_TOML: &str = "locket.toml";
const EXAMPLE_FILE: &str = ".env.example";
const GITIGNORE_FILE: &str = ".gitignore";
const EXAMPLE_BEGIN: &str = "# --- BEGIN LOCKET MANAGED ---";
const EXAMPLE_END: &str = "# --- END LOCKET MANAGED ---";
const GITIGNORE_ENTRIES: [&str; 4] = [".env", ".env.*", ".locket.local", ".locketignore"];

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
    /// Manage the local agent.
    Agent {
        /// Agent command.
        #[command(subcommand)]
        command: AgentCommand,
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

#[derive(Debug, Subcommand)]
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
        Command::List(args) => list_command(context, output, &args)?,
        Command::Exec(args) => exec_command(context, output, &args)?,
        Command::EmitExample => emit_example_command(context, output)?,
        Command::Profile { command } => profile_command(context, output, command)?,
        Command::Scan(args) => scan_command(context, output, args)?,
        Command::Redact(args) => redact_command(context, output, args)?,
        Command::Context(args) => context_command(context, output, args)?,
        _ => {
            writeln!(output, "locket: command parsed but not implemented yet")?;
        }
    }

    Ok(())
}

#[derive(Clone)]
struct RuntimeContext {
    cwd: PathBuf,
    store_path: PathBuf,
    key_store: Arc<dyn MasterKeyStore + Send + Sync>,
}

impl RuntimeContext {
    fn default() -> Result<Self, CliError> {
        let cwd = std::env::current_dir()?;
        let Some(project_dirs) = ProjectDirs::from("dev", "0xdoublesharp", "Locket") else {
            return Err(CliError::Config("could not resolve a local data directory".to_owned()));
        };
        let data_dir = project_dirs.data_dir();
        fs::create_dir_all(data_dir)?;
        Ok(Self {
            cwd,
            store_path: data_dir.join("store.db"),
            key_store: Arc::new(KeyringMasterKeyStore),
        })
    }
}

#[derive(Debug)]
enum CliError {
    Config(String),
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
            Self::Platform(locket_platform::PlatformError::MasterKeyNotFound) => 72,
            Self::Io(_) | Self::Store(_) | Self::Crypto(_) | Self::Platform(_) | Self::Time => 90,
        }
    }
}

impl Display for CliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(message) => formatter.write_str(message),
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
    if args.overwrite {
        return Err(CliError::Config(
            "import --overwrite is not wired in this build yet".to_owned(),
        ));
    }
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
    store.tombstone_secret(&secret.id, now_unix_nanos()?)?;
    refresh_example_for_project(context)?;
    writeln!(output, "removed {} ({source})", args.key)?;
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
    let secrets =
        store.list_active_secrets_by_profile(resolved.config.project_id.as_str(), &profile.id)?;
    if args.all {
        writeln!(output, "list: deleted and deprecated rows are not wired in this build yet")?;
    }
    if secrets.is_empty() {
        writeln!(output, "no secrets")?;
        return Ok(());
    }
    for secret in secrets {
        writeln!(
            output,
            "{} source={} version={}",
            secret.name, secret.source, secret.current_version
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

fn profile_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    command: ProfileCommand,
) -> Result<(), CliError> {
    match command {
        ProfileCommand::List => list_profiles(context, output),
        ProfileCommand::Create(args) => create_profile(context, output, args),
        ProfileCommand::MarkDangerous(_) | ProfileCommand::ClearDangerous(_) => {
            writeln!(output, "locket: command parsed but not implemented yet")?;
            Ok(())
        }
    }
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

fn emit_example_command(context: &RuntimeContext, output: &mut impl Write) -> Result<(), CliError> {
    let resolved = require_project(context)?;
    refresh_example_for_project(context)?;
    writeln!(output, "updated {}", resolved.root.join(EXAMPLE_FILE).display())?;
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

    if args.require_known && resolve_project(&context.cwd)?.is_none() {
        return Err(CliError::Config(
            "known-value scanning requires a Locket project and unlocked vault".to_owned(),
        ));
    }
    if args.no_gitignore {
        writeln!(output, "scan: gitignore rules disabled")?;
    }

    let scan_root = match args.path {
        Some(path) => absolutize(&context.cwd, Path::new(&path)),
        None => resolve_project(&context.cwd)?
            .map_or_else(|| context.cwd.clone(), |project| project.root),
    };

    let mut findings = Vec::new();
    scan_path(&scan_root, &scan_root, &mut findings)?;
    for finding in &findings {
        writeln!(output, "{}", format_finding(finding))?;
    }

    if findings.is_empty() {
        writeln!(output, "scan: no findings")?;
    } else {
        writeln!(output, "scan: {} finding(s)", findings.len())?;
    }

    if args.require_known {
        writeln!(output, "scan: known-value coverage is not wired in this build yet")?;
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

    let result = redact_text(&input);
    write!(output, "{}", result.text)?;
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
    if store
        .get_active_secret(resolved.config.project_id.as_str(), &profile.id, name.as_str(), source)?
        .is_some()
    {
        return Err(CliError::Config("secret already exists; use rotate".to_owned()));
    }

    let secret_id = SecretId::generate().map_err(|_| CliError::Time)?;
    let version = 1;
    let profile_secret_key = load_profile_key(
        context,
        &store,
        resolved.config.project_id.as_str(),
        &profile.id,
        KeyPurpose::ProfileSecret,
    )?;
    let profile_fingerprint_key = load_profile_key(
        context,
        &store,
        resolved.config.project_id.as_str(),
        &profile.id,
        KeyPurpose::ProfileFingerprint,
    )?;
    let value_aad = secret_blob_aad_v1(&locket_crypto::SecretBlobAad::new(
        resolved.config.project_id.as_str(),
        &profile.id,
        secret_id.as_str(),
        name.as_str(),
        version,
    ))?;
    let wrap_aad = key_wrap_aad_v1(&KeyWrapAad::new(
        resolved.config.project_id.as_str(),
        secret_id.as_str(),
        Some(&profile.id),
        version,
        KeyWrapPurpose::SecretDek,
    ))?;
    let encrypted = encrypt_secret_value_v1(&profile_secret_key, value, &value_aad, &wrap_aad)?;
    let fingerprint = secret_fingerprint_v1(&profile_fingerprint_key, value)?;
    let secret_id_string = secret_id.into_string();

    store.create_active_secret(
        &SecretRecord {
            id: secret_id_string.clone(),
            project_id: resolved.config.project_id.as_str().to_owned(),
            profile_id: profile.id,
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
            fingerprint: fingerprint.to_vec(),
            created_at: timestamp,
        },
    )?;
    Ok(())
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

fn decrypt_current_secret(
    context: &RuntimeContext,
    resolved: &ResolvedSecret,
) -> Result<zeroize::Zeroizing<String>, CliError> {
    let store = open_store(context)?;
    let profile_secret_key = load_profile_key(
        context,
        &store,
        resolved.project.config.project_id.as_str(),
        &resolved.profile.id,
        KeyPurpose::ProfileSecret,
    )?;
    let blob = store
        .get_blob(&resolved.secret.id, resolved.secret.current_version)?
        .ok_or_else(|| CliError::Config("secret blob is missing".to_owned()))?;
    let value_aad = secret_blob_aad_v1(&locket_crypto::SecretBlobAad::new(
        resolved.project.config.project_id.as_str(),
        &resolved.profile.id,
        &resolved.secret.id,
        &resolved.secret.name,
        resolved.secret.current_version,
    ))?;
    let wrap_aad = key_wrap_aad_v1(&KeyWrapAad::new(
        resolved.project.config.project_id.as_str(),
        &resolved.secret.id,
        Some(&resolved.profile.id),
        resolved.secret.current_version,
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

fn scan_path(root: &Path, path: &Path, findings: &mut Vec<ScanFinding>) -> Result<(), CliError> {
    if path.is_dir() {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let child = entry.path();
            if should_skip_scan_path(&child) {
                continue;
            }
            scan_path(root, &child, findings)?;
        }
        return Ok(());
    }

    if !path.is_file() {
        return Ok(());
    }

    let label = path_label(root, path);
    match fs::read_to_string(path) {
        Ok(text) => findings.extend(scan_text(&label, &text)),
        Err(error) if error.kind() == io::ErrorKind::InvalidData => {
            findings.extend(scan_text(&label, ""));
        }
        Err(error) => return Err(error.into()),
    }

    Ok(())
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
            key_store: std::sync::Arc::new(MemoryMasterKeyStore::default()),
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
            &["locket", "exec", "--secret", "DATABASE_URL", "--", "/bin/sh", "-c", "true"],
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
            &["locket", "project", "untrust-root", "abc123"],
            &["locket", "agent", "start"],
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
}
