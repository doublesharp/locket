//! Locket command-line entry point.

use clap::{Args, Parser, Subcommand, ValueEnum};
use directories::ProjectDirs;
use locket_core::{ProfileId, ProfileName, ProjectConfig, ProjectId};
use locket_scan::{FindingKind, ScanFinding, redact_text, scan_text};
use locket_store::{Store, StoreError};
use sha2::{Digest, Sha256};
use std::error::Error;
use std::fmt::{self, Display};
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode as ProcessExitCode;
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
    /// Get secret metadata, reveal, or copy.
    Get(GetArgs),
    /// Tombstone a secret source.
    Rm(SourceKeyArgs),
    /// Destructively purge encrypted versions.
    Purge(PurgeArgs),
    /// List secrets.
    List(ListArgs),
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

#[derive(Debug, Clone)]
struct RuntimeContext {
    cwd: PathBuf,
    store_path: PathBuf,
}

impl RuntimeContext {
    fn default() -> Result<Self, CliError> {
        let cwd = std::env::current_dir()?;
        let Some(project_dirs) = ProjectDirs::from("dev", "0xdoublesharp", "Locket") else {
            return Err(CliError::Config("could not resolve a local data directory".to_owned()));
        };
        let data_dir = project_dirs.data_dir();
        fs::create_dir_all(data_dir)?;
        Ok(Self { cwd, store_path: data_dir.join("store.db") })
    }
}

#[derive(Debug)]
enum CliError {
    Config(String),
    Io(io::Error),
    Store(StoreError),
    TomlDe(toml::de::Error),
    TomlSer(toml::ser::Error),
    Time,
}

impl CliError {
    const fn exit_code(&self) -> u8 {
        match self {
            Self::Config(_) | Self::TomlDe(_) | Self::TomlSer(_) => 64,
            Self::Io(_) | Self::Store(_) | Self::Time => 90,
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
    writeln!(
        output,
        "note: encrypted secret storage and recovery setup are not wired in this build yet"
    )?;
    Ok(())
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

    writeln!(output, "created profile {profile_name} ({profile_id})")?;
    writeln!(output, "note: profile key generation is not wired in this build yet")?;
    Ok(())
}

fn emit_example_command(context: &RuntimeContext, output: &mut impl Write) -> Result<(), CliError> {
    let resolved = require_project(context)?;
    ensure_example_file(&resolved.root)?;
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
    let managed_block = managed_example_block();
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

fn managed_example_block() -> String {
    format!("{EXAMPLE_BEGIN}\n{EXAMPLE_END}\n")
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
    use tempfile::tempdir;

    use super::{Cli, RuntimeContext, run_with_context};

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
            &["locket", "get", "DATABASE_URL", "--copy"],
            &["locket", "rm", "DATABASE_URL"],
            &["locket", "purge", "DATABASE_URL", "--all-versions"],
            &["locket", "rotate", "DATABASE_URL", "--grace-ttl", "24h"],
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
        let context = RuntimeContext {
            cwd: directory.path().to_path_buf(),
            store_path: directory.path().join("store.db"),
        };
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
        let context = RuntimeContext {
            cwd: directory.path().to_path_buf(),
            store_path: directory.path().join("store.db"),
        };
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
    fn scan_reports_metadata_only_provider_findings() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let sample_path = directory.path().join("sample.txt");
        std::fs::write(&sample_path, "token=sk_test_sampleTokenValue123\n")?;
        let context = RuntimeContext {
            cwd: directory.path().to_path_buf(),
            store_path: directory.path().join("store.db"),
        };
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
        let context = RuntimeContext {
            cwd: directory.path().to_path_buf(),
            store_path: directory.path().join("store.db"),
        };
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
