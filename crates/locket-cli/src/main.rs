//! Locket command-line entry point.

mod agent;
mod audit;
mod bootstrap;
mod bundle;
mod cli_error;
mod client;
mod config_cmd;
mod config_validation;
mod context;
mod debug_cmd;
mod device;
pub(crate) mod diagnostics;
mod diff;
mod emit_example;
mod exec;
mod get;
mod import;
mod init;
mod install_hooks;
mod key_access;
mod lock;
mod meta;
mod onboarding;
mod passkey;
mod policy_authoring;
mod profile;
mod project;
mod project_files;
mod prompts;
mod recovery;
mod redact;
mod run;
mod runtime;
pub(crate) mod scan;
mod secret_helpers;
mod secrets_cmd;
mod set;
mod shell;
mod status;
mod time_helpers;

pub(crate) use cli_error::{
    CliError, bundle_verification_error, child_exit_error, exec_prepare_error,
    project_root_untrusted_error, secret_deleted_error, unimplemented_in_build_error,
};
pub(crate) use config_validation::{
    CONFIG_KEY_SPECS, config_get_value, config_set_value, config_unset_value, format_config_value,
    parse_config_value, read_user_config, split_config_key, validate_config_key,
    validate_config_value_not_secret_like, validate_stored_config_value,
    write_config_update_audit_if_available, write_user_config,
};
pub(crate) use context::privacy_redact_names_enabled;
#[cfg(test)]
pub(crate) use device::{device_fingerprint_hex, encode_device_descriptor};
pub(crate) use install_hooks::git_dir_for_worktree;
pub(crate) use key_access::{
    MasterKeySource, default_profile, ensure_project_exists, load_master_key,
    load_master_key_verified_by_project_key, load_project_key, load_project_key_with_source,
    store_master_key_with_fallback,
};
pub(crate) use project_files::{
    EXAMPLE_FILE, GITIGNORE_ENTRIES, GITIGNORE_FILE, collect_example_secret_names,
    config_bool_value, ensure_gitignore, refresh_example_for_project_if_enabled,
    write_example_block, write_example_block_for_emit, write_example_emit_audit,
};
#[cfg(test)]
pub(crate) use prompts::{
    ConfirmationReader, PassphraseReader, RecoveryCodeReader, SecretValueReader,
    read_secret_value_from_reader, validate_secret_value,
};
#[cfg(test)]
pub(crate) use recovery::{recovery_dir, recovery_rotate_command, restore_from_recovery_code};
#[cfg(test)]
pub(crate) use redact::{
    AiSafeRawChunk, AiSafeStream, AiSafeStreamRedactor, KnownSecretRedaction,
    collect_redaction_values_for_redact,
};
pub(crate) use runtime::RuntimeContext;
use secret_helpers::{
    PolicySecretSelection, ResolvedSecret, SecretEncryptRequest,
    decrypt_secret_version, encrypt_secret_version,
    policy_secret_selections, resolve_active_secret_for_source,
    resolve_secret_for_source, secret_audit_metadata,
    select_copy_profiles_and_sources,
};
#[cfg(test)]
pub(crate) use get::{ClipboardCommand, copy_secret_to_clipboard_with, get_command_with_clipboard, select_clipboard_command};
#[cfg(test)]
pub(crate) use import::{EnvImportEntry, parse_env_import};
#[cfg(test)]
pub(crate) use set::set_secret_value;
#[cfg(test)]
pub(crate) use shell::SHELL_HOOK_BEGIN;
pub(crate) use time_helpers::{
    format_optional_unix_nanos, format_unix_nanos, optional_i64, resolve_diff_since,
    unix_nanos_to_rfc3339,
};

use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use clap_complete::Shell as CompletionShell;
use locket_core::{
    CommandPolicy, CommandSpec, Duration as LocketDuration, ExternalEnvSource, KeyId,
    PROJECT_CONFIG_SCHEMA_VERSION, PolicyDocument, ProfileId, ProjectConfig,
    SecretId, SecretName,
};
use locket_crypto::{
    EncryptedSecretValue, HkdfWrapInfo, KeyPurpose, KeyWrapAad, KeyWrapPurpose,
    derive_wrapping_key_v1, generate_key, generate_recovery_code_bytes, generate_recovery_salt,
    key_wrap_aad_v1, recovery_code_decode, recovery_code_encode, seal_recovery_entry_v1,
    wrap_key_material_v1,
};
use locket_platform::RecoveryEnvelopeEntry;
#[cfg(test)]
use locket_platform::{
    RecoveryEnvelope, RecoveryKdfToml, save_recovery_envelope, save_recovery_kdf_toml,
};
#[cfg(test)]
use locket_platform::{load_recovery_envelope, load_recovery_kdf_toml};
use locket_scan::{FindingKind, redact_text, scan_text};
#[cfg(test)]
use locket_store::DeviceRecord;
use locket_store::{
    AuditContext, AuditWrite, KeyRecord, ProfileRecord, SecretBlobRecord, SecretCopyTarget,
    SecretFingerprintRecord, SecretRecord, SecretVersionRecord, Store, VersionDeprecation,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, Write};
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::ExitCode as ProcessExitCode;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use policy_authoring::PolicyCommand;
use time_helpers::NANOS_PER_SECOND;

pub(crate) const LOCKET_TOML: &str = "locket.toml";
pub(crate) const CONFIG_TOML: &str = "config.toml";
pub(crate) const HOOK_BEGIN: &str = "# --- BEGIN LOCKET PRE-COMMIT ---";
pub(crate) const HOOK_END: &str = "# --- END LOCKET PRE-COMMIT ---";
const DEFAULT_MAX_GRACE_TTL_SECONDS: u64 = 7 * 24 * 60 * 60;
const AGENT_LOG_MAX_BYTES: u64 = 1024 * 1024;
const AGENT_LOG_RETAINED_FILES: u8 = 5;
const AGENT_LOG_FOLLOW_SLEEP_MS: u64 = 250;
const AI_SAFE_READ_CHUNK_BYTES: usize = 8 * 1024;
const AI_SAFE_PARTIAL_LINE_MAX_BYTES: usize = 64 * 1024;

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
    /// Manage local/trusted devices.
    Device {
        /// Device command.
        #[command(subcommand)]
        command: DeviceCommand,
    },
    /// Manage automation clients.
    Client {
        /// Automation-client command.
        #[command(subcommand)]
        command: ClientCommand,
    },
    /// Export a sealed local bundle.
    Export(ExportArgs),
    /// Import a sealed local bundle.
    ImportBundle(ImportBundleArgs),
    /// Verify sealed local bundles.
    Bundle {
        /// Bundle command.
        #[command(subcommand)]
        command: BundleCommand,
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
pub(crate) struct InitArgs {
    /// Project display name.
    #[arg(long)]
    pub(crate) name: Option<String>,
    /// Initial profile name.
    #[arg(long)]
    pub(crate) profile: Option<String>,
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
    /// Skip the typed confirmation prompt.
    ///
    /// Intended for non-interactive automation. Use only when the caller has
    /// already confirmed the destructive scope through another channel.
    #[arg(long)]
    force: bool,
}

#[derive(Debug, Args)]
struct ListArgs {
    /// Include deleted sources and deprecated version counts.
    #[arg(long)]
    all: bool,
}

/// Arguments for the `locket exec` command.
#[derive(Debug, Args)]
pub struct ExecArgs {
    /// Secret name to inject. May be repeated.
    #[arg(long = "secret")]
    pub secrets: Vec<String>,
    /// Inject every active profile secret after confirmation.
    #[arg(long, conflicts_with = "secrets")]
    pub all: bool,
    /// Skip the typed confirmation prompt for `--all`.
    ///
    /// Intended for non-interactive automation. The active-profile secret
    /// names are still recorded in the EXEC audit row.
    #[arg(long)]
    pub force: bool,
    /// Command and arguments after `--`.
    #[arg(last = true, required = true)]
    pub command: Vec<String>,
}

/// Arguments for the `locket run` command.
#[derive(Debug, Args)]
pub struct RunArgs {
    /// Command policy name from [commands.<policy>].
    pub policy: String,
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
    /// Require known-value coverage; fails when the vault cannot supply known values.
    #[arg(long)]
    require_known: bool,
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
    /// Restrict the listing to a single runtime source.
    #[arg(long, value_enum)]
    source: Option<SecretSourceArg>,
    /// Restrict the listing to versions in a single state.
    #[arg(long, value_enum)]
    state: Option<HistoryStateFilter>,
    /// Maximum number of versions to display per source.
    #[arg(long)]
    limit: Option<u32>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum HistoryStateFilter {
    /// Current/active versions only.
    Current,
    /// Deprecated versions only.
    Deprecated,
    /// Purged versions only.
    Purged,
}

impl HistoryStateFilter {
    fn matches(self, state: &str) -> bool {
        match self {
            Self::Current => state == "current",
            Self::Deprecated => state == "deprecated",
            Self::Purged => state == "purged",
        }
    }
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
pub(crate) struct CopyArgs {
    /// Secret key name.
    pub(crate) key: String,
    /// Source profile name.
    #[arg(long)]
    pub(crate) from: String,
    /// Target profile name.
    #[arg(long)]
    pub(crate) to: String,
    /// Runtime source to copy from.
    #[arg(long, value_enum)]
    pub(crate) from_source: Option<SecretSourceArg>,
    /// Runtime source to copy to.
    #[arg(long, value_enum)]
    pub(crate) to_source: Option<SecretSourceArg>,
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

#[derive(Debug, Subcommand)]
enum DeviceCommand {
    /// Initialize or rotate the local device descriptor.
    Init(DeviceInitArgs),
    /// Print the active local device descriptor.
    Pubkey,
    /// Add a trusted device descriptor.
    Add(DeviceAddArgs),
    /// List trusted device metadata.
    List(DeviceListArgs),
    /// Revoke a trusted device.
    Remove(DeviceRemoveArgs),
}

#[derive(Debug, Args)]
struct DeviceInitArgs {
    /// Replace the active local device descriptor.
    #[arg(long)]
    force: bool,
}

#[derive(Debug, Args)]
struct DeviceAddArgs {
    /// Human-readable device name.
    name: String,
    /// Device descriptor emitted by `locket device pubkey`.
    #[arg(long)]
    device: String,
}

#[derive(Debug, Args)]
struct DeviceListArgs {
    /// Include revoked devices.
    #[arg(long)]
    all: bool,
}

#[derive(Debug, Args)]
struct DeviceRemoveArgs {
    /// Device name, id, or fingerprint.
    device: String,
    /// Permit removing the active local device.
    #[arg(long)]
    force: bool,
}

#[derive(Debug, Subcommand)]
enum ClientCommand {
    /// Create a Locket-managed automation client metadata record.
    Create(ClientCreateArgs),
    /// Add an externally managed automation client public key.
    Add(ClientAddArgs),
    /// List registered automation clients.
    List(ClientListArgs),
    /// Revoke an automation client.
    Revoke {
        /// Client name or id.
        client: String,
    },
}

#[derive(Debug, Args)]
struct ClientCreateArgs {
    /// Client display name.
    name: String,
    /// Locket-managed private-key storage mode metadata.
    #[arg(long, value_enum, default_value_t = ClientStorageArg::OsKeychain)]
    storage: ClientStorageArg,
    /// Allowed automation action. May be repeated.
    #[arg(long = "action")]
    actions: Vec<String>,
    /// Allowed command policy. May be repeated.
    #[arg(long = "policy")]
    policies: Vec<String>,
}

#[derive(Debug, Args)]
struct ClientAddArgs {
    /// Client display name.
    name: String,
    /// Ed25519 public key as 64 lowercase or uppercase hex characters.
    #[arg(long)]
    pubkey: String,
    /// Allowed automation action. May be repeated.
    #[arg(long = "action")]
    actions: Vec<String>,
    /// Allowed command policy. May be repeated.
    #[arg(long = "policy")]
    policies: Vec<String>,
}

#[derive(Debug, Args)]
struct ClientListArgs {
    /// Include revoked clients.
    #[arg(long)]
    all: bool,
}

#[derive(Debug, Args)]
struct ExportArgs {
    /// Require sealed-bundle mode.
    #[arg(long)]
    sealed: bool,
    /// Recipient device descriptor. May be repeated.
    #[arg(long = "recipient", required = true)]
    recipients: Vec<String>,
    /// Profile to include. Defaults to the active profile.
    #[arg(long, conflicts_with = "all_profiles")]
    profile: Option<String>,
    /// Include all profiles.
    #[arg(long)]
    all_profiles: bool,
    /// Include encrypted remote audit rows in the bundle payload.
    #[arg(long)]
    include_audit: bool,
    /// Output path. Defaults to locket-bundle-<utc-timestamp>.locket-bundle.
    #[arg(long)]
    output: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct ImportBundleArgs {
    /// Bundle file to import.
    bundle: PathBuf,
    /// Import remote audit rows when present.
    #[arg(long)]
    include_audit: bool,
    /// Prefer incoming metadata on conflicts.
    #[arg(long, conflicts_with = "accept_local")]
    accept_incoming: bool,
    /// Prefer local metadata on conflicts.
    #[arg(long)]
    accept_local: bool,
}

#[derive(Debug, Subcommand)]
enum BundleCommand {
    /// Verify a sealed bundle without importing it.
    Verify(BundleVerifyArgs),
}

#[derive(Debug, Args)]
struct BundleVerifyArgs {
    /// Bundle file to verify.
    bundle: PathBuf,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ClientStorageArg {
    /// Store client private key in the OS keychain.
    OsKeychain,
    /// Store a wrapped local private-key file.
    WrappedLocalFile,
}

impl ClientStorageArg {
    const fn as_str(self) -> &'static str {
        match self {
            Self::OsKeychain => "os-keychain",
            Self::WrappedLocalFile => "wrapped-local-file",
        }
    }
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
pub(crate) enum SecretSourceArg {
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
        Command::Status => status::status(context, output)?,
        Command::New(args) => new_command(context, output, &args)?,
        Command::Bootstrap => bootstrap::bootstrap_command(context, output)?,
        Command::Completion(args) => completion_command(output, args.shell)?,
        Command::Doctor => return diagnostics::doctor_command(context, output),
        Command::Debug { command } => debug_cmd::debug_command(context, output, command)?,
        Command::Init(args) => init::init(context, output, args)?,
        Command::Set(args) => set::set_command(context, output, &args)?,
        Command::Import(args) => import::import_command(context, output, &args)?,
        Command::Get(args) => get::get_command(context, output, &args)?,
        Command::Rm(args) => secrets_cmd::rm_command(context, output, &args)?,
        Command::Purge(args) => secrets_cmd::purge_command(context, output, &args)?,
        Command::List(args) => secrets_cmd::list_command(context, output, &args)?,
        Command::Exec(args) => exec::exec_command(context, output, &args)?,
        Command::Run(args) => run::run_command(context, output, &args)?,
        Command::Env { command } => env_command(context, output, command)?,
        Command::Compose { command } => compose_command(context, output, command)?,
        Command::Rotate(args) => secrets_cmd::rotate_command(context, output, &args)?,
        Command::Meta(args) => meta::meta_command(context, output, &args)?,
        Command::History(args) => secrets_cmd::history_command(context, output, &args)?,
        Command::Diff(args) => diff::diff_command(context, output, &args)?,
        Command::Copy(args) => secrets_cmd::copy_command(context, output, &args)?,
        Command::Audit { command } => audit::audit_command(context, output, command)?,
        Command::Lock => lock::lock_command(context, output)?,
        Command::Unlock(args) => lock::unlock_command(context, output, &args)?,
        Command::EmitExample => emit_example::emit_example_command(context, output)?,
        Command::InstallHooks => install_hooks::install_hooks_command(context, output)?,
        Command::Profile { command } => profile::profile_command(context, output, command)?,
        Command::Policy { command } => policy_authoring::command(context, output, command)?,
        Command::Project { command } => project::project_command(context, output, command)?,
        Command::Shellenv(args) => shell::shellenv_command(output, &args)?,
        Command::Hook(args) => shell::hook_command(output, &args)?,
        Command::Allow => shell::allow_command(context, output)?,
        Command::Deny(args) => shell::deny_command(context, output, &args)?,
        Command::Agent { command } => agent::agent_command(context, output, command)?,
        Command::Use(args) => profile::use_profile_command(context, output, args)?,
        Command::Scan(args) => scan::scan_command(context, output, &args)?,
        Command::Redact(args) => redact::redact_command(context, output, &args)?,
        Command::Context(args) => context::context_command(context, output, &args)?,
        Command::AiSafe(args) => redact::ai_safe_command(context, output, &args)?,
        Command::Config { command } => config_cmd::config_command(context, output, command)?,
        Command::Passkey { command } => passkey::passkey_command(context, output, command)?,
        Command::Device { command } => device::device_command(context, output, command)?,
        Command::Client { command } => client::client_command(context, output, command)?,
        Command::Export(args) => bundle::export_bundle_command(context, output, &args)?,
        Command::ImportBundle(args) => bundle::import_bundle_command(context, output, &args)?,
        Command::Bundle { command } => bundle::bundle_command(context, output, command)?,
        Command::Recover(args) => recovery::recover_command(context, output, &args)?,
        Command::Recovery { command } => recovery::recovery_command(context, output, command)?,
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

pub(crate) fn active_profile_secret_names(
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
    ensure_trusted_project_root(&store, &resolved)?;
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
    Err(child_exit_error(status))
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
    Err(child_exit_error(status))
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
    let execution = locket_exec::prepare_execution(&request).map_err(exec_prepare_error)?;
    debug_assert_eq!(
        plan.injected_names.len(),
        selections.iter().filter(|s| s.selected.is_some()).count()
    );

    Ok(PreparedDockerPolicyExecution { resolved, profile, policy, execution, plan, helper_kind })
}

fn ensure_runtime_policy_supported(policy: &CommandPolicy) -> Result<(), CliError> {
    if matches!(policy.command, CommandSpec::Shell(_)) {
        return Err(unimplemented_in_build_error(
            "shell policy execution is not wired in this build",
        ));
    }
    if policy.confirm {
        return Err(unimplemented_in_build_error("policy confirmation is not wired in this build"));
    }
    if policy.require_user_verification {
        return Err(unimplemented_in_build_error(
            "policy user verification is not wired in this build",
        ));
    }
    if !policy.external_env_sources.is_empty() {
        return Err(unimplemented_in_build_error(
            "policy external environment sources are not wired in this build",
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
    ensure_trusted_project_root(&store, resolved)?;
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

fn format_optional_str(value: Option<&str>) -> &str {
    value.unwrap_or("none")
}

pub(crate) const fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

pub(crate) fn ensure_project_metadata(
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

pub(crate) fn insert_wrapped_key(
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

fn preflight_rotate_secret_value(
    context: &RuntimeContext,
    args: &RotateArgs,
) -> Result<(), CliError> {
    let name = SecretName::new(args.key.clone())
        .map_err(|_| CliError::Config("invalid secret name".to_owned()))?;
    resolve_active_secret_for_source(context, name.as_str(), args.source.source)?;
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

struct CopySecretResult {
    from_profile: String,
    to_profile: String,
    from_source: String,
    to_source: String,
    from_version: u32,
    target_version: u32,
    prior_target_version: Option<u32>,
    operation: &'static str,
}

struct CopyTargetPlan {
    secret_id: String,
    version: u32,
    prior_version: Option<u32>,
    existing: Option<SecretRecord>,
}

pub(crate) struct CopySelection {
    pub(crate) from_profile: ProfileRecord,
    pub(crate) to_profile: ProfileRecord,
    pub(crate) source_secret: SecretRecord,
    pub(crate) from_source: String,
    pub(crate) to_source: String,
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
    ensure_trusted_project_root(&store, &resolved)?;
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
        from_version: selection.source_secret.current_version,
        target_version: target.version,
        prior_target_version: target.prior_version,
        operation,
    })
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
        return Err(secret_deleted_error("SecretDeleted: target secret source is deleted"));
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

pub(crate) fn collect_known_secret_values(
    context: &RuntimeContext,
    project: &ResolvedProject,
    timestamp: i64,
) -> Result<Vec<zeroize::Zeroizing<String>>, CliError> {
    let store = open_store(context)?;
    ensure_trusted_project_root(&store, project)?;
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

pub(crate) fn privacy_alias(kind: &str, id: &str) -> String {
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

pub(crate) fn trust_root(
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

pub(crate) fn open_store(context: &RuntimeContext) -> Result<Store, CliError> {
    if let Some(parent) = context.store_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut store = Store::open(&context.store_path)?;
    store.initialize_schema()?;
    Ok(store)
}

pub(crate) fn ensure_trusted_project_root(
    store: &Store,
    resolved: &ResolvedProject,
) -> Result<(), CliError> {
    let root_hash = root_hash(&resolved.root)?;
    if store.project_root_is_trusted(resolved.config.project_id.as_str(), &root_hash)? {
        return Ok(());
    }
    Err(project_root_untrusted_error())
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
/// Project root and configuration loaded from disk.
pub struct ResolvedProject {
    /// Absolute project root path.
    pub root: PathBuf,
    /// Parsed `locket.toml` configuration.
    pub config: ProjectConfig,
}

pub(crate) fn require_project(context: &RuntimeContext) -> Result<ResolvedProject, CliError> {
    resolve_project(&context.cwd)?.ok_or_else(|| CliError::Config("project not found".to_owned()))
}

pub(crate) fn resolve_project(start: &Path) -> Result<Option<ResolvedProject>, CliError> {
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
    if config.schema_version != PROJECT_CONFIG_SCHEMA_VERSION {
        return Err(CliError::Config(format!(
            "unsupported locket.toml schema_version {}; supported {}",
            config.schema_version, PROJECT_CONFIG_SCHEMA_VERSION
        )));
    }
    Ok(config)
}

pub(crate) fn load_command_policy(
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

pub(crate) fn read_policy_document(path: &Path) -> Result<PolicyDocument, CliError> {
    let content = fs::read_to_string(path)?;
    PolicyDocument::from_toml_str(&content).map_err(|error| CliError::Config(error.to_string()))
}

pub(crate) const fn command_type(command: &CommandSpec) -> &'static str {
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

pub(crate) fn write_project_config(path: &Path, config: &ProjectConfig) -> Result<(), CliError> {
    let content = toml::to_string_pretty(config)?;
    fs::write(path, content)?;
    Ok(())
}

pub(crate) fn write_runtime_policy_audit_if_available(
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

fn absolutize(cwd: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() { path.to_path_buf() } else { cwd.join(path) }
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

fn validate_secret_metadata_update(
    context: &RuntimeContext,
    resolved_secret: &ResolvedSecret,
    metadata: &SecretMetadataFlags,
    timestamp: i64,
) -> Result<(), CliError> {
    let fields = secret_metadata_text_fields(metadata);
    for (field, value) in &fields {
        validate_secret_metadata_field(field, value)?;
    }

    if let Ok(known_values) =
        collect_known_secret_values(context, &resolved_secret.project, timestamp)
    {
        for (field, value) in fields {
            if known_values.iter().any(|known_value| known_value.as_str() == value) {
                return Err(CliError::Config(format!(
                    "metadata field {field} matches an existing secret value; refusing to store it"
                )));
            }
        }
    }

    Ok(())
}

fn secret_metadata_text_fields(metadata: &SecretMetadataFlags) -> Vec<(&'static str, &str)> {
    let mut fields = Vec::new();
    if let Some(description) = metadata.description.as_deref() {
        fields.push(("description", description));
    }
    if let Some(owner) = metadata.owner.as_deref() {
        fields.push(("owner", owner));
    }
    for tag in &metadata.tags {
        fields.push(("tag", tag.as_str()));
    }
    fields
}

fn validate_secret_metadata_field(field: &str, value: &str) -> Result<(), CliError> {
    if value.chars().any(char::is_control) {
        return Err(CliError::Config(format!(
            "metadata field {field} contains control characters; refusing to store it"
        )));
    }
    let secret_like = scan_text(&format!("metadata:{field}"), value).iter().any(|finding| {
        matches!(finding.kind, FindingKind::HighEntropy | FindingKind::ProviderTokenPattern)
    });
    if secret_like {
        return Err(CliError::Config(format!(
            "metadata field {field} looks like a secret; refusing to store it"
        )));
    }
    Ok(())
}

fn write_secret_meta_update_failure_audit_if_available(
    context: &RuntimeContext,
    store: &mut Store,
    resolved_secret: &ResolvedSecret,
    metadata: &SecretMetadataFlags,
    timestamp: i64,
) {
    let project_id = resolved_secret.project.config.project_id.as_str();
    let Ok(audit_key) = load_project_key(context, store, project_id, KeyPurpose::Audit) else {
        return;
    };
    let audit_metadata = secret_meta_update_audit_metadata(
        resolved_secret,
        metadata,
        "FAILED",
        Some("metadata_privacy_validation"),
    );
    let audit = AuditWrite {
        project_id,
        profile_id: Some(&resolved_secret.profile.id),
        action: "SECRET_META_UPDATE",
        status: "FAILED",
        secret_name: Some(&resolved_secret.secret.name),
        command: None,
        metadata_json: &audit_metadata,
        timestamp,
    };
    let _ignored = store.append_audit(audit_key.as_ref(), &audit);
}

fn secret_meta_update_audit_metadata(
    resolved_secret: &ResolvedSecret,
    metadata: &SecretMetadataFlags,
    status: &str,
    failure_reason: Option<&str>,
) -> Value {
    let updated_fields = metadata_update_field_names(metadata);
    let updated_field_count = updated_fields.len();
    json!({
        "schema_version": 1,
        "action": "SECRET_META_UPDATE",
        "status": status,
        "secret_name": &resolved_secret.secret.name,
        "profile": &resolved_secret.profile.name,
        "profile_id": &resolved_secret.profile.id,
        "source": &resolved_secret.secret.source,
        "version": resolved_secret.secret.current_version,
        "updated_fields": updated_fields,
        "updated_field_count": updated_field_count,
        "description_updated": metadata.description.is_some(),
        "owner_updated": metadata.owner.is_some(),
        "tag_update_count": metadata.tags.len(),
        "required_update": metadata_required_update(metadata),
        "failure_reason": failure_reason,
    })
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

pub(crate) fn active_secrets_by_name(
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

pub(crate) const fn source_arg_to_str(source: SecretSourceArg) -> &'static str {
    match source {
        SecretSourceArg::TeamManaged => "team-managed",
        SecretSourceArg::UserLocal => "user-local",
        SecretSourceArg::MachineLocal => "machine-local",
    }
}

pub(crate) const fn source_precedence(source: &str) -> u8 {
    match source.as_bytes() {
        b"team-managed" => 1,
        b"user-local" => 2,
        b"machine-local" => 3,
        _ => 0,
    }
}

pub(crate) fn fallback_project_name(root: &Path) -> String {
    root.file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .map_or_else(|| "locket-project".to_owned(), ToOwned::to_owned)
}

pub(crate) fn root_hash(root: &Path) -> Result<[u8; 32], CliError> {
    let canonical = root.canonicalize()?;
    let digest = Sha256::digest(canonical.to_string_lossy().as_bytes());
    let mut output = [0_u8; 32];
    output.copy_from_slice(&digest);
    Ok(output)
}

pub(crate) fn format_hex(bytes: &[u8]) -> String {
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
    hex_nibble_with_message(byte, "root hash must be hex encoded")
}

fn hex_nibble_with_message(byte: u8, message: &str) -> Result<u8, CliError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(CliError::Config(message.to_owned())),
    }
}

pub(crate) fn seal_recovery_envelope_entry(
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

pub(crate) fn formatted_recovery_code(
    code_bytes: &[u8; locket_crypto::RECOVERY_CODE_BYTES],
) -> Result<String, CliError> {
    let encoded = recovery_code_encode(code_bytes);
    let code = std::str::from_utf8(&encoded)
        .map_err(|_| CliError::Crypto(locket_crypto::CryptoError::InvalidSecretValue))?;
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &code[0..8],
        &code[8..16],
        &code[16..24],
        &code[24..32],
        &code[32..34]
    ))
}

pub(crate) fn now_unix_nanos() -> Result<i64, CliError> {
    let elapsed = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| CliError::Time)?;
    i64::try_from(elapsed.as_nanos()).map_err(|_| CliError::Time)
}

#[cfg(test)]
#[path = "tests/mod.rs"]
mod tests;
