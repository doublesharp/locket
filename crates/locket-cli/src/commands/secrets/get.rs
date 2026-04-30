//! Implementation of the `locket get` command and clipboard helpers.

use std::io::{self, IsTerminal, Write};
use std::path::Path;
use std::process::{Command as ProcessCommand, Stdio};

use crate::runtime::RuntimeContext;
use crate::runtime::error::{CliError, external_source_unavailable_error};
use crate::runtime::user_verification::{UserVerificationAudit, require_user_verification};
use crate::support::secret_helpers::{
    ResolvedSecret, ValueAccessAudit, decrypt_current_secret, resolve_active_secret,
    resolve_active_secret_for_source, reveal_ttl_seconds, write_value_access_audit_if_available,
};
use crate::{GetArgs, access_denied_error};

pub fn get_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &GetArgs,
) -> Result<(), CliError> {
    let mut error_output = io::stderr();
    get_command_with_clipboard(context, output, &mut error_output, args, copy_secret_to_clipboard)
}

pub fn get_command_with_clipboard(
    context: &RuntimeContext,
    output: &mut impl Write,
    error_output: &mut impl Write,
    args: &GetArgs,
    copy_to_clipboard: impl FnOnce(&str) -> Result<(), String>,
) -> Result<(), CliError> {
    let limit = clipboard_clear_limit(
        select_clipboard_command(CLIPBOARD_COMMANDS, command_exists),
        std::env::var("XDG_SESSION_TYPE").ok().as_deref(),
    );
    get_command_with_clipboard_and_limit(
        context,
        output,
        error_output,
        args,
        copy_to_clipboard,
        limit,
    )
}

pub fn get_command_with_clipboard_and_limit(
    context: &RuntimeContext,
    output: &mut impl Write,
    error_output: &mut impl Write,
    args: &GetArgs,
    copy_to_clipboard: impl FnOnce(&str) -> Result<(), String>,
    limit: ClipboardClearLimit,
) -> Result<(), CliError> {
    let resolved_secret = match args.source.source {
        Some(source) => resolve_active_secret_for_source(context, &args.key, Some(source))?,
        None => resolve_active_secret(context, &args.key)?,
    };
    if args.copy {
        return get_copy_command(
            context,
            output,
            error_output,
            &resolved_secret,
            args.verify_user,
            copy_to_clipboard,
            limit,
        );
    }
    if args.reveal {
        return get_reveal_command(context, output, &resolved_secret, args.force, args.verify_user);
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

fn get_copy_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    error_output: &mut impl Write,
    resolved_secret: &ResolvedSecret,
    verify_user: bool,
    copy_to_clipboard: impl FnOnce(&str) -> Result<(), String>,
    limit: ClipboardClearLimit,
) -> Result<(), CliError> {
    let ttl_seconds = reveal_ttl_seconds(context)?;
    writeln!(error_output, "{}", limit.warning_text())?;
    let user_verification = value_access_user_verification_or_audit_denial(
        context,
        resolved_secret,
        "COPY",
        verify_user,
        Some(ttl_seconds),
        false,
        "clipboard",
    )?;
    let value = decrypt_current_secret(context, resolved_secret)?;
    let result = copy_to_clipboard(value.as_str());
    let status = if result.is_ok() { "SUCCESS" } else { "FAILED" };
    let unsupported_reason = match result.as_ref() {
        Err(error) => Some(error.as_str()),
        Ok(()) => Some(limit.audit_reason()),
    };
    write_value_access_audit_if_available(&ValueAccessAudit {
        context,
        resolved: resolved_secret,
        action: "COPY",
        status,
        access_mode: "clipboard",
        ttl_seconds: Some(ttl_seconds),
        force: false,
        clipboard_supported: Some(result.is_ok()),
        clipboard_clear_supported: Some(false),
        unsupported_reason,
        denial_reason: None,
        user_verification,
    })?;
    result.map_err(external_source_unavailable_error)?;
    writeln!(
        output,
        "copied {} source={} version={} ttl_seconds={} clipboard_clear_supported=no metadata_only=yes",
        resolved_secret.secret.name,
        resolved_secret.secret.source,
        resolved_secret.secret.current_version,
        ttl_seconds
    )?;
    Ok(())
}

fn get_reveal_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    resolved_secret: &ResolvedSecret,
    force: bool,
    verify_user: bool,
) -> Result<(), CliError> {
    if !force && !io::stdout().is_terminal() {
        write_value_access_audit_if_available(&ValueAccessAudit {
            context,
            resolved: resolved_secret,
            action: "REVEAL",
            status: "DENIED",
            access_mode: "stdout",
            ttl_seconds: None,
            force,
            clipboard_supported: None,
            clipboard_clear_supported: None,
            unsupported_reason: None,
            denial_reason: Some("noninteractive_terminal"),
            user_verification: UserVerificationAudit::not_required(),
        })?;
        return Err(access_denied_error(
            "get --reveal requires an interactive terminal; pass --force for noninteractive stdout",
        ));
    }
    let user_verification = value_access_user_verification_or_audit_denial(
        context,
        resolved_secret,
        "REVEAL",
        verify_user,
        None,
        force,
        "stdout",
    )?;
    let value = decrypt_current_secret(context, resolved_secret)?;
    write_value_access_audit_if_available(&ValueAccessAudit {
        context,
        resolved: resolved_secret,
        action: "REVEAL",
        status: "SUCCESS",
        access_mode: "stdout",
        ttl_seconds: None,
        force,
        clipboard_supported: None,
        clipboard_clear_supported: None,
        unsupported_reason: None,
        denial_reason: None,
        user_verification,
    })?;
    writeln!(output, "{}", value.as_str())?;
    Ok(())
}

fn value_access_user_verification_or_audit_denial(
    context: &RuntimeContext,
    resolved_secret: &ResolvedSecret,
    audit_action: &'static str,
    verify_user: bool,
    ttl_seconds: Option<u64>,
    force: bool,
    access_mode: &'static str,
) -> Result<UserVerificationAudit, CliError> {
    let verification_action = if audit_action == "COPY" { "copy" } else { "reveal" };
    match value_access_user_verification(
        context,
        verify_user,
        verification_action,
        &resolved_secret.secret.name,
    ) {
        Ok(audit) => Ok(audit),
        Err(error) => {
            write_value_access_audit_if_available(&ValueAccessAudit {
                context,
                resolved: resolved_secret,
                action: audit_action,
                status: "DENIED",
                access_mode,
                ttl_seconds,
                force,
                clipboard_supported: None,
                clipboard_clear_supported: None,
                unsupported_reason: None,
                denial_reason: Some("user_verification_failed"),
                user_verification: UserVerificationAudit::failed_required(),
            })?;
            Err(error)
        }
    }
}

fn value_access_user_verification(
    context: &RuntimeContext,
    required: bool,
    action: &'static str,
    secret_name: &str,
) -> Result<UserVerificationAudit, CliError> {
    if !required {
        return Ok(UserVerificationAudit::not_required());
    }
    require_user_verification(context, action, format!("{action} secret {secret_name}"))
}

#[derive(Debug, Eq, PartialEq)]
pub struct ClipboardCommand {
    pub program: &'static str,
    pub args: &'static [&'static str],
}

pub const CLIPBOARD_COMMANDS: &[ClipboardCommand] = if cfg!(target_os = "macos") {
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

/// Why the direct-CLI clipboard path can't reliably clear the value at TTL.
/// Used to drive both the pre-copy stderr warning and the
/// `clipboard_clear_supported`/`unsupported_reason` audit metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClipboardClearLimit {
    /// Direct-CLI copy cannot schedule a background clearer; clearing waits
    /// on the agent path. This is the baseline limit on every platform.
    DirectCli,
    /// Wayland clipboards belong to the source process. When the CLI exits
    /// after writing the value, a strict compositor may drop the selection
    /// before TTL elapses; a permissive one may keep it past TTL with no
    /// way for Locket to clear it. Either failure mode leaks intent.
    WaylandSourceProcessLimited,
}

impl ClipboardClearLimit {
    /// Stable string used in the audit metadata `unsupported_reason` field.
    pub const fn audit_reason(self) -> &'static str {
        match self {
            Self::DirectCli => "direct_cli_no_background_clear",
            Self::WaylandSourceProcessLimited => "wayland_source_process_limited",
        }
    }

    /// Operator-facing pre-copy warning text written to stderr.
    pub const fn warning_text(self) -> &'static str {
        match self {
            Self::DirectCli => {
                "warning: clipboard TTL clearing is unsupported in this direct CLI path"
            }
            Self::WaylandSourceProcessLimited => {
                "warning: Wayland clipboards belong to the source process; \
                 the value may be cleared before TTL or persist past it"
            }
        }
    }
}

/// Classifies how reliably the current environment can clear the clipboard
/// after the documented TTL. `xdg_session_type` lets tests inject the
/// session value (`Some("wayland")`) without touching the process env.
pub fn clipboard_clear_limit(
    selected: Option<&ClipboardCommand>,
    xdg_session_type: Option<&str>,
) -> ClipboardClearLimit {
    let Some(command) = selected else {
        return ClipboardClearLimit::DirectCli;
    };
    if command.program == "wl-copy"
        || matches!(xdg_session_type, Some(value) if value.eq_ignore_ascii_case("wayland"))
    {
        return ClipboardClearLimit::WaylandSourceProcessLimited;
    }
    ClipboardClearLimit::DirectCli
}

pub fn copy_secret_to_clipboard(value: &str) -> Result<(), String> {
    SystemClipboard.copy(value)
}

pub fn copy_secret_to_clipboard_with(
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

pub fn select_clipboard_command(
    commands: &'static [ClipboardCommand],
    mut exists: impl FnMut(&str) -> bool,
) -> Option<&'static ClipboardCommand> {
    commands.iter().find(|command| exists(command.program))
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClipboardClearResult {
    Cleared,
    Changed,
    Unsupported,
}

pub trait ClipboardBackend {
    fn copy(&mut self, value: &str) -> Result<(), String>;

    #[cfg(test)]
    fn clear_if_current(&mut self, expected: &str) -> ClipboardClearResult;
}

#[cfg(test)]
#[derive(Debug, Default, Eq, PartialEq)]
pub struct MemoryClipboard {
    value: Option<String>,
    clear_supported: bool,
}

#[cfg(test)]
impl MemoryClipboard {
    #[must_use]
    pub const fn clearing_supported() -> Self {
        Self { value: None, clear_supported: true }
    }

    #[must_use]
    pub const fn clearing_unsupported() -> Self {
        Self { value: None, clear_supported: false }
    }

    #[must_use]
    pub fn value(&self) -> Option<&str> {
        self.value.as_deref()
    }
}

#[cfg(test)]
impl ClipboardBackend for MemoryClipboard {
    fn copy(&mut self, value: &str) -> Result<(), String> {
        self.value = Some(value.to_owned());
        Ok(())
    }

    fn clear_if_current(&mut self, expected: &str) -> ClipboardClearResult {
        if !self.clear_supported {
            return ClipboardClearResult::Unsupported;
        }
        if self.value.as_deref() == Some(expected) {
            self.value = None;
            ClipboardClearResult::Cleared
        } else {
            ClipboardClearResult::Changed
        }
    }
}

pub struct SystemClipboard;

impl ClipboardBackend for SystemClipboard {
    fn copy(&mut self, value: &str) -> Result<(), String> {
        copy_secret_to_clipboard_with(value, CLIPBOARD_COMMANDS, command_exists)
    }

    #[cfg(test)]
    fn clear_if_current(&mut self, _expected: &str) -> ClipboardClearResult {
        ClipboardClearResult::Unsupported
    }
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
