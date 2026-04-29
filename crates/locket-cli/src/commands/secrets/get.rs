//! Implementation of the `locket get` command and clipboard helpers.

use std::io::{self, IsTerminal, Write};
use std::path::Path;
use std::process::{Command as ProcessCommand, Stdio};

use crate::GetArgs;
use crate::runtime::RuntimeContext;
use crate::runtime::error::CliError;
use crate::support::secret_helpers::{
    ValueAccessAudit, decrypt_current_secret, resolve_active_secret, reveal_ttl_seconds,
    write_value_access_audit_if_available,
};

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
    let resolved_secret = resolve_active_secret(context, &args.key)?;
    if args.copy {
        let ttl_seconds = reveal_ttl_seconds(context)?;
        writeln!(
            error_output,
            "warning: clipboard TTL clearing is unsupported in this direct CLI path"
        )?;
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

pub fn copy_secret_to_clipboard(value: &str) -> Result<(), String> {
    copy_secret_to_clipboard_with(value, CLIPBOARD_COMMANDS, command_exists)
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
