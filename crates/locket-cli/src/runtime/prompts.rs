//! Interactive prompt readers and helpers used by the CLI runtime.

use std::io::{self, IsTerminal, Read};

use crate::runtime::error::{CliError, tty_required_error};

pub trait ConfirmationReader {
    fn read_confirmation(&self, prompt: &str) -> Result<String, CliError>;
}

#[derive(Debug, Clone, Copy)]
pub struct StdinConfirmationReader;

impl ConfirmationReader for StdinConfirmationReader {
    fn read_confirmation(&self, prompt: &str) -> Result<String, CliError> {
        if !io::stdin().is_terminal() {
            return Err(tty_required_error(format!("{prompt} requires interactive confirmation")));
        }
        let mut confirmation = String::new();
        io::stdin().read_line(&mut confirmation)?;
        Ok(confirmation)
    }
}

pub trait PassphraseReader {
    fn existing_passphrase(&self) -> Result<zeroize::Zeroizing<String>, CliError>;

    fn new_passphrase(&self) -> Result<zeroize::Zeroizing<String>, CliError>;
}

pub trait RecoveryCodeReader {
    fn read_recovery_code(&self, prompt: &str) -> Result<zeroize::Zeroizing<String>, CliError>;
}

#[derive(Debug, Clone, Copy)]
pub struct TtyRecoveryCodeReader;

impl RecoveryCodeReader for TtyRecoveryCodeReader {
    fn read_recovery_code(&self, prompt: &str) -> Result<zeroize::Zeroizing<String>, CliError> {
        read_recovery_code(prompt)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct EnvOrPromptPassphraseReader;

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

pub fn require_interactive_passphrase(reason: &str) -> Result<(), CliError> {
    if io::stdin().is_terminal() && io::stderr().is_terminal() {
        Ok(())
    } else {
        Err(tty_required_error(format!("{reason} requires an interactive TTY")))
    }
}

pub fn read_hidden_passphrase(prompt: &str) -> Result<zeroize::Zeroizing<String>, CliError> {
    let passphrase = zeroize::Zeroizing::new(rpassword::prompt_password(prompt)?);
    if passphrase.is_empty() {
        return Err(CliError::Config("passphrase must not be empty".to_owned()));
    }
    Ok(passphrase)
}

pub trait SecretValueReader {
    fn read_secret_value(&self, prompt: &str) -> Result<zeroize::Zeroizing<String>, CliError>;
}

#[derive(Debug, Clone, Copy)]
pub struct StdinOrPromptSecretValueReader;

impl SecretValueReader for StdinOrPromptSecretValueReader {
    fn read_secret_value(&self, prompt: &str) -> Result<zeroize::Zeroizing<String>, CliError> {
        if io::stdin().is_terminal() {
            read_secret_value_from_prompt(prompt)
        } else {
            read_secret_value_from_stdin()
        }
    }
}

pub fn read_secret_value_from_prompt(prompt: &str) -> Result<zeroize::Zeroizing<String>, CliError> {
    let value = rpassword::prompt_password(format!("Enter {prompt}: "))?;
    validate_secret_value(zeroize::Zeroizing::new(value))
}

pub fn read_secret_value_from_stdin() -> Result<zeroize::Zeroizing<String>, CliError> {
    read_secret_value_from_reader(io::stdin())
}

pub fn read_secret_value_from_reader(
    mut reader: impl Read,
) -> Result<zeroize::Zeroizing<String>, CliError> {
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes)?;
    let mut value = String::from_utf8(bytes)
        .map_err(|_| CliError::Config("secret value must be valid UTF-8".to_owned()))?;
    if value.ends_with('\n') {
        value.pop();
        if value.ends_with('\r') {
            value.pop();
        }
    }
    validate_secret_value(zeroize::Zeroizing::new(value))
}

pub fn validate_secret_value(
    value: zeroize::Zeroizing<String>,
) -> Result<zeroize::Zeroizing<String>, CliError> {
    if value.is_empty() {
        return Err(CliError::Config("secret value cannot be empty".to_owned()));
    }
    if value.contains('\0') {
        return Err(CliError::Config("secret value cannot contain NUL bytes".to_owned()));
    }
    Ok(value)
}

pub fn read_recovery_code(prompt: &str) -> Result<zeroize::Zeroizing<String>, CliError> {
    if io::stdin().is_terminal() {
        let value = rpassword::prompt_password(format!("Enter {prompt}: "))?;
        return Ok(zeroize::Zeroizing::new(value));
    }
    let mut value = String::new();
    io::stdin().read_to_string(&mut value)?;
    Ok(zeroize::Zeroizing::new(value))
}
