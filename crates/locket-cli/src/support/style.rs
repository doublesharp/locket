//! Small ANSI presentation helpers for interactive CLI output.

use std::env;
use std::fmt;
use std::io::{self, IsTerminal, Write};

/// Semantic color roles used by the CLI theme.
#[derive(Clone, Copy)]
pub(crate) enum Tone {
    /// Locket brand accents.
    Brand,
    /// Successful or armed state.
    Good,
    /// Warning state.
    Warn,
    /// Field labels.
    Key,
    /// Primary values.
    Value,
    /// Low-emphasis chrome.
    Muted,
    /// High-emphasis text.
    Strong,
    /// Secret or recovery-code material.
    Secret,
}

impl Tone {
    const fn code(self) -> &'static str {
        match self {
            Self::Brand => "38;5;51",
            Self::Good => "38;5;82",
            Self::Warn => "38;5;214",
            Self::Key => "38;5;117",
            Self::Value => "38;5;255",
            Self::Muted => "38;5;245",
            Self::Strong => "1;38;5;255",
            Self::Secret => "1;38;5;226",
        }
    }
}

/// Returns true when interactive output should include ANSI styling.
pub(crate) fn enabled() -> bool {
    if env_flag_set("NO_COLOR") || env_value_is("LOCKET_STYLE", &["0", "off", "plain", "never"]) {
        return false;
    }
    if env_flag_set("FORCE_COLOR")
        || env_value_is("CLICOLOR_FORCE", &["1", "true"])
        || env_value_is("LOCKET_STYLE", &["1", "ansi", "always"])
    {
        return true;
    }
    io::stdout().is_terminal()
        && env::var("TERM").map_or(true, |term| !term.eq_ignore_ascii_case("dumb"))
}

/// Paints text with the selected terminal tone when styling is enabled.
pub(crate) fn paint(tone: Tone, text: impl fmt::Display) -> String {
    if enabled() { format!("\x1b[{}m{text}\x1b[0m", tone.code()) } else { text.to_string() }
}

/// Writes a compact hacker-ish section banner in interactive terminals.
pub(crate) fn write_banner(output: &mut impl Write, title: &str, status: &str) -> io::Result<()> {
    if enabled() {
        writeln!(
            output,
            "{} {} {}",
            paint(Tone::Brand, "==[ locket ]=="),
            paint(Tone::Strong, title),
            paint(Tone::Good, format!("// {status}"))
        )
    } else {
        writeln!(output, "{title}: {status}")
    }
}

/// Writes a labeled metadata row with aligned labels in interactive output.
pub(crate) fn write_kv(
    output: &mut impl Write,
    key: &str,
    value: impl fmt::Display,
) -> io::Result<()> {
    if enabled() {
        writeln!(
            output,
            "  {} {} {}",
            paint(Tone::Key, format!("{key:<20}")),
            paint(Tone::Muted, "::"),
            paint(Tone::Value, value)
        )
    } else {
        writeln!(output, "{key}: {value}")
    }
}

fn env_flag_set(name: &str) -> bool {
    env::var_os(name).is_some_and(|value| !value.is_empty())
}

fn env_value_is(name: &str, values: &[&str]) -> bool {
    env::var(name).is_ok_and(|actual| values.iter().any(|value| actual.eq_ignore_ascii_case(value)))
}
