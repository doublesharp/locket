//! Locket command-line entry point.

use clap::Parser;
use std::io::{self, Write};

#[derive(Debug, Parser)]
#[command(name = "locket", version, about = "Local-first secrets control plane")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, clap::Subcommand)]
enum Command {
    /// Show metadata-only status.
    Status,
}

fn main() -> io::Result<()> {
    let cli = Cli::parse();

    match cli.command.unwrap_or(Command::Status) {
        Command::Status => {
            writeln!(io::stdout(), "locket: not initialized")?;
        }
    }

    Ok(())
}
