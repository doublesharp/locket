//! Debug command implementation.

use std::io::Write;

use super::diagnostics;
use crate::{CliError, DebugCommand, RuntimeContext};

pub fn debug_command(
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
