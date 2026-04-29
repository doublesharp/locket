//! `locket emit-example` command.

use std::io::Write;

use crate::{
    CliError, RuntimeContext, collect_example_secret_names, open_store, require_project,
    write_example_block_for_emit, write_example_emit_audit,
};

pub fn emit_example_command(
    context: &RuntimeContext,
    output: &mut impl Write,
) -> Result<(), CliError> {
    let resolved = require_project(context)?;
    let mut store = open_store(context)?;
    let names = collect_example_secret_names(&store, &resolved)?;
    let result = write_example_block_for_emit(&resolved.root, &names, output)?;
    write_example_emit_audit(context, &mut store, &resolved, &result)?;
    writeln!(output, "updated {}", result.path.display())?;
    Ok(())
}
