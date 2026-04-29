//! Audit command implementation.

use std::io::Write;

use locket_crypto::KeyPurpose;

use crate::{
    AuditCommand, CliError, RuntimeContext, load_project_key, now_unix_nanos, open_store,
    require_project,
};

pub fn audit_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    command: AuditCommand,
) -> Result<(), CliError> {
    match command {
        AuditCommand::Verify => {
            let resolved = require_project(context)?;
            let mut store = open_store(context)?;
            let audit_key = load_project_key(
                context,
                &store,
                resolved.config.project_id.as_str(),
                KeyPurpose::Audit,
            )?;
            let rows = store.verify_audit_chain_and_append(
                resolved.config.project_id.as_str(),
                audit_key.as_ref(),
                now_unix_nanos()?,
            )?;
            writeln!(output, "audit: verified {rows} row(s)")?;
            Ok(())
        }
    }
}
