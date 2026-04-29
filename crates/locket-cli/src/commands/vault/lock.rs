//! Lock and unlock command implementations.

use std::io::Write;

use locket_crypto::KeyPurpose;

use crate::{
    CliError, RuntimeContext, UnlockArgs, default_profile, ensure_project_exists,
    load_project_key_with_source, open_store, require_project, resolve_project,
    unimplemented_in_build_error,
};

pub fn lock_command(context: &RuntimeContext, output: &mut impl Write) -> Result<(), CliError> {
    writeln!(output, "lock: no agent-held keys to clear")?;
    writeln!(output, "agent: unavailable")?;
    writeln!(output, "metadata_only: yes")?;
    if let Some(project) = resolve_project(&context.cwd)? {
        writeln!(output, "project_id: {}", project.config.project_id)?;
    }
    Ok(())
}

pub fn unlock_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    args: &UnlockArgs,
) -> Result<(), CliError> {
    if args.verify_user {
        return Err(unimplemented_in_build_error(
            "unlock --verify-user: platform user verification is not implemented in this build; no interactive verification was performed",
        ));
    }

    let resolved = require_project(context)?;
    let store = open_store(context)?;
    ensure_project_exists(&store, resolved.config.project_id.as_str())?;
    let profile = default_profile(&store, &resolved.config)?;
    let (_audit_key, source) = load_project_key_with_source(
        context,
        &store,
        resolved.config.project_id.as_str(),
        KeyPurpose::Audit,
    )?;

    writeln!(output, "unlock: metadata-only direct CLI unlock succeeded")?;
    writeln!(output, "project_id: {}", resolved.config.project_id)?;
    writeln!(output, "active_profile: {} ({})", resolved.config.default_profile, profile.id)?;
    writeln!(output, "unlock_source: {}", source.as_str())?;
    writeln!(output, "agent: unavailable")?;
    writeln!(output, "cached_keys: no")?;
    writeln!(output, "verify_user: not requested")?;
    Ok(())
}
