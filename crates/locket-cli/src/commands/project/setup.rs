//! Metadata-only setup guidance for local development flows.

use std::io::Write;

use crate::{
    CliError, LOCKET_TOML, RuntimeContext, SetupCommand, read_policy_document, resolve_project,
};

pub fn setup_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    command: Option<SetupCommand>,
) -> Result<(), CliError> {
    match command.unwrap_or(SetupCommand::Status) {
        SetupCommand::Status => setup_status(context, output),
        SetupCommand::Agent => setup_agent(output),
        SetupCommand::Share => setup_share(output),
    }
}

fn setup_status(context: &RuntimeContext, output: &mut impl Write) -> Result<(), CliError> {
    let Some(resolved) = resolve_project(&context.cwd)? else {
        writeln!(output, "setup: new_project")?;
        writeln!(output, "metadata_only: yes")?;
        writeln!(output, "next_actions:")?;
        writeln!(output, "- locket init --name <name> --profile dev")?;
        writeln!(output, "- locket import .env")?;
        writeln!(output, "- locket policy add dev -- <command>")?;
        writeln!(output, "- locket setup agent")?;
        return Ok(());
    };

    let policy_document = read_policy_document(&resolved.root.join(LOCKET_TOML))?;
    writeln!(output, "setup: local_development")?;
    writeln!(output, "project: {}", resolved.config.name)?;
    writeln!(output, "profile: {}", resolved.config.default_profile)?;
    writeln!(output, "policies: {}", policy_document.commands.len())?;
    writeln!(output, "metadata_only: yes")?;
    writeln!(output, "next_actions:")?;
    if policy_document.commands.is_empty() {
        writeln!(output, "- locket policy add dev -- <command>")?;
    }
    writeln!(output, "- locket import .env")?;
    writeln!(output, "- locket scan .")?;
    writeln!(output, "- locket setup agent")?;
    Ok(())
}

fn setup_agent(output: &mut impl Write) -> Result<(), CliError> {
    writeln!(output, "setup: agent_invite")?;
    writeln!(output, "metadata_only: yes")?;
    writeln!(output, "steps:")?;
    writeln!(output, "- receiver: locket agent invite request")?;
    writeln!(
        output,
        "- maintainer: locket agent invite create <label> --device <descriptor> --profile dev --role developer --expires-in 7d"
    )?;
    writeln!(output, "- receiver_accept: locket agent invite accept -")?;
    writeln!(output, "paste_flow: request_text_then_invite_text")?;
    Ok(())
}

fn setup_share(output: &mut impl Write) -> Result<(), CliError> {
    writeln!(output, "setup: share_access")?;
    writeln!(output, "metadata_only: yes")?;
    writeln!(output, "agent_path: locket setup agent")?;
    writeln!(
        output,
        "team_path: locket team invite <name> --device <descriptor> --profile dev --role developer"
    )?;
    writeln!(output, "bundle_path: locket export --sealed --recipient <descriptor> --profile dev")?;
    Ok(())
}
