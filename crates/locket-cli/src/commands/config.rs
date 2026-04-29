//! Config command implementations.

pub mod spec;

use std::io::Write;

use self::spec::{
    CONFIG_KEY_SPECS, config_get_value, config_set_value, config_unset_value, format_config_value,
    parse_config_value, read_user_config, validate_config_key,
    validate_config_value_not_secret_like, validate_stored_config_value,
    write_config_update_audit_if_available, write_user_config,
};
use crate::{CliError, ConfigCommand, RuntimeContext};

pub fn config_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    command: ConfigCommand,
) -> Result<(), CliError> {
    match command {
        ConfigCommand::List => config_list_command(context, output),
        ConfigCommand::Get(args) => config_get_command(context, output, &args.key),
        ConfigCommand::Set(args) => config_set_command(context, output, &args.key, &args.value),
        ConfigCommand::Unset(args) => config_unset_command(context, output, &args.key),
    }
}

fn config_list_command(context: &RuntimeContext, output: &mut impl Write) -> Result<(), CliError> {
    let config = read_user_config(context)?;
    let mut listed = 0_u32;
    for spec in CONFIG_KEY_SPECS {
        if let Some(value) = config_get_value(&config, spec.key) {
            validate_stored_config_value(spec, value)?;
            writeln!(output, "{}={}", spec.key, format_config_value(value))?;
            listed += 1;
        }
    }
    if listed == 0 {
        writeln!(output, "no config values")?;
    }
    Ok(())
}

fn config_get_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    key: &str,
) -> Result<(), CliError> {
    let spec = validate_config_key(key)?;
    let config = read_user_config(context)?;
    let value = config_get_value(&config, key)
        .ok_or_else(|| CliError::Config("config key is not set".to_owned()))?;
    validate_stored_config_value(spec, value)?;
    writeln!(output, "{}", format_config_value(value))?;
    Ok(())
}

fn config_set_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    key: &str,
    value: &str,
) -> Result<(), CliError> {
    let spec = validate_config_key(key)?;
    validate_config_value_not_secret_like(value)?;
    let parsed = parse_config_value(spec, value)?;
    let mut config = read_user_config(context)?;
    config_set_value(&mut config, key, parsed)?;
    write_user_config(context, &config)?;
    if spec.audit {
        write_config_update_audit_if_available(context, key, "set")?;
    }
    writeln!(output, "set {key}")?;
    Ok(())
}

fn config_unset_command(
    context: &RuntimeContext,
    output: &mut impl Write,
    key: &str,
) -> Result<(), CliError> {
    let spec = validate_config_key(key)?;
    let mut config = read_user_config(context)?;
    config_unset_value(&mut config, key)?;
    write_user_config(context, &config)?;
    if spec.audit {
        write_config_update_audit_if_available(context, key, "unset")?;
    }
    writeln!(output, "unset {key}")?;
    Ok(())
}
