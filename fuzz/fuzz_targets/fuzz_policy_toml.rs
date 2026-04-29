#![no_main]

use libfuzzer_sys::fuzz_target;
use locket_core::{CommandSpec, MAX_COMMAND_POLICY_TTL_SECONDS, PolicyDocument, SecretName};

fuzz_target!(|data: &[u8]| {
    if data.len() > 8192 {
        return;
    }
    let Ok(input) = std::str::from_utf8(data) else {
        return;
    };

    let Ok(document) = PolicyDocument::from_toml_str(input) else {
        return;
    };
    for (name, policy) in document.commands {
        assert_eq!(name, policy.name);
        assert!(!policy.name.is_empty());
        assert!(policy.ttl.as_secs() <= MAX_COMMAND_POLICY_TTL_SECONDS);
        match &policy.command {
            CommandSpec::Argv(argv) => assert!(!argv.is_empty()),
            CommandSpec::Shell(shell) => assert!(!shell.trim().is_empty()),
        }
        for secret in policy.required_secrets.iter().chain(policy.optional_secrets.iter()) {
            assert!(SecretName::new(secret.as_str().to_owned()).is_ok());
            assert!(policy.allowed_secrets.contains(secret));
        }
    }
});
