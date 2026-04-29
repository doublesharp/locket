#[allow(unused_imports)]
use super::*;

#[test]
fn new_from_builtin_template_initializes_metadata_only_project()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();

    run_with_context(
        Cli::try_parse_from(["locket", "new", "--from-template", "basic"])?,
        &context,
        &mut output,
    )?;

    let output = String::from_utf8(output)?;
    assert!(output.contains("template: basic"));
    assert!(output.contains("template_source: built-in"));
    assert!(output.contains("secrets: not written"));
    assert!(!output.contains("postgres://"));
    let config = std::fs::read_to_string(directory.path().join("locket.toml"))?;
    assert!(config.contains("[commands.dev]"));
    let example = std::fs::read_to_string(directory.path().join(".env.example"))?;
    assert!(example.contains("DATABASE_URL="));
    Ok(())
}

#[test]
fn new_from_local_template_and_bootstrap_report_checklist() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempdir()?;
    let context = test_context(&directory);
    let templates_dir = context.template_dir.clone();
    std::fs::create_dir_all(&templates_dir)?;
    std::fs::write(
        templates_dir.join("web.toml"),
        r#"
name = "web-app"
default_profile = "dev"
profiles = ["dev", "staging"]
expected_secrets = ["DATABASE_URL", "API_KEY"]

[commands.test]
argv = ["cargo", "test"]
optional_secrets = ["API_KEY"]
"#,
    )?;

    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "new", "--from-template", "web"])?,
        &context,
        &mut output,
    )?;
    let output = String::from_utf8(output)?;
    assert!(output.contains("template_source: local:"));
    assert!(output.contains("profiles: 2"));
    assert!(output.contains("expected_secrets: 2"));
    assert!(output.contains("commands: 1"));

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let config = crate::read_project_config(&directory.path().join("locket.toml"))?;
    let profiles = store.list_profiles(config.project_id.as_str())?;
    assert_eq!(profiles.len(), 2);

    let mut bootstrap_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "bootstrap"])?,
        &context,
        &mut bootstrap_output,
    )?;
    let bootstrap_output = String::from_utf8(bootstrap_output)?;
    assert!(bootstrap_output.contains("project: web-app"));
    assert!(bootstrap_output.contains("profile: dev"));
    assert!(bootstrap_output.contains(".env.example: yes"));
    assert!(bootstrap_output.contains("trusted_root: yes"));
    assert!(bootstrap_output.contains("metadata_only: yes"));
    assert!(bootstrap_output.contains("- none"));
    assert!(bootstrap_output.contains("team: solo"));
    assert!(bootstrap_output.contains("policies: 1"));
    assert!(bootstrap_output.contains("smoke_policy: none"));
    assert!(bootstrap_output.contains("pre_commit_hook: not_git_repo"));
    assert!(!bootstrap_output.contains("postgres://"));
    Ok(())
}

#[test]
fn bootstrap_reports_smoke_policy_and_writes_audit_row() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let templates_dir = context.template_dir.clone();
    std::fs::create_dir_all(&templates_dir)?;
    std::fs::write(
        templates_dir.join("api.toml"),
        r#"
name = "api"
default_profile = "dev"
profiles = ["dev"]

[commands.smoke]
argv = ["cargo", "test"]
"#,
    )?;
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "new", "--from-template", "api"])?,
        &context,
        &mut output,
    )?;

    let toml_path = directory.path().join("locket.toml");
    let mut toml_content = std::fs::read_to_string(&toml_path)?;
    toml_content.push_str("\n[bootstrap]\nsmoke_policy = \"smoke\"\n");
    std::fs::write(&toml_path, &toml_content)?;

    let mut bootstrap_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "bootstrap"])?,
        &context,
        &mut bootstrap_output,
    )?;
    let bootstrap_output = String::from_utf8(bootstrap_output)?;
    assert!(bootstrap_output.contains("smoke_policy: configured (smoke)"));
    assert!(bootstrap_output.contains("policies: 1"));
    assert!(bootstrap_output.contains("- none"));

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let bootstrap_audit = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'BOOTSTRAP'",
        [],
        |row| row.get::<_, String>(0),
    )?;
    assert!(bootstrap_audit.contains("\"action\":\"BOOTSTRAP\""));
    assert!(bootstrap_audit.contains("\"smoke_policy_configured\":true"));
    assert!(bootstrap_audit.contains("\"team_status\":\"solo\""));
    Ok(())
}

#[test]
fn bootstrap_reports_missing_smoke_policy() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let templates_dir = context.template_dir.clone();
    std::fs::create_dir_all(&templates_dir)?;
    std::fs::write(
        templates_dir.join("plain.toml"),
        r#"
name = "plain"
default_profile = "dev"
profiles = ["dev"]
"#,
    )?;
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "new", "--from-template", "plain"])?,
        &context,
        &mut output,
    )?;

    let toml_path = directory.path().join("locket.toml");
    let mut toml_content = std::fs::read_to_string(&toml_path)?;
    toml_content.push_str("\n[bootstrap]\nsmoke_policy = \"missing\"\n");
    std::fs::write(&toml_path, &toml_content)?;

    let mut bootstrap_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "bootstrap"])?,
        &context,
        &mut bootstrap_output,
    )?;
    let bootstrap_output = String::from_utf8(bootstrap_output)?;
    assert!(bootstrap_output.contains("smoke_policy: missing (missing)"));
    assert!(bootstrap_output.contains("- run locket policy add missing"));
    Ok(())
}

#[test]
fn new_rejects_template_with_invalid_expected_secret_name() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempdir()?;
    let context = test_context(&directory);
    std::fs::create_dir_all(&context.template_dir)?;
    std::fs::write(
        context.template_dir.join("bad.toml"),
        r#"
name = "bad-app"
expected_secrets = ["database-url"]
"#,
    )?;
    let mut output = Vec::new();

    assert_error_contains(
        run_with_context(
            Cli::try_parse_from(["locket", "new", "--from-template", "bad"])?,
            &context,
            &mut output,
        ),
        "template expected secret name is invalid",
    );
    assert!(!directory.path().join("locket.toml").exists());
    Ok(())
}

#[test]
fn new_unknown_template_is_config_error() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();

    assert_error_contains(
        run_with_context(
            Cli::try_parse_from(["locket", "new", "--from-template", "missing"])?,
            &context,
            &mut output,
        ),
        "unknown template",
    );
    Ok(())
}

#[test]
fn emit_example_uses_all_profiles_rewrites_managed_block_and_audits()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;

    let dev_args = test_secret_write_args("DATABASE_URL");
    crate::set_secret_value(&context, &dev_args, "postgres://localhost/app", "manual", 1_000)?;
    let mut create_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "profile", "create", "staging"])?,
        &context,
        &mut create_output,
    )?;
    let mut use_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "use", "staging"])?,
        &context,
        &mut use_output,
    )?;
    let staging_args = test_secret_write_args("API_KEY");
    crate::set_secret_value(&context, &staging_args, "sk_test_sample", "manual", 2_000)?;

    let example_path = directory.path().join(".env.example");
    std::fs::write(
        &example_path,
        "HEADER=kept\n# --- BEGIN LOCKET MANAGED ---\nOLD_SECRET=\n# --- END LOCKET MANAGED ---\nFOOTER=kept\n",
    )?;

    let mut emit_output = Vec::new();
    run_with_context(Cli::try_parse_from(["locket", "emit-example"])?, &context, &mut emit_output)?;

    let example = std::fs::read_to_string(&example_path)?;
    assert!(example.contains("HEADER=kept"));
    assert!(example.contains("FOOTER=kept"));
    assert!(example.contains("API_KEY="));
    assert!(example.contains("DATABASE_URL="));
    assert!(!example.contains("OLD_SECRET="));
    assert!(!example.contains("postgres://localhost/app"));
    assert!(!example.contains("sk_test_sample"));

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'EXAMPLE_EMIT'",
        [],
        |row| row.get(0),
    )?;
    assert!(metadata.contains("\"secret_name_count\":2"));
    assert!(metadata.contains("\"path_kind\":\"project_env_example\""));
    assert!(metadata.contains("\"marker_only\":true"));
    assert!(!metadata.contains("DATABASE_URL"));
    assert!(!metadata.contains("postgres://localhost/app"));
    Ok(())
}

#[test]
fn automatic_example_refresh_respects_user_and_project_config()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;

    let mut config_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "config", "set", "example.auto_refresh", "false"])?,
        &context,
        &mut config_output,
    )?;
    std::fs::write(directory.path().join("import.env"), "USER_DISABLED=value\n")?;
    let mut import_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "import", "import.env"])?,
        &context,
        &mut import_output,
    )?;
    let example = std::fs::read_to_string(directory.path().join(".env.example"))?;
    assert!(!example.contains("USER_DISABLED="));

    let mut emit_output = Vec::new();
    run_with_context(Cli::try_parse_from(["locket", "emit-example"])?, &context, &mut emit_output)?;
    let example = std::fs::read_to_string(directory.path().join(".env.example"))?;
    assert!(example.contains("USER_DISABLED="));

    let mut config_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "config", "set", "example.auto_refresh", "true"])?,
        &context,
        &mut config_output,
    )?;
    let locket_toml_path = directory.path().join("locket.toml");
    let mut locket_toml = std::fs::read_to_string(&locket_toml_path)?;
    locket_toml.push_str("\n[example]\nauto_refresh = false\n");
    std::fs::write(&locket_toml_path, locket_toml)?;

    std::fs::write(directory.path().join("import2.env"), "PROJECT_DISABLED=value\n")?;
    let mut import_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "import", "import2.env"])?,
        &context,
        &mut import_output,
    )?;
    let example = std::fs::read_to_string(directory.path().join(".env.example"))?;
    assert!(example.contains("USER_DISABLED="));
    assert!(!example.contains("PROJECT_DISABLED="));
    Ok(())
}

#[test]
fn automatic_example_refresh_refuses_unmanaged_example_file()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;

    let example_path = directory.path().join(".env.example");
    std::fs::write(&example_path, "MANUAL=kept\n")?;
    let mut names = BTreeSet::new();
    names.insert("DATABASE_URL".to_owned());

    assert_error_contains(
        crate::write_example_block(directory.path(), &names).map(|_| ()),
        "refusing automatic overwrite",
    );
    assert_eq!(std::fs::read_to_string(&example_path)?, "MANUAL=kept\n");
    Ok(())
}

#[test]
fn init_creates_project_metadata_files_and_profiles() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();

    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;

    assert!(directory.path().join("locket.toml").exists());
    assert!(directory.path().join(".gitignore").exists());
    assert!(directory.path().join(".env.example").exists());

    let mut profiles_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "profile", "list"])?,
        &context,
        &mut profiles_output,
    )?;
    let profiles_output = String::from_utf8(profiles_output)?;
    assert!(profiles_output.contains("* dev"));

    let mut create_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "profile", "create", "staging"])?,
        &context,
        &mut create_output,
    )?;
    let mut use_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "use", "staging"])?,
        &context,
        &mut use_output,
    )?;
    assert!(String::from_utf8(use_output)?.contains("active profile: staging"));

    let mut profiles_after_use = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "profile", "list"])?,
        &context,
        &mut profiles_after_use,
    )?;
    assert!(String::from_utf8(profiles_after_use)?.contains("* staging"));
    Ok(())
}

#[test]
fn device_commands_initialize_describe_add_list_and_revoke_metadata_only()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();

    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    output.clear();

    run_with_context(Cli::try_parse_from(["locket", "device", "init"])?, &context, &mut output)?;
    let init_output = String::from_utf8(output.clone())?;
    assert!(init_output.contains("device: initialized"));
    assert!(init_output.contains("metadata_only: yes"));
    let descriptor = init_output
        .lines()
        .find_map(|line| line.strip_prefix("descriptor: "))
        .ok_or("missing descriptor")?
        .to_owned();
    let local_device_id = init_output
        .lines()
        .find_map(|line| line.strip_prefix("device_id: "))
        .ok_or("missing device id")?
        .to_owned();
    assert!(descriptor.starts_with("lkdev1_"));

    output.clear();
    run_with_context(Cli::try_parse_from(["locket", "device", "pubkey"])?, &context, &mut output)?;
    let pubkey_output = String::from_utf8(output.clone())?;
    assert!(pubkey_output.contains(&descriptor));
    assert!(!pubkey_output.contains("private"));

    let remote_device = crate::DeviceRecord {
        id: "lk_dev_remote".to_owned(),
        project_id: "lk_proj_external".to_owned(),
        name: "remote".to_owned(),
        signing_public_key: vec![7; 32],
        sealing_public_key: vec![8; 32],
        fingerprint: crate::device_fingerprint_hex(&[7; 32], &[8; 32]),
        safety_words: vec!["amber".to_owned(), "basil".to_owned(), "cedar".to_owned()],
        local: false,
        created_at: 1,
        last_seen_at: None,
        revoked_at: None,
    };
    let remote_descriptor = crate::encode_device_descriptor(&remote_device)?;

    output.clear();
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "device",
            "add",
            "teammate-laptop",
            "--device",
            &remote_descriptor,
        ])?,
        &context,
        &mut output,
    )?;
    let add_output = String::from_utf8(output.clone())?;
    assert!(add_output.contains("device: added"));
    assert!(!add_output.contains("private"));

    output.clear();
    run_with_context(Cli::try_parse_from(["locket", "device", "list"])?, &context, &mut output)?;
    let list_output = String::from_utf8(output.clone())?;
    assert!(list_output.contains("local"));
    assert!(list_output.contains("teammate-laptop"));

    output.clear();
    let remove_without_force = run_with_context(
        Cli::try_parse_from(["locket", "device", "remove", local_device_id.as_str()])?,
        &context,
        &mut output,
    );
    assert_error_contains(remove_without_force, "requires --force");

    output.clear();
    run_with_context(
        Cli::try_parse_from(["locket", "device", "remove", "teammate-laptop"])?,
        &context,
        &mut output,
    )?;
    assert!(String::from_utf8(output.clone())?.contains("device: revoked"));

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let device_audits = store.connection().query_row(
        "SELECT COUNT(*) FROM audit_log WHERE action IN ('DEVICE_ADD', 'DEVICE_REVOKE')",
        [],
        |row| row.get::<_, i64>(0),
    )?;
    assert_eq!(device_audits, 3);
    drop(local_device_id);
    Ok(())
}

#[test]
fn init_writes_recovery_envelope_and_metadata_only_audit() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();

    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;

    let output = String::from_utf8(output)?;
    let recovery_code = recovery_code_from_output(&output)?;
    assert!(output.contains("recovery_code_init: success"));
    assert!(output.contains("terminal scrollback may retain this code"));
    assert!(output.contains("metadata_only: yes"));
    assert!(directory.path().join(".locket/recovery/kdf.toml").exists());
    assert!(directory.path().join(".locket/recovery/envelope.bin").exists());

    let store = crate::open_store(&context)?;
    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'INIT'",
        [],
        |row| row.get(0),
    )?;
    assert!(metadata.contains("\"recovery_code_displayed\":true"));
    assert!(metadata.contains("\"generated_files\":[\".gitignore\",\".env.example\"]"));
    assert!(!metadata.contains(recovery_code));
    Ok(())
}

#[test]
fn device_init_force_replaces_active_local_device() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();

    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    output.clear();

    run_with_context(Cli::try_parse_from(["locket", "device", "init"])?, &context, &mut output)?;
    let init_output = String::from_utf8(output.clone())?;
    let local_device_id = init_output
        .lines()
        .find_map(|line| line.strip_prefix("device_id: "))
        .ok_or("missing device id")?
        .to_owned();

    output.clear();
    run_with_context(
        Cli::try_parse_from(["locket", "device", "init", "--force"])?,
        &context,
        &mut output,
    )?;
    let forced_init_output = String::from_utf8(output.clone())?;
    assert!(forced_init_output.contains("device: initialized"));
    assert!(forced_init_output.contains("metadata_only: yes"));
    assert!(!forced_init_output.contains(&local_device_id));

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let project_id: String =
        store.connection().query_row("SELECT id FROM projects LIMIT 1", [], |row| row.get(0))?;
    let active_devices = store.list_devices(&project_id, false)?;
    assert_eq!(active_devices.len(), 1);
    assert_ne!(active_devices[0].id, local_device_id);
    Ok(())
}

#[test]
fn init_existing_complete_project_is_idempotent_without_new_rows_or_recovery_code()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    let first_output = String::from_utf8(output)?;
    let first_recovery_code = recovery_code_from_output(&first_output)?.to_owned();
    let store = crate::open_store(&context)?;
    let audit_rows_before: i64 =
        store.connection().query_row("SELECT COUNT(*) FROM audit_log", [], |row| row.get(0))?;

    let mut rerun_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "ignored", "--profile", "prod"])?,
        &context_with_confirmation(&context, "wrong\n"),
        &mut rerun_output,
    )?;

    let rerun_output = String::from_utf8(rerun_output)?;
    assert!(rerun_output.contains("project already initialized"));
    assert!(!rerun_output.contains("recovery_code"));
    assert!(!rerun_output.contains(&first_recovery_code));
    let audit_rows_after: i64 =
        store.connection().query_row("SELECT COUNT(*) FROM audit_log", [], |row| row.get(0))?;
    assert_eq!(audit_rows_after, audit_rows_before);
    Ok(())
}

#[test]
fn init_resumes_valid_locket_toml_without_store_project_and_creates_keys()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let config = locket_core::ProjectConfig::new(
        locket_core::ProjectId::generate()?,
        "app".to_owned(),
        locket_core::ProfileName::new("dev".to_owned())?,
    );
    crate::write_project_config(&directory.path().join("locket.toml"), &config)?;

    let mut output = Vec::new();
    run_with_context(Cli::try_parse_from(["locket", "init"])?, &context, &mut output)?;

    let output = String::from_utf8(output)?;
    assert!(output.contains("resumed locket project"));
    assert!(output.contains(config.project_id.as_str()));
    assert!(output.contains("recovery_code_init: success"));
    let store = crate::open_store(&context)?;
    assert!(store.get_project(config.project_id.as_str())?.is_some());
    let profile =
        store.get_profile_by_name(config.project_id.as_str(), "dev")?.ok_or("profile missing")?;
    assert!(
        store
            .get_key_by_scope(
                config.project_id.as_str(),
                None,
                locket_crypto::KeyPurpose::ProjectMetadata.as_str(),
            )?
            .is_some()
    );
    assert!(
        store
            .get_key_by_scope(
                config.project_id.as_str(),
                None,
                locket_crypto::KeyPurpose::Audit.as_str(),
            )?
            .is_some()
    );
    assert!(
        store
            .get_key_by_scope(
                config.project_id.as_str(),
                Some(&profile.id),
                locket_crypto::KeyPurpose::ProfileSecret.as_str(),
            )?
            .is_some()
    );
    assert!(
        store
            .get_key_by_scope(
                config.project_id.as_str(),
                Some(&profile.id),
                locket_crypto::KeyPurpose::ProfileFingerprint.as_str(),
            )?
            .is_some()
    );
    Ok(())
}

#[test]
fn init_failure_on_unmanaged_env_example_rolls_back_owned_changes()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    std::fs::write(directory.path().join(".env.example"), "MANUAL=kept\n")?;
    let mut output = Vec::new();

    let result = run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    );

    assert_error_contains(result, "refusing silent overwrite");
    assert!(!directory.path().join("locket.toml").exists());
    assert!(!directory.path().join(".gitignore").exists());
    assert_eq!(std::fs::read_to_string(directory.path().join(".env.example"))?, "MANUAL=kept\n");
    assert!(!directory.path().join(".locket/recovery/kdf.toml").exists());
    assert!(!directory.path().join(".locket/recovery/envelope.bin").exists());
    let store = crate::open_store(&context)?;
    let project_count: i64 =
        store.connection().query_row("SELECT COUNT(*) FROM projects", [], |row| row.get(0))?;
    assert_eq!(project_count, 0);
    Ok(())
}

#[test]
fn init_rejects_unsupported_locket_toml_schema_without_rewriting_file()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let config = locket_core::ProjectConfig::new(
        locket_core::ProjectId::generate()?,
        "app".to_owned(),
        locket_core::ProfileName::new("dev".to_owned())?,
    );
    let config_path = directory.path().join("locket.toml");
    crate::write_project_config(&config_path, &config)?;
    let unsupported = std::fs::read_to_string(&config_path)?
        .replace("schema_version = 1", "schema_version = 999");
    std::fs::write(&config_path, &unsupported)?;

    let result =
        run_with_context(Cli::try_parse_from(["locket", "init"])?, &context, &mut Vec::new());

    assert_error_contains(result, "unsupported locket.toml schema_version 999");
    assert_eq!(std::fs::read_to_string(config_path)?, unsupported);
    Ok(())
}
