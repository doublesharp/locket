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

    assert_metadata_invalid(
        run_with_context(
            Cli::try_parse_from(["locket", "new", "--from-template", "bad"])?,
            &context,
            &mut output,
        ),
        "template expected secret name is invalid",
    )?;
    assert!(!directory.path().join("locket.toml").exists());
    Ok(())
}

#[test]
fn new_template_validation_errors_are_typed_metadata_invalid()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    std::fs::create_dir_all(&context.template_dir)?;
    std::fs::write(
        context.template_dir.join("bad-profile.toml"),
        r#"
name = "bad-app"
profiles = ["BadProfile"]
"#,
    )?;
    std::fs::write(
        context.template_dir.join("bad-policy.toml"),
        r#"
name = "bad-app"
default_profile = "dev"

[commands.dev]
required_secrets = "DATABASE_URL"
"#,
    )?;

    assert_metadata_invalid(
        run_with_context(
            Cli::try_parse_from(["locket", "new", "--from-template", "bad-profile"])?,
            &context,
            &mut Vec::new(),
        ),
        "template profile name is invalid",
    )?;
    assert_metadata_invalid(
        run_with_context(
            Cli::try_parse_from(["locket", "new", "--from-template", "bad-policy"])?,
            &context,
            &mut Vec::new(),
        ),
        "invalid template command policy",
    )?;
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
    assert!(metadata.contains("\"command\":\"emit-example\""));
    assert!(metadata.contains("\"path_kind\":\"project_env_example\""));
    assert!(metadata.contains("\"marker_only\":true"));
    assert!(!metadata.contains("DATABASE_URL"));
    assert!(!metadata.contains("postgres://localhost/app"));
    Ok(())
}

#[test]
fn emit_example_confirms_unmanaged_replacement_without_value_leakage()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context_with_confirmation(&directory, "replace .env.example\n");
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    let args = test_secret_write_args("DATABASE_URL");
    crate::set_secret_value(&context, &args, "postgres://localhost/app", "manual", 1_000)?;
    std::fs::write(directory.path().join(".env.example"), "DATABASE_URL=manual-value\n")?;

    let mut emit_output = Vec::new();
    run_with_context(Cli::try_parse_from(["locket", "emit-example"])?, &context, &mut emit_output)?;
    let emit_output = String::from_utf8(emit_output)?;
    assert!(emit_output.contains(".env.example: unmanaged"));
    assert!(!emit_output.contains("manual-value"));

    let example = std::fs::read_to_string(directory.path().join(".env.example"))?;
    assert!(example.contains(crate::support::project_files::EXAMPLE_BEGIN));
    assert!(example.contains("DATABASE_URL="));
    assert!(!example.contains("manual-value"));
    assert!(!example.contains("postgres://localhost/app"));

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'EXAMPLE_EMIT'",
        [],
        |row| row.get(0),
    )?;
    assert!(metadata.contains("\"replaced_unmanaged\":true"));
    assert!(metadata.contains("\"command\":\"emit-example\""));
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
fn team_members_lists_members_and_pending_invites_metadata_only()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    seed_team_members_fixture(&directory, false)?;

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let audit_count_before = audit_row_count(&store)?;
    output.clear();
    run_with_context(Cli::try_parse_from(["locket", "team", "members"])?, &context, &mut output)?;

    let members_output = String::from_utf8(output)?;
    assert!(members_output.contains("team: Core Team"));
    assert!(members_output.contains("team_id: lk_team_cli"));
    assert!(members_output.contains("display=Alice Owner"));
    assert!(members_output.contains("role=owner"));
    assert!(members_output.contains("trusted_devices=1"));
    assert!(members_output.contains("display=Bob Removed"));
    assert!(members_output.contains("removed_at=30"));
    assert!(members_output.contains("pending_invites:"));
    assert!(members_output.contains("id=lk_invite_pending"));
    assert!(members_output.contains("status=pending"));
    assert!(members_output.contains("profiles=dev,staging"));
    assert!(members_output.contains("recipient_device=recipient-fingerprint"));
    assert!(members_output.contains("metadata_only: yes"));
    assert!(!members_output.contains("secret"));
    assert_eq!(audit_row_count(&store)?, audit_count_before);
    Ok(())
}

#[test]
fn team_members_is_locked_vault_safe() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    seed_team_members_fixture(&directory, false)?;

    let locked_context =
        test_context_with_key_store(&directory, Arc::new(UnavailableMasterKeyStore));
    output.clear();
    run_with_context(
        Cli::try_parse_from(["locket", "team", "members"])?,
        &locked_context,
        &mut output,
    )?;

    let members_output = String::from_utf8(output)?;
    assert!(members_output.contains("display=Alice Owner"));
    assert!(members_output.contains("metadata_only: yes"));
    Ok(())
}

#[test]
fn team_members_uses_privacy_aliases() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;
    seed_team_members_fixture(&directory, true)?;
    output.clear();
    run_with_context(
        Cli::try_parse_from(["locket", "config", "set", "privacy.redact_names", "true"])?,
        &context,
        &mut output,
    )?;

    output.clear();
    run_with_context(Cli::try_parse_from(["locket", "team", "members"])?, &context, &mut output)?;

    let members_output = String::from_utf8(output)?;
    assert!(members_output.contains("team: team-"));
    assert!(members_output.contains("team_id: team-"));
    assert!(members_output.contains("display=member-"));
    assert!(members_output.contains("id=member-"));
    assert!(members_output.contains("profiles=profile-"));
    assert!(members_output.contains("recipient_device=device-"));
    assert!(!members_output.contains("Core Team"));
    assert!(!members_output.contains("Alice Owner"));
    assert!(!members_output.contains("lk_invite_pending"));
    assert!(!members_output.contains("recipient-fingerprint"));
    assert!(members_output.contains("metadata_only: yes"));
    Ok(())
}

#[test]
fn team_members_without_team_is_metadata_only() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut output,
    )?;

    output.clear();
    run_with_context(Cli::try_parse_from(["locket", "team", "members"])?, &context, &mut output)?;

    assert_eq!(
        String::from_utf8(output)?,
        "team: none\nmembers: none\npending_invites: none\nmetadata_only: yes\n"
    );
    Ok(())
}

#[test]
fn team_remove_member_sets_removed_at_and_writes_team_remove_audit()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    seed_team_members_with_two_owners(&directory)?;

    let remove_context = context_with_confirmation(&context, "Alice Owner\n");
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "team", "remove", "Alice Owner"])?,
        &remove_context,
        &mut output,
    )?;

    let output = String::from_utf8(output)?;
    assert!(output.contains("remove member: Alice Owner (owner)"));
    assert!(output.contains("team_remove: success"));
    assert!(output.contains("metadata_only: yes"));
    // Rotation checklist must surface every project profile and a total
    // active-secret count so the operator can rotate accessible secrets.
    assert!(output.contains("rotation_checklist:"));
    assert!(output.contains("profile dev:"));
    assert!(output.contains("rotate_active_secrets="));
    assert!(output.contains("total_active_secrets="));

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let removed_at: Option<i64> = store.connection().query_row(
        "SELECT removed_at FROM team_members WHERE id = 'lk_member_owner'",
        [],
        |row| row.get(0),
    )?;
    assert!(removed_at.is_some(), "removed_at must be set after team remove");

    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'TEAM_REMOVE'",
        [],
        |row| row.get(0),
    )?;
    assert!(metadata.contains("\"action\":\"TEAM_REMOVE\""));
    assert!(metadata.contains("\"command\":\"team remove\""));
    assert!(metadata.contains("\"member_id\":\"lk_member_owner\""));
    assert!(metadata.contains("\"member_role\":\"owner\""));
    Ok(())
}

#[test]
fn team_revoke_device_sets_revoked_at_and_writes_device_revoke_audit()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    seed_team_members_fixture(&directory, false)?;

    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "team", "revoke-device", "lk_dev_team_owner"])?,
        &context,
        &mut output,
    )?;

    let output = String::from_utf8(output)?;
    assert!(output.contains("device: revoked"));
    assert!(output.contains("device_id: lk_dev_team_owner"));
    assert!(output.contains("metadata_only: yes"));
    // The same rotation checklist surfaces from `team revoke-device`.
    assert!(output.contains("rotation_checklist:"));
    assert!(output.contains("rotate_active_secrets="));
    assert!(output.contains("total_active_secrets="));

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let revoked_at: Option<i64> = store.connection().query_row(
        "SELECT revoked_at FROM devices WHERE id = 'lk_dev_team_owner'",
        [],
        |row| row.get(0),
    )?;
    assert!(revoked_at.is_some(), "revoked_at must be set after team revoke-device");

    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'DEVICE_REVOKE' AND metadata_json LIKE '%team revoke-device%'",
        [],
        |row| row.get(0),
    )?;
    assert!(metadata.contains("\"action\":\"DEVICE_REVOKE\""));
    assert!(metadata.contains("\"command\":\"team revoke-device\""));
    assert!(metadata.contains("\"device_id\":\"lk_dev_team_owner\""));
    Ok(())
}

#[test]
fn maintainer_can_remove_developer_team_member() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    seed_team_role_authorization_fixture(&directory, "maintainer")?;

    let remove_context = context_with_confirmation(&context, "Dev User\n");
    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "team", "remove", "Dev User"])?,
        &remove_context,
        &mut output,
    )?;

    let output = String::from_utf8(output)?;
    assert!(output.contains("team_remove: success"));
    assert!(output.contains("metadata_only: yes"));
    Ok(())
}

#[test]
fn maintainer_cannot_remove_owner_team_member() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    seed_team_role_authorization_fixture(&directory, "maintainer")?;

    let result = run_with_context(
        Cli::try_parse_from(["locket", "team", "remove", "Owner User"])?,
        &context,
        &mut Vec::new(),
    );

    let Err(error) = result else {
        return Err("maintainer removing owner must fail".into());
    };
    assert_eq!(error.exit_code(), 70);
    assert!(error.to_string().contains("maintainers can remove only"));
    Ok(())
}

#[test]
fn developer_cannot_remove_team_member() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    seed_team_role_authorization_fixture(&directory, "developer")?;

    let result = run_with_context(
        Cli::try_parse_from(["locket", "team", "remove", "Dev User"])?,
        &context,
        &mut Vec::new(),
    );

    let Err(error) = result else {
        return Err("developer removing member must fail".into());
    };
    assert_eq!(error.exit_code(), 70);
    assert!(error.to_string().contains("cannot remove members"));
    Ok(())
}

#[test]
fn maintainer_can_revoke_developer_team_device() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    seed_team_role_authorization_fixture(&directory, "maintainer")?;

    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "team", "revoke-device", "lk_dev_target_developer"])?,
        &context,
        &mut output,
    )?;

    let output = String::from_utf8(output)?;
    assert!(output.contains("device: revoked"));
    assert!(output.contains("device_id: lk_dev_target_developer"));
    Ok(())
}

#[test]
fn maintainer_cannot_revoke_owner_team_device() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    seed_team_role_authorization_fixture(&directory, "maintainer")?;

    let result = run_with_context(
        Cli::try_parse_from(["locket", "team", "revoke-device", "lk_dev_target_owner"])?,
        &context,
        &mut Vec::new(),
    );

    let Err(error) = result else {
        return Err("maintainer revoking owner device must fail".into());
    };
    assert_eq!(error.exit_code(), 70);
    assert!(error.to_string().contains("cannot revoke owner"));
    Ok(())
}

#[test]
fn team_remove_last_owner_is_rejected_with_team_role_denied()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    seed_team_members_fixture(&directory, false)?;

    let remove_context = context_with_confirmation(&context, "Alice Owner\n");
    let result = run_with_context(
        Cli::try_parse_from(["locket", "team", "remove", "Alice Owner"])?,
        &remove_context,
        &mut Vec::new(),
    );

    let Err(error) = result else {
        return Err("removing last owner must fail".into());
    };
    assert_eq!(error.exit_code(), 70, "TeamRoleDenied is in the authorization band");
    assert!(error.to_string().contains("last remaining owner"));
    Ok(())
}

#[test]
fn team_remove_wrong_confirmation_fails_with_confirmation_failed()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    seed_team_members_with_two_owners(&directory)?;

    let remove_context = context_with_confirmation(&context, "wrong name\n");
    let result = run_with_context(
        Cli::try_parse_from(["locket", "team", "remove", "Alice Owner"])?,
        &remove_context,
        &mut Vec::new(),
    );

    let Err(error) = result else {
        return Err("wrong confirmation must fail".into());
    };
    assert_eq!(error.exit_code(), 68, "ConfirmationFailed is in the input band");
    Ok(())
}

#[test]
fn team_remove_unknown_member_fails_with_secret_not_found() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    seed_team_members_fixture(&directory, false)?;

    let result = run_with_context(
        Cli::try_parse_from(["locket", "team", "remove", "Nonexistent Member"])?,
        &context,
        &mut Vec::new(),
    );

    let Err(error) = result else {
        return Err("removing unknown member must fail".into());
    };
    assert_eq!(error.exit_code(), 77, "SecretNotFound is in the not-found band");
    Ok(())
}

#[test]
fn team_revoke_device_already_revoked_is_idempotent() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    seed_team_members_fixture(&directory, false)?;
    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let project_id =
        crate::read_project_config(&directory.path().join("locket.toml"))?.project_id.into_string();
    store.insert_device(&crate::DeviceRecord {
        id: "lk_dev_revoked_remote".to_owned(),
        project_id: project_id.clone(),
        name: "revoked remote".to_owned(),
        signing_public_key: vec![11; 32],
        sealing_public_key: vec![12; 32],
        fingerprint: crate::device_fingerprint_hex(&[11; 32], &[12; 32]),
        safety_words: vec!["cedar".to_owned(), "delta".to_owned()],
        local: false,
        created_at: 50,
        last_seen_at: Some(51),
        revoked_at: Some(52),
    })?;

    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "team", "revoke-device", "lk_dev_revoked_remote"])?,
        &context,
        &mut output,
    )?;

    let output = String::from_utf8(output)?;
    assert!(output.contains("device: already revoked"));
    assert!(output.contains("metadata_only: yes"));
    Ok(())
}

#[test]
fn team_revoke_device_unknown_device_fails_with_invalid_reference()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    seed_team_members_fixture(&directory, false)?;

    let result = run_with_context(
        Cli::try_parse_from(["locket", "team", "revoke-device", "nonexistent"])?,
        &context,
        &mut Vec::new(),
    );

    let Err(error) = result else {
        return Err("revoking unknown device must fail".into());
    };
    assert_eq!(error.exit_code(), 64, "InvalidReference is in the input band");
    assert!(error.to_string().contains("device not found"));
    Ok(())
}

/// Seed two owners so the last-owner guard doesn't fire during remove tests.
fn seed_team_members_with_two_owners(
    directory: &tempfile::TempDir,
) -> Result<(), Box<dyn std::error::Error>> {
    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let project_id =
        crate::read_project_config(&directory.path().join("locket.toml"))?.project_id.into_string();
    store.connection().execute(
        "INSERT INTO devices(
           id, project_id, name, signing_public_key, sealing_public_key, fingerprint,
           safety_words_json, local, created_at, last_seen_at, revoked_at
         )
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        (
            "lk_dev_owner_one",
            project_id.as_str(),
            "owner one laptop",
            vec![21_u8; 32],
            vec![22_u8; 32],
            crate::device_fingerprint_hex(&[21; 32], &[22; 32]),
            serde_json::to_string(&vec!["owner".to_owned(), "one".to_owned()])?,
            true,
            3_i64,
            Some(4_i64),
            Option::<i64>::None,
        ),
    )?;
    store.connection().execute(
        "INSERT INTO teams(id, project_id, name, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        ("lk_team_two", project_id.as_str(), "Two Owners", 1_i64, 2_i64),
    )?;
    store.connection().execute(
        "INSERT INTO team_members(id, team_id, device_id, display_name, role, joined_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        ("lk_member_owner", "lk_team_two", "lk_dev_owner_one", "Alice Owner", "owner", 10_i64),
    )?;
    store.connection().execute(
        "INSERT INTO team_members(id, team_id, display_name, role, joined_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        ("lk_member_owner2", "lk_team_two", "Bob Owner", "owner", 20_i64),
    )?;
    Ok(())
}

fn seed_team_role_authorization_fixture(
    directory: &tempfile::TempDir,
    caller_role: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let project_id =
        crate::read_project_config(&directory.path().join("locket.toml"))?.project_id.into_string();
    store.connection().execute(
        "INSERT INTO devices(
           id, project_id, name, signing_public_key, sealing_public_key, fingerprint,
           safety_words_json, local, created_at, last_seen_at, revoked_at
         )
         VALUES
           (?1, ?2, 'caller laptop', ?3, ?4, ?5, ?6, 1, 10, 11, NULL),
           (?7, ?2, 'developer laptop', ?8, ?9, ?10, ?11, 0, 12, 13, NULL),
           (?12, ?2, 'owner laptop', ?13, ?14, ?15, ?16, 0, 14, 15, NULL)",
        (
            "lk_dev_caller",
            project_id.as_str(),
            vec![31_u8; 32],
            vec![32_u8; 32],
            crate::device_fingerprint_hex(&[31; 32], &[32; 32]),
            serde_json::to_string(&vec!["caller".to_owned()])?,
            "lk_dev_target_developer",
            vec![33_u8; 32],
            vec![34_u8; 32],
            crate::device_fingerprint_hex(&[33; 32], &[34; 32]),
            serde_json::to_string(&vec!["developer".to_owned()])?,
            "lk_dev_target_owner",
            vec![35_u8; 32],
            vec![36_u8; 32],
            crate::device_fingerprint_hex(&[35; 32], &[36; 32]),
            serde_json::to_string(&vec!["owner".to_owned()])?,
        ),
    )?;
    store.connection().execute(
        "INSERT INTO teams(id, project_id, name, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        ("lk_team_roles", project_id.as_str(), "Role Team", 20_i64, 21_i64),
    )?;
    store.connection().execute(
        "INSERT INTO team_members(id, team_id, device_id, display_name, role, joined_at)
         VALUES
           ('lk_member_caller', 'lk_team_roles', 'lk_dev_caller', 'Caller User', ?1, 30),
           ('lk_member_developer', 'lk_team_roles', 'lk_dev_target_developer', 'Dev User', 'developer', 31),
           ('lk_member_owner', 'lk_team_roles', 'lk_dev_target_owner', 'Owner User', 'owner', 32)",
        [caller_role],
    )?;
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
    let verified_force_rows: i64 = store.connection().query_row(
        "SELECT COUNT(*) FROM audit_log
         WHERE action IN ('DEVICE_ADD', 'DEVICE_REVOKE')
           AND metadata_json LIKE '%\"user_verification\"%'
           AND metadata_json LIKE '%\"method\":\"test\"%'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(verified_force_rows, 2);
    Ok(())
}

#[test]
fn device_init_force_requires_local_user_verification_before_rekey()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;

    let mut init_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "device", "init"])?,
        &context,
        &mut init_output,
    )?;
    let init_output = String::from_utf8(init_output)?;
    let local_device_id = init_output
        .lines()
        .find_map(|line| line.strip_prefix("device_id: "))
        .ok_or("missing device id")?
        .to_owned();

    let rejecting_context =
        context_with_user_verifier(&context, Arc::new(MemoryLocalUserVerifier::denying()));
    let mut output = Vec::new();
    let result = run_with_context(
        Cli::try_parse_from(["locket", "device", "init", "--force"])?,
        &rejecting_context,
        &mut output,
    );
    let Err(error) = result else {
        return Err("device init --force must fail when verification is denied".into());
    };
    assert_eq!(error.exit_code(), locket_core::LocketError::UserVerificationFailed.exit_code());
    assert!(output.is_empty());

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let project_id: String =
        store.connection().query_row("SELECT id FROM projects LIMIT 1", [], |row| row.get(0))?;
    let active_devices = store.list_devices(&project_id, false)?;
    assert_eq!(active_devices.len(), 1);
    assert_eq!(active_devices[0].id, local_device_id);
    let revoke_rows: i64 = store.connection().query_row(
        "SELECT COUNT(*) FROM audit_log WHERE action = 'DEVICE_REVOKE'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(revoke_rows, 0);
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
fn init_resume_failure_rolls_back_new_store_rows_and_master_key()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let key_store = Arc::new(MemoryMasterKeyStore::default());
    let context = test_context_with_key_store(&directory, key_store.clone());
    let config = locket_core::ProjectConfig::new(
        locket_core::ProjectId::generate()?,
        "app".to_owned(),
        locket_core::ProfileName::new("dev".to_owned())?,
    );
    crate::write_project_config(&directory.path().join("locket.toml"), &config)?;
    let original_config_text = std::fs::read_to_string(directory.path().join("locket.toml"))?;
    std::fs::write(directory.path().join(".env.example"), "MANUAL=kept\n")?;

    let store = crate::open_store(&context)?;
    store.insert_project_if_absent(config.project_id.as_str(), &config.name, 1_000)?;
    drop(store);

    let result =
        run_with_context(Cli::try_parse_from(["locket", "init"])?, &context, &mut Vec::new());

    assert_error_contains(result, "refusing silent overwrite");
    assert_eq!(
        std::fs::read_to_string(directory.path().join("locket.toml"))?,
        original_config_text
    );
    assert_eq!(std::fs::read_to_string(directory.path().join(".env.example"))?, "MANUAL=kept\n");
    assert!(!directory.path().join(".locket/recovery/kdf.toml").exists());
    assert!(!directory.path().join(".locket/recovery/envelope.bin").exists());
    assert!(matches!(
        key_store.load_master_key(config.project_id.as_str()),
        Err(locket_platform::PlatformError::MasterKeyNotFound)
    ));

    let store = crate::open_store(&context)?;
    assert!(store.get_project(config.project_id.as_str())?.is_some());
    let count_rows = |table: &str| -> Result<i64, Box<dyn std::error::Error>> {
        let sql = format!("SELECT COUNT(*) FROM {table} WHERE project_id = ?1");
        Ok(store.connection().query_row(&sql, [config.project_id.as_str()], |row| row.get(0))?)
    };
    assert_eq!(count_rows("profiles")?, 0);
    assert_eq!(count_rows("keys")?, 0);
    assert_eq!(count_rows("project_roots")?, 0);
    assert_eq!(count_rows("audit_log")?, 0);
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

#[test]
fn new_from_builtin_template_writes_init_audit_row() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();

    run_with_context(
        Cli::try_parse_from(["locket", "new", "--from-template", "basic"])?,
        &context,
        &mut output,
    )?;

    let store = crate::open_store(&context)?;
    let config = crate::read_project_config(&directory.path().join("locket.toml"))?;
    let (sequence, action, status, command, secret_name, profile_id, metadata, hmac_len) =
        store.connection().query_row(
            "SELECT sequence, action, status, command, secret_name, profile_id, metadata_json,
                length(hmac)
         FROM audit_log WHERE action = 'INIT'",
            [],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, i64>(7)?,
                ))
            },
        )?;
    assert_eq!(sequence, 1);
    assert_eq!(action, "INIT");
    assert_eq!(status, "SUCCESS");
    assert_eq!(command.as_deref(), Some("new"));
    assert_eq!(secret_name, None);
    assert!(profile_id.is_some(), "INIT row must populate profile_id");
    assert_eq!(hmac_len, 32);
    let metadata: serde_json::Value = serde_json::from_str(&metadata)?;
    assert_eq!(metadata["schema_version"], json!(1));
    assert_eq!(metadata["action"], json!("INIT"));
    assert_eq!(metadata["status"], json!("SUCCESS"));
    assert_eq!(metadata["command"], json!("new"));
    assert_eq!(metadata["template_name"], json!("basic"));
    assert_eq!(metadata["template_source_kind"], json!("built-in"));
    assert_eq!(metadata["trust_root_recorded"], json!(true));
    assert_eq!(metadata["profile_count"], json!(1));
    assert_eq!(metadata["expected_secret_count"], json!(1));
    assert_eq!(metadata["command_count"], json!(1));
    assert_eq!(metadata["generated_files"], json!([".gitignore", ".env.example"]));
    assert!(metadata.get("secret_name").is_none());
    assert_eq!(metadata["project_id"].as_str(), Some(config.project_id.as_str()));
    assert_eq!(metadata["default_profile_id"].as_str(), profile_id.as_deref());

    let total: i64 = store.connection().query_row(
        "SELECT COUNT(*) FROM audit_log WHERE action = 'INIT'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(total, 1);
    Ok(())
}

#[test]
fn new_from_local_template_records_local_source_kind() -> Result<(), Box<dyn std::error::Error>> {
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

    let store = crate::open_store(&context)?;
    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'INIT'",
        [],
        |row| row.get(0),
    )?;
    let metadata: serde_json::Value = serde_json::from_str(&metadata)?;
    assert_eq!(metadata["template_name"], json!("web"));
    assert_eq!(metadata["template_source_kind"], json!("local"));
    assert_eq!(metadata["profile_count"], json!(2));
    assert_eq!(metadata["expected_secret_count"], json!(2));
    assert_eq!(metadata["command_count"], json!(1));
    assert_eq!(metadata["generated_files"], json!([".gitignore", ".env.example"]));
    assert_eq!(metadata["command"], json!("new"));
    assert!(!metadata.to_string().contains(&templates_dir.display().to_string()));
    Ok(())
}

#[test]
fn new_already_initialized_writes_no_audit_row() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    let mut output = Vec::new();

    run_with_context(
        Cli::try_parse_from(["locket", "new", "--from-template", "basic"])?,
        &context,
        &mut output,
    )?;
    let store = crate::open_store(&context)?;
    let init_rows_before: i64 = store.connection().query_row(
        "SELECT COUNT(*) FROM audit_log WHERE action = 'INIT'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(init_rows_before, 1);
    drop(store);

    let result = run_with_context(
        Cli::try_parse_from(["locket", "new", "--from-template", "basic"])?,
        &context,
        &mut Vec::new(),
    );
    assert_error_contains(result, "project already initialized");

    let store = crate::open_store(&context)?;
    let init_rows_after: i64 = store.connection().query_row(
        "SELECT COUNT(*) FROM audit_log WHERE action = 'INIT'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(init_rows_after, 1, "second `new` must not append a second INIT row");
    Ok(())
}

#[test]
fn new_rejects_invalid_template_without_writing_audit() -> Result<(), Box<dyn std::error::Error>> {
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

    let result = run_with_context(
        Cli::try_parse_from(["locket", "new", "--from-template", "bad"])?,
        &context,
        &mut Vec::new(),
    );
    assert_metadata_invalid(result, "template expected secret name is invalid")?;
    assert!(!directory.path().join("locket.toml").exists());

    let store = crate::open_store(&context)?;
    let total: i64 =
        store.connection().query_row("SELECT COUNT(*) FROM audit_log", [], |row| row.get(0))?;
    assert_eq!(total, 0, "rejected template must not write any audit row");
    Ok(())
}

fn seed_team_members_fixture(
    directory: &tempfile::TempDir,
    include_expired_invite: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let project_id =
        crate::read_project_config(&directory.path().join("locket.toml"))?.project_id.into_string();
    let device = crate::DeviceRecord {
        id: "lk_dev_team_owner".to_owned(),
        project_id: project_id.clone(),
        name: "owner laptop".to_owned(),
        signing_public_key: vec![3; 32],
        sealing_public_key: vec![4; 32],
        fingerprint: crate::device_fingerprint_hex(&[3; 32], &[4; 32]),
        safety_words: vec!["amber".to_owned(), "basil".to_owned()],
        local: true,
        created_at: 5,
        last_seen_at: Some(6),
        revoked_at: None,
    };
    store.insert_device(&device)?;
    store.connection().execute(
        "INSERT INTO teams(id, project_id, name, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        ("lk_team_cli", project_id.as_str(), "Core Team", 7_i64, 8_i64),
    )?;
    store.connection().execute(
        "INSERT INTO team_members(id, team_id, device_id, display_name, role, joined_at, removed_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        (
            "lk_member_owner",
            "lk_team_cli",
            "lk_dev_team_owner",
            "Alice Owner",
            "owner",
            10_i64,
            Option::<i64>::None,
        ),
    )?;
    store.connection().execute(
        "INSERT INTO team_members(id, team_id, display_name, role, joined_at, removed_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        ("lk_member_removed", "lk_team_cli", "Bob Removed", "developer", 20_i64, Some(30_i64)),
    )?;
    let expires_at = crate::now_unix_nanos()? + 1_000_000_000_000;
    store.connection().execute(
        "INSERT INTO team_invites(
           id, team_id, recipient_device_fingerprint, role, profiles_json, nonce, created_at,
           expires_at
         )
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        (
            "lk_invite_pending",
            "lk_team_cli",
            "recipient-fingerprint",
            "developer",
            serde_json::to_string(&vec!["dev", "staging"])?,
            vec![9_u8; 24],
            40_i64,
            expires_at,
        ),
    )?;
    if include_expired_invite {
        store.connection().execute(
            "INSERT INTO team_invites(
               id, team_id, recipient_device_fingerprint, role, profiles_json, nonce, created_at,
               expires_at
             )
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            (
                "lk_invite_expired",
                "lk_team_cli",
                "expired-fingerprint",
                "developer",
                "[]",
                vec![8_u8; 24],
                1_i64,
                2_i64,
            ),
        )?;
    }
    Ok(())
}

fn audit_row_count(store: &locket_store::Store) -> Result<i64, Box<dyn std::error::Error>> {
    Ok(store.connection().query_row("SELECT COUNT(*) FROM audit_log", [], |row| row.get(0))?)
}

fn assert_metadata_invalid<T>(
    result: Result<T, crate::CliError>,
    expected_message: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let Err(error) = result else {
        return Err(
            format!("expected MetadataInvalid error containing {expected_message:?}").into()
        );
    };
    assert_eq!(error.exit_code(), 64);
    let crate::CliError::Typed { kind, message } = error else {
        return Err(format!("expected typed MetadataInvalid error, got {error:?}").into());
    };
    assert_eq!(kind, locket_core::LocketError::MetadataInvalid);
    assert!(message.contains(expected_message), "{message}");
    Ok(())
}

#[test]
#[allow(clippy::too_many_lines)]
fn team_invite_creates_signed_file_pending_row_and_audit() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    run_with_context(
        Cli::try_parse_from(["locket", "device", "init"])?,
        &context,
        &mut Vec::new(),
    )?;
    run_with_context(
        Cli::try_parse_from(["locket", "team", "init", "platform-team"])?,
        &context,
        &mut Vec::new(),
    )?;

    let config = crate::read_project_config(&directory.path().join("locket.toml"))?;
    let recipient_fingerprint = crate::device_fingerprint_hex(&[11; 32], &[12; 32]);
    let recipient = crate::DeviceRecord {
        id: "lk_dev_recipient".to_owned(),
        project_id: config.project_id.to_string(),
        name: "recipient laptop".to_owned(),
        signing_public_key: vec![11; 32],
        sealing_public_key: vec![12; 32],
        fingerprint: recipient_fingerprint.clone(),
        safety_words: vec!["amber".to_owned(), "basil".to_owned()],
        local: false,
        created_at: 10,
        last_seen_at: None,
        revoked_at: None,
    };
    let descriptor = crate::encode_device_descriptor(&recipient)?;
    let output_path = directory.path().join("invite.locket-invite");

    let mut output = Vec::new();
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "team",
            "invite",
            "Teammate",
            "--device",
            descriptor.as_str(),
            "--profile",
            "dev",
            "--role",
            "developer",
            "--output",
            output_path.to_str().ok_or("non-utf8 output path")?,
        ])?,
        &context,
        &mut output,
    )?;
    let output = String::from_utf8(output)?;
    assert!(output.contains("team_invite: created"), "{output}");
    assert!(output.contains("role: developer"), "{output}");
    assert!(output.contains("profiles: dev"), "{output}");
    assert!(output.contains("metadata_only: yes"), "{output}");
    assert!(!output.contains("recipient laptop"));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&output_path)?.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "invite file must be 0600, got 0o{mode:o}");
    }

    let invite_text = std::fs::read_to_string(&output_path)?;
    let invite = locket_core::SignedInvite::decode(invite_text.trim())?;
    invite.verify()?;
    assert_eq!(invite.payload.project_id.as_str(), config.project_id.as_str());
    assert_eq!(invite.payload.recipient_device_fingerprint, recipient_fingerprint);
    assert_eq!(invite.payload.role, locket_core::TeamRole::Developer);
    assert_eq!(invite.payload.profiles, vec!["dev".to_owned()]);
    assert!(!invite.signature.is_empty());

    assert!(
        output
            .contains(&format!("issuer_fingerprint: {}", invite.payload.issuer_device_fingerprint)),
        "{output}"
    );

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let (role, profiles_json, nonce_len): (String, String, i64) = store.connection().query_row(
        "SELECT role, profiles_json, length(nonce) FROM team_invites WHERE id = ?1",
        [invite.payload.invite_id.as_str()],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    assert_eq!(role, "developer");
    assert_eq!(serde_json::from_str::<Vec<String>>(&profiles_json)?, vec!["dev"]);
    assert_eq!(nonce_len, 24);

    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log WHERE action = 'TEAM_INVITE'
         ORDER BY sequence DESC LIMIT 1",
        [],
        |row| row.get(0),
    )?;
    let metadata: serde_json::Value = serde_json::from_str(&metadata)?;
    assert_eq!(metadata["status"], "SUCCESS");
    assert_eq!(metadata["command"], "team invite");
    assert_eq!(metadata["invite_id"], invite.payload.invite_id.as_str());
    assert_eq!(metadata["recipient_device_fingerprint"], recipient_fingerprint);
    assert_eq!(metadata["role"], "developer");
    assert_eq!(metadata["profiles"], json!(["dev"]));
    drop(store);

    let mut revoke_output = Vec::new();
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "team",
            "revoke-invite",
            invite.payload.invite_id.as_str(),
        ])?,
        &context,
        &mut revoke_output,
    )?;
    let revoke_output = String::from_utf8(revoke_output)?;
    assert!(revoke_output.contains("team_invite: revoked"), "{revoke_output}");
    assert!(revoke_output.contains(invite.payload.invite_id.as_str()), "{revoke_output}");
    assert!(revoke_output.contains("role: developer"), "{revoke_output}");
    assert!(revoke_output.contains("profiles: dev"), "{revoke_output}");
    assert!(revoke_output.contains("metadata_only: yes"), "{revoke_output}");
    assert!(!revoke_output.contains("recipient laptop"));

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let revoked_at: Option<i64> = store.connection().query_row(
        "SELECT revoked_at FROM team_invites WHERE id = ?1",
        [invite.payload.invite_id.as_str()],
        |row| row.get(0),
    )?;
    assert!(revoked_at.is_some());
    let pending_count: i64 = store.connection().query_row(
        "SELECT COUNT(*) FROM team_invites WHERE id = ?1 AND revoked_at IS NULL",
        [invite.payload.invite_id.as_str()],
        |row| row.get(0),
    )?;
    assert_eq!(pending_count, 0);

    let metadata: String = store.connection().query_row(
        "SELECT metadata_json FROM audit_log
         WHERE action = 'TEAM_INVITE' AND command = 'team revoke-invite'
         ORDER BY sequence DESC LIMIT 1",
        [],
        |row| row.get(0),
    )?;
    let metadata: serde_json::Value = serde_json::from_str(&metadata)?;
    assert_eq!(metadata["status"], "SUCCESS");
    assert_eq!(metadata["command"], "team revoke-invite");
    assert_eq!(metadata["operation"], "revoke");
    assert_eq!(metadata["invite_id"], invite.payload.invite_id.as_str());
    assert_eq!(metadata["recipient_device_fingerprint"], recipient_fingerprint);
    assert_eq!(metadata["role"], "developer");
    assert_eq!(metadata["profiles"], json!(["dev"]));
    Ok(())
}

#[test]
fn team_invite_rejects_bad_descriptor_without_file_or_audit()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    run_with_context(
        Cli::try_parse_from(["locket", "device", "init"])?,
        &context,
        &mut Vec::new(),
    )?;
    run_with_context(
        Cli::try_parse_from(["locket", "team", "init", "platform-team"])?,
        &context,
        &mut Vec::new(),
    )?;
    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let before = audit_row_count(&store)?;
    drop(store);

    let output_path = directory.path().join("bad-invite.locket-invite");
    let result = run_with_context(
        Cli::try_parse_from([
            "locket",
            "team",
            "invite",
            "Teammate",
            "--device",
            "lkdev1_not-base64",
            "--profile",
            "dev",
            "--role",
            "developer",
            "--output",
            output_path.to_str().ok_or("non-utf8 output path")?,
        ])?,
        &context,
        &mut Vec::new(),
    );
    assert_metadata_invalid(result, "device descriptor is not valid base64url")?;
    assert!(!output_path.exists());
    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    assert_eq!(audit_row_count(&store)?, before);
    Ok(())
}

#[test]
fn team_invite_locked_vault_fails_before_writing_output() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    run_with_context(
        Cli::try_parse_from(["locket", "device", "init"])?,
        &context,
        &mut Vec::new(),
    )?;
    run_with_context(
        Cli::try_parse_from(["locket", "team", "init", "platform-team"])?,
        &context,
        &mut Vec::new(),
    )?;
    let config = crate::read_project_config(&directory.path().join("locket.toml"))?;
    let recipient = crate::DeviceRecord {
        id: "lk_dev_recipient".to_owned(),
        project_id: config.project_id.to_string(),
        name: "recipient laptop".to_owned(),
        signing_public_key: vec![21; 32],
        sealing_public_key: vec![22; 32],
        fingerprint: crate::device_fingerprint_hex(&[21; 32], &[22; 32]),
        safety_words: vec!["cedar".to_owned(), "delta".to_owned()],
        local: false,
        created_at: 10,
        last_seen_at: None,
        revoked_at: None,
    };
    let descriptor = crate::encode_device_descriptor(&recipient)?;
    context.key_store.delete_master_key(config.project_id.as_str())?;
    let output_path = directory.path().join("locked-invite.locket-invite");

    let result = run_with_context(
        Cli::try_parse_from([
            "locket",
            "team",
            "invite",
            "Teammate",
            "--device",
            descriptor.as_str(),
            "--profile",
            "dev",
            "--role",
            "developer",
            "--output",
            output_path.to_str().ok_or("non-utf8 output path")?,
        ])?,
        &context,
        &mut Vec::new(),
    );
    let Err(error) = result else {
        return Err("locked vault invite must fail".into());
    };
    assert_eq!(error.exit_code(), locket_core::LocketError::UnlockRequired.exit_code());
    assert!(!output_path.exists());
    Ok(())
}

#[test]
fn team_revoke_invite_locked_vault_fails_before_revocation()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;
    run_with_context(
        Cli::try_parse_from(["locket", "device", "init"])?,
        &context,
        &mut Vec::new(),
    )?;
    run_with_context(
        Cli::try_parse_from(["locket", "team", "init", "platform-team"])?,
        &context,
        &mut Vec::new(),
    )?;
    let config = crate::read_project_config(&directory.path().join("locket.toml"))?;
    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let (team_id, member_id): (String, String) = store.connection().query_row(
        "SELECT t.id, m.id
         FROM teams t JOIN team_members m ON m.team_id = t.id
         WHERE t.project_id = ?1
         LIMIT 1",
        [config.project_id.as_str()],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    store.connection().execute(
        "INSERT INTO team_invites(
           id, team_id, issuer_member_id, recipient_device_fingerprint, role, profiles_json,
           nonce, created_at, expires_at
         )
         VALUES (?1, ?2, ?3, 'recipient-fingerprint', 'developer', '[\"dev\"]', zeroblob(24), 1, 999999)",
        ["lk_invite_locked_revoke", team_id.as_str(), member_id.as_str()],
    )?;
    let before = audit_row_count(&store)?;
    drop(store);

    context.key_store.delete_master_key(config.project_id.as_str())?;
    let result = run_with_context(
        Cli::try_parse_from(["locket", "team", "revoke-invite", "lk_invite_locked_revoke"])?,
        &context,
        &mut Vec::new(),
    );
    let Err(error) = result else {
        return Err("locked vault revoke-invite must fail".into());
    };
    assert_eq!(error.exit_code(), locket_core::LocketError::UnlockRequired.exit_code());

    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let revoked_at: Option<i64> = store.connection().query_row(
        "SELECT revoked_at FROM team_invites WHERE id = 'lk_invite_locked_revoke'",
        [],
        |row| row.get(0),
    )?;
    assert!(revoked_at.is_none());
    assert_eq!(audit_row_count(&store)?, before);
    Ok(())
}

#[test]
fn e2e_greenfield_init_set_get_with_audit_chain_and_file_modes()
-> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempdir()?;
    let context = test_context_with_secret_value(&directory, "postgres://localhost/e2e");

    // Step 1: locket init (project name "app" matches the default init confirmation reader)
    let mut init_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut init_output,
    )?;
    let init_text = String::from_utf8(init_output)?;
    assert!(init_text.contains("initialized locket project"), "init output: {init_text}");
    assert!(init_text.contains("default_profile: dev"));

    // Step 2: locket device init
    let mut device_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "device", "init"])?,
        &context,
        &mut device_output,
    )?;
    let device_text = String::from_utf8(device_output)?;
    assert!(device_text.contains("device: initialized"), "device init output: {device_text}");
    assert!(device_text.contains("metadata_only: yes"));

    // Step 3: locket profile create staging
    let mut profile_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "profile", "create", "staging"])?,
        &context,
        &mut profile_output,
    )?;
    let profile_text = String::from_utf8(profile_output)?;
    assert!(
        profile_text.contains("created profile staging"),
        "profile create output: {profile_text}"
    );

    // Step 4: locket set DATABASE_URL
    let mut set_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "set", "DATABASE_URL"])?,
        &context,
        &mut set_output,
    )?;
    let set_text = String::from_utf8(set_output)?;
    assert!(set_text.contains("set DATABASE_URL"), "set output: {set_text}");
    assert!(
        !set_text.contains("postgres://localhost/e2e"),
        "secret value must not appear in output"
    );

    // Step 5: locket get DATABASE_URL --reveal --force
    let mut get_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "get", "DATABASE_URL", "--reveal", "--force"])?,
        &context,
        &mut get_output,
    )?;
    assert_eq!(
        String::from_utf8(get_output)?,
        "postgres://localhost/e2e\n",
        "get --reveal should output exact secret value"
    );

    // Verify audit chain integrity via locket audit verify
    let mut audit_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "audit", "verify"])?,
        &context,
        &mut audit_output,
    )?;
    let audit_text = String::from_utf8(audit_output)?;
    assert!(audit_text.contains("audit: verified"), "audit verify output: {audit_text}");

    // Assert no secret values appear in any audit row metadata
    let store = locket_store::Store::open(directory.path().join("store.db"))?;
    let metadata_rows: Vec<String> = {
        let mut stmt =
            store.connection().prepare("SELECT metadata_json FROM audit_log ORDER BY sequence")?;
        stmt.query_map([], |row| row.get::<_, String>(0))?.collect::<Result<Vec<_>, _>>()?
    };
    for metadata in &metadata_rows {
        assert!(
            !metadata.contains("postgres://localhost/e2e"),
            "audit metadata must not contain secret value"
        );
    }

    // Assert INIT audit row is present
    let actions: Vec<String> = {
        let mut stmt =
            store.connection().prepare("SELECT action FROM audit_log ORDER BY sequence")?;
        stmt.query_map([], |row| row.get::<_, String>(0))?.collect::<Result<Vec<_>, _>>()?
    };
    assert!(actions.contains(&"INIT".to_owned()), "INIT audit row missing: {actions:?}");
    assert!(actions.contains(&"SET".to_owned()), "SET audit row missing: {actions:?}");
    assert!(actions.contains(&"REVEAL".to_owned()), "REVEAL audit row missing: {actions:?}");

    // Assert passphrase-fallback key file (if present) has 0600 permissions.
    // The store.db itself uses SQLite's default umask; file-mode hardening for
    // store.db is tracked as a separate work item.
    let passphrase_fallback = directory.path().join("passphrase-fallback");
    if passphrase_fallback.exists() {
        let mode = fs::metadata(&passphrase_fallback)?.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "passphrase-fallback must have 0600 permissions, got 0o{mode:o}");
    }

    Ok(())
}

#[test]
fn solo_project_without_team_allows_all_owner_operations() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;

    let args = test_secret_write_args("DATABASE_URL");
    crate::set_secret_value(&context, &args, "postgres://localhost/app", "manual", 1_000)?;

    let mut get_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "get", "DATABASE_URL"])?,
        &context,
        &mut get_output,
    )?;

    let mut members_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "team", "members"])?,
        &context,
        &mut members_output,
    )?;
    let members_output = String::from_utf8(members_output)?;
    assert!(members_output.contains("team: none"), "solo project should show no team");
    assert!(members_output.contains("members: none"));
    assert!(members_output.contains("pending_invites: none"));

    run_with_context(
        Cli::try_parse_from([
            "locket",
            "exec",
            "--force",
            "--secret",
            "DATABASE_URL",
            "--",
            "/bin/sh",
            "-c",
            "test \"$DATABASE_URL\" = \"postgres://localhost/app\"",
        ])?,
        &context,
        &mut Vec::new(),
    )?;

    Ok(())
}

#[test]
fn solo_project_without_team_init_rejects_duplicate_team_init()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;

    let mut team_init_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "team", "init", "myteam"])?,
        &context,
        &mut team_init_output,
    )?;
    let team_init_output = String::from_utf8(team_init_output)?;
    assert!(team_init_output.contains("team initialized: myteam"));

    let result = run_with_context(
        Cli::try_parse_from(["locket", "team", "init", "myteam"])?,
        &context,
        &mut Vec::new(),
    );
    let Err(error) = result else {
        return Err("duplicate team init must fail".into());
    };
    assert_eq!(error.exit_code(), 67, "SecretAlreadyExists is exit 67");
    assert!(error.to_string().contains("team already initialized"));

    Ok(())
}

#[test]
fn solo_project_can_init_team_and_becomes_team_project() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let context = test_context(&directory);
    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut Vec::new(),
    )?;

    let mut members_before = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "team", "members"])?,
        &context,
        &mut members_before,
    )?;
    assert!(String::from_utf8(members_before)?.contains("team: none"), "no team before init");

    let mut team_init_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "team", "init", "myteam"])?,
        &context,
        &mut team_init_output,
    )?;
    let team_init_output = String::from_utf8(team_init_output)?;
    assert!(team_init_output.contains("team initialized: myteam"));

    let mut members_output = Vec::new();
    run_with_context(
        Cli::try_parse_from(["locket", "team", "members"])?,
        &context,
        &mut members_output,
    )?;
    let members_output = String::from_utf8(members_output)?;
    assert!(members_output.contains("team: myteam"), "after init, team should be present");

    Ok(())
}
