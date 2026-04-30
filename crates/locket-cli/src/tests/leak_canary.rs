#[allow(unused_imports)]
use super::*;

fn cli_canary_value() -> String {
    ["lk", "canary", "cli", "value", "1234567890abcdef"].join("-")
}

#[test]
fn cli_canary_does_not_leak_to_outputs_or_generated_artifacts()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let canary = cli_canary_value();
    let context = test_context_with_secret_value(&directory, &canary);
    let mut captured = Vec::new();

    run_with_context(
        Cli::try_parse_from(["locket", "init", "--name", "app", "--profile", "dev"])?,
        &context,
        &mut captured,
    )?;
    run_with_context(
        Cli::try_parse_from(["locket", "set", "DATABASE_URL"])?,
        &context,
        &mut captured,
    )?;
    run_with_context(Cli::try_parse_from(["locket", "list"])?, &context, &mut captured)?;
    run_with_context(
        Cli::try_parse_from(["locket", "history", "DATABASE_URL"])?,
        &context,
        &mut captured,
    )?;
    run_with_context(Cli::try_parse_from(["locket", "status"])?, &context, &mut captured)?;

    let bundle_path = directory.path().join("canary-debug-bundle.tar.gz");
    run_with_context(
        Cli::try_parse_from([
            "locket",
            "debug",
            "bundle",
            "--redacted",
            "--output",
            bundle_path.to_str().ok_or("utf8 path")?,
        ])?,
        &context,
        &mut captured,
    )?;

    let output_text = String::from_utf8(captured)?;
    assert!(!output_text.contains(&canary));
    let bundle_json = read_debug_bundle_json(&bundle_path)?;
    assert!(!bundle_json.contains(&canary));
    assert_canary_absent_from_files(directory.path(), canary.as_bytes())?;
    Ok(())
}

fn assert_canary_absent_from_files(
    root: &Path,
    canary: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    for path in collect_files(root)? {
        let bytes = fs::read(&path)?;
        assert!(!contains_bytes(&bytes, canary), "canary leaked into {}", path.display());
    }
    Ok(())
}

fn collect_files(root: &Path) -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
    let mut files = Vec::new();
    collect_files_into(root, &mut files)?;
    Ok(files)
}

fn collect_files_into(
    root: &Path,
    files: &mut Vec<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let path = entry.path();
        let metadata = entry.metadata()?;
        if metadata.is_dir() {
            collect_files_into(&path, files)?;
        } else if metadata.is_file() {
            files.push(path);
        }
    }
    Ok(())
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|window| window == needle)
}
