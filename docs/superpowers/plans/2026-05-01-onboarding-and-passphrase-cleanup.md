# Onboarding & Passphrase-Prompt Cleanup — Implementation Plan

> **For agentic workers:** Each task below is self-contained and independent
> from the others (different files, no shared symbols beyond standard
> library). Tasks may be implemented in parallel. Run the full workspace
> test suite (`cargo test --workspace`) before declaring done.

**Goal:** Implement the four UX changes from
`docs/superpowers/specs/2026-05-01-onboarding-and-passphrase-cleanup.md`.

**Architecture:** All four are surgical changes inside existing
`locket-cli` modules. No crypto, no schema, no new files for code (only
new tests).

**Tech stack:** Rust, clap, rpassword, the existing `locket-store` /
`locket-platform` / `locket-crypto` workspace crates.

---

## Task 1 — Explain why a passphrase is being requested

**Spec:** Change 1.

**Files:**
- Modify: `crates/locket-cli/src/runtime/key_access.rs` (around lines
  30–72 and 74–89)
- Test: `crates/locket-cli/src/tests/cli_errors.rs` or
  `crates/locket-cli/src/tests/recovery.rs` (whichever is closer to
  passphrase-fallback territory; reuse existing test fixtures)

### Step 1.1 — Add a stderr-writing helper

In `key_access.rs`, add a small private helper above the existing
functions:

```rust
fn explain_passphrase_prompt(reason: PassphrasePromptReason) {
    let mut stderr = std::io::stderr();
    let _ = match reason {
        PassphrasePromptReason::NewFallback => writeln!(
            stderr,
            "locket: OS keychain is unavailable; setting up a passphrase fallback for this project.\n\
             locket: you will need this passphrase to use this vault on this machine.\n\
             locket: save your recovery code separately when it is displayed."
        ),
        PassphrasePromptReason::ExistingFallback => writeln!(
            stderr,
            "locket: OS keychain entry not found for this project; using the passphrase fallback.\n\
             locket: enter the passphrase you set when this project was first initialized on this machine."
        ),
    };
}

#[derive(Clone, Copy)]
enum PassphrasePromptReason {
    NewFallback,
    ExistingFallback,
}
```

Add `use std::io::Write;` to the imports if not already present.

### Step 1.2 — Wire the helper into both call sites

In `store_master_key_with_fallback` (the `Err(_primary_error)` branch),
*immediately before* the call to
`context.passphrase_reader.new_passphrase()`, insert:

```rust
explain_passphrase_prompt(PassphrasePromptReason::NewFallback);
```

In `load_fallback_master_key`, *immediately before*
`context.passphrase_reader.existing_passphrase()`, insert:

```rust
explain_passphrase_prompt(PassphrasePromptReason::ExistingFallback);
```

### Step 1.3 — Add a unit test that asserts the stderr lines appear

Look at how existing tests stub `passphrase_reader` and `key_store`
(see `tests/mod.rs:127-134` and `tests/config_passkey_lock.rs:989-990`
for examples of how `MockMasterKeyStoreFailure::MasterKeyNotFound` is
configured). Add a test in the most appropriate existing test file (or
extend an existing one) that:

- Configures a key store that returns `MasterKeyNotFound`.
- Captures stderr (use the existing test infrastructure for this — the
  test crate already does it elsewhere; grep for `BufferedStderr` or
  similar).
- Calls `store_master_key_with_fallback` (or whichever public entry
  point) and asserts the new lines appear in stderr.

If existing tests don't capture stderr, this is acceptable: skip the
stderr assertion and verify only that the prompt still works
end-to-end. Document the gap with a `// TODO: capture stderr` comment.

### Step 1.4 — Run tests

```bash
cargo test --workspace --no-fail-fast 2>&1 | tail -50
```

Ensure all pass. Existing tests that capture stderr verbatim may need
their fixtures updated to include the new lines — update them to match.

### Step 1.5 — Commit

```bash
git add -p crates/locket-cli/src/runtime/key_access.rs \
          crates/locket-cli/src/tests/
git commit -m "cli: explain why a passphrase fallback prompt appeared

Both `store_master_key_with_fallback` and `load_fallback_master_key`
now write a short stderr explanation before invoking the passphrase
reader, so users understand the OS keychain became unavailable rather
than wondering why locket is asking for a password."
```

---

## Task 2 — `locket status` shows cwd and flags mismatch

**Spec:** Change 2.

**Files:**
- Modify: `crates/locket-cli/src/commands/project/status.rs`
- Test: `crates/locket-cli/src/tests/cli_basics.rs` (and
  `grants_agent_diag.rs` if it asserts on status output verbatim)

### Step 2.1 — Add cwd lines to `status`

In `status.rs`, after the `writeln!(output, "root: {}", …)` line at
line 55, insert:

```rust
let cwd_display = match std::env::current_dir() {
    Ok(path) => path.canonicalize().unwrap_or(path).display().to_string(),
    Err(_) => "<unavailable>".to_owned(),
};
let cwd_matches_root = match std::env::current_dir() {
    Ok(path) => path.canonicalize().ok().as_deref() == Some(&resolved.root),
    Err(_) => false,
};
writeln!(output, "cwd: {cwd_display}")?;
writeln!(
    output,
    "cwd_matches_root: {}",
    if cwd_matches_root { "yes" } else { "no" }
)?;
if !cwd_matches_root {
    writeln!(
        output,
        "cwd_hint: locket.toml resolved from a parent directory; commands act on the project at root:"
    )?;
}
```

(Order: `root:`, `cwd:`, `cwd_matches_root:`, optional `cwd_hint:`,
then existing fields.)

### Step 2.2 — Update existing tests

Run:

```bash
cargo test --package locket-cli --test cli_basics 2>&1 | head -80
```

Any test that asserts on the verbatim output of `locket status` will
fail. Update the expected fixtures to include `cwd:` and
`cwd_matches_root:` lines. For tests run from the project root, the
expected value is `yes` and no `cwd_hint`. For any test that runs from
a subdirectory, expected is `no` with the hint line.

### Step 2.3 — Add a new test for the mismatch case

In the most appropriate test file (`tests/cli_basics.rs`), add a test:

```rust
#[test]
fn status_shows_cwd_mismatch_when_run_from_subdirectory() {
    // Set up a project at <root>/, then chdir into <root>/sub/
    // Run status, assert cwd_matches_root: no and cwd_hint line present
}
```

Use the existing test scaffolding for project setup (see other tests
in the same file for pattern). The exact API for "chdir during a test"
may already be wrapped in a helper; reuse it.

### Step 2.4 — Run tests

```bash
cargo test --workspace --no-fail-fast 2>&1 | tail -50
```

### Step 2.5 — Commit

```bash
git add -p crates/locket-cli/src/commands/project/status.rs \
          crates/locket-cli/src/tests/
git commit -m "cli(status): show cwd and flag mismatch with trusted root

Adds always-on \`cwd:\` and \`cwd_matches_root:\` fields to
\`locket status\`, plus a one-line hint when locket.toml resolved from
a parent directory rather than the current working directory."
```

---

## Task 3 — `locket init` runs device init and offers passkey

**Spec:** Change 3.

**Files:**
- Modify: `crates/locket-cli/src/commands/project/init.rs`
- Modify: `crates/locket-cli/src/main.rs` (clap arg definitions for
  `init`)
- Test: `crates/locket-cli/src/tests/init_template_device.rs`

### Step 3.1 — Add new flags to `InitArgs`

In `main.rs`, find the `InitArgs` struct (search for `struct InitArgs`
or `Command::Init`). Add:

```rust
/// Skip creating a local device during init.
#[arg(long)]
no_device: bool,

/// Register a passkey after device init using the host name as the
/// label. Conflicts with --no-passkey.
#[arg(long, conflicts_with = "no_passkey")]
register_passkey: bool,

/// Skip the passkey registration prompt entirely.
#[arg(long)]
no_passkey: bool,
```

If `InitArgs` is in a different file, follow the existing pattern in
that file.

### Step 3.2 — Thread the flags into `complete_init`

`complete_init()` lives in
`crates/locket-cli/src/commands/project/init.rs`. Find its signature
and add three parameters: `no_device: bool`, `register_passkey: bool`,
`no_passkey: bool`. Update the call site(s) to pass the new flags
through.

### Step 3.3 — Call `device_init_command` from `complete_init`

After `trust_root()` (around line 373) and *before*
`display_recovery_code()` (around line 377), add:

```rust
if !no_device {
    let device_args = crate::DeviceInitArgs::default(); // or build with default name
    if let Err(error) = crate::commands::team::device::device_init_command(
        context,
        output,
        &device_args,
    ) {
        let mut stderr = std::io::stderr();
        let _ = writeln!(
            stderr,
            "locket: device init failed during init: {error}\n\
             locket: vault is usable; run `locket device init` later to retry."
        );
    }
}
```

The exact `DeviceInitArgs` fields you need to supply depend on what's
in `main.rs`; read the struct first and instantiate it with sensible
defaults (no force, no explicit label, etc.). If `device_init_command`
takes a different signature, adapt — the principle is "call the
existing function with default args."

### Step 3.4 — Add the passkey prompt + register call

After the device-init block, add:

```rust
if !no_passkey {
    let should_register = if register_passkey {
        true
    } else if context.confirmation_reader.is_interactive() {
        // Prompt: "Register a passkey for this device? [y/N]"
        let response = context
            .confirmation_reader
            .read_confirmation("Register a passkey for this device? [y/N] ")?;
        matches!(response.trim().to_lowercase().as_str(), "y" | "yes")
    } else {
        false
    };
    if should_register {
        let label = std::env::var("HOSTNAME")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .unwrap_or_else(|| "primary".to_owned());
        let rp_id = "locket.localhost".to_owned();
        let args = crate::PasskeyRegisterArgs { label, relying_party_id: rp_id };
        if let Err(error) = crate::commands::vault::passkey::passkey_register_command(
            context,
            output,
            &args,
        ) {
            let mut stderr = std::io::stderr();
            let _ = writeln!(
                stderr,
                "locket: passkey registration failed during init: {error}\n\
                 locket: vault is usable; run `locket passkey register --label <name>` later to retry."
            );
        }
    }
}
```

`ConfirmationReader::is_interactive()` may not exist — if so, infer
interactivity by checking `io::stdin().is_terminal()` directly (look
at `prompts.rs:74-94` for how the codebase already does this). The
goal is: in non-TTY contexts, do not prompt; treat as `--no-passkey`.

If `ConfirmationReader` does not have a method for "ask y/N and parse,"
use `read_confirmation()` and parse manually as shown.

If the existing `read_confirmation` in tests requires the user to type
a specific selector (see `passkey_remove_command` for an example
where the confirmation must match a specific string), this y/N flow is
*new* behavior. Add a minimal helper at the call site rather than
modifying the trait.

### Step 3.5 — Add unit tests

In `tests/init_template_device.rs`:

1. **Test:** default `init` creates a device row.
   - Arrange: stub passkey registrar to refuse (or set up the test to
     pass `--no-passkey`).
   - Act: call init.
   - Assert: `store.get_active_local_device(project_id)?` returns
     `Some`.

2. **Test:** `--no-device` skips device creation.
   - Arrange: same as above.
   - Act: call init with `no_device=true`.
   - Assert: `get_active_local_device` returns `None`.

3. **Test:** `--register-passkey` triggers the passkey registrar.
   - Arrange: stub passkey registrar to succeed with a fake credential.
   - Act: call init with `register_passkey=true`.
   - Assert: `store.list_passkey_credentials(project_id, false)?`
     contains one row.

4. **Test:** failing device init does not fail overall init.
   - Arrange: stub `device_init_command` (if mockable) or set up
     conditions where it would fail (e.g., already-initialized device
     without `--force`).
   - Assert: init returns `Ok`, recovery code is still displayed.

5. **Test:** `--no-passkey` and `--register-passkey` conflict at clap
   parse time.
   - Use `Cli::try_parse_from(["locket", "init", "--no-passkey",
     "--register-passkey"])` and assert it errors.

### Step 3.6 — Run tests

```bash
cargo test --workspace --no-fail-fast 2>&1 | tail -50
```

Existing init tests will fail because device init now runs by default;
update fixtures to either pass `--no-device` (preserving prior
behavior) or update assertions to expect a device row.

### Step 3.7 — Commit

```bash
git add -p crates/locket-cli/src/main.rs \
          crates/locket-cli/src/commands/project/init.rs \
          crates/locket-cli/src/tests/
git commit -m "cli(init): create local device and offer passkey by default

\`locket init\` now calls \`device init\` and prompts to register a
passkey (interactive only). New flags: --no-device, --register-passkey,
--no-passkey. Failures of either sub-step warn but do not fail init."
```

---

## Task 4 — Better error from `passkey register` when no device exists

**Spec:** Change 4.

**Files:**
- Modify: `crates/locket-cli/src/commands/vault/passkey.rs:56-58`
- Test: `crates/locket-cli/src/tests/config_passkey_lock.rs` or
  similar

### Step 4.1 — Update the error message

Change [crates/locket-cli/src/commands/vault/passkey.rs:56-58](../../../crates/locket-cli/src/commands/vault/passkey.rs#L56-L58)
from:

```rust
let local_device = store.get_active_local_device(project_id)?.ok_or_else(|| {
    invalid_reference_error("active local device required for passkey registration")
})?;
```

to:

```rust
let local_device = store.get_active_local_device(project_id)?.ok_or_else(|| {
    invalid_reference_error(
        "no active local device for this project. Run `locket device init` to create one, \
         or re-run `locket init` (which now sets one up automatically by default)."
    )
})?;
```

### Step 4.2 — Update any test that asserts on the old string

Grep for `active local device required for passkey registration`:

```bash
grep -rn "active local device required for passkey registration" \
    crates/locket-cli/src/tests
```

Update each match to expect the new string. Use a substring match
(`assert!(msg.contains("no active local device"))`) rather than the
full string if possible, so future copy edits don't break tests.

### Step 4.3 — Run tests

```bash
cargo test --package locket-cli --no-fail-fast 2>&1 | tail -30
```

### Step 4.4 — Commit

```bash
git add -p crates/locket-cli/src/commands/vault/passkey.rs \
          crates/locket-cli/src/tests/
git commit -m "cli(passkey): clarify error when no active local device exists

The error from \`passkey register\` now tells the user how to create a
device, rather than just saying one is required."
```

---

## Final verification

After all four tasks are committed:

```bash
cargo test --workspace --no-fail-fast 2>&1 | tail -30
cargo clippy --workspace --all-targets --no-deps -- -D warnings
cargo fmt --all -- --check
```

All three must pass. If any task touched an area covered by another
task, verify there's no merge conflict by running the full suite
together.

## Out of scope (explicit, do not pull in)

- Changing `init_platform_keyring` failure handling.
- Changing how trusted roots are registered.
- Adding `master_unlock_preference`.
- Touching the passkey-PRF crypto.
