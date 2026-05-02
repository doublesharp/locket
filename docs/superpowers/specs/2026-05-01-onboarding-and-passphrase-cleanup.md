# Locket Onboarding & Passphrase-Prompt Cleanup

> **Note (2026-05-01 final revision):** This spec replaces two earlier drafts in
> the same file. The first proposed a from-scratch passkey-unlock factor; on
> reading the codebase, that was already shipped. The second narrowed to UX
> gaps in the existing passkey flow. Real testing surfaced a different set of
> bugs — passphrase-prompt confusion, invisible cwd/trusted-root mismatch,
> multi-step onboarding — and that is what this revision targets.

## Goal

Make `locket` work the way a first-time user expects:

1. `locket init` produces a fully usable vault in one command (project + master
   key + recovery envelope + local device + optional passkey).
2. When Locket asks for a passphrase, the user understands why.
3. When the user is in a directory whose `locket.toml` is not registered as a
   trusted root, that mismatch is visible.

## Non-goals

- Changing the master-key crypto, the passphrase fallback crypto, or the
  passkey PRF crypto.
- Changing how trusted roots are registered or hashed.
- Replacing or relocating the existing `locket device init` /
  `locket passkey register` commands. They keep working as standalone tools.
- Auto-trusting unregistered roots. The spec only adds visibility, not
  automatic trust changes.
- Adding preference modes for passkey-first unlock (out of scope; see history
  earlier in this file's revisions).

## Background (current state)

- `locket init` ([init.rs:40-110](../../../crates/locket-cli/src/commands/project/init.rs))
  generates `locket.toml`, master key, recovery envelope, and trusts the root.
  It does **not** create a local device.
- `locket device init` ([device.rs:46-154](../../../crates/locket-cli/src/commands/team/device.rs))
  creates the local device. It assumes the master key already exists. With
  the master key reachable, this command requires no interactive input
  beyond user verification (which is policy-driven and may be a no-op).
- `locket passkey register` ([passkey.rs:39-148](../../../crates/locket-cli/src/commands/vault/passkey.rs))
  registers a passkey credential and, if PRF-capable, writes a master-key
  wrap. Requires an active local device. Triggers a platform passkey
  ceremony (Touch ID, FIDO2, etc.).
- The passphrase prompt (`"locket passphrase: "`) is emitted unconditionally
  from [prompts.rs:60](../../../crates/locket-cli/src/runtime/prompts.rs#L60)
  via `rpassword::prompt_password`. The two call sites in
  [key_access.rs:39](../../../crates/locket-cli/src/runtime/key_access.rs#L39)
  (new passphrase) and [key_access.rs:83](../../../crates/locket-cli/src/runtime/key_access.rs#L83)
  (existing passphrase) print no preceding explanation.
- `locket status` ([status.rs:15-68](../../../crates/locket-cli/src/commands/project/status.rs))
  prints `root:` (the directory containing `locket.toml`) and
  `trusted_root: yes|no`, but does not print the user's cwd.
  `resolve_project()` is a filesystem walk; there is no DB lookup of
  `project_id → trusted_root`.

## Changes

### Change 1 — Explain why a passphrase is being requested

**Where:** [crates/locket-cli/src/runtime/key_access.rs](../../../crates/locket-cli/src/runtime/key_access.rs),
above each call to `passphrase_reader.new_passphrase()` (line 39) and
`passphrase_reader.existing_passphrase()` (line 83).

**Behavior:** Before invoking the passphrase reader, write a short
explanation to stderr (not stdout — this is operator-facing context, not
command output).

For `store_master_key_with_fallback` (the new-passphrase path):

```text
locket: OS keychain is unavailable; setting up a passphrase fallback for this project.
locket: you will need this passphrase to use this vault on this machine.
locket: save your recovery code separately when it is displayed.
```

For `load_fallback_master_key` (the existing-passphrase path):

```text
locket: OS keychain entry not found for this project; using the passphrase fallback.
locket: enter the passphrase you set when this project was first initialized on this machine.
```

The explanation must be **emitted only when the prompt is about to be
shown**, not earlier. Tests must continue to pass with stderr matched
exactly; existing test fixtures that capture stderr need updating to
include these lines.

**Out of scope:** changing why the fallback is reached. The prompt happens
exactly when it does today; we just explain it.

**Risk:** Tests that assert on stderr will fail until updated. No runtime
behavior change.

### Change 2 — `locket status` shows cwd and flags mismatch

**Where:** [crates/locket-cli/src/commands/project/status.rs](../../../crates/locket-cli/src/commands/project/status.rs),
in the print block around line 49–67.

**Behavior:** After `root:`, print one new field:

```text
cwd: <std::env::current_dir() canonical>
```

`cwd` is always shown, even when it equals `root`. Two reasons: a missing
field is hard to grep for in support transcripts, and an always-present
`cwd` line establishes a stable contract for scripts.

When `cwd != root`, append a hint as a separate line *only in the mismatch
case*:

```text
cwd_matches_root: no
cwd_hint: locket.toml resolved from a parent directory; commands act on the project at root:
```

When `cwd == root`, print `cwd_matches_root: yes` and no hint.

**Why this is correct:** `resolve_project()` walks up from cwd to find a
`locket.toml`. If the user is in a subdirectory of the project, `root` is
the project root and `cwd` is below it — that's normal, not an error. The
new line shows that walk transparently.

**Out of scope:** changing trust-root registration. This is display-only.

**Risk:** Tests that assert on `status` output verbatim will fail until
updated. The `cli_basics.rs` and `grants_agent_diag.rs` fixtures need new
lines.

### Change 3 — `locket init` runs device init and offers passkey

**Where:** [crates/locket-cli/src/commands/project/init.rs](../../../crates/locket-cli/src/commands/project/init.rs),
inside `complete_init` after `trust_root()` (around line 373) and before
the recovery-code display (line 377).

**Behavior:**

1. After the recovery envelope is created and the root is trusted, call
   into the existing `team::device::device_init_command` code path with
   default arguments (no `--force`, default device name from `HOSTNAME` or
   `"local-device"`). On failure, print a one-line warning to stderr and
   continue. Init must not fail because device creation failed; the vault
   is still usable via OS keychain + recovery code.

2. After successful device init, prompt:

   ```text
   Register a passkey for this device? [y/N]
   ```

   - Default `n`. Accept `y`, `Y`, `yes`. Anything else is a no-op.
   - On `y`, call into `vault::passkey::passkey_register_command` with a
     default label (`HOSTNAME` or `"primary"`) and the project's
     `webauthn_relying_party_id` from configuration (or
     `locket.localhost` if not set, matching current `passkey register`
     defaults).
   - On platform-passkey-unsupported, on user cancellation, or on any
     passkey-register error: print a one-line warning and continue. Init
     never fails because passkey registration failed.

3. New flags on `init`:
   - `--no-device` — skip device init entirely.
   - `--no-passkey` — skip the passkey prompt entirely.
   - `--register-passkey` — skip the prompt, register a passkey with
     defaults.
   - `--register-passkey` and `--no-passkey` conflict (clap
     `conflicts_with`).

4. Non-interactive mode (when `confirmation_reader` reports no TTY): treat
   as `--no-passkey`. Device init still runs by default, because it
   doesn't need user input beyond what already happens during normal
   init.

**Sequence after the change:**

```text
init:
  ensure_project_metadata()
  ensure_project_key_material()       # may prompt for new passphrase (Change 1 explains)
  ensure_initial_recovery_envelope()
  trust_root()
  [NEW] device init (unless --no-device)
  [NEW] passkey register (if --register-passkey, or interactive y)
  display_recovery_code()
  audit row
```

**Out of scope:** any change to `device_init_command` or
`passkey_register_command` themselves. Init *calls* them; their internals
are untouched.

**Risk:** Init now does more work and has more failure modes. The
"continue on subcommand failure with a warning" rule is what bounds the
blast radius — init's success criterion is unchanged (master key +
recovery envelope + trust). The init test in
`tests/init_template_device.rs` will need new cases for the device and
passkey paths.

### Change 4 — Better error from `passkey register` when no device exists

**Where:** [crates/locket-cli/src/commands/vault/passkey.rs:56-58](../../../crates/locket-cli/src/commands/vault/passkey.rs#L56-L58).

**Today:**

```text
locket: active local device required for passkey registration
```

**Change to:**

```text
locket: no active local device for this project. Run `locket device init` to create one,
or re-run `locket init` (which now sets one up automatically by default).
```

**Risk:** Trivial. Tests that assert on the exact error string need
updating.

## Test plan

- **passphrase explanation (Change 1):** unit-test
  `store_master_key_with_fallback` and `load_fallback_master_key` with a
  capturing stderr. Assert the new lines appear above the prompt.
- **status cwd field (Change 2):** test that `status` from project root
  prints `cwd_matches_root: yes`; test that `status` from a subdirectory
  prints `cwd_matches_root: no` with the hint line; test that the absence
  of `locket.toml` is unchanged behavior.
- **init device + passkey (Change 3):** test that default `init` creates
  a device row; test that `--no-device` does not; test that
  `--register-passkey` calls into the passkey registrar (with a stub
  registrar in tests) and writes a credential row; test that a failing
  device init does not fail the overall init; test that
  `--no-passkey` and `--register-passkey` conflict at clap parse time.
- **passkey register error (Change 4):** test that running passkey
  register with no device emits the new error string.

## Out of scope (explicit, do not creep)

- Auto-running `locket recover` when the master key is missing.
- Cleaning up stale passphrase envelopes from earlier failed inits.
- Surfacing `init_platform_keyring` failures (separate defensive
  hardening, separate spec if needed).
- Changing how `resolve_project` walks the filesystem.
- Adding `master_unlock_preference` modes.
- Touching the passkey-PRF crypto or the `passkey_prf_wraps` table.

## Risk summary

All four changes are additive UX/text changes plus mechanical wiring.
None touch crypto, schema, or storage. The biggest blast radius is
`init` gaining two new optional steps; that risk is bounded by the
"failure of a sub-step does not fail init" rule.
