# Secret-name error reasons & per-command master-key cache

Date: 2026-05-01
Status: design — not yet implemented

## Problem

Two independent CLI papercuts:

1. **Opaque secret-name validation error.** `locket set foo` exits with `locket: invalid secret name` and gives the user no hint why. Names must match `^[A-Z_][A-Z0-9_]*$` (env-var-compatible), but the error string carries no reason — a user has to find the validation rule in `crates/locket-core/src/identity/secret_name.rs:10` to understand what went wrong.

2. **Repeated passphrase prompts within one command.** Running `locket set FOO` against a vault using the passphrase fallback (no OS key store entry) prompts for the master passphrase three times in a single command. Each `load_master_key` call independently invokes `passphrase_reader.existing_passphrase()` because there's no in-process memoization. The `locket-agent` crate caches across commands, but inside one CLI invocation every key-loading helper re-unlocks from scratch.

   `locket set` walks this path:
   - `set_secret_value_in_profile` → `load_project_key(Audit)` (1st unlock)
   - `encrypt_secret_version` → `load_profile_key(ProfileSecret)` (2nd unlock)
   - `encrypt_secret_version` → `load_profile_key(ProfileFingerprint)` (3rd unlock)
   - `refresh_example_for_project_if_enabled` → `load_project_key(Audit)` (4th unlock)

   With the OS key store populated this is invisible (each load is a fast keychain read); with passphrase fallback active it's three or four interactive prompts per command.

## Goals

- Validation errors tell the user **why** a name was rejected.
- A single CLI invocation prompts for the passphrase **at most once**, regardless of how many key-loading calls the command path makes.
- No change to the wire-protocol error code (`InvalidSecretName`) or to security properties (master key still held only in `Zeroizing` memory, dropped at command exit).

## Non-goals

- Cross-command caching (that's the agent's job).
- Auto-starting the agent.
- Changing the secret-name regex.
- Refactoring `set` / `rotate` / `import` to thread keys explicitly through their call chains (Option B in brainstorming — rejected as larger scope without commensurate user benefit).

## Design

### Part 1 — Secret-name error reasons

Convert `InvalidSecretName` from a unit struct into an enum that carries the failure reason, while keeping the wire-stable prefix `invalid secret name` so existing error-string assertions and the `LocketError::InvalidSecretName` typed code keep working.

**`crates/locket-core/src/identity/secret_name.rs`:**

```rust
#[derive(Debug, Clone, Eq, Error, PartialEq)]
pub enum InvalidSecretName {
    #[error("invalid secret name: empty")]
    Empty,
    #[error("invalid secret name: must start with A-Z or '_', got {0:?}")]
    InvalidStartChar(char),
    #[error("invalid secret name: contains invalid character {0:?} (only A-Z, 0-9, '_' allowed)")]
    InvalidChar(char),
}
```

`validate_secret_name` already distinguishes the three cases internally; it just discards the detail. Update it to return the appropriate variant.

The Display prefix `invalid secret name` is preserved verbatim, so:
- `LocketError::InvalidSecretName` → `"invalid secret name"` mapping in `crates/locket-core/src/error.rs:713` is unchanged (that's the typed code's *canonical* string, not derived from `InvalidSecretName`'s Display).
- Existing tests that `assert!(error.to_string().contains("invalid secret name"))` still pass.
- Existing `assert_eq!(error.to_string(), "invalid secret name")` in `crates/locket-cli/src/tests/cli_errors.rs:300` will need updating to use the new prefix-carrying message — that test asserts the helper-built error, not `InvalidSecretName` itself, so the update is to the literal string.

**Call-site updates.** Eight sites currently do:

```rust
SecretName::new(...).map_err(|_| invalid_secret_name_error("invalid secret name"))
```

Change each to forward the reason:

```rust
SecretName::new(...).map_err(|err| invalid_secret_name_error(err.to_string()))
```

Sites (from `grep "invalid secret name"`):
- `crates/locket-cli/src/main.rs:1560,1573,1716`
- `crates/locket-cli/src/support/secret_helpers.rs:165,240`
- `crates/locket-cli/src/commands/secrets/set.rs:46,125`
- `crates/locket-cli/src/commands/secrets/import.rs:275`
- `crates/locket-cli/src/commands/secrets/lifecycle.rs:254`
- `crates/locket-cli/src/commands/policy.rs:893` (already formats `invalid secret name: {key}`; update to also include reason)

`crates/locket-agent/src/handlers/{reveal,set_secret}.rs` use the literal `"invalid secret name"` for protocol errors. Leave them unchanged — the agent IPC contract should keep the canonical typed-code string, and the agent isn't the surface where users see opaque messages.

### Part 2 — Per-command master-key cache

Add an in-process cache on `RuntimeContext`. Keyed by `project_id` (a single CLI invocation can in principle touch multiple projects, e.g. via `lk://` references — keying by project keeps the cache correct).

**`crates/locket-cli/src/runtime/`** (location TBD by writing-plans — likely `key_access.rs` or a new sibling):

```rust
pub struct MasterKeyCache {
    entries: RefCell<HashMap<String, (Zeroizing<KeyBytes>, MasterKeySource)>>,
}

impl MasterKeyCache {
    pub fn new() -> Self { ... }
    pub fn get(&self, project_id: &str) -> Option<(Zeroizing<KeyBytes>, MasterKeySource)>;
    pub fn insert(&self, project_id: &str, key: Zeroizing<KeyBytes>, source: MasterKeySource);
}
```

`Zeroizing<KeyBytes>` is `Clone` (clones the inner array; the new `Zeroizing` wrapper takes ownership of zeroizing the clone), so `get` returning a fresh `Zeroizing` clone is safe and matches the current API of `load_master_key`.

Add a field to `RuntimeContext`:

```rust
pub master_key_cache: MasterKeyCache,
```

Modify `load_master_key` in `crates/locket-cli/src/runtime/key_access.rs:51`:

```rust
pub fn load_master_key(
    context: &RuntimeContext,
    project_id: &str,
) -> Result<(Zeroizing<KeyBytes>, MasterKeySource), CliError> {
    if let Some(cached) = context.master_key_cache.get(project_id) {
        return Ok(cached);
    }
    let (key, source) = load_master_key_uncached(context, project_id)?;
    context.master_key_cache.insert(project_id, key.clone(), source);
    Ok((key, source))
}
```

Where `load_master_key_uncached` is the current `load_master_key` body.

Same treatment for `load_fallback_master_key` if it can be reached without going through `load_master_key` first — audit shows it's also called from `load_master_key_verified_by_project_key` and `load_project_key_with_source`. The cleanest fix: route every passphrase-prompting path through the cache. Concretely, also cache inside `load_fallback_master_key`, OR (better) restructure so the cache is consulted before `load_fallback_master_key` is ever invoked. Implementation plan to pick the exact wiring.

**Thread-safety.** CLI is single-threaded; `RefCell` is fine. If a future caller wants `Send` (e.g., an in-process test harness running commands in parallel threads), upgrade to `Mutex`. Don't pre-emptively use `Mutex` — YAGNI.

**Lifetime / security.** The cache lives on `RuntimeContext`, which is constructed per CLI invocation and dropped on exit. `Zeroizing<KeyBytes>` ensures the key bytes are wiped on drop. The cache extends the in-memory window of the master key from "duration of a single key-load" to "duration of one command" — already the implicit reality, since the key sits in stack frames during `set` between the four loads. No new exposure.

### Testing

**Part 1.** Unit tests in `secret_name.rs`:
- Empty input → `Empty`
- Lowercase first char → `InvalidStartChar('f')`
- Digit first char → `InvalidStartChar('1')`
- Invalid mid-name char → `InvalidChar(...)` for each of `-`, `.`, ` `, lowercase, etc.

A CLI integration test asserting `locket set foo` exit message contains both `invalid secret name` and `must start with A-Z or '_', got 'f'`.

**Part 2.** Unit test on `MasterKeyCache`: insert + get returns the same bytes; second `load_master_key` for the same `project_id` does not invoke the underlying `key_store.load_master_key`. Use a mock `key_store` that increments a counter; assert counter == 1 after two `load_master_key` calls.

A CLI integration test for `set` against a passphrase-fallback vault: a stub `PassphraseReader` that counts invocations; assert it's called exactly once across a complete `locket set FOO` invocation.

### Open question

Whether to also memoize the **derived project / profile keys** (the four loads in `set` derive *different* keys from the same master). That would eliminate the redundant HKDF derivations as well as the redundant master-key loads. Not necessary for the user-facing fix (HKDF is microseconds, doesn't prompt), so deferred unless writing-plans surfaces a reason to include it.

## Risks & mitigations

- **Risk:** Test expects exact `"invalid secret name"` Display string — `crates/locket-cli/src/tests/cli_errors.rs:300`. **Mitigation:** Update assertion to either accept the new format or assert the prefix.
- **Risk:** `KeyBytes` Clone behavior must zeroize. **Mitigation:** Verify `KeyBytes` is `[u8; KEY_LEN]` (a Copy array) wrapped in `Zeroizing` — cloning `Zeroizing<[u8; N]>` produces a new `Zeroizing` that drops via zeroize. Confirmed in `locket_crypto`.
- **Risk:** Multi-project commands silently use stale cached master after a project switch mid-command. **Mitigation:** Cache is keyed by `project_id`, so different projects get different entries.

## Success criteria

- `locket set foo` prints something like `locket: invalid secret name: must start with A-Z or '_', got 'f'`.
- `locket set FOO` against a passphrase-fallback vault prompts for the passphrase exactly once.
- All existing tests pass; the typed `LocketError::InvalidSecretName` exit code (64) and protocol string are unchanged.
