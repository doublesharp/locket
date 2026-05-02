# Passkey Unlock Factor — Design

## Goal

Allow Locket users to unlock the project master key with a WebAuthn PRF-capable
passkey as an additional unlock factor, alongside the existing OS keychain and
Argon2id passphrase fallback. The recovery code remains the sole mandatory
recovery secret.

## Non-goals

- Replacing or weakening the recovery code model. Recovery code support remains
  mandatory per [docs/specs/crypto.md:154-160](../../specs/crypto.md).
- Replacing presence-gate passkeys. The existing `vault passkey` flow for
  reveal/copy/dangerous-profile-switch approvals is untouched.
- Supporting authenticators that do not expose WebAuthn PRF / hmac-secret.
  Registration fails closed when PRF is unavailable.
- Browser-style WebAuthn ceremonies for ordinary unlock. PRF extraction uses
  platform CTAP2/PRF surfaces, consistent with [crypto.md:179-180](../../specs/crypto.md).

## Background

Today the master key has two unlock paths and one recovery path
([key_access.rs:30-90](../../../crates/locket-cli/src/runtime/key_access.rs)):

1. OS key store (Keychain / Credential Manager / Secret Service) — default.
2. Argon2id passphrase fallback — when OS key store is unavailable.
3. Recovery code — restores both above from `recovery/envelope.bin`.

The crypto spec already permits WebAuthn PRF / hmac-secret as an optional
key-wrapping factor ([crypto.md:180,208,215](../../specs/crypto.md)). This design
implements that permitted path as a first-class unlock factor.

## User-visible behavior

### Registration

- Offered interactively at `locket init`: "Register a passkey for unlock?"
  Decline is a no-op.
- Available post-init: `locket vault passkey-unlock add [--label NAME]`.
- Authenticators lacking PRF cause registration to fail closed with
  `PasskeyUnlockPrfUnsupported`. No silent downgrade to a non-PRF wrap.

### Preference modes

A new project-level preference, `master_unlock_preference`:

| Value             | Behavior                                                                                        |
| ----------------- | ----------------------------------------------------------------------------------------------- |
| `keychain` (default) | OS keychain first; passkey only on explicit `--passkey` or keychain failure. Passphrase fallback unchanged. |
| `passkey`         | Passkey first; silently falls back to keychain → passphrase if no PRF authenticator present.    |
| `strict-passkey`  | Passkey required. Keychain alone is not sufficient. Recovery code still works.                  |

Set with `locket vault passkey-unlock prefer keychain|passkey|strict`.

### Unlock command surface

- `locket unlock` honors preference; one-shot overrides via `--passkey` /
  `--no-passkey`.
- All sensitive ops route through the same `load_master_key` path, so the
  preference applies uniformly.

### Removal

`locket vault passkey-unlock remove <credential-id>` rules:

- `strict-passkey` mode + last credential: refuse with
  `PasskeyUnlockLastInStrictMode`. User must downgrade preference or register
  another authenticator first.
- `keychain` or `passkey` mode + last credential: print warning, require
  `--yes` or interactive confirmation.
- Otherwise: remove with no special prompt.

## Crypto

### Wrap key derivation

```text
prf_output = WebAuthn-PRF(credential, eval = "locket-passkey-unlock-v1")
wrap_key   = HKDF-SHA256(
                ikm  = prf_output,
                salt = master_key_wraps.row_salt (32 random bytes),
                info = "locket-passkey-unlock-wrap-v1"
                       || field("credential_id", credential_id)
                       || field("project_id", project_id)
             )
```

`field(name, value)` uses the length-prefixed UTF-8 encoding from canonical
AAD v1 ([crypto.md:134-137](../../specs/crypto.md)).

The PRF output is never used directly as a wrap key. HKDF binds the wrap to a
per-row salt and credential id so that:

- The same authenticator registered against two projects produces independent
  wrap keys.
- A stolen `wrap_ciphertext` cannot be replayed against a different row even
  given the PRF output.

### Wrap layout

Reuses `key_wrap_v1` from [crypto.md:86-105](../../specs/crypto.md):

```text
master_key_wraps.wrap_ciphertext = XChaCha20-Poly1305(
  key       = wrap_key,
  nonce     = master_key_wraps.nonce (24 random bytes),
  plaintext = master_key,
  aad       = key_wrap_aad_v1 with:
                project_id = <project>
                key_id     = <credential_id_hex>
                profile_id = ""
                version    = 0
                purpose    = "master-key-passkey-wrap"
)
```

`key_id` uses the lowercase hex encoding of the raw credential id bytes for
canonical AAD encoding.

### Invariants

- Master key value is unchanged by registration; passkey-unlock is an
  additional wrap of the existing master key.
- AAD schema v1 is unchanged. `key_wrap_v1` is unchanged.
- PRF unavailable at any point → fail closed with a typed error, never a
  silent fallback to a non-PRF wrap.

## Data model

New table `master_key_wraps`:

| Column                  | Type                | Notes                                                       |
| ----------------------- | ------------------- | ----------------------------------------------------------- |
| `id`                    | TEXT PRIMARY KEY    | `lk_mkw_*` opaque id                                        |
| `project_id`            | TEXT NOT NULL       | foreign key to project row                                  |
| `credential_id`         | BLOB NOT NULL       | raw WebAuthn credential id                                  |
| `relying_party_id`      | TEXT NOT NULL       | RP id at registration; mismatch on unlock fails closed      |
| `authenticator_aaguid`  | BLOB NULL           | for display + sync-eligibility surfacing                    |
| `prf_eval_salt`         | BLOB NOT NULL       | `b"locket-passkey-unlock-v1"` for v1; stored for forward-compat |
| `row_salt`              | BLOB NOT NULL       | 32 random bytes, HKDF salt                                  |
| `nonce`                 | BLOB NOT NULL       | 24 random bytes, AEAD nonce                                 |
| `wrap_ciphertext`       | BLOB NOT NULL       | XChaCha20-Poly1305 ciphertext + tag                         |
| `wrap_schema_version`   | INTEGER NOT NULL    | `1` for v1                                                  |
| `label`                 | TEXT NULL           | user-supplied display name                                  |
| `created_at`            | INTEGER NOT NULL    | unix nanos UTC                                              |
| `last_used_at`          | INTEGER NULL        | unix nanos UTC, updated on successful unwrap                |

Indexes:

- UNIQUE (`project_id`, `credential_id`).
- Index (`project_id`) for list queries.

Why a dedicated table rather than overloading the existing `keys` table: the
existing `keys` table holds project-scoped and profile-scoped keys derived
under the master. A passkey-unlock wrap is a parallel wrap of the master key
itself under a different root and belongs at a different layer.

The project preference is added to the existing project config storage as a
new column `master_unlock_preference` with a CHECK constraint over the three
valid values. Default `'keychain'` for existing rows.

## Components and boundaries

### `locket-crypto::passkey_unlock` (new module)

Pure crypto. No platform calls, no DB, no I/O.

```rust
pub fn derive_wrap_key(
    prf_output: &[u8; 32],
    row_salt: &[u8; 32],
    credential_id: &[u8],
    project_id: &ProjectId,
) -> KeyBytes;

pub fn wrap_master_key(
    wrap_key: &KeyBytes,
    master_key: &KeyBytes,
    nonce: &[u8; 24],
    project_id: &ProjectId,
    credential_id: &[u8],
) -> Vec<u8>; // ciphertext

pub fn unwrap_master_key(
    wrap_key: &KeyBytes,
    nonce: &[u8; 24],
    ciphertext: &[u8],
    project_id: &ProjectId,
    credential_id: &[u8],
) -> Result<KeyBytes, KeyWrapError>;
```

Unit-testable with synthetic PRF outputs.

### `locket-platform::passkey_prf` (new module)

Platform-trait providing PRF evaluation. Per-OS impls (macOS, Windows, Linux)
plus a test stub.

```rust
pub trait PasskeyPrfProvider: Send + Sync {
    fn probe_supported(&self, options: PrfProbeOptions) -> Result<PrfProbeResult, PasskeyPrfError>;
    fn evaluate(
        &self,
        credential_id: &[u8],
        relying_party_id: &str,
        eval_salt: &[u8],
    ) -> Result<[u8; 32], PasskeyPrfError>;
}
```

`probe_supported` is invoked at registration to confirm PRF support before
writing any row. Returns `PasskeyPrfError::PrfUnsupported` when the
authenticator cannot return PRF output.

### `locket-cli::runtime::key_access::passkey` (new submodule)

Orchestration. Loads `master_key_wraps` rows, calls platform PRF, derives the
wrap key, unwraps the master key, and inserts into the existing
`master_key_cache`.

`MasterKeySource` enum gains `PasskeyUnlock { credential_id: Vec<u8> }`.

### `runtime::key_access::load_master_key` extension

```text
match master_unlock_preference:
  keychain:
    1. try OS keychain
    2. on failure, try passphrase fallback if present
    3. (passkey only attempted via explicit --passkey flag elsewhere)
  passkey:
    1. try passkey-unlock (silently skip if no PRF authenticator present)
    2. fall through to keychain, then passphrase fallback
  strict-passkey:
    1. try passkey-unlock
    2. on failure, surface PasskeyUnlock* error; do NOT fall through
```

`should_try_passphrase_fallback` is extended so passkey-unlock failure in
non-strict modes falls through cleanly to the existing keychain → passphrase
chain. Strict mode never falls through to keychain or passphrase.

### `locket-cli::commands::vault::passkey_unlock` (new file)

New subcommands; kept distinct from the existing `vault::passkey` module which
covers presence-gate passkeys. Shared helpers extracted to a small
`vault::passkey::common` module if real duplication emerges; do not pre-extract.

## CLI surface

```text
locket vault passkey-unlock add [--label NAME]
locket vault passkey-unlock list
locket vault passkey-unlock remove <credential-id> [--yes]
locket vault passkey-unlock prefer keychain | passkey | strict

locket unlock [--passkey | --no-passkey]
```

`locket init` gains a single yes/no prompt: "Register a passkey for unlock?"
Decline is a no-op; accept runs the same code path as `passkey-unlock add`.

`list` columns: credential id (truncated), label, AAGUID display string when
known, RP id, created at, last used at, sync-eligibility note when the
authenticator surface exposes it.

## Error handling

New typed errors in `locket-cli::runtime::error`:

| Error                              | Trigger                                                | Behavior     |
| ---------------------------------- | ------------------------------------------------------ | ------------ |
| `PasskeyUnlockPrfUnsupported`      | authenticator lacks PRF at registration                | fail closed  |
| `PasskeyUnlockCredentialNotPresent`| authenticator not connected / user cancelled prompt    | fail closed  |
| `PasskeyUnlockRpIdMismatch`        | stored `relying_party_id` ≠ runtime RP id              | fail closed  |
| `PasskeyUnlockLastInStrictMode`    | `remove` would delete last credential in strict mode   | fail closed  |
| `PasskeyUnlockNoneRegistered`      | strict mode but `master_key_wraps` is empty            | fail closed  |
| `PasskeyUnlockUnwrapFailed`        | AEAD verification failed (tamper / wrong row)          | fail closed  |

All errors fail closed. None silently cross security boundaries.

## Audit

Each of the following writes an audit row when project context is available,
per [crypto.md:184](../../specs/crypto.md):

- `passkey-unlock add` (success, failure)
- `passkey-unlock remove` (success)
- `passkey-unlock prefer` (preference change)
- `unlock` via passkey (success, failure)

Audit row fields: action, credential_id (truncated for display), preference
at time of action, success/failure, error code on failure.

`last_used_at` is updated on successful unwrap and is written outside the
audit HMAC chain, matching existing `last_used_at` patterns elsewhere in the
codebase.

## Recovery interaction

- `locket recovery rotate` does **not** touch `master_key_wraps`. The recovery
  code wraps the master key inside the recovery envelope; passkey-unlock wraps
  are an independent parallel wrap of the same master key under a PRF-derived
  root. Rotating one does not invalidate the other, and re-wrapping passkey
  entries during rotation would require physically tapping every registered
  authenticator with no security payoff.
- `locket recover` (restore from recovery code) preserves `master_key_wraps`
  rows as-is because they wrap the same master key value. If the user's
  authenticators are also lost, they re-register via `passkey-unlock add` after
  recovery.
- Strict-mode lockout safety: during `recover`, if
  `master_unlock_preference == 'strict-passkey'` and no `master_key_wraps` row
  can be unwrapped (authenticators also lost), preference is auto-downgraded to
  `'keychain'` with an audit row and a printed notice. Without this, recovery
  would restore a vault the user cannot open.

## Testing

Crypto layer (`locket-crypto::passkey_unlock`):

- Round-trip wrap/unwrap with synthetic PRF outputs.
- AAD tampering: every field in `key_wrap_aad_v1` causes unwrap failure.
- Row-salt independence: same PRF output, different `row_salt` → different
  ciphertexts that cannot be cross-decrypted.
- Cross-project replay: same PRF, same credential, different `project_id` →
  unwrap fails.

Runtime layer (`runtime::key_access`):

- Matrix: each preference mode × (keychain available / unavailable) ×
  (passkey available / unavailable / PRF-unsupported). Stub PRF backend.
- Strict mode never falls through to keychain or passphrase.
- Cache: a successful passkey unwrap populates `master_key_cache` with source
  `PasskeyUnlock` and is reused on the next call within cache lifetime.

CLI:

- `passkey-unlock add` happy path and PRF-unsupported failure.
- `passkey-unlock list` formatting.
- `passkey-unlock remove`: last-in-strict blocked; last-in-non-strict requires
  `--yes`; non-last removes silently.
- `passkey-unlock prefer` writes preference; subsequent `unlock` honors it.
- `init` accept/decline both leave the vault in a working state.

Recovery:

- Post-recover with stale `master_key_wraps` rows: master key recovered →
  passkey unwrap still succeeds (because master key value is unchanged).
- Strict-mode auto-downgrade fires when no wraps can be unwrapped post-recover.

Existing `config_passkey_lock` test must remain green; the presence-gate
passkey feature is independent.

## Risks and mitigations

| Risk                                                                                         | Mitigation                                                                                          |
| -------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| User loses all authenticators in strict mode                                                 | Recovery code still works; strict-mode auto-downgrades on `recover` if no wraps unwrap.             |
| Synced passkey on another device unexpectedly grants unlock                                  | `list` surfaces sync-eligibility (per [crypto.md:217](../../specs/crypto.md)); user can choose to remove and re-register a non-syncable credential. |
| PRF availability varies by platform / authenticator                                          | Probe at registration and fail closed; never silently downgrade.                                    |
| Stolen DB + stolen authenticator                                                             | Same threat model as stolen DB + stolen OS keychain access; recovery code rotation is the response. |
| RP id silently changes between registration and unlock                                       | Stored `relying_party_id` is checked; mismatch fails closed with `PasskeyUnlockRpIdMismatch`.       |

## Out of scope for v1

- Multi-project shared passkey-unlock (each project keeps its own
  `master_key_wraps` rows).
- Importing pre-registered authenticators across devices via team-sync (would
  require sealing PRF credentials, which is not possible).
- UI surface in `locket-app` (Tauri). v1 ships CLI-only; the Tauri app picks up
  the same `runtime::key_access` path automatically when it lands.
