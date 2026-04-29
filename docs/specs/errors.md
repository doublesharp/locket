# Errors & Failure Modes

This file is part of the normative planned Locket implementation spec. Start at [index.md](index.md).

## Failure Modes

Exit-code ranges:

- `locket doctor` is the only command-specific exception: it returns `0` for no failed executed checks, `1` for non-critical check failures, and `2` for critical check failures as defined in [operations.md](operations.md). It never returns codes in the `64-119` range for check failures.
- `64-69`: input, config, and reference validation.
- `70-79`: authorization, trust, and secret access gates.
- `80-89`: agent and automation-client failures.
- `90-99`: storage, schema, concurrency, and integrity failures.
- `100-109`: keychain and recovery failures.
- `110-119`: team, device, and sealed-bundle failures.

| Category | Failure | Behavior | Exit code | Recovery action |
| --- | --- | --- | --- | --- |
| Input/config/reference | Invalid `lk://` reference | Fail the command or scan with a typed reference error | 64 | Fix the reference syntax or profile/key/version |
| Input/config/reference | Git worktree required | `locket scan --staged` is not running inside a Git worktree and fails with `ConfigError` | 64 | Run inside a Git worktree or scan an explicit path instead |
| Input/config/reference | Policy not found | Referenced command policy or automation-client policy binding is missing | 64 | Add the policy or choose an existing client/policy reference |
| Input/config/reference | Policy validation incomplete | `policy doctor` could not validate agent-required references | 65 | Start or unlock the agent and rerun `locket policy doctor` |
| Input/config/reference | Environment conflict | Refuse spawn when `override = "error"` detects a name conflict | 66 | Change policy to `locket`, `preserve`, or rename the conflicting variable |
| Input/config/reference | Interactive TTY required | Refuse flows that require no-echo input or typed confirmation when no interactive terminal is available | 68 | Retry from an interactive terminal or use a non-interactive flow explicitly allowed by policy |
| Authorization/trust/access | Access denied | Refuse action because policy explicitly denies it | 70 | Update policy or request an appropriate team role/profile grant |
| Authorization/trust/access | Project root untrusted | Refuse secret access for that root | 71 | Run `locket project trust-root` from the intended project path |
| Authorization/trust/access | Unlock required | Refuse action until vault is unlocked | 72 | Run `locket unlock` or use an approved agent grant |
| Authorization/trust/access | Grant required | Refuse action because no live grant covers it | 73 | Run `locket allow`, refresh shell/editor grant, or use an explicit command policy |
| Authorization/trust/access | Local user verification failed | Refuse protected action without downgrading silently | 74 | Retry platform or hardware-key verification, or use an explicitly configured recovery path |
| Authorization/trust/access | Deprecated secret version expired | Refuse pinned `lk://...@vN` resolution, reveal/copy, and execution use of that version; exclude it from default known-value scan matching | 75 | Update the reference to the current version, rotate again with an intentional grace window, or remove the stale reference |
| Authorization/trust/access | Secret source deleted | Refuse `set`, `rotate`, `copy`, reveal/copy, and execution against a tombstoned `(profile, key, source)` | 76 | Use a different name or source, restore from backup, or wait for an explicit future restore flow; v1 does not silently reactivate tombstones |
| Agent/automation | Agent unavailable | Commands requiring long-lived grants or `lk://` resolution fail closed; direct one-shot commands may use direct unlock when policy permits | 80 | Run `locket agent start` or retry through `locket run` |
| Agent/automation | Agent socket in use | Verify peer/process identity; refuse if not the active trusted agent | 81 | Stop stale agent or use direct CLI mode |
| Agent/automation | Automation client not trusted | Refuse signed client request | 82 | Register the client, fix its policy scope, or rotate/revoke the client key |
| Agent/automation | Automation client replay detected | Refuse signed client request and leave prior authorization unchanged | 83 | Check client clock skew, rotate the client key if replay is suspected, and retry with a fresh nonce |
| Storage/schema/integrity | Corrupt DB | Refuse reads/writes that require corrupt data | 90 | Restore from backup or sealed bundle; run integrity diagnostics before reuse |
| Storage/schema/integrity | Two Locket processes writing | One writer proceeds; the other waits or returns typed storage busy error | 91 | Retry after first command exits |
| Storage/schema/integrity | Schema newer than binary | Fail closed before opening mutable store | 92 | Upgrade Locket binary |
| Storage/schema/integrity | Audit chain broken | Refuse to append success verification row and report first break | 93 | Investigate store tampering or restore from backup |
| Storage/schema/integrity | Secret version overflow | Refuse to advance a secret version counter that cannot be represented | 90 | Inspect store metadata for corruption before retrying |
| Keychain/recovery | Keychain unavailable | Fail closed unless passphrase fallback is configured | 100 | Unlock with passphrase fallback or run `locket recover` |
| Keychain/recovery | Lost recovery code | Cannot recover a future lost keychain entry or local device private key from this device alone | 101 | Generate a new recovery envelope while the vault is still unlocked, restore from an already trusted device, or request a fresh team invite |
| Keychain/recovery | Lost keychain entry | Vault remains encrypted but is recoverable if the recovery code and envelope are present | 102 | Run `locket recover` |
| Keychain/recovery | Lost recovery code AND lost keychain entry | Vault is unrecoverable on this device | 103 | Reinitialize the project; restore from another trusted device or a fresh team invite if available |
| Team/device/sync | Bundle verification failed | Malformed sealed bundle, invalid digest/authentication, or unsupported bundle structure fails verification with `BundleVerificationFailed`; bundles that are structurally valid but not decryptable by this device exit `0` with a notice | 110 | Recreate the bundle, request a new export, or verify on an addressed device |
| Team/device/sync | Invite expired | Refuse import | 111 | Ask a maintainer for a fresh sealed invite |
| Team/device/sync | Team bundle conflict | Show metadata-only conflict summary and refuse destructive overwrite by default | 112 | Choose keep-local, import-newer, or manual rotation |
| Team/device/sync | Device revoked | Refuse team import, export, reveal, and grant actions for that device | 113 | Add a new trusted device or rotate affected secrets |

Exit codes must be centralized in `locket-core`, kept stable after release, and stay below `126` so they do not collide with common shell command-not-found, permission, or signal conventions.

Error boundaries:

- `UnlockRequired`: vault or required key is locked and no unlock material is available.
- `GrantRequired`: vault is available, but the caller lacks a live TTL grant for this action/context.
- `AccessDenied`: policy, role, profile, dangerous-profile rules, or command scope explicitly deny the action.
- `SecretVersionExpired`: a pinned reference targets a deprecated version without an active grace window; the current unpinned secret may still be valid.
- `SecretDeleted`: the selected `(profile, key, source)` is tombstoned. v1 preserves tombstones and requires a different name/source or explicit future restore flow.
