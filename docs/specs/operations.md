# Diagnostics & Distribution

This file is part of the normative planned Locket implementation spec. Start at [index.md](index.md).

## Local Diagnostics

Diagnostics must help users and implementers debug without leaking secrets.

Commands:

```bash
locket doctor
locket agent logs [--lines N] [--since <timestamp>] [--follow]
locket debug bundle --redacted [--output <path>]
```

Behavior:

- `doctor` checks store integrity, schema compatibility, audit chain, agent status, keychain availability, permissions, hooks, trusted roots, profile availability, required secrets, and bundle readability where requested.
- `doctor` always runs locked-safe checks first: config parsing, project resolution, schema compatibility, SQLite integrity, file permissions, hook presence, trusted-root metadata, profile/policy metadata availability, agent status, keychain backend availability, and incomplete `runtime_sessions` reporting. Checks requiring unwrapped keys are skipped while locked with a metadata-only notice: audit HMAC verification, key unwrap/decryption probes, recovery-envelope decryptability, known-value scanner readiness, and cryptographic bundle decryptability. When the vault is unlocked or the user unlocks during `doctor`, those checks run. A locked invocation exits successfully only if all executed checks pass and skipped checks are reported as skipped, not passed.
- `doctor` exit codes are command-specific: `0` means every executed check passed and skipped checks, if any, were reported as skipped; `1` means one or more non-critical checks failed; `2` means one or more critical checks failed and Locket should not be used until resolved. Critical checks include schema incompatibility, SQLite integrity failure, audit-chain failure when checked, key unwrap/decryption failure when checked, unsafe file permissions on the store or agent endpoint, and trusted-root mismatch. A `DOCTOR` audit row is written when project context is available regardless of check results; metadata contains check names and pass/warn/fail/skip counts only.
- `doctor` reports incomplete `runtime_sessions` rows. It may offer to mark a session ended only after verifying the recorded `(pid, process_start_time)` is no longer live; automatic cleanup without that verification is forbidden because it would create misleading audit/session data. `doctor` also reports runtime-session rows whose `secret_names` retention window has expired and may offer to prune only that sensitive metadata field. Retention pruning must preserve the row, timing fields, process identity, policy name, exit status, and any audit linkage.
- `agent logs` prints redacted metadata-only logs from the local agent log file. Logs are JSON Lines by default, stored under the user-scoped Locket runtime/data directory with user-only permissions, rotated at 1 MiB per file with 5 retained files. Default output is the last 200 lines. `--lines N` changes the line count, capped at 10,000. `--since <timestamp>` accepts RFC 3339 UTC timestamps or Unix seconds and filters by log timestamp. `--follow` streams new log entries until interrupted. Log entries may include timestamps, severity, component, request id, action, project/profile ids, policy name, and typed error names; they must never include secret values, plaintext env maps, recovery codes, wrapped keys, grant tokens, private keys, full credential ids, raw local usernames, hostnames, or full filesystem paths. When a path is useful for diagnosis, logs store a path kind and a stable hash unless the user explicitly runs a foreground diagnostic command that prints the path.
- `debug bundle --redacted` creates a support artifact with configuration, versions, schema state, audit verification status, and redacted errors. It must not include secret values, wrapped keys, recovery material, grant tokens, device private keys, raw public keys, full credential ids, passkey `user_handle` fields, raw local usernames, hostnames, or full filesystem paths by default. Project/profile/secret/policy/member/device names are replaced with stable local aliases when `privacy.redact_names = true`. Output defaults to `locket-debug-<utc-timestamp>.tar.gz` under the user-scoped Locket diagnostics directory, not the project tree, to reduce accidental commits; `--output <path>` overrides the destination. The artifact is created with user-only permissions and must fail rather than overwrite an existing file; v1 has no overwrite flag for debug bundles.
- `debug bundle --redacted` does not require the vault to be unlocked and does not require the agent. If the agent is reachable, the bundle may include metadata-only agent status; if not, it records `AgentUnavailable` as diagnostic metadata.

## Distribution

Install targets:

- Homebrew formula for macOS and Linux.
- `cargo install` for Rust users.
- Signed macOS `.pkg`.
- Signed Windows `.msi`.
- Signed Linux `.deb` where practical.

Release integrity:

- Public release artifacts must be built by CI on hosted, isolated runners where practical, not from a maintainer laptop.
- Release artifacts must include cryptographic digests, signatures, SBOMs, and provenance attestations.
- Provenance verification must follow the SLSA v1.2 verification shape: check the artifact digest, provenance signature, builder identity, source repository, workflow/build type, and expected build parameters before publication.
- Public artifacts should target SLSA Build L3 where the selected hosted build platform can provide isolated build environments and unforgeable provenance. If release infrastructure starts below Build L3, the gap must be documented before public release.
- Package-manager submissions must be generated from the same signed release artifacts or from verifiable source tags.

Update policy:

- Update checks are opt-in.
- No silent updates.
- Update checks fetch a signed manifest from a configured HTTPS URL. The default manifest URL is controlled by the project maintainers and may be disabled entirely.
- Update checks must be privacy-preserving: no project id, profile id, secret names, policy names, device identifiers, member identifiers, local paths, hostnames, usernames, install id, or persistent tracking token is sent. The request should be a static manifest fetch keyed only by update channel, platform, architecture, and current app version where needed for compatibility.
- Update manifests must be signed by an offline release key whose public verification key is pinned in the binary. Release-key rotation requires a manifest signed by both the old and new keys or a full binary update through the platform package manager.
- No npm wrapper as a primary distribution path; it muddies the security story and encourages install-time indirection.
- VS Code extension distribution uses a signed VSIX direct download; marketplace listing is optional.
