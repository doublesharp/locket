# Invariants & Threat Model

This file is part of the normative planned Locket implementation spec. Start at [index.md](index.md).

## Invariants & Decisions

These rules apply across the CLI, local agent, shell hooks, VS Code extension, desktop UI, tray, scanner, import flow, backup flow, and runtime execution.

1. Secrets must not exist in plaintext on disk.
2. Secrets may be decrypted in memory only for child-process delivery, controlled scanning, backup/recovery operations, or explicitly gated reveal/copy flows.
3. Secrets must never be globally exported.
4. Access must be explicitly scoped to a project, profile, directory, command, process, shell grant, editor session, or reveal/copy grant.
5. Default behavior must be deny-all.
6. `.env` files must not be required or treated as source of truth.
7. Secret values must never be logged.
8. CLI, UI, tray, shell, editor, and agent behavior must be backed by the same core policy APIs.
9. Any reveal, copy, import, execution, deletion, rotation, recovery, sync import/export, grant, denied access, or scan event that touches sensitive state must be auditable when project context is available.
10. If a convenience feature conflicts with these rules, the security rule wins.

Non-negotiable product decisions:

- `locket get <KEY>` does not print the secret by default. Plain `get` returns metadata only. Secret value access requires `--reveal` or `--copy`, an unlock check, and an audit event.
- `locket exec --all` is a risky escape hatch, not the normal workflow. Prefer `locket run <policy>`, `lk://` references resolved by the agent, or repeated `--secret KEY`.
- Raw `sha256(secret_value)` fingerprints are forbidden. Use profile-scoped HMAC-SHA256 fingerprints and decrypt known values only in memory for exact-match scanning.
- `locket.toml` contains the stable `project_id`. Trusted root hashes protect against copied or moved project files silently accessing an existing local vault.
- The desktop UI and VS Code extension are administration and status surfaces, not secret browsing apps.
- The local agent is part of the core developer experience. Without it, repeated keychain prompts and Argon2 runs make shell/editor workflows poor.

## Threat Model

Locket protects against accidental plaintext persistence, overly broad process environments, leaked logs, committed `.env` files, casual local inspection, editor/workspace state leaks, copied AI prompt context, and accidental secret delivery to the wrong local process.

Locket does not promise protection against a fully compromised user account, malicious kernel, memory scraping malware, debugger access to a granted child process, screen capture during reveal, or a child process that intentionally exfiltrates secrets it was allowed to receive.

Secret names and descriptive fields are metadata. Names, descriptions, owners, tags, sources, profile names, policy names, version numbers, states, and timestamps may appear in list, history, diff, audit rows, `.env.example`, editor completions, policy files, and debug bundles. Locket protects secret values cryptographically; it does not try to hide the existence or metadata of configured secrets from local users who can inspect project metadata.

Metadata still deserves minimization. User-facing metadata fields must be treated as non-secret but potentially sensitive: they should be validated, redacted from support artifacts where possible, and never sent to a remote service by default. Locket must provide a privacy display mode that replaces project, profile, policy, device, member, and secret names with stable local aliases on status surfaces such as tray, shell prompt, VS Code status, `locket context`, redaction labels, and debug bundles. Privacy aliases are deterministic display labels of the form `<kind>-<hash8>`, where `hash8` is the first 8 lowercase hex characters of `SHA-256("locket-privacy-alias-v1" || field("kind", kind) || field("id", opaque_id_or_canonical_name))`. Aliases are for display only and do not grant anonymity against someone with the local store. Privacy display mode does not change audit rows, encrypted store contents, policy evaluation, or `.env.example`, because those surfaces rely on exact names for local correctness.

The policy model should be honest about this boundary: Locket controls which secrets are granted and where plaintext is persisted. It cannot make an untrusted process safe after granting it a secret.

## Fixed Implementation Decisions

- Recovery codes use exactly 160 random bits encoded as 32 Crockford Base32 data characters plus 2 checksum characters, grouped for paper entry, protecting a sealed master-key and local-device-key wrap.
- `locket get --reveal` requires a TTY unless `--force` is provided; `--force` is audited.
- Scanner token patterns include common formats for OpenAI, Anthropic, GitHub, npm, AWS access keys, Stripe, Slack, Discord, Google API keys, private keys, generic bearer tokens, database URLs, and high-entropy fallback detection.
- Dangerous profiles require typed confirmation of the profile name for `--all`, shell grants, tray reveal/copy, and command policies marked `confirm = true`.
- Switching the active profile to a dangerous profile requires typed confirmation of the profile name on every surface.
- Team invites expire after 7 days by default, may use `--expires-in` within the configured bounds, and can be explicitly revoked before acceptance. Revocation is local-first: it prevents acceptance from the issuer's machine but cannot prevent acceptance on a device that has not yet observed the revocation. This is a known design constraint for v1's offline-first model; the mitigation is short invite TTLs and profile key rotation after detecting unexpected acceptance.
- Revoking a member or device creates a rotation checklist for every profile and secret that member/device could access.
- Shell grants are scoped to project id, profile id, directory hash, shell process id, and TTL. Process ancestry checks are best-effort and strengthen the grant where the platform exposes reliable ancestry data.
- VS Code diagnostics are name-based only: they inspect secret references and environment variable names without decrypting secret values.
- Sealed bundles use age v1 binary payload encryption and include encrypted project/profile/secret metadata, encrypted blobs, device recipient metadata, schema version, and audit-chain checkpoint by default. Full audit rows are included only with `--include-audit`.
- Recovery code implementation uses the `data-encoding` crate for Crockford Base32 encoding and checksum handling.
