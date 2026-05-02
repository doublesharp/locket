<div align="center">

<img src="docs/Locket.png" alt="Locket" width="160" />

# Locket

### A local-first secrets control plane for development environments.

<p>
  <img alt="local-first" src="https://img.shields.io/badge/local--first-✓-3b82f6?style=flat-square" />
  <img alt="no telemetry" src="https://img.shields.io/badge/no_telemetry-✓-10b981?style=flat-square" />
  <img alt="encrypted vault" src="https://img.shields.io/badge/encrypted_vault-✓-8b5cf6?style=flat-square" />
  <img alt="rust" src="https://img.shields.io/badge/built_with-Rust-orange?style=flat-square&logo=rust&logoColor=white" />
  <img alt="platforms" src="https://img.shields.io/badge/macOS_·_Linux_·_Windows-grey?style=flat-square" />
</p>

<em>Replace plaintext <code>.env</code> files with an encrypted vault, explicit policy,<br/>and process-scoped delivery — without ever leaving your machine.</em>

<br/>

<sub>
  🔐&nbsp;Encrypted&nbsp;&nbsp;·&nbsp;&nbsp;🎯&nbsp;Capability-scoped&nbsp;&nbsp;·&nbsp;&nbsp;🧭&nbsp;Project&nbsp;+&nbsp;Profile&nbsp;&nbsp;·&nbsp;&nbsp;🪪&nbsp;Passkey&nbsp;Sync&nbsp;&nbsp;·&nbsp;&nbsp;🚫&nbsp;No&nbsp;Telemetry
</sub>

</div>

<br/>

> Locket treats secrets as **capabilities** — granted to specific projects, profiles, commands, directories, editors, shells, and runtime sessions. No plaintext on disk. No values in shell history. No telemetry. No remote calls except the ones you explicitly ask for.

---

## Why Locket

- 🔐 **Encrypted local vault** — your secrets, sealed at rest, unlocked only when you ask.
- 🎯 **Capability-scoped delivery** — `locket run`, `locket exec`, Docker, and Compose helpers inject secrets into one child process and nowhere else.
- 📋 **Explicit command policies** — declare which secrets a command may receive, and Locket enforces it.
- 🧭 **Project + profile workflows** — keep `dev`, `staging`, and per-machine secrets cleanly separated.
- 🛠️ **Shell, editor, desktop, and tray integrations** — local status, approvals, and `lk://` reference resolution.
- 🔄 **Rotation, history, and diffs** — change values safely; compare profiles without revealing them.
- 🧹 **Scanner, pre-commit, redaction, AI-safe tools** — keep secrets out of code, logs, and prompts.
- 🪪 **Recovery and passkey support** — first-class multi-machine sync without a hosted service.
- 👥 **Local-first team onboarding** — encrypted invites, roles, bootstrap checks; no cloud required.
- 🧾 **Metadata-only audit and diagnostics** — report what happened, never the values.
- 🚫 **No telemetry, no analytics** — only opt-in update checks or explicit sealed sync/export/import.

## Project Files

- `locket.toml` lives in the project and contains shareable configuration, policies, and metadata.
- Secret values stay in the local encrypted vault, **not** in Git-tracked project files.
- `.env.example` is maintained as a names-only contract for expected variables.
- `.gitignore` is updated to keep plaintext local env files out of Git.

> Locket is intentionally local-first. CI and production should use their platform-native secret stores; Locket is for local development workflows.

## Install From Source

```bash
cargo install --path crates/locket-cli
```

For repository development, run the CLI without installing it:

```bash
cargo run -p locket-cli -- <command>
```

## Quick Start

Initialize a project:

```bash
locket init --name my-app --profile dev
```

Import an existing env file:

```bash
locket import .env
```

Or set one secret from stdin:

```bash
printf '%s' "$DATABASE_URL" | locket set DATABASE_URL
```

Inspect metadata without printing values:

```bash
locket status
locket list
locket get DATABASE_URL
```

Create a command policy and run it:

```bash
locket policy add dev -- npm run dev
locket policy require dev DATABASE_URL
locket run dev
```

Check the workspace for accidental leaks:

```bash
locket scan .
locket scan --require-known .
```

## Core Workflows

### Project Setup

```bash
locket init [--name <name>] [--profile <profile>]
locket new --from-template <name>
locket bootstrap
locket status
locket emit-example
```

`locket init` creates the project configuration, prepares the local vault, updates `.gitignore`, and creates a managed `.env.example` block.

### Secrets And Profiles

```bash
locket set <KEY> [--source user-local|machine-local|team-managed]
locket import .env [--overwrite]
locket list [--all]
locket get <KEY>
locket get <KEY> --reveal
locket rotate <KEY> [--grace-ttl <duration>]
locket history <KEY>
locket diff <profileA> <profileB>
locket profile create staging
locket use staging
```

Secret names use portable environment-variable syntax, such as `DATABASE_URL` or `STRIPE_SECRET_KEY`. Secret values are not accepted as command-line arguments; use stdin for writes so values do not land in shell history or process listings.

### Policies And Execution

```bash
locket policy add dev -- pnpm dev
locket policy allow dev DATABASE_URL
locket policy require dev API_TOKEN
locket policy doctor
```

Run a saved policy or inject explicit secrets into one child process:

```bash
locket run dev
locket env inspect --policy dev
locket exec --secret DATABASE_URL -- <command> [args...]
locket env docker --policy dev -- docker run ...
locket compose run --policy dev -- docker compose up
```

Execution commands prepare the child process environment for that invocation only. They do not export secrets into the parent shell.

### Agent And Integrations

```bash
locket agent start
locket agent status
locket shellenv
locket hook
locket allow
locket deny
locket install-hooks
```

The local agent backs unlock caching, live grants, shell prompts, editor status, `lk://` reference resolution, and desktop/tray workflows.

### Scan And Redact

```bash
locket scan [path]
locket scan --staged
locket scan --require-known [path]
locket redact file.log
some-command | locket redact --stdin
locket context
locket ai-safe -- <command> [args...]
```

`scan` reports provider-token patterns, high-entropy strings, env-file markers, and, with `--require-known`, values already stored in the local vault. `redact` and `context` help prepare logs or project metadata before sharing them.

### Access And Recovery

```bash
locket unlock [--verify-user]
locket lock
locket passkey register
locket recover
locket recovery rotate
```

Recovery and verification flows are local-first and avoid putting recovery material in project files.

### Team And Sync

```bash
locket device init
locket device pubkey
locket team init
locket team invite <name> --device <device-descriptor> --profile dev --role developer
locket team accept <invite.locket>
locket team members
locket export --sealed --recipient <device-descriptor> --profile dev
locket import-bundle <bundle>
```

Team and sync workflows use encrypted files addressed to trusted devices. They never require a hosted service or plaintext secret exchange.

### Audit And Diagnostics

```bash
locket audit verify
locket doctor
locket agent logs
locket debug bundle --redacted
```

Diagnostics are designed to report project, vault, hook, agent, policy, and bundle state without exposing secret values.

## Development

The workspace uses the repository-pinned Rust toolchain.

```bash
make ci-local
make fmt-check
make clippy
make test
make coverage
make coverage-html  # doublcov via npx (primary); set COVERAGE_HTML_TOOL=llvm-cov for the cargo llvm-cov --html fallback
make dependency-hygiene
make vet
make bench-fixtures
make perf-passphrase-unlock
make perf-recovery-envelope-unlock
make slsa-provenance
```

`make ci-local` is the default local quality gate. It uses `OFFLINE=1` by
default, runs with `CARGO_JOBS=12`, and skips optional tools with explicit
warnings instead of fetching network state.

Additional quality gates are available through the `Makefile`:

```bash
make nextest
make coverage-branch
make mutation
make leak-canary
make bench-ci
make bench-report
make supply-chain-local
make deny
make audit
make unsafe-inventory
make sbom
make supply-chain-exceptions
make fuzz-smoke
```

Release-style checks should be run explicitly when the required tools and
network-backed advisory data are available. `make ci-strict` includes the
unsafe inventory and SBOM release artifacts under `target/quality/`.

```bash
make ci-strict OFFLINE=0 STRICT=1
make fuzz-nightly STRICT=1
```

Quality gate scripts live in `scripts/` and are intentionally metadata-only:
they must not print, snapshot, or persist secret values. Generated reports are
written under `target/quality/` or `coverage/` and are ignored by Git. RustSec
advisory policy output is written to `target/quality/rustsec-policy.md`.
Supply-chain exceptions are tracked in `supply-chain-exceptions.json` and
validated by `make supply-chain-exceptions`.

Full design specs live in [`docs/specs/index.md`](docs/specs/index.md).
