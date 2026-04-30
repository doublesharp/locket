# Tauri desktop shell + hardening + Vue3/Vite frontend bootstrap

Single combined slice for the locket multi-agent worker flow. Bundles
five TODO subtasks under **App/UI → Build the Tauri desktop app** and
**App/UI → Tauri hardening**:

- `tauri-shell` — Tauri 2 main window + IPC plumbing in
  `crates/locket-app/src-tauri/`; opens, renders an empty UI, exits
  cleanly on every supported platform.
- `tauri-frontend-bootstrap` — Vue 3 + Vite + `pnpm` build/lint/typecheck;
  renders an empty project shell.
- `tauri-csp` — restrictive Content-Security-Policy on every renderer
  window; reject inline scripts/styles in release.
- `tauri-devtools-release` — devtools open only behind
  `cfg(debug_assertions)`; never exposed in release builds.
- `tauri-command-scope` — every Tauri command is explicitly scoped to
  the minimum capability set it needs (this slice ships zero registered
  commands).
- `tauri-capabilities-deny-default` — deny-by-default `fs` / `shell` /
  `network` / `updater` / `clipboard` capabilities.

Spec references: `docs/specs/desktop.md:5-65`,
`docs/specs/desktop.md:30-31` (CSP / devtools / capability scoping).

## Goals

- Land the Tauri 2 binary crate so every downstream desktop subtask
  (`tauri-agent-client`, `tray-bind-platform`, reveal/copy gates,
  status subscription, every primary view) has a shell to attach to.
- Lock the security harness in place before any feature can sneak past
  it: empty IPC surface, empty capability file, restrictive release
  CSP, devtools off in release.
- Bootstrap the JS toolchain (`pnpm` + Vite + Vue 3 + TypeScript) so
  later UI work can land features without re-litigating tooling.

## Non-goals

- No agent socket client. Surfacing `AgentUnavailable` is
  `tauri-agent-client`'s job.
- No tray icon registration. That's `tray-bind-platform`.
- No primary views beyond an empty locked-state placeholder.
- No production icon set; placeholder PNGs satisfy `tauri-build` only.
- No CI gating of the `pnpm` toolchain. The Makefile targets skip when
  `pnpm` is missing; integrator notes any skipped steps in the
  ready-file.

## Architecture

The existing `crates/locket-app` library crate stays as-is — pure
descriptor types in [crates/locket-app/src/lib.rs](../../../crates/locket-app/src/lib.rs)
remain unchanged and load-bearing for spec parity tests.

A new binary crate is added beside the lib:

```
crates/locket-app/
  Cargo.toml              # existing: descriptor lib, untouched
  src/lib.rs              # existing: descriptors, untouched
  src-tauri/              # NEW: Tauri 2 binary crate `locket-desktop`
    Cargo.toml
    tauri.conf.json
    capabilities/
      desktop.json
    build.rs
    icons/
    src/main.rs
    src/lib.rs
    tests/
      config.rs
  ui/                     # NEW: Vue 3 + Vite frontend (standalone pnpm)
    package.json
    pnpm-lock.yaml
    vite.config.ts
    tsconfig.json
    tsconfig.node.json
    eslint.config.js
    .prettierrc.json
    index.html
    src/main.ts
    src/App.vue
    src/env.d.ts
    public/
```

Key boundaries:

- The `src-tauri` binary crate joins the Cargo workspace as
  `crates/locket-app/src-tauri`. Its Cargo `name` is `locket-desktop`
  (binary `locket-desktop`).
- `src-tauri` depends on `locket-app` via `path = ".."` so descriptor
  types are reachable from future Tauri commands without restructuring.
- `ui/` is **not** a workspace member of the Rust workspace. It is a
  standalone pnpm project. `tauri.conf.json` references it via
  `frontendDist = "../ui/dist"` and `devUrl = "http://localhost:1420"`.

## Security posture

### Content-Security-Policy

`tauri.conf.json` ships two CSP variants via Tauri v2's
`app.windows[].csp` plus environment-aware composition. The release
CSP is exact:

```
default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'
```

This string is byte-for-byte equal to
`ReleaseWebviewPolicy::default().content_security_policy` in
[crates/locket-app/src/lib.rs](../../../crates/locket-app/src/lib.rs),
which the existing
`release_webview_policy_denies_broad_and_remote_capabilities` test
already pins. The new config-parse test asserts that the release CSP
in `tauri.conf.json` matches that descriptor exactly.

The dev CSP relaxes only what Vite HMR requires:

```
default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self' ws://localhost:1420 http://localhost:1420
```

Dev CSP is wired through Tauri's `tauri.dev.conf.json` overlay so
`cargo tauri dev` picks it up and `tauri build` does not.

### Capabilities

A single `capabilities/desktop.json` file binds to the `main` window
with an empty `permissions` array. No `fs:`, `shell:`, `http:`,
`updater:`, `clipboard:`, `dialog:`, or `notification:` permissions.

The config-parse test asserts that the file is structurally valid JSON,
that `permissions` is `[]`, and that the file does not contain the
substrings `"fs:"`, `"shell:"`, `"http:"`, `"updater:"`, `"clipboard:"`.

### Devtools

Devtools open only when `cfg(debug_assertions)` is true. In
`src-tauri/src/lib.rs`:

```rust
.setup(|app| {
    #[cfg(debug_assertions)]
    {
        if let Some(window) = app.get_webview_window("main") {
            window.open_devtools();
        }
    }
    Ok(())
})
```

Release builds compile out the call.

### IPC surface

Zero `#[tauri::command]` functions are registered. The `invoke_handler`
is set to `tauri::generate_handler![]`. This is the strongest form of
"every command explicitly scoped" — there are no commands.

The config-parse test asserts that `src-tauri/src/lib.rs` contains the
literal `tauri::generate_handler![]` and no `#[tauri::command]`
attribute.

## Build & test wiring

### Cargo workspace

`Cargo.toml` adds `crates/locket-app/src-tauri` to `[workspace.members]`.

`crates/locket-app/src-tauri/Cargo.toml`:

- `name = "locket-desktop"`
- `[lib] crate-type = ["staticlib", "cdylib", "rlib"]` (Tauri convention)
- `[[bin]] name = "locket-desktop"`
- `tauri = { version = "2", features = [] }`
- `tauri-build = { version = "2", features = [] }` (build-dep)
- `serde`, `serde_json` from `[workspace.dependencies]`
- `locket-app = { path = ".." }`

The crate inherits workspace lints. Because Tauri's generated code
trips `clippy::pedantic` lints we don't own, the binary crate's
`Cargo.toml` overrides:

```toml
[lints.rust]
missing_docs = "warn"
unsafe_code = "forbid"
unused_crate_dependencies = "warn"

[lints.clippy]
all = { level = "deny", priority = -1 }
# Tauri 2 emits these from generated code; allow at the crate boundary.
pedantic = { level = "allow", priority = -1 }
nursery = { level = "allow", priority = -1 }
cargo = { level = "allow", priority = -1 }
```

If clippy on the workspace flags the crate after this, the integrator
note records the failure for follow-up.

### pnpm / Vite

`crates/locket-app/ui/package.json` scripts:

- `dev` — `vite` (port 1420, host 127.0.0.1, strictPort)
- `build` — `vue-tsc --noEmit && vite build`
- `lint` — `eslint . --max-warnings=0`
- `typecheck` — `vue-tsc --noEmit`
- `format:check` — `prettier --check .`

Pinned versions (latest stable as of design date):

- `vue@^3.5`
- `vite@^6`
- `@vitejs/plugin-vue@^5`
- `typescript@~5.6`
- `vue-tsc@^2`
- `eslint@^9` + `eslint-plugin-vue@^9` + `@vue/eslint-config-typescript`
- `prettier@^3`

`vite.config.ts` fixes the port at 1420 (Tauri convention) and sets
`server.strictPort = true` and `clearScreen = false` so terminal logs
survive HMR.

### Makefile

New targets gated on `pnpm` availability:

```make
PNPM ?= $(shell command -v pnpm 2>/dev/null)

app-ui-install:
    @if [ -z "$(PNPM)" ]; then \
        echo "skip: pnpm not on PATH"; \
    else \
        $(PNPM) --dir crates/locket-app/ui install --frozen-lockfile; \
    fi

app-ui-check: app-ui-install
    @if [ -z "$(PNPM)" ]; then \
        echo "skip: pnpm not on PATH"; \
    else \
        $(PNPM) --dir crates/locket-app/ui lint && \
        $(PNPM) --dir crates/locket-app/ui typecheck; \
    fi

app-ui-build: app-ui-install
    @if [ -z "$(PNPM)" ]; then \
        echo "skip: pnpm not on PATH"; \
    else \
        $(PNPM) --dir crates/locket-app/ui build; \
    fi
```

CI integration of these targets is a follow-up TODO; this slice does
not edit `.github/` or any CI workflow.

### .gitignore

Append:

```
crates/locket-app/ui/node_modules/
crates/locket-app/ui/dist/
crates/locket-app/src-tauri/target/
crates/locket-app/src-tauri/gen/
```

## Tests

Three layers, all scoped to the touched crate per the worker rules
(`cargo test -p <crate> -j 12` only):

1. **Existing lib tests** in `crates/locket-app/src/lib.rs` keep
   passing untouched. The
   `release_webview_policy_denies_broad_and_remote_capabilities` test
   remains the canonical anchor for the release CSP string.

2. **New `crates/locket-app/src-tauri/tests/config.rs`** —
   deserializes `tauri.conf.json` with `serde_json`, deserializes
   `capabilities/desktop.json`, and asserts:

   - The release CSP equals
     `locket_app::ReleaseWebviewPolicy::default().content_security_policy`
     byte-for-byte. This is the load-bearing security regression — a
     future change to either string fails fast in CI without anyone
     having to remember to update both.
   - `app.windows[0].title == "Locket"` and `app.windows[0].label == "main"`.
   - `app.security.csp` is set (release CSP).
   - `capabilities/desktop.json` `permissions` array is empty.
   - The capability file does not contain `"fs:"`, `"shell:"`,
     `"http:"`, `"updater:"`, or `"clipboard:"` substrings.
   - `src-tauri/src/lib.rs` source contains
     `tauri::generate_handler![]` and contains no `#[tauri::command]`
     attribute.

3. **Smoke `cargo check -p locket-desktop -j 12`** runs in the
   worker's quick-check. Full `cargo tauri build` is integrator-only
   and gated on `pnpm` + system webkit availability. Failures there
   are noted in the ready-file.

## Risks and mitigations

| Risk | Mitigation |
|------|------------|
| Linux webkit2gtk system dep (`libwebkit2gtk-4.1-dev`) | Note in ready-file; not blocking on macOS dev machine. |
| Tauri 2's generated code trips workspace `clippy::pedantic` | Crate-local lint override (see Cargo wiring). |
| `pnpm` not on integrator PATH | Makefile targets skip cleanly; integrator notes which steps were skipped. |
| Vite HMR needs inline scripts | Dev-only CSP relaxation in `tauri.dev.conf.json`; release CSP is still the strict one and is what the test pins. |
| Bundling six TODO items into one slice violates "one slice per TODO" | Documented on the claim line; the TODOs are tightly coupled (CSP / capabilities / devtools / command-scope all live in `tauri.conf.json` and the same `lib.rs` setup hook). The integrator can split if they object. |

## Acceptance criteria

- `cargo build -p locket-desktop` succeeds on macOS.
- `cargo test -p locket-app` continues to pass.
- `cargo test -p locket-desktop` passes — config and source-shape
  assertions hold.
- `pnpm --dir crates/locket-app/ui install && pnpm --dir crates/locket-app/ui build`
  produces `crates/locket-app/ui/dist/index.html` on a machine with
  `pnpm` installed.
- Release CSP in `tauri.conf.json` is byte-for-byte equal to
  `ReleaseWebviewPolicy::default().content_security_policy`.
- `capabilities/desktop.json` has `permissions: []`.
- Six matching TODO items move to `[~] [<id>]` on the claim line under
  the existing **App/UI → Build the Tauri desktop app** and
  **App/UI → Tauri hardening** sections; the claim note names
  `tauri-shell` as the primary topic and lists the bundled subtasks.

## Out-of-scope follow-ups

- Real app icon set when desktop visual design ships.
- CI gating of `app-ui-install` / `app-ui-check` / `app-ui-build`.
- `tauri-agent-client` slice — wires the agent socket client and
  surfaces `AgentUnavailable`.
- `tray-bind-platform` slice — registers the tray icon and menu.
- Reveal/copy / status / view subtasks — each its own slice.
