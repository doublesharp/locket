# Installing Locket via `cargo install`

`cargo install` is the supported install path for Rust users who already
have a working toolchain. It builds the `locket` binary from source against
the published `locket-cli` crate and installs it into `$CARGO_HOME/bin`
(typically `~/.cargo/bin`).

## Recommended invocation

```sh
cargo install locket-cli --locked
```

The `--locked` flag is mandatory for reproducibility. It tells Cargo to use
the exact versions recorded in the published `Cargo.lock`. Without it,
Cargo will resolve dependency versions afresh against the registry, which
can pick up newer patch versions of transitive dependencies between the
moment the release was tested and the moment a user runs the install. For
a security-sensitive tool that ships an embedded SBOM, `--locked` is the
only invocation that produces a binary whose dependency graph matches the
release's audit baseline.

## Feature flags

`locket-cli` defaults to a minimal-secure feature profile. There are no
debug or experimental features enabled by default.

If a user needs to override defaults (for example, to disable a default
feature in a constrained environment), the standard Cargo flags apply:

```sh
cargo install locket-cli --locked --no-default-features
cargo install locket-cli --locked --features <name>
```

The set of feature flags follows Cargo conventions and is documented in
`crates/locket-cli/Cargo.toml`. Treat any feature flag whose name suggests
debug, unsafe, or experimental behavior as not recommended for production
local-development use.

## Install location and PATH

`cargo install` writes the `locket` binary to `$CARGO_HOME/bin/locket`. By
convention `CARGO_HOME` is `~/.cargo` unless overridden. Make sure
`$CARGO_HOME/bin` is on `PATH` before running `locket`:

```sh
export PATH="$HOME/.cargo/bin:$PATH"
locket --version
```

To install into a custom prefix (for example, when packaging Locket inside
a sandboxed tool installation), use `--root`:

```sh
cargo install locket-cli --locked --root /opt/locket
```

The Homebrew formula in `dist/homebrew/locket.rb` uses this `--root` form
to install into the formula prefix.

## Relationship to other distribution channels

- The Homebrew formula (`dist/homebrew/locket.rb`) calls
  `cargo install --locked --path crates/locket-cli` against a signed source
  tarball, so the same metadata, feature defaults, and lock-file behavior
  apply.
- The signed binary releases produced by the upcoming
  `release-key-offline` pipeline use `cargo auditable build --release`
  (see `scripts/release-build.sh`). Users who prefer not to compile from
  source should use those signed binaries; users who want to verify the
  build themselves should use `cargo install --locked`.

## Verification: `cargo publish --dry-run`

The `crates/locket-cli/Cargo.toml` manifest is set up so that
`cargo publish --dry-run -p locket-cli` succeeds in a network-enabled
environment. Required metadata fields satisfied:

- `description` — short crate description.
- `license` — `MIT` (inherited from the workspace).
- `repository` — workspace repository URL.
- `readme` — workspace `README.md`.
- `categories`, `keywords` — populated.
- All internal `locket-*` path dependencies carry an explicit `version`
  alongside the `path` field so that the published crate can resolve them
  against the registry while local builds still use the path.

Known dry-run constraints:

- `cargo publish --dry-run` requires network access to the registry index
  to resolve dependency metadata, even though it does not upload. In
  hermetic build sandboxes the dry-run is expected to fail with a
  registry-fetch error; that is an environment limitation, not a manifest
  defect.
- Internal `locket-*` crates must have been published (or their versions
  reserved) before `locket-cli` itself can be published. The
  `release-key-offline` plan covers the publication ordering.
- Build-time `unused_crate_dependencies` warnings are surfaced as warnings,
  not errors, by `cargo publish` and do not block the dry-run.
