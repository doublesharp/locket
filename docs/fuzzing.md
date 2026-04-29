# Fuzzing

Fuzzing is part of the normal quality bar for Locket because many boundaries accept untrusted or semi-trusted input.

## Tooling

Use `cargo-fuzz` for Rust fuzz targets. Fuzzing requires a nightly Rust
toolchain because `cargo-fuzz` uses sanitizer instrumentation.

```bash
rustup toolchain install nightly
cargo install cargo-fuzz
make fuzz-list
make fuzz FUZZ_TARGET=<target> FUZZ_TIME=300
```

## Target Requirements

Every fuzz target should:

- Be deterministic.
- Avoid network and filesystem side effects unless explicitly isolated in a temp directory.
- Avoid printing generated secret-like input.
- Assert parser round trips, fail-closed behavior, and no panics.
- Keep a minimized regression corpus after each finding.

## Initial Fuzz Target List

- `fuzz_dotenv_import`
- `fuzz_locket_toml`
- `fuzz_lk_uri`
- `fuzz_policy_toml`
- `fuzz_agent_protocol`
- `fuzz_bundle_container`
- `fuzz_redactor`
- `fuzz_env_merge`

## Finding Workflow

1. Minimize the crashing input.
2. Add it to the corpus or convert it into a unit regression test.
3. Fix the bug.
4. Run the target long enough to confirm the fix.
5. Commit the regression and fix together.
