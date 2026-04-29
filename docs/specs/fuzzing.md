# Fuzzing

This file is part of the normative planned Locket implementation spec. Start at [index.md](index.md).

Fuzzing is part of the normal quality bar for Locket because many boundaries accept untrusted or semi-trusted input.

## Tooling

Use `cargo-fuzz` for Rust fuzz targets. Fuzzing requires a nightly Rust toolchain because `cargo-fuzz` uses sanitizer instrumentation.

```bash
rustup toolchain install nightly
cargo install cargo-fuzz
make fuzz-list
make fuzz-smoke
make fuzz FUZZ_TARGET=<target> FUZZ_TIME=300
make fuzz-nightly
```

Fuzz harnesses live outside release crates and must not require real keychain, biometric, Docker, network, or desktop services.

## Target Requirements

Every fuzz target must:

- Be deterministic.
- Avoid network and filesystem side effects unless explicitly isolated in a temp directory.
- Avoid printing generated secret-like input.
- Assert parser round trips, fail-closed behavior, and no panics.
- Keep a minimized regression corpus after each finding.

Fuzz findings must become regression tests before the fuzz target is considered fixed.

## Cadence And Gates

Fuzzing is not optional background work; it is part of the release bar:

- Pull requests that touch a fuzzed parser, decoder, scanner, redactor, env merge path, bundle reader, recovery envelope, audit canonicalizer, or agent protocol frame must run `make fuzz-smoke`. The smoke job runs each affected target against its seed corpus and a short randomized budget of at least 60 seconds per target.
- Nightly CI runs every required fuzz target for at least 15 minutes per target with sanitizer instrumentation enabled. The job stores crashing inputs, minimized reproducers, and corpus growth as CI artifacts.
- Before a public release, every required fuzz target must complete at least 8 cumulative CPU-hours since the previous release without unresolved crashes, timeouts, OOMs, or sanitizer findings.
- Fuzz corpora live under versioned `fuzz/corpus/<target>` directories. Large generated corpora may be stored as CI artifacts, but every fixed bug must add a small minimized reproducer to the repository.
- Fuzz failures block merge or release until the crashing input is minimized, a regression test is added, and the affected target passes its required budget.
- Sanitizer-supported jobs should use AddressSanitizer and UndefinedBehaviorSanitizer where available. MemorySanitizer is optional because Rust dependency support is uneven.
- Fuzz targets must set deterministic resource limits for input size, recursion depth, frame length, and allocation growth so malformed inputs cannot hide denial-of-service behavior behind unbounded harness work.

## Required Fuzz Coverage

Fuzz targets are required for:

- `.env` import parsing.
- `locket.toml` parsing.
- `lk://` reference parsing.
- Command policy parsing.
- Agent protocol frame and JSON payload decoding.
- Sealed bundle container and manifest decoding.
- Recovery envelope parsing.
- Audit row parsing and HMAC canonicalization.
- Scanner/redactor rules and tokenization.
- Environment merge and conflict resolution.
- Device descriptor parsing.

## Initial Fuzz Target List

- `fuzz_dotenv_import`
- `fuzz_locket_toml`
- `fuzz_lk_uri`
- `fuzz_policy_toml`
- `fuzz_agent_protocol`
- `fuzz_bundle_container`
- `fuzz_recovery_envelope`
- `fuzz_audit_row`
- `fuzz_redactor`
- `fuzz_scanner_tokenization`
- `fuzz_env_merge`
- `fuzz_device_descriptor`

## Finding Workflow

1. Minimize the crashing input.
2. Add it to the corpus or convert it into a unit regression test.
3. Fix the bug.
4. Run the target long enough to confirm the fix.
5. Commit the regression and fix together.
