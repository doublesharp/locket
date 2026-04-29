# Performance Budgets

This file is part of the normative planned Locket implementation spec. Start at [index.md](index.md).

## Performance Budgets

Performance targets with an already-running unlocked agent:

- Metadata-only CLI commands such as `list`, `profile list`, `agent status`, and `project list-roots`: p95 under 100 ms.
- `locket run <policy>` process preparation overhead before child spawn: p95 under 150 ms for 50 or fewer secrets.
- `lk://` resolution through the agent: p95 under 25 ms per reference after grant validation.
- `locket scan --staged`: p95 under 500 ms for typical staged diffs under 2 MB.
- Full repository scan: at least 25 MB/s on local SSDs excluding time spent decrypting known secret values.
- Locked-vault pattern, entropy, provider-token, and `.env` scans use the same throughput budget as full repository scan because they do not require decryption.
- Cold-start Argon2id unlock is bounded by stored KDF parameters. Default passphrase fallback parameters must complete under 300 ms on the project reference laptop class; recovery-envelope parameters must complete under 2 seconds on the same reference class.
- Agent idle memory: under 50 MB excluding UI/Tauri process.
- No Argon2 execution on hot paths while the agent is unlocked and holding valid unwrapped keys.

Performance requirements must never justify caching plaintext secrets on disk or weakening grant checks.

## Benchmark Methodology

Performance budgets must be measured with repeatable fixtures and the same commands locally and in CI.

Required benchmark commands:

```bash
make bench
make bench-ci
make bench-report
```

Tooling:

- Use Criterion or an equivalent Rust benchmark harness for library and agent microbenchmarks.
- Use `hyperfine` or an equivalent command benchmark tool for CLI cold/warm process measurements.
- Use `cargo flamegraph`, `samply`, Instruments, Windows Performance Recorder, or platform equivalents for investigation only; profiler output is not a pass/fail artifact.

Reference runner:

- The project must define a named reference runner before public release. Until dedicated hardware exists, the reference class is a developer laptop or CI runner with at least 4 physical CPU cores, 16 GB RAM, and a local SSD/NVMe filesystem.
- Benchmark reports must record CPU model, core count, memory, OS, filesystem type, power mode, commit SHA, build profile, Rust version, and whether the agent was already running and unlocked.
- Release-blocking benchmark runs must use `--release`, run on AC power where applicable, and avoid concurrent heavy workloads.

Fixtures:

- Metadata fixture: one project with 3 profiles, 150 secret metadata rows, 50 active secrets in the active profile, 10 command policies, 5 trusted roots, and a valid audit chain.
- Runtime fixture: 50 active secrets with values between 16 bytes and 4 KiB, 10 `lk://` references, and one policy that injects all 50 names.
- Reference-resolution fixture: at least 500 `lk://` references split across current, pinned-current, deprecated-in-grace, expired, missing, and unauthorized cases.
- Staged-scan fixture: deterministic staged diff corpus between 1.5 MB and 2 MB with provider-shaped tokens, high-entropy false positives, `.env` paths, known active values, and known deprecated-in-grace values.
- Full-scan fixture: deterministic repository corpus of at least 250 MB for pull-request benchmarking and at least 1 GB for release benchmarking, with a mix of text, ignored paths, binary files, large generated files, and nested directories.
- Argon2 fixture: stored KDF parameter sets for passphrase fallback and recovery envelope, using deterministic test salts and test passphrases only.

Sampling and calculations:

- Each benchmark must perform at least 5 warmup iterations before recording samples.
- CLI latency benchmarks must record at least 50 samples; library and agent microbenchmarks must record at least 100 samples unless the benchmark cost makes that impractical and the report explains the lower count.
- p95 is computed by sorting recorded latencies ascending and selecting index `ceil(0.95 * n) - 1`.
- Throughput is measured as processed bytes divided by wall-clock elapsed time after fixture setup is complete. Decryption time is included only for known-value scan measurements and excluded for locked pattern/entropy/provider scans.
- Memory budgets use peak resident set size where the platform exposes it; otherwise the report must name the platform-specific approximation used.

Regression policy:

- Pull-request `make bench-ci` may use reduced fixtures but must include metadata commands, agent `lk://` resolution, staged scan, and `run` preparation.
- A pull request fails the performance gate when it exceeds a hard budget in this file by more than 10% on the reference runner, or when it regresses a tracked benchmark by more than 20% without an accepted implementation note.
- Release candidates must run the full fixtures and meet the absolute budgets in this file without the 10% pull-request tolerance.
- Security invariants override performance. A benchmark improvement that weakens isolation, policy checks, audit coverage, key handling, or plaintext lifetime is invalid even if it meets the numeric target.
