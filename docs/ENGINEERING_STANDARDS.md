# Engineering Standards

Locket handles secret material, so the default engineering posture is stricter than a normal CLI.

## Required Practices

- Prefer small crates with explicit ownership boundaries.
- Keep public APIs typed; avoid stringly typed policy, crypto, and storage boundaries.
- Use `thiserror` for typed library errors and `anyhow` only at executable edges.
- Do not log, print, serialize, snapshot, or persist secret values.
- Do not use `unwrap`, `expect`, `panic`, `todo`, `unimplemented`, or `dbg` in production code.
- Do not introduce `unsafe` without a documented design review and a narrow exception.
- Add tests before or alongside behavior changes. Security-sensitive behavior needs regression tests.
- Add fuzz coverage for parsers, protocol decoders, scanners, redactors, bundle readers, and env merge logic.
- Keep dependencies minimal and justify new dependencies that touch crypto, IPC, parsing, or persistence.

## Commit Discipline

- Commit coherent progress slices.
- Do not include coauthor trailers.
- Keep generated output, formatting churn, and unrelated edits out of feature commits.
- Every commit that changes behavior should include tests or document why tests are not applicable.

## Review Bar

A change is not ready if it:

- Can print or persist a secret value through an error, trace, test snapshot, debug bundle, or UI state.
- Weakens deny-by-default behavior.
- Adds a new secret delivery path without policy and audit coverage.
- Adds a parser or binary decoder without malformed-input tests and a fuzz target.
- Adds a new storage migration without rollback/fail-closed behavior.
- Adds a CLI command without failure-mode documentation.

## Coverage Bar

- Aim for full practical coverage on `locket-core`, `locket-crypto`, `locket-store`, `locket-agent`, and parsers.
- The repository coverage gate starts at 90% line coverage and should ratchet upward as real code lands.
- Security-critical modules should target branch and error-path coverage, not only happy-path line coverage.
- Coverage exclusions require an inline reason and should be rare.

## Fuzzing Bar

Fuzz targets are required for:

- `.env` import parsing.
- `locket.toml` parsing.
- `lk://` reference parsing.
- Command policy parsing.
- Agent protocol decoding.
- Sealed bundle decoding.
- Scanner/redactor rules.
- Environment merge and conflict resolution.

Fuzz findings should become regression tests before the fuzz target is considered fixed.
