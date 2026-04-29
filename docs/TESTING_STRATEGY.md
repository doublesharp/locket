# Testing Strategy

Testing should be driven from the threat model and user-facing guarantees.

## Test Pyramid

- Unit tests: type validation, parsers, policy evaluation, env merge, crypto AAD construction, error mapping.
- Integration tests: CLI commands against temp stores, agent RPC calls, import/export bundles, scan and redact flows.
- End-to-end tests: representative local-dev flows such as greenfield init, dotenv migration, team invite accept, Docker/Compose injection, and VS Code/agent smoke paths where practical.
- Fuzz tests: malformed, random, and adversarial inputs for parsers and protocol boundaries.

## TDD Expectations

For new behavior:

1. Add a failing test that captures the required behavior or regression.
2. Implement the smallest production change that passes it.
3. Add edge-case and error-path tests before widening the API.
4. Add a fuzz target when the behavior accepts structured external input.

## Coverage Commands

```bash
make test
make coverage
make coverage-html
```

Coverage failures should be handled by adding meaningful tests, not by lowering thresholds.

## Required Scenarios

- Secret values never appear in errors, logs, audit metadata, generated files, or UI payloads.
- `set` fails on an existing key; `rotate` creates subsequent versions.
- Env injection honors `strict`, `minimal`, `merge`, and `passthrough` modes.
- `override = "preserve"` never overwrites existing env vars.
- `override = "error"` fails before process spawn.
- Docker/Compose helpers do not write persistent plaintext env files.
- Agent grants bind to process identity and process start time where available.
- Expired, revoked, or replayed team invites fail closed.
- Bundle conflicts show metadata-only resolution.
- Recovery restores both local master key access and local device private key wrap.
