# Locket

Locket is a planned local-first secrets control plane for development environments.

This repository is currently a pre-implementation planning and Rust workspace scaffold.
The docs describe the product target and engineering requirements for the app we are about
to build; they do not describe a shipped or usable application yet.

The product and implementation requirements live in [`docs/specs/index.md`](docs/specs/index.md).
Engineering standards, testing expectations, and fuzzing guidance are part of the planned implementation specs.

## Planned Quality Gates

```bash
make fmt-check
make clippy
make test
make coverage
```

Fuzz targets are planned in [`docs/specs/fuzzing.md`](docs/specs/fuzzing.md).
