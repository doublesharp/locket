# Locket

Locket is a local-first secrets control plane for development environments.

The product and implementation requirements live in [`LOCKET_PLAN.md`](LOCKET_PLAN.md).
Engineering standards, testing expectations, and fuzzing guidance live under
[`docs/`](docs/).

## Quality Gates

```bash
make fmt-check
make clippy
make test
make coverage
```

Fuzz targets are documented in [`docs/FUZZING.md`](docs/FUZZING.md).
