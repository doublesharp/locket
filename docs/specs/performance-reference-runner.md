# Performance Reference Runner

This file is part of the normative planned Locket implementation spec. Start at
[index.md](index.md). It satisfies the
[performance.md](performance.md) requirement that "the project must define a
named reference runner before public release" by pinning the hardware classes,
operating system images, CPU governor, filesystem, power policy, and background
state used to record release-blocking benchmark numbers.

This document is structural. Numeric budgets are not invented here; they remain
in [performance.md](performance.md). The
`# TODO(perf-budget-table-revision)` section below tracks how those budgets are
re-validated once the named runners are physically online.

## Named reference runners

Two runner classes are named. Every public-release performance claim must be
recorded on at least one of them, and any claim that depends on platform-
specific behavior (sandboxing, agent IPC, file I/O) must be recorded on both.

### `locket-ref-arm64-mac` (Apple Silicon)

- **Hardware class:** Apple Mac mini, M2 Pro chip (10-core CPU, 16-core GPU),
  32 GB unified memory, 512 GB internal NVMe SSD. No external storage attached
  during benchmark runs.
- **OS:** macOS 15.x (Sequoia), latest patch level at the time of the release
  candidate. `softwareupdate --list` recorded in the bench report.
- **CPU governor:** macOS does not expose a Linux-style `cpupower` governor.
  Pin behavior with the following defaults instead:
  - Low Power Mode disabled (`pmset -a lowpowermode 0`).
  - Disable App Nap for the benchmark shell session
    (`defaults write NSGlobalDomain NSAppSleepDisabled -bool YES` for the
    duration of the run; revert after).
  - Disable automatic sleep while plugged in
    (`pmset -a sleep 0 disksleep 0 displaysleep 0`).
  - Record the active power source and thermal pressure state via
    `pmset -g therm` and include in the bench report.
- **Filesystem:** APFS on the internal SSD with default mount options
  (case-insensitive, encrypted, copy-on-write). No external volumes mounted
  during runs.
- **Power:** AC power, lid open if applicable (Mac mini has no lid; this rule
  applies to MacBook backups of the same class). UPS recommended; brownouts
  invalidate samples.
- **Background:** no Xcode build, no Time Machine backup, no Spotlight
  indexing burst (`mdutil -a -i off` for the duration of the run, restored
  after), no `mds_stores` heavy activity, no fan-modulating apps (e.g.
  Macs Fan Control, TG Pro), no virtualization (Docker Desktop, OrbStack,
  Parallels) running, no screen recording, no Bluetooth audio sinks active.
  Wi-Fi may remain enabled but no active large transfers.

### `locket-ref-x86-linux` (x86_64)

- **Hardware class:** AWS EC2 `c7i.xlarge` (4 vCPU Intel Sapphire Rapids, 8 GB
  RAM, dedicated tenancy, EBS-only `gp3` 100 GB io-tuned to 3000 IOPS / 125
  MB/s baseline) for cloud reference runs; equivalent dedicated bare-metal:
  Hetzner `CCX13` (4 dedicated AMD EPYC vCPU, 16 GB RAM, NVMe-backed root) for
  local reference runs. Either qualifies; both must be available for release
  blocking. Do not mix samples across the two within a single report.
- **OS:** Ubuntu 24.04 LTS (Noble Numbat), HWE kernel pinned to the version
  shipped at the release-candidate cut. Record `uname -srmo` and
  `/etc/os-release` in the bench report.
- **CPU governor:** `performance` on every online CPU. Apply with:
  ```bash
  sudo cpupower frequency-set -g performance
  # verify
  cpupower frequency-info | grep -i 'current policy\|governor'
  ```
  Record the governor and minimum/maximum frequency in the bench report. On
  bare-metal hosts also disable Intel Turbo Boost variance by setting
  `intel_pstate=performance` in the kernel cmdline if the workload is
  short-lived; on EC2 leave Turbo on but record the steady-state frequency.
- **Filesystem:** ext4 with default mount options (`relatime,errors=remount-ro`)
  on the root volume. No tmpfs overlays for the bench fixtures. Record
  `findmnt /` in the bench report.
- **Power:** AC power for bare-metal Hetzner; EC2 instances are inherently
  AC-backed but must not be `t`-class (burstable) — only `c7i` or comparable
  fixed-performance class. Document instance type in the bench report.
- **Background:** no concurrent CI jobs, no Docker daemons running other
  workloads, no `unattended-upgrades` cron windows during the run, no
  `updatedb`/`mlocate` indexing, no `snapd` refreshes, no kernel-module
  rebuilds. SSH session may remain attached; no `tmux` session resizing or
  active log tailing during sample collection.

## Reproducibility

Both runners are stood up via the per-class setup script under
`scripts/reference-runners/` (added with the first concrete benchmark that
needs it). The script is idempotent and records its applied state into
`target/quality/reference-runner-setup.json` so the bench report can include
the verification fingerprint.

A Docker image is **not** appropriate for this runner because containerization
masks CPU governor, filesystem, and thermal-pressure pinning. Reference runs
must execute on the host. CI runners using ephemeral containers are explicitly
not reference runners; they may run `make bench-ci` for regression detection
but their numbers are advisory only.

When invoking benchmarks on a reference runner, the operator must:

1. Run the setup script and confirm a clean exit.
2. Wait at least 5 minutes after the setup script exits before recording
   samples, to let thermal state settle.
3. Run `make bench` (full fixtures, release profile) — the existing harness
   in `scripts/bench-smoke.sh` records the metadata fields required by
   [performance.md § Benchmark Methodology](performance.md).
4. Run the dedicated perf scripts in `scripts/perf-*.sh` for the budgets the
   bench-smoke harness does not yet cover (passphrase unlock, recovery
   envelope unlock, agent idle memory).
5. Archive the resulting `target/quality/bench-summary.json`,
   `target/quality/bench-report.md`, and each `target/quality/perf-*.md` to
   the release artifact bucket alongside the runner-setup fingerprint.

## TODO(perf-budget-table-revision)

The following budgets in [performance.md](performance.md) currently use
placeholder thresholds tuned for "developer laptop or CI runner with at least
4 physical CPU cores, 16 GB RAM". Once both reference runners above are
provisioned, re-record p95 / throughput on each runner and revise the budget
table. Until then, the values below are the placeholder defaults; the spec
text remains canonical.

| Spec budget | Harness env var (current default) | Script |
| --- | --- | --- |
| Metadata-only CLI commands p95 < 100 ms (`list`, `profile list`, `agent status`, `project list-roots`) | `BENCH_SAMPLES=50` (cli_help, agent_status budgets hard-coded to 100 ms in `bench-smoke.sh`) | `scripts/bench-smoke.sh` |
| `locket run <policy>` preparation overhead p95 < 150 ms | not yet wired; will use `LOCKET_RUN_PREP_BUDGET_MS=150` | TBD |
| `lk://` resolution through agent p95 < 25 ms | not yet wired; will use `LOCKET_LK_RESOLVE_BUDGET_MS=25` | TBD |
| `locket scan --staged` p95 < 500 ms | hard-coded 500 ms in `bench-smoke.sh` | `scripts/bench-smoke.sh` |
| Full repository scan throughput >= 25 MB/s | not yet wired; will use `LOCKET_FULL_SCAN_MIN_MBPS=25` | TBD |
| Locked-vault pattern / entropy / provider-token / `.env` scans (same throughput as full scan) | not yet wired; will use `LOCKET_LOCKED_SCAN_MIN_MBPS=25` | TBD |
| Argon2id passphrase fallback p95 < 300 ms | `PERF_PASSPHRASE_BUDGET_MS=300` | `scripts/perf-passphrase-unlock.sh` |
| Recovery-envelope Argon2 unlock p95 < 2000 ms | `PERF_RECOVERY_BUDGET_MS=2000` | `scripts/perf-recovery-envelope-unlock.sh` |
| Agent idle memory < 50 MB | `PERF_AGENT_IDLE_BUDGET_MB=50` | `scripts/perf-agent-idle-memory.sh` |

When the named runners are online, each row above must either:

- be re-confirmed at the existing budget on both runners with at least one
  release-blocking run, or
- be revised in [performance.md](performance.md) with the lower of the two
  runner-class p95s minus a 10% pull-request tolerance, with a paired ADR
  recording the revision.

The follow-on task list that enumerates the wiring of the rows currently
marked "not yet wired" lives at
[../superpowers/specs/2026-04-30-perf-budget-tasks.md](../superpowers/specs/2026-04-30-perf-budget-tasks.md).
