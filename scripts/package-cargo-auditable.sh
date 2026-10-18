#!/usr/bin/env bash
# Tauri --runner receives cargo's arguments; retain auditable dependency metadata.
set -euo pipefail
exec cargo auditable "$@"
