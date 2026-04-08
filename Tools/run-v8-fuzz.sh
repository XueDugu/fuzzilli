#!/usr/bin/env bash

set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
    echo "Usage: $0 /path/to/d8 [storage-dir]" >&2
    exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
D8_BIN="$1"
STORAGE_DIR="${2:-$ROOT_DIR/out-v8}"
CLI_BIN="${FUZZILLI_CLI_BIN:-$ROOT_DIR/.build/release/FuzzilliCli}"

if [[ ! -x "$D8_BIN" ]]; then
    echo "d8 binary is missing or not executable: $D8_BIN" >&2
    exit 1
fi

RUNNER=()
if [[ -x "$CLI_BIN" ]]; then
    RUNNER=("$CLI_BIN")
elif command -v swift >/dev/null 2>&1; then
    RUNNER=(swift run -c release FuzzilliCli)
else
    echo "Neither $CLI_BIN nor swift is available. Set FUZZILLI_CLI_BIN or install Swift." >&2
    exit 1
fi

exec "${RUNNER[@]}" \
    --profile=v8 \
    --engine=mutation \
    --corpus=markov \
    --argumentRandomization \
    --swarmTesting \
    --exportStatistics \
    --storagePath="$STORAGE_DIR" \
    "$D8_BIN"
