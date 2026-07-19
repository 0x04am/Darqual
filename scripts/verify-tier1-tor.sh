#!/usr/bin/env bash
# Standalone Tier-1 Tor/relay regression gate.
# Run on a build host (Avante), never on memory-constrained Jade.
set -euo pipefail
cd "$(dirname "$0")/../crates/darqual-tor"

echo "== Tier-1 Tor gate: fmt =="
cargo fmt --check

echo "== Tier-1 Tor gate: build =="
cargo build

echo "== Tier-1 Tor gate: tests =="
cargo test

echo "== Tier-1 Tor gate: clippy =="
cargo clippy --all-targets -- -D warnings

echo "== TIER-1 TOR VERIFY GREEN =="
