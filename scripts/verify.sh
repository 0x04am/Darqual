#!/usr/bin/env bash
# Darqual regression gate — run after every big change. Commit only if this is green.
# Usage: ./scripts/verify.sh
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2
ROOT="$PWD"
BIN="$ROOT/target/debug/darqual"
fail=0

say() { printf '\n\033[1;36m== %s ==\033[0m\n' "$*"; }
ok()  { printf '\033[1;32m  ✓ %s\033[0m\n' "$*"; }
bad() { printf '\033[1;31m  ✗ %s\033[0m\n' "$*"; fail=1; }

say "0/5  cargo fmt --check (workspace)"
cargo fmt --check 2>&1
[ "${PIPESTATUS[0]}" -eq 0 ] && ok "fmt clean" || bad "fmt check failed — run 'cargo fmt'"

say "1/5  cargo build (workspace)"
cargo build --workspace 2>&1 | tail -3
[ "${PIPESTATUS[0]}" -eq 0 ] && ok "build" || bad "build failed"

say "2/5  cargo test (workspace)"
test_out=$(cargo test --workspace 2>&1); trc=$?
echo "$test_out" | grep -E "test result:" || true
if [ "$trc" -ne 0 ] || echo "$test_out" | grep -q "test result: FAILED"; then bad "tests failed"; else ok "all tests pass"; fi

say "3/5  cargo clippy (-D warnings)"
cargo clippy --workspace --all-targets -- -D warnings 2>&1 | tail -4
[ "${PIPESTATUS[0]}" -eq 0 ] && ok "clippy clean" || bad "clippy warnings"

say "4/5  live messaging demo (Alice -> Bob, Eve rejected)"
if [ -x "$BIN" ]; then
  rm -rf /tmp/dq-v-alice /tmp/dq-v-bob /tmp/dq-v-eve
  HOME=/tmp/dq-v-alice "$BIN" keygen >/dev/null 2>&1
  HOME=/tmp/dq-v-bob   "$BIN" keygen >/dev/null 2>&1
  HOME=/tmp/dq-v-eve   "$BIN" keygen >/dev/null 2>&1
  CARD=$(HOME=/tmp/dq-v-bob "$BIN" address 2>/dev/null | grep -oE 'dqcard1[a-z0-9]+' | head -1)
  MSG="darqual verify $(date +%s)"
  BOX=$(HOME=/tmp/dq-v-alice "$BIN" seal --to "$CARD" --message "$MSG" 2>/dev/null | grep -oE 'dqbox1[A-Za-z0-9+/=]+' | head -1)
  GOT=$(HOME=/tmp/dq-v-bob "$BIN" open --lockbox "$BOX" 2>/dev/null)
  EVE=$(HOME=/tmp/dq-v-eve "$BIN" open --lockbox "$BOX" 2>&1)
  [ "$GOT" = "$MSG" ] && ok "Bob decrypts: '$GOT'" || bad "Bob FAILED to decrypt (got: '$GOT')"
  echo "$EVE" | grep -qi "not addressed" && ok "Eve correctly rejected" || bad "Eve should NOT have decrypted (got: '$EVE')"
  rm -rf /tmp/dq-v-alice /tmp/dq-v-bob /tmp/dq-v-eve
else
  bad "binary missing — run cargo build"
fi

echo
if [ "$fail" -eq 0 ]; then printf '\033[1;32m=== VERIFY GREEN — safe to commit ===\033[0m\n'; exit 0
else printf '\033[1;31m=== VERIFY RED — DO NOT COMMIT ===\033[0m\n'; exit 1; fi
