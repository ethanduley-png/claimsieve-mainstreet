#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
mkdir -p evidence
status=0
log="$(mktemp)"
{
  echo "Native compilation attempt"
  echo "Release: $(cat VERSION)"
  echo "UTC: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo
  if command -v cargo >/dev/null 2>&1; then
    echo "[Rust] $(cargo --version)"
    if ! (cd rust && cargo fmt --check); then status=1; fi
    if ! (cd rust && cargo clippy --workspace --all-targets --all-features -- -D warnings); then status=1; fi
    if ! (cd rust && cargo test --workspace --all-features); then status=1; fi
    if [[ "$status" -eq 0 ]]; then echo "[Rust] PASS"; else echo "[Rust] FAIL"; fi
  else
    echo "[Rust] NOT_AVAILABLE: cargo/rustc are absent. Source inspection is not compilation."
    status=2
  fi
  echo
  if command -v rocq >/dev/null 2>&1; then
    echo "[Rocq] $(rocq --version 2>&1 | head -1)"
    if ! (cd rocq && rocq compile -Q . ClaimSieve Claimsieve.v); then status=1; fi
    if ! (cd rocq && rocq compile -Q . ClaimSieve DurableState.v); then status=1; fi
    if ! (cd rocq && rocq compile -Q . ClaimSieve Check.v); then status=1; fi
    if ! (cd rocq && rocq compile -Q . ClaimSieve CheckDurableState.v); then status=1; fi
    if [[ "$status" -eq 0 ]]; then echo "[Rocq] PASS"; else echo "[Rocq] FAIL_OR_OTHER_NATIVE_GATE_UNAVAILABLE"; fi
  elif command -v coqc >/dev/null 2>&1; then
    echo "[Rocq/Coq] $(coqc --version 2>&1 | head -1)"
    if ! (cd rocq && coqc -Q . ClaimSieve Claimsieve.v); then status=1; fi
    if ! (cd rocq && coqc -Q . ClaimSieve DurableState.v); then status=1; fi
    if ! (cd rocq && coqc -Q . ClaimSieve Check.v); then status=1; fi
    if ! (cd rocq && coqc -Q . ClaimSieve CheckDurableState.v); then status=1; fi
    if [[ "$status" -eq 0 ]]; then echo "[Rocq] PASS"; else echo "[Rocq] FAIL_OR_OTHER_NATIVE_GATE_UNAVAILABLE"; fi
  else
    echo "[Rocq] NOT_AVAILABLE: rocq/coqc are absent. Proof source inspection is not proof acceptance."
    if [[ "$status" -eq 0 ]]; then status=2; fi
  fi
} >"$log" 2>&1
cat "$log" | tee evidence/NATIVE_COMPILATION_ATTEMPT.txt
rm -f "$log"
exit "$status"
