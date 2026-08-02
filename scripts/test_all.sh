#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
mkdir -p evidence

# Manifest verification must happen before this script updates any generated
# evidence file. Write the verification transcript outside the release tree,
# then copy it into evidence only after the immutable check succeeds.
if [[ "${VERIFY_MANIFEST:-0}" == "1" ]]; then
  manifest_tmp="$(mktemp)"
  sha256sum -c MANIFEST.sha256 > "$manifest_tmp"
  cat "$manifest_tmp"
  cp "$manifest_tmp" evidence/MANIFEST_VERIFICATION.txt
  rm -f "$manifest_tmp"
else
  echo "MANIFEST VERIFICATION: SKIPPED (set VERIFY_MANIFEST=1 in an immutable fresh extraction)" | tee evidence/MANIFEST_VERIFICATION.txt
fi

{
  echo "Release: $(cat VERSION)"
  echo "Python: $(python3 --version 2>&1)"
  echo "Node: $(node --version 2>&1)"
  echo "Cargo: $(command -v cargo >/dev/null 2>&1 && cargo --version || echo NOT_AVAILABLE)"
  echo "Rocq: $(command -v rocq >/dev/null 2>&1 && rocq --version || (command -v coqc >/dev/null 2>&1 && coqc --version | head -1) || echo NOT_AVAILABLE)"
  echo "UTC: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
} | tee evidence/ENVIRONMENT.txt

PYTHONPATH=python python3 -m unittest discover -s python/tests -v 2>&1 | tee evidence/PYTHON_TEST_OUTPUT.txt
PYTHONPATH=python python3 python/generate_bundle.py | tee evidence/BUNDLE_GENERATION.txt
PYTHONPATH=python python3 python/generate_durable_vector.py | tee evidence/DURABLE_VECTOR_GENERATION.txt
PYTHONPATH=python python3 python/verify_bundle.py \
  vectors/valid_evidence_bundle.json \
  trust/fixture-trust-root.json | tee evidence/BUNDLE_VERIFICATION.txt
node --test mainstreet/test/*.test.js 2>&1 | tee evidence/NODE_TEST_OUTPUT.txt
node --check mainstreet/src/index.js
node --check mainstreet/src/founder-os.js
PYTHONPATH=python python3 python/founder_os_demo.py | tee evidence/FOUNDER_OS_DEMO_OUTPUT.txt
PYTHONPATH=python python3 scripts/run_founder_os_red_team.py | tee evidence/FOUNDER_OS_RED_TEAM_REPORT.json
python3 scripts/source_gate.py | tee evidence/SOURCE_GATE.txt
PYTHONPATH=python python3 evidence/V033_PATCHED_TRACE_PROBE.py | tee evidence/V033_PATCHED_TRACE.json
PYTHONPATH=python python3 scripts/provider_contract_gate.py | tee evidence/PROVIDER_CONTRACT_GATE_OUTPUT.txt
PYTHONPATH=python python3 scripts/semantic_divergence_gate.py | tee evidence/SEMANTIC_DIVERGENCE_GATE_OUTPUT.txt
PYTHONPATH=python python3 scripts/run_red_team.py | tee evidence/RED_TEAM_OUTPUT.txt
PYTHONPATH=python python3 scripts/run_durable_red_team.py | tee evidence/DURABLE_RED_TEAM_OUTPUT.txt

rust_available=false
rust_fmt="NOT_EXECUTED"
rust_clippy="NOT_EXECUTED"
rust_test="NOT_EXECUTED"
if command -v cargo >/dev/null 2>&1; then
  rust_available=true
  (
    cd rust
    cargo fmt --check
  ) 2>&1 | tee evidence/RUST_FMT_OUTPUT.txt
  rust_fmt="PASS"
  (
    cd rust
    cargo clippy --workspace --all-targets --all-features -- -D warnings
  ) 2>&1 | tee evidence/RUST_CLIPPY_OUTPUT.txt
  rust_clippy="PASS"
  (
    cd rust
    cargo test --workspace --all-features
  ) 2>&1 | tee evidence/RUST_TEST_OUTPUT.txt
  rust_test="PASS"
else
  echo "RUST TOOLCHAIN: NOT_AVAILABLE; source inspection is not compilation." | tee evidence/RUST_TOOLCHAIN_OUTPUT.txt
fi

rocq_available=false
rocq_compile="NOT_EXECUTED"
rocq_assumptions="NOT_EXECUTED"
if command -v rocq >/dev/null 2>&1; then
  rocq_available=true
  (
    cd rocq
    rocq compile -Q . ClaimSieve Claimsieve.v
    rocq compile -Q . ClaimSieve DurableState.v
    rocq compile -Q . ClaimSieve Check.v
    rocq compile -Q . ClaimSieve CheckDurableState.v
  ) 2>&1 | tee evidence/ROCQ_OUTPUT.txt
  rocq_compile="PASS"
  rocq_assumptions="PRINTED_BY_CHECK_V"
elif command -v coqc >/dev/null 2>&1; then
  rocq_available=true
  (
    cd rocq
    coqc -Q . ClaimSieve Claimsieve.v
    coqc -Q . ClaimSieve DurableState.v
    coqc -Q . ClaimSieve Check.v
    coqc -Q . ClaimSieve CheckDurableState.v
  ) 2>&1 | tee evidence/ROCQ_OUTPUT.txt
  rocq_compile="PASS"
  rocq_assumptions="PRINTED_BY_CHECK_V"
else
  echo "ROCQ TOOLCHAIN: NOT_AVAILABLE; proof source inspection is not proof acceptance." | tee evidence/ROCQ_OUTPUT.txt
fi

python3 - "$rust_available" "$rust_fmt" "$rust_clippy" "$rust_test" "$rocq_available" "$rocq_compile" "$rocq_assumptions" <<'PY' | tee evidence/NATIVE_TOOLCHAIN_STATUS.json
import json, sys
rust_available, rust_fmt, rust_clippy, rust_test, rocq_available, rocq_compile, rocq_assumptions = sys.argv[1:]
print(json.dumps({
    "rust": {
        "available": rust_available == "true",
        "fmt": rust_fmt,
        "clippy": rust_clippy,
        "tests": rust_test,
        "claim_scope": "compiled and executed" if rust_test == "PASS" else "source present but not compiled in this environment"
    },
    "rocq": {
        "available": rocq_available == "true",
        "compile": rocq_compile,
        "assumption_audit": rocq_assumptions,
        "claim_scope": "compiled and assumptions printed" if rocq_compile == "PASS" else "formally modeled source present but not compiled or accepted in this environment"
    }
}, indent=2, sort_keys=True))
PY

echo "ALL AVAILABLE EXECUTABLE GATES PASSED" | tee evidence/LOCAL_GATE_SUMMARY.txt
