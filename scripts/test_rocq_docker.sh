#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
if ! command -v docker >/dev/null 2>&1; then
  echo "SKIP: docker is unavailable; use CI or a Rocq 9.2 installation" >&2
  exit 77
fi
docker run --rm -v "$ROOT/rocq:/work:ro" -w /work rocq/rocq-prover:9.2 \
  sh -lc 'rocq compile -Q . ClaimSieve Claimsieve.v && rocq compile -Q . ClaimSieve Check.v'
