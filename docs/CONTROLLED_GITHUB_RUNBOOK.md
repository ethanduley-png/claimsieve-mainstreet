# Controlled GitHub workflow operator runbook

**Production dispatch is blocked.** These commands install and exercise the local
reference pilot without GitHub credentials. Do not deploy the placeholder
Kubernetes manifests or treat this monolithic reference composition as isolated.

## Install and start an isolated reference pilot

Extract the release payload into a new directory. From its root:

```bash
umask 077
python3 -m venv ../claimsieve-venv
. ../claimsieve-venv/bin/activate
python -m pip install -r python/requirements-executed.lock.txt
python -m pip check
sha256sum -c MANIFEST.sha256
export CLAIMSIEVE_MODE=reference
PYTHONPATH=python python python/founder_os_demo.py
VERIFY_MANIFEST=1 bash scripts/test_all.sh
python scripts/engineering_policy_gate.py
```

The demo starts a local composition, prepares an exact approval, reserves,
executes against the simulator and independently observes. There is no production
server or authenticated multi-role daemon to start. The test script writes
generated evidence; preserve the initial manifest verification before those writes.
Do not use real tokens or sensitive customer content in this pilot.

For native gates install Rust **1.90.0** with rustfmt/clippy, then:

```bash
(cd rust && cargo fmt --check)
(cd rust && cargo clippy --locked --workspace --all-targets --all-features -- -D warnings)
(cd rust && cargo test --locked --workspace --all-features)
PYTHONPATH=python python scripts/cross_language_outcome_gate.py
```

Rocq **9.2** remains a separate required gate. Use the complete file list in
`.github/workflows/rocq.yml` on an approved build runner, retaining assumption
output. The shorter Docker helper does not cover every proof file.

## State, health and logs

Keep the state directory on a local persistent volume owned only by the trusted
state identity, mode 0700, with files restricted to that identity. Do not mount
it in a proposal worker. Schema 1 stores the complete approved proposal, including
potentially sensitive issue content: protect backups and storage accordingly.
The health command is read-only and never creates a missing database:

```bash
python scripts/state_health.py /absolute/path/founder-state.sqlite3
```

Exit 1 means storage cannot be validated; stop dispatch. Exit 0 means readable
schema-1 storage, not permission to send or proof of journal authenticity. Review
`frozen`, pending counts and `legacy_snapshots_missing`. Database errors propagate
before provider dispatch; an error after dispatch must remain ambiguous. Do not
replace a missing/unavailable database with a new empty database to resume work.

The existing journal records event type, sequence, reservation, digests, fence
and containment epoch. It detects chain damage within its trust assumptions; a
database administrator can rewrite the database and journal together. Do not log
tokens, full proposals, approvals, issue bodies or raw HTTP errors. The health
output is aggregate structured JSON. External centralized append-only audit,
retention and alerting remain deployment gates, not implemented guarantees.

## Revocation and unresolved outcomes

Use only a trusted administrative process with the pinned role keys to invoke
`DurableStateService.revoke_permit`, `suspend_campaign` or `freeze`. These are
library interfaces, not remotely authenticated administration endpoints. Preserve
the resulting journal events. Do not expose them directly to agents.

Revocation dominates until `DISPATCH_COMMIT_POINT` commits. After that point it
cannot recall a request or prove prevention. Never resend GitHub issue creation
from DISPATCHING, PROVIDER_ACKNOWLEDGED or OUTCOME_UNKNOWN. GitHub provides no
native idempotency contract for this workflow, and finding no marker is not proof
that no issue was created. No same-dispatch GitHub transport replay is supported.

Inspect `recovery_queue()` under trusted administration. For schema-1 RESERVED or
EXECUTING rows, `resume_reserved` requires the exact persisted proposal and still
checks ownership, expiry and containment before claiming dispatch. If multiple
workers compete only one can claim dispatch. For any possibly dispatched request,
use `IndependentObserver.reconcile` with the exact snapshot; a substituted proposal
is rejected. Conflicts remain unknown and suspend the campaign. Revocation does
not forbid read-only observation of an earlier in-flight effect. Do not rewrite
terminal outcomes. An intentional new action needs new independently approved
authority and explicit acknowledgement of duplicate risk.

The standalone `github_integration.py observe` command is a diagnostic summary;
it does not itself establish authenticated durable terminal state. Do not present
its caller-supplied expected digest as recovered authorization.

## Backup, upgrade, restore and rollback

1. Freeze dispatch and stop all workers. Resolve or record every in-flight
   reservation. Keep the provider credentials disabled during maintenance.
2. Back up with SQLite's online backup API (not a copy of the main file while
   WAL writers run). Example from a trusted offline administrative shell:

   ```python
   import sqlite3
   from pathlib import Path
   source = Path('/absolute/path/founder-state.sqlite3')
   backup = Path('/absolute/protected/new-backup.sqlite3')
   if backup.exists():
       raise RuntimeError('refusing to overwrite backup')
   with sqlite3.connect(source.as_uri() + '?mode=ro', uri=True) as src:
       with sqlite3.connect(backup) as dst:
           src.backup(dst)
           assert dst.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
   ```

3. Preserve hashes, external audit heads, schema version, source artifact identity
   and pending reservation list separately. Keep backup access restricted. The
   local regression verifies backup/reopen retains consumption and journal state;
   it does not provide off-host anti-rollback.
4. Initialize the new service against a **copy** first. Schema 0 to 1 migration is
   transactional; existing reservations remain and receive no invented snapshot.
   Such legacy rows need manual evidence review and remain non-dispatchable through
   recovery. Future schemas are rejected. Never populate snapshots from new caller
   input to make a legacy reservation executable.
5. Validate health, journal, pending state and exact artifact before replacing the
   stopped installation. Never run old and new writers against the same volume.
6. Restore only with workers stopped and network/provider access disabled, into a
   separate path. A stale backup may omit consumed permits and revocations: compare
   against external records and provider observations. If completeness cannot be
   established, remain frozen and do not dispatch. Restoration is not replay authority.
7. Do not roll back to the old executable for live dispatch: it ignores the new
   snapshot protections. Retain the new state and fixes or remain offline. There
   is no automatic safe downgrade of this security boundary.

## Credentials and promotion

For a future approved production composition, proposal agents receive no signing
or GitHub tokens. The writer must be scoped to Issues:write on exactly one
repository, observer to Issues:read using a separately controlled identity. The
observer must not share the writer's process, secret mounts or process-control
permissions. Approval/evidence signing must not be performed by the proposal
agent. Enforce boundaries in the target operating environment and test denial of
cross-role access before any live canary. Current fixture auto-approval cannot
satisfy these requirements. `CLAIMSIEVE_MODE=production` intentionally rejects it.
