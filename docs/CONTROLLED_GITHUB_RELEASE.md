# Controlled GitHub issue release assessment

Decision: **BLOCKED for production**. The executable scope validated here is an
isolated, single-node reference pilot with a fake GitHub provider, trusted local
operators, one Python v0.33 permit authority, and local SQLite WAL storage.
This is not approval to deploy or perform a live issue creation.

Baseline: `fa858f56a9d459d7dcb4b1651dd77f8d93ce1157`, clean checkout of
`ethanduley-png/claimsieve-mainstreet`, release identity 0.34.0. No user edits were
present. Changes are local; no merge, publication, credential change or live
provider mutation was performed. Final payload hashes and commands are retained
in `evidence/production-readiness/`; the packaged MANIFEST binds source files.

## Boundary and assumptions

The selected workload is one approved GitHub issue in one allowlisted repository.
MainStreet, OpenClaw, other agents, supplied proposals, and provider records are
untrusted. The kernel, authority, authenticated approval/evidence issuers, durable
state service, executor, independent observer, pinned keys, operating system and
operator are trusted. SQLite must reside on a local persistent filesystem with
working fsync, not a shared network filesystem or replicated writable volume.
An attacker may substitute caller input, replay messages, race workers, corrupt
untrusted responses, and cause timeouts, process crashes or delayed observations.
The local tests do not establish protection against root, database rollback,
compromised trusted role keys, or an executor that can bypass its Python interface.

External dependencies: GitHub REST availability, TLS trust and DNS, repository
identity and permissions, token lifecycle, provider read consistency; Python 3.11+
(the tested version is recorded), cryptography 46.0.4, jsonschema 4.26.0 and the
exact dependency snapshot. Rust 1.90.0 and Rocq 9.2 are assurance toolchains,
not alternate active permit authorities. Compact admission remains shadow-only;
proposal-side agent experiments and the customer web/API applications are outside
this execution path. No distributed consensus or high-availability claim is made.

## Implemented corrections and discriminating evidence

| Invariant / path | Original failure | Correction | Evidence |
| --- | --- | --- | --- |
| I-002, I-023 recovery | Replacement payload/principal could dispatch | Atomic immutable proposal snapshot; recovery validates full proposal including approval, trace and action | `before.txt`, `targeted.txt` |
| I-002 dispatch | Caller mutation after reservation reached provider, then failed receipt persistence | Execute detached reserved snapshot | `before-mutable-input.txt`, `targeted.txt` |
| I-033A/B observer | Replacement proposal controlled expected effect | Reconcile only against reserved proposal | `before.txt`, `targeted.txt` |
| I-033A/C correlation | Wrong request digest still certified success | Bind key, request, resource, fence and optional provider action digest; conflicts stay unknown and contain campaign | `before-correlation.txt`, `targeted.txt` |
| I-021, I-033A durable outcome | Stale sequence and signed success with wrong effect accepted | Reject stale sequence; independently enforce terminal effect semantics in durable service | `before-observation.txt`, `targeted.txt` |
| Configuration | Fixture composition accepted production mode | Reject every mode except explicit/default reference mode before state initialization | `before-correlation.txt`, `targeted.txt` |
| Artifact verification | Clean package omitted executable trace probe | Put executable probe in scripts; both platform test runners use it | `archive-before.txt`, fresh extraction results |

Schema 1 adds `reservation_proposals` atomically and immutable update/delete
triggers. It does not change observer-v2 wire fields. Legacy schema-0 reservations
are retained but cannot resume or receive terminal certification through the new
path without a trusted snapshot. Callers cannot backfill one. Unknown future
schemas fail closed. Database administrators can defeat triggers; this is not
protection against administrative compromise.

## Readiness table

| Requirement | Implementation | Verification | Remaining risk | Status |
| --- | --- | --- | --- | --- |
| One permit authority and exact bindings | Existing authority plus immutable recovery snapshot | Negative tests, source review | Trusted issuer and storage compromise | PASS for reference scope |
| Durable one-use and competing-worker exclusion | SQLite unique reservation, BEGIN IMMEDIATE, signed dispatch commands | Existing multiprocess, crash, expiry and revocation tests | Local filesystem and trusted logical sequence | PASS for reference scope |
| Unknown and no GitHub retry | One-shot executor; independent correlated readback | Timeout, conflicting evidence and crash tests | Readback can remain unknown indefinitely | PASS for reference scope |
| Outcome immutability | Signed observer boundary and durable effect validation | Terminal rewrite and stale/effect regression tests | Observer honesty and complete provider truth | PASS for reference scope |
| Production secrets and real approval | Fixture composition deliberately rejected in production mode | Negative configuration test | No production key provisioning or authenticated human approval frontend | BLOCKED |
| Enforced role isolation | Reference interfaces and distinct keys/tokens only | Source inspection; no deployment test | Shared process can access authority, writer and observer credentials | BLOCKED |
| Bounded transport | Existing restricted endpoints, response limits, timeout, bounded pages, no POST retry | GitHub fake transport tests | Timeout is not a process-wide wall-clock budget | PARTIAL |
| Durable operations | Schema migration, read-only health, SQLite backup/restore experiment | New migration/reopen/backup tests | No off-host anti-rollback; in-memory workflow ledgers | PARTIAL |
| Python/Node/schema | Full executable suites | Preserved transcripts | Tests are not exhaustive security evidence | PASS where recorded |
| Rust/Python compatibility | Observer-v2 and outcome differential execution | 12 wire and 11 outcome vectors passed | Rust executor-v1 and full signature/state refinement incomplete | PARTIAL |
| Formal acceptance | Rocq model sources retained unmodified | Rocq 9.2 unavailable locally | Proof acceptance gate must run on final revision | BLOCKED |
| Final artifact | Deterministic package, manifest and clean extraction checks | Fresh extraction transcript and hash | No signed build provenance or independent review | PARTIAL |
| Production provider validation | Historical single canary only | No new live requests | No representative faults, host isolation or credential validation | BLOCKED |

## Evidence interpretation and release gates

Source inspection establishes intent, not execution. Python tests and fake-provider
faults are implementation tests. The red-team/model enumerations describe bounded
models. Rust differential execution covers the specified vectors only. No local
Rocq acceptance or implementation refinement is claimed. The historical canary
is not rerun and does not prove current production safety. Cryptography 50.0.1
was not used: the installed 46.0.4 satisfies >=42,<47. The dependency snapshot now
also pins its previously omitted typing-extensions dependency; it is still not
a platform-independent hash lock.

To unblock: provision a concrete target with independent authority, approval,
executor and observer identities, authenticated role interfaces, enforced egress
and key custody; implement and validate that composition using the existing
protocol. Run Rocq 9.2, provenance and independent security review on the final
revision. Then obtain explicit authorization for a bounded live canary with
least-privilege credentials. An environment variable or different token strings
alone do not establish isolation. See `CONTROLLED_GITHUB_RUNBOOK.md`.
