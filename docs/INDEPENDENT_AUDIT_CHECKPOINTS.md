# Independent audit checkpoints (reference)

Local hash chaining and SQLite atomicity do **not** protect a journal against
an administrator who can rewrite or restore the database. The reference
`claimsieve_ref.audit_checkpoint` module supplies independent attestation.

## Required trust model

1. A separate auditor reads an exported complete journal and verifies each
   event's contiguous sequence, predecessor and hash.
2. The auditor signs the current event count and head with a distinct Ed25519
   key held outside the execution host. The application never sees the key.
3. Publish the full signed checkpoint or at minimum its canonical digest into
   an independently controlled immutable log. The verifier gets that digest
   and the auditor public key **out of band**.
4. A verifier checks the full journal, checkpoint signature and the external
   pin. Incremental checkpoints also bind the previous checkpoint digest.

The reference code deliberately does **not** automatically publish, provision
keys, rotate keys, or assert independent infrastructure. Its fixture keys are
only for tests. Production readiness requires external persistence, independent
key custody, authorized checkpoint advancement, alerting, recovery exercises,
retention and operational review.

A pin placed in the same mutable SQLite file as the journal offers no meaningful
protection against full-host rollback. Nor does a valid signature attest that the
underlying provider reported the truth.
