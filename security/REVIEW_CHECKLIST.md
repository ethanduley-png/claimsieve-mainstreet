# Release Security Review Checklist

## Design

- [ ] Trust boundaries and role identities are documented.
- [ ] No component holds unnecessary credentials.
- [ ] Every side-effect path passes through the reservation and executor boundary.
- [ ] Campaign state is stored outside the agent lifecycle.
- [ ] Redirects, package fetches, data uploads, DNS, and metadata endpoints are modeled as capabilities.
- [ ] Human approval displays exact destination, action, parameters, risk, and expiration.

## Code

- [ ] Rust workspace forbids unsafe code.
- [ ] Canonicalization rejects floats, duplicate keys, unknown critical fields, and unsupported versions.
- [ ] All signatures are domain separated.
- [ ] Constant-time verification comes from reviewed cryptographic libraries.
- [ ] Reservation is atomic and durable.
- [ ] Errors fail closed and do not downgrade to allow.
- [ ] Logs redact secrets without deleting evidence of secret access.

## Tests

- [ ] Unit tests pass.
- [ ] Adversarial suite passes.
- [ ] Randomized trace suite passes.
- [ ] Concurrency replay test yields one reservation.
- [ ] Seeded faulty kernels are detected.
- [ ] Ledger tamper tests fail verification.
- [ ] MainStreet direct-execution test passes.
- [ ] Rust/Python conformance vectors match in CI.
- [ ] Rocq proofs compile in CI.

## Deployment

- [ ] Agent runtime has no connector credentials.
- [ ] Egress is deny by default.
- [ ] Executor uses a distinct workload identity.
- [ ] Policy, authority, reservation, executor, observer, and containment roles use separate keys.
- [ ] Sandbox and host controls are verified on the target kernel.
- [ ] External ledger-head anchoring is configured.
- [ ] Key rotation and incident recovery are tested.
- [ ] Unknown outcomes page a human and prevent automatic retry.
