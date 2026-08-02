# Security Assumptions

The release depends on these assumptions; none is implied by a signature or hash chain alone.

1. The operator pins the correct external trust root through an independent channel.
2. Mutually exclusive role keys are generated, stored, rotated, and revoked separately.
3. The campaign and reservation backends provide the documented atomicity and durability.
4. The canonicalization profile is implemented identically at every authority boundary.
5. The executor has no alternate connector, credential, network, or process-control path.
6. The observer obtains evidence through a path that the executor cannot forge.
7. Provider receipts and read APIs have documented identity, idempotency, and consistency semantics.
8. Human approvals are authenticated, understandable, current, and free of unauthorized substitution.
9. Policy and evidence issuers do not sign false claims merely because a request is correctly formatted.
10. Deployment, operating system, runtime, and supply chain preserve the intended binaries and configuration.

A failed assumption should result in denial, quarantine, or suspension where detectable. Undetectable assumption failures remain residual risk.
