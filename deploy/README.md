# Hardened deployment reference

This directory is a reference boundary, not a complete production deployment.

The intended deployment separates the proposal generator, canonical intake, deterministic kernel, authority signer, reservation service, connector-specific executor, independent observer, and containment controller into different workload identities. The agent namespace starts with deny-all ingress and egress. Its only allowed connection is mutually authenticated traffic to ClaimSieve intake.

The agent reference uses gVisor and the Kubernetes restricted profile. The executor should additionally use a connector-specific seccomp and Landlock policy. Seccomp alone is not a sandbox. Network policy alone is not sufficient where the container network interface or node is compromised. Production acceptance requires host-level egress enforcement, workload identity, managed keys, immutable image digests, runtime attestation, and an independent penetration test.

Do not deploy the placeholder image reference. Replace it with a reviewed immutable digest and generate a deployment certificate whose evidence record binds that exact runtime and skill manifest.
