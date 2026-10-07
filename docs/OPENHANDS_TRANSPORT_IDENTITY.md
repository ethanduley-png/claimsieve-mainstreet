# OpenHands Transport Identity Boundary

## Why this exists

The OpenHands proposal payload is untrusted. A field inside an `ActionEvent` cannot prove which workload sent it, which OpenHands revision is actually running, or which deployment manifest produced the process.

For that reason, the runtime identity used for ClaimSieve admission must arrive out of band from the proposal itself.

## Reference model

`AuthenticatedRuntimeBinding` represents identity supplied by a trusted transport or attestation layer. It contains the exact runtime name, runtime version, principal, runtime manifest digest, skills manifest digest, and network profile digest.

`OpenHandsAuthenticatedRoute` binds that authenticated identity to the independently configured ClaimSieve runtime profile before the OpenHands adapter receives a routing callback.

The adapter can submit proposals through the bound callback, but proposal fields cannot replace the authenticated transport binding.

The reference tests discriminate principal substitution, manifest substitution, malformed authenticated-binding schemas, and attempts to mutate runtime identity fields inside the proposal payload.

## Important limitation

This code models the identity boundary; it is not an mTLS, SPIFFE workload-identity, confidential-computing, or measured-attestation implementation.

In the local reference workflow, the authenticated binding is constructed from test configuration. A production deployment must derive the equivalent binding from infrastructure the OpenHands process cannot forge, for example workload identity plus deployment attestation.

The static `PINNED_OPENHANDS_COMMIT` in the adapter is therefore an expected-version binding, not proof that the running process was measured at that revision.

The existing `runtime_manifest_digest` is a canonical digest of the ClaimSieve reference runtime profile. It is not a hash of the complete OpenHands binary, container image, filesystem, or measured boot state.

## Deployment requirement

Before calling the OpenHands execution boundary green, the production path should establish all of the following independently of model-controlled payloads:

1. authenticated workload principal;
2. measured or supply-chain-bound runtime artifact identity;
3. exact allowed network profile;
4. absence of ambient executor/provider credentials in the OpenHands workload;
5. egress restricted to the ClaimSieve intake and explicitly approved read channels;
6. restricted executor as the sole holder of consequential provider credentials;
7. independent observer credentials and readback path;
8. durable replay/freshness state outside the proposal runtime process.

Until those deployment properties are tested, the runtime-principal increment is evidence about reference composition and fail-closed semantics, not proof of deployment-level complete mediation.
