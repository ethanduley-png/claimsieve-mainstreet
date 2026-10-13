# Separately signed GitHub observer (reference increment)

Status: **offline implementation and adversarial tests**, not production-host independence or a formal proof.

## What this increment establishes

The repository's existing GitHub canary reads GitHub through a read-only provider adapter and refuses to treat executor text as outcome finality. This increment adds:

- An Ed25519 observer attestation over the readback classification and exact approved-action digest.
- A 256-bit unpredictable verifier-issued challenge and an exact dispatch ticket commitment.
- An expiry-bound, durable, single-use verifier-side SQLite challenge ledger. Its atomic claim makes concurrent replay yield at most one success.
- Signature validation against an observer public key provisioned independently of the agent and executor.
- Strict receipt fields, action/destination/provider URL validation, and no automatic retry.
- A POSIX read-only observer CLI that obtains a dedicated read credential, accepts **no GitHub write or ambient GitHub credential**, reads a private mode-0600 seed file without following symlinks and outputs a signed observation.

## Minimal protocol

1. A trusted ClaimSieve verifier obtains the already verified action A and authorized durable dispatch ticket. It calls \`GitHubVerifierChallengeStore.issue(ticket=..., approved_action_digest=...)\` and sends only the challenge and declared inputs to the isolated observer process.
2. The observer uses its **own separately administered read-only GitHub credential** to read GitHub state and reconstruct the exact action/effect. Agent text, executor text and tool-wrapper output are not trusted.
3. The observer signs \`claimsieve.github_observer_attestation.v1\` with a key never exposed to agent/executor.
4. The verifier calls \`verify_github_observer_attestation(..., challenge_store=..., observer_public_key=...)\` with its original action, ticket, out-of-band observer public key, and issued challenge. The durable challenge is consumed **only after** all checks pass.
5. An absent, ambiguous or conflicting observation returns authenticated \`OUTCOME_UNKNOWN\`. A valid signature with an invalid binding or stale/replayed challenge **raises an error**, never confirming success.

The raw JSON request consumed by the CLI contains exactly \`approved_action\`, \`approved_action_digest\`, \`ticket\`, and \`challenge\`. Importantly, the observer is **not** an approval authority: if an attacker sends its own arbitrary request and receives a signed result, the genuine verifier must refuse it because it does not match its original trusted approval and reserved challenge.

## Reproduce without secrets

\`\`\`bash
PYTHONPATH=python:python/tests python -m unittest discover -s python/tests -p 'test_github_observer_attestation.py' -v
PYTHONPATH=python:python/tests python scripts/github_canary_evaluation.py
\`\`\`

The first suite uses a fake GitHub API, distinct seeded fixture identities, durable SQLite challenges and adversarial tampering. No internet or GitHub write tokens are used.

## Observer CLI handoff for independently administered host

A separately controlled observer host can use:

\`\`\`bash
# Provision the 32-byte Ed25519 seed securely ON the observer host only.
umask 077
openssl rand 32 > /run/secrets/claimsieve-observer-seed
chmod 600 /run/secrets/claimsieve-observer-seed
# Independently provision an Issues-read-only token. NEVER forward it to an agent.
export CLAIMSIEVE_GITHUB_READ_TOKEN='READ_ONLY_TOKEN_FROM_SECRET_MANAGER'
PYTHONPATH=python python python/github_observer_cli.py \
    --repository example/claimsieve-mainstreet \
    --request /run/claimsieve/request.json \
    --observer-key-id observer-prod-1 \
    --key-seed-file /run/secrets/claimsieve-observer-seed \
    > /run/claimsieve/receipt.json
\`\`\`

Replace the example repository with the approved exact repository, create and transfer the request through an authenticated channel, and distribute the observer public key out-of-band to the verifier. The request is not a token or approval. In production use a managed non-exportable signer rather than a raw seed where possible; the CLI's raw seed is a reference handoff only. The CLI rejects ambient \`GITHUB_TOKEN\`, \`GH_TOKEN\` and \`CLAIMSIEVE_GITHUB_WRITE_TOKEN\`.

## What this DOES NOT establish

**Deployment separation is still unverified.** No second real host, independent administrator, managed signer, or private network path has been provisioned or verified. A compromised observer or its signing key can lie about provider evidence. A valid GitHub issue marker comes from **mutable provider content**, not an immutable GitHub signature. An attacker with sufficient GitHub write privilege can manipulate a recorded issue or create spoofed provider state; a signed readback of that state does not establish exclusive causation.

A local SQLite challenge journal resists concurrent single-host replay but remains vulnerable to administrator rollback or cloned verifier databases; use externally pinned journal checkpoints or remote conditional storage to prevent this. Verification time must come from a trusted verifier clock. Do not use untrusted requests to choose the trusted action, ticket, challenge, public key or observed timestamp.

The Kubernetes reference manifests already deny agent egress; they do **not** configure a separately controlled GitHub observer egress gateway. Kubernetes NetworkPolicy alone cannot reliably authorize a dynamic GitHub.com DNS name. Before a live test, deploy an independently managed outbound proxy with FQDN/TLS restrictions, provider token separation, no agent credentials, and audit checkpoint anchoring. The client process requires a transport identity, authentication, authorization, resource limits, and replay control at its inbound boundary. Do not expose the CLI directly to the public Internet.

## Next verification milestone

Run the observer from a separate failure/administration domain, pin its public key independently and perform a fresh challenge/readback against one explicitly human-approved GitHub issue. Demonstrate that tampering with the agent, the tool wrapper, or executor cannot forge the observer signature; capture separate GitHub provider state, a signed observer receipt, a consumed nonce and an externally anchored audit checkpoint. No live write occurs in this pull request.
