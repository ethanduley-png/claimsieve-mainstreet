# Founder OS Architecture

```text
Founder or collaborator
        |
        v
MainStreet Founder OS proposal builder
        |  no credentials, network, permit, or execution capability
        v
ClaimSieve proposal intake
        |
        v
Signed work-item evidence + signed repository registry
        |
        v
Policy kernel + durable campaign state
        |
        +---- DENY / REQUIRE_HUMAN / SUSPEND
        |
        v
Exact founder approval
        |
        v
Independent ClaimSieve permit authority
        |
        v
Durable one-use reservation + dispatch fence
        |
        v
Restricted GitHub adapter contract
        |
        v
Independent provider readback / reconciliation
        |
        v
CONFIRMED_SUCCESS | CONFIRMED_FAILURE | DIVERGENT_EFFECT | OUTCOME_UNKNOWN
```

## Authority ownership

MainStreet and OpenClaw can only prepare a proposal. They do not possess provider credentials, permit signing keys, reservation state, or outcome authority.

The Founder OS Python workflow is a reference composition. It uses fixture signing keys and defaults to a local provider simulator. It can also receive the restricted GitHub issue provider, which separates writer and observer credentials. This remains a reference integration rather than the intended production topology.

## Exact bindings

The permit remains bound to the existing v0.33 fields:

- tenant
- principal
- campaign
- proposal
- action
- destination
- parameters
- policy
- evidence root
- human approval
- campaign predecessor and successor
- validity interval
- single use

For GitHub issue creation, the exact repository is also required to appear in signed destination-registry evidence.

## Unknown outcome

The simulated adapter supports three important traces:

- timeout before commit: no provider record, therefore `OUTCOME_UNKNOWN`;
- timeout after commit: independent provider readback reveals the effect, therefore `CONFIRMED_SUCCESS`;
- contradictory or divergent evidence: the outcome remains unknown or divergent and the campaign can be suspended.

The live GitHub adapter appends a hidden marker, performs one POST, and uses a separate read token to reconstruct the issue action from provider state. A transport timeout never authorizes an automatic retry. Missing read-back remains unknown; an edited issue is divergent; duplicate or malformed matching markers are conflicting evidence.
