# Main Street agent ergonomics

This directory is the non-authoritative agent experience layer for Main Street.

It is influenced by useful ECC patterns such as skills, agent roles, rules, memory, adapters, and evaluations, but it is implemented independently around the ClaimSieve boundary.

## Trust model

The ergonomics layer can:

1. read context supplied by the host,
2. select a declared skill,
3. bind explicit inputs into that skill,
4. prepare a canonical ClaimSieve proposal,
5. validate only non-authoritative intake acknowledgements through the existing bridge,
6. record observations as unreviewed memory,
7. run tests and evaluations.

It cannot:

- access provider credentials,
- execute provider actions,
- issue or reserve permits,
- fabricate human approval,
- promote memory into policy,
- confirm external outcomes,
- gain generic network egress,
- gain shell or filesystem-write access through this layer.

## Layout

- `skills/`: reusable declarative proposal procedures
- `agents/`: specialized non-authoritative roles that select and apply skills
- `rules/`: durable operating constraints for harnesses and humans
- `memory/`: trust rules for persistent context
- `adapters/`: contracts for OpenClaw, Agent Reach, and future harnesses
- `evals/`: reliability, regression, and adversarial evaluation guidance

## Core rule

Ergonomics can make it easier to decide what to propose. Ergonomics never decides what is authorized to happen.

The only path to a consequential effect remains:

`agent/harness -> skill -> ProposalOnlyBridge -> ClaimSieve -> independently governed execution boundary`
