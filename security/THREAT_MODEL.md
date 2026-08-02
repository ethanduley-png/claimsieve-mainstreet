# Threat Model

## Protected assets

* customer and business data
* human authority and approval meaning
* connector and cloud credentials
* production systems and external accounts
* policy bundles and signing keys
* audit evidence and ledger integrity
* execution uniqueness and outcome truth
* tenant isolation
* MainStreet product identity and provider neutrality

## Adversaries and failure sources

1. A capable or misaligned model pursuing a goal beyond intended constraints.
2. Prompt injection or malicious content inside email, documents, web pages, datasets, packages, or tool output.
3. A compromised OpenClaw plugin, model provider, connector, dependency, or build artifact.
4. A malicious tenant user or stolen user session.
5. A compromised MainStreet service attempting direct execution.
6. A compromised policy, authority, executor, observer, or ledger role.
7. Operator error, stale configuration, clock error, partial failure, and ambiguous provider response.
8. Concurrency, retry, crash, and network partition creating replay or duplicate effects.
9. A sandbox escape or hidden side channel through packages, redirects, DNS, metadata services, uploads, logs, or terminal control sequences.
10. Supply-chain tampering between source, build, package, deployment, and evidence export.

## Trust assumptions

* Ed25519 and SHA-256 are secure for the intended use.
* Role private keys remain controlled by distinct trust domains in production. Fixture keys do not demonstrate this assumption.
* The campaign and reservation stores provide durable linearizable compare-and-set. The Python reference demonstrates only in-process atomicity.
* The independent observer receives sufficiently complete telemetry to classify outcomes.
* Workload identity issuance correctly binds process identity to role and tenant.
* The host and isolation layer enforce configured boundaries.
* Human approvals are authenticated and users understand the exact bounded action shown.
* External providers may fail, delay, duplicate, or return ambiguous results; they are not assumed truthful without reconciliation.

## Threats and controls

| Threat | Primary control | Independent evidence |
|---|---|---|
| destination swap after approval | exact canonical action digest in permit | verifier recomputes digest |
| permit replay | atomic reservation and max uses = 1 | execution ledger uniqueness check |
| session reset to regain budget | durable campaign state | campaign digest and lineage records |
| hidden direct connector call | network isolation and no credentials in MainStreet | egress and workload telemetry |
| objective substitution | explicit purpose chain and policy scope | proposal and decision ledgers |
| package proxy as covert channel | destination, method, response and purpose binding | egress proxy records |
| redirect to new host | redirects disabled unless explicitly permitted | observed destination chain |
| credential discovery and use | immediate quarantine and credential-use prohibition | evidence event and containment receipt |
| log deletion or tampering | remote observer and signed hash chains | offline chain verification |
| fabricated or stale `ALLOW` at authority boundary | independent deterministic kernel re-evaluation | supplied decision must equal re-evaluated decision and next-state digest |
| caller-selected or compromised policy input | externally trusted policy signer and exact signed envelope | authority and verifier validate signer role and permit binding |
| compromised executor | observer receipt and divergent-effect quarantine | cross-role receipt comparison |
| compromised observer | executor receipt plus external provider state checks | reconciliation evidence; no single receipt proves success |
| valid chain containing unrelated artifacts | exact artifact-to-ledger inclusion | offline bundle verifier compares canonical payload and digest |
| semantically contradictory signed receipts | reservation, action, status, reconciliation and observed-effect checks | cross-role receipt comparison |
| hostile JavaScript object graph or injected transport | descriptor-first validation and single-callable transport | Node boundary regression suite |
| malicious build artifact | signed provenance, generated SBOM, checksum and controlled builder | not implemented in this release |
| denial of service | resource budgets and containment | campaign metrics and circuit-breaker receipt |
| ambiguous provider response | outcome-unknown quarantine | reconciliation state |

## Out of scope for proof

* perfect natural-language understanding
* prevention of all hardware side channels
* correctness of external provider state
* compromise of every independent signing role at once
* coercion or deception of the human approver outside the product
* physical compromise of deployment infrastructure
