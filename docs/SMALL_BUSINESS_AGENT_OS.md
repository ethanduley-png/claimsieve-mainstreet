# MainStreet Small Business Agent OS

## Product thesis

A small business owner should be able to operate the company from one trusted conversation. MainStreet is not intended to be a chatbot or a pile of disconnected automations. It is a business operating layer that can understand company state, surface priorities, prepare work, coordinate systems, and propose consequential actions while ClaimSieve independently governs authority and execution.

The agent should feel like a founder's chief of staff, operations manager, sales coordinator, customer service lead, analyst, project manager, marketing assistant, bookkeeping aide, compliance organizer, hiring coordinator, and executive assistant in one interface. It must never gain the combined power to propose, approve, execute, and certify its own consequential action.

## Operating domains

1. Executive command center: daily brief, priorities, goals, metrics, decisions, risk register, weekly operating review.
2. Communications: inbox triage, drafting, customer follow up, internal messages, call notes, summaries, escalation.
3. Sales and customer relationship management: lead capture, qualification, pipeline hygiene, reminders, proposals, quotes, follow ups, win loss analysis.
4. Customer service: questions, complaints, refunds, cancellations, issue tracking, escalation, service recovery.
5. Marketing and growth: campaign planning, content calendar, social drafts, reputation monitoring, local promotions, referral programs, experiments.
6. Scheduling and task operations: calendar, appointments, reminders, recurring checklists, capacity planning, dispatch, handoffs.
7. Finance administration: invoice preparation, accounts receivable follow up, expense categorization proposals, cash flow summaries, budget variance, payment proposals.
8. Purchasing and vendors: quote comparison, reorder suggestions, vendor communication, purchase proposals, contract renewal tracking.
9. People operations: hiring pipeline, interview scheduling, onboarding checklists, training records, policy acknowledgements, performance documentation.
10. Compliance and records: licenses, insurance, tax deadlines, required filings, policy versions, evidence retention, audit packets.
11. Documents and knowledge: business policies, procedures, templates, contracts, FAQs, product/service catalog, institutional memory.
12. Projects and execution: initiatives, milestones, dependencies, blockers, owners, decision logs, postmortems.
13. Analytics: revenue, lead conversion, churn, utilization, labor, inventory, marketing return, customer experience, operational exceptions.
14. Inventory and physical operations: stock alerts, reorder proposals, asset records, maintenance schedules, facility issues.
15. Information technology and security: account inventory, access review, software renewals, incident intake, credential-risk escalation, backups and device posture.
16. Web and commerce: website changes, catalog updates, listing accuracy, ecommerce operations, review responses, marketplace administration.
17. Strategy and growth: pricing analysis, market research, competitor tracking, new service design, expansion scenarios, capital planning.
18. Founder personal operating layer: travel, personal reminders tied to business obligations, meeting prep, relationship reminders, learning queue, decision journal.

## Core loop

```text
Observe business state
        |
        v
Understand owner intent
        |
        v
Deterministic capability and risk normalization
        |
        +---- informational/internal work ----> analyze or draft
        |
        +---- consequential work -------------> proposal
                                                   |
                                                   v
                                              ClaimSieve
                                                   |
                                      deny / require human / permit
                                                   |
                                                   v
                                           restricted executor
                                                   |
                                                   v
                                           independent observer
                                                   |
                                                   v
                                          evidence + business state
```

## Non-negotiable architecture

MainStreet and its internal agent runtime are proposal-only for consequential actions. They may read permitted business context, reason, draft, classify, and create action proposals. They do not possess unrestricted provider credentials or permit-signing keys.

ClaimSieve remains outside the agent's authority path. It evaluates exact action bindings against policy, evidence, human approval requirements, campaign state, freshness, destination, parameters, and expected effect.

Restricted executors hold narrowly scoped credentials and perform only actions covered by valid permits. Independent observers reconstruct provider outcome where possible. Unknown outcome remains unknown and is never silently converted into success or failure.

## Fail-closed intent normalization

Natural language is not an authority boundary. The deterministic planner is therefore allowed to be conservative.

Topic matching uses token and phrase boundaries instead of raw substring matching. More importantly, direct imperative language that plausibly requests a side effect is not allowed to collapse into an informational or drafting capability merely because the same nouns appear in both.

Examples:

- `Email Bob and tell him the order is ready` becomes a governed external-message proposal.
- `Draft an email to Bob` stays non-executing drafting work.
- `Cancel this customer's membership` becomes a human-gated governed cancellation proposal.
- `Delete all old customer records` becomes a human-gated irreversible-change proposal.
- `Wire 500 dollars to the supplier` becomes a human-gated money-movement proposal.

These classifications do not authorize or execute the action. Their purpose is to prevent the planner from underclassifying a request before ClaimSieve sees it.

## Founder brief safety rule

Known sensitive signal types such as money movement, refunds, pricing commitments, legal deadlines, employment decisions, credential changes, and safety incidents require founder attention. Unknown signals at severity 4 or 5 also escalate to the founder rather than being labeled as work the agent can handle autonomously.

Business state rejects non-finite monetary and metric values so `NaN` or infinite values cannot silently enter prioritization and evidence calculations.

## Autonomy ladder

### Level 0 — Observe
Read and summarize only.

### Level 1 — Draft
Prepare messages, documents, plans, analyses, and proposed records.

### Level 2 — Recommend
Rank options and produce proposed actions with evidence and expected effect.

### Level 3 — Governed execution
Execute bounded actions only after ClaimSieve policy and approval requirements are satisfied.

### Level 4 — Bounded campaigns
Run recurring or multi-step campaigns inside explicit budgets, destinations, rate limits, time windows, risk limits, and suspension conditions.

There is no unrestricted Level 5. The agent never receives general authority over the business.

## Risk classes

- `informational`: analysis, summaries, retrieval, no external side effect.
- `internal_reversible`: task creation, internal drafts, reversible internal state.
- `external_communication`: email, text, social, or customer-facing communication.
- `commercial_commitment`: quote, discount, refund, order, subscription, purchase, contract-related promise.
- `financial`: money movement, payment, banking, payroll, tax payment, credit.
- `legal_compliance`: legal representations, regulatory submissions, licenses, tax filings, attestations.
- `employment`: hiring, termination, compensation, discipline, employee records.
- `health_safety`: medical, injury, safety, emergency, hazardous-work implications.
- `credential_security`: access grants, secrets, authentication changes, security controls.
- `irreversible_high_impact`: deletion, account closure, destructive change, public disclosure, material external commitment.

Higher risk requires stronger evidence, freshness, human approval, separation of duties, execution fencing, and observation.

## Business memory

The agent needs a structured business model rather than a giant prompt. Stable context should be separated from run-specific work. Each fact should have an authoritative home, and agents should load only the context required for the current work item.

## First production wedge

The first deployable version should be broad in architecture but narrow in live authority. It should support:

- morning founder brief;
- inbox and lead triage;
- customer follow-up drafting;
- calendar and task planning;
- business knowledge retrieval;
- sales pipeline review;
- customer issue escalation;
- weekly metrics and cash-awareness brief;
- compliance and deadline reminders;
- proposal generation for governed external actions.

Live execution capabilities should be added connector by connector behind ClaimSieve rather than giving the agent generic network or credential access.

## Success definition

The product wins when the owner spends less time remembering, searching, copying, chasing, scheduling, reconciling, and checking while gaining more confidence that delegated AI actions remain bounded, attributable, reviewable, and recoverable.
