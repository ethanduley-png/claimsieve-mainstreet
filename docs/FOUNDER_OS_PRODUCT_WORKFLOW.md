# Founder OS Product Workflow

## Customer-facing states

The Founder OS interface should expose only the states needed by a founder:

1. **Draft** — MainStreet has assembled an issue proposal.
2. **Needs evidence** — a work item or repository authorization is missing.
3. **Ready for review** — evidence is complete and the exact action can be approved.
4. **Approved** — the approval is bound to the exact repository and content.
5. **Executing** — a one-use reservation has been committed.
6. **Completed** — independent provider evidence confirms the issue exists as proposed.
7. **Outcome uncertain** — the request may have left the system, but independent evidence is absent.
8. **Blocked** — policy, approval, mutation, replay, expiry, or containment prevented execution.

## Founder review card

The approval card must visibly show:

- repository;
- title;
- full body or an explicit expandable view;
- work-item source;
- evidence freshness;
- policy version;
- expiration;
- expected effect;
- whether the action is reversible or compensable.

A material change creates a new proposal and requires a new approval.

## Five-minute deterministic demo

```bash
PYTHONPATH=python python3 python/founder_os_demo.py
```

The demo uses a timeout-after-commit simulation. The executor sees an ambiguous response; the independent observer reads provider state and confirms the exact action. No GitHub request is made.
