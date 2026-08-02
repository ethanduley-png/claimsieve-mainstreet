# MainStreet Product Report — v0.33.0

## Product role

MainStreet remains the customer-facing product. It should present requests, evidence, uncertainty, approvals, status, and recovery in plain language while ClaimSieve enforces authority beneath the interface.

## Implemented boundary

The included JavaScript module performs pure proposal preparation and rejects dangerous object graphs. It exposes no transport, credential, filesystem, subprocess, provider SDK, or generic network capability.

Eighteen Node tests execute this boundary.

## Unknown-outcome experience requirement

The user must see the distinction between:

* request prepared;
* permission granted;
* dispatch started;
* provider response received;
* external effect observed;
* outcome confirmed;
* outcome still unknown.

The interface must not display a timeout as failure or a submitted action as resolved.

## Tax-notice pilot

The best near-term product proof remains a no-send tax-notice workspace that:

* separates personal and business cases;
* extracts deadlines and amounts;
* links every factual statement to evidence;
* requests explicit user attestations;
* drafts packets without filing;
* distinguishes draft, submission, acknowledgment, correction, and resolution;
* supports professional escalation.

## Current limitation

The package contains the boundary and synthetic workflow logic, not a complete owner-facing application or live tax integration.
