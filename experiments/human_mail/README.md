# Human Mail — AI-to-human physical task dispatch (v0.1)

**Reference prototype, not a live marketplace.** Human Mail lets software agents **propose** legitimate, consent-based work in the physical world. An independent operator approves the exact task and reward, a matcher issues offers to human workers in the same region with the required skill, and a worker can accept and submit evidence for an independent final review.

This is intentionally an *agent-to-human task mailbox*, not an unbounded autonomous contractor, mail-forwarding business, or payout service.

## Demonstrated workflow

1. `POST /v1/workers` — operator registers an opted-in worker and receives their one-time worker credential.
2. `POST /v1/tasks` — AI agent proposes a camera/measurement/observation task, fixed reward and purpose.
3. `POST /v1/tasks/{id}/approve` — **operator** reviews safety and the exact requested reward, then offers the job to eligible workers in the specified region.
4. `GET /v1/offers` — authenticated workers see their own offers (and optionally receive emails through a separately controlled SMTP outbox).
5. `POST /v1/offers/{id}/accept` — first accepted offer wins; others are withdrawn in the same database transaction.
6. `POST /v1/tasks/{id}/submit` — assigned worker records a proof pointer, SHA-256 digest and notes; no external evidence is fetched automatically.
7. `POST /v1/tasks/{id}/review` — independent operator marks proof verified or rejected.
8. `GET /v1/tasks/{id}/status` and `GET /v1/audit/verify` — agents can read coarse task status; operators can verify the keyed audit chain.

The service exposes interactive API docs at `/docs` when run locally. No customer billing or worker payouts occur, even if a task is accepted or verified.

## Quickstart

Python 3.11+:

```bash
python3 -m pip install -r requirements-test.txt
export HUMAN_MAIL_AGENT_KEY="$(python3 -c 'import secrets;print(secrets.token_urlsafe(32))')"
export HUMAN_MAIL_OPERATOR_KEY="$(python3 -c 'import secrets;print(secrets.token_urlsafe(32))')"
export HUMAN_MAIL_AUDIT_KEY="$(python3 -c 'import secrets;print(secrets.token_urlsafe(32))')"
export HUMAN_MAIL_DB=./human-mail.sqlite3
python3 -m uvicorn human_mail.app:app --host 127.0.0.1 --port 8000
# In another shell: visit http://127.0.0.1:8000/docs
```

Supply `X-API-Key` matching the configured agent/operator keys for their separate endpoints. Each registered worker gets their own `worker_api_key_one_time` returned only during registration. Never publish these keys or commit real `.env` files.

Example agent proposal:

```bash
curl -sS -X POST http://127.0.0.1:8000/v1/tasks \
  -H "X-API-Key: $HUMAN_MAIL_AGENT_KEY" -H 'Content-Type: application/json' \
  -d '{"title":"Record tool operation","description":"Record a demonstration of a hand tool in a consenting, private workspace.","purpose":"Training a robotic manipulation model","kind":"video","region":"Elkhart","reward_cents":3500,"risk":"low"}'
```

Next, operator registers workers using `/docs`, and calls `/approve` with `{ "approved_budget_cents": 3500, "safety_review_complete": true }`. Accepted evidence must be independently checked and legally collected.

Run tests:

```bash
python3 -m pytest -q tests
```

## Controlled outgoing email

On approval, the service creates a **recipient-bound queued email per offer**. It does not send automatically. Operators can inspect `GET /v1/outbox` and send a queued message with `POST /v1/outbox/{id}/send` *only* after the SMTP environment is configured:

```
HUMAN_MAIL_SMTP_HOST=smtp.example.com
HUMAN_MAIL_SMTP_PORT=587
HUMAN_MAIL_SMTP_USERNAME=...
HUMAN_MAIL_SMTP_PASSWORD=...
HUMAN_MAIL_FROM=tasks@example.com
```

Outgoing SMTP uses STARTTLS. Failed/uncertain sends are marked `unknown` rather than retried blindly. `sent` means accepted by the configured SMTP server, **not** delivered or read. Human users must independently opt in and be able to opt out in any future public service.

## Safety, trust boundaries, and limitations

- **Agents cannot approve tasks, assign workers, send mail, review evidence, or pay anyone.** They can propose only.
- Matching is deterministic by normalized region and skill, not geolocation, background screening or worker performance. Only opted-in worker registrations qualify; this v0.1 does *not* independently validate that the operator truly obtained the worker's consent.
- Approval requires an explicit operator call and exact reward equality. The `safety_review_complete` flag is an assertion by that operator, not proof of real-world policy compliance. Dangerous/illegal/unauthorized tasks are **not** comprehensively filtered by this software.
- Task payloads carry a SHA-256 binding and queued email destinations are fixed at approval; there is no automatic payment execution.
- Audit records have a keyed, chained HMAC and can detect modified historic entries when the secret is held separately. This is **not** an independent external ledger, proof of real-world performance, proof of database integrity, or full ClaimSieve integration.
- Evidence URLs are recorded but never downloaded, scanned, or independently authenticated. Do not upload confidential material or record people/property without permission. Do not use tasks involving personal surveillance, children, restricted locations, hazardous work, or shipments during this pilot.
- No account recovery, worker disablement API, deletion/privacy retention controls, spam/rate limits, legal contracts, tax handling, insurance, worker classification compliance, payments, multi-tenancy, dispute resolution or production auth. This service must **not** be deployed publicly as-is.
- One configured agent credential and one operator credential represent a single trusted pilot tenant. Per-agent identities and independent ClaimSieve permit verification are future integration work.

## ClaimSieve integration target

In production, the trust boundary should be: **untrusted agent proposal → ClaimSieve signed policy permit (exact envelope + approved budget + recipients) → restricted one-use outbox/dispatch executor → independently observed acceptance and proof → payment authorization separate from agent**. This reference is a standalone seam that does **not** invoke the ClaimSieve verifier today.

## Test coverage

The test suite exercises agent permission denial, mandatory independent approval, exact reward binding, first-accept-wins, unauthorized proof rejection, independent review, mail suppression after assignment, missing SMTP fail closed, no eligible worker, task envelope tampering, and audit-chain tamper detection.