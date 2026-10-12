# SMS sandbox provider — second action surface

The MainStreet `SMSProposalBuilder` emits a proposal only. It does not send,
authorize, approve, or certify anything. It uses the same proposal-only
boundary as the Founder OS GitHub workflow.

The Python `SandboxSMSProvider` implements the existing `DurableProvider`
interface and exercises a distinct action shape: `sms`/E.164 destination,
`SEND`, an allowlisted recipient, exact sender identity and message text.
It delegates persistence, fencing and idempotency to the existing SQLite
provider *simulator*. There is **no SMS transport** and **no external send**.

This is a contract and workflow experiment, not an integration with Twilio,
not independent provider evidence, and not a production tenant deployment.
A real adapter would require isolated provider credentials, documented
idempotency/reconciliation guarantees, recipient consent and opt-out controls,
carrier compliance, verified sender identity, account isolation, rate limits,
privacy protections, and representative live fault injection.

Do not turn on live send by replacing the simulator in place. A real transport
must live behind a separately reviewed, authorized executor and independent
observer with fail-closed reconciliation.
