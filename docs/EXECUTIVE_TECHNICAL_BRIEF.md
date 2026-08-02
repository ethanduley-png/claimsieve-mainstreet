# Executive Technical Brief

## ClaimSieve v0.33.0 — Independent Outcome Boundary

### Problem

A consequential action can leave the local system without a definitive response. A timeout does not reveal whether the remote effect happened. A compromised executor can also sign a false narrative about its own attempt. If the observer trusts that narrative, a cryptographically authentic lie can become system state.

### Concrete failure

The v0.32 reference allowed this trace:

1. A valid permit was reserved and claimed for dispatch.
2. No independently readable provider record existed.
3. The executor signed a false `rejected` receipt with its legitimate key.
4. The observer accepted the executor receipt and finalized `CONFIRMED_FAILURE`.

The signature was valid. The semantics were false. The terminal outcome was unsupported.

### Patch

v0.33 removes executor receipts from the observer's terminal-outcome trust path. The observer uses only independently readable provider evidence to classify:

* exact observed effect → `CONFIRMED_SUCCESS`;
* confirmed rejection with no effect → `CONFIRMED_FAILURE`;
* different effect → `DIVERGENT_EFFECT`;
* absent or contradictory evidence → `OUTCOME_UNKNOWN`.

Executor receipts remain useful for audit and detecting disagreement. They no longer establish outcome.

### Trusted-computing-base reduction

The smallest removable trusted component was the executor verification key and receipt parser inside the outcome authority. Removing it shrinks the conditions required for terminal correctness. The executor can still be compromised without gaining the power to declare its own success or failure.

### Provider contract test

The release encodes Stripe's published POST idempotency contract into a deterministic offline model. It tests the narrow case where a transport replay is a continuation of the same dispatch, not a new logical action. The replay must retain the same reservation, idempotency key, canonical request, endpoint, account, active authority, provider guarantee, retention window, and bounded replay count.

A cached 500 remains indeterminate. Reusing a key after the conservative 24-hour window is denied because the provider may have pruned the prior result.

### Evidence status

Executed here:

* Python reference and tests
* MainStreet Node boundary tests
* concrete violating and patched traces
* provider contract gate
* inherited and durable red-team harnesses
* schema and source gates
* semantic divergence gate

Not executed here:

* Rust compilation, tests, formatting, or Clippy
* Rocq compilation or assumption audit
* live Stripe API or webhook behavior
* distributed consensus or independent-host observation

### Strongest remaining divergence

Rust still emits a v1-shaped observer receipt while executed Python and the JSON schema use v2 fields. This is not hidden as a documentation issue. It is a concrete protocol divergence that blocks any parity claim.

### Next decisive step

Compile the unchanged Rust and Rocq artifacts in a controlled environment, run the same outcome vectors through every executable implementation, and preserve disagreements before modifying code. The objective is not to demonstrate consensus. It is to discover where the models assign different authority or meaning to the same trace.
