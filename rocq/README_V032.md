# v0.32 durable-state proof scope

`DurableState.v` models only selected transition properties:

* freeze and revocation block dispatch before the dispatch commit point;
* logical sequences must be strict successors;
* a provider rejects fencing tokens that are not greater than its recorded token;
* terminal outcomes cannot be rewritten to a conflicting terminal outcome;
* unknown outcomes may later be resolved;
* no outcome authorizes automatic retry;
* mutation of a bound request changes reservation identity.

The files were authored for compilation with the package's pinned Rocq line, but the current build environment does not contain Rocq. They are **formally modeled but not compiled or accepted** in this release environment. Consensus, SQLite, operating-system durability, cryptography, key custody, network behavior, provider semantics, and correspondence with Python or Rust remain outside the proof boundary.
