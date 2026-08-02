# Status Matrix

| Claim | Status | Evidence |
|---|---|---|
| MainStreet can prepare a bounded GitHub issue proposal | Implemented and tested | Node tests |
| MainStreet has no execution or credential capability in the module | Implemented and source-gated | Source gate and capability manifest |
| Founder OS uses the v0.33 authority rather than a second issuer | Implemented and tested | Python integration and merge report |
| Repository and content mutation after approval are blocked | Implemented and tested | Python tests and red-team report |
| Permit replay is blocked durably | Implemented and tested | Durable state tests and Founder OS tests |
| Timeout before commit remains unknown | Implemented and tested in simulator | Founder OS tests |
| Timeout after commit can be confirmed by independent readback | Implemented and tested in simulator | Founder OS tests |
| Four Founder OS ledger chains verify | Implemented and tested | Founder OS test and demo |
| One live GitHub action matched its exact permit | Executed and observed | `evidence/GITHUB_LIVE_CANARY_REPORT.json` and issue #1 |
| Live GitHub issue creation is generally safe | Not established | One canary cannot establish production safety |
| GitHub natively guarantees idempotent issue creation | Not claimed | Production contract work remains open |
| Rust enforces Founder OS semantics | Implemented only where inherited; not established for new slice | Native status report |
| Rocq proves Founder OS end to end | Not claimed | Outside current proof boundary |
