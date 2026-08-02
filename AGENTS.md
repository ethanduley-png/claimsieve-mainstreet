# Agent Rules

1. MainStreet and OpenClaw are proposal-only for consequential actions.
2. There is one active permit authority: the v0.33 ClaimSieve authority path.
3. The Founder OS v0.1 code in the preserved archive is not an importable runtime dependency.
4. Never add GitHub credentials, SDK calls, `fetch`, shell execution, or generic network egress to `mainstreet/`.
5. Never convert a provider timeout into failure or success without independent evidence.
6. Never automatically retry an issue creation after the request may have left the executor.
7. Repository, title, body, policy, evidence, approval, campaign state, and expected effect must remain exact permit bindings.
8. New provider code must sit behind the restricted executor and independent observer interfaces.
9. Every security claim requires a discriminating test and a preserved trace.
10. Rust source inspection is not compilation. Rocq source inspection is not proof acceptance.
11. Update the claims matrix, limitations, test report, manifest, and fresh extraction evidence for every release.
