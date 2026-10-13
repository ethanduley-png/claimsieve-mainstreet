# PR #4 integration conflict resolution

This branch incorporates main at 8841b8f39016f6efb356296dfaffa9edccc76491 into the older Open Execution Assurance Profile series (previous head 5a8fa0bf24a9ec8a4fcf984a7de21d04bc67c227).

The resolution retains the newer Rust observer receipt protocol and verifier code already on main from PR #32 rather than replacing them with the older versions in PR #4. Runtime ConnectorResponse additionally rejects unknown fields.

The Python state store integrates the older proposed idempotent campaign-containment helper and makes independent observation reconciliation and mandatory containment atomic. The Python verifier retains newer v2 receipt checks and permits an observed-action digest on an unknown conflicting provider outcome only when supported by a signed v2 conflict flag.

The existing SHA-pinned GitHub Actions, mandatory full-assurance pull request trigger, Rocq reconstruction checks, and application tests remain intact. The new execution-assurance proof compilation and deterministic payload/evidence packaging checks are added.

This is an integration candidate, **not** a claim of formal equivalence between the old and new Rust observer implementations. GitHub CI, semantic vectors, and independent code review must validate it before merge. All base branch security gates must remain enabled.
