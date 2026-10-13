# Memory trust model

Main Street memory is context, not authority.

New memories are created with `trust: unreviewed` and `status: active`. The ergonomics API intentionally has no operation that promotes a memory into policy, approval, or execution authority.

A memory record should contain a bounded observation plus evidence references when available. Agents may use memories to improve recall or suggest a workflow, but ClaimSieve must evaluate the resulting proposal against current policy and current evidence.

Future reviewed-memory or workflow-crystallization features must preserve provenance and define an independent promotion mechanism. Repetition alone must never transform an observation into authority.
