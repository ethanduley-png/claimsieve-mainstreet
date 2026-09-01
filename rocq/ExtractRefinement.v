From Corelib Require Extraction.
From ClaimSieve Require Import DurableState.

(** First mechanically executable refinement slice.

    This does not claim that the Rust runtime refines the Rocq model yet.
    It establishes only that one audited Rocq decision function and all of its
    required datatypes can be extracted to OCaml and accepted by the OCaml
    compiler used by the pinned Rocq toolchain.

    The selected function is intentionally security-relevant and narrow:
    executor claims cannot establish terminal truth; terminal classification
    is derived from the independent provider observation. *)

Extraction Language OCaml.

Extraction TestCompile reconcile_from_independent_provider.
