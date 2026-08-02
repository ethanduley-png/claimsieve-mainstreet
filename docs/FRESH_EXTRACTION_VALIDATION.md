# Fresh Extraction Validation — v0.33.0

The release is valid only after extraction into an empty directory and execution of:

```bash
VERIFY_MANIFEST=1 ./scripts/test_all.sh
```

Manifest verification must occur before generated evidence files are rewritten. The final external validation report distributed beside the ZIP records the exact result.

A passing fresh extraction demonstrates only that the included Python, Node, schema, trace, provider-contract, semantic-divergence, bundle, and adversarial gates do not rely on hidden local source files.

It does not establish native Rust or Rocq assurance, live provider behavior, independent infrastructure, distributed consensus, or reproducible binaries.
