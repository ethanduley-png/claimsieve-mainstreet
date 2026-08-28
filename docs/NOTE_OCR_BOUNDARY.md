# MainStreet Note OCR Boundary

## Status

This increment adds a provider-neutral document extraction boundary with a PaddleOCR 3.x adapter. It is an intake/evidence component, not a source of execution authority.

## Boundary

```text
original note/image/PDF
        |
        v
immutable source storage + SHA-256
        |
        v
DocumentExtractor
        |
        +--> PaddleOCR adapter
        |
        v
provenance-bound extracted spans
(text + confidence + polygon + page)
        |
        v
canonical extraction digest
        |
        v
candidate claims
        |
        v
validation / human review / business policy
        |
        v
accepted business knowledge
        |
        v
ClaimSieve for any consequential action
```

## Invariants

1. OCR output is always `candidate_evidence`, never authoritative business state.
2. Candidate claims are always `unverified_candidate` and bind to the SHA-256 of the original source, the canonical digest of the exact extraction record, and one or more OCR span indices.
3. Reordering or changing extracted spans changes the extraction digest, preventing a span index from being silently reinterpreted against a different OCR run.
4. The OCR layer has no API that promotes a claim to authoritative state or executes an external action.
5. Malformed provider output fails closed. Recognition text, confidence scores, and polygons must have equal lengths; confidence values must be finite and in `[0, 1]`; polygons must be valid finite coordinate sets. Empty recognized strings emitted by current PaddleOCR pipelines are validated for alignment and skipped rather than treated as business text.
6. Source size, provider-result count, and accepted-span count are bounded. Unsupported media types are rejected before provider execution.
7. The provider is replaceable behind `DocumentExtractor`; downstream code is not required to depend on PaddleOCR.
8. The caller must durably preserve the original source bytes under the returned source digest. This adapter hashes the source but does not itself provide immutable object storage.
9. Consequential actions derived from notes remain subject to the normal ClaimSieve proposal, adjudication, authorization, execution, observation, and audit path.

## Extraction identity

The extraction digest reuses the repository's restricted canonical hashing utility. Because that canonical profile deliberately forbids floating-point JSON values, OCR confidence and polygon coordinates are bound as exact hexadecimal floating-point strings. User/provider text is bound as UTF-8 hexadecimal text. This preserves the exact normalized extraction content without weakening the existing canonical profile.

The extraction digest is not an assertion that OCR is correct. It only identifies exactly which OCR result a downstream candidate claim referenced.

## PaddleOCR integration

The adapter targets the PaddleOCR 3.x `PaddleOCR.predict()` result shape and consumes `rec_texts`, `rec_scores`, `rec_polys`, and optional `page_index` fields. PaddleOCR is loaded lazily so the baseline ClaimSieve assurance test environment does not download OCR models or add a large inference dependency graph.

`python/requirements-ocr.txt` pins the top-level PaddleOCR package used for this evaluation. A production OCR service still needs a platform-specific PaddlePaddle runtime, a fully frozen transitive dependency graph, exact model/profile identity and model artifact provenance, deployment isolation, release provenance, and controlled model-fetch/network behavior before it should be treated as a reproducible production evidence producer.

## Deliberate non-goals in this increment

- no direct write into authoritative business memory
- no automatic acceptance of OCR-derived prices, obligations, dates, identities, or instructions
- no provider credentials in the ClaimSieve verifier/executor
- no model download in baseline CI
- no claim that handwriting recognition is perfect
- no attempt to formally prove OCR correctness
- no production object-storage implementation

The assurance target is narrower: preserve the source and extraction bindings and prevent uncertain OCR output from silently becoming trusted authority.
