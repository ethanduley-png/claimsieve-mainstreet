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
2. Candidate claims are always `unverified_candidate` and bind to the SHA-256 of the original source plus one or more OCR span indices.
3. The OCR layer has no API that promotes a claim to authoritative state or executes an external action.
4. Malformed provider output fails closed. Recognition text, confidence scores, and polygons must have equal lengths; confidence values must be finite and in `[0, 1]`; polygons must be valid finite coordinate sets.
5. The provider is replaceable behind `DocumentExtractor`; downstream code is not required to depend on PaddleOCR.
6. The caller must durably preserve the original source bytes under the returned source digest. This adapter hashes the source but does not itself provide immutable object storage.
7. Consequential actions derived from notes remain subject to the normal ClaimSieve proposal, adjudication, authorization, execution, observation, and audit path.

## PaddleOCR integration

The adapter targets the PaddleOCR 3.x `PaddleOCR.predict()` result shape and consumes `rec_texts`, `rec_scores`, `rec_polys`, and optional `page_index` fields. PaddleOCR is loaded lazily so the baseline ClaimSieve assurance test environment does not download OCR models or add a large inference dependency graph.

`python/requirements-ocr.txt` pins the top-level PaddleOCR package used for this evaluation. A production OCR service still needs a platform-specific PaddlePaddle runtime, a fully frozen transitive dependency graph, exact model/profile identity, deployment isolation, and release provenance before it should be treated as a reproducible production evidence producer.

## Deliberate non-goals in this increment

- no direct write into authoritative business memory
- no automatic acceptance of OCR-derived prices, obligations, dates, identities, or instructions
- no provider credentials in the ClaimSieve verifier/executor
- no model download in baseline CI
- no claim that handwriting recognition is perfect
- no attempt to formally prove OCR correctness

The assurance target is narrower: preserve the source binding and prevent uncertain OCR output from silently becoming trusted authority.
