# MainStreet Note OCR and Memory Boundary

## Status

This increment adds a provider-neutral document extraction boundary with a PaddleOCR 3.x adapter, a bounded reference note interpreter, explicit human validation, and a durable SQLite metadata store. None of these components is execution authority.

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
non-authoritative note interpretation
        |
        v
typed candidate facts/tasks/people/dates/prices/contacts
        |
        v
explicit human validation
        |
        v
accepted business knowledge metadata
        |
        v
MainStreet planning / retrieval
        |
        v
ClaimSieve for every consequential action
```

## Invariants

1. OCR output is always `candidate_evidence`, never authoritative business state.
2. OCR candidate claims bind to the original source SHA-256, the canonical digest of the exact extraction record, and exact span indices.
3. Reordering or changing extracted spans changes the extraction digest.
4. Extracted span text and extraction metadata are bounded before canonical evidence hashing; total accepted extraction text is bounded.
5. Malformed PaddleOCR output fails closed. Text, confidence and polygon arrays must align; confidence values and geometry must be valid; unsupported media types and excessive source/result/span counts are rejected.
6. Note interpretation is `non_authoritative_interpretation`. Every typed candidate remains `unverified_note_candidate` and has `execution_authority == False`.
7. Material candidates such as prices, dates, people, contacts, commitments and tasks require human review. The reference promotion path currently rejects non-human reviewers.
8. The interpreter cannot validate its own candidate.
9. Prompt-injection-like note text is classified as `instruction`, remains data, and cannot be promoted even by the normal human-promotion function. A human must re-enter any legitimate instruction through an ordinary trusted workflow.
10. Accepted note knowledge is still not execution authority. It can inform planning or retrieval, but consequential action must traverse ClaimSieve.
11. Candidate, interpretation and validation identities are canonical digests. The durable store uses immutable/idempotent inserts and rejects a forged accepted record that does not exactly match the persisted candidate and accepting validation.
12. Conflicting accepted values are preserved and surfaced; the store does not silently use last-write-wins semantics.
13. The caller must durably preserve the original source bytes under the returned source SHA-256. The metadata store does not provide immutable object storage.

## Interpretation scope

`RuleBasedNoteInterpreter` is deliberately conservative. It recognizes obvious labeled people, contact details, money, weekday/ISO date mentions, task prefixes, commitments and prompt-injection markers. Unmatched spans become free-form fact candidates. It is a reference implementation, not a claim of general language understanding.

A future model-based interpreter should sit behind the same closed candidate contract. Model output must remain non-authoritative and retain exact source/extraction/span bindings.

## Durable promotion boundary

`NoteMemoryStore` uses SQLite with WAL, `synchronous=FULL`, foreign keys and immutable record identities. It stores interpretation/candidate/validation/accepted-knowledge metadata. It does not store the original image or PDF and it does not issue ClaimSieve permits.

The current human validation record is integrity-bound by canonical digest but is not yet cryptographically signed by an authenticated reviewer identity. Production deployment should bind reviewer identity to the application authentication layer and, for higher-assurance use cases, add signed validation receipts.

## PaddleOCR integration

The adapter targets PaddleOCR 3.x `PaddleOCR.predict()` results and consumes `rec_texts`, `rec_scores`, `rec_polys`, and optional `page_index`. PaddleOCR is loaded lazily so baseline assurance tests do not download models.

`python/requirements-ocr.txt` pins the top-level PaddleOCR package used for this evaluation. Production still needs a platform-specific PaddlePaddle runtime, frozen transitive dependencies, exact model/profile identity and model artifact provenance, deployment isolation, release provenance, immutable source object storage, and controlled model-fetch/network behavior.

## Deliberate non-goals

- no automatic acceptance of OCR-derived prices, obligations, identities or instructions
- no direct provider credentials in the ClaimSieve verifier/executor
- no claim that handwriting recognition is perfect
- no formal proof of OCR correctness
- no production object-storage implementation
- no cryptographic reviewer signature yet
- no model-based general note interpretation yet
- no automatic resolution of conflicting accepted business knowledge

The assurance target is narrow: preserve evidence identity, contain uncertain interpretation, require an explicit promotion boundary, and prevent note content from bypassing the normal ClaimSieve execution path.
