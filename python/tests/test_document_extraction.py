import hashlib
import os
import unittest

from small_business_agent.document_extraction import (
    CANDIDATE_EVIDENCE,
    UNVERIFIED_CANDIDATE,
    DocumentExtraction,
    PaddleOCRExtractor,
    bind_candidate_claim,
)


class FakeResult:
    def __init__(self, payload):
        self.json = {"res": payload}


class FakeEngine:
    def __init__(self, results):
        self.results = results
        self.seen_path = None
        self.seen_bytes = None
        self.path_existed_during_predict = False

    def predict(self, path):
        self.seen_path = path
        self.path_existed_during_predict = os.path.exists(path)
        with open(path, "rb") as handle:
            self.seen_bytes = handle.read()
        return self.results


class DocumentExtractionTests(unittest.TestCase):
    def test_paddleocr_3x_result_is_provenance_bound_and_non_authoritative(self):
        source = b"fake-image-bytes"
        engine = FakeEngine(
            [
                FakeResult(
                    {
                        "rec_texts": ["AJ", "membership $100", "call Fri"],
                        "rec_scores": [0.99, 0.95, 0.91],
                        "rec_polys": [
                            [[10, 10], [30, 10], [30, 20], [10, 20]],
                            [[10, 30], [120, 30], [120, 45], [10, 45]],
                            [[10, 50], [80, 50], [80, 65], [10, 65]],
                        ],
                        "page_index": 0,
                    }
                )
            ]
        )
        extraction = PaddleOCRExtractor(engine=engine).extract(
            source,
            source_name="gym-note.jpg",
            media_type="image/jpeg",
        )

        self.assertEqual(extraction.source_sha256, hashlib.sha256(source).hexdigest())
        self.assertEqual(extraction.authority, CANDIDATE_EVIDENCE)
        self.assertFalse(extraction.is_authoritative)
        self.assertEqual(extraction.raw_text, "AJ\nmembership $100\ncall Fri")
        self.assertEqual(extraction.spans[1].polygon[0], (10.0, 30.0))
        self.assertEqual(extraction.spans[1].bounding_box, (10.0, 30.0, 120.0, 45.0))
        self.assertEqual(extraction.spans[1].page_index, 0)
        self.assertTrue(extraction.extraction_digest.startswith("sha256:"))
        self.assertTrue(engine.path_existed_during_predict)
        self.assertEqual(engine.seen_bytes, source)
        self.assertFalse(os.path.exists(engine.seen_path))

    def test_empty_recognized_strings_are_skipped_but_alignment_is_preserved(self):
        engine = FakeEngine(
            [
                FakeResult(
                    {
                        "rec_texts": ["", "real text"],
                        "rec_scores": [0.2, 0.93],
                        "rec_polys": [
                            [[0, 0], [1, 0], [1, 1], [0, 1]],
                            [[2, 0], [6, 0], [6, 1], [2, 1]],
                        ],
                    }
                )
            ]
        )
        extraction = PaddleOCRExtractor(engine=engine).extract(
            b"note",
            source_name="note.jpg",
            media_type="image/jpeg",
        )
        self.assertEqual([span.text for span in extraction.spans], ["real text"])
        self.assertEqual(extraction.spans[0].polygon[0], (2.0, 0.0))

    def test_confidence_threshold_filters_spans_without_changing_source_binding(self):
        source = b"note"
        engine = FakeEngine(
            [
                FakeResult(
                    {
                        "rec_texts": ["high", "low"],
                        "rec_scores": [0.97, 0.40],
                        "rec_polys": [
                            [[0, 0], [1, 0], [1, 1], [0, 1]],
                            [[2, 0], [3, 0], [3, 1], [2, 1]],
                        ],
                    }
                )
            ]
        )
        extraction = PaddleOCRExtractor(engine=engine, min_confidence=0.8).extract(
            source,
            source_name="note.png",
            media_type="image/png",
        )
        self.assertEqual([span.text for span in extraction.spans], ["high"])
        self.assertEqual(extraction.source_sha256, hashlib.sha256(source).hexdigest())

    def test_multiple_pages_preserve_page_indices_and_order(self):
        engine = FakeEngine(
            [
                FakeResult(
                    {
                        "rec_texts": ["page zero"],
                        "rec_scores": [0.9],
                        "rec_polys": [[[0, 0], [2, 0], [2, 2], [0, 2]]],
                        "page_index": 0,
                    }
                ),
                FakeResult(
                    {
                        "rec_texts": ["page one"],
                        "rec_scores": [0.92],
                        "rec_polys": [[[0, 0], [2, 0], [2, 2], [0, 2]]],
                        "page_index": 1,
                    }
                ),
            ]
        )
        extraction = PaddleOCRExtractor(engine=engine).extract(
            b"fake-pdf",
            source_name="notes.pdf",
            media_type="application/pdf",
        )
        self.assertEqual(extraction.raw_text, "page zero\npage one")
        self.assertEqual([span.page_index for span in extraction.spans], [0, 1])

    def test_candidate_claim_is_bound_to_source_and_cannot_self_promote(self):
        engine = FakeEngine(
            [
                FakeResult(
                    {
                        "rec_texts": ["AJ", "membership $100"],
                        "rec_scores": [0.99, 0.95],
                        "rec_polys": [
                            [[0, 0], [1, 0], [1, 1], [0, 1]],
                            [[0, 2], [5, 2], [5, 3], [0, 3]],
                        ],
                    }
                )
            ]
        )
        extraction = PaddleOCRExtractor(engine=engine).extract(
            b"note",
            source_name="note.jpg",
            media_type="image/jpeg",
        )
        claim = bind_candidate_claim(
            extraction,
            text="AJ discussed a $100 membership",
            span_indices=(0, 1),
        )
        self.assertEqual(claim.source_sha256, extraction.source_sha256)
        self.assertEqual(claim.extraction_digest, extraction.extraction_digest)
        self.assertEqual(claim.span_indices, (0, 1))
        self.assertEqual(claim.authority, UNVERIFIED_CANDIDATE)
        self.assertFalse(claim.is_authoritative)

        with self.assertRaises(ValueError):
            type(claim)(
                text=claim.text,
                source_sha256=claim.source_sha256,
                extraction_digest=claim.extraction_digest,
                span_indices=claim.span_indices,
                extraction_provider=claim.extraction_provider,
                authority="authoritative",
            )

    def test_extraction_digest_changes_when_same_source_spans_are_reordered(self):
        source_digest = hashlib.sha256(b"same-source").hexdigest()
        span_a = PaddleOCRExtractor(
            engine=FakeEngine(
                [
                    FakeResult(
                        {
                            "rec_texts": ["A", "B"],
                            "rec_scores": [0.9, 0.8],
                            "rec_polys": [
                                [[0, 0], [1, 0], [1, 1], [0, 1]],
                                [[2, 0], [3, 0], [3, 1], [2, 1]],
                            ],
                        }
                    )
                ]
            )
        ).extract(b"same-source", source_name="note.png", media_type="image/png")
        span_b = DocumentExtraction(
            source_sha256=source_digest,
            source_name=span_a.source_name,
            media_type=span_a.media_type,
            provider=span_a.provider,
            provider_profile=span_a.provider_profile,
            spans=tuple(reversed(span_a.spans)),
            raw_text="B\nA",
        )
        self.assertEqual(span_a.source_sha256, span_b.source_sha256)
        self.assertNotEqual(span_a.extraction_digest, span_b.extraction_digest)

    def test_candidate_claim_rejects_unknown_span(self):
        extraction = DocumentExtraction(
            source_sha256=hashlib.sha256(b"x").hexdigest(),
            source_name="note.png",
            media_type="image/png",
            provider="paddleocr",
            provider_profile="PP-OCRv6",
            spans=(),
            raw_text="",
        )
        with self.assertRaisesRegex(ValueError, "unknown OCR span"):
            bind_candidate_claim(
                extraction,
                text="invented claim",
                span_indices=(0,),
            )

    def test_mismatched_provider_arrays_fail_closed(self):
        engine = FakeEngine(
            [
                FakeResult(
                    {
                        "rec_texts": ["one", "two"],
                        "rec_scores": [0.9],
                        "rec_polys": [[[0, 0], [1, 0], [1, 1], [0, 1]]],
                    }
                )
            ]
        )
        with self.assertRaisesRegex(ValueError, "field lengths do not match"):
            PaddleOCRExtractor(engine=engine).extract(
                b"note",
                source_name="note.png",
                media_type="image/png",
            )

    def test_missing_required_provider_fields_fail_closed(self):
        engine = FakeEngine([FakeResult({"rec_texts": ["one"], "rec_scores": [0.9]})])
        with self.assertRaisesRegex(ValueError, "must contain rec_texts"):
            PaddleOCRExtractor(engine=engine).extract(
                b"note",
                source_name="note.png",
                media_type="image/png",
            )

    def test_invalid_confidence_fails_closed(self):
        engine = FakeEngine(
            [
                FakeResult(
                    {
                        "rec_texts": ["one"],
                        "rec_scores": [1.1],
                        "rec_polys": [[[0, 0], [1, 0], [1, 1], [0, 1]]],
                    }
                )
            ]
        )
        with self.assertRaisesRegex(ValueError, "confidence"):
            PaddleOCRExtractor(engine=engine).extract(
                b"note",
                source_name="note.png",
                media_type="image/png",
            )

    def test_unsupported_media_type_is_rejected_before_provider_execution(self):
        engine = FakeEngine([])
        with self.assertRaisesRegex(ValueError, "unsupported OCR media_type"):
            PaddleOCRExtractor(engine=engine).extract(
                b"note",
                source_name="note.heic",
                media_type="image/heic",
            )
        self.assertIsNone(engine.seen_path)

    def test_source_size_limit_is_enforced_before_provider_execution(self):
        engine = FakeEngine([])
        with self.assertRaisesRegex(ValueError, "size limit"):
            PaddleOCRExtractor(engine=engine, max_source_bytes=3).extract(
                b"four",
                source_name="note.png",
                media_type="image/png",
            )
        self.assertIsNone(engine.seen_path)

    def test_result_count_limit_bounds_lazy_provider_output(self):
        def results():
            payload = {
                "rec_texts": ["one"],
                "rec_scores": [0.9],
                "rec_polys": [[[0, 0], [1, 0], [1, 1], [0, 1]]],
            }
            yield FakeResult(payload)
            yield FakeResult(payload)

        engine = FakeEngine(results())
        with self.assertRaisesRegex(ValueError, "result count"):
            PaddleOCRExtractor(engine=engine, max_results=1).extract(
                b"note",
                source_name="note.png",
                media_type="image/png",
            )

    def test_bad_candidate_span_type_fails_closed_as_value_error(self):
        extraction = DocumentExtraction(
            source_sha256=hashlib.sha256(b"x").hexdigest(),
            source_name="note.png",
            media_type="image/png",
            provider="paddleocr",
            provider_profile="test",
            spans=(),
            raw_text="",
        )
        with self.assertRaisesRegex(ValueError, "non-negative integers"):
            bind_candidate_claim(
                extraction,
                text="bad claim",
                span_indices=("0",),
            )

    def test_empty_source_is_rejected_before_provider_execution(self):
        engine = FakeEngine([])
        with self.assertRaisesRegex(ValueError, "non-empty bytes"):
            PaddleOCRExtractor(engine=engine).extract(
                b"",
                source_name="note.png",
                media_type="image/png",
            )
        self.assertIsNone(engine.seen_path)


if __name__ == "__main__":
    unittest.main()
