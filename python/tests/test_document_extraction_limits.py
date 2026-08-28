import hashlib
import unittest

from small_business_agent.document_extraction import (
    MAX_SOURCE_NAME_BYTES,
    MAX_SPAN_TEXT_BYTES,
    DocumentExtraction,
    ExtractedSpan,
)


class DocumentExtractionLimitTests(unittest.TestCase):
    def test_oversized_span_text_fails_before_canonicalization(self):
        with self.assertRaisesRegex(ValueError, "configured text limit"):
            ExtractedSpan(
                text="x" * (MAX_SPAN_TEXT_BYTES + 1),
                confidence=0.9,
                polygon=((0, 0), (1, 0), (1, 1), (0, 1)),
            )

    def test_oversized_source_name_is_rejected(self):
        span = ExtractedSpan(
            text="ok",
            confidence=0.9,
            polygon=((0, 0), (1, 0), (1, 1), (0, 1)),
        )
        with self.assertRaisesRegex(ValueError, "source_name exceeds"):
            DocumentExtraction(
                source_sha256=hashlib.sha256(b"note").hexdigest(),
                source_name="n" * (MAX_SOURCE_NAME_BYTES + 1),
                media_type="image/png",
                provider="paddleocr",
                provider_profile="test",
                spans=(span,),
                raw_text="ok",
            )

    def test_boundary_sized_span_can_still_hash(self):
        span = ExtractedSpan(
            text="x" * MAX_SPAN_TEXT_BYTES,
            confidence=0.9,
            polygon=((0, 0), (1, 0), (1, 1), (0, 1)),
        )
        extraction = DocumentExtraction(
            source_sha256=hashlib.sha256(b"note").hexdigest(),
            source_name="note.png",
            media_type="image/png",
            provider="paddleocr",
            provider_profile="test",
            spans=(span,),
            raw_text=span.text,
        )
        self.assertTrue(extraction.extraction_digest.startswith("sha256:"))


if __name__ == "__main__":
    unittest.main()
