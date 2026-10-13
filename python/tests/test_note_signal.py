import hashlib
import unittest

from small_business_agent.document_extraction import DocumentExtraction, ExtractedSpan
from small_business_agent.note_memory import (
    NoteCandidateKind,
    RuleBasedNoteInterpreter,
    ValidationDisposition,
    ValidationRecord,
    promote_note_candidate,
)
from small_business_agent.note_signal import accepted_note_to_signal


class NoteSignalTests(unittest.TestCase):
    def _accepted_money_record(self):
        span = ExtractedSpan(
            text="membership $100",
            confidence=0.95,
            polygon=((0, 0), (1, 0), (1, 1), (0, 1)),
        )
        extraction = DocumentExtraction(
            source_sha256=hashlib.sha256(b"note").hexdigest(),
            source_name="note.jpg",
            media_type="image/jpeg",
            provider="paddleocr",
            provider_profile="test",
            spans=(span,),
            raw_text=span.text,
        )
        interpretation = RuleBasedNoteInterpreter().interpret(extraction)
        candidate = next(
            item for item in interpretation.candidates if item.kind == NoteCandidateKind.MONEY
        )
        validation = ValidationRecord(
            candidate_id=candidate.candidate_id,
            interpretation_digest=interpretation.interpretation_digest,
            reviewer_id="owner",
            reviewer_kind="human",
            reviewed_at="2026-08-28T20:00:00Z",
            disposition=ValidationDisposition.ACCEPT,
            reason="verified against price sheet",
        )
        return promote_note_candidate(interpretation, candidate, validation)

    def test_accepted_note_becomes_informational_signal_with_provenance(self):
        record = self._accepted_money_record()
        signal = accepted_note_to_signal(record, severity=2)
        self.assertEqual(signal.kind, "accepted_note_money")
        self.assertEqual(signal.title, "membership $100")
        self.assertEqual(signal.metadata["knowledge_id"], record.knowledge_id)
        self.assertEqual(signal.metadata["source_sha256"], record.source_sha256)
        self.assertTrue(signal.metadata["content_is_data"])
        self.assertFalse(signal.metadata["execution_authority"])

    def test_signal_adapter_rejects_invalid_severity(self):
        record = self._accepted_money_record()
        with self.assertRaisesRegex(ValueError, "severity"):
            accepted_note_to_signal(record, severity=6)


if __name__ == "__main__":
    unittest.main()
