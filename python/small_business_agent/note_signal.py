from __future__ import annotations

from .brain import BusinessSignal
from .note_memory import AcceptedKnowledgeRecord


def accepted_note_to_signal(
    record: AcceptedKnowledgeRecord,
    *,
    severity: int = 1,
) -> BusinessSignal:
    """Expose accepted note knowledge to MainStreet planning as information only.

    The resulting signal carries provenance and an explicit no-execution marker.
    Any consequential action proposed from this information still requires the
    ordinary ClaimSieve authority path.
    """
    if not isinstance(record, AcceptedKnowledgeRecord):
        raise ValueError("record must be AcceptedKnowledgeRecord")
    if not isinstance(severity, int) or isinstance(severity, bool) or not 0 <= severity <= 5:
        raise ValueError("severity must be an integer from 0 to 5")
    signal = BusinessSignal(
        signal_id=f"accepted-note:{record.knowledge_id}",
        kind=f"accepted_note_{record.kind.value}",
        title=record.text,
        severity=severity,
        source=f"accepted-note:{record.knowledge_id}",
        metadata={
            "knowledge_id": record.knowledge_id,
            "candidate_id": record.candidate_id,
            "interpretation_digest": record.interpretation_digest,
            "validation_digest": record.validation_digest,
            "source_sha256": record.source_sha256,
            "extraction_digest": record.extraction_digest,
            "semantic_key": record.semantic_key,
            "normalized_value": record.normalized_value,
            "content_is_data": True,
            "execution_authority": False,
        },
    )
    signal.validate()
    return signal
