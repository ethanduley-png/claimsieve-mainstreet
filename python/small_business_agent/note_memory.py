from __future__ import annotations

import re
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Iterable

from claimsieve_ref.canonical import canonical_bytes, digest as canonical_digest
from .document_extraction import DocumentExtraction

UNVERIFIED_NOTE_CANDIDATE = "unverified_note_candidate"
NON_AUTHORITATIVE_INTERPRETATION = "non_authoritative_interpretation"
VALIDATION_DECISION = "validation_decision"
ACCEPTED_BUSINESS_KNOWLEDGE = "accepted_business_knowledge"


class NoteCandidateKind(str, Enum):
    TASK = "task"
    MONEY = "money"
    DATE = "date"
    CONTACT = "contact"
    PERSON = "person"
    COMMITMENT = "commitment"
    FACT = "fact"
    INSTRUCTION = "instruction"


class ValidationDisposition(str, Enum):
    ACCEPT = "accept"
    REJECT = "reject"


def _text(name: str, value: str, limit: int = 262_144) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be non-empty")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError(f"{name} must contain valid Unicode") from exc
    if len(encoded) > limit:
        raise ValueError(f"{name} exceeds the text limit")


def _digest(name: str, value: str, *, prefixed: bool = True) -> None:
    pattern = r"sha256:[0-9a-f]{64}" if prefixed else r"[0-9a-f]{64}"
    if not isinstance(value, str) or re.fullmatch(pattern, value) is None:
        raise ValueError(f"{name} must be a SHA-256 digest")


def _hex(value: str) -> str:
    return value.encode("utf-8").hex()


def _utc(value: str) -> str:
    _text("reviewed_at", value, 128)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("reviewed_at must be ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("reviewed_at must include a timezone")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True)
class NoteCandidate:
    kind: NoteCandidateKind
    text: str
    normalized_value: str
    semantic_key: str
    source_sha256: str
    extraction_digest: str
    extraction_provider: str
    span_indices: tuple[int, ...]
    confidence_basis_points: int
    material: bool
    requires_human_review: bool
    authority: str = UNVERIFIED_NOTE_CANDIDATE

    def __post_init__(self) -> None:
        if not isinstance(self.kind, NoteCandidateKind):
            raise ValueError("kind must be a NoteCandidateKind")
        for name in ("text", "normalized_value", "semantic_key", "extraction_provider"):
            _text(name, getattr(self, name))
        _digest("source_sha256", self.source_sha256, prefixed=False)
        _digest("extraction_digest", self.extraction_digest)
        if not isinstance(self.span_indices, tuple) or not self.span_indices:
            raise ValueError("span_indices must be a non-empty immutable tuple")
        if len(set(self.span_indices)) != len(self.span_indices) or any(
            not isinstance(i, int) or isinstance(i, bool) or i < 0 for i in self.span_indices
        ):
            raise ValueError("span_indices must contain unique non-negative integers")
        if not isinstance(self.confidence_basis_points, int) or isinstance(self.confidence_basis_points, bool) or not 0 <= self.confidence_basis_points <= 10_000:
            raise ValueError("confidence_basis_points must be in [0, 10000]")
        if not isinstance(self.material, bool) or not isinstance(self.requires_human_review, bool):
            raise ValueError("material and requires_human_review must be booleans")
        if self.material and not self.requires_human_review:
            raise ValueError("material note candidates must require human review")
        if self.authority != UNVERIFIED_NOTE_CANDIDATE:
            raise ValueError("note candidates cannot self-promote")

    def canonical_record(self) -> dict:
        return {
            "schema": "mainstreet.note-candidate.v1", "kind": self.kind.value,
            "text_utf8_hex": _hex(self.text), "normalized_value_utf8_hex": _hex(self.normalized_value),
            "semantic_key_utf8_hex": _hex(self.semantic_key), "source_sha256": self.source_sha256,
            "extraction_digest": self.extraction_digest, "extraction_provider_utf8_hex": _hex(self.extraction_provider),
            "span_indices": list(self.span_indices), "confidence_basis_points": self.confidence_basis_points,
            "material": self.material, "requires_human_review": self.requires_human_review, "authority": self.authority,
        }

    @property
    def candidate_id(self) -> str:
        return canonical_digest(self.canonical_record())

    @property
    def execution_authority(self) -> bool:
        return False


@dataclass(frozen=True)
class NoteInterpretation:
    source_sha256: str
    extraction_digest: str
    interpreter_id: str
    interpreter_version: str
    candidates: tuple[NoteCandidate, ...]
    authority: str = NON_AUTHORITATIVE_INTERPRETATION

    def __post_init__(self) -> None:
        _digest("source_sha256", self.source_sha256, prefixed=False)
        _digest("extraction_digest", self.extraction_digest)
        _text("interpreter_id", self.interpreter_id, 1024)
        _text("interpreter_version", self.interpreter_version, 1024)
        if not isinstance(self.candidates, tuple) or not all(isinstance(c, NoteCandidate) for c in self.candidates):
            raise ValueError("candidates must be an immutable tuple of NoteCandidate values")
        if len({c.candidate_id for c in self.candidates}) != len(self.candidates):
            raise ValueError("duplicate note candidates are not allowed")
        if any(c.source_sha256 != self.source_sha256 or c.extraction_digest != self.extraction_digest for c in self.candidates):
            raise ValueError("note candidate extraction digest must match interpretation")
        if self.authority != NON_AUTHORITATIVE_INTERPRETATION:
            raise ValueError("note interpretation must remain non-authoritative")

    @property
    def interpretation_digest(self) -> str:
        return canonical_digest({
            "schema": "mainstreet.note-interpretation.v1", "source_sha256": self.source_sha256,
            "extraction_digest": self.extraction_digest, "interpreter_id_utf8_hex": _hex(self.interpreter_id),
            "interpreter_version_utf8_hex": _hex(self.interpreter_version),
            "candidate_ids": [c.candidate_id for c in self.candidates], "authority": self.authority,
        })

    @property
    def execution_authority(self) -> bool:
        return False


@dataclass(frozen=True)
class ValidationRecord:
    candidate_id: str
    interpretation_digest: str
    reviewer_id: str
    reviewer_kind: str
    reviewed_at: str
    disposition: ValidationDisposition
    reason: str
    authority: str = VALIDATION_DECISION

    def __post_init__(self) -> None:
        _digest("candidate_id", self.candidate_id)
        _digest("interpretation_digest", self.interpretation_digest)
        _text("reviewer_id", self.reviewer_id, 1024)
        _text("reviewer_kind", self.reviewer_kind, 32)
        if self.reviewer_kind != "human":
            raise ValueError("note promotion currently requires a human reviewer")
        object.__setattr__(self, "reviewed_at", _utc(self.reviewed_at))
        if not isinstance(self.disposition, ValidationDisposition):
            raise ValueError("disposition must be a ValidationDisposition")
        _text("reason", self.reason, 8192)
        if self.authority != VALIDATION_DECISION:
            raise ValueError("validation record authority is fixed")

    @property
    def validation_digest(self) -> str:
        return canonical_digest({
            "schema": "mainstreet.note-validation.v1", "candidate_id": self.candidate_id,
            "interpretation_digest": self.interpretation_digest, "reviewer_id_utf8_hex": _hex(self.reviewer_id),
            "reviewer_kind": self.reviewer_kind, "reviewed_at": self.reviewed_at,
            "disposition": self.disposition.value, "reason_utf8_hex": _hex(self.reason), "authority": self.authority,
        })


@dataclass(frozen=True)
class AcceptedKnowledgeRecord:
    candidate_id: str
    interpretation_digest: str
    validation_digest: str
    semantic_key: str
    kind: NoteCandidateKind
    text: str
    normalized_value: str
    source_sha256: str
    extraction_digest: str
    reviewed_at: str
    authority: str = ACCEPTED_BUSINESS_KNOWLEDGE

    def __post_init__(self) -> None:
        for name in ("candidate_id", "interpretation_digest", "validation_digest", "extraction_digest"):
            _digest(name, getattr(self, name))
        _digest("source_sha256", self.source_sha256, prefixed=False)
        for name in ("semantic_key", "text", "normalized_value"):
            _text(name, getattr(self, name))
        if not isinstance(self.kind, NoteCandidateKind):
            raise ValueError("kind must be a NoteCandidateKind")
        object.__setattr__(self, "reviewed_at", _utc(self.reviewed_at))
        if self.authority != ACCEPTED_BUSINESS_KNOWLEDGE:
            raise ValueError("accepted knowledge authority is fixed")

    @property
    def knowledge_id(self) -> str:
        return canonical_digest({
            "schema": "mainstreet.accepted-note-knowledge.v1", "candidate_id": self.candidate_id,
            "interpretation_digest": self.interpretation_digest, "validation_digest": self.validation_digest,
            "semantic_key_utf8_hex": _hex(self.semantic_key), "kind": self.kind.value, "text_utf8_hex": _hex(self.text),
            "normalized_value_utf8_hex": _hex(self.normalized_value), "source_sha256": self.source_sha256,
            "extraction_digest": self.extraction_digest, "reviewed_at": self.reviewed_at, "authority": self.authority,
        })

    @property
    def execution_authority(self) -> bool:
        return False


_INJECTION = ("ignore previous instructions", "ignore all previous", "system prompt", "developer message", "reveal your prompt", "bypass claimsieve", "disable claimsieve")
_TASKS = ("call ", "email ", "text ", "send ", "follow up", "book ", "schedule ", "order ", "pay ", "review ", "prepare ", "remind ")
_COMMITMENTS = ("promised", "agreed", "committed", "owe ", "owes ", "due ")
_MONEY = re.compile(r"(?<!\w)\$\s*([0-9]{1,9}(?:\.[0-9]{1,2})?)\b")
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}\b")
_PHONE = re.compile(r"(?<!\d)(?:\+?1[-.\s]?)?\(?([2-9][0-9]{2})\)?[-.\s]?([2-9][0-9]{2})[-.\s]?([0-9]{4})(?!\d)")
_DATE = re.compile(r"\b(?:mon(?:day)?|tue(?:sday)?|wed(?:nesday)?|thu(?:rsday)?|fri(?:day)?|sat(?:urday)?|sun(?:day)?|today|tomorrow|\d{4}-\d{2}-\d{2})\b", re.I)
_PERSON = re.compile(r"^(?:name|customer|client|vendor|contact)\s*:\s*(.+)$", re.I)


class RuleBasedNoteInterpreter:
    """High-precision reference interpreter; model-based interpreters must emit the same closed contract."""

    def __init__(self, interpreter_id: str = "mainstreet.rule-note-interpreter", interpreter_version: str = "1") -> None:
        _text("interpreter_id", interpreter_id, 1024)
        _text("interpreter_version", interpreter_version, 1024)
        self.interpreter_id, self.interpreter_version = interpreter_id, interpreter_version

    def _make(self, extraction: DocumentExtraction, index: int, kind: NoteCandidateKind, text: str, value: str, key: str, confidence: int, material: bool) -> NoteCandidate:
        return NoteCandidate(kind, text, value, key, extraction.source_sha256, extraction.extraction_digest, extraction.provider, (index,), confidence, material, material)

    def interpret(self, extraction: DocumentExtraction) -> NoteInterpretation:
        items: list[NoteCandidate] = []
        for index, span in enumerate(extraction.spans):
            text, lower = span.text.strip(), span.text.strip().casefold()
            confidence = max(0, min(10_000, int(round(float(span.confidence) * 10_000))))
            produced = False
            if any(marker in lower for marker in _INJECTION):
                items.append(self._make(extraction, index, NoteCandidateKind.INSTRUCTION, text, text, f"instruction:{index}", confidence, True)); produced = True
            person = _PERSON.match(text)
            if person and person.group(1).strip():
                label = text.split(":", 1)[0].strip().casefold()
                items.append(self._make(extraction, index, NoteCandidateKind.PERSON, text, person.group(1).strip(), f"person:{label}", confidence, True)); produced = True
            for email in _EMAIL.findall(text):
                value = email.casefold(); items.append(self._make(extraction, index, NoteCandidateKind.CONTACT, text, value, f"contact:email:{value}", confidence, True)); produced = True
            for match in _PHONE.finditer(text):
                value = "+1" + "".join(match.groups()); items.append(self._make(extraction, index, NoteCandidateKind.CONTACT, text, value, f"contact:phone:{value}", confidence, True)); produced = True
            for match in _MONEY.finditer(text):
                value = match.group(1) if "." in match.group(1) else match.group(1) + ".00"
                label = re.sub(r"[^a-z0-9]+", "-", lower[:match.start()].strip()).strip("-") or "unspecified"
                items.append(self._make(extraction, index, NoteCandidateKind.MONEY, text, value, f"money:{label}", confidence, True)); produced = True
            date = _DATE.search(text)
            if date:
                key = re.sub(r"[^a-z0-9]+", "-", lower).strip("-")[:80]
                items.append(self._make(extraction, index, NoteCandidateKind.DATE, text, date.group(0).casefold(), f"date:{key}", confidence, True)); produced = True
            if lower.startswith(_TASKS):
                items.append(self._make(extraction, index, NoteCandidateKind.TASK, text, text, f"task:{index}", confidence, True)); produced = True
            if any(marker in lower for marker in _COMMITMENTS):
                items.append(self._make(extraction, index, NoteCandidateKind.COMMITMENT, text, text, f"commitment:{index}", confidence, True)); produced = True
            if not produced:
                items.append(self._make(extraction, index, NoteCandidateKind.FACT, text, text, f"fact:{index}", confidence, False))
        unique: dict[str, NoteCandidate] = {}
        for item in items:
            unique.setdefault(item.candidate_id, item)
        return NoteInterpretation(extraction.source_sha256, extraction.extraction_digest, self.interpreter_id, self.interpreter_version, tuple(unique.values()))


def validate_note_interpretation_binding(interpretation: NoteInterpretation, extraction: DocumentExtraction) -> None:
    if interpretation.source_sha256 != extraction.source_sha256 or interpretation.extraction_digest != extraction.extraction_digest:
        raise ValueError("note interpretation extraction digest mismatch")
    for candidate in interpretation.candidates:
        if candidate.extraction_provider != extraction.provider or any(i >= len(extraction.spans) for i in candidate.span_indices):
            raise ValueError("note candidate extraction binding mismatch")


def promote_note_candidate(interpretation: NoteInterpretation, candidate: NoteCandidate, validation: ValidationRecord) -> AcceptedKnowledgeRecord:
    if candidate.candidate_id not in {c.candidate_id for c in interpretation.candidates}:
        raise ValueError("candidate is not part of the interpretation")
    if validation.candidate_id != candidate.candidate_id or validation.interpretation_digest != interpretation.interpretation_digest:
        raise ValueError("validation candidate binding mismatch")
    if validation.reviewer_id == interpretation.interpreter_id:
        raise ValueError("interpreter cannot validate its own note candidate")
    if validation.disposition != ValidationDisposition.ACCEPT:
        raise ValueError("rejected candidate cannot be promoted")
    if candidate.kind == NoteCandidateKind.INSTRUCTION:
        raise ValueError("instruction-like note content remains quarantined and cannot be promoted")
    return AcceptedKnowledgeRecord(candidate.candidate_id, interpretation.interpretation_digest, validation.validation_digest, candidate.semantic_key, candidate.kind, candidate.text, candidate.normalized_value, candidate.source_sha256, candidate.extraction_digest, validation.reviewed_at)


def detect_knowledge_conflicts(records: Iterable[AcceptedKnowledgeRecord]) -> dict[str, tuple[AcceptedKnowledgeRecord, ...]]:
    grouped: dict[str, list[AcceptedKnowledgeRecord]] = {}
    for record in records:
        grouped.setdefault(record.semantic_key, []).append(record)
    return {key: tuple(items) for key, items in grouped.items() if len({item.normalized_value for item in items}) > 1}


class NoteMemoryStore:
    """SQLite metadata store. Original note bytes remain in immutable object storage; accepted knowledge is never execution authority."""

    def __init__(self, path: str | Path) -> None:
        self._conn = sqlite3.connect(str(path))
        self._conn.execute("PRAGMA journal_mode=WAL"); self._conn.execute("PRAGMA synchronous=FULL"); self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.executescript("""
        CREATE TABLE IF NOT EXISTS interpretations(id TEXT PRIMARY KEY, extraction TEXT NOT NULL, source TEXT NOT NULL, interpreter TEXT NOT NULL, record BLOB NOT NULL);
        CREATE TABLE IF NOT EXISTS candidates(id TEXT PRIMARY KEY, interpretation TEXT NOT NULL, semantic_key TEXT NOT NULL, kind TEXT NOT NULL, text TEXT NOT NULL, value TEXT NOT NULL, source TEXT NOT NULL, extraction TEXT NOT NULL, record BLOB NOT NULL, FOREIGN KEY(interpretation) REFERENCES interpretations(id));
        CREATE TABLE IF NOT EXISTS validations(id TEXT PRIMARY KEY, candidate TEXT NOT NULL, interpretation TEXT NOT NULL, disposition TEXT NOT NULL, reviewer TEXT NOT NULL, record BLOB NOT NULL, FOREIGN KEY(candidate) REFERENCES candidates(id), FOREIGN KEY(interpretation) REFERENCES interpretations(id));
        CREATE TABLE IF NOT EXISTS knowledge(id TEXT PRIMARY KEY, candidate TEXT NOT NULL, semantic_key TEXT NOT NULL, value TEXT NOT NULL, record BLOB NOT NULL, FOREIGN KEY(candidate) REFERENCES candidates(id));
        """); self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def _put(self, table: str, key: str, columns: tuple[str, ...], values: tuple) -> None:
        row = self._conn.execute(f"SELECT {', '.join(columns)} FROM {table} WHERE id = ?", (key,)).fetchone()
        if row is not None:
            if tuple(row) != tuple(values): raise ValueError(f"immutable {table} record conflict")
            return
        marks = ",".join("?" for _ in range(len(values) + 1))
        self._conn.execute(f"INSERT INTO {table}(id,{','.join(columns)}) VALUES({marks})", (key, *values))

    def record_interpretation(self, interpretation: NoteInterpretation) -> None:
        with self._conn:
            self._put("interpretations", interpretation.interpretation_digest, ("extraction","source","interpreter","record"), (interpretation.extraction_digest, interpretation.source_sha256, interpretation.interpreter_id, canonical_bytes({"digest": interpretation.interpretation_digest})))
            for c in interpretation.candidates:
                self._put("candidates", c.candidate_id, ("interpretation","semantic_key","kind","text","value","source","extraction","record"), (interpretation.interpretation_digest, c.semantic_key, c.kind.value, c.text, c.normalized_value, c.source_sha256, c.extraction_digest, canonical_bytes(c.canonical_record())))

    def record_validation(self, validation: ValidationRecord) -> None:
        with self._conn:
            self._put("validations", validation.validation_digest, ("candidate","interpretation","disposition","reviewer","record"), (validation.candidate_id, validation.interpretation_digest, validation.disposition.value, validation.reviewer_id, canonical_bytes({"digest": validation.validation_digest})))

    def record_accepted_knowledge(self, record: AcceptedKnowledgeRecord) -> None:
        with self._conn:
            candidate = self._conn.execute("SELECT interpretation,semantic_key,kind,text,value,source,extraction FROM candidates WHERE id=?", (record.candidate_id,)).fetchone()
            expected = (record.interpretation_digest, record.semantic_key, record.kind.value, record.text, record.normalized_value, record.source_sha256, record.extraction_digest)
            if candidate is None or tuple(candidate) != expected:
                raise ValueError("accepted knowledge does not exactly match the persisted candidate")
            validation = self._conn.execute("SELECT disposition,interpretation FROM validations WHERE id=? AND candidate=?", (record.validation_digest, record.candidate_id)).fetchone()
            if validation is None or validation != (ValidationDisposition.ACCEPT.value, record.interpretation_digest):
                raise ValueError("accepted knowledge requires a persisted accepting validation")
            self._put("knowledge", record.knowledge_id, ("candidate","semantic_key","value","record"), (record.candidate_id, record.semantic_key, record.normalized_value, canonical_bytes({"digest": record.knowledge_id})))

    def conflicts(self) -> dict[str, tuple[str, ...]]:
        grouped: dict[str, set[str]] = {}
        for key, value in self._conn.execute("SELECT semantic_key,value FROM knowledge ORDER BY semantic_key,value"):
            grouped.setdefault(key, set()).add(value)
        return {key: tuple(sorted(values)) for key, values in grouped.items() if len(values) > 1}
