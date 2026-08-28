from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from math import isfinite
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any, Protocol


CANDIDATE_EVIDENCE = "candidate_evidence"
UNVERIFIED_CANDIDATE = "unverified_candidate"


def _validate_sha256(value: str, *, field_name: str) -> None:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or value.lower() != value
        or any(ch not in "0123456789abcdef" for ch in value)
    ):
        raise ValueError(f"{field_name} must be a lowercase SHA-256 hex digest")


def sha256_hex(payload: bytes) -> str:
    if not isinstance(payload, bytes) or not payload:
        raise ValueError("source payload must be non-empty bytes")
    return sha256(payload).hexdigest()


@dataclass(frozen=True)
class ExtractedSpan:
    text: str
    confidence: float
    polygon: tuple[tuple[float, float], ...]
    page_index: int | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.text, str) or not self.text.strip():
            raise ValueError("extracted span text must be non-empty")
        if not isinstance(self.confidence, (int, float)) or not isfinite(float(self.confidence)):
            raise ValueError("extracted span confidence must be finite")
        if not 0.0 <= float(self.confidence) <= 1.0:
            raise ValueError("extracted span confidence must be in [0, 1]")
        if len(self.polygon) < 4:
            raise ValueError("extracted span polygon must contain at least four points")
        for point in self.polygon:
            if len(point) != 2:
                raise ValueError("polygon points must be x/y pairs")
            if not all(isinstance(value, (int, float)) and isfinite(float(value)) for value in point):
                raise ValueError("polygon coordinates must be finite numbers")
        if self.page_index is not None and (
            not isinstance(self.page_index, int)
            or isinstance(self.page_index, bool)
            or self.page_index < 0
        ):
            raise ValueError("page_index must be a non-negative integer or None")

    @property
    def bounding_box(self) -> tuple[float, float, float, float]:
        xs = [float(point[0]) for point in self.polygon]
        ys = [float(point[1]) for point in self.polygon]
        return min(xs), min(ys), max(xs), max(ys)


@dataclass(frozen=True)
class DocumentExtraction:
    source_sha256: str
    source_name: str
    media_type: str
    provider: str
    provider_profile: str
    spans: tuple[ExtractedSpan, ...]
    raw_text: str
    authority: str = CANDIDATE_EVIDENCE

    def __post_init__(self) -> None:
        _validate_sha256(self.source_sha256, field_name="source_sha256")
        for field_name in ("source_name", "media_type", "provider", "provider_profile"):
            value = getattr(self, field_name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{field_name} must be non-empty")
        if self.authority != CANDIDATE_EVIDENCE:
            raise ValueError("OCR extraction authority must remain candidate_evidence")
        expected_text = "\n".join(span.text for span in self.spans)
        if self.raw_text != expected_text:
            raise ValueError("raw_text must exactly match the ordered extracted spans")

    @property
    def is_authoritative(self) -> bool:
        return False


@dataclass(frozen=True)
class CandidateClaim:
    text: str
    source_sha256: str
    span_indices: tuple[int, ...]
    extraction_provider: str
    authority: str = UNVERIFIED_CANDIDATE

    def __post_init__(self) -> None:
        if not isinstance(self.text, str) or not self.text.strip():
            raise ValueError("candidate claim text must be non-empty")
        _validate_sha256(self.source_sha256, field_name="source_sha256")
        if not self.span_indices:
            raise ValueError("candidate claim must bind to at least one source span")
        if len(set(self.span_indices)) != len(self.span_indices):
            raise ValueError("candidate claim span indices must be unique")
        if any(
            not isinstance(index, int) or isinstance(index, bool) or index < 0
            for index in self.span_indices
        ):
            raise ValueError("candidate claim span indices must be non-negative integers")
        if self.authority != UNVERIFIED_CANDIDATE:
            raise ValueError("candidate claims cannot be promoted by the OCR layer")

    @property
    def is_authoritative(self) -> bool:
        return False


class DocumentExtractor(Protocol):
    def extract(
        self,
        source: bytes,
        *,
        source_name: str,
        media_type: str,
    ) -> DocumentExtraction:
        ...


def bind_candidate_claim(
    extraction: DocumentExtraction,
    *,
    text: str,
    span_indices: tuple[int, ...],
) -> CandidateClaim:
    if not span_indices:
        raise ValueError("candidate claim must bind to at least one source span")
    if any(index >= len(extraction.spans) for index in span_indices):
        raise ValueError("candidate claim references an unknown OCR span")
    return CandidateClaim(
        text=text,
        source_sha256=extraction.source_sha256,
        span_indices=span_indices,
        extraction_provider=extraction.provider,
    )


class PaddleOCRExtractor:
    """Provider adapter for PaddleOCR 3.x.

    OCR output is deliberately non-authoritative. The caller is responsible for
    durably preserving the original source bytes under ``source_sha256`` and for
    routing any interpreted business claim through the appropriate validation
    and ClaimSieve boundary before consequential use.
    """

    _SAFE_SUFFIXES = {
        ".bmp",
        ".jpeg",
        ".jpg",
        ".pdf",
        ".png",
        ".tif",
        ".tiff",
        ".webp",
    }

    def __init__(
        self,
        *,
        engine: Any | None = None,
        min_confidence: float = 0.0,
        provider_profile: str = "paddleocr-3.x-default",
    ) -> None:
        if (
            not isinstance(min_confidence, (int, float))
            or not isfinite(float(min_confidence))
            or not 0.0 <= float(min_confidence) <= 1.0
        ):
            raise ValueError("min_confidence must be in [0, 1]")
        if not isinstance(provider_profile, str) or not provider_profile.strip():
            raise ValueError("provider_profile must be non-empty")
        self._engine = engine
        self.min_confidence = float(min_confidence)
        self.provider_profile = provider_profile

    def _get_engine(self) -> Any:
        if self._engine is None:
            try:
                from paddleocr import PaddleOCR
            except ImportError as exc:
                raise RuntimeError(
                    "PaddleOCR is not installed. Install the optional OCR dependencies "
                    "and a deployment-appropriate PaddlePaddle runtime."
                ) from exc
            self._engine = PaddleOCR(
                use_doc_orientation_classify=False,
                use_doc_unwarping=False,
                use_textline_orientation=False,
                engine="paddle",
            )
        return self._engine

    @staticmethod
    def _result_payload(result: Any) -> dict[str, Any]:
        if isinstance(result, dict):
            payload = result
        else:
            payload = getattr(result, "json", None)
            if callable(payload):
                payload = payload()
        if not isinstance(payload, dict):
            raise ValueError("PaddleOCR result must expose a JSON dictionary")
        if "res" in payload:
            payload = payload["res"]
        if not isinstance(payload, dict):
            raise ValueError("PaddleOCR result 'res' must be a dictionary")
        return payload

    @staticmethod
    def _normalize_polygon(raw_polygon: Any) -> tuple[tuple[float, float], ...]:
        try:
            points = list(raw_polygon)
        except TypeError as exc:
            raise ValueError("PaddleOCR rec_polys entry must be an iterable polygon") from exc
        normalized: list[tuple[float, float]] = []
        for raw_point in points:
            try:
                point = list(raw_point)
            except TypeError as exc:
                raise ValueError("PaddleOCR polygon point must be iterable") from exc
            if len(point) != 2:
                raise ValueError("PaddleOCR polygon point must contain x and y")
            try:
                x = float(point[0])
                y = float(point[1])
            except (TypeError, ValueError) as exc:
                raise ValueError("PaddleOCR polygon coordinates must be numeric") from exc
            if not isfinite(x) or not isfinite(y):
                raise ValueError("PaddleOCR polygon coordinates must be finite")
            normalized.append((x, y))
        return tuple(normalized)

    def _parse_result(self, result: Any) -> tuple[ExtractedSpan, ...]:
        payload = self._result_payload(result)
        texts = payload.get("rec_texts")
        scores = payload.get("rec_scores")
        polygons = payload.get("rec_polys")
        if texts is None or scores is None or polygons is None:
            raise ValueError("PaddleOCR result must contain rec_texts, rec_scores, and rec_polys")
        try:
            texts = list(texts)
            scores = list(scores)
            polygons = list(polygons)
        except TypeError as exc:
            raise ValueError("PaddleOCR recognition fields must be iterable") from exc
        if not (len(texts) == len(scores) == len(polygons)):
            raise ValueError("PaddleOCR recognition field lengths do not match")

        page_index = payload.get("page_index")
        if page_index is not None and (
            not isinstance(page_index, int)
            or isinstance(page_index, bool)
            or page_index < 0
        ):
            raise ValueError("PaddleOCR page_index must be a non-negative integer or None")

        spans: list[ExtractedSpan] = []
        for text, score, polygon in zip(texts, scores, polygons):
            if not isinstance(text, str) or not text.strip():
                raise ValueError("PaddleOCR rec_texts entries must be non-empty strings")
            try:
                confidence = float(score)
            except (TypeError, ValueError) as exc:
                raise ValueError("PaddleOCR rec_scores entries must be numeric") from exc
            if not isfinite(confidence) or not 0.0 <= confidence <= 1.0:
                raise ValueError("PaddleOCR confidence must be finite and in [0, 1]")
            normalized_polygon = self._normalize_polygon(polygon)
            span = ExtractedSpan(
                text=text,
                confidence=confidence,
                polygon=normalized_polygon,
                page_index=page_index,
            )
            if confidence >= self.min_confidence:
                spans.append(span)
        return tuple(spans)

    def extract(
        self,
        source: bytes,
        *,
        source_name: str,
        media_type: str,
    ) -> DocumentExtraction:
        digest = sha256_hex(source)
        if not isinstance(source_name, str) or not source_name.strip():
            raise ValueError("source_name must be non-empty")
        if not isinstance(media_type, str) or not media_type.strip():
            raise ValueError("media_type must be non-empty")

        suffix = Path(source_name).suffix.lower()
        if suffix not in self._SAFE_SUFFIXES:
            suffix = ".img"

        engine = self._get_engine()
        with NamedTemporaryFile(suffix=suffix) as handle:
            handle.write(source)
            handle.flush()
            results = engine.predict(handle.name)
            if results is None:
                raise ValueError("PaddleOCR returned no result collection")
            try:
                result_items = list(results)
            except TypeError as exc:
                raise ValueError("PaddleOCR predict() must return an iterable result collection") from exc

        spans: list[ExtractedSpan] = []
        for result in result_items:
            spans.extend(self._parse_result(result))

        ordered_spans = tuple(spans)
        return DocumentExtraction(
            source_sha256=digest,
            source_name=source_name,
            media_type=media_type,
            provider="paddleocr",
            provider_profile=self.provider_profile,
            spans=ordered_spans,
            raw_text="\n".join(span.text for span in ordered_spans),
        )
