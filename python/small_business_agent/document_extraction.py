from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from math import isfinite
from numbers import Integral
from tempfile import NamedTemporaryFile
from typing import Any, Protocol

from claimsieve_ref.canonical import digest as canonical_digest


CANDIDATE_EVIDENCE = "candidate_evidence"
UNVERIFIED_CANDIDATE = "unverified_candidate"
MAX_SPAN_TEXT_BYTES = 128 * 1024
MAX_EXTRACTION_TEXT_BYTES = 16 * 1024 * 1024
MAX_SOURCE_NAME_BYTES = 4096
MAX_PROVIDER_FIELD_BYTES = 4096


def _validate_sha256(value: str, *, field_name: str) -> None:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or value.lower() != value
        or any(ch not in "0123456789abcdef" for ch in value)
    ):
        raise ValueError(f"{field_name} must be a lowercase SHA-256 hex digest")


def _validate_digest(value: str, *, field_name: str) -> None:
    if not isinstance(value, str) or not value.startswith("sha256:"):
        raise ValueError(f"{field_name} must be a sha256: digest")
    _validate_sha256(value.removeprefix("sha256:"), field_name=field_name)


def _validate_text(value: str, *, field_name: str, max_bytes: int) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be non-empty")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError(f"{field_name} must contain valid Unicode scalar values") from exc
    if len(encoded) > max_bytes:
        raise ValueError(f"{field_name} exceeds the configured text limit")


def _utf8_hex(value: str, *, field_name: str) -> str:
    try:
        return value.encode("utf-8").hex()
    except UnicodeEncodeError as exc:
        raise ValueError(f"{field_name} must contain valid Unicode scalar values") from exc


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
        _validate_text(self.text, field_name="extracted span text", max_bytes=MAX_SPAN_TEXT_BYTES)
        if (
            not isinstance(self.confidence, (int, float))
            or isinstance(self.confidence, bool)
            or not isfinite(float(self.confidence))
        ):
            raise ValueError("extracted span confidence must be finite")
        if not 0.0 <= float(self.confidence) <= 1.0:
            raise ValueError("extracted span confidence must be in [0, 1]")
        if not isinstance(self.polygon, tuple):
            raise ValueError("extracted span polygon must be an immutable tuple")
        if len(self.polygon) < 4:
            raise ValueError("extracted span polygon must contain at least four points")
        for point in self.polygon:
            if not isinstance(point, tuple) or len(point) != 2:
                raise ValueError("polygon points must be immutable x/y pairs")
            if not all(
                isinstance(value, (int, float))
                and not isinstance(value, bool)
                and isfinite(float(value))
                for value in point
            ):
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
        if not isinstance(self.spans, tuple) or not all(
            isinstance(span, ExtractedSpan) for span in self.spans
        ):
            raise ValueError("spans must be an immutable tuple of ExtractedSpan values")
        _validate_text(self.source_name, field_name="source_name", max_bytes=MAX_SOURCE_NAME_BYTES)
        _validate_text(self.media_type, field_name="media_type", max_bytes=255)
        _validate_text(self.provider, field_name="provider", max_bytes=MAX_PROVIDER_FIELD_BYTES)
        _validate_text(
            self.provider_profile,
            field_name="provider_profile",
            max_bytes=MAX_PROVIDER_FIELD_BYTES,
        )
        if self.authority != CANDIDATE_EVIDENCE:
            raise ValueError("OCR extraction authority must remain candidate_evidence")
        expected_text = "\n".join(span.text for span in self.spans)
        if self.raw_text != expected_text:
            raise ValueError("raw_text must exactly match the ordered extracted spans")
        try:
            raw_bytes = self.raw_text.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise ValueError("raw_text must contain valid Unicode scalar values") from exc
        if len(raw_bytes) > MAX_EXTRACTION_TEXT_BYTES:
            raise ValueError("OCR extraction text exceeds the configured total text limit")

    def canonical_record(self) -> dict[str, Any]:
        return {
            "schema": "mainstreet.document-extraction.v1",
            "source_sha256": self.source_sha256,
            "source_name_utf8_hex": _utf8_hex(self.source_name, field_name="source_name"),
            "media_type_utf8_hex": _utf8_hex(self.media_type, field_name="media_type"),
            "provider_utf8_hex": _utf8_hex(self.provider, field_name="provider"),
            "provider_profile_utf8_hex": _utf8_hex(
                self.provider_profile, field_name="provider_profile"
            ),
            "spans": [
                {
                    "text_utf8_hex": _utf8_hex(span.text, field_name="span.text"),
                    "confidence_hex": float(span.confidence).hex(),
                    "polygon": [
                        [float(point[0]).hex(), float(point[1]).hex()]
                        for point in span.polygon
                    ],
                    "page_index": span.page_index,
                }
                for span in self.spans
            ],
        }

    @property
    def extraction_digest(self) -> str:
        return canonical_digest(self.canonical_record())

    @property
    def is_authoritative(self) -> bool:
        return False


@dataclass(frozen=True)
class CandidateClaim:
    text: str
    source_sha256: str
    extraction_digest: str
    span_indices: tuple[int, ...]
    extraction_provider: str
    authority: str = UNVERIFIED_CANDIDATE

    def __post_init__(self) -> None:
        _validate_text(self.text, field_name="candidate claim text", max_bytes=MAX_SPAN_TEXT_BYTES)
        _validate_sha256(self.source_sha256, field_name="source_sha256")
        _validate_digest(self.extraction_digest, field_name="extraction_digest")
        _validate_text(
            self.extraction_provider,
            field_name="extraction_provider",
            max_bytes=MAX_PROVIDER_FIELD_BYTES,
        )
        if not isinstance(self.span_indices, tuple):
            raise ValueError("candidate claim span indices must be an immutable tuple")
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
    if any(
        not isinstance(index, int) or isinstance(index, bool) or index < 0
        for index in span_indices
    ):
        raise ValueError("candidate claim span indices must be non-negative integers")
    if any(index >= len(extraction.spans) for index in span_indices):
        raise ValueError("candidate claim references an unknown OCR span")
    claim = CandidateClaim(
        text=text,
        source_sha256=extraction.source_sha256,
        extraction_digest=extraction.extraction_digest,
        span_indices=span_indices,
        extraction_provider=extraction.provider,
    )
    validate_candidate_claim_binding(claim, extraction)
    return claim


def validate_candidate_claim_binding(
    claim: CandidateClaim,
    extraction: DocumentExtraction,
) -> None:
    if claim.source_sha256 != extraction.source_sha256:
        raise ValueError("candidate claim source digest does not match extraction")
    if claim.extraction_digest != extraction.extraction_digest:
        raise ValueError("candidate claim extraction digest does not match extraction")
    if claim.extraction_provider != extraction.provider:
        raise ValueError("candidate claim provider does not match extraction")
    if any(index >= len(extraction.spans) for index in claim.span_indices):
        raise ValueError("candidate claim references an unknown OCR span")


class PaddleOCRExtractor:
    """Provider adapter for PaddleOCR 3.x.

    OCR output is deliberately non-authoritative. The caller is responsible for
    durably preserving the original source bytes under ``source_sha256`` and for
    routing any interpreted business claim through the appropriate validation
    and ClaimSieve boundary before consequential use.
    """

    _MEDIA_TYPE_SUFFIXES = {
        "application/pdf": ".pdf",
        "image/bmp": ".bmp",
        "image/jpeg": ".jpg",
        "image/png": ".png",
        "image/tiff": ".tiff",
        "image/webp": ".webp",
    }

    def __init__(
        self,
        *,
        engine: Any | None = None,
        min_confidence: float = 0.0,
        provider_profile: str = "paddleocr-3.x-default",
        max_source_bytes: int = 25 * 1024 * 1024,
        max_results: int = 200,
        max_spans: int = 20_000,
    ) -> None:
        if (
            not isinstance(min_confidence, (int, float))
            or isinstance(min_confidence, bool)
            or not isfinite(float(min_confidence))
            or not 0.0 <= float(min_confidence) <= 1.0
        ):
            raise ValueError("min_confidence must be in [0, 1]")
        _validate_text(
            provider_profile,
            field_name="provider_profile",
            max_bytes=MAX_PROVIDER_FIELD_BYTES,
        )
        for field_name, value in (
            ("max_source_bytes", max_source_bytes),
            ("max_results", max_results),
            ("max_spans", max_spans),
        ):
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                raise ValueError(f"{field_name} must be a positive integer")
        self._engine = engine
        self.min_confidence = float(min_confidence)
        self.provider_profile = provider_profile
        self.max_source_bytes = max_source_bytes
        self.max_results = max_results
        self.max_spans = max_spans

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
        if page_index is not None:
            if (
                not isinstance(page_index, Integral)
                or isinstance(page_index, bool)
                or page_index < 0
            ):
                raise ValueError("PaddleOCR page_index must be a non-negative integer or None")
            page_index = int(page_index)

        spans: list[ExtractedSpan] = []
        for text, score, polygon in zip(texts, scores, polygons):
            if not isinstance(text, str):
                raise ValueError("PaddleOCR rec_texts entries must be strings")
            try:
                confidence = float(score)
            except (TypeError, ValueError) as exc:
                raise ValueError("PaddleOCR rec_scores entries must be numeric") from exc
            if not isfinite(confidence) or not 0.0 <= confidence <= 1.0:
                raise ValueError("PaddleOCR confidence must be finite and in [0, 1]")
            normalized_polygon = self._normalize_polygon(polygon)
            if not text.strip():
                continue
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
        if len(source) > self.max_source_bytes:
            raise ValueError("source payload exceeds the configured OCR size limit")
        _validate_text(source_name, field_name="source_name", max_bytes=MAX_SOURCE_NAME_BYTES)
        _validate_text(media_type, field_name="media_type", max_bytes=255)
        suffix = self._MEDIA_TYPE_SUFFIXES.get(media_type.lower())
        if suffix is None:
            raise ValueError("unsupported OCR media_type")

        engine = self._get_engine()
        spans: list[ExtractedSpan] = []
        with NamedTemporaryFile(suffix=suffix) as handle:
            handle.write(source)
            handle.flush()
            results = engine.predict(handle.name)
            if results is None:
                raise ValueError("PaddleOCR returned no result collection")
            try:
                iterator = iter(results)
            except TypeError as exc:
                raise ValueError("PaddleOCR predict() must return an iterable result collection") from exc

            for result_index, result in enumerate(iterator):
                if result_index >= self.max_results:
                    raise ValueError("PaddleOCR result count exceeds the configured limit")
                parsed = self._parse_result(result)
                if len(spans) + len(parsed) > self.max_spans:
                    raise ValueError("PaddleOCR span count exceeds the configured limit")
                spans.extend(parsed)

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
