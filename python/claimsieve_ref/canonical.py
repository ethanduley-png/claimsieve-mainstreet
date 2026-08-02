from __future__ import annotations

import hashlib
import json
import unicodedata
from dataclasses import dataclass
from typing import Any


class CanonicalizationError(ValueError):
    pass


MAX_SAFE_INTEGER = 9_007_199_254_740_991
MAX_DEPTH = 64
MAX_NODES = 100_000
MAX_STRING_LENGTH = 1_048_576
MAX_CONTAINER_ITEMS = 100_000


@dataclass
class _Budget:
    nodes: int = 0


def _validate_string(value: str, path: str) -> None:
    if len(value) > MAX_STRING_LENGTH:
        raise CanonicalizationError(f"string exceeds canonical profile limit at {path}")
    if unicodedata.normalize("NFC", value) != value:
        raise CanonicalizationError(f"string is not NFC-normalized at {path}")
    if any(unicodedata.category(character) == "Cc" for character in value):
        raise CanonicalizationError(f"control character forbidden at {path}")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise CanonicalizationError(f"invalid Unicode scalar value at {path}") from exc


def _validate(value: Any, path: str = "$", depth: int = 0, budget: _Budget | None = None) -> None:
    active_budget = budget if budget is not None else _Budget()
    active_budget.nodes += 1
    if active_budget.nodes > MAX_NODES:
        raise CanonicalizationError("canonical JSON tree exceeds node limit")
    if depth > MAX_DEPTH:
        raise CanonicalizationError(f"canonical JSON tree exceeds depth limit at {path}")
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, str):
        _validate_string(value, path)
        return
    if isinstance(value, int):
        if not -MAX_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER:
            raise CanonicalizationError(f"integer outside safe JSON range at {path}")
        return
    if isinstance(value, float):
        raise CanonicalizationError(f"floating-point values are forbidden at {path}")
    if isinstance(value, list):
        if len(value) > MAX_CONTAINER_ITEMS:
            raise CanonicalizationError(f"array exceeds canonical profile limit at {path}")
        for index, item in enumerate(value):
            _validate(item, f"{path}[{index}]", depth + 1, active_budget)
        return
    if isinstance(value, dict):
        if len(value) > MAX_CONTAINER_ITEMS:
            raise CanonicalizationError(f"object exceeds canonical profile limit at {path}")
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalizationError(f"non-string key at {path}")
            _validate_string(key, f"{path}.<key>")
            _validate(item, f"{path}.{key}", depth + 1, active_budget)
        return
    raise CanonicalizationError(f"unsupported value type {type(value).__name__} at {path}")


def _utf16_sort_key(value: str) -> bytes:
    # RFC 8785 property ordering is based on UTF-16 code units. NFC validation
    # above prevents canonically equivalent strings from hashing differently.
    return value.encode("utf-16be")


def _encode(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    if isinstance(value, int):
        return str(value)
    if isinstance(value, list):
        return "[" + ",".join(_encode(item) for item in value) + "]"
    if isinstance(value, dict):
        parts = []
        for key in sorted(value, key=_utf16_sort_key):
            encoded_key = json.dumps(key, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
            parts.append(encoded_key + ":" + _encode(value[key]))
        return "{" + ",".join(parts) + "}"
    raise CanonicalizationError(f"unsupported value type {type(value).__name__}")


def canonical_bytes(value: Any) -> bytes:
    """Canonical JSON for the restricted ClaimSieve profile.

    The profile rejects duplicate keys at parse time, floating-point values,
    integers outside the interoperable safe range, non-NFC strings, control
    characters, invalid Unicode scalars, and excessively deep or large trees.
    Object properties use RFC 8785 UTF-16 ordering.
    """
    _validate(value)
    return _encode(value).encode("utf-8")


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def digest_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def loads_strict(text: str) -> Any:
    def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise CanonicalizationError(f"duplicate key: {key}")
            result[key] = value
        return result

    def no_floats(_: str) -> Any:
        raise CanonicalizationError("floats forbidden")

    def safe_integer(value: str) -> int:
        parsed = int(value)
        if abs(parsed) > MAX_SAFE_INTEGER:
            raise CanonicalizationError("integer outside safe JSON range")
        return parsed

    value = json.loads(
        text,
        object_pairs_hook=no_duplicates,
        parse_float=no_floats,
        parse_int=safe_integer,
        parse_constant=no_floats,
    )
    _validate(value)
    return value
