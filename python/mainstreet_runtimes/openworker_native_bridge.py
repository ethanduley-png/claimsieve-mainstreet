from __future__ import annotations

import copy
import inspect
import json
from importlib import metadata
from typing import Any, Mapping

from .openworker_adapter import OpenWorkerProposalAdapter

PINNED_OPENWORKER_COMMIT = "86c57f0692a5a318e55d1b9e0188d798b9fc5690"
EXPECTED_TOOL_CALL_FIELDS = ("id", "name", "arguments")
_EXTERNAL_TOOL_CATEGORIES = frozenset({"connector", "mcp"})


class OpenWorkerNativeBridgeError(RuntimeError):
    """Raised when the pinned OpenWorker runtime no longer matches the tested boundary."""


def _coworker_distribution() -> metadata.Distribution:
    try:
        return metadata.distribution("coworker")
    except metadata.PackageNotFoundError as exc:
        raise OpenWorkerNativeBridgeError("OpenWorker/coworker is not installed") from exc


def installed_openworker_commit() -> str:
    """Return the VCS commit recorded by PEP 610 for the installed OpenWorker package.

    OpenWorker currently reports package version 0.0.0, which is not a useful compatibility
    identity. The integration therefore fails closed unless pip records the exact pinned git
    commit in direct_url.json.
    """

    raw = _coworker_distribution().read_text("direct_url.json")
    if not raw:
        raise OpenWorkerNativeBridgeError(
            "installed OpenWorker has no PEP 610 direct_url.json provenance"
        )
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise OpenWorkerNativeBridgeError("OpenWorker direct_url.json is malformed") from exc
    vcs = payload.get("vcs_info")
    if not isinstance(vcs, Mapping) or vcs.get("vcs") != "git":
        raise OpenWorkerNativeBridgeError("OpenWorker installation is not git-provenanced")
    commit = vcs.get("commit_id")
    if not isinstance(commit, str) or len(commit) != 40:
        raise OpenWorkerNativeBridgeError("OpenWorker git provenance lacks an exact commit")
    return commit.lower()


def verify_pinned_openworker_runtime() -> str:
    """Fail closed on package provenance or native API drift."""

    commit = installed_openworker_commit()
    if commit != PINNED_OPENWORKER_COMMIT:
        raise OpenWorkerNativeBridgeError(
            f"OpenWorker runtime drift: expected {PINNED_OPENWORKER_COMMIT}, got {commit}"
        )

    from coworker.engine import TurnEngine
    from coworker.providers.base import ToolCall

    fields = tuple(ToolCall.__dataclass_fields__)
    if fields[:3] != EXPECTED_TOOL_CALL_FIELDS or len(fields) != 3:
        raise OpenWorkerNativeBridgeError(
            f"OpenWorker ToolCall API drift: expected {EXPECTED_TOOL_CALL_FIELDS}, got {fields}"
        )
    sig = inspect.signature(TurnEngine._execute_sync)
    if tuple(sig.parameters) != ("self", "tool_call"):
        raise OpenWorkerNativeBridgeError(
            f"OpenWorker execution seam drift: unexpected _execute_sync signature {sig}"
        )
    return commit


def translate_native_tool_call(
    tool_call: Any,
    *,
    tool_map: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Translate an actual pinned OpenWorker ToolCall into the stable MainStreet envelope."""

    from coworker.providers.base import ToolCall

    if type(tool_call) is not ToolCall:
        raise OpenWorkerNativeBridgeError(
            "native invocation must be exactly coworker.providers.base.ToolCall"
        )
    if not isinstance(tool_call.id, str) or not tool_call.id:
        raise OpenWorkerNativeBridgeError("native OpenWorker tool call id is invalid")
    if not isinstance(tool_call.name, str) or not tool_call.name:
        raise OpenWorkerNativeBridgeError("native OpenWorker tool name is invalid")
    if not isinstance(tool_call.arguments, dict):
        raise OpenWorkerNativeBridgeError("native OpenWorker arguments must be a dict")

    canonical_name = (tool_map or {}).get(tool_call.name, tool_call.name)
    if not isinstance(canonical_name, str) or not canonical_name:
        raise OpenWorkerNativeBridgeError("canonical tool mapping is invalid")
    return {
        "schema_version": OpenWorkerProposalAdapter.BOUNDARY_SCHEMA,
        "id": tool_call.id,
        "name": canonical_name,
        "arguments": copy.deepcopy(tool_call.arguments),
    }


def guarded_turn_engine_class():
    """Return a pinned TurnEngine subclass that gates external and consequential execution.

    The subclass is created lazily so ordinary ClaimSieve tests do not acquire an OpenWorker
    dependency. Only _execute_sync is specialized. Explicitly mapped consequential calls are
    translated and routed into ClaimSieve. Any other OpenWorker call that is consequential by
    OpenWorker's base risk model, or belongs to an external connector/MCP category, fails closed
    rather than falling through to ToolRegistry.execute. Pure local reads retain native behavior.
    """

    verify_pinned_openworker_runtime()
    from coworker.engine import TurnEngine
    from coworker.risk import classify, is_consequential

    class ClaimSieveGuardedOpenWorkerTurnEngine(TurnEngine):
        def __init__(
            self,
            *args: Any,
            claimsieve_adapter: OpenWorkerProposalAdapter,
            native_tool_map: Mapping[str, str] | None = None,
            **kwargs: Any,
        ) -> None:
            super().__init__(*args, **kwargs)
            self._claimsieve_adapter = claimsieve_adapter
            self._native_tool_map = dict(native_tool_map or {})

        def _canonical_name(self, native_name: str) -> str:
            return self._native_tool_map.get(native_name, native_name)

        def _routes_to_claimsieve(self, tool_call: Any) -> bool:
            return self._claimsieve_adapter.is_consequential(
                self._canonical_name(tool_call.name)
            )

        def _native_call_must_not_fall_through(self, tool_call: Any) -> bool:
            spec = self.registry.get(tool_call.name)
            metadata_value = spec.metadata if spec else None
            category = str(getattr(metadata_value, "category", "") or "").lower()
            if category in _EXTERNAL_TOOL_CATEGORIES:
                return True
            # Deliberately ignore user-local risk overrides here. A local OpenWorker override
            # may make its own approval UX quieter, but it cannot downgrade MainStreet's
            # execution-boundary decision about whether native execution is allowed.
            return is_consequential(classify(tool_call.name, metadata_value, None))

        def _execute_sync(self, tool_call: Any) -> tuple[Any, str]:
            if self._routes_to_claimsieve(tool_call):
                try:
                    boundary = translate_native_tool_call(
                        tool_call,
                        tool_map=self._native_tool_map,
                    )
                    routed = self._claimsieve_adapter.route_tool_call(boundary)
                    return routed, "ok"
                except Exception as exc:
                    # Match OpenWorker's native execution contract: tool failures become an
                    # error result. Crucially, there is no fallback to registry.execute.
                    return {"error": str(exc), "error_type": type(exc).__name__}, "error"

            if self._native_call_must_not_fall_through(tool_call):
                return {
                    "error": (
                        "unmapped consequential OpenWorker tool is blocked from native "
                        f"execution: {tool_call.name}"
                    ),
                    "error_type": "OpenWorkerNativeBridgeError",
                }, "error"

            return super()._execute_sync(tool_call)

    return ClaimSieveGuardedOpenWorkerTurnEngine
