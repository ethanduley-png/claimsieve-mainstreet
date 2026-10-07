from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import keyword
import math
import re
from typing import Any, Iterable, Mapping, Sequence


KNOWN_RISK_CLASSES = frozenset({
    "informational",
    "internal_reversible",
    "external_communication",
    "commercial_commitment",
    "financial",
    "legal_compliance",
    "employment",
    "health_safety",
    "credential_security",
    "irreversible_high_impact",
})

HIGH_RISK_CLASSES = frozenset({
    "financial",
    "legal_compliance",
    "employment",
    "health_safety",
    "credential_security",
    "irreversible_high_impact",
})

ALLOWED_CANDIDATE_STATUSES = frozenset({
    "PROPOSED",
    "SHADOW",
    "PROMOTABLE",
    "REJECTED",
})


class CrystallizationError(ValueError):
    """Raised when a trace or candidate violates the crystallization contract."""


_FACT_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.\\-]{0,127}$")


def _check_fact_name(name: object) -> str:
    """Fact names reach generated source; accept only a conservative identifier-like form."""
    if type(name) is not str or _FACT_NAME_RE.fullmatch(name) is None:
        raise CrystallizationError("fact names must match [A-Za-z_][A-Za-z0-9_.-]{0,127}")
    return name


def _python_literal(value: Any) -> str:
    """Render only exact built-in JSON-like values as Python source literals."""
    value_type = type(value)
    if value is None:
        return "None"
    if value_type is bool:
        return "True" if value else "False"
    if value_type is int:
        return str(value)
    if value_type is float:
        if not math.isfinite(value):
            raise CrystallizationError("generated values must use finite floats")
        return repr(value)
    if value_type is str:
        return repr(value)
    if value_type is list:
        return "[" + ", ".join(_python_literal(item) for item in value) + "]"
    if value_type is tuple:
        parts = [_python_literal(item) for item in value]
        if len(parts) == 1:
            return "(" + parts[0] + ",)"
        return "(" + ", ".join(parts) + ")"
    if value_type is dict:
        parts = []
        for key, item in value.items():
            if type(key) is not str:
                raise CrystallizationError("generated mappings require exact string keys")
            parts.append(_python_literal(key) + ": " + _python_literal(item))
        return "{" + ", ".join(parts) + "}"
    raise CrystallizationError("generated values must use exact built-in JSON-like types")


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def digest(value: Any) -> str:
    return "sha256:" + sha256(_canonical(value)).hexdigest()


@dataclass(frozen=True)
class AgentTrace:
    trace_id: str
    capability_id: str
    risk_class: str
    input_facts: Mapping[str, Any]
    proposed_action: Mapping[str, Any]
    claimsieve_verdict: str
    terminal_outcome: str
    policy_digest: str
    evidence_root: str

    def validate(self) -> None:
        for name, value in {
            "trace_id": self.trace_id,
            "capability_id": self.capability_id,
            "risk_class": self.risk_class,
            "claimsieve_verdict": self.claimsieve_verdict,
            "terminal_outcome": self.terminal_outcome,
            "policy_digest": self.policy_digest,
            "evidence_root": self.evidence_root,
        }.items():
            if not isinstance(value, str) or not value:
                raise CrystallizationError(f"{name} must be non-empty")
        if self.risk_class not in KNOWN_RISK_CLASSES:
            raise CrystallizationError("unknown risk class")
        if not isinstance(self.input_facts, Mapping) or not isinstance(self.proposed_action, Mapping):
            raise CrystallizationError("input_facts and proposed_action must be mappings")
        if "kind" not in self.proposed_action or "destination" not in self.proposed_action:
            raise CrystallizationError("proposed_action requires kind and destination")
        if self.claimsieve_verdict not in {"ALLOW", "DENY", "REVIEW"}:
            raise CrystallizationError("invalid ClaimSieve verdict")
        if self.terminal_outcome not in {
            "CONFIRMED_SUCCESS",
            "CONFIRMED_FAILURE",
            "OUTCOME_UNKNOWN",
            "DIVERGENT_EFFECT",
            "NOT_EXECUTED",
        }:
            raise CrystallizationError("invalid terminal outcome")

    @property
    def eligible_for_learning(self) -> bool:
        return (
            self.claimsieve_verdict == "ALLOW"
            and self.terminal_outcome == "CONFIRMED_SUCCESS"
            and self.risk_class not in HIGH_RISK_CLASSES
        )


@dataclass(frozen=True)
class FieldBinding:
    action_path: tuple[str, ...]
    source_fact: str | None = None
    constant: Any = None

    @property
    def is_dynamic(self) -> bool:
        return self.source_fact is not None

    def as_dict(self) -> dict[str, Any]:
        return {
            "action_path": list(self.action_path),
            "source_fact": self.source_fact,
            "constant": self.constant,
        }


@dataclass(frozen=True)
class WorkflowCandidate:
    schema_version: str
    candidate_id: str
    capability_id: str
    risk_class: str
    required_policy_digest: str
    bindings: tuple[FieldBinding, ...]
    required_facts: tuple[str, ...]
    support_count: int
    dataset_digest: str
    status: str = "PROPOSED"
    requires_claimsieve: bool = True
    autonomous_deployment_allowed: bool = False

    def validate(self) -> None:
        if self.schema_version != "mainstreet.workflow_candidate.v1":
            raise CrystallizationError("unsupported candidate schema")
        if self.status not in ALLOWED_CANDIDATE_STATUSES:
            raise CrystallizationError("invalid candidate status")
        if not self.requires_claimsieve:
            raise CrystallizationError("crystallized consequential workflows must require ClaimSieve")
        if self.autonomous_deployment_allowed:
            raise CrystallizationError("autonomous deployment is forbidden")
        if self.risk_class not in KNOWN_RISK_CLASSES:
            raise CrystallizationError("unknown risk class")
        if self.risk_class in HIGH_RISK_CLASSES:
            raise CrystallizationError("high-risk workflows cannot auto-crystallize in v1")
        if self.support_count < 1:
            raise CrystallizationError("support_count must be positive")
        if not self.bindings:
            raise CrystallizationError("candidate requires bindings")
        for fact in self.required_facts:
            _check_fact_name(fact)
        for binding in self.bindings:
            if not binding.action_path:
                raise CrystallizationError("binding action_path cannot be empty")
            if binding.is_dynamic:
                _check_fact_name(binding.source_fact)
            if binding.is_dynamic and binding.source_fact not in self.required_facts:
                raise CrystallizationError("dynamic binding must reference a required fact")

        identity_payload = {
            "schema_version": self.schema_version,
            "capability_id": self.capability_id,
            "risk_class": self.risk_class,
            "required_policy_digest": self.required_policy_digest,
            "bindings": [binding.as_dict() for binding in self.bindings],
            "required_facts": list(self.required_facts),
            "support_count": self.support_count,
            "dataset_digest": self.dataset_digest,
            "requires_claimsieve": self.requires_claimsieve,
            "autonomous_deployment_allowed": self.autonomous_deployment_allowed,
        }
        expected_id = "workflow:" + sha256(_canonical(identity_payload)).hexdigest()
        if self.candidate_id != expected_id:
            raise CrystallizationError("candidate identity mismatch")

    def contract(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "candidate_id": self.candidate_id,
            "capability_id": self.capability_id,
            "risk_class": self.risk_class,
            "required_policy_digest": self.required_policy_digest,
            "bindings": [binding.as_dict() for binding in self.bindings],
            "required_facts": list(self.required_facts),
            "support_count": self.support_count,
            "dataset_digest": self.dataset_digest,
            "status": self.status,
            "requires_claimsieve": self.requires_claimsieve,
            "autonomous_deployment_allowed": self.autonomous_deployment_allowed,
        }


@dataclass(frozen=True)
class ShadowResult:
    total: int
    exact_matches: int
    divergences: tuple[str, ...]
    safety_violations: tuple[str, ...]

    @property
    def agreement_rate(self) -> float:
        return 0.0 if self.total == 0 else self.exact_matches / self.total


@dataclass(frozen=True)
class PromotionDecision:
    promotable: bool
    reasons: tuple[str, ...]


def _flatten(value: Mapping[str, Any], prefix: tuple[str, ...] = ()) -> dict[tuple[str, ...], Any]:
    flat: dict[tuple[str, ...], Any] = {}
    for key in sorted(value):
        item = value[key]
        path = prefix + (str(key),)
        if isinstance(item, Mapping):
            flat.update(_flatten(item, path))
        else:
            flat[path] = item
    return flat


def _set_path(target: dict[str, Any], path: Sequence[str], value: Any) -> None:
    cursor = target
    for part in path[:-1]:
        next_value = cursor.get(part)
        if not isinstance(next_value, dict):
            next_value = {}
            cursor[part] = next_value
        cursor = next_value
    cursor[path[-1]] = value


def _discover_binding(
    path: tuple[str, ...],
    values: Sequence[Any],
    traces: Sequence[AgentTrace],
) -> FieldBinding | None:
    common_fact_names = set(traces[0].input_facts)
    for trace in traces[1:]:
        common_fact_names.intersection_update(trace.input_facts)
    for fact_name in sorted(common_fact_names):
        if all(trace.input_facts.get(fact_name) == value for trace, value in zip(traces, values)):
            return FieldBinding(action_path=path, source_fact=fact_name)

    first = values[0]
    if all(value == first for value in values):
        return FieldBinding(action_path=path, constant=first)
    return None


def learn_candidate(
    traces: Iterable[AgentTrace],
    *,
    minimum_support: int = 5,
) -> WorkflowCandidate:
    items = tuple(traces)
    if isinstance(minimum_support, bool) or not isinstance(minimum_support, int) or minimum_support < 2:
        raise CrystallizationError("minimum_support must be an integer >= 2")
    if len(items) < minimum_support:
        raise CrystallizationError("insufficient support for crystallization")
    for trace in items:
        trace.validate()

    first = items[0]
    if first.risk_class in HIGH_RISK_CLASSES:
        raise CrystallizationError("high-risk workflows cannot auto-crystallize in v1")
    if not all(trace.eligible_for_learning for trace in items):
        raise CrystallizationError("learning set contains denied, uncertain, divergent, failed, or high-risk traces")
    if any(trace.capability_id != first.capability_id for trace in items):
        raise CrystallizationError("mixed capabilities cannot form one candidate")
    if any(trace.risk_class != first.risk_class for trace in items):
        raise CrystallizationError("mixed risk classes cannot form one candidate")
    if any(trace.policy_digest != first.policy_digest for trace in items):
        raise CrystallizationError("policy drift requires a separate candidate")

    flattened = [_flatten(trace.proposed_action) for trace in items]
    paths = set(flattened[0])
    if any(set(current) != paths for current in flattened[1:]):
        raise CrystallizationError("action shape is not stable")

    bindings: list[FieldBinding] = []
    for path in sorted(paths):
        values = [current[path] for current in flattened]
        binding = _discover_binding(path, values, items)
        if binding is None:
            raise CrystallizationError(
                "action field varies without a deterministic input-fact binding: " + ".".join(path)
            )
        bindings.append(binding)

    required_facts = tuple(sorted({
        binding.source_fact
        for binding in bindings
        if binding.source_fact is not None
    }))
    dataset = [
        {
            "trace_id": trace.trace_id,
            "capability_id": trace.capability_id,
            "risk_class": trace.risk_class,
            "input_facts": trace.input_facts,
            "proposed_action": trace.proposed_action,
            "policy_digest": trace.policy_digest,
            "evidence_root": trace.evidence_root,
        }
        for trace in items
    ]
    dataset_digest = digest(dataset)
    contract_without_id = {
        "schema_version": "mainstreet.workflow_candidate.v1",
        "capability_id": first.capability_id,
        "risk_class": first.risk_class,
        "required_policy_digest": first.policy_digest,
        "bindings": [binding.as_dict() for binding in bindings],
        "required_facts": list(required_facts),
        "support_count": len(items),
        "dataset_digest": dataset_digest,
        "requires_claimsieve": True,
        "autonomous_deployment_allowed": False,
    }
    candidate_id = "workflow:" + sha256(_canonical(contract_without_id)).hexdigest()
    candidate = WorkflowCandidate(
        schema_version="mainstreet.workflow_candidate.v1",
        candidate_id=candidate_id,
        capability_id=first.capability_id,
        risk_class=first.risk_class,
        required_policy_digest=first.policy_digest,
        bindings=tuple(bindings),
        required_facts=required_facts,
        support_count=len(items),
        dataset_digest=dataset_digest,
    )
    candidate.validate()
    return candidate


def compile_action(
    candidate: WorkflowCandidate,
    input_facts: Mapping[str, Any],
    *,
    policy_digest: str,
) -> dict[str, Any]:
    candidate.validate()
    if policy_digest != candidate.required_policy_digest:
        raise CrystallizationError("policy digest mismatch")
    missing = [fact for fact in candidate.required_facts if fact not in input_facts]
    if missing:
        raise CrystallizationError("missing required fact(s): " + ", ".join(missing))

    action: dict[str, Any] = {}
    for binding in candidate.bindings:
        value = input_facts[binding.source_fact] if binding.is_dynamic else binding.constant
        _set_path(action, binding.action_path, value)
    return action


def render_python_module(
    candidate: WorkflowCandidate,
    *,
    function_name: str = "build_proposal",
) -> str:
    """Render a pure deterministic proposal builder with no provider or credential access."""
    candidate.validate()
    if type(function_name) is not str or not function_name.isidentifier() or keyword.iskeyword(function_name):
        raise CrystallizationError("function_name must be a valid Python identifier")

    policy_literal = _python_literal(candidate.required_policy_digest)
    candidate_id_literal = _python_literal(candidate.candidate_id)

    lines = [
        '"""Generated by MainStreet workflow crystallization. Proposal-only; ClaimSieve remains authority."""',
        "",
        "def _set_path(target, path, value):",
        "    cursor = target",
        "    for part in path[:-1]:",
        "        current = cursor.get(part)",
        "        if not isinstance(current, dict):",
        "            current = {}",
        "            cursor[part] = current",
        "        cursor = current",
        "    cursor[path[-1]] = value",
        "",
        f"def {function_name}(input_facts, policy_digest):",
        f"    if policy_digest != {policy_literal}:",
        "        raise ValueError('policy digest mismatch')",
    ]
    for fact in candidate.required_facts:
        fact_literal = _python_literal(fact)
        message_literal = _python_literal("missing required fact: " + fact)
        lines.extend([
            f"    if {fact_literal} not in input_facts:",
            f"        raise ValueError({message_literal})",
        ])
    lines.append("    action = {}")
    for binding in candidate.bindings:
        value_expr = (
            "input_facts[" + _python_literal(binding.source_fact) + "]"
            if binding.is_dynamic
            else _python_literal(binding.constant)
        )
        path_literal = _python_literal(binding.action_path)
        lines.append(
            f"    _set_path(action, {path_literal}, {value_expr})"
        )
    lines.extend([
        "    return {",
        f"        'candidate_id': {candidate_id_literal},",
        "        'proposal': action,",
        "        'requires_claimsieve': True,",
        "        'autonomous_execution_allowed': False,",
        "    }",
        "",
    ])
    return "\n".join(lines)


def shadow_compare(
    candidate: WorkflowCandidate,
    traces: Iterable[AgentTrace],
) -> ShadowResult:
    candidate.validate()
    divergences: list[str] = []
    safety: list[str] = []
    total = 0
    exact = 0

    for trace in traces:
        trace.validate()
        total += 1
        if trace.capability_id != candidate.capability_id:
            safety.append(f"{trace.trace_id}: capability mismatch")
            continue
        if trace.risk_class != candidate.risk_class:
            safety.append(f"{trace.trace_id}: risk-class mismatch")
            continue
        if trace.policy_digest != candidate.required_policy_digest:
            safety.append(f"{trace.trace_id}: policy drift")
            continue
        if trace.claimsieve_verdict != "ALLOW":
            safety.append(f"{trace.trace_id}: historical action was not allowed")
            continue
        if trace.terminal_outcome != "CONFIRMED_SUCCESS":
            safety.append(f"{trace.trace_id}: historical outcome was not confirmed success")
            continue
        try:
            compiled = compile_action(
                candidate,
                trace.input_facts,
                policy_digest=trace.policy_digest,
            )
        except CrystallizationError as exc:
            safety.append(f"{trace.trace_id}: {exc}")
            continue
        if compiled == dict(trace.proposed_action):
            exact += 1
        else:
            divergences.append(trace.trace_id)

    return ShadowResult(
        total=total,
        exact_matches=exact,
        divergences=tuple(divergences),
        safety_violations=tuple(safety),
    )


def promotion_gate(
    candidate: WorkflowCandidate,
    shadow: ShadowResult,
    *,
    minimum_shadow_cases: int = 20,
    minimum_agreement: float = 1.0,
) -> PromotionDecision:
    candidate.validate()
    reasons: list[str] = []
    if isinstance(minimum_shadow_cases, bool) or not isinstance(minimum_shadow_cases, int) or minimum_shadow_cases < 1:
        raise CrystallizationError("minimum_shadow_cases must be positive")
    if not 0.0 <= minimum_agreement <= 1.0:
        raise CrystallizationError("minimum_agreement must be between 0 and 1")
    if shadow.total < minimum_shadow_cases:
        reasons.append("insufficient shadow cases")
    if shadow.safety_violations:
        reasons.append("shadow safety violations present")
    if shadow.divergences:
        reasons.append("shadow divergences present")
    if shadow.agreement_rate < minimum_agreement:
        reasons.append("shadow agreement below threshold")
    if candidate.risk_class in HIGH_RISK_CLASSES:
        reasons.append("high-risk workflow cannot auto-promote in v1")
    if not candidate.requires_claimsieve:
        reasons.append("candidate does not require ClaimSieve")
    if candidate.autonomous_deployment_allowed:
        reasons.append("autonomous deployment is forbidden")
    return PromotionDecision(promotable=not reasons, reasons=tuple(reasons))
