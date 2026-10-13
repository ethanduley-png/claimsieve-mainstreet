from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

from claimsieve_ref.canonical import digest as canonical_digest
from claimsieve_ref.crypto import KeyPair, PublicKey

from .core import (
    AgentTrace,
    CrystallizationError,
    WorkflowCandidate,
    compile_action,
    learn_candidate,
)


TRACE_SIGNATURE_DOMAIN = "mainstreet.crystallization.trace.v1"
SIGNED_TRACE_SCHEMA = "mainstreet.signed_agent_trace.v1"
HARDENED_WORKFLOW_SCHEMA = "mainstreet.hardened_workflow.v1"


def _json_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_value(item) for item in value]
    return value


def trace_payload(trace: AgentTrace) -> dict[str, Any]:
    trace.validate()
    return {
        "schema_version": "mainstreet.agent_trace.payload.v1",
        "trace_id": trace.trace_id,
        "capability_id": trace.capability_id,
        "risk_class": trace.risk_class,
        "input_facts": _json_value(trace.input_facts),
        "proposed_action": _json_value(trace.proposed_action),
        "claimsieve_verdict": trace.claimsieve_verdict,
        "terminal_outcome": trace.terminal_outcome,
        "policy_digest": trace.policy_digest,
        "evidence_root": trace.evidence_root,
    }


@dataclass(frozen=True)
class SignedAgentTrace:
    schema_version: str
    signer_key_id: str
    trace: AgentTrace
    signature: str

    def signing_subject(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "signer_key_id": self.signer_key_id,
            "trace": trace_payload(self.trace),
        }

    def as_dict(self) -> dict[str, Any]:
        return {
            **self.signing_subject(),
            "signature": self.signature,
        }

    def validate_shape(self) -> None:
        if self.schema_version != SIGNED_TRACE_SCHEMA:
            raise CrystallizationError("unsupported signed-trace schema")
        if not isinstance(self.signer_key_id, str) or not self.signer_key_id:
            raise CrystallizationError("signer_key_id must be non-empty")
        if not isinstance(self.signature, str) or not self.signature.startswith("ed25519:"):
            raise CrystallizationError("signed trace requires an Ed25519 signature")
        self.trace.validate()


def sign_trace(trace: AgentTrace, signer: KeyPair) -> SignedAgentTrace:
    trace.validate()
    unsigned = SignedAgentTrace(
        schema_version=SIGNED_TRACE_SCHEMA,
        signer_key_id=signer.key_id,
        trace=trace,
        signature="ed25519:pending",
    )
    signature = signer.sign(TRACE_SIGNATURE_DOMAIN, unsigned.signing_subject())
    return SignedAgentTrace(
        schema_version=unsigned.schema_version,
        signer_key_id=unsigned.signer_key_id,
        trace=trace,
        signature=signature,
    )


def verify_signed_trace(
    envelope: SignedAgentTrace,
    trust_store: Mapping[str, PublicKey],
) -> AgentTrace:
    envelope.validate_shape()
    public_key = trust_store.get(envelope.signer_key_id)
    if public_key is None:
        raise CrystallizationError("signed trace uses an untrusted signer")
    if public_key.key_id != envelope.signer_key_id:
        raise CrystallizationError("trust-store key id mismatch")
    if not public_key.verify(
        TRACE_SIGNATURE_DOMAIN,
        envelope.signing_subject(),
        envelope.signature,
    ):
        raise CrystallizationError("signed trace signature verification failed")
    return envelope.trace


@dataclass(frozen=True)
class FactGuard:
    fact_name: str
    expected_value: Any

    def validate(self) -> None:
        if not isinstance(self.fact_name, str) or not self.fact_name:
            raise CrystallizationError("guard fact_name must be non-empty")
        canonical_digest({"value": _json_value(self.expected_value)})

    def as_dict(self) -> dict[str, Any]:
        return {
            "fact_name": self.fact_name,
            "expected_value": _json_value(self.expected_value),
        }


@dataclass(frozen=True)
class HardenedWorkflow:
    schema_version: str
    profile_id: str
    candidate: WorkflowCandidate
    guards: tuple[FactGuard, ...]
    signed_dataset_digest: str
    positive_trace_digest: str
    negative_trace_digest: str
    signer_key_ids: tuple[str, ...]
    positive_count: int
    negative_count: int
    requires_claimsieve: bool = True
    autonomous_execution_allowed: bool = False

    def identity_payload(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "candidate_id": self.candidate.candidate_id,
            "guards": [guard.as_dict() for guard in self.guards],
            "signed_dataset_digest": self.signed_dataset_digest,
            "positive_trace_digest": self.positive_trace_digest,
            "negative_trace_digest": self.negative_trace_digest,
            "signer_key_ids": list(self.signer_key_ids),
            "positive_count": self.positive_count,
            "negative_count": self.negative_count,
            "requires_claimsieve": self.requires_claimsieve,
            "autonomous_execution_allowed": self.autonomous_execution_allowed,
        }

    def validate(self) -> None:
        if self.schema_version != HARDENED_WORKFLOW_SCHEMA:
            raise CrystallizationError("unsupported hardened-workflow schema")
        self.candidate.validate()
        if not self.requires_claimsieve:
            raise CrystallizationError("hardened workflows must require ClaimSieve")
        if self.autonomous_execution_allowed:
            raise CrystallizationError("autonomous execution is forbidden")
        if self.positive_count < 2:
            raise CrystallizationError("hardened workflow requires positive support")
        if self.negative_count < 1:
            raise CrystallizationError("hardened workflow requires negative evidence")
        if not self.guards:
            raise CrystallizationError("hardened workflow requires explicit safe-input guards")
        guard_names = [guard.fact_name for guard in self.guards]
        if len(set(guard_names)) != len(guard_names):
            raise CrystallizationError("duplicate guard fact")
        if tuple(sorted(guard_names)) != tuple(guard_names):
            raise CrystallizationError("guards must use canonical fact ordering")
        for guard in self.guards:
            guard.validate()
        if not self.signer_key_ids or tuple(sorted(set(self.signer_key_ids))) != self.signer_key_ids:
            raise CrystallizationError("signer_key_ids must be sorted and unique")
        for name, value in {
            "signed_dataset_digest": self.signed_dataset_digest,
            "positive_trace_digest": self.positive_trace_digest,
            "negative_trace_digest": self.negative_trace_digest,
        }.items():
            if not isinstance(value, str) or not value.startswith("sha256:"):
                raise CrystallizationError(f"{name} must be a sha256 digest")
        expected_profile_id = canonical_digest(self.identity_payload()).replace(
            "sha256:", "workflow-profile:", 1
        )
        if self.profile_id != expected_profile_id:
            raise CrystallizationError("hardened workflow identity mismatch")


def _constant_positive_facts(positives: tuple[AgentTrace, ...]) -> dict[str, Any]:
    common_names = set(positives[0].input_facts)
    for trace in positives[1:]:
        common_names.intersection_update(trace.input_facts)
    constants: dict[str, Any] = {}
    for fact_name in sorted(common_names):
        expected = positives[0].input_facts[fact_name]
        if all(trace.input_facts[fact_name] == expected for trace in positives[1:]):
            constants[fact_name] = expected
    return constants


def _negative_excluded(trace: AgentTrace, guards: tuple[FactGuard, ...]) -> bool:
    return any(
        guard.fact_name not in trace.input_facts
        or trace.input_facts[guard.fact_name] != guard.expected_value
        for guard in guards
    )


def learn_hardened_workflow(
    signed_traces: Iterable[SignedAgentTrace],
    trust_store: Mapping[str, PublicKey],
    *,
    minimum_support: int = 5,
    minimum_negative_examples: int = 2,
) -> HardenedWorkflow:
    envelopes = tuple(signed_traces)
    if isinstance(minimum_negative_examples, bool) or not isinstance(minimum_negative_examples, int) or minimum_negative_examples < 1:
        raise CrystallizationError("minimum_negative_examples must be an integer >= 1")
    if not envelopes:
        raise CrystallizationError("signed trace set cannot be empty")

    verified: list[AgentTrace] = []
    trace_ids: set[str] = set()
    for envelope in envelopes:
        trace = verify_signed_trace(envelope, trust_store)
        if trace.trace_id in trace_ids:
            raise CrystallizationError("duplicate signed trace id")
        trace_ids.add(trace.trace_id)
        verified.append(trace)

    first = verified[0]
    if any(trace.capability_id != first.capability_id for trace in verified):
        raise CrystallizationError("mixed capabilities cannot form one hardened workflow")
    if any(trace.risk_class != first.risk_class for trace in verified):
        raise CrystallizationError("mixed risk classes cannot form one hardened workflow")
    if any(trace.policy_digest != first.policy_digest for trace in verified):
        raise CrystallizationError("policy drift requires a separate hardened workflow")

    positives = tuple(trace for trace in verified if trace.eligible_for_learning)
    negatives = tuple(trace for trace in verified if not trace.eligible_for_learning)
    if len(negatives) < minimum_negative_examples:
        raise CrystallizationError("insufficient negative evidence for hardened crystallization")

    candidate = learn_candidate(positives, minimum_support=minimum_support)
    constants = _constant_positive_facts(positives)
    guards = tuple(
        FactGuard(fact_name=fact_name, expected_value=value)
        for fact_name, value in constants.items()
        if any(
            fact_name not in negative.input_facts
            or negative.input_facts[fact_name] != value
            for negative in negatives
        )
    )
    if not guards:
        raise CrystallizationError(
            "negative examples do not establish an explicit safe-input guard"
        )
    unresolved = [
        trace.trace_id
        for trace in negatives
        if not _negative_excluded(trace, guards)
    ]
    if unresolved:
        raise CrystallizationError(
            "unresolved negative example(s): " + ", ".join(sorted(unresolved))
        )

    ordered_envelopes = sorted(envelopes, key=lambda item: item.trace.trace_id)
    ordered_positives = sorted(positives, key=lambda item: item.trace_id)
    ordered_negatives = sorted(negatives, key=lambda item: item.trace_id)
    signed_dataset_digest = canonical_digest([item.as_dict() for item in ordered_envelopes])
    positive_trace_digest = canonical_digest([trace_payload(item) for item in ordered_positives])
    negative_trace_digest = canonical_digest([trace_payload(item) for item in ordered_negatives])
    signer_key_ids = tuple(sorted({item.signer_key_id for item in envelopes}))

    temporary = HardenedWorkflow(
        schema_version=HARDENED_WORKFLOW_SCHEMA,
        profile_id="workflow-profile:pending",
        candidate=candidate,
        guards=guards,
        signed_dataset_digest=signed_dataset_digest,
        positive_trace_digest=positive_trace_digest,
        negative_trace_digest=negative_trace_digest,
        signer_key_ids=signer_key_ids,
        positive_count=len(positives),
        negative_count=len(negatives),
    )
    profile_id = canonical_digest(temporary.identity_payload()).replace(
        "sha256:", "workflow-profile:", 1
    )
    profile = HardenedWorkflow(
        **{
            **temporary.__dict__,
            "profile_id": profile_id,
        }
    )
    profile.validate()
    return profile


@dataclass(frozen=True)
class RoutingDecision:
    mode: str
    reason: str
    proposal: Mapping[str, Any] | None
    requires_claimsieve: bool = True
    autonomous_execution_allowed: bool = False


@dataclass
class DriftMonitor:
    window_size: int = 20
    max_divergences: int = 0
    _matches: list[bool] = field(default_factory=list, init=False, repr=False)
    _tripped_reason: str | None = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        if isinstance(self.window_size, bool) or not isinstance(self.window_size, int) or self.window_size < 1:
            raise CrystallizationError("window_size must be a positive integer")
        if isinstance(self.max_divergences, bool) or not isinstance(self.max_divergences, int) or self.max_divergences < 0:
            raise CrystallizationError("max_divergences must be a non-negative integer")
        if self.max_divergences >= self.window_size:
            raise CrystallizationError("max_divergences must be smaller than window_size")

    @property
    def tripped(self) -> bool:
        return self._tripped_reason is not None

    @property
    def tripped_reason(self) -> str | None:
        return self._tripped_reason

    @property
    def observation_count(self) -> int:
        return len(self._matches)

    @property
    def divergence_count(self) -> int:
        return sum(not item for item in self._matches)

    def observe(
        self,
        match: bool,
        *,
        safety_violation: bool = False,
        reason: str = "behavioral_drift",
    ) -> None:
        if not isinstance(match, bool) or not isinstance(safety_violation, bool):
            raise CrystallizationError("drift observations must be boolean")
        if self.tripped:
            return
        if safety_violation:
            self._tripped_reason = reason or "safety_violation"
            return
        self._matches.append(match)
        if len(self._matches) > self.window_size:
            self._matches = self._matches[-self.window_size:]
        if len(self._matches) == self.window_size and self.divergence_count > self.max_divergences:
            self._tripped_reason = reason or "behavioral_drift"


def _guard_mismatch(profile: HardenedWorkflow, input_facts: Mapping[str, Any]) -> str | None:
    for guard in profile.guards:
        if guard.fact_name not in input_facts:
            return f"missing_guard_fact:{guard.fact_name}"
        if input_facts[guard.fact_name] != guard.expected_value:
            return f"guard_mismatch:{guard.fact_name}"
    return None


def route_work(
    profile: HardenedWorkflow,
    input_facts: Mapping[str, Any],
    *,
    policy_digest: str,
    monitor: DriftMonitor | None = None,
) -> RoutingDecision:
    profile.validate()
    if monitor is not None and monitor.tripped:
        return RoutingDecision(
            mode="AGENT_FALLBACK",
            reason="runtime_drift:" + str(monitor.tripped_reason),
            proposal=None,
        )
    if policy_digest != profile.candidate.required_policy_digest:
        return RoutingDecision(
            mode="AGENT_FALLBACK",
            reason="policy_drift",
            proposal=None,
        )
    mismatch = _guard_mismatch(profile, input_facts)
    if mismatch is not None:
        return RoutingDecision(
            mode="AGENT_FALLBACK",
            reason=mismatch,
            proposal=None,
        )
    try:
        proposal = compile_action(
            profile.candidate,
            input_facts,
            policy_digest=policy_digest,
        )
    except CrystallizationError:
        return RoutingDecision(
            mode="AGENT_FALLBACK",
            reason="runtime_fact_mismatch",
            proposal=None,
        )
    return RoutingDecision(
        mode="DETERMINISTIC_PROPOSAL",
        reason="within_learned_envelope",
        proposal=proposal,
    )


@dataclass(frozen=True)
class DriftObservation:
    trace_id: str
    eligible_for_monitor: bool
    matched_expected_action: bool
    safety_violation: bool
    reason: str
    monitor_tripped: bool


def observe_signed_execution(
    profile: HardenedWorkflow,
    envelope: SignedAgentTrace,
    trust_store: Mapping[str, PublicKey],
    monitor: DriftMonitor,
) -> DriftObservation:
    profile.validate()
    try:
        trace = verify_signed_trace(envelope, trust_store)
    except CrystallizationError:
        monitor.observe(
            False,
            safety_violation=True,
            reason="invalid_signed_execution_evidence",
        )
        raise

    if trace.capability_id != profile.candidate.capability_id:
        monitor.observe(False, safety_violation=True, reason="capability_drift")
        return DriftObservation(
            trace.trace_id, False, False, True, "capability_drift", monitor.tripped
        )
    if trace.risk_class != profile.candidate.risk_class:
        monitor.observe(False, safety_violation=True, reason="risk_class_drift")
        return DriftObservation(
            trace.trace_id, False, False, True, "risk_class_drift", monitor.tripped
        )
    if trace.policy_digest != profile.candidate.required_policy_digest:
        monitor.observe(False, safety_violation=True, reason="policy_drift")
        return DriftObservation(
            trace.trace_id, False, False, True, "policy_drift", monitor.tripped
        )

    mismatch = _guard_mismatch(profile, trace.input_facts)
    if mismatch is not None:
        return DriftObservation(
            trace.trace_id, False, False, False, mismatch, monitor.tripped
        )
    try:
        expected_action = compile_action(
            profile.candidate,
            trace.input_facts,
            policy_digest=trace.policy_digest,
        )
    except CrystallizationError:
        return DriftObservation(
            trace.trace_id,
            False,
            False,
            False,
            "runtime_fact_mismatch",
            monitor.tripped,
        )

    action_match = expected_action == dict(trace.proposed_action)
    verdict_ok = trace.claimsieve_verdict == "ALLOW"
    outcome_ok = trace.terminal_outcome == "CONFIRMED_SUCCESS"
    safety_violation = (
        not verdict_ok
        or trace.terminal_outcome in {"OUTCOME_UNKNOWN", "DIVERGENT_EFFECT"}
    )
    match = action_match and verdict_ok and outcome_ok
    if not action_match:
        reason = "action_divergence"
    elif not verdict_ok:
        reason = "claimsieve_verdict_drift"
    elif trace.terminal_outcome == "OUTCOME_UNKNOWN":
        reason = "outcome_unknown"
    elif trace.terminal_outcome == "DIVERGENT_EFFECT":
        reason = "divergent_effect"
    elif not outcome_ok:
        reason = "confirmed_failure"
    else:
        reason = "match"
    monitor.observe(match, safety_violation=safety_violation, reason=reason)
    return DriftObservation(
        trace_id=trace.trace_id,
        eligible_for_monitor=True,
        matched_expected_action=match,
        safety_violation=safety_violation,
        reason=reason,
        monitor_tripped=monitor.tripped,
    )
