"""Deterministic Core §7.6 execution-boundary observation classification.

Private authenticated semantic inputs, not audit wire records. In this contract
`executed` means observed dispatch, not #139 downstream effect confirmation.
Recording a failure/opening a breach are returned obligations, never asserted
side effects. A decision alone supplies no observation of execution or its lack.
"""
from dataclasses import dataclass
import re
from kinetic_trust_library.errors import ValidationError
from .root_lifecycle import _time
from .supervision_rails import LEVELS


def _name(value):return type(value) is str and bool(value) and not any(c.isspace() for c in value)
def _digest(value):return type(value) is str and re.fullmatch(r"(?:sha256:[0-9a-f]{64}|sha384:[0-9a-f]{96})",value) is not None


@dataclass(frozen=True,slots=True)
class ExecutionScope:
    actor: str
    operation_digest: str
    zone: str
    topology_epoch: int

    def __post_init__(self):
        if not _name(self.actor) or not _digest(self.operation_digest) or not _name(self.zone) or not _time(self.topology_epoch):
            raise ValidationError("invalid complete execution scope")


@dataclass(frozen=True,slots=True)
class ExecutionDecision:
    scope: ExecutionScope
    decision_id: str
    record_digest: str
    decided_at: int
    execution_permitted: bool
    supervision: str

    def __post_init__(self):
        if (type(self.scope) is not ExecutionScope or not _name(self.decision_id) or not _digest(self.record_digest)
                or not _time(self.decided_at) or type(self.execution_permitted) is not bool
                or self.supervision not in LEVELS or self.execution_permitted and self.supervision=="silent_veto"):
            raise ValidationError("invalid execution decision projection")


@dataclass(frozen=True,slots=True)
class ExecutionObservation:
    scope: ExecutionScope
    decision_id: str | None
    decision_digest: str | None
    boundary_id: str
    kind: str
    observed_at: int

    def __post_init__(self):
        if (type(self.scope) is not ExecutionScope or not _name(self.boundary_id)
                or self.kind not in ("dispatch","non_dispatch") or not _time(self.observed_at)
                or not (self.decision_id is None and self.decision_digest is None
                        or _name(self.decision_id) and _digest(self.decision_digest))):
            raise ValidationError("invalid execution-boundary observation projection")


@dataclass(frozen=True,slots=True)
class ExecutionObservationProjection:
    effect: str
    reason: str
    bypass: bool
    conformance_failure_record_required: bool
    breach_record_required: bool
    reportable_as_not_executed: bool


def classify_execution_observation(*,scope,decision,observation,enforcement_point_present):
    """Classify only observations bound to this exact historical operation.

    `decision=None` must mean authenticated absence, not a failed record lookup.
    On a route with an enforcement point a missing decision remains unverified
    in this reference; it cannot establish a valid permit or non-execution.
    """
    if (type(scope) is not ExecutionScope or decision is not None and type(decision) is not ExecutionDecision
            or observation is not None and type(observation) is not ExecutionObservation
            or type(enforcement_point_present) is not bool):
        raise ValidationError("exact execution observation inputs required")
    def result(effect,reason,bypass=False):
        return ExecutionObservationProjection(effect,reason,bypass,bypass,bypass,effect=="not-executed")
    if decision is not None and decision.scope!=scope:return result("unverified","EXECUTION_DECISION_SCOPE")
    if observation is None:return result("unverified","EXECUTION_OBSERVATION_ABSENT")
    if observation.scope!=scope:return result("unverified","EXECUTION_OBSERVATION_SCOPE")
    if decision is None:
        if observation.kind=="dispatch" and not enforcement_point_present:
            return result("executed","EXECUTION_UNENFORCED_BYPASS",True)
        return result("unverified","EXECUTION_DECISION_MISSING")
    if (observation.decision_id!=decision.decision_id or observation.decision_digest!=decision.record_digest
            or observation.observed_at<decision.decided_at):
        return result("unverified","EXECUTION_OBSERVATION_BINDING")
    if observation.kind=="non_dispatch":return result("not-executed","EXECUTION_NON_DISPATCH_OBSERVED")
    return result("executed","EXECUTION_DISPATCH_OBSERVED" if decision.execution_permitted
                  else "EXECUTION_DENIAL_BYPASS",not decision.execution_permitted)
