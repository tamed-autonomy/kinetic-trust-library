"""Non-authorizing software magnitude, availability and supervision joins.

The caller authenticates facts and independently establishes all bindings and
prerequisites. This arithmetic neither verifies a signed software decision nor
enables the optional software execution profile on an ordinary native verifier.
"""
from dataclasses import dataclass
from kinetic_trust_library.errors import ValidationError
from .native_envelope import NativeEnvelopeThresholds,project_comparable_envelope
from .supervision_rails import LEVELS
from .root_lifecycle import _time


MAGNITUDES=("effectBytes","affectedObjects","fanoutTargets")


def software_magnitudes(value):
    if type(value) is not dict or set(value)!=set(MAGNITUDES) or any(not _time(v) for v in value.values()):
        raise ValidationError("all three software magnitudes require nonnegative safe integer tokens")
    return value


@dataclass(frozen=True,slots=True,init=False)
class SoftwareRestrictionProjection:
    supervision: str
    ceilings: tuple[tuple[str,int],...]
    capacity_known: bool
    margin: object
    conditional_candidate: bool
    action_permitted: bool

    def __init__(self,*args,**kwargs):raise TypeError("software restrictions require derived non-widening composition")


def project_software_restrictions(*,requested,candidate_ceilings,prior_ceilings,candidate_supervision,prior_supervision,
        demand,capacity,capacity_known,repair_path_verified,supervision_available,thresholds=None):
    """Preserve every floor and maximum on the selected native 0..100 scale.

    Availability loss withholds all effect magnitudes. A caller must evaluate a
    changed actual scope afresh; attaching lower numbers cannot authorize the
    original operation. No fixture authentication/compliance flag is accepted.
    """
    requested=software_magnitudes(requested);candidate=software_magnitudes(candidate_ceilings);prior=software_magnitudes(prior_ceilings)
    if (candidate_supervision not in LEVELS or prior_supervision not in LEVELS
            or any(type(v) is not bool for v in (capacity_known,repair_path_verified,supervision_available))
            or thresholds is not None and type(thresholds) is not NativeEnvelopeThresholds):
        raise ValidationError("explicit software availability/capacity state and installed supervision policy required")
    margin=None;level="silent_veto"
    ceilings={k:min(requested[k],candidate[k],prior[k]) for k in MAGNITUDES}
    if (candidate_supervision!="silent_veto" and prior_supervision!="silent_veto" and repair_path_verified and supervision_available):
        envelope=project_comparable_envelope(demand=demand,decision_capacity=capacity,capacity_known=capacity_known,thresholds=thresholds)
        margin=envelope.margin
        level=max((candidate_supervision,prior_supervision,envelope.supervision),key=LEVELS.index)
        if not capacity_known and LEVELS.index(level)<LEVELS.index("assisted"):level="assisted"
    if level=="silent_veto":ceilings=dict.fromkeys(MAGNITUDES,0)
    result=object.__new__(SoftwareRestrictionProjection)
    for k,v in dict(supervision=level,ceilings=tuple((k,ceilings[k]) for k in MAGNITUDES),capacity_known=capacity_known,
            margin=margin,conditional_candidate=level!="silent_veto",action_permitted=False).items():object.__setattr__(result,k,v)
    return result
