"""Recognition cannot import a term; offered coordination is an own-zone act.

Inputs are authenticated semantic facts, not a new signed agreement format.
No projection creates an adoption, obligation, breach or permission to execute.
"""
from dataclasses import dataclass
from kinetic_trust_library.errors import ValidationError
from .root_lifecycle import _time


RECOGNITION_VOID_EFFECTS=frozenset(("recognition-obligation","recognition-membership-condition"))


def _name(value):return type(value) is str and bool(value)


@dataclass(frozen=True,slots=True,init=False)
class RecognitionAssessment:
    clause_void: bool
    term_created: bool
    obligation_created: bool
    changes_agreement: bool

    def __init__(self,*args,**kwargs):raise TypeError("recognition assessment requires classified original clause facts")


def assess_recognition_clause(effect):
    if type(effect) is not str or effect not in RECOGNITION_VOID_EFFECTS|{"recognition-only"}:
        raise ValidationError("unclassified recognition effect cannot establish a term")
    result=object.__new__(RecognitionAssessment)
    for k,v in dict(clause_void=effect in RECOGNITION_VOID_EFFECTS,term_created=False,obligation_created=False,changes_agreement=False).items():
        object.__setattr__(result,k,v)
    return result


@dataclass(frozen=True,slots=True,init=False)
class CoordinationHistoryProjection:
    zone: str
    coordination: str
    adopted: bool
    latest_anchor: str | None
    latest_sequence: int | None
    adoption_is_agreement_term: bool
    withdrawal_is_breach: bool
    changes_agreement: bool
    action_permitted: bool

    def __init__(self,*args,**kwargs):raise TypeError("coordination history requires complete actual own-zone acts")


def project_coordination_history(*,zone,coordination,offered_coordination,acts,evaluated_at):
    if (not _name(zone) or not _name(coordination) or not _time(evaluated_at) or type(offered_coordination) is not tuple
            or len(offered_coordination)>4096 or any(not _name(c) for c in offered_coordination)
            or len(set(offered_coordination))!=len(offered_coordination) or coordination not in offered_coordination
            or type(acts) is not tuple or len(acts)>4096):
        raise ValidationError("actual offered coordination, own zone and complete bounded act history required")
    ids=set();anchors=set();sequence=-1;occurred=-1;adopted=False;latest_anchor=None
    for act in acts:
        if (type(act) is not dict or set(act)!={"id","anchor","sequence","occurred_at","zone","coordination","kind"}
                or not _name(act["id"]) or not _name(act["anchor"]) or act["zone"]!=zone or act["coordination"]!=coordination
                or act["kind"] not in ("adopt","withdraw") or not _time(act["sequence"]) or act["sequence"]<=sequence
                or not _time(act["occurred_at"]) or not occurred<=act["occurred_at"]<=evaluated_at
                or act["id"] in ids or act["anchor"] in anchors):
            raise ValidationError("coordination act is not an original ordered current own-zone adoption/withdrawal")
        ids.add(act["id"]);anchors.add(act["anchor"]);sequence=act["sequence"];occurred=act["occurred_at"]
        latest_anchor=act["anchor"];adopted=act["kind"]=="adopt"
    result=object.__new__(CoordinationHistoryProjection)
    for k,v in dict(zone=zone,coordination=coordination,adopted=adopted,latest_anchor=latest_anchor,
            latest_sequence=None if not acts else sequence,adoption_is_agreement_term=False,withdrawal_is_breach=False,
            changes_agreement=False,action_permitted=False).items():object.__setattr__(result,k,v)
    return result
