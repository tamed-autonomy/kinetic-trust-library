"""Earned repair-ceiling lift under an explicitly installed ordinary-rail policy.

No lift formula is invented here. The installed pure projector computes its
declared formula over authenticated post-record acts; endpoint/prefix checks
prevent time alone, invalid acts or an empty set from earning a lift.
"""
from dataclasses import dataclass
from decimal import Decimal
import re
from kinetic_trust_library._decimal import as_decimal
from kinetic_trust_library.errors import ValidationError
from .root_lifecycle import _time
from .trust_proof_json import _parse_jcs_object
from .repair import ReentryProjection


def _digest_shape(value):
    return type(value) is str and re.fullmatch(r"(?:sha256:[0-9a-f]{64}|sha384:[0-9a-f]{96})",value) is not None


@dataclass(frozen=True,slots=True)
class EarnedRepairAct:
    anchor: str
    recorded_at: int
    lineage: str
    ordinary_profile_digest: str
    record_bytes: bytes
    current_anchor_verified: bool
    ordinary_admissible: bool


def project_earned_ceiling(reentry,acts,*,lineage,evaluated_at,profile_bytes,adapter):
    if (type(reentry) is not ReentryProjection or not reentry.record_valid
            or type(acts) is not tuple or len(acts)>4096 or any(type(act) is not EarnedRepairAct for act in acts)
            or type(lineage) is not str or not lineage or not _time(evaluated_at) or evaluated_at<reentry.anchored_at
            or type(profile_bytes) is not bytes or not callable(getattr(adapter,"project",None))):
        raise ValidationError("earned repair requires an anchored record and installed policy")
    seen=set();accepted=[]
    for act in acts:
        if (not _digest_shape(act.anchor) or not _digest_shape(act.ordinary_profile_digest) or act.anchor in seen
                or not _time(act.recorded_at) or type(act.lineage) is not str or not act.lineage
                or type(act.current_anchor_verified) is not bool or type(act.ordinary_admissible) is not bool
                or type(act.record_bytes) is not bytes or not 0<len(act.record_bytes)<=262144):
            raise ValidationError("invalid or duplicate earned repair act")
        _parse_jcs_object(act.record_bytes)
        seen.add(act.anchor)
        if (act.current_anchor_verified and act.ordinary_admissible and act.lineage==lineage
                and reentry.anchored_at<act.recorded_at<=evaluated_at):accepted.append(act)
    accepted.sort(key=lambda act:(act.recorded_at,act.anchor))
    value=reentry.ceiling
    for count in range(len(accepted)+1):
        proposed=as_decimal(adapter.project(base_ceiling=reentry.ceiling,acts=tuple(accepted[:count]),profile_bytes=profile_bytes),
            name="earned repair ceiling",minimum=0,maximum=100)
        if (count==0 and proposed!=reentry.ceiling) or proposed<value:
            raise ValidationError("repair policy produced an unearned or decreasing ceiling lift")
        value=proposed
    return value


__all__=("EarnedRepairAct","project_earned_ceiling")
