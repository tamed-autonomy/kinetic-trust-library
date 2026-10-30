"""Pure managed/unmanaged history and uniform public denial projections.

Source owns complete attested classification history and actual request identity.
Nothing here authenticates a proof or grants action permission. Delivery of final
hand-backs and operational response timing require separate installed checks.
"""
from dataclasses import dataclass,field
import json
from kinetic_trust_library.errors import ValidationError
from .root_lifecycle import _time
from .execution_observation import _name,_digest as is_digest


@dataclass(frozen=True,slots=True)
class ManagementHistoryProjection:
    regime: str
    ever_managed: bool
    demotion_digests: tuple
    final_hand_back_digest: str | None
    action_permitted: bool=field(default=False,init=False)


def project_management_history(*,history,declared_regime,event_count,ledger_head_sequence,evaluated_at):
    if (type(history) is not list or len(history)>4096 or declared_regime not in ("managed","unmanaged")
            or not _time(event_count) or event_count!=len(history)
            or not _time(ledger_head_sequence) or not _time(evaluated_at)):
        raise ValidationError("complete bounded actual classification history required")
    regime="unmanaged";previous_sequence=-1;previous_at=0;anchors=set();digests=[];final=None;ever=False
    for e in history:
        if (type(e) is not dict or set(e)!={"kind","anchor","sequence","occurred_at","authority","hand_back_digest"}
                or e["kind"] not in ("admitted","demoted") or not _name(e["anchor"]) or e["anchor"] in anchors
                or not _name(e["authority"]) or not _time(e["sequence"])
                or not previous_sequence<e["sequence"]<=ledger_head_sequence
                or not _time(e["occurred_at"]) or not previous_at<=e["occurred_at"]<=evaluated_at):
            raise ValidationError("classification history has invalid events or audit order")
        if e["kind"]=="admitted":
            if regime!="unmanaged" or e["hand_back_digest"] is not None:
                raise ValidationError("admission must follow unmanaged classification")
            regime="managed";ever=True;final=None
        else:
            if regime!="managed" or not is_digest(e["hand_back_digest"]) or e["hand_back_digest"] in digests:
                raise ValidationError("demotion must retain a distinct final hand-back")
            regime="unmanaged";final=e["hand_back_digest"];digests.append(final)
        anchors.add(e["anchor"]);previous_sequence=e["sequence"];previous_at=e["occurred_at"]
    if regime!=declared_regime:raise ValidationError("declared regime rewrites actual classification history")
    return ManagementHistoryProjection(regime,ever,tuple(digests),final)


@dataclass(frozen=True,slots=True)
class UniformUnmanagedResponse:
    status: int | None
    code: str | None
    body_bytes: bytes | None
    action_permitted: bool=field(default=False,init=False)


def unmanaged_response(*,hostile_facing,wire_silence,admission,admission_endpoint,credential_bytes=None):
    """Select only declared surface behavior; credential variants never vary it.

    Caller must already have an authenticated unmanaged classification. Raw
    credentials are deliberately never parsed, evaluated or echoed here.
    """
    if (any(type(v) is not bool for v in (hostile_facing,wire_silence,admission))
            or wire_silence and not hostile_facing or not _name(admission_endpoint)
            or credential_bytes is not None and type(credential_bytes) is not bytes):
        raise ValidationError("unmanaged response requires declared surface/admission policy")
    if wire_silence and not admission:return UniformUnmanagedResponse(None,None,None)
    body=json.dumps(dict(admission_endpoint=admission_endpoint),
        sort_keys=True,separators=(",",":"),ensure_ascii=True).encode("utf-8")
    return UniformUnmanagedResponse(401,"NO_TRUST_RELATION",body)
