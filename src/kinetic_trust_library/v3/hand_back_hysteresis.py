"""Declared capped hysteresis over complete authenticated audit-backed history.

Source authenticates actual stop/finding/expungement anchors, causation, audit
order and completeness. Library excludes wrongful history immediately, reports
missing mandatory expungements and keeps revoker accounting separate. No ledger
is modified and no standing cost is calculated or imposed by this module.
"""
from dataclasses import dataclass
from fractions import Fraction
from kinetic_trust_library.errors import ValidationError
from .root_lifecycle import _time
from .execution_observation import _name,_digest as is_digest


def _at(value):
    if type(value) in (int,Fraction) and 0<=value<=2**53-1:return Fraction(value)
    if type(value) is str:
        from .hand_back import _instant
        return _instant(value)
    raise ValidationError("exact supported hysteresis instant required")


def profile_terms(p):
    if (type(p) is not dict or set(p)!={"id","version","zone","formula","ledger_owner","append_protocol","window_seconds",
                "retention_seconds","revoker_repeat_threshold","classes"}
            or any(not _name(p[k]) for k in ("id","zone","ledger_owner","append_protocol"))
            or not _time(p["version"]) or p["version"]==0 or p["formula"]!="capped-linear-adjudicated-hysteresis-v1"
            or not _time(p["window_seconds"]) or p["window_seconds"]==0 or not _time(p["retention_seconds"])
            or not _time(p["revoker_repeat_threshold"]) or p["revoker_repeat_threshold"]<2
            or type(p["classes"]) is not dict or set(p["classes"])!={"Logistics","Coordination","Relational"}):
        raise ValidationError("invalid declared hysteresis policy")
    for kind,c in p["classes"].items():
        if (type(c) is not dict or set(c)!={"minimum_seconds","increment_seconds","cap_seconds"}
                or any(not _time(c[k]) for k in c) or c["increment_seconds"]==0 or c["cap_seconds"]<c["minimum_seconds"]
                or kind!="Logistics" and c["minimum_seconds"]==0):raise ValidationError("invalid finite class hysteresis bounds")
    if p["retention_seconds"]<p["window_seconds"]+max(c["cap_seconds"] for c in p["classes"].values()):
        raise ValidationError("reference policy requires history covering window plus largest active delay")
    return p


@dataclass(frozen=True,slots=True)
class HysteresisProjection:
    prior_adverse_count: int
    counted_ids: tuple[str,...]
    delay_seconds: int
    reissue_not_before: Fraction
    original_prior_adverse_count: int
    original_delay_seconds: int
    original_reissue_not_before: Fraction
    priced_stop_expunged: bool
    expungement_required: tuple[str,...]
    revoker_overturn_counts: tuple[tuple[str,str,int],...]
    revoker_accountability_required: tuple[tuple[str,str],...]


def project_hysteresis(profile,history,*,subject,consequence_class,issued_at,current_sequence,as_of,ledger_head_sequence):
    """Price one stop using knowledge then available, with current corrections.

    Prior confirmed stops on this subject across consequence classes count in
    the declared window. Actual audit order, not hash order, resolves same-tick
    events. Later confirmations never raise an old price; later overturn/false
    findings remove wrongful history even before append-only expungement catches
    up. Revoker findings use the complete zone-wide current window.
    """
    p=profile_terms(profile);issued=_at(issued_at);now=_at(as_of)
    if (not _name(subject) or type(consequence_class) is not str or consequence_class not in p["classes"] or not _time(current_sequence) or current_sequence==0
            or not _time(ledger_head_sequence) or current_sequence>ledger_head_sequence or issued>now
            or type(history) is not list or len(history)>4096):raise ValidationError("complete scoped hysteresis inventory required")
    seen=set();anchors=set();sequences=set();counted=[];original=[];corrections=[];revokers={};priced_expunged=False
    for e in history:
        if (type(e) is not dict or set(e)!={"id","stop_anchor","sequence","subject","consequence_class","variant","occurred_at","revoker",
                "causing_attestation_digest","adjudications","false_attestation_finding","expungement"}
                or not _name(e["id"]) or e["id"] in seen or not is_digest(e["stop_anchor"]) or e["stop_anchor"] in anchors
                or not _time(e["sequence"]) or not 0<e["sequence"]<=ledger_head_sequence or e["sequence"] in sequences
                or not _name(e["subject"]) or type(e["consequence_class"]) is not str or e["consequence_class"] not in p["classes"]
                or e["variant"] not in ("Expired","Revoked","Exceeded")
                or not (e["revoker"] is None if e["variant"]!="Revoked" else _name(e["revoker"]))
                or e["causing_attestation_digest"] is not None and not is_digest(e["causing_attestation_digest"])):
            raise ValidationError("invalid or duplicated actual hysteresis event")
        occurred=_at(e["occurred_at"])
        if occurred>now:raise ValidationError("future hysteresis event")
        seen.add(e["id"]);anchors.add(e["stop_anchor"]);sequences.add(e["sequence"])
        adjudications=e["adjudications"];finding=e["false_attestation_finding"];expungement=e["expungement"];bases={}
        if type(adjudications) is not list or len(adjudications)>4096:raise ValidationError("complete actual adjudication sequence required")
        previous=e["sequence"];rulings=set();then_confirmed=False;overturned=False
        for adjudication in adjudications:
            if (type(adjudication) is not dict or set(adjudication)!={"record_id","stop_anchor","sequence","decided_at","outcome"}
                    or adjudication["stop_anchor"]!=e["stop_anchor"]
                    or not _name(adjudication["record_id"]) or adjudication["record_id"] in rulings or not _time(adjudication["sequence"])
                    or not previous<adjudication["sequence"]<=ledger_head_sequence
                    or adjudication["outcome"] not in ("confirmed","overturned")
                    or overturned and adjudication["outcome"]=="confirmed"
                    or not occurred<=_at(adjudication["decided_at"])<=now):raise ValidationError("invalid actual adversity adjudication")
            previous=adjudication["sequence"];rulings.add(adjudication["record_id"])
            if adjudication["sequence"]<current_sequence and _at(adjudication["decided_at"])<=issued:
                then_confirmed=adjudication["outcome"]=="confirmed"
            if adjudication["outcome"]=="overturned":overturned=True
            if adjudication["outcome"]=="overturned":bases[adjudication["record_id"]]=(_at(adjudication["decided_at"]),adjudication["sequence"])
        if finding is not None:
            if (type(finding) is not dict or set(finding)!={"record_id","sequence","found_at","attestation_digest"}
                    or not _name(finding["record_id"]) or not _time(finding["sequence"]) or not 0<finding["sequence"]<=ledger_head_sequence
                    or e["variant"]!="Exceeded" or e["causing_attestation_digest"] is None
                    or finding["attestation_digest"]!=e["causing_attestation_digest"] or _at(finding["found_at"])>now):
                raise ValidationError("false finding must answer the actual causing attestation")
            bases[finding["record_id"]]=(_at(finding["found_at"]),finding["sequence"])
        if expungement is not None:
            if (type(expungement) is not dict or set(expungement)!={"record_id","stop_anchor","sequence","recorded_at","basis_record_id"}
                    or expungement["stop_anchor"]!=e["stop_anchor"] or not _name(expungement["basis_record_id"])
                    or not _name(expungement["record_id"]) or expungement["basis_record_id"] not in bases
                    or not _time(expungement["sequence"]) or not max(e["sequence"],bases[expungement["basis_record_id"]][1])<expungement["sequence"]<=ledger_head_sequence
                    or not max(occurred,bases[expungement["basis_record_id"]][0])<=_at(expungement["recorded_at"])<=now):
                raise ValidationError("expungement lacks its actual overturn/false finding basis")
        if e["sequence"]==current_sequence:
            if e["subject"]!=subject or e["consequence_class"]!=consequence_class or occurred!=issued:
                raise ValidationError("priced audit position belongs to another stop")
            if e["variant"]=="Expired":raise ValidationError("routine expiry has no adverse price")
            priced_expunged=bool(bases)
        if e["variant"]!="Expired" and bases and expungement is None:corrections.append(e["id"])
        if (e["variant"]=="Revoked" and overturned
                and now-p["window_seconds"]<=occurred<=now):
            key=(e["revoker"],e["consequence_class"]);revokers[key]=revokers.get(key,0)+1
        if (e["subject"]==subject and e["variant"]!="Expired" and then_confirmed and e["sequence"]<current_sequence
                and issued-p["window_seconds"]<=occurred<=issued):
            if not any(time<=issued and sequence<current_sequence for time,sequence in bases.values()):original.append(e["id"])
            if not bases:counted.append(e["id"])
    c=p["classes"][consequence_class];delay=min(c["cap_seconds"],c["minimum_seconds"]+len(counted)*c["increment_seconds"])
    original_delay=min(c["cap_seconds"],c["minimum_seconds"]+len(original)*c["increment_seconds"])
    if issued+max(delay,original_delay)>2**53-1:raise ValidationError("reissue bound exceeds supported clock range")
    return HysteresisProjection(len(counted),tuple(sorted(counted)),delay,issued+delay,len(original),original_delay,issued+original_delay,priced_expunged,tuple(sorted(corrections)),
        tuple((*key,count) for key,count in sorted(revokers.items())),
        tuple(key for key,count in sorted(revokers.items()) if count>=p["revoker_repeat_threshold"]))
