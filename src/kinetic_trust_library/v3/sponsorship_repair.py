"""Repair-based sponsorship admission at the bond's authenticated opening.

The installed source verifies the complete bond (or its current anchor), actual
opening, published policy and complete root-lineage inventory at that opening,
including any prior blocked state. This is one genesis prerequisite, never a
genesis record, authorization or a statement of active bond credit today.
"""
from dataclasses import dataclass
from fractions import Fraction
from kinetic_trust_library._decimal import as_decimal
from kinetic_trust_library.errors import ValidationError
from .trust_proof_json import _parse_jcs_object
from .root_lifecycle import _time
from .demand_supplier import _digest
from .installed_repair import HARD_ENTRIES


def _profile(raw):
    profile=_parse_jcs_object(raw)
    if (set(profile)!={"id","version","entry_classes","aggregate_count_limit"} or type(profile["id"]) is not str or not profile["id"]
            or not _time(profile["version"]) or profile["version"]==0 or type(profile["entry_classes"]) is not dict
            or not HARD_ENTRIES<=profile["entry_classes"].keys() or not _time(profile["aggregate_count_limit"])):
        raise ValidationError("invalid declared sponsorship repair policy")
    capacities=[]
    for name,value in profile["entry_classes"].items():
        if (not name or type(value) is not dict or set(value)!={"hard","count_limit","declared_capacity"}
                or type(value["hard"]) is not bool or name in HARD_ENTRIES and not value["hard"]
                or not _time(value["count_limit"]) or value["hard"] and value["count_limit"]>1):
            raise ValidationError("invalid sponsorship breach count limit")
        capacity=as_decimal(value["declared_capacity"],name="declared repair capacity",minimum=0)
        capacities.append(Fraction(capacity))
        if value["count_limit"]>capacity:raise ValidationError("sponsorship count limit exceeds repair capacity")
    if profile["aggregate_count_limit"]>sum(capacities):raise ValidationError("aggregate sponsorship limit exceeds repair capacity")
    return profile



def sponsorship_counts_eligible(profile,counts,blocked,aggregate_blocked,hard_blocked):
    """Internal predicate for an authenticated, validated published profile."""
    if (type(counts) is not dict or counts.keys()!=profile["entry_classes"].keys() or any(not _time(value) for value in counts.values())
            or type(blocked) is not list or any(type(name) is not str or name not in counts for name in blocked)
            or len(set(blocked))!=len(blocked) or type(aggregate_blocked) is not bool or type(hard_blocked) is not bool):
        raise ValidationError("complete root-lineage counts and prior blocking state required")
    total=sum(counts.values());hard=sum(count for name,count in counts.items() if profile["entry_classes"][name]["hard"])
    eligible=(total<=profile["aggregate_count_limit"] and (not aggregate_blocked or total<profile["aggregate_count_limit"])
        and hard<=1 and (not hard_blocked or hard<1) and all(count<=profile["entry_classes"][name]["count_limit"]
        and (name not in blocked or count<profile["entry_classes"][name]["count_limit"]) for name,count in counts.items())
    )
    return eligible

@dataclass(frozen=True,slots=True)
class AuthenticatedSponsorshipContext:
    state_bytes: bytes
    bond_body_bytes: bytes
    evidence_bytes: bytes


@dataclass(frozen=True,slots=True,init=False)
class SponsorshipRepairAssessment:
    eligible: bool
    reason: str
    opened_at: int
    checked_at: int
    expires_at: int
    zone_id: str
    root: str
    subject: str
    bond_id: str
    context_bytes: bytes
    complete_instrument_bytes: bytes
    authenticated_bond_body_bytes: bytes
    profile_bytes: bytes
    authenticated_state_bytes: bytes
    source_evidence_bytes: bytes

    def __init__(self,*args,**kwargs):raise TypeError("sponsorship repair assessments require installed verification")


@dataclass(frozen=True,slots=True)
class InstalledSponsorshipRepairVerifier:
    deployment_profile_bytes: bytes
    profile_bytes: bytes
    context_source: object
    algorithm: str
    expected_zone: str

    def __post_init__(self):
        if (type(self.deployment_profile_bytes) is not bytes or type(self.profile_bytes) is not bytes
                or self.algorithm not in ("sha256","sha384") or not callable(getattr(self.context_source,"resolve",None))
                or type(self.expected_zone) is not str or not self.expected_zone):
            raise ValidationError("invalid installed sponsorship repair verifier")
        _parse_jcs_object(self.deployment_profile_bytes);_profile(self.profile_bytes)

    def evaluate(self,instrument_bytes,*,context_bytes,evaluated_at,clock_healthy):
        import hashlib
        if (type(instrument_bytes) is not bytes or not 0<len(instrument_bytes)<=262144 or type(context_bytes) is not bytes
                or not _time(evaluated_at) or clock_healthy is not True):
            raise ValidationError("sponsorship opening requires bounded immutable evidence and trusted time")
        context=_parse_jcs_object(context_bytes);profile=_profile(self.profile_bytes)
        deployment=_digest(_parse_jcs_object(self.deployment_profile_bytes),self.algorithm);policy=_digest(profile,self.algorithm)
        if (context.get("deployment_digest")!=deployment or context.get("sponsorship_repair_profile_digest")!=policy
                or context.get("subject_profile")!="software"):
            raise ValidationError("sponsorship policy differs from installed identity/deployment context")
        source=self.context_source.resolve(instrument_bytes=instrument_bytes,context_bytes=context_bytes,
            deployment_profile_bytes=self.deployment_profile_bytes,profile_bytes=self.profile_bytes,evaluated_at=evaluated_at)
        if (type(source) is not AuthenticatedSponsorshipContext or type(source.state_bytes) is not bytes
                or type(source.bond_body_bytes) is not bytes or type(source.evidence_bytes) is not bytes or not source.evidence_bytes):
            raise ValidationError("sponsorship source must authenticate the complete opening inventory")
        state=_parse_jcs_object(source.state_bytes);body=_parse_jcs_object(source.bond_body_bytes)
        digest=self.algorithm+":"+hashlib.new(self.algorithm,instrument_bytes).hexdigest()
        if (set(state)!={"deployment_digest","profile_digest","context_digest","instrument_digest","body_digest","root","subject","bond_id",
                "opened_at","checked_at","expires_at","zone_id","opening_anchor_verified","counts","blocked_classes","aggregate_blocked","hard_blocked"}
                or state["deployment_digest"]!=deployment or state["profile_digest"]!=policy
                or state["context_digest"]!=_digest(context,self.algorithm) or state["instrument_digest"]!=digest
                or state["body_digest"]!=_digest(body,self.algorithm) or body.get("kind")!="sponsorship_bond"
                or state["subject"]!=context.get("subject") or state["subject"]!=body.get("subject")
                or state["root"]!=body.get("issuer") or state["bond_id"]!=body.get("id")
                or any(type(state[name]) is not str or not state[name] for name in ("root","subject","bond_id"))
                or state["zone_id"]!=self.expected_zone or state["opening_anchor_verified"] is not True
                or not _time(state["checked_at"]) or state["checked_at"]!=evaluated_at
                or not _time(state["expires_at"]) or state["expires_at"]<=evaluated_at
                or not _time(state["opened_at"]) or not _time(body.get("start_time")) or not _time(body.get("end_time"))
                or not state["opened_at"]<=body["start_time"]<body["end_time"] or state["opened_at"]>evaluated_at):
            raise ValidationError("sponsorship opening differs from current authenticated identity/instrument/policy")
        eligible=sponsorship_counts_eligible(profile,state["counts"],state["blocked_classes"],state["aggregate_blocked"],state["hard_blocked"])
        result=object.__new__(SponsorshipRepairAssessment)
        for name,value in dict(eligible=eligible,reason="SPONSORSHIP_OPENING_ELIGIBLE" if eligible else "SPONSORSHIP_BREACH_LIMIT",
            opened_at=state["opened_at"],checked_at=evaluated_at,expires_at=state["expires_at"],zone_id=self.expected_zone,
            root=state["root"],subject=state["subject"],bond_id=state["bond_id"],context_bytes=context_bytes,
            complete_instrument_bytes=instrument_bytes,authenticated_bond_body_bytes=source.bond_body_bytes,
            profile_bytes=self.profile_bytes,authenticated_state_bytes=source.state_bytes,source_evidence_bytes=source.evidence_bytes).items():object.__setattr__(result,name,value)
        return result


__all__=("InstalledSponsorshipRepairVerifier","SponsorshipRepairAssessment","AuthenticatedSponsorshipContext")
