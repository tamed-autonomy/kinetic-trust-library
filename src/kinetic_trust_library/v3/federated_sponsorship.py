"""Current cross-zone bond evidence with opening and active credit separated.

The source authenticates the complete signed bond/current anchor, original home
inventory and all-zone lineage counts at opening, current home ownership and
capital facts, signed directional agreements/admissions, current sponsor-local
prerequisites, withdrawal and severance. These are semantic adapter projections,
not a new wire, reservation mechanism, genesis or execution permission.
"""
from dataclasses import dataclass,fields,replace
from fractions import Fraction
import hashlib
from kinetic_trust_library.errors import ValidationError
from .trust_proof_json import _parse_jcs_object
from .demand_supplier import _digest
from .root_lifecycle import _time
from .ambient_repair import ratio
from .federation import InstalledFederationVerifier
from .federation_terms import profile_terms,agreement_terms,name,identifiers
from .sponsorship_capital import BondCapital,project_sponsor_capital
from .sponsorship_repair import _profile as repair_profile,sponsorship_counts_eligible

SPONSOR_CREDIT_PREFIX="federated_sponsor_credit."


def _profile(raw):
    value=_parse_jcs_object(raw)
    if (set(value)-{"root_binding"}!={"id","version","receiving_zone","formula","federation_profile_digest","sponsor_admission_floor"}
            or not name(value["id"]) or not name(value["receiving_zone"]) or not _time(value["version"]) or value["version"]==0
            or value["formula"]!="home-reserve-and-receiver-measure-v1"):
        raise ValidationError("invalid selected cross-zone sponsorship profile")
    if "root_binding" in value and value["root_binding"]!="credit-digest-ceiling-v1":
        raise ValidationError("unsupported cross-zone root credit binding")
    ratio(value["sponsor_admission_floor"],name="receiver sponsor admission floor",maximum=100)
    return value


@dataclass(frozen=True,slots=True)
class AuthenticatedFederatedSponsorshipContext:
    state_bytes: bytes
    bond_body_bytes: bytes
    evidence_bytes: bytes


@dataclass(frozen=True,slots=True,init=False)
class FederatedSponsorshipAssessment:
    opening_valid: bool
    active: bool
    reason: str
    sponsor_measure: Fraction | None
    root_sponsor_basis: Fraction | None
    receiver_collateral: Fraction
    subject_intrinsic_base: Fraction
    home_capital: object
    ends_at: int
    checked_at: int
    expires_at: int
    opened_at: int
    home_zone: str
    receiving_zone: str
    sponsor: str
    subject: str
    bond_id: str
    context_bytes: bytes
    complete_instrument_bytes: bytes
    authenticated_bond_body_bytes: bytes
    profile_bytes: bytes
    federation_profile_bytes: bytes
    authenticated_state_bytes: bytes
    source_evidence_bytes: bytes
    frame_digest: str
    frame_bytes: bytes
    credit_ceiling_name: str | None

    def __init__(self,*args,**kwargs):raise TypeError("cross-zone sponsorship requires installed verification")


def _commitments(items):
    if type(items) is not list or len(items)>4096:raise ValidationError("complete bounded home capital inventory required")
    values=[]
    for item in items:
        if type(item) is not dict or set(item)!={field.name for field in fields(BondCapital)}:
            raise ValidationError("incomplete owned sponsorship capital record")
        values.append(BondCapital(**item))
    return tuple(values)


def _admission(state,*,sponsor,home,receiver,profile,at,algorithm):
    required={"subject","subject_profile","from_zone","to_zone","enforcement_class","action_class","substrate_profile",
        "receiver_accepting","required_sovereignty","lowered_factors","agreement","attestation","ingress_at"}
    if (type(state) is not dict or set(state)!=required or state["subject"]!=sponsor or state["subject_profile"]!="software"
            or state["from_zone"]!=home or state["to_zone"]!=receiver
            or any(not name(state[key]) for key in ("enforcement_class","action_class","substrate_profile"))
            or type(state["receiver_accepting"]) is not bool or not _time(state["ingress_at"]) or state["ingress_at"]>at):
        raise ValidationError("sponsor admission differs from authenticated bond party/time/direction")
    identifiers(state["required_sovereignty"])
    result=dict(admitted=False,factor=None,exportable_base=None,expires_at=at+1,agreement_end=None,sponsorship_allowed=False)
    try:
        agreement_terms(state["agreement"])
        result["agreement_end"]=state["agreement"]["expires_at"]
        result["sponsorship_allowed"]=state["agreement"]["data_handling"]["cross_zone_sponsorship"]
        result["expires_at"]=state["agreement"]["expires_at"]
        InstalledFederationVerifier._project(state,profile,result,at,algorithm)
    except ValidationError:result.update(admitted=False,exportable_base=None)
    return result


@dataclass(frozen=True,slots=True)
class InstalledFederatedSponsorshipVerifier:
    deployment_profile_bytes: bytes
    profile_bytes: bytes
    federation_profile_bytes: bytes
    context_source: object
    algorithm: str

    def __post_init__(self):
        if (any(type(value) is not bytes for value in (self.deployment_profile_bytes,self.profile_bytes,self.federation_profile_bytes))
                or self.algorithm not in ("sha256","sha384") or not callable(getattr(self.context_source,"resolve",None))):
            raise ValidationError("invalid installed cross-zone sponsorship verifier")
        _parse_jcs_object(self.deployment_profile_bytes);profile=_profile(self.profile_bytes)
        federation=profile_terms(_parse_jcs_object(self.federation_profile_bytes))
        if (profile["federation_profile_digest"]!=_digest(federation,self.algorithm)
                or profile["receiving_zone"]!=federation["receiving_zone"]):
            raise ValidationError("cross-zone sponsorship differs from installed receiver federation profile")

    def evaluate(self,instrument_bytes,*,context_bytes,evaluated_at,clock_healthy):
        if (type(instrument_bytes) is not bytes or not 0<len(instrument_bytes)<=262144 or type(context_bytes) is not bytes
                or not _time(evaluated_at) or clock_healthy is not True):
            raise ValidationError("cross-zone sponsorship requires immutable evidence and trusted current time")
        context=_parse_jcs_object(context_bytes);profile=_profile(self.profile_bytes)
        deployment=_digest(_parse_jcs_object(self.deployment_profile_bytes),self.algorithm);policy=_digest(profile,self.algorithm)
        if (context.get("deployment_digest")!=deployment or context.get("federated_sponsorship_profile_digest")!=policy
                or context.get("subject_profile")!="software"):
            raise ValidationError("cross-zone sponsorship differs from installed identity/deployment context")
        source=self.context_source.resolve(instrument_bytes=instrument_bytes,context_bytes=context_bytes,
            deployment_profile_bytes=self.deployment_profile_bytes,profile_bytes=self.profile_bytes,
            federation_profile_bytes=self.federation_profile_bytes,evaluated_at=evaluated_at)
        if (type(source) is not AuthenticatedFederatedSponsorshipContext or type(source.state_bytes) is not bytes or len(source.state_bytes)>262144
                or type(source.bond_body_bytes) is not bytes or type(source.evidence_bytes) is not bytes or not source.evidence_bytes):
            raise ValidationError("cross-zone sponsorship source must authenticate complete historical and current facts")
        state=_parse_jcs_object(source.state_bytes);body=_parse_jcs_object(source.bond_body_bytes)
        if (set(state)!={"deployment_digest","profile_digest","context_digest","instrument_digest","body_digest","checked_at","expires_at",
                "receiving_zone","home_zone","root","sponsor","subject","bond_id","opened_at","opening","current"}
                or state["deployment_digest"]!=deployment or state["profile_digest"]!=policy or state["context_digest"]!=_digest(context,self.algorithm)
                or state["instrument_digest"]!=self.algorithm+":"+hashlib.new(self.algorithm,instrument_bytes).hexdigest()
                or state["body_digest"]!=_digest(body,self.algorithm) or body.get("kind")!="sponsorship_bond"
                or state["subject"]!=context.get("subject") or state["subject"]!=body.get("subject") or state["sponsor"]!=body.get("issuer")
                or state["bond_id"]!=body.get("id") or any(not name(state[key]) for key in ("root","sponsor","subject","bond_id","home_zone"))
                or state["receiving_zone"]!=profile["receiving_zone"] or state["home_zone"]==state["receiving_zone"]
                or not _time(state["checked_at"]) or state["checked_at"]!=evaluated_at or not _time(state["expires_at"]) or state["expires_at"]<=evaluated_at
                or not _time(state["opened_at"]) or not _time(body.get("start_time")) or not _time(body.get("end_time"))
                or not state["opened_at"]<=body["start_time"]<body["end_time"] or state["opened_at"]>evaluated_at
                or type(body.get("inputs")) is not dict or not {"sponsor_e_base","stake_percentage"}<=body["inputs"].keys()):
            raise ValidationError("cross-zone bond differs from authenticated context/instrument/profile/current time")
        opening=state["opening"];current=state["current"]
        common={"home_base","commitments","sponsor_admission","sponsor_otherwise_admissible","home_recorded","receiving_anchor_verified"}
        if (type(opening) is not dict or set(opening)!=common|{"repair_zones"}
                or type(current) is not dict or set(current)!=common|{"subject_intrinsic_base","severance_at","lent_withdrawn"}
                or any(type(part[key]) is not bool for part in (opening,current) for key in ("sponsor_otherwise_admissible","home_recorded","receiving_anchor_verified"))
                or type(current["lent_withdrawn"]) is not bool or current["severance_at"] is not None and not _time(current["severance_at"])):
            raise ValidationError("cross-zone bond requires complete opening and current snapshots")
        original=ratio(body["inputs"]["sponsor_e_base"],name="original sponsor base",maximum=100)
        percentage=ratio(body["inputs"]["stake_percentage"],name="original stake percentage",minimum=1,maximum=50)
        stake=original*percentage/100
        opening_inventory=_commitments(opening["commitments"])
        if any(item.bond_id==state["bond_id"] for item in opening_inventory):raise ValidationError("opening inventory already counts the new bond")
        before=project_sponsor_capital(sponsor_base=opening["home_base"],bonds=opening_inventory,now=state["opened_at"])
        federation=profile_terms(_parse_jcs_object(self.federation_profile_bytes))
        def admission(part,at):return _admission(part["sponsor_admission"],sponsor=state["sponsor"],home=state["home_zone"],
            receiver=state["receiving_zone"],profile=federation,at=at,algorithm=self.algorithm)
        first=admission(opening,state["opened_at"]);latest=admission(current,evaluated_at)
        zones=opening["repair_zones"];seen=set();repair_ok=True
        if type(zones) is not list or len(zones)>4096:raise ValidationError("complete opening all-zone breach inventory required")
        for zone in zones:
            if (type(zone) is not dict or set(zone)!={"zone_id","root","profile","counts","blocked_classes","aggregate_blocked","hard_blocked"}
                    or not name(zone["zone_id"]) or zone["zone_id"] in seen or zone["root"]!=state["root"]):
                raise ValidationError("invalid or duplicate root opening breach zone")
            seen.add(zone["zone_id"])
            import rfc8785
            declared=repair_profile(rfc8785.dumps(zone["profile"]))
            repair_ok=sponsorship_counts_eligible(declared,zone["counts"],zone["blocked_classes"],zone["aggregate_blocked"],zone["hard_blocked"]) and repair_ok
        floor=ratio(profile["sponsor_admission_floor"],name="sponsor admission floor")
        opening_measure=None if not first["admitted"] else min(before.sponsor_base,first["exportable_base"])*first["factor"].applied_factor
        valid=(first["admitted"] and first["sponsorship_allowed"] and opening_measure>=floor and original==before.sponsor_base
            and original<=first["exportable_base"] and before.available_base>=stake and not before.overcommitted
            and opening["sponsor_otherwise_admissible"] and opening["home_recorded"] and opening["receiving_anchor_verified"] and repair_ok)
        ends=min((body["end_time"],*(value for value in (first["agreement_end"],current["severance_at"]) if value is not None)))
        same_origin=(opening["sponsor_admission"]["agreement"]==current["sponsor_admission"]["agreement"]
            and opening["sponsor_admission"]["ingress_at"]==current["sponsor_admission"]["ingress_at"])
        inventory=list(_commitments(current["commitments"]));matching=[item for item in inventory if item.bond_id==state["bond_id"]]
        if len(matching)!=1:raise ValidationError("current home inventory must retain the exact new liability")
        target=matching[0];intrinsic=ratio(current["subject_intrinsic_base"],name="subject locally earned standing",maximum=100)
        if (ratio(target.stake_amount,name="current original stake")!=stake or ratio(target.intrinsic_base,name="current intrinsic standing")!=intrinsic
                or target.opened_at!=state["opened_at"] or target.expires_at!=body["end_time"] or target.depth!=1 or target.transferred_residual is not None):
            raise ValidationError("current capital substitutes the signed bond or actual sponsored subject")
        if evaluated_at>=ends>state["opened_at"]:inventory[inventory.index(target)]=replace(target,previously_closed=True)
        capital=project_sponsor_capital(sponsor_base=current["home_base"],bonds=tuple(inventory),now=evaluated_at)
        measure=None if not latest["admitted"] else min(capital.sponsor_base,latest["exportable_base"])*latest["factor"].applied_factor
        active=bool(valid and same_origin and latest["admitted"] and latest["sponsorship_allowed"] and measure>=floor and not capital.overcommitted
            and current["sponsor_otherwise_admissible"] and current["home_recorded"] and current["receiving_anchor_verified"]
            and body["start_time"]<=evaluated_at<ends and not current["lent_withdrawn"] and target.for_cause_state=="none"
            and dict(capital.bonds)[state["bond_id"]].phase=="active")
        basis=None if not active else min(opening_measure,measure)
        collateral=Fraction(0) if not active else stake*min(first["factor"].applied_factor,latest["factor"].applied_factor)/2
        expiry=state["expires_at"] if not active else min(state["expires_at"],latest["expires_at"],ends)
        import rfc8785
        def exact(value):return None if value is None else dict(n=str(value.numerator),d=str(value.denominator))
        credit=None
        if active and profile.get("root_binding")=="credit-digest-ceiling-v1":
            credit=SPONSOR_CREDIT_PREFIX+_digest(dict(deployment_digest=deployment,profile_digest=policy,
                instrument_digest=state["instrument_digest"],sponsor=state["sponsor"],subject=state["subject"],home_zone=state["home_zone"],
                receiving_zone=state["receiving_zone"],root_sponsor_basis=exact(basis),ends_at=ends),self.algorithm)
        frame=dict(source={key:value for key,value in state.items() if key not in ("checked_at","expires_at")},
            projection=dict(opening_valid=bool(valid),active=active,ends_at=ends,sponsor_measure=exact(measure),root_sponsor_basis=exact(basis),
                receiver_collateral=exact(collateral),subject_intrinsic_base=exact(intrinsic),available_home_base=exact(capital.available_base),
                total_reserved=exact(capital.total_reserved),overcommitted=capital.overcommitted,
                bonds=[dict(bond_id=key,reserve=exact(value.effective_reserve),liability=exact(value.retained_liability),phase=value.phase,
                    nonrenewable=value.nonrenewable,unresolved_lapse=value.unresolved_lapse) for key,value in capital.bonds]))
        result=object.__new__(FederatedSponsorshipAssessment)
        for key,value in dict(opening_valid=bool(valid),active=active,reason="CROSS_SPONSORSHIP_ACTIVE" if active else
                "CROSS_SPONSORSHIP_INACTIVE" if valid else "CROSS_SPONSORSHIP_OPENING_INVALID",sponsor_measure=measure,root_sponsor_basis=basis,
                receiver_collateral=collateral,subject_intrinsic_base=intrinsic,home_capital=capital,ends_at=ends,checked_at=evaluated_at,expires_at=expiry,
                opened_at=state["opened_at"],home_zone=state["home_zone"],receiving_zone=state["receiving_zone"],sponsor=state["sponsor"],
                subject=state["subject"],bond_id=state["bond_id"],context_bytes=context_bytes,complete_instrument_bytes=instrument_bytes,
                authenticated_bond_body_bytes=source.bond_body_bytes,profile_bytes=self.profile_bytes,federation_profile_bytes=self.federation_profile_bytes,
                authenticated_state_bytes=source.state_bytes,source_evidence_bytes=source.evidence_bytes,frame_digest=_digest(frame,self.algorithm),
                frame_bytes=rfc8785.dumps(frame),credit_ceiling_name=credit).items():
            object.__setattr__(result,key,value)
        return result


__all__=("AuthenticatedFederatedSponsorshipContext","FederatedSponsorshipAssessment","InstalledFederatedSponsorshipVerifier")
