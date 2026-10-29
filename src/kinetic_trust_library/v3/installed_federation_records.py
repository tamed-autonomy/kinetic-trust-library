"""Installed federation exposure and anchoring-notification delivery assessment.

The Source authenticates the exact original record, actual registry/witness
facts, current signed agreement versions and complete subject coverage/prior
delivery history for this breach anchor. It also authenticates current validity
of the breach/withdrawal or anchored reconciliation. No requester-supplied
permission, destination list, standing delta or closure decision is accepted.
Semantic Source projections are private adapter contracts, not RFC record wire.
Service owns durable delivery, retries, constraint enforcement and local review.
"""
from dataclasses import dataclass
from kinetic_trust_library.errors import ValidationError
from .trust_proof_json import _parse_jcs_object
from .demand_supplier import _digest
from .root_lifecycle import _time
from .federation_terms import name,identifiers,agreement_terms
from .federation_records import plan_federation_delivery


def _profile(value):
    if (type(value) is not dict or set(value)!={"id","version","origin_zone","formula"}
            or not name(value["id"]) or not name(value["origin_zone"])
            or not _time(value["version"]) or value["version"]==0
            or value["formula"]!="reached-subject-exposure-and-anchor-notification-v1"):
        raise ValidationError("unsupported federation record delivery profile")
    return value


@dataclass(frozen=True,slots=True)
class AuthenticatedFederationRecordContext:
    state_bytes: bytes
    evidence_bytes: bytes


@dataclass(frozen=True,slots=True,init=False)
class FederationRecordAssessment:
    plan: object
    deployment_digest: str
    profile_bytes: bytes
    profile_digest: str
    record_bytes: bytes
    record_digest: str
    subject: str
    subject_profile: str
    origin_zone: str
    evaluated_at: int
    expires_at: int
    frame_digest: str
    frame_bytes: bytes
    authenticated_state_bytes: bytes
    source_evidence_bytes: bytes

    def __init__(self,*args,**kwargs):
        raise TypeError("record assessments require installed current verification")


@dataclass(frozen=True,slots=True)
class InstalledFederationRecordVerifier:
    deployment_profile_bytes: bytes
    profile_bytes: bytes
    context_source: object
    algorithm: str

    def __post_init__(self):
        if (type(self.deployment_profile_bytes) is not bytes or type(self.profile_bytes) is not bytes
                or self.algorithm not in ("sha256","sha384")
                or not callable(getattr(self.context_source,"resolve",None))):
            raise ValidationError("invalid installed federation record verifier")
        _parse_jcs_object(self.deployment_profile_bytes)
        _profile(_parse_jcs_object(self.profile_bytes))

    def evaluate(self,*,record_bytes,evaluated_at,clock_healthy):
        if (type(record_bytes) is not bytes or len(record_bytes)>262144
                or not _time(evaluated_at) or clock_healthy is not True):
            raise ValidationError("record verification requires bounded record and healthy current clock")
        record=_parse_jcs_object(record_bytes)
        profile=_profile(_parse_jcs_object(self.profile_bytes))
        policy=_digest(profile,self.algorithm)
        deployment=_digest(_parse_jcs_object(self.deployment_profile_bytes),self.algorithm)
        record_digest=_digest(record,self.algorithm)
        source=self.context_source.resolve(deployment_profile_bytes=self.deployment_profile_bytes,
            profile_bytes=self.profile_bytes,record_bytes=record_bytes,evaluated_at=evaluated_at)
        if (type(source) is not AuthenticatedFederationRecordContext
                or type(source.state_bytes) is not bytes or len(source.state_bytes)>262144
                or type(source.evidence_bytes) is not bytes or not source.evidence_bytes):
            raise ValidationError("record Source must authenticate complete current delivery evidence")
        state=_parse_jcs_object(source.state_bytes)
        if (set(state)!={"deployment_digest","profile_digest","record_digest","checked_at","expires_at",
                "origin_zone","subject","subject_profile","kind","breach_anchor","reconciliation_anchor",
                "recorded_at","current_valid","signatures","required_sovereignty","destinations"}
                or state["deployment_digest"]!=deployment or state["profile_digest"]!=policy
                or state["record_digest"]!=record_digest or state["origin_zone"]!=profile["origin_zone"]
                or not name(state["subject"]) or not _time(state["checked_at"]) or state["checked_at"]!=evaluated_at
                or not _time(state["expires_at"]) or state["expires_at"]<=evaluated_at
                or not _time(state["recorded_at"]) or state["recorded_at"]>evaluated_at
                or state["current_valid"] is not True or type(state["signatures"]) is not list
                or not state["signatures"] or len(state["signatures"])>4096
                or type(state["destinations"]) is not list or len(state["destinations"])>4096):
            raise ValidationError("record delivery evidence differs from installed record/profile/time")
        signers=set();witnesses=set()
        for signature in state["signatures"]:
            if (type(signature) is not dict or set(signature)!={"zone_id","registry_verified","witnessed"}
                    or not name(signature["zone_id"]) or signature["zone_id"] in signers
                    or signature["registry_verified"] is not True or type(signature["witnessed"]) is not bool):
                raise ValidationError("record signatures require distinct registry-verified zones")
            signers.add(signature["zone_id"])
            if signature["witnessed"]:witnesses.add(signature["zone_id"])
        if state["origin_zone"] not in witnesses:
            raise ValidationError("origin zone did not witness the record")
        required=identifiers(state["required_sovereignty"])
        destinations=[];seen=set();expiry=state["expires_at"]
        for item in state["destinations"]:
            if (type(item) is not dict or set(item)!={"zone","agreement","receiver_accepting","standing_admitted",
                    "bond_ever_opened","attestation_admitted","prior_breach_delivery"}
                    or not name(item["zone"]) or item["zone"] in seen or item["zone"]==state["origin_zone"]
                    or any(type(item[key]) is not bool for key in ("receiver_accepting","standing_admitted",
                        "bond_ever_opened","attestation_admitted"))):
                raise ValidationError("invalid complete federation record destination inventory")
            seen.add(item["zone"])
            agreement=item["agreement"]
            agreement_terms(agreement)
            parties={party["zone_id"] for party in agreement["parties"]}
            if parties!={state["origin_zone"],item["zone"]}:
                raise ValidationError("record agreement names another origin or destination")
            prior=item["prior_breach_delivery"]
            if prior is not None:
                if (type(prior) is not dict or set(prior)!={"subject","breach_anchor","origin_zone","agreement_digest","delivered_at"}
                        or prior["subject"]!=state["subject"] or prior["breach_anchor"]!=state["breach_anchor"]
                        or prior["origin_zone"]!=state["origin_zone"]
                        or prior["agreement_digest"]!=_digest(agreement,self.algorithm)
                        or not _time(prior["delivered_at"]) or prior["delivered_at"]>evaluated_at
                        or not agreement["starts_at"]<=prior["delivered_at"]<agreement["expires_at"]):
                    raise ValidationError("prior breach delivery differs from subject/anchor/same agreement terms")
            active=(item["receiver_accepting"] and agreement["starts_at"]<=evaluated_at<agreement["expires_at"])
            if active:expiry=min(expiry,agreement["expires_at"])
            destinations.append(dict(zone=item["zone"],agreement_applicable=active,
                standing_admitted=item["standing_admitted"],bond_ever_opened=item["bond_ever_opened"],
                attestation_admitted=item["attestation_admitted"],breach_previously_delivered=prior is not None,
                sovereignty_enforced=required<=set(agreement["sovereignty_enforced"][item["zone"]])))
        plan=plan_federation_delivery(kind=state["kind"],subject_profile=state["subject_profile"],
            breach_anchor=state["breach_anchor"],reconciliation_anchor=state["reconciliation_anchor"],
            destinations=tuple(destinations))
        import rfc8785
        frame={key:value for key,value in state.items() if key not in ("checked_at","expires_at")}
        # Derived routing changes at agreement expiry even if Source raw facts
        # otherwise stay unchanged across a clock-only refresh.
        frame["delivery"]=dict(disposition=plan.disposition,required=list(plan.required_destinations),
            permitted=list(plan.permitted_destinations),blocked=list(plan.blocked_destinations),
            notification_payload=dict(plan.notification_payload))
        result=object.__new__(FederationRecordAssessment)
        for key,value in dict(plan=plan,deployment_digest=deployment,profile_bytes=self.profile_bytes,
                profile_digest=policy,record_bytes=record_bytes,record_digest=record_digest,
                subject=state["subject"],subject_profile=state["subject_profile"],origin_zone=state["origin_zone"],
                evaluated_at=evaluated_at,expires_at=expiry,frame_digest=_digest(frame,self.algorithm),
                frame_bytes=rfc8785.dumps(frame),authenticated_state_bytes=source.state_bytes,
                source_evidence_bytes=source.evidence_bytes).items():object.__setattr__(result,key,value)
        return result
