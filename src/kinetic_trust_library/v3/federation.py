"""Installed current one-link federation import evidence, not local permission.

The source authenticates actual agreements/signatures, admission-time version,
current directional acceptance, sender exportable earned standing, registry and
witness truth, action/substrate classification and declared lowering results.
It receives no candidate proof or claimed admission facts from the requester.
"""
from dataclasses import dataclass
from fractions import Fraction
import re
from kinetic_trust_library.errors import ValidationError
from .trust_proof_json import _parse_jcs_object
from .demand_supplier import _digest
from .demand_operation import canonical_demand_operation_bytes,digest_demand_operation
from .root_lifecycle import _time
from .ambient_repair import ratio
from .federation_terms import name,identifiers,agreement_terms,profile_terms
from .imported_standing import derive_federation_factor,calculate_imported_standing

FEDERATION_CEILING_PREFIX="federation_ingress."


@dataclass(frozen=True,slots=True)
class AuthenticatedFederationContext:
    state_bytes: bytes
    evidence_bytes: bytes


@dataclass(frozen=True,slots=True,init=False)
class FederationAssessment:
    admitted: bool
    reason: str
    deployment_digest: str
    operation_digest: str
    profile_bytes: bytes
    profile_digest: str
    evaluated_at: int
    expires_at: int
    admission_id: str | None
    ingress_at: int | None
    subject: str
    source_zone: str
    receiving_zone: str
    factor: object
    exportable_base: Fraction | None
    void_clauses: tuple
    frame_digest: str
    frame_bytes: bytes
    authenticated_state_bytes: bytes
    source_evidence_bytes: bytes
    standing_ceiling_name: str | None

    def __init__(self,*args,**kwargs):raise TypeError("federation assessments require installed current verification")

    def derive_standing(self,*,ceilings,root_available):
        if not self.admitted:raise ValidationError("unavailable import supplies no standing; select an independent local route")
        if type(ceilings) is not dict or any(type(name) is not str or name.startswith(FEDERATION_CEILING_PREFIX) for name in ceilings):
            raise ValidationError("provider ceilings cannot replace the federation admission binding")
        base=calculate_imported_standing(exportable_base=self.exportable_base,factor=self.factor,source_zone=self.source_zone,
            receiving_zone=self.receiving_zone,ceilings=ceilings,root_available=root_available)
        if self.standing_ceiling_name is None:return base
        return calculate_imported_standing(exportable_base=self.exportable_base,factor=self.factor,source_zone=self.source_zone,
            receiving_zone=self.receiving_zone,ceilings={**ceilings,self.standing_ceiling_name:base.base_trust},root_available=root_available)

    def geometry_value(self):
        def exact(value):return None if value is None else dict(n=str(value.numerator),d=str(value.denominator))
        return dict(profile_digest=self.profile_digest,frame_digest=self.frame_digest,admitted=self.admitted,reason=self.reason,
            source_zone=self.source_zone,receiving_zone=self.receiving_zone,admission_id=self.admission_id,ingress_at=self.ingress_at,
            factor=exact(None if self.factor is None else self.factor.applied_factor),exportable_base=exact(self.exportable_base),
            void_clauses=list(self.void_clauses))


@dataclass(frozen=True,slots=True)
class InstalledFederationVerifier:
    deployment_profile_bytes: bytes
    profile_bytes: bytes
    context_source: object
    algorithm: str

    def __post_init__(self):
        if (type(self.deployment_profile_bytes) is not bytes or type(self.profile_bytes) is not bytes
                or self.algorithm not in ("sha256","sha384") or not callable(getattr(self.context_source,"resolve",None))):
            raise ValidationError("invalid installed federation policy")
        _parse_jcs_object(self.deployment_profile_bytes);profile_terms(_parse_jcs_object(self.profile_bytes))

    def evaluate(self,*,actual_operation,evaluated_at,clock_healthy):
        if not _time(evaluated_at) or clock_healthy is not True:raise ValidationError("federation requires a healthy current clock")
        operation_bytes=canonical_demand_operation_bytes(actual_operation);operation=_parse_jcs_object(operation_bytes)
        profile=profile_terms(_parse_jcs_object(self.profile_bytes));policy=_digest(profile,self.algorithm)
        deployment=_digest(_parse_jcs_object(self.deployment_profile_bytes),self.algorithm)
        invocation=digest_demand_operation(operation,algorithm=self.algorithm)
        source=self.context_source.resolve(deployment_profile_bytes=self.deployment_profile_bytes,profile_bytes=self.profile_bytes,
            operation_bytes=operation_bytes,evaluated_at=evaluated_at)
        if (type(source) is not AuthenticatedFederationContext or type(source.state_bytes) is not bytes or len(source.state_bytes)>262144
                or type(source.evidence_bytes) is not bytes or not source.evidence_bytes):
            raise ValidationError("federation source must authenticate complete current admission evidence")
        state=_parse_jcs_object(source.state_bytes)
        if (set(state)!={"deployment_digest","profile_digest","operation_digest","checked_at","expires_at","admission_id","ingress_at",
                "subject","subject_profile","from_zone","to_zone","enforcement_class","action_class","substrate_profile",
                "receiver_accepting","required_sovereignty","lowered_factors","agreement","attestation"}
                or state["deployment_digest"]!=deployment or state["profile_digest"]!=policy or state["operation_digest"]!=invocation
                or not _time(state["checked_at"]) or state["checked_at"]!=evaluated_at
                or not _time(state["expires_at"]) or state["expires_at"]<=evaluated_at or state["subject"]!=operation["actor"]
                or any(not name(state[key]) for key in ("subject_profile","from_zone","to_zone","enforcement_class","action_class","substrate_profile"))
                or state["from_zone"]==state["to_zone"] or state["to_zone"]!=profile["receiving_zone"]
                or type(state["receiver_accepting"]) is not bool
                or not (state["admission_id"] is None and state["ingress_at"] is None
                    or name(state["admission_id"]) and _time(state["ingress_at"]) and state["ingress_at"]<=evaluated_at)):
            raise ValidationError("federation state differs from current invocation/profile/admission scope")
        identifiers(state["required_sovereignty"])
        values=dict(admitted=False,reason="FEDERATION_IMPORT_UNAVAILABLE",factor=None,exportable_base=None,void_clauses=(),expires_at=state["expires_at"])
        try:self._project(state,profile,values,evaluated_at,self.algorithm)
        except ValidationError:values.update(admitted=False,reason="FEDERATION_EVIDENCE_INVALID",exportable_base=None)
        import rfc8785
        frame={key:value for key,value in state.items() if key not in ("checked_at","expires_at")}
        binding=None
        if values["admitted"] and profile.get("standing_binding")=="admission-digest-ceiling-v1":
            admission=dict(deployment_digest=deployment,profile_digest=policy,admission_id=state["admission_id"],ingress_at=state["ingress_at"],
                subject=state["subject"],source_zone=state["from_zone"],receiving_zone=state["to_zone"],
                agreement_digest=_digest(state["agreement"],self.algorithm),attestation_digest=state["attestation"]["payload_digest"])
            binding=FEDERATION_CEILING_PREFIX+_digest(admission,self.algorithm)
        result=object.__new__(FederationAssessment)
        for key,value in dict(**values,deployment_digest=deployment,operation_digest=invocation,profile_bytes=self.profile_bytes,
                profile_digest=policy,evaluated_at=evaluated_at,admission_id=state["admission_id"],ingress_at=state["ingress_at"],subject=state["subject"],
                source_zone=state["from_zone"],receiving_zone=state["to_zone"],frame_digest=_digest(frame,self.algorithm),frame_bytes=rfc8785.dumps(frame),
                authenticated_state_bytes=source.state_bytes,source_evidence_bytes=source.evidence_bytes,standing_ceiling_name=binding).items():object.__setattr__(result,key,value)
        return result

    @staticmethod
    def _project(state,profile,out,now,algorithm):
        agreement=state["agreement"];attestation=state["attestation"]
        if agreement is None or attestation is None or state["ingress_at"] is None:return
        out["void_clauses"]=agreement_terms(agreement)
        if not state["receiver_accepting"]:
            out["reason"]="FEDERATION_ACCEPTANCE_ENDED";return
        if not agreement["starts_at"]<=state["ingress_at"]<agreement["expires_at"] or now>=agreement["expires_at"]:
            out["reason"]="FEDERATION_AGREEMENT_INACTIVE";return
        direction=next((item for item in agreement["directions"] if item["from_zone"]==state["from_zone"] and item["to_zone"]==state["to_zone"]),None)
        if direction is None:
            out["reason"]="FEDERATION_DIRECTION_UNAVAILABLE";return
        classes=profile["enforcement_classes"]
        if (state["subject_profile"] not in profile["subject_profiles"] or state["enforcement_class"] not in classes
                or direction["lowest_enforcement_class"] not in classes
                or classes[state["enforcement_class"]]["rank"]<classes[direction["lowest_enforcement_class"]]["rank"]):
            out["reason"]="FEDERATION_PROFILE_UNSUPPORTED";return
        if not set(state["required_sovereignty"])<=set(agreement["sovereignty_enforced"][state["to_zone"]]):
            out["reason"]="FEDERATION_SOVEREIGNTY_UNAVAILABLE";return
        selected=[]
        for cell,key in (("factors_by_action_class","action_class"),("factors_by_substrate_profile","substrate_profile")):
            if state[key] in direction[cell]:selected.append(direction[cell][state[key]])
        if not selected:selected=[direction["factor"]]
        selected=tuple(ratio(value,name="selected signed factor") for value in selected)
        # A selected invalid clause cannot be laundered through a valid matching
        # selector. Otherwise the explicitly named reference chooses the minimum.
        signed=max(selected) if any(value>1 for value in selected) else min(selected)
        if type(state["lowered_factors"]) is not list:raise ValidationError("invalid declared lowering results")
        lower=[];seen=set()
        for item in state["lowered_factors"]:
            if (type(item) is not dict or set(item)!={"policy","factor"} or not name(item["policy"]) or item["policy"] in seen
                    or item["policy"] not in direction["lowering_policies"] or item["policy"] not in profile["lowering_policies"]):
                raise ValidationError("undeclared or duplicate federation lowering result")
            seen.add(item["policy"]);lower.append(ratio(item["factor"],name="lowered factor"))
        factor=derive_federation_factor(signed_factor=signed,receiver_signed=direction["signed_by"]==state["to_zone"],
            class_ceiling=classes[state["enforcement_class"]]["factor_ceiling"],
            lowered_factor=None if not lower else min(lower),declared_floor=direction["floor"])
        out["factor"]=factor
        if factor.applied_factor is None:
            out["reason"]=factor.reason;return
        if (type(attestation) is not dict or set(attestation)!={"subject","subject_profile","from_zone","to_zone","kind","attested_at","expires_at",
                "link_count","earned_in_zone","attested_base","exportable_base","signatures","signed_act","payload_digest","current_valid"}
                or any(attestation[key]!=state[key] for key in ("subject","subject_profile","from_zone","to_zone"))
                or attestation["earned_in_zone"]!=state["from_zone"] or type(attestation["link_count"]) is not int or attestation["link_count"]!=1
                or not _time(attestation["attested_at"]) or not _time(attestation["expires_at"])
                or not attestation["attested_at"]<=state["ingress_at"]<attestation["expires_at"] or attestation["expires_at"]<=now
                or attestation["kind"] not in agreement["data_handling"]["attestation_types"]
                or attestation["kind"] in ("silent-veto","soul-veto","reconciliation","standing-delta")
                or attestation["current_valid"] is not True
                or type(attestation["signed_act"]) is not bool or type(attestation["payload_digest"]) is not str
                or re.fullmatch(algorithm+r":[0-9a-f]{"+str(64 if algorithm=="sha256" else 96)+"}",attestation["payload_digest"]) is None
                or type(attestation["signatures"]) is not list or not attestation["signatures"]):
            raise ValidationError("attestation is not an admissible current one-link software record")
        witnesses=set();signers=set()
        for signature in attestation["signatures"]:
            if (type(signature) is not dict or set(signature)!={"zone_id","registry_verified","witnessed"}
                    or not name(signature["zone_id"]) or signature["zone_id"] in signers
                    or type(signature["witnessed"]) is not bool or signature["registry_verified"] is not True):
                raise ValidationError("attestation signature lacks current registry verification")
            signers.add(signature["zone_id"])
            if signature["witnessed"]:witnesses.add(signature["zone_id"])
        if state["from_zone"] not in witnesses:raise ValidationError("sending zone did not witness its attestation")
        exportable=ratio(attestation["exportable_base"],name="sender-earned exportable standing",maximum=100)
        if exportable>ratio(attestation["attested_base"],name="attested base standing",maximum=100):
            raise ValidationError("exportable standing exceeds the attested base")
        out.update(admitted=True,reason="FEDERATION_IMPORT_ADMISSIBLE",exportable_base=exportable,
            expires_at=min(out["expires_at"],agreement["expires_at"],attestation["expires_at"]))


__all__=("AuthenticatedFederationContext","FederationAssessment","InstalledFederationVerifier")
