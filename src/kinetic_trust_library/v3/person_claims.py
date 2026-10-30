"""Provisional person standing assertions, separate from human execution.

Compose actual signed-act standing with identically scoped Soul and five-factor
environment evidence. This supplies neither eligibility nor measured operational
capacity and never synthesizes software generation/lineage/advancement fields.
"""
from dataclasses import dataclass
from fractions import Fraction
from kinetic_trust_library.errors import ValidationError
from .installed_person_standing import PersonStandingAssessment
from .installed_soul import NativeSoulAssessment
from .installed_environment import NativeEnvironmentAssessment
from .boundary import BoundaryAssessment
from .core_risk import assess_five_factor_risk
from .core_claims import _wire_number
from ._exact import finite_decimal
from .native_proof_profile import RootProofBinding,native_schema_bundle
from .trust_proof_json import _parse_jcs_object
from .demand_supplier import _digest
from .demand_operation import digest_demand_operation
from .root_lifecycle import _time
from .execution_observation import _name


@dataclass(frozen=True,slots=True)
class NativePersonClaimsSource:
    deployment_profile_bytes: bytes
    standing: PersonStandingAssessment
    soul: NativeSoulAssessment
    environment: NativeEnvironmentAssessment | None
    assertion_metadata_bytes: bytes
    algorithm: str
    boundary: BoundaryAssessment | None = None
    no_credit_reason: str = "missing"

    def __post_init__(self):
        if (type(self.deployment_profile_bytes) is not bytes or type(self.assertion_metadata_bytes) is not bytes
                or type(self.standing) is not PersonStandingAssessment or type(self.soul) is not NativeSoulAssessment
                or self.environment is not None and type(self.environment) is not NativeEnvironmentAssessment
                or self.algorithm not in ("sha256","sha384")):
            raise ValidationError("person assertions require actual installed immutable standing/Soul/environment assessments")
        dp=_parse_jcs_object(self.deployment_profile_bytes);m=_parse_jcs_object(self.assertion_metadata_bytes)
        s=_parse_jcs_object(self.standing.authenticated_state_bytes);op=_parse_jcs_object(self.standing.operation_bytes)
        now=self.standing.evaluated_at;deployment=_digest(dp,self.algorithm);operation=digest_demand_operation(op,algorithm=self.algorithm)
        roots=self.standing.roots;root_context=_parse_jcs_object(roots.context_bytes)
        if (set(m)!={"iss","aud","jti","exp","zone"} or any(not _name(m[n]) for n in ("iss","aud","jti","zone"))
                or m["aud"]!=op["audience"] or m["zone"]!=s["zone"] or s["subject"]!=op["actor"]
                or s["deployment_digest"]!=deployment or s["operation_digest"]!=operation or s["checked_at"]!=now
                or type(dp.get("peer_share")) is not int or dp["peer_share"]!=0
                or not _time(m["exp"]) or not now<m["exp"]<=min(now+10,self.standing.expires_at)
                or self.soul.deployment_digest!=deployment or self.soul.operation_digest!=operation or self.soul.evaluated_at!=now
                or self.soul.required_frameworks!=tuple(dp["soul_veto"]["frameworks"])
                or roots.algorithm!=self.algorithm or roots.evaluated_at!=now or root_context.get("subject_profile")!="person"
                or root_context.get("subject")!=op["actor"] or root_context.get("deployment_digest")!=deployment):
            raise ValidationError("person claims differ from the exact current operation, declaration, Root, Soul or validity")
        e=self.environment
        if e is not None and (e.deployment_digest!=deployment or e.operation_digest!=operation or e.evaluated_at!=now or e.ambient is not None):
            raise ValidationError("person environment differs from current scope or selects an unsupported supplemental composition")
        if ("boundary" in dp)!=(self.boundary is not None):raise ValidationError("person proof must select its actual declared boundary")
        b=self.boundary
        if b is not None and (type(b) is not BoundaryAssessment or not b.allowed or b.deployment_digest!=deployment
                or b.operation_digest!=operation or b.evaluated_at!=now or b.zone_id!=m["zone"] or m["exp"]>b.expires_at):
            raise ValidationError("person proof cannot omit, contradict or outlive its boundary")

    def produce(self,*,evaluated_at):
        import rfc8785
        if not _time(evaluated_at) or evaluated_at!=self.standing.evaluated_at:
            raise ValidationError("person claim snapshot belongs to another evaluation time")
        dp=_parse_jcs_object(self.deployment_profile_bytes);m=_parse_jcs_object(self.assertion_metadata_bytes)
        s=_parse_jcs_object(self.standing.authenticated_state_bytes);standing=self.standing.standing
        state=self.soul.gate.state.value;risk=None;base=trust=None;context=None
        soul_claim=None
        if state=="veto":
            responses={r.framework:r for r in self.soul.responses}
            response=next(responses[f] for f in self.soul.required_frameworks if f in responses and responses[f].state=="veto")
            if response.proof_claim_bytes is None:raise ValidationError("person veto proof requires actual authenticated constraint details")
            soul_claim=_parse_jcs_object(response.proof_claim_bytes)
        elif state=="clear":
            soul_claim={"soul":0}
            if self.environment is None:raise ValidationError("clear person assertion requires installed environment evidence")
            risk=assess_five_factor_risk(self.environment.factors,weights={n:c["weight"] for n,c in dp["risk_factors"].items()})
            base=standing.base_trust
            if not risk.has_complete_measurement:state="undetermined"
            else:
                if Fraction(str(s["zone_risk"]))!=Fraction(risk.measured_risk):
                    raise ValidationError("person standing risk differs from the actual installed five-factor assessment")
                trust=finite_decimal(Fraction(base)*(1-Fraction(risk.measured_risk)))
                if Fraction(trust)!=Fraction(standing.effective_trust):raise ValidationError("person standing effective trust contradicts exact current risk")
                context={f.factor:_wire_number(f.value) for f in risk.factors}
        roots=self.standing.roots
        root=_parse_jcs_object(roots.selected.projection_bytes) if roots.selected is not None else dict(kind="none",status="none",reason=self.no_credit_reason)
        ktp=dict(version="ktp-trust-proof-v3",subject_kind="person",gate_state=state,zone=m["zone"],
            e_base=_wire_number(base),e_trust=_wire_number(trust),r=_wire_number(None if risk is None else risk.measured_risk),
            context=context,soul=soul_claim,peer_share=0,root_instrument=root,
            applicable_ceilings=[dict(ceiling=name,value=_wire_number(finite_decimal(value))) for name,value in standing.ceilings])
        payload=rfc8785.dumps(dict(iss=m["iss"],sub=standing.subject,aud=m["aud"],iat=evaluated_at,exp=m["exp"],jti=m["jti"],ktp=ktp))
        if not native_schema_bundle().valid(payload) or not RootProofBinding(roots,m["zone"],self.no_credit_reason)(payload,evaluated_at):
            raise ValidationError("derived person claims violate the pinned native person proof contract")
        return payload
