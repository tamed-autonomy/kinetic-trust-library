"""Installed signed-act-only person federation, distinct from software import."""
from dataclasses import dataclass
from kinetic_trust_library.errors import ValidationError
from .federation import InstalledFederationVerifier,resolve_current_federation_state
from .federation_terms import profile_terms
from .trust_proof_json import _parse_jcs_object
from .demand_operation import canonical_demand_operation_bytes
from .person_standing import calculate_imported_person_standing,_person
from .root_lifecycle import _time
from .ambient_repair import ratio


def person_profile_terms(p):
    if (type(p) is not dict or p.get("formula")!="minimum-person-directional-terms-v1"
            or p.get("subject_profiles")!=["person"] or "zone_ceiling" not in p or "standing_binding" in p):
        raise ValidationError("invalid selected person federation profile")
    # Validate the identical directional/class/lowering structure under the
    # common validator; this copy never changes the installed signed identity.
    common={k:v for k,v in p.items() if k!="zone_ceiling"}
    common.update(formula="minimum-applicable-directional-terms-v1",subject_profiles=["software"])
    profile_terms(common)
    ratio(p["zone_ceiling"],name="declared receiver person ceiling",maximum=100)
    return p


@dataclass(frozen=True,slots=True,init=False)
class PersonFederationAssessment:
    admitted: bool
    reason: str
    standing: object
    factor: object
    void_clauses: tuple
    profile_bytes: bytes
    operation_bytes: bytes
    authenticated_state_bytes: bytes
    source_evidence_bytes: bytes
    evaluated_at: int
    expires_at: int
    action_permitted: bool

    def __init__(self,*args,**kwargs):raise TypeError("person transfer requires installed current agreement evidence")


@dataclass(frozen=True,slots=True)
class InstalledPersonFederationVerifier:
    deployment_profile_bytes: bytes
    profile_bytes: bytes
    context_source: object
    algorithm: str

    def __post_init__(self):
        if (type(self.deployment_profile_bytes) is not bytes or type(self.profile_bytes) is not bytes
                or self.algorithm not in ("sha256","sha384") or not callable(getattr(self.context_source,"resolve",None))):
            raise ValidationError("invalid installed person federation verifier")
        _parse_jcs_object(self.deployment_profile_bytes);person_profile_terms(_parse_jcs_object(self.profile_bytes))

    def evaluate(self,*,actual_operation,evaluated_at,clock_healthy):
        if not _time(evaluated_at) or clock_healthy is not True:
            raise ValidationError("person transfer requires healthy current time")
        p=person_profile_terms(_parse_jcs_object(self.profile_bytes))
        op_bytes=canonical_demand_operation_bytes(actual_operation);op=_parse_jcs_object(op_bytes)
        if not _person(op["actor"]):raise ValidationError("person transfer requires an explicit person subject")
        source,s=resolve_current_federation_state(self,p,op_bytes,evaluated_at)
        values=dict(admitted=False,reason="FEDERATION_PERSON_IMPORT_UNAVAILABLE",factor=None,exportable_base=None,
            void_clauses=(),expires_at=s["expires_at"])
        agreement=s["agreement"];attestation=s["attestation"]
        person_terms=None if type(agreement) is not dict or type(agreement.get("data_handling")) is not dict else agreement["data_handling"].get("persons")
        if (s["subject_profile"]=="person" and s["substrate_profile"]=="person-signed-acts"
                and type(person_terms) is dict and person_terms.get("standing") is True
                and person_terms.get("terms")=="signed-acts-only" and type(attestation) is dict
                and attestation.get("signed_act") is True and attestation.get("kind")=="person-signed-acts"):
            try:InstalledFederationVerifier._project(s,p,values,evaluated_at,self.algorithm)
            except ValidationError:values.update(admitted=False,reason="FEDERATION_PERSON_EVIDENCE_INVALID",exportable_base=None)
        standing=None
        if values["admitted"]:
            standing=calculate_imported_person_standing(subject=op["actor"],source_zone=s["from_zone"],receiving_zone=s["to_zone"],
                exportable_base=values["exportable_base"],agreement_exists=True,receiver_signed=True,
                person_factor=values["factor"].applied_factor,zone_ceiling=p["zone_ceiling"])
        result=object.__new__(PersonFederationAssessment)
        for k,v in dict(admitted=values["admitted"],reason=values["reason"],standing=standing,factor=values["factor"],
                void_clauses=values["void_clauses"],profile_bytes=self.profile_bytes,operation_bytes=op_bytes,authenticated_state_bytes=source.state_bytes,
                source_evidence_bytes=source.evidence_bytes,evaluated_at=evaluated_at,expires_at=values["expires_at"],
                action_permitted=False).items():object.__setattr__(result,k,v)
        return result
