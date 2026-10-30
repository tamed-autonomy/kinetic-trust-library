"""Native Core-to-Decision Geometry production under an installed profile.

The authority adapter authenticates current grants and inherited restrictions
for the exact invocation. This profile retains their pointwise minimum; it does
not invent an operation envelope or establish readiness/execution permission.
Profile JSON below is Library configuration, not a new RFC wire declaration.
"""
from dataclasses import dataclass
from decimal import Decimal
from fractions import Fraction
from hashlib import new as hash_new
from kinetic_trust_library._decimal import as_decimal
from kinetic_trust_library.errors import ValidationError
from .core_claims import NativeCoreClaimsSource, _wire_number
from .demand_classification import NativeClassifiedDemand
from .trust_proof_json import _parse_jcs_object
from .request_binding import canonical_request_bytes, digest_canonical_request, digest_complete_proof
from .complete_proof_verifier import InstalledProofVerifier
from .geometry_verifier import AuthenticatedGeometryReproduction
from .decision_geometry import _geometry_validator
from .native_envelope import NativeEnvelopeThresholds, project_native_envelope
from .supervision_rails import SupervisionRailAssessment
from .demand_supplier import _digest


_LEVELS = ("stable", "metacognitive", "assisted", "regulated", "silent_veto")
_LAYERS = {"feed":0, "signal":1, "term":2, "query":3}
_MISSING = ("absent", "unanswered", "stale", "undefined")


@dataclass(frozen=True, slots=True)
class AuthenticatedGeometryAuthority:
    """Adapter-authenticated, current, invocation-bound grant/prior state.

The adapter verifies provenance, delegation, validity and declared magnitude
units/directions. Retained evidence must resolve the complete source payload.
No readiness, execution or durable replay assertion is implied.
"""
    payload_bytes: bytes
    evidence_bytes: bytes


@dataclass(frozen=True, slots=True)
class NativeGeometrySource:
    claim_source: NativeCoreClaimsSource
    demand: NativeClassifiedDemand
    compact_proof: str
    proof_verifier: InstalledProofVerifier
    evaluation_profile_bytes: bytes
    authority_adapter: object
    decision_id: str
    clock_healthy: bool
    supervision_rails: SupervisionRailAssessment | None = None

    def __post_init__(self):
        if (type(self.claim_source) is not NativeCoreClaimsSource or type(self.demand) is not NativeClassifiedDemand
                or type(self.proof_verifier) is not InstalledProofVerifier or type(self.compact_proof) is not str
                or type(self.evaluation_profile_bytes) is not bytes or type(self.clock_healthy) is not bool
                or type(self.decision_id) is not str or not 1<=len(self.decision_id)<=255
                or not callable(getattr(self.authority_adapter,"verify",None))):
            raise ValidationError("native geometry requires installed immutable inputs")
        context=self.claim_source.context
        if (self.demand.deployment_digest!=self.claim_source.standing.deployment_digest
                or self.demand.operation_digest!=self.claim_source.standing.operation_digest
                or self.demand.evaluated_at!=context.evaluated_at
                or self.claim_source.core.classified_demand is not None and self.claim_source.core.classified_demand is not self.demand):
            raise ValidationError("geometry demand belongs to another Core invocation")
        profile=_parse_jcs_object(self.evaluation_profile_bytes)
        required={"id","release","evaluator","core_deployment_digest","input_order","sources","magnitudes","thresholds","numeric_convention","constraint_policy"}
        if (not required<=set(profile) or set(profile)-required-{"supervision_rail_profile_digest","ambient_repair_profile_digest","federation_profile_digest","normative_demand_profile_digest"}
                or profile["core_deployment_digest"]!=self.demand.deployment_digest
                or profile["input_order"]!="layer-then-name-v1"
                or profile["numeric_convention"]!="exact-decimal-boundaries-binary64-margin-v1"
                or profile["constraint_policy"]!="retain-grant-and-prior-v1"
                or type(profile["sources"]) is not dict or set(profile["sources"])!={"soul","core","environment","demand","authority"}
                or any(type(s) is not str or not s for s in profile["sources"].values())
                or type(profile["magnitudes"]) is not dict or any(type(m) is not str or not 1<=len(m)<=249 for m in profile["magnitudes"])
                or any(type(spec) is not dict or set(spec)!={"unit","direction"}
                       or type(spec["unit"]) is not str or not spec["unit"] or spec["direction"]!="maximum"
                       for spec in profile["magnitudes"].values())
                or type(profile["release"]) is not str or len(profile["release"])>255 or "unreleased" not in profile["release"].lower()):
            raise ValidationError("installed native geometry profile is invalid")
        normative=self.demand.normative
        if ("normative_demand_profile_digest" in profile)!=(normative is not None):
            raise ValidationError("native geometry normative selection must be symmetric")
        if normative is not None and (profile["normative_demand_profile_digest"]!=normative.profile_digest
                or normative.profile_bytes!=context.normative_demand_profile_bytes):
            raise ValidationError("native geometry normative profile differs from Core")
        if context.ambient_profile_bytes is not None:
            if profile.get("ambient_repair_profile_digest")!=_digest(_parse_jcs_object(context.ambient_profile_bytes),context.algorithm):
                raise ValidationError("ambient geometry profile differs from the selected Core policy")
        elif "ambient_repair_profile_digest" in profile:raise ValidationError("ambient geometry requires a selected Core policy")
        if context.federation_profile_bytes is not None:
            if profile.get("federation_profile_digest")!=_digest(_parse_jcs_object(context.federation_profile_bytes),context.algorithm):
                raise ValidationError("federation geometry profile differs from the selected Core policy")
        elif "federation_profile_digest" in profile:raise ValidationError("federation geometry requires a selected Core policy")
        if self.supervision_rails is not None:
            rails=self.supervision_rails
            if (type(rails) is not SupervisionRailAssessment or rails.core is not self.claim_source.core
                    or rails.projection.scope.evaluation_id!=self.decision_id
                    or rails.operation_bytes!=context.operation_bytes or rails.checked_at!=context.evaluated_at
                    or rails.expires_at<=context.evaluated_at
                    or rails.evaluation_profile_digest!=_digest(profile,context.algorithm)
                    or profile.get("supervision_rail_profile_digest")!=_digest(_parse_jcs_object(rails.profile_bytes),context.algorithm)):
                raise ValidationError("supervision rail evidence differs from native geometry context/profile")
        elif "supervision_rail_profile_digest" in profile:
            raise ValidationError("selected supervision rail profile requires current evidence")
        from .schema_formats import installed_format_checker
        for uri in (profile["id"],profile["evaluator"],*profile["sources"].values()):
            if type(uri) is not str or not 1<=len(uri)<=2048 or not installed_format_checker().conforms(uri,"uri"):
                raise ValidationError("installed geometry profile URI is invalid")
        bands=profile["thresholds"]
        deployment=_parse_jcs_object(context.deployment_profile_bytes).get("envelope_thresholds")
        if bands is None:
            if deployment is not None:
                raise ValidationError("geometry cannot omit declared envelope thresholds")
        else:
            if type(bands) is not dict or set(bands)!={"veto","assisted_floor","metacognitive_floor","allow"}:
                raise ValidationError("native geometry envelope bands are invalid")
            NativeEnvelopeThresholds(**bands)
            if (deployment is None or Decimal(str(bands["veto"]))!=Decimal(str(deployment["m_veto"]))
                    or Decimal(str(bands["allow"]))!=Decimal(str(deployment["m_allow"]))):
                raise ValidationError("geometry envelope differs from the installed Core profile")

    @property
    def request_bytes(self) -> bytes:
        context=self.claim_source.context
        operation=_parse_jcs_object(context.operation_bytes)
        return canonical_request_bytes({**operation,"version":"request-binding-v1",
            "demand":{"value":_wire_number(self.demand.demand),"unit":"urn:ktp:unit:action-risk-points"},
            "classification_profile":{"id":self.demand.classification_profile_id,"digest":self.demand.classification_profile_digest}})

    def reproduce(self, *, evaluated_at: int) -> AuthenticatedGeometryReproduction:
        return AuthenticatedGeometryReproduction(self.produce(evaluated_at=evaluated_at),self.request_bytes,
            self.compact_proof,self.clock_healthy)

    def produce(self, *, evaluated_at: int) -> bytes:
        import rfc8785
        context=self.claim_source.context
        if type(evaluated_at) is not int or evaluated_at!=context.evaluated_at:
            raise ValidationError("native geometry belongs to another evaluation time")
        profile=_parse_jcs_object(self.evaluation_profile_bytes)
        core=self.claim_source.core
        request=_parse_jcs_object(self.request_bytes)
        algorithm=context.algorithm
        def digest(raw): return algorithm+":"+hash_new(algorithm,raw).hexdigest()
        gates=dict.fromkeys(("binding","soul","prior","inputs","capacity","envelope","consumer"),"not_evaluated")
        body=dict(record_version="decision-geometry-v1",decision_id=self.decision_id,evaluated_at=evaluated_at,
            ktp_release=profile["release"],evaluation_profile={"id":profile["id"],"digest":digest(self.evaluation_profile_bytes)},
            evaluator=profile["evaluator"],subject=request["subject"],actor=request["actor"],audience=request["audience"],
            association=None,inputs=[],undefined_inputs=[],gates=gates,
            result={"supervision":"silent_veto","tightenedConstraints":{"profile":profile["id"],"ceilings":[]}},reason_codes=[])
        inputs={}
        undefined={}
        def add(name,layer,state,source,evidence=(),value=None):
            key=(name,layer)
            if key in inputs: raise ValidationError("duplicate native geometry input")
            item=dict(name=name,layer=layer,state=state,source=source,evidence_digests=sorted({digest(e) for e in evidence if e}))
            if state in ("observed","modeled","estimated"):
                if not item["evidence_digests"]: raise ValidationError("native geometry input lacks authenticated evidence")
                item["value"]=value
            else:
                undefined[key]=dict(input=name,layer=layer,state=state)
            inputs[key]=item
        def finish(reason):
            ordered=sorted(inputs,key=lambda k:(_LAYERS[k[1]],k[0]))
            body["inputs"]=[inputs[k] for k in ordered]
            body["undefined_inputs"]=[undefined[k] for k in ordered if k in undefined]
            body["reason_codes"]=[reason]
            if not _geometry_validator().is_valid(body):
                raise ValidationError("derived native geometry violates the RFC schema")
            raw=rfc8785.dumps(body)
            if len(raw)>262144: raise ValidationError("derived native geometry exceeds record size")
            return raw
        proof=self.proof_verifier.verify(self.compact_proof,now=evaluated_at,clock_healthy=self.clock_healthy)
        if (proof.stage!=8 or proof.authenticated_payload_bytes!=self.claim_source.produce(evaluated_at=evaluated_at)):
            gates["binding"]="failed"
            return finish("BINDING_INVALID")
        claims=_parse_jcs_object(proof.authenticated_payload_bytes)
        if claims["sub"]!=request["actor"] or claims["aud"]!=request["audience"]:
            gates["binding"]="failed"
            return finish("BINDING_INVALID")
        gates["binding"]="passed"
        body["association"]={"version":"request-proof-association-v1",
            "request_digest":digest_canonical_request(request,algorithm=algorithm),
            "proof_digest":digest_complete_proof(self.compact_proof,algorithm=algorithm),"proof_jti":claims["jti"]}
        soul=core.soul_assessment
        responses={r.framework:r for r in soul.responses}
        for query in core.soul.queries:
            response=responses.get(query.framework)
            name=query.framework if len(query.framework)<=255 else "soul.framework."+hash_new(algorithm,query.framework.encode("utf-8")).hexdigest()
            add(name,"query","observed" if query.state in ("clear","veto") else query.state,
                profile["sources"]["soul"],() if response is None else (response.evidence_bytes,),1 if query.state=="veto" else 0)
        if core.soul.state.value!="clear":
            veto=core.soul.state.value=="veto"
            gates["soul"]="failed" if veto else "undetermined"
            return finish("SOVEREIGNTY_CONSTRAINT" if veto else "SOVEREIGNTY_UNDETERMINED")
        gates["soul"]="passed"
        federation=self.claim_source.standing.federation
        if federation is not None:
            add("federation","term","modeled",profile["sources"]["core"],
                (federation.profile_bytes,federation.frame_bytes,federation.authenticated_state_bytes,federation.source_evidence_bytes),federation.geometry_value())
        ambient=core.environment_assessment.ambient
        if ambient is not None:
            add("ambient_repair","term","modeled",profile["sources"]["environment"],
                (ambient.profile_bytes,ambient.normalizer_profile_bytes,ambient.frame_bytes,ambient.authenticated_state_bytes,ambient.source_evidence_bytes),ambient.geometry_value())
        authority=self.authority_adapter.verify(evaluation_profile_bytes=self.evaluation_profile_bytes,
            deployment_profile_bytes=context.deployment_profile_bytes,operation_bytes=context.operation_bytes,
            compact_proof=self.compact_proof,evaluated_at=evaluated_at)
        if (type(authority) is not AuthenticatedGeometryAuthority or type(authority.payload_bytes) is not bytes
                or type(authority.evidence_bytes) is not bytes):
            raise ValidationError("geometry authority adapter returned invalid evidence")
        auth=_parse_jcs_object(authority.payload_bytes)
        if set(auth)!={"prior","grant"}: raise ValidationError("geometry authority response is invalid")
        prior,grant=auth["prior"],auth["grant"]
        if type(prior) is not dict or prior.get("state") not in ("observed",*_MISSING):
            raise ValidationError("geometry prior state is invalid")
        evidence=(authority.payload_bytes,authority.evidence_bytes)
        prior_state=prior["state"]
        if set(prior)!=({"state","supervision","ceilings"} if prior_state=="observed" else {"state"}):
            raise ValidationError("geometry prior response shape is invalid")
        prior_level=prior.get("supervision")
        if prior_state=="observed" and (prior_level not in _LEVELS or not authority.evidence_bytes):
            raise ValidationError("geometry prior lacks authenticated supervision")
        add("prior_supervision","term",prior_state,profile["sources"]["authority"],evidence,prior_level)
        if prior_state!="observed" or prior_level=="silent_veto":
            gates["prior"]="failed" if prior_level=="silent_veto" and prior_state=="observed" else "undetermined"
            return finish("PRIOR_VETO" if gates["prior"]=="failed" else "INPUT_UNAVAILABLE")
        gates["prior"]="passed"
        if ambient is not None and (ambient.criticality_valid is False or ambient.consequential_hosting_forbidden):
            gates["inputs"]="failed"
            # Keep the RFC's ordered gates and closed wire reason vocabulary.
            # The bound ambient model retains the precise profile/hosting cause.
            return finish("TRUST_INSUFFICIENT")
        if type(grant) is not dict or grant.get("state") not in ("observed",*_MISSING):
            raise ValidationError("geometry grant state is invalid")
        if set(grant)!=({"state","ceilings"} if grant["state"]=="observed" else {"state"}):
            raise ValidationError("geometry grant response shape is invalid")
        def ceilings(section):
            values=section.get("ceilings")
            if type(values) is not dict or set(values)-set(profile["magnitudes"]):
                raise ValidationError("geometry authority contains undeclared ceiling magnitudes")
            return {name:as_decimal(value,name="geometry ceiling") for name,value in values.items()}
        prior_caps=ceilings(prior)
        grant_caps=ceilings(grant) if grant["state"]=="observed" else {}
        for prefix,values in (("prior",prior_caps),("grant",grant_caps)):
            for name,value in sorted(values.items()):
                add(prefix+"."+name,"term","observed",profile["sources"]["authority"],evidence,_wire_number(value))
        if grant["state"]!="observed":
            add("grant","term",grant["state"],profile["sources"]["authority"],evidence)
        add("demand","term","modeled",profile["sources"]["demand"],
            (context.deployment_profile_bytes,self.demand.classifier_profile_bytes,context.operation_bytes,self.demand.evidence.original_evidence),_wire_number(self.demand.demand))
        demand_evidence=self.demand.evidence
        normative=self.demand.normative
        if normative is not None:
            add("normative_demand","term","modeled",profile["sources"]["demand"],
                (normative.profile_bytes,normative.external_schema_bytes,normative.authenticated_state_bytes,
                 normative.source_evidence_bytes,normative.frame_bytes),normative.geometry_value())
        add("demand.moment_criticality","term","observed" if demand_evidence.state=="observed" else "undefined",
            profile["sources"]["demand"],tuple(e for e in (demand_evidence.original_evidence,demand_evidence.payload_bytes,demand_evidence.provenance_bytes) if e),
            _wire_number(demand_evidence.observed_value))
        environment=core.environment_assessment
        for factor in core.risk.factors:
            add(factor.factor,"term","modeled" if factor.value is not None else "undefined",profile["sources"]["environment"],
                (environment.original_evidence,environment.authenticated_body_bytes),_wire_number(factor.value))
        for missing in core.risk.undefined_inputs:
            if (missing.input,missing.layer) not in inputs:
                add(missing.input,missing.layer,missing.state,profile["sources"]["environment"],(environment.authenticated_body_bytes,))
        if (grant["state"]!="observed" or not core.capacity.capacity_known or proof.reason!="TP_CLEAR"):
            gates["inputs"]="undetermined"
            return finish("TRUST_INSUFFICIENT")
        gates["inputs"]="passed"
        capacity=core.capacity
        if core.classified_demand is not self.demand:
            raise ValidationError("geometry Core uses another classified demand")
        add("capacity","term","modeled",profile["sources"]["core"],
            (self.claim_source.standing.authenticated_body_bytes,environment.authenticated_body_bytes,self.compact_proof.encode("ascii")),
            _wire_number(capacity.measured_effective_trust))
        relation="zero" if capacity.decision_effective_trust==0 else "over" if capacity.relation=="above" else "within"
        body["capacity"]={"A":_wire_number(capacity.demand),"E":_wire_number(capacity.decision_effective_trust),
            "unit":"urn:ktp:unit:action-risk-points","capacityKnown":True,"relation":relation}
        if relation!="within":
            gates["capacity"]="failed"
            return finish("TRUST_INSUFFICIENT")
        gates["capacity"]="passed"
        bands=profile["thresholds"]
        envelope=project_native_envelope(capacity,thresholds=None if bands is None else NativeEnvelopeThresholds(**bands))
        # Display follows this installed profile's explicit binary64 convention;
        # supervision has already used exact rational threshold comparisons.
        body["margin"]=float(1-Fraction(capacity.demand)/Fraction(capacity.decision_effective_trust))
        if envelope.supervision=="silent_veto":
            gates["envelope"]="failed"
            return finish("TRUST_INSUFFICIENT")
        gates["envelope"]="passed"
        level=max((envelope.supervision,prior_level),key=_LEVELS.index)
        if self.supervision_rails is not None:
            rails=self.supervision_rails
            if rails.projection.environment_supervision!=envelope.supervision:
                raise ValidationError("rail environment floor differs from native envelope")
            add("supervision_rails","term","modeled",profile["sources"]["authority"],
                (rails.authenticated_state_bytes,rails.source_evidence_bytes,*rails.increment_tokens,*rails.release_tokens),rails.projection.supervision)
            level=max((level,rails.projection.supervision),key=_LEVELS.index)
        combined={name:min(value,prior_caps.get(name,value)) for name,value in grant_caps.items()}
        combined.update({name:value for name,value in prior_caps.items() if name not in combined})
        body["result"]={"supervision":level,"tightenedConstraints":{"profile":profile["id"],
            "ceilings":[{"magnitude":name,"max":_wire_number(value)} for name,value in sorted(combined.items())]}}
        return finish("EVALUATION_COMPLETE" if level=="stable" else "SUPERVISION_REQUIRED")


__all__=["NativeGeometrySource","AuthenticatedGeometryAuthority"]
