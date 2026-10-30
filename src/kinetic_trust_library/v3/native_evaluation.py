"""Compose native request, geometry and current readiness prerequisites.

A valid result is an immutable conditional evaluation, never execution
permission. Products still establish remaining ordinary authorization and fence
all current source state with protected effects. No legacy format is selected.
"""
from dataclasses import dataclass
from decimal import Decimal
from kinetic_trust_library.errors import ValidationError
from .request_association import InstalledRequestAssociationVerifier,RequestAssociationResult
from .readiness_decision import InstalledReadinessDecisionVerifier,ReadinessDecisionResult
from .geometry_verifier import InstalledGeometryVerifier
from .trust_proof_json import _parse_jcs_object
from kinetic_trust_library.proofs._jwt import _decode_segment
from .root_lifecycle import _time
from .adjudication import InstalledAdjudicationVerifier, AdjudicationAssessment
from .boundary import InstalledBoundaryVerifier, BoundaryAssessment
from .installed_repair import InstalledRepairVerifier,RepairAssessment
from .installed_ambient_repair import InstalledAmbientRepairVerifier,AmbientRepairAssessment
from .federation import InstalledFederationVerifier,FederationAssessment,FEDERATION_CEILING_PREFIX
from fractions import Fraction
from .risk import _FACTORS
from .normative_demand import InstalledNormativeDemandVerifier,NormativeDemandAssessment
from .demand_supplier import _digest
from .native_capabilities import validate_native_capabilities,ORDINARY_NATIVE_EXECUTION_PROFILE


@dataclass(frozen=True, slots=True, init=False)
class NativeEvaluationResult:
    verifier: object
    reason: str
    checked_at: int
    supervision: str
    tightened_constraints_bytes: bytes | None
    canonical_geometry_bytes: bytes | None
    association: RequestAssociationResult
    readiness: ReadinessDecisionResult | None
    expires_at: int | None
    adjudication: AdjudicationAssessment | None
    adjudications: tuple[AdjudicationAssessment, ...]
    boundary: BoundaryAssessment | None
    repair: RepairAssessment | None
    ambient: AmbientRepairAssessment | None
    federation: FederationAssessment | None
    normative_demand: NormativeDemandAssessment | None

    def __init__(self,*args,**kwargs):
        raise TypeError("native evaluation results are derived by an installed verifier")


@dataclass(frozen=True, slots=True)
class InstalledNativeEvaluationVerifier:
    association_verifier: InstalledRequestAssociationVerifier
    readiness_verifier: InstalledReadinessDecisionVerifier
    local_geometry_verifier: InstalledGeometryVerifier | None = None
    local_evaluated_at: int | None = None
    local_profile_expires_at: int | None = None
    adjudication_verifier: InstalledAdjudicationVerifier | None = None
    adjudication_verifiers: tuple[InstalledAdjudicationVerifier, ...] = ()
    boundary_verifier: InstalledBoundaryVerifier | None = None
    repair_verifier: InstalledRepairVerifier | None = None
    ambient_verifier: InstalledAmbientRepairVerifier | None = None
    federation_verifier: InstalledFederationVerifier | None = None
    normative_demand_verifier: InstalledNormativeDemandVerifier | None = None
    normative_classifier_profile_bytes: bytes | None = None
    execution_profile: str = ORDINARY_NATIVE_EXECUTION_PROFILE

    def __post_init__(self):
        if (type(self.association_verifier) is not InstalledRequestAssociationVerifier
                or type(self.readiness_verifier) is not InstalledReadinessDecisionVerifier
                or self.association_verifier.proof_verifier is not self.readiness_verifier.proof_verifier):
            raise ValidationError("native evaluation requires one installed ordinary proof policy")
        if not self.association_verifier.crosses_trust_boundary:
            if (type(self.local_geometry_verifier) is not InstalledGeometryVerifier
                    or self.local_geometry_verifier.proof_verifier is not self.association_verifier.proof_verifier
                    or not _time(self.local_evaluated_at) or not _time(self.local_profile_expires_at)
                    or self.local_evaluated_at>=self.local_profile_expires_at):
                raise ValidationError("local native geometry requires an installed verifier, evaluation time and profile expiry")
        elif any(v is not None for v in (self.local_geometry_verifier,self.local_evaluated_at,self.local_profile_expires_at)):
            raise ValidationError("protected carriage cannot select a local unsigned geometry alternative")

        if (type(self.adjudication_verifiers) is not tuple or len(self.adjudication_verifiers)>256
                or self.adjudication_verifier is not None and self.adjudication_verifiers):
            raise ValidationError("select one explicit adjudication policy form")
        policies=self.adjudication_verifiers if self.adjudication_verifier is None else (self.adjudication_verifier,)
        ids=[]
        for policy in policies:
            if (type(policy) is not InstalledAdjudicationVerifier
                    or policy.deployment_profile_bytes != self.readiness_verifier.readiness_verifier.deployment_profile_bytes
                    or _parse_jcs_object(policy.profile_bytes)["zone_id"] != self.readiness_verifier.readiness_verifier.receiving_zone):
                raise ValidationError("adjudication policy differs from native deployment/receiving zone")
            ids.append(_parse_jcs_object(policy.profile_bytes)["gate_id"])
        if len(set(ids))!=len(ids):raise ValidationError("duplicate declared adjudication gate")
        deployment=self.readiness_verifier.readiness_verifier.deployment_profile_bytes
        validate_native_capabilities(_parse_jcs_object(deployment),execution_profile=self.execution_profile)
        normative=self.normative_demand_verifier
        if (normative is not None)!=(self.normative_classifier_profile_bytes is not None):
            raise ValidationError("native normative demand requires its selected classifier profile")
        if normative is not None:
            if (type(normative) is not InstalledNormativeDemandVerifier or normative.deployment_profile_bytes!=deployment
                    or normative.algorithm!=self.association_verifier.algorithm
                    or _parse_jcs_object(normative.profile_bytes)["zone"]!=self.readiness_verifier.readiness_verifier.receiving_zone
                    or type(self.normative_classifier_profile_bytes) is not bytes):
                raise ValidationError("native normative policy differs from installed deployment/zone")
            classifier=_parse_jcs_object(self.normative_classifier_profile_bytes)
            if classifier.get("normative_input_profile_digest")!=_digest(_parse_jcs_object(normative.profile_bytes),normative.algorithm):
                raise ValidationError("native normative classifier profile differs from installed policy")
        if "boundary" in _parse_jcs_object(deployment):
            if (type(self.boundary_verifier) is not InstalledBoundaryVerifier
                    or self.boundary_verifier.deployment_profile_bytes!=deployment):
                raise ValidationError("declared boundary requires the same installed deployment policy")
            proof_context=_parse_jcs_object(self.association_verifier.proof_verifier.expected_context_bytes)
            if proof_context["ring_depth"]>0 and self.boundary_verifier.enclosing_deployment_profile_bytes is None:
                raise ValidationError("nested receiving boundary requires enclosing resources")
        elif self.boundary_verifier is not None:raise ValidationError("boundary policy requires a declared boundary")
        if self.repair_verifier is not None and (type(self.repair_verifier) is not InstalledRepairVerifier
                or self.repair_verifier.deployment_profile_bytes!=deployment):
            raise ValidationError("repair policy differs from native deployment")
        if self.ambient_verifier is not None and (type(self.ambient_verifier) is not InstalledAmbientRepairVerifier
                or self.ambient_verifier.deployment_profile_bytes!=deployment or self.ambient_verifier.algorithm!=self.association_verifier.algorithm
                or _parse_jcs_object(self.ambient_verifier.profile_bytes)["zone_id"]!=self.readiness_verifier.readiness_verifier.receiving_zone):
            raise ValidationError("ambient policy differs from native deployment/receiving zone")
        if self.federation_verifier is not None and (type(self.federation_verifier) is not InstalledFederationVerifier
                or self.federation_verifier.deployment_profile_bytes!=deployment or self.federation_verifier.algorithm!=self.association_verifier.algorithm
                or _parse_jcs_object(self.federation_verifier.profile_bytes)["receiving_zone"]!=self.readiness_verifier.readiness_verifier.receiving_zone
                or _parse_jcs_object(self.federation_verifier.profile_bytes).get("standing_binding")!="admission-digest-ceiling-v1"):
            raise ValidationError("federation policy differs from native deployment/receiving zone or admission binding")

    def verify(self, request_bytes: bytes, association_bytes: bytes, compact_proof: str, *,
               decision_bytes: bytes, attestation_bytes: bytes, invocation_evidence: bytes,
               now: int, clock_healthy: bool, geometry_body_bytes: bytes | None = None,
               adjudication_token: bytes | None = None,
               adjudication_tokens: tuple[tuple[str,bytes], ...] = ()) -> NativeEvaluationResult:
        import rfc8785
        if not _time(now):raise ValidationError("native evaluation requires trusted current time")
        if (type(adjudication_tokens) is not tuple or len(adjudication_tokens)>256
                or any(type(item) is not tuple or len(item)!=2 or type(item[0]) is not str
                       or type(item[1]) is not bytes for item in adjudication_tokens)):
            raise ValidationError("adjudication candidates require immutable gate/token pairs")
        candidates=dict(adjudication_tokens)
        declared={_parse_jcs_object(policy.profile_bytes)["gate_id"] for policy in self.adjudication_verifiers}
        if (len(candidates)!=len(adjudication_tokens) or not candidates.keys()<=declared
                or adjudication_token is not None and self.adjudication_verifier is None
                or adjudication_tokens and self.adjudication_verifier is not None):
            raise ValidationError("adjudication candidates differ from declared gates")
        association=self.association_verifier.verify(request_bytes,association_bytes,compact_proof,
            invocation_evidence=invocation_evidence,now=now,clock_healthy=clock_healthy)
        raw=constraints=None
        readiness=None
        adjudication=None
        adjudications=()
        boundary=None
        repair=None
        ambient=None
        federation=None
        normative_demand=None
        def result(reason,supervision="silent_veto",expiry=None):
            value=object.__new__(NativeEvaluationResult)
            for name,member in (("verifier",self),("reason",reason),("checked_at",now),("supervision",supervision),
                ("tightened_constraints_bytes",constraints),("canonical_geometry_bytes",raw),
                ("association",association),("readiness",readiness),("expires_at",expiry),("adjudication",adjudication),
                ("adjudications",adjudications),("boundary",boundary),("repair",repair),("ambient",ambient),("federation",federation),
                ("normative_demand",normative_demand)):
                object.__setattr__(value,name,member)
            return value
        if association.reason!="RB_BOUND":return result(association.reason)
        actual=_parse_jcs_object(association.canonical_request_bytes)
        if self.boundary_verifier is not None:
            operation={name:value for name,value in actual.items() if name not in ("version","demand","classification_profile")}
            boundary=self.boundary_verifier.evaluate(actual_operation=operation,evaluated_at=now,clock_healthy=clock_healthy)
            if boundary.zone_id!=self.readiness_verifier.readiness_verifier.receiving_zone:return result("BOUNDARY_ZONE")
            ingress=association.proof_verification.ingress_verification
            if ingress is not None:
                topology=_parse_jcs_object(ingress.authenticated_state_bytes)["topology"]
                rings=topology["rings"]
                parent=None if len(rings)==1 else rings[-2]["zone_id"]
                if (boundary.topology_epoch!=topology["epoch"] or boundary.zone_id!=rings[-1]["zone_id"]
                        or boundary.enclosure_zone!=parent):return result("BOUNDARY_TOPOLOGY")
            elif _parse_jcs_object(self.association_verifier.proof_verifier.expected_context_bytes)["ring_depth"]>0:
                return result("BOUNDARY_TOPOLOGY")
            if not boundary.allowed:return result(boundary.reason)
        if self.repair_verifier is not None:
            operation={name:value for name,value in actual.items() if name not in ("version","demand","classification_profile")}
            repair=self.repair_verifier.evaluate(actual_operation=operation,evaluated_at=now,clock_healthy=clock_healthy)
            if repair.zone_id!=self.readiness_verifier.readiness_verifier.receiving_zone:return result("REPAIR_ZONE")
            if not repair.reentry_eligible:return result(repair.reason)
            current_claims=_parse_jcs_object(association.proof_verification.authenticated_payload_bytes)
            if repair.standing_ceiling is not None and Decimal(str(current_claims["ktp"]["e_base"]))>repair.standing_ceiling:
                return result("REPAIR_STANDING")
            if repair.standing_ceiling is not None:
                declared=[item for item in current_claims["ktp"]["applicable_ceilings"] if item["ceiling"]=="repair_reentry"]
                if len(declared)!=1 or Decimal(str(declared[0]["value"]))>repair.standing_ceiling:
                    return result("REPAIR_CEILING")
        current_claims=_parse_jcs_object(association.proof_verification.authenticated_payload_bytes)
        admission_markers=[item for item in current_claims["ktp"]["applicable_ceilings"] if item["ceiling"].startswith(FEDERATION_CEILING_PREFIX)]
        if self.federation_verifier is None:
            if admission_markers:return result("FEDERATION_POLICY_REQUIRED")
        else:
            if len(admission_markers)!=1:return result("FEDERATION_BINDING")
            operation={name:value for name,value in actual.items() if name not in ("version","demand","classification_profile")}
            federation=self.federation_verifier.evaluate(actual_operation=operation,evaluated_at=now,clock_healthy=clock_healthy)
            if not federation.admitted:return result(federation.reason)
            if admission_markers[0]["ceiling"]!=federation.standing_ceiling_name:return result("FEDERATION_BINDING")
            if current_claims["iat"]<federation.ingress_at:return result("FEDERATION_ADMISSION")
            try:
                bound=Fraction(str(admission_markers[0]["value"]))
                if (bound>federation.exportable_base*federation.factor.applied_factor
                        or Fraction(str(current_claims["ktp"]["e_base"]))>bound):return result("FEDERATION_STANDING")
            except (ValueError,TypeError,ZeroDivisionError):return result("FEDERATION_STANDING")
        if self.ambient_verifier is not None:
            operation={name:value for name,value in actual.items() if name not in ("version","demand","classification_profile")}
            ambient=self.ambient_verifier.evaluate(actual_operation=operation,evaluated_at=now,clock_healthy=clock_healthy)
            if boundary is not None and (ambient.zone_id!=boundary.zone_id or ambient.parent_zone!=boundary.enclosure_zone
                    or ambient.topology_epoch!=boundary.topology_epoch):return result("AMBIENT_TOPOLOGY")
            ingress=association.proof_verification.ingress_verification
            if ingress is not None:
                topology=_parse_jcs_object(ingress.authenticated_state_bytes)["topology"];rings=topology["rings"]
                if (ambient.topology_epoch!=topology["epoch"] or ambient.zone_id!=rings[-1]["zone_id"]
                        or ambient.parent_zone!=(None if len(rings)==1 else rings[-2]["zone_id"])):return result("AMBIENT_TOPOLOGY")
            elif ambient.parent_zone is not None or _parse_jcs_object(self.association_verifier.proof_verifier.expected_context_bytes)["ring_depth"]>0:
                return result("AMBIENT_TOPOLOGY")
            if ambient.criticality_valid is False:return result("AMBIENT_PROFILE_INVALID")
            if ambient.consequential_hosting_forbidden:return result("AMBIENT_HOSTING_FORBIDDEN")
            if ambient.pressure_floor is None:return result("AMBIENT_INPUT_UNAVAILABLE")
            current_claims=_parse_jcs_object(association.proof_verification.authenticated_payload_bytes)["ktp"]
            deployment=_parse_jcs_object(self.ambient_verifier.deployment_profile_bytes)
            try:
                stresses={name:Fraction(str(current_claims["context"][name])) for name in _FACTORS}
                local_r=sum((stresses[name]*Fraction(str(deployment["risk_factors"][name]["weight"])) for name in _FACTORS),Fraction(0))
                if (any(not 0<=value<=1 for value in stresses.values()) or stresses["adversarial_pressure"]<Fraction(ambient.pressure_floor)
                        or Fraction(str(current_claims["r"]))<local_r
                        or Fraction(str(current_claims["e_trust"]))>Fraction(str(current_claims["e_base"]))*(1-local_r)):
                    return result("AMBIENT_PRESSURE")
            except (ValueError,KeyError,TypeError,ZeroDivisionError):return result("AMBIENT_PRESSURE")
        if self.association_verifier.crosses_trust_boundary:
            binding=association.carrier_binding
            if binding is None or binding.verified_at!=now or geometry_body_bytes is not None:
                return result("DG_BINDING")
            raw=binding.canonical_geometry_bytes
            carrier=_parse_jcs_object(_decode_segment(binding.compact_carrier.split(".")[1],name="verified geometry payload"))
            expiry=carrier["expires_at"]
        else:
            if not self.local_evaluated_at<=now<self.local_profile_expires_at:
                return result("DG_CONTEXT")
            if type(geometry_body_bytes) is not bytes:return result("DG_BINDING")
            verified=self.local_geometry_verifier.verify(geometry_body_bytes,evaluated_at=self.local_evaluated_at)
            if verified.reason!="DG_VALID":return result(verified.reason)
            raw=verified.canonical_body_bytes
            expiry=self.local_profile_expires_at
        body=_parse_jcs_object(raw)
        normative_entries=[item for item in body["inputs"] if item["name"]=="normative_demand" and item["layer"]=="term"]
        if self.normative_demand_verifier is None:
            if normative_entries:return result("NORMATIVE_DEMAND_POLICY_REQUIRED")
        else:
            classifier=_parse_jcs_object(self.normative_classifier_profile_bytes)
            expected_classifier=dict(id=classifier.get("id"),digest=_digest(classifier,self.association_verifier.algorithm))
            if actual["classification_profile"]!=expected_classifier:return result("NORMATIVE_DEMAND_CLASSIFIER")
            operation={name:value for name,value in actual.items() if name not in ("version","demand","classification_profile")}
            normative_demand=self.normative_demand_verifier.evaluate(actual_operation=operation,
                baseline_demand=actual["demand"]["value"],evaluated_at=now,clock_healthy=clock_healthy)
            if normative_demand.demand>Decimal(str(actual["demand"]["value"])):return result("NORMATIVE_DEMAND_INCREASED")
            if boundary is not None and (normative_demand.zone!=boundary.zone_id or normative_demand.topology_epoch!=boundary.topology_epoch):
                return result("NORMATIVE_DEMAND_TOPOLOGY")
            ingress=association.proof_verification.ingress_verification
            if ingress is not None:
                topology=_parse_jcs_object(ingress.authenticated_state_bytes)["topology"]
                if normative_demand.topology_epoch!=topology["epoch"] or normative_demand.zone!=topology["rings"][-1]["zone_id"]:
                    return result("NORMATIVE_DEMAND_TOPOLOGY")
            if (len(normative_entries)!=1 or normative_entries[0].get("state")!="modeled" or normative_entries[0].get("value")!=normative_demand.geometry_value()
                    or not {normative_demand.profile_digest,normative_demand.frame_digest}<=set(normative_entries[0]["evidence_digests"])):
                return result("NORMATIVE_DEMAND_BINDING")
            expiry=min(expiry,normative_demand.expires_at)
        if federation is not None:
            entries=[item for item in body["inputs"] if item["name"]=="federation" and item["layer"]=="term"]
            if (len(entries)!=1 or entries[0].get("value")!=federation.geometry_value()
                    or not {federation.profile_digest,federation.frame_digest}<=set(entries[0]["evidence_digests"])):
                return result("FEDERATION_BINDING")
        if ambient is not None:
            entries=[item for item in body["inputs"] if item["name"]=="ambient_repair" and item["layer"]=="term"]
            if (len(entries)!=1 or entries[0].get("value")!=ambient.geometry_value()
                    or not {ambient.profile_digest,ambient.frame_digest}<=set(entries[0]["evidence_digests"])):
                return result("AMBIENT_BINDING")
            pressure=[item for item in body["inputs"] if item["name"]=="adversarial_pressure" and item["layer"]=="term"]
            try:
                if len(pressure)!=1 or Fraction(str(pressure[0].get("value")))<Fraction(ambient.pressure_floor):return result("AMBIENT_PRESSURE")
            except (ValueError,TypeError):return result("AMBIENT_PRESSURE")
        actual=_parse_jcs_object(association.canonical_request_bytes)
        if (rfc8785.dumps(body["association"])!=association.canonical_association_bytes
                or any(body[name]!=actual[name] for name in ("subject","actor","audience"))):
            return result("DG_BINDING")
        projected=body.get("consumer_result",body["result"])
        levels=("stable","metacognitive","assisted","regulated","silent_veto")
        capacity=body.get("capacity")
        if capacity is not None:
            claims=_parse_jcs_object(association.proof_verification.authenticated_payload_bytes)
            a,e=Decimal(str(capacity["A"])),Decimal(str(capacity["E"]))
            if a!=Decimal(str(actual["demand"]["value"])) or e>Decimal(str(claims["ktp"]["e_trust"])):
                return result("DG_INPUTS")
            relation="zero" if e==0 else "over" if a>e else "within"
            if capacity["relation"]!=relation or (e==0 or a>=e) and body["result"]["supervision"]!="silent_veto":
                return result("DG_ORDER")
            if not capacity["capacityKnown"] and levels.index(body["result"]["supervision"])<levels.index("assisted"):
                return result("DG_CONSTRAINTS")
        def ceilings(value):
            items=value["tightenedConstraints"]["ceilings"]
            values={item["magnitude"]:Decimal(str(item["max"])) for item in items}
            return values if len(values)==len(items) else None
        producer_caps,consumer_caps=ceilings(body["result"]),ceilings(projected)
        if (producer_caps is None or consumer_caps is None
                or projected["tightenedConstraints"]["profile"]!=body["evaluation_profile"]["id"]
                or body["result"]["tightenedConstraints"]["profile"]!=body["evaluation_profile"]["id"]
                or levels.index(projected["supervision"])<levels.index(body["result"]["supervision"])
                or any(name not in consumer_caps or consumer_caps[name]>limit for name,limit in producer_caps.items())):
            return result("DG_CONSTRAINTS")
        constraints=rfc8785.dumps(projected["tightenedConstraints"])
        if projected["supervision"]=="silent_veto":return result("NATIVE_EVALUATION_RESTRICTED")
        readiness=self.readiness_verifier.verify(decision_bytes,attestation_bytes,association,
            evaluated_at=now,clock_healthy=clock_healthy)
        if not readiness.valid:return result(readiness.reason)
        if repair is not None and repair.readiness_after is not None:
            attestation=_parse_jcs_object(readiness.readiness.attestation_bytes)
            if attestation["assessed_at"]<=repair.readiness_after:return result("REPAIR_READINESS_STALE")
        claims=_parse_jcs_object(readiness.proof_verification.authenticated_payload_bytes)
        expiry=min(expiry,readiness.expires_at,claims["exp"])
        if boundary is not None:expiry=min(expiry,boundary.expires_at)
        if repair is not None:expiry=min(expiry,repair.expires_at)
        if ambient is not None:expiry=min(expiry,ambient.expires_at)
        if federation is not None:expiry=min(expiry,federation.expires_at)
        if now>=expiry:return result("NATIVE_EVALUATION_EXPIRED")
        policies=self.adjudication_verifiers if self.adjudication_verifier is None else (self.adjudication_verifier,)
        if policies:
            operation = {name:value for name,value in actual.items() if name not in ("version", "demand", "classification_profile")}
            adjudications=tuple(policy.evaluate(adjudication_token if self.adjudication_verifier is not None
                else candidates.get(_parse_jcs_object(policy.profile_bytes)["gate_id"]),actual_operation=operation,
                evaluated_at=now,clock_healthy=clock_healthy) for policy in policies)
            if self.adjudication_verifier is not None:adjudication=adjudications[0]
            if any(value.gate_required and not value.gate_satisfied for value in adjudications):
                return result("ADJ_GATE_UNSATISFIED", projected["supervision"])
            expiry=min((expiry,*(value.expires_at for value in adjudications if value.gate_required)))
        return result("NATIVE_PREREQUISITES_VALID",projected["supervision"],expiry)


__all__=["InstalledNativeEvaluationVerifier","NativeEvaluationResult"]
