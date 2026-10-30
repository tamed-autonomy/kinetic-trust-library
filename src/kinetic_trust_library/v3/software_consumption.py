"""Bounded native-duration software consumption; no target release occurs.

This installed adapter requires current native conditional Clear, management and
authority audits. Vendor grant/intent original signatures and semantic projection
truth are authenticated by Source under the independently installed contract.
Readiness is independently verified by the native graph. Service must atomically
recheck the returned complete conditions and enforce every native/software limit.
"""
from dataclasses import dataclass
from fractions import Fraction
import hashlib
from kinetic_trust_library.errors import ValidationError
from .clearance import InstalledClearanceVerifier
from .software_evidence import InstalledSoftwareEvidenceVerifier,software_thresholds
from .software_decision_signature import InstalledSoftwareDecisionSignatureVerifier,_software_key_authorized
from .software_decision_shape import parse_software_decision
from .software_restrictions import project_software_restrictions
from .trust_proof_json import _parse_jcs_object
from .demand_supplier import _digest
from .demand_operation import canonical_demand_operation_bytes
from .execution_observation import _name
from .root_lifecycle import _time
from .supervision_rails import LEVELS


def _number(value):return Fraction(str(value))


@dataclass(frozen=True,slots=True,init=False)
class SoftwareConsumptionAssessment:
    verifier: object
    verified: bool
    issuance_prepared: bool
    reason: str
    conditional_consumption: bool
    action_permitted: bool
    checked_at: int
    expires_at: int | None
    operation_bytes: bytes
    decision_bytes: bytes | None
    clearance: object
    management_checkpoint: object
    evidence: object
    signature: object
    restriction_projection: object
    supervision: str
    ceilings: tuple
    native_constraints_bytes: bytes | None
    commit_conditions_bytes: bytes | None

    def __init__(self,*args,**kwargs):raise TypeError("software consumption requires the complete installed current graph")


@dataclass(frozen=True,slots=True)
class InstalledSoftwareConsumptionVerifier:
    clearance_verifier: InstalledClearanceVerifier
    evidence_verifier: InstalledSoftwareEvidenceVerifier
    signature_profile_bytes: bytes
    profile_bytes: bytes

    def __post_init__(self):
        cv=self.clearance_verifier;ev=self.evidence_verifier
        if (type(cv) is not InstalledClearanceVerifier or type(ev) is not InstalledSoftwareEvidenceVerifier
                or type(self.signature_profile_bytes) is not bytes or type(self.profile_bytes) is not bytes):
            raise ValidationError("installed native clearance/evidence/signing declarations required")
        hb=cv.template_verifier.hand_back_verifier;p=_parse_jcs_object(self.profile_bytes)
        ep=_parse_jcs_object(ev.profile_bytes);sp=_parse_jcs_object(self.signature_profile_bytes)
        # Validate the independent signing declaration without selecting a key
        # from the untrusted candidate. The current inventory is resolved at use.
        InstalledSoftwareDecisionSignatureVerifier(b"{}",self.signature_profile_bytes)
        if (set(p)!={"id","version","zone","formula","clearance_profile_digest","evidence_profile_digest",
                "signature_profile_digest","prerequisite_order","original_artifact_contract"}
                or not _name(p["id"]) or not _time(p["version"]) or p["version"]==0
                or p["formula"]!="native-duration-software-consumption-v1"
                or p["original_artifact_contract"]!="authenticated-vendor-grant-intent-v1"
                or p["prerequisite_order"]!=["readiness","lease","intent"]
                or p["clearance_profile_digest"]!=_digest(_parse_jcs_object(cv.profile_bytes),ev.algorithm)
                or p["evidence_profile_digest"]!=_digest(ep,ev.algorithm)
                or p["signature_profile_digest"]!=_digest(sp,ev.algorithm)
                or p["zone"]!=ep["zone"] or p["zone"]!=sp["zone"] or p["zone"]!=_parse_jcs_object(cv.profile_bytes)["zone"]
                or ev.deployment_profile_bytes!=hb.deployment_profile_bytes or ev.algorithm!=hb.algorithm
                or sp["execution_profile_digest"]!=ep["execution_profile_digest"] or sp["policy_digest"]!=ep["policy_digest"]
                or cv.management_verifier is None or cv.authority_verifier is None):
            raise ValidationError("software consumption requires exact current native management/authority and installed declaration bindings")
        nv=cv.native_verifier
        if (cv.relational_commit_verifier is not None or cv.reissue_verifier is not None
                or nv.adjudication_verifier is not None or nv.adjudication_verifiers
                or any(getattr(nv,n) is not None for n in ("repair_verifier","ambient_verifier","federation_verifier","normative_demand_verifier"))):
            raise ValidationError("this software adapter does not bind the complete artifacts of supplemental native prerequisite families")

    def evaluate(self,decision_bytes,native_result,*,actual_operation,evaluated_at,clock_healthy,previous_assessment=None):
        return self._assess(decision_bytes,native_result,actual_operation=actual_operation,evaluated_at=evaluated_at,
            clock_healthy=clock_healthy,previous_assessment=previous_assessment,issuance_selection=None)

    def prepare_issuance(self,payload_bytes,native_result,*,actual_operation,evaluated_at,clock_healthy,algorithm,kid,previous_assessment=None):
        """Validate unsigned installed-source input without making it consumable.

        A local placeholder is used solely to apply the unchanged closed wire
        schema to an unsigned payload. It is never signature-verified, returned
        as a decision, or given conditional-consumption/commit status.
        """
        import rfc8785
        if type(payload_bytes) is not bytes or len(payload_bytes)>262144:
            raise ValidationError("bounded canonical software issuance payload required")
        body=_parse_jcs_object(payload_bytes)
        if "signature" in body or body.get("evaluated_at")!=evaluated_at or algorithm not in ("ES256","EdDSA") or not _name(kid):
            raise ValidationError("software issuer requires fresh unsigned payload and installed signing identity")
        shape_only=rfc8785.dumps(dict(body,signature="e30.e30.AA"))
        return self._assess(shape_only,native_result,actual_operation=actual_operation,evaluated_at=evaluated_at,
            clock_healthy=clock_healthy,previous_assessment=previous_assessment,issuance_selection=(algorithm,kid))

    def _assess(self,decision_bytes,native_result,*,actual_operation,evaluated_at,clock_healthy,previous_assessment,issuance_selection):
        if not _time(evaluated_at) or clock_healthy is not True:
            raise ValidationError("software use requires healthy current trusted time")
        import rfc8785
        op_bytes=canonical_demand_operation_bytes(actual_operation);old=None
        if previous_assessment is not None:
            if (type(previous_assessment) is not SoftwareConsumptionAssessment or previous_assessment.verifier is not self
                    or previous_assessment.operation_bytes!=op_bytes or previous_assessment.checked_at>evaluated_at):
                raise ValidationError("retained software consumption belongs to another installed operation or clock")
            old=previous_assessment
        c=self.clearance_verifier.evaluate(native_result,actual_operation=actual_operation,evaluated_at=evaluated_at,
            clock_healthy=clock_healthy,previous_management=None if old is None else old.management_checkpoint)
        # A denial in another prerequisite must not erase retained software
        # history. The prior evidence is continuity-only until rechecked below;
        # it cannot make this denied result valid or authorize consumption.
        e=None if old is None else old.evidence
        sig=projection=None;level="silent_veto";ceilings=();expiry=None;conditions=None
        def result(reason,verified=False,conditional=False):
            r=object.__new__(SoftwareConsumptionAssessment)
            signed=issuance_selection is None
            for k,v in dict(verifier=self,verified=verified and signed,issuance_prepared=verified and not signed,
                    reason=reason,conditional_consumption=conditional and signed,action_permitted=False,
                    checked_at=evaluated_at,expires_at=expiry,operation_bytes=op_bytes,decision_bytes=decision_bytes if verified and signed else None,
                    clearance=c,management_checkpoint=c.management if c.management is not None else None if old is None else old.management_checkpoint,
                    evidence=e,signature=sig,restriction_projection=projection,supervision=level,ceilings=ceilings,
                    native_constraints_bytes=c.tightened_constraints_bytes if verified else None,commit_conditions_bytes=conditions).items():object.__setattr__(r,k,v)
            return r
        if not c.conditional_clear:return result(c.reason)
        state=_parse_jcs_object(c.authenticated_state_bytes)
        if c.lease.single_use_required or state["mutates_relation"]:return result("SOFTWARE_NATIVE_PREREQUISITES_UNSUPPORTED")
        ev=self.evidence_verifier;ep=_parse_jcs_object(ev.profile_bytes);algorithm=ev.algorithm
        e=ev.evaluate(actual_operation=actual_operation,evaluated_at=evaluated_at,clock_healthy=clock_healthy,
            previous_assessment=None if old is None else old.evidence)
        if not e.valid:return result(e.reason)
        body=parse_software_decision(decision_bytes)
        if issuance_selection is None:
            sig=InstalledSoftwareDecisionSignatureVerifier(e.signing_keys_bytes,self.signature_profile_bytes).verify(
                decision_bytes,now=evaluated_at,clock_healthy=clock_healthy)
            if not sig.verified:return result(sig.reason)
            key_expiry=sig.signing_key_expires_at
        else:
            signing_algorithm,kid=issuance_selection
            key=_parse_jcs_object(e.signing_keys_bytes).get(kid);sp=_parse_jcs_object(self.signature_profile_bytes)
            if not _software_key_authorized(key,sp,body,evaluated_at) or key["kid"]!=kid or key["alg"]!=signing_algorithm:
                return result("SOFTWARE_ISSUANCE_KEY_INVALID")
            key_expiry=key["not_after"]
        s=_parse_jcs_object(e.source_state_bytes)
        binding=_parse_jcs_object(e.request_binding_bytes);a=_parse_jcs_object(e.assessment_bytes);out=body["result"]
        def raw_digest(raw):return algorithm+":"+hashlib.new(algorithm,raw).hexdigest()
        prerequisites=e.prerequisites
        if (len(prerequisites)!=2 or tuple(p.kind for p in prerequisites)!=("lease","intent")
                or any(p.representation!="source-contract-original-bytes" for p in prerequisites)
                or any(_parse_jcs_object(p.projection_bytes)!=state[p.kind] for p in prerequisites)):
            return result("SOFTWARE_PREREQUISITES_INVALID")
        originals=(native_result.readiness.decision_bytes,*(p.artifact_bytes for p in prerequisites))
        expected_prerequisites=[raw_digest(raw) for raw in originals]
        if (body["request_binding"]!=binding or body["request_digest"]!=_digest(binding,algorithm)
                or body["proof_digest"]!=raw_digest(native_result.association.compact_proof.encode("ascii"))
                or body["evidence_digest"]!=_digest(_parse_array(e.observations_bytes),algorithm)
                or body["prerequisite_digests"]!=expected_prerequisites or body["consumption_epoch"]!=e.consumption_epoch
                or ep["authority_classes"][binding["authority_class"]]!=state["consequence_class"]):
            return result("SOFTWARE_CURRENT_BINDING_INVALID")
        observations=_parse_array(e.observations_bytes)
        readiness_body=_parse_jcs_object(native_result.readiness.decision_bytes)
        if body["evaluated_at"]<max(*(r["observed_at"] for r in observations),state["lease"]["issued_at"],readiness_body["evaluated_at"]):
            return result("SOFTWARE_EVALUATION_PRECEDES_INPUTS")
        # A principal's intent is a historical mint-time prerequisite under the
        # native lease contract, not a second currently-live permission token.
        # Its complete signed original remains bound; current grant status and
        # expiration are independently established by the native graph.
        max_expiry=min(c.expires_at,e.inputs_expires_at,native_result.expires_at,c.lease.expires_at,
            native_result.readiness.expires_at,key_expiry)
        if body["expires_at"]>max_expiry:return result("SOFTWARE_VALIDITY_WIDENED")
        geometry=_parse_jcs_object(native_result.canonical_geometry_bytes)["capacity"]
        if (geometry["unit"]!=ep["scale"] or any(_number(out[n])!=_number(a[n]) for n in ("autonomyDemand","environmentalCapacity"))
                or out["capacityKnown"]!=a["capacityKnown"] or not geometry["capacityKnown"] and out["capacityKnown"]
                or _number(out["autonomyDemand"])<_number(geometry["A"])
                or _number(out["environmentalCapacity"])>_number(geometry["E"])
                or out["repairPathVerified"]!=e.repair_path_verified or out["supervisionAvailable"]!=e.supervision_available):
            return result("SOFTWARE_ASSESSMENT_WIDENED_OR_SUBSTITUTED")
        maxima={v["magnitude"]:v["max"] for v in out["tightenedConstraints"]["ceilings"]}
        if any(maxima[k]>min(s["requested_magnitudes"][k],s["existing_ceilings"][k]) for k in maxima):
            return result("SOFTWARE_CEILINGS_WIDENED")
        floor=max((c.supervision,s["existing_supervision"]),key=LEVELS.index)
        projection=project_software_restrictions(requested=s["requested_magnitudes"],candidate_ceilings=maxima,
            prior_ceilings=s["existing_ceilings"],candidate_supervision=out["supervision"],prior_supervision=floor,
            demand=out["autonomyDemand"],capacity=out["environmentalCapacity"],capacity_known=out["capacityKnown"],
            repair_path_verified=e.repair_path_verified,supervision_available=e.supervision_available,
            thresholds=software_thresholds(ep["envelope_thresholds"]))
        if LEVELS.index(out["supervision"])<LEVELS.index(projection.supervision):return result("SOFTWARE_SUPERVISION_LOWERED")
        if "margin" in out:
            A=_number(out["autonomyDemand"]);E=_number(out["environmentalCapacity"])
            if E==0 or A>E or _number(out["margin"])!=1-A/E:return result("SOFTWARE_MARGIN_INVALID")
        level=projection.supervision;ceilings=projection.ceilings
        expiry=min(body["expires_at"],c.expires_at,e.expires_at)
        if not projection.conditional_candidate:return result("SOFTWARE_RESTRICTED",verified=True)
        if any(s["requested_magnitudes"][k]>limit for k,limit in ceilings):
            return result("SOFTWARE_REVISED_OPERATION_REQUIRED",verified=True)
        if issuance_selection is not None:return result("SOFTWARE_ISSUANCE_PREPARED",verified=True)
        # These are conditions for the actual Service transaction, never proof
        # of atomicity, dispatch, target effects, reservations or reconciliation.
        conditions=rfc8785.dumps(dict(consumer_profile_digest=_digest(_parse_jcs_object(self.profile_bytes),algorithm),
            operation_digest=raw_digest(op_bytes),decision_digest=raw_digest(decision_bytes),proof_digest=body["proof_digest"],
            prerequisite_digests=expected_prerequisites,native_geometry_digest=raw_digest(native_result.canonical_geometry_bytes),
            native_constraints=_parse_jcs_object(c.tightened_constraints_bytes),software_ceilings=dict(ceilings),supervision=level,
            clearance_state=_parse_jcs_object(c.authenticated_state_bytes),
            management_state=_parse_jcs_object(c.management.authenticated_state_bytes),
            authority_state=_parse_jcs_object(c.authority_separation.authenticated_state_bytes),
            readiness_state=_parse_jcs_object(native_result.readiness.readiness.authenticated_state_bytes),
            readiness_keys_digest=raw_digest(native_result.readiness.readiness.trusted_keys_bytes),
            boundary_state=None if native_result.boundary is None else _parse_jcs_object(native_result.boundary.authenticated_state_bytes),
            native_graph_revalidation_required=True,
            evidence_frame=_parse_jcs_object(e.frame_bytes),evidence_digest=body["evidence_digest"],expires_at=expiry))
        return result("SOFTWARE_CONDITIONAL_CONSUMPTION",verified=True,conditional=True)


def _parse_array(raw):
    # This is already canonical Source-derived JSON, not candidate ingestion.
    import json
    return json.loads(raw)
