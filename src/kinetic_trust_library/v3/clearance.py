"""Conditional Clear construction from one installed native policy and lease.

Source authenticates current managed-relation, signed grant/intent, epoch and
actual active-stop state. These are private SDK projections, not new RFC wire.
Service still owns complete authorization, custody, atomic fencing and effects.
"""
from dataclasses import dataclass
from kinetic_trust_library.errors import ValidationError
from .native_evaluation import InstalledNativeEvaluationVerifier,NativeEvaluationResult
from .hand_back_template import InstalledHandBackTemplateVerifier,HandBackTemplateAssessment
from .non_clearance import InstalledNonClearanceVerifier,NonClearanceAssessment
from .lease import LeaseProjection,project_lease
from .formation_authority import project_formation_authority
from .root_lifecycle import _time
from .execution_observation import _name,_digest as is_digest
from .trust_proof_json import _parse_jcs_object
from .demand_supplier import _digest
from .demand_operation import canonical_demand_operation_bytes,digest_demand_operation
from .supervision_rails import LEVELS
from .reissue import InstalledHandBackReissueVerifier,HandBackReissueAssessment
from .relational_commit import InstalledRelationalCommitVerifier,RelationalCommitAssessment
from .installed_authority_separation import InstalledAuthoritySeparationVerifier
from .installed_management import InstalledManagementVerifier
from .proof_expiry import InstalledProofExpiryVerifier


def _profile(p):
    if (set(p)-{"reissue_profile_digest","relational_commit_profile_digest","authority_profile_digest","management_profile_digest","proof_expiry_profile_digest"}!={"id","version","zone","formula","non_clearance_profile_digest","relational_clear"}
            or not _name(p["id"]) or not _name(p["zone"]) or not _time(p["version"]) or p["version"]==0
            or not is_digest(p["non_clearance_profile_digest"]) or p["formula"]!="native-template-lease-clearance-v1"
            or p["relational_clear"] not in ("unsupported","conditional-single-use-v1")
            or (p["relational_clear"]=="conditional-single-use-v1")!=("relational_commit_profile_digest" in p)):
        raise ValidationError("invalid selected clearance policy or unsupported relational Clear claim")
    if "reissue_profile_digest" in p and not is_digest(p["reissue_profile_digest"]):raise ValidationError("invalid selected reissue digest")
    if "relational_commit_profile_digest" in p and not is_digest(p["relational_commit_profile_digest"]):raise ValidationError("invalid selected relational commit digest")
    if "authority_profile_digest" in p and not is_digest(p["authority_profile_digest"]):raise ValidationError("invalid selected authority audit digest")
    if "management_profile_digest" in p and not is_digest(p["management_profile_digest"]):raise ValidationError("invalid selected management digest")
    if "proof_expiry_profile_digest" in p and not is_digest(p["proof_expiry_profile_digest"]):raise ValidationError("invalid selected proof expiry digest")
    return p


@dataclass(frozen=True,slots=True)
class AuthenticatedClearanceContext:
    state_bytes: bytes
    hand_back_bytes: bytes | None
    evidence_bytes: bytes


@dataclass(frozen=True,slots=True,init=False)
class ClearanceAssessment:
    valid: bool
    kind: str | None
    reason: str
    conditional_clear: bool
    action_permitted: bool
    hand_back_required: bool
    native_result: NativeEvaluationResult
    lease: LeaseProjection | None
    template: HandBackTemplateAssessment | None
    non_clearance: NonClearanceAssessment | None
    supervision: str
    tightened_constraints_bytes: bytes | None
    profile_bytes: bytes
    operation_bytes: bytes
    evaluated_at: int
    expires_at: int | None
    authenticated_state_bytes: bytes | None
    source_evidence_bytes: bytes | None
    reissue: HandBackReissueAssessment | None
    relational_commit: RelationalCommitAssessment | None
    authority_separation: object
    management: object
    proof_expiry: object
    reissue_path: str | None

    def __init__(self,*args,**kwargs):raise TypeError("clearance requires installed native/template/lease validation")


@dataclass(frozen=True,slots=True)
class InstalledClearanceVerifier:
    native_verifier: InstalledNativeEvaluationVerifier
    template_verifier: InstalledHandBackTemplateVerifier
    non_clearance_verifier: InstalledNonClearanceVerifier
    profile_bytes: bytes
    context_source: object
    reissue_verifier: InstalledHandBackReissueVerifier | None = None
    relational_commit_verifier: InstalledRelationalCommitVerifier | None = None
    authority_verifier: InstalledAuthoritySeparationVerifier | None = None
    management_verifier: InstalledManagementVerifier | None = None
    proof_expiry_verifier: InstalledProofExpiryVerifier | None = None

    def __post_init__(self):
        if (type(self.native_verifier) is not InstalledNativeEvaluationVerifier or type(self.template_verifier) is not InstalledHandBackTemplateVerifier
                or type(self.non_clearance_verifier) is not InstalledNonClearanceVerifier or type(self.profile_bytes) is not bytes
                or not callable(getattr(self.context_source,"resolve",None))):
            raise ValidationError("invalid installed clearance verifier")
        hb=self.template_verifier.hand_back_verifier;p=_profile(_parse_jcs_object(self.profile_bytes))
        ev=self.proof_expiry_verifier
        if ("proof_expiry_profile_digest" in p)!=(ev is not None):raise ValidationError("Clear proof expiry selection must be symmetric")
        if ev is not None and (type(ev) is not InstalledProofExpiryVerifier or self.management_verifier is None
                or ev.proof_verifier is not self.native_verifier.association_verifier.proof_verifier
                or _parse_jcs_object(ev.profile_bytes)["zone"]!=p["zone"]
                or _parse_jcs_object(ev.profile_bytes)["refresh_path"]==_parse_jcs_object(self.non_clearance_verifier.profile_bytes)["reissue_path"]
                or p["proof_expiry_profile_digest"]!=_digest(_parse_jcs_object(ev.profile_bytes),hb.algorithm)):
            raise ValidationError("proof refresh requires exact native proof/management policy and distinct lease reissue path")
        mv=self.management_verifier
        if ("management_profile_digest" in p)!=(mv is not None):raise ValidationError("Clear management selection must be symmetric")
        if mv is not None and (type(mv) is not InstalledManagementVerifier or mv.hand_back_verifier is not hb
                or _parse_jcs_object(mv.profile_bytes)["zone"]!=p["zone"]
                or p["management_profile_digest"]!=_digest(_parse_jcs_object(mv.profile_bytes),hb.algorithm)):
            raise ValidationError("Clear management differs from installed return-path/zone policy")
        av=self.authority_verifier
        if ("authority_profile_digest" in p)!=(av is not None):
            raise ValidationError("Clear authority-audit selection must be symmetric")
        if av is not None and (type(av) is not InstalledAuthoritySeparationVerifier or av.deployment_profile_bytes!=hb.deployment_profile_bytes
                or av.algorithm!=hb.algorithm or _parse_jcs_object(av.profile_bytes)["zone"]!=p["zone"]
                or _parse_jcs_object(av.profile_bytes)["lease_authority"]!=_parse_jcs_object(self.non_clearance_verifier.profile_bytes)["lease_authority"]
                or p["authority_profile_digest"]!=_digest(_parse_jcs_object(av.profile_bytes),hb.algorithm)):
            raise ValidationError("Clear authority audit differs from actual deployment/zone/issuer policy")
        rv=self.reissue_verifier
        if ("reissue_profile_digest" in p)!=(rv is not None) or (hb.hysteresis_verifier is not None)!=(rv is not None):
            raise ValidationError("Clear hysteresis and reissue selection must be symmetric")
        if rv is not None and (type(rv) is not InstalledHandBackReissueVerifier or rv.hysteresis_verifier is not hb.hysteresis_verifier
                or p["reissue_profile_digest"]!=_digest(_parse_jcs_object(rv.profile_bytes),hb.algorithm)):
            raise ValidationError("Clear reissue differs from installed hand-back ledger/profile")
        cv=self.relational_commit_verifier
        if (p["relational_clear"]=="conditional-single-use-v1")!=(cv is not None):
            raise ValidationError("relational Clear and installed commit selection must be symmetric")
        if cv is not None and (type(cv) is not InstalledRelationalCommitVerifier or rv is None
                or cv.decision_verifier.relational_verifier is not rv.relational_verifier
                or self.native_verifier.boundary_verifier is None
                or p["relational_commit_profile_digest"]!=_digest(_parse_jcs_object(cv.profile_bytes),hb.algorithm)
                or _parse_jcs_object(cv.profile_bytes)["authority"]!=_parse_jcs_object(self.non_clearance_verifier.profile_bytes)["lease_authority"]):
            raise ValidationError("relational Clear requires the exact reissue/decision/authority policy and native boundary")
        if (self.non_clearance_verifier.hand_back_verifier is not hb
                or self.native_verifier.readiness_verifier.readiness_verifier.deployment_profile_bytes!=hb.deployment_profile_bytes
                or self.native_verifier.association_verifier.algorithm!=hb.algorithm
                or self.native_verifier.readiness_verifier.readiness_verifier.receiving_zone!=p["zone"]
                or _parse_jcs_object(hb.profile_bytes)["zone"]!=p["zone"]
                or p["non_clearance_profile_digest"]!=_digest(_parse_jcs_object(self.non_clearance_verifier.profile_bytes),hb.algorithm)):
            raise ValidationError("clearance policies differ on native deployment/zone or return path")

    def evaluate(self,native_result,*,actual_operation,evaluated_at,clock_healthy,relational_token_bytes=None,previous_management=None):
        if type(native_result) is not NativeEvaluationResult or not _time(evaluated_at):
            raise ValidationError("clearance requires an immutable native result and current time")
        if relational_token_bytes is not None and (type(relational_token_bytes) is not bytes or len(relational_token_bytes)>262144):
            raise ValidationError("relational clearance requires immutable bounded signed token bytes")
        hb=self.template_verifier.hand_back_verifier;p=_profile(_parse_jcs_object(self.profile_bytes))
        op_bytes=canonical_demand_operation_bytes(actual_operation);op=_parse_jcs_object(op_bytes)
        source=None;lease=None;template=None;non_clearance=None;reissue=None;relational_commit=None;authority_separation=None;management=None;proof_expiry=None
        def result(reason,kind=None,expiry=None,hand_back_required=False):
            r=object.__new__(ClearanceAssessment)
            for k,v in dict(valid=kind is not None,kind=kind,reason=reason,conditional_clear=kind=="Clear",action_permitted=False,
                    hand_back_required=hand_back_required,native_result=native_result,lease=lease,template=template,non_clearance=non_clearance,
                    supervision=native_result.supervision if kind=="Clear" else "silent_veto",
                    tightened_constraints_bytes=native_result.tightened_constraints_bytes if kind=="Clear" else None,
                    profile_bytes=self.profile_bytes,operation_bytes=op_bytes,evaluated_at=evaluated_at,expires_at=expiry,
                    authenticated_state_bytes=None if source is None else source.state_bytes,
                    source_evidence_bytes=None if source is None else source.evidence_bytes,reissue=reissue,
                    relational_commit=relational_commit,authority_separation=authority_separation,management=management,
                    proof_expiry=proof_expiry,reissue_path=(proof_expiry.refresh_path if proof_expiry is not None and proof_expiry.expired else
                        _parse_jcs_object(self.non_clearance_verifier.profile_bytes)["reissue_path"] if kind=="Expired" else None)).items():object.__setattr__(r,k,v)
            return r
        if native_result.verifier is not self.native_verifier:return result("CLEARANCE_NATIVE_POLICY",hand_back_required=True)
        if clock_healthy is not True or native_result.checked_at!=evaluated_at:return result("CLEARANCE_NATIVE_TIME",hand_back_required=True)
        if previous_management is not None and self.management_verifier is None:
            raise ValidationError("prior management checkpoint requires selected management verifier")
        if self.management_verifier is not None:
            management=self.management_verifier.evaluate(actual_operation=op,evaluated_at=evaluated_at,clock_healthy=clock_healthy,
                credential_bytes=native_result.association.compact_proof.encode("utf-8"),previous_assessment=previous_management)
            if not management.valid:return result("CLEARANCE_MANAGEMENT_INVALID",hand_back_required=management.hand_back_required)
            if management.management.regime!="managed":return result("CLEARANCE_UNMANAGED",hand_back_required=management.hand_back_required)
        invocation=digest_demand_operation(op,algorithm=hb.algorithm)
        deployment=_digest(_parse_jcs_object(hb.deployment_profile_bytes),hb.algorithm)
        geometry_digest=None if native_result.canonical_geometry_bytes is None else _digest(_parse_jcs_object(native_result.canonical_geometry_bytes),hb.algorithm)
        source=self.context_source.resolve(deployment_profile_bytes=hb.deployment_profile_bytes,profile_bytes=self.profile_bytes,
            operation_bytes=op_bytes,native_geometry_digest=geometry_digest,evaluated_at=evaluated_at)
        if (type(source) is not AuthenticatedClearanceContext or type(source.state_bytes) is not bytes or len(source.state_bytes)>262144
                or source.hand_back_bytes is not None and (type(source.hand_back_bytes) is not bytes or len(source.hand_back_bytes)>262144)
                or type(source.evidence_bytes) is not bytes or not source.evidence_bytes):
            raise ValidationError("clearance Source must authenticate complete actual current registry facts")
        s=_parse_jcs_object(source.state_bytes)
        expected={"deployment_digest","profile_digest","operation_digest","subject","zone","managed_relation_id","checked_at","expires_at",
                "principal","consequence_class","mutates_relation","current_grant_epoch","template_digest","lease","intent","adverse_stop","native_geometry_digest","formation"}
        if management is not None:expected.add("management_admission_anchor")
        if (set(s)!=expected
                or s["deployment_digest"]!=deployment or s["profile_digest"]!=_digest(p,hb.algorithm) or s["operation_digest"]!=invocation
                or s["subject"]!=op["actor"] or s["zone"]!=p["zone"] or not _name(s["managed_relation_id"])
                or not _time(s["checked_at"]) or s["checked_at"]!=evaluated_at or not _time(s["expires_at"]) or s["expires_at"]<=evaluated_at
                or s["native_geometry_digest"]!=geometry_digest):
            raise ValidationError("clearance registry differs from current actual native evaluation scope")
        import rfc8785
        if s["adverse_stop"] is not None:
            if source.hand_back_bytes is None:return result("CLEARANCE_HAND_BACK_REQUIRED",hand_back_required=True)
            stop=s["adverse_stop"]
            if type(stop) is not dict or stop.get("kind") not in ("Revoked","Exceeded"):
                raise ValidationError("actual current stop requires a typed adverse variant")
            non_clearance=self.non_clearance_verifier.evaluate(rfc8785.dumps(dict(kind=stop["kind"],hand_back=_parse_jcs_object(source.hand_back_bytes))),
                actual_operation=op,evaluated_at=evaluated_at,clock_healthy=clock_healthy)
            if not non_clearance.valid:return result("CLEARANCE_HAND_BACK_INVALID",hand_back_required=True)
            return result(non_clearance.reason,non_clearance.kind,min(s["expires_at"],non_clearance.expires_at))
        if source.hand_back_bytes is not None:raise ValidationError("clearance Source returned orphan current hand-back bytes")
        np=_parse_jcs_object(self.non_clearance_verifier.profile_bytes)
        def expired_proof_result():
            nonlocal proof_expiry
            pv=native_result.association.proof_verification
            if (self.proof_expiry_verifier is None or native_result.association.reason!="RB_PROOF"
                    or pv is None or pv.stage!=5 or pv.reason!="TP_TIME"):
                return None
            request=_parse_jcs_object(native_result.association.canonical_request_bytes)
            actual={k:v for k,v in request.items() if k not in ("version","demand","classification_profile")}
            if canonical_demand_operation_bytes(actual)!=op_bytes:
                return result("CLEARANCE_NATIVE_BINDING",hand_back_required=True)
            proof_expiry=self.proof_expiry_verifier.evaluate(native_result.association.compact_proof,
                actual_operation=op,evaluated_at=evaluated_at,clock_healthy=clock_healthy)
            if not proof_expiry.expired:return None
            expiry=min(s["expires_at"],management.expires_at)
            if lease is not None and lease.expires_at is not None:expiry=min(expiry,lease.expires_at)
            return result("CLEARANCE_PROOF_EXPIRED","Expired",expiry)
        if s["lease"] is None and self.proof_expiry_verifier is not None:
            # Absence is an authenticated current registry fact, not a lease
            # with invented dates or revocation flags. Contradictory retained
            # intent and malformed relation facts cannot enter routine refresh.
            if (s["intent"] is not None or not _name(s["principal"])
                    or s["consequence_class"] not in ("Logistics","Coordination","Relational")
                    or type(s["mutates_relation"]) is not bool
                    or s["mutates_relation"] and s["consequence_class"]!="Relational"
                    or not _time(s["current_grant_epoch"])
                    or s["template_digest"] is not None and not is_digest(s["template_digest"])):
                return result("CLEARANCE_LEASE_INVALID",hand_back_required=True)
            admission=_parse_jcs_object(management.authenticated_state_bytes)["history"][-1]
            if s["management_admission_anchor"]!=admission["anchor"]:
                return result("CLEARANCE_MANAGEMENT_GRANT_BINDING",hand_back_required=True)
            expired=expired_proof_result()
            if expired is not None:return expired
            return result("CLEARANCE_LEASE_INVALID",hand_back_required=True)
        try:
            lease=project_lease(s["lease"],s["intent"],actual_actor=op["actor"],actual_operation_digest=invocation,
                actual_consequence_class=s["consequence_class"],mutates_relation=s["mutates_relation"],principal=s["principal"],
                lease_authority=np["lease_authority"],template_digest=s["template_digest"],current_grant_epoch=s["current_grant_epoch"],
                principal_token_max_age_seconds=np["principal_token_max_age_seconds"],evaluated_at=evaluated_at)
        except ValidationError:return result("CLEARANCE_LEASE_INVALID",hand_back_required=True)
        if management is not None:
            admission=_parse_jcs_object(management.authenticated_state_bytes)["history"][-1]
            if s["management_admission_anchor"]!=admission["anchor"] or lease.issued_at<admission["occurred_at"]:
                return result("CLEARANCE_MANAGEMENT_GRANT_BINDING",hand_back_required=True)
        if lease.reason=="LEASE_EXPIRED":
            non_clearance=self.non_clearance_verifier.evaluate(rfc8785.dumps(dict(kind="Expired",reissue_path=np["reissue_path"])),
                actual_operation=op,evaluated_at=evaluated_at,clock_healthy=clock_healthy)
            if non_clearance.valid:return result(non_clearance.reason,"Expired",min(s["expires_at"],non_clearance.expires_at))
            return result("CLEARANCE_EXPIRY_UNVERIFIED",hand_back_required=True)
        if not lease.active:return result(lease.reason,hand_back_required=True)
        expired=expired_proof_result()
        if expired is not None:return expired
        if lease.single_use_required and self.relational_commit_verifier is None:
            return result("CLEARANCE_RELATIONAL_UNSUPPORTED",hand_back_required=True)
        if (native_result.reason!="NATIVE_PREREQUISITES_VALID" or native_result.supervision not in LEVELS[:-1]
                or native_result.tightened_constraints_bytes is None or native_result.expires_at is None or native_result.expires_at<=evaluated_at
                or native_result.association.canonical_request_bytes is None or native_result.readiness is None):
            return result("CLEARANCE_NATIVE_NOT_CLEAR",hand_back_required=True)
        request=_parse_jcs_object(native_result.association.canonical_request_bytes)
        actual={k:v for k,v in request.items() if k not in ("version","demand","classification_profile")}
        ready=native_result.readiness.readiness
        if (canonical_demand_operation_bytes(actual)!=op_bytes or ready is None or ready.deployment_profile_digest!=deployment):
            return result("CLEARANCE_NATIVE_BINDING",hand_back_required=True)
        if self.reissue_verifier is not None:
            reissue=self.reissue_verifier.evaluate(rfc8785.dumps(s["lease"]),actual_operation=op,evaluated_at=evaluated_at,clock_healthy=clock_healthy)
            if (reissue.current_grant_epoch!=s["current_grant_epoch"] or reissue.lease_id!=lease.lease_id or reissue.issued_at!=lease.issued_at):
                return result("CLEARANCE_REISSUE_BINDING",hand_back_required=True)
            if not reissue.eligible:return result(reissue.reason,hand_back_required=True)
        try:
            template=self.template_verifier.evaluate(template_digest=lease.template_digest,actual_operation=op,
                evaluated_at=evaluated_at,clock_healthy=clock_healthy)
        except ValidationError:return result("CLEARANCE_TEMPLATE_UNAVAILABLE",hand_back_required=True)
        if (template.subject_profile!="software" or template.consequence_class!=lease.consequence_class
                or template.principal!=s["principal"] or template.registered_at>lease.issued_at):
            return result("CLEARANCE_TEMPLATE_BINDING",hand_back_required=True)
        if s["formation"] is None:return result("CLEARANCE_FORMATION_REQUIRED",hand_back_required=True)
        try:
            formation=project_formation_authority(subject=s["subject"],relation_id=s["managed_relation_id"],
                consequence_class=s["consequence_class"],principal=s["principal"],claimant=s["principal"],
                template_digest=s["template_digest"],grant_issued_at=lease.issued_at,
                evaluated_at=evaluated_at,formation=s["formation"])
            if s["formation"]["registered_at"]!=template.registered_at:
                return result("CLEARANCE_FORMATION_INVALID",hand_back_required=True)
        except ValidationError:return result("CLEARANCE_FORMATION_INVALID",hand_back_required=True)
        if formation.minting_suspended:
            return result("CLEARANCE_FORMATION_CLASSIFICATION_REQUIRED",hand_back_required=True)
        if self.authority_verifier is not None:
            authority_separation=self.authority_verifier.evaluate(decision_digest=geometry_digest,
                actual_operation=op,evaluated_at=evaluated_at,clock_healthy=clock_healthy)
            if not authority_separation.valid:return result(authority_separation.reason,hand_back_required=True)
        expiry=min(native_result.expires_at,template.expires_at,s["expires_at"],reissue.expires_at if reissue is not None else s["expires_at"])
        if authority_separation is not None:expiry=min(expiry,authority_separation.expires_at)
        if management is not None:expiry=min(expiry,management.expires_at)
        if lease.single_use_required:
            relational_commit=self.relational_commit_verifier.evaluate(relational_token_bytes,rfc8785.dumps(s["lease"]),
                evidence_digest=geometry_digest,actual_operation=op,evaluated_at=evaluated_at,clock_healthy=clock_healthy,not_after=expiry)
            if not relational_commit.conditional_commit:return result(relational_commit.reason,hand_back_required=True)
            human=relational_commit.decision;hr=human.reissue;pr=reissue.relational
            contract=_parse_jcs_object(relational_commit.contract_bytes)
            if (hr.lease_digest!=reissue.lease_digest or hr.current_grant_epoch!=s["current_grant_epoch"]
                    or hr.grant_sequence!=pr.grant_sequence or hr.ledger_head_anchor!=pr.ledger_head_anchor
                    or hr.ledger_head_sequence!=pr.ledger_head_sequence or native_result.boundary is None
                    or contract["topology_epoch"]!=native_result.boundary.topology_epoch):
                return result("CLEARANCE_RELATIONAL_COMMIT_BINDING",hand_back_required=True)
            if _parse_jcs_object(template.template_bytes)["repair"]["ref"]!=human.repair_ref:
                return result("CLEARANCE_RELATIONAL_REPAIR_BINDING",hand_back_required=True)
            expiry=min(expiry,relational_commit.expires_at)
        else:expiry=min(expiry,lease.expires_at)
        return result("CLEARANCE_CONDITIONAL_CLEAR","Clear",expiry)
