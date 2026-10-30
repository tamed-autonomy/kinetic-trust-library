"""Registered return paths for actual native adjudication/readiness stops.

The preparation Source owns genuine sealing, durable stop/cause registration
and delivery work. Revalidation of the existing current clearance graph, not a
preparation acknowledgment, establishes the resulting Exceeded projection.
"""
from dataclasses import dataclass
from kinetic_trust_library.errors import ValidationError
from .clearance import InstalledClearanceVerifier
from .native_evaluation import NativeEvaluationResult
from .trust_proof_json import _parse_jcs_object
from .demand_operation import canonical_demand_operation_bytes
from .demand_supplier import _digest
from .request_binding import digest_complete_proof
from .root_lifecycle import _time
from .execution_observation import _name
from .non_clearance import _instant


@dataclass(frozen=True,slots=True)
class PreparedNativeStop:
    cause_bytes: bytes
    stop_anchor: str
    hand_back_bytes: bytes
    evidence_bytes: bytes


@dataclass(frozen=True,slots=True,init=False)
class NativeStopResolution:
    clearance: object
    template: object
    cause_bytes: bytes
    preparation: PreparedNativeStop
    evaluated_at: int
    expires_at: int
    action_permitted: bool

    def __init__(self,*args,**kwargs):raise TypeError("native stop resolution requires current registered hand-back validation")


@dataclass(frozen=True,slots=True)
class _InstalledNativeStopResolver:
    clearance_verifier: InstalledClearanceVerifier
    profile_bytes: bytes
    preparation_source: object

    def __post_init__(self):
        if (type(self.clearance_verifier) is not InstalledClearanceVerifier or type(self.profile_bytes) is not bytes
                or not callable(getattr(self.preparation_source,"prepare",None)) or self.clearance_verifier.management_verifier is None):
            raise ValidationError("native stop resolution requires exact installed clearance and current management")
        p=_parse_jcs_object(self.profile_bytes);cv=self.clearance_verifier
        hb=cv.template_verifier.hand_back_verifier;cp=_parse_jcs_object(cv.profile_bytes)
        if (set(p)!={"id","version","zone","formula","clearance_profile_digest"}
                or not _name(p["id"]) or not _time(p["version"]) or p["version"]==0 or p["zone"]!=cp["zone"]
                or p["formula"]!=self._FORMULA
                or p["clearance_profile_digest"]!=_digest(cp,hb.algorithm)):
            raise ValidationError("native stop resolution differs from selected current clearance/zone policy")

    def evaluate(self,native_result,*,actual_operation,evaluated_at,clock_healthy):
        cv=self.clearance_verifier;hb=cv.template_verifier.hand_back_verifier
        if (type(native_result) is not NativeEvaluationResult or native_result.verifier is not cv.native_verifier
                or native_result.reason not in self._FAILURES or not _time(evaluated_at)
                or native_result.checked_at!=evaluated_at or clock_healthy is not True):
            raise ValidationError("selected resolver requires its actual current native failure family")
        op_bytes=canonical_demand_operation_bytes(actual_operation)
        initial=cv.evaluate(native_result,actual_operation=actual_operation,evaluated_at=evaluated_at,clock_healthy=True)
        if (initial.reason!="CLEARANCE_NATIVE_NOT_CLEAR" or initial.kind is not None or not initial.hand_back_required
                or initial.management is None or not initial.management.valid or initial.management.management.regime!="managed"
                or initial.lease is None or not initial.lease.active):
            raise ValidationError("new native stop requires current managed relation and unchanged active grant")
        state=_parse_jcs_object(initial.authenticated_state_bytes)
        template=cv.template_verifier.evaluate(template_digest=initial.lease.template_digest,actual_operation=actual_operation,
            evaluated_at=evaluated_at,clock_healthy=True)
        if (template.subject!=state["subject"] or template.principal!=state["principal"]
                or template.consequence_class!=initial.lease.consequence_class or template.registered_at>initial.lease.issued_at):
            raise ValidationError("native stop return path differs from actual original grant")
        import rfc8785
        policies=cv.native_verifier.adjudication_verifiers
        if cv.native_verifier.adjudication_verifier is not None:policies=(cv.native_verifier.adjudication_verifier,)
        request=_parse_jcs_object(native_result.association.canonical_request_bytes)
        actual={k:v for k,v in request.items() if k not in ("version","demand","classification_profile")}
        if canonical_demand_operation_bytes(actual)!=op_bytes:
            raise ValidationError("native stop failure belongs to another actual operation")
        cause=rfc8785.dumps(dict(profile_digest=_digest(_parse_jcs_object(self.profile_bytes),hb.algorithm),
            operation_digest=_digest(_parse_jcs_object(op_bytes),hb.algorithm),native_reason=native_result.reason,
            evaluated_at=evaluated_at,reason="exceeded_permit_condition",template_digest=template.template_digest,
            proof_digest=digest_complete_proof(native_result.association.compact_proof,algorithm=hb.algorithm),
            geometry_digest=None if native_result.canonical_geometry_bytes is None else _digest(_parse_jcs_object(native_result.canonical_geometry_bytes),hb.algorithm),
            clearance_state_digest=_digest(state,hb.algorithm),gate_profile_digests=[_digest(_parse_jcs_object(p.profile_bytes),hb.algorithm) for p in policies],
            readiness_profile_digest=_digest(_parse_jcs_object(cv.native_verifier.readiness_verifier.readiness_verifier.readiness_profile_bytes),hb.algorithm),
            readiness_input_digests=native_result.readiness_input_digests,
            readiness_context_digests=(None if native_result.readiness is None or native_result.readiness.readiness is None
                else native_result.readiness.readiness.observed_context_digests)))
        prepared=self.preparation_source.prepare(profile_bytes=self.profile_bytes,cause_bytes=cause,
            template_bytes=template.template_bytes,operation_bytes=op_bytes,evaluated_at=evaluated_at)
        if (type(prepared) is not PreparedNativeStop or type(prepared.cause_bytes) is not bytes
                or prepared.cause_bytes!=cause or not _name(prepared.stop_anchor)
                or type(prepared.hand_back_bytes) is not bytes or len(prepared.hand_back_bytes)>262144
                or type(prepared.evidence_bytes) is not bytes or not prepared.evidence_bytes):
            raise ValidationError("native stop Source must authenticate exact cause, anchor and original sealed hand-back")
        current=cv.evaluate(native_result,actual_operation=actual_operation,evaluated_at=evaluated_at,clock_healthy=True,
            previous_management=initial.management)
        if (not current.valid or current.kind!="Exceeded" or current.non_clearance is None
                or current.non_clearance.hand_back.hand_back_bytes!=prepared.hand_back_bytes
                or current.non_clearance.lease is None or not current.non_clearance.lease.active):
            raise ValidationError("prepared native stop is not the actual current registered Exceeded hand-back")
        now_state=_parse_jcs_object(current.authenticated_state_bytes)
        wire=_parse_jcs_object(prepared.hand_back_bytes)
        hs=_parse_jcs_object(current.non_clearance.hand_back.authenticated_state_bytes)
        if (now_state["adverse_stop"]["id"]!=prepared.stop_anchor or now_state["lease"]!=state["lease"]
                or now_state["intent"]!=state["intent"] or now_state["managed_relation_id"]!=state["managed_relation_id"]
                or now_state["management_admission_anchor"]!=state["management_admission_anchor"]
                or _parse_jcs_object(current.management.authenticated_state_bytes)["history"][-1]["anchor"]!=
                    _parse_jcs_object(initial.management.authenticated_state_bytes)["history"][-1]["anchor"]
                or wire["reason"]!="exceeded_permit_condition" or _instant(wire["issued_at"])!=evaluated_at or hs["stop_origin"]!="system"):
            raise ValidationError("native stop changed its actual cause, admission, grant or registered recourse branch")
        result=object.__new__(NativeStopResolution)
        for k,v in dict(clearance=current,template=template,cause_bytes=cause,preparation=prepared,evaluated_at=evaluated_at,
                expires_at=min(current.expires_at,template.expires_at),action_permitted=False).items():object.__setattr__(result,k,v)
        return result


@dataclass(frozen=True,slots=True)
class InstalledNativeAdjudicationStopResolver(_InstalledNativeStopResolver):
    _FORMULA="native-adjudication-return-path-v1"
    _FAILURES=frozenset(("ADJ_GATE_UNSATISFIED",))


@dataclass(frozen=True,slots=True)
class InstalledNativeReadinessStopResolver(_InstalledNativeStopResolver):
    _FORMULA="native-readiness-return-path-v1"
    _FAILURES=frozenset(("READINESS_UNAVAILABLE","READINESS_INVALID","READINESS_PROOF_INVALID","READINESS_DECISION_INVALID"))

    def evaluate(self,native_result,*,actual_operation,evaluated_at,clock_healthy):
        if (type(native_result) is not NativeEvaluationResult or native_result.association.reason!="RB_BOUND"
                or native_result.readiness is None or native_result.readiness.valid
                or native_result.readiness_input_digests is None
                or native_result.readiness.reason!=native_result.reason):
            raise ValidationError("readiness stop requires the actual failed current readiness assessment")
        return super(InstalledNativeReadinessStopResolver,self).evaluate(native_result,actual_operation=actual_operation,
            evaluated_at=evaluated_at,clock_healthy=clock_healthy)
