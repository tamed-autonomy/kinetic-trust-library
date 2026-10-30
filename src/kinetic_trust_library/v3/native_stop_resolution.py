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


def _prepare_registered_stop(*,cv,initial,native_result,template,profile_bytes,cause,op_bytes,preparation_source,evaluated_at,
        expected_reason="exceeded_permit_condition",expected_origin="system",sovereign_authority=None):
    """Validate a genuine Source-prepared stop through the current native graph."""
    hb=cv.template_verifier.hand_back_verifier
    state=_parse_jcs_object(initial.authenticated_state_bytes)
    actual_operation=_parse_jcs_object(op_bytes)
    prepared=preparation_source.prepare(profile_bytes=profile_bytes,cause_bytes=cause,
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
            or wire["reason"]!=expected_reason or _instant(wire["issued_at"])!=evaluated_at or hs["stop_origin"]!=expected_origin
            or expected_origin=="sovereign" and hs.get("sovereign_authority")!=sovereign_authority):
        raise ValidationError("native stop changed its actual cause, admission, grant or registered recourse branch")
    return prepared,current


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

    def _reason(self,native_result):return "exceeded_permit_condition"

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
        reason=self._reason(native_result)
        cause=rfc8785.dumps(dict(profile_digest=_digest(_parse_jcs_object(self.profile_bytes),hb.algorithm),
            operation_digest=_digest(_parse_jcs_object(op_bytes),hb.algorithm),native_reason=native_result.reason,
            evaluated_at=evaluated_at,reason=reason,template_digest=template.template_digest,
            proof_digest=digest_complete_proof(native_result.association.compact_proof,algorithm=hb.algorithm),
            geometry_digest=None if native_result.canonical_geometry_bytes is None else _digest(_parse_jcs_object(native_result.canonical_geometry_bytes),hb.algorithm),
            clearance_state_digest=_digest(state,hb.algorithm),gate_profile_digests=[_digest(_parse_jcs_object(p.profile_bytes),hb.algorithm) for p in policies],
            readiness_profile_digest=_digest(_parse_jcs_object(cv.native_verifier.readiness_verifier.readiness_verifier.readiness_profile_bytes),hb.algorithm),
            readiness_input_digests=native_result.readiness_input_digests,
            readiness_context_digests=(None if native_result.readiness is None or native_result.readiness.readiness is None
                else native_result.readiness.readiness.observed_context_digests)))
        prepared,current=_prepare_registered_stop(cv=cv,initial=initial,native_result=native_result,template=template,
            profile_bytes=self.profile_bytes,cause=cause,op_bytes=op_bytes,preparation_source=self.preparation_source,evaluated_at=evaluated_at,
            expected_reason=reason)
        result=object.__new__(NativeStopResolution)
        for k,v in dict(clearance=current,template=template,cause_bytes=cause,preparation=prepared,evaluated_at=evaluated_at,
                expires_at=min(current.expires_at,template.expires_at),action_permitted=False).items():object.__setattr__(result,k,v)
        return result


@dataclass(frozen=True,slots=True)
class InstalledNativeAdjudicationStopResolver(_InstalledNativeStopResolver):
    _FORMULA="native-adjudication-return-path-v1"
    _FAILURES=frozenset(("ADJ_GATE_UNSATISFIED",))


@dataclass(frozen=True,slots=True)
class InstalledNativeCapacityStopResolver(_InstalledNativeStopResolver):
    _FORMULA="native-capacity-return-path-v1"
    _FAILURES=frozenset(("NATIVE_EVALUATION_RESTRICTED",))

    def _reason(self,native_result):
        from fractions import Fraction
        c=_parse_jcs_object(native_result.canonical_geometry_bytes)["capacity"]
        return "exceeded_zeroth_law" if c["capacityKnown"] and Fraction(str(c["A"]))>Fraction(str(c["E"])) else "exceeded_permit_condition"

    def evaluate(self,native_result,*,actual_operation,evaluated_at,clock_healthy):
        from fractions import Fraction
        if (type(native_result) is not NativeEvaluationResult or native_result.canonical_geometry_bytes is None
                or native_result.association.reason not in ("RB_BOUND","RB_CURRENT")):
            raise ValidationError("capacity stop requires the actual authenticated native geometry restriction")
        body=_parse_jcs_object(native_result.canonical_geometry_bytes);c=body.get("capacity")
        if (type(c) is not dict or body["gates"]["soul"]!="passed"
                or not (Fraction(str(c["E"]))==0 or Fraction(str(c["A"]))>=Fraction(str(c["E"])))):
            raise ValidationError("capacity stop cannot attribute another restriction to measured capacity")
        return super(InstalledNativeCapacityStopResolver,self).evaluate(native_result,actual_operation=actual_operation,
            evaluated_at=evaluated_at,clock_healthy=clock_healthy)


@dataclass(frozen=True,slots=True)
class InstalledNativeReadinessStopResolver(_InstalledNativeStopResolver):
    _FORMULA="native-readiness-return-path-v1"
    _FAILURES=frozenset(("READINESS_UNAVAILABLE","READINESS_INVALID","READINESS_PROOF_INVALID","READINESS_DECISION_INVALID"))

    def evaluate(self,native_result,*,actual_operation,evaluated_at,clock_healthy):
        if (type(native_result) is not NativeEvaluationResult or native_result.association.reason not in ("RB_BOUND","RB_CURRENT")
                or native_result.association.reason=="RB_CURRENT" and (native_result.association.checked_at!=evaluated_at
                    or not _time(native_result.association.expires_at) or evaluated_at>=native_result.association.expires_at)
                or native_result.readiness is None or native_result.readiness.valid
                or native_result.readiness_input_digests is None
                or native_result.readiness.reason!=native_result.reason):
            raise ValidationError("readiness stop requires the actual failed current readiness assessment")
        return super(InstalledNativeReadinessStopResolver,self).evaluate(native_result,actual_operation=actual_operation,
            evaluated_at=evaluated_at,clock_healthy=clock_healthy)


@dataclass(frozen=True,slots=True)
class InstalledNativeSoulStopResolver:
    clearance_verifier: InstalledClearanceVerifier
    profile_bytes: bytes
    preparation_source: object

    def __post_init__(self):
        if (type(self.clearance_verifier) is not InstalledClearanceVerifier or type(self.profile_bytes) is not bytes
                or not callable(getattr(self.preparation_source,"prepare",None)) or self.clearance_verifier.management_verifier is None):
            raise ValidationError("Soul stop requires actual installed clearance, management and preparation source")
        from kinetic_trust_library._uri import validate_absolute_uri
        cv=self.clearance_verifier;hb=cv.template_verifier.hand_back_verifier;p=_parse_jcs_object(self.profile_bytes)
        cp=_parse_jcs_object(cv.profile_bytes)
        if (set(p)!={"id","version","zone","formula","clearance_profile_digest","soul_authority_bindings"}
                or not _name(p["id"]) or not _time(p["version"]) or p["version"]==0 or p["zone"]!=cp["zone"]
                or p["formula"]!="native-soul-return-path-v1" or p["clearance_profile_digest"]!=_digest(cp,hb.algorithm)
                or _parse_jcs_object(hb.profile_bytes)["formula"]!="registered-template-and-sealed-context-v2"
                or type(p["soul_authority_bindings"]) is not dict or not p["soul_authority_bindings"]
                or any(not _name(v) for v in p["soul_authority_bindings"].values())):
            raise ValidationError("Soul stop requires exact policy and named sovereign authority bindings")
        for authority in p["soul_authority_bindings"]:validate_absolute_uri(authority,name="installed Soul authority")

    def evaluate(self,native_result,*,actual_operation,evaluated_at,clock_healthy):
        cv=self.clearance_verifier;hb=cv.template_verifier.hand_back_verifier
        if (type(native_result) is not NativeEvaluationResult or native_result.verifier is not cv.native_verifier
                or native_result.reason!="RB_GATE" or native_result.association.proof_reason!="TP_VETO"
                or not _time(evaluated_at) or native_result.checked_at!=evaluated_at or clock_healthy is not True):
            raise ValidationError("Soul stop requires an actual current authenticated native veto")
        verification=native_result.association.proof_verification
        if verification is None or verification.reason!="TP_VETO" or verification.stage!=8 or verification.authenticated_payload_bytes is None:
            raise ValidationError("Soul stop cannot use an unauthenticated candidate or generic gate failure")
        claims=_parse_jcs_object(verification.authenticated_payload_bytes);soul=claims["ktp"]["soul"]
        p=_parse_jcs_object(self.profile_bytes)
        authority=p["soul_authority_bindings"].get(soul.get("authority"))
        if claims["ktp"]["gate_state"]!="veto" or soul.get("soul")!=1 or authority is None:
            raise ValidationError("Soul veto authority lacks its installed named sovereign binding")
        op_bytes=canonical_demand_operation_bytes(actual_operation)
        request=_parse_jcs_object(native_result.association.canonical_request_bytes)
        actual={k:v for k,v in request.items() if k not in ("version","demand","classification_profile")}
        if canonical_demand_operation_bytes(actual)!=op_bytes:raise ValidationError("Soul failure belongs to another actual operation")
        initial=cv.evaluate(native_result,actual_operation=actual_operation,evaluated_at=evaluated_at,clock_healthy=True)
        if (initial.reason!="CLEARANCE_NATIVE_NOT_CLEAR" or initial.management is None or not initial.management.valid
                or initial.management.management.regime!="managed" or initial.lease is None or not initial.lease.active):
            raise ValidationError("new Soul stop requires the actual current managed relation and active original grant")
        state=_parse_jcs_object(initial.authenticated_state_bytes)
        template=cv.template_verifier.evaluate(template_digest=initial.lease.template_digest,actual_operation=actual_operation,
            evaluated_at=evaluated_at,clock_healthy=True)
        if (template.subject!=state["subject"] or template.principal!=state["principal"]
                or template.consequence_class!=initial.lease.consequence_class or template.registered_at>initial.lease.issued_at):
            raise ValidationError("Soul return path differs from the actual original grant")
        from .hand_back_template import select_recourse
        route=select_recourse(_parse_jcs_object(template.template_bytes),_parse_jcs_object(hb.profile_bytes),"sovereign",authority)
        if route["kind"]!="closed_by_authority":raise ValidationError("Soul refusal cannot be changed into a system contest")
        import rfc8785
        cause=rfc8785.dumps(dict(profile_digest=_digest(p,hb.algorithm),operation_digest=_digest(_parse_jcs_object(op_bytes),hb.algorithm),
            evaluated_at=evaluated_at,reason="exceeded_soul",native_reason=native_result.reason,soul_claim=soul,
            soul_authority=soul["authority"],registered_sovereign_authority=authority,
            registered_recourse={k:route[k] for k in ("kind","ref")},template_digest=template.template_digest,
            proof_digest=digest_complete_proof(native_result.association.compact_proof,algorithm=hb.algorithm),clearance_state_digest=_digest(state,hb.algorithm)))
        prepared,current=_prepare_registered_stop(cv=cv,initial=initial,native_result=native_result,template=template,
            profile_bytes=self.profile_bytes,cause=cause,op_bytes=op_bytes,preparation_source=self.preparation_source,evaluated_at=evaluated_at,
            expected_reason="exceeded_soul",expected_origin="sovereign",sovereign_authority=authority)
        result=object.__new__(NativeStopResolution)
        for k,v in dict(clearance=current,template=template,cause_bytes=cause,preparation=prepared,evaluated_at=evaluated_at,
                expires_at=min(current.expires_at,template.expires_at),action_permitted=False).items():object.__setattr__(result,k,v)
        return result
