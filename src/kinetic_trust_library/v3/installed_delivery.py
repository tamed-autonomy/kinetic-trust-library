"""Audit-backed delivery lifecycle around an already valid original hand-back.

Grant-time declaration, durable sealed escrow, actual capacity observations and
recipient receipts are independently authenticated Source facts. No transport,
ledger append, escalation, acknowledgment or permission is performed here.
"""
from dataclasses import dataclass
from kinetic_trust_library.errors import ValidationError
from .hand_back import InstalledHandBackVerifier
from .bootstrap_hand_back import InstalledBootstrapHandBackVerifier
from .delivery_effort import project_delivery_effort
from .trust_proof_json import _parse_jcs_object
from .demand_supplier import _digest
from .demand_operation import canonical_demand_operation_bytes,digest_demand_operation
from .execution_observation import _name,_digest as is_digest
from .root_lifecycle import _time
from .hand_back_hysteresis import _at

_TIMING=("retry_seconds","tolerance_seconds","escalation_seconds","escalation_cap")


def _profile(p):
    if (set(p)!={"id","version","zone","formula","hand_back_profile_digest","capacity_freshness_seconds","classes","ledger_owner","append_protocol"}
            or any(not _name(p[k]) for k in ("id","zone","ledger_owner","append_protocol")) or not _time(p["version"]) or p["version"]==0
            or p["formula"] not in ("anchored-retry-and-escalation-v1","anchored-retry-and-escalation-v2") or not is_digest(p["hand_back_profile_digest"])
            or not _time(p["capacity_freshness_seconds"]) or p["capacity_freshness_seconds"]==0
            or type(p["classes"]) is not dict or set(p["classes"])!={"Logistics","Coordination","Relational"}):
        raise ValidationError("complete selected hand-back delivery policy required")
    for q in p["classes"].values():
        if (type(q) is not dict or set(q)!=set(_TIMING)|{"primary_route","escalation_routes"}
                or any(not _time(q[k]) for k in _TIMING) or q["retry_seconds"]==0 or q["escalation_seconds"]==0 or q["escalation_cap"]>4096
                or not _name(q["primary_route"]) or type(q["escalation_routes"]) is not list or len(q["escalation_routes"])!=q["escalation_cap"]
                or any(not _name(r) for r in q["escalation_routes"])):raise ValidationError("declared class retry/escalation schedule and routes required")
    return p


@dataclass(frozen=True,slots=True)
class AuthenticatedDeliveryContext:
    state_bytes: bytes
    evidence_bytes: bytes


@dataclass(frozen=True,slots=True,init=False)
class HandBackDeliveryAssessment:
    hand_back: object
    projection: object
    effort_current: bool
    late_escrow_record_required: bool
    action_permitted: bool
    hand_back_digest: str
    profile_bytes: bytes
    operation_bytes: bytes
    evaluated_at: int
    expires_at: int
    authenticated_state_bytes: bytes
    source_evidence_bytes: bytes
    capacity_pressure_record_required: bool
    capacity_pressure_hand_back_digest: str | None

    def __init__(self,*args,**kwargs):raise TypeError("delivery assessments require validated original hand-back and actual lifecycle facts")


@dataclass(frozen=True,slots=True)
class InstalledHandBackDeliveryVerifier:
    hand_back_verifier: InstalledHandBackVerifier | InstalledBootstrapHandBackVerifier
    profile_bytes: bytes
    context_source: object

    def __post_init__(self):
        if (type(self.hand_back_verifier) not in (InstalledHandBackVerifier,InstalledBootstrapHandBackVerifier) or type(self.profile_bytes) is not bytes
                or not callable(getattr(self.context_source,"resolve",None))):raise ValidationError("invalid installed delivery verifier")
        p=_profile(_parse_jcs_object(self.profile_bytes));hb=self.hand_back_verifier;hp=_parse_jcs_object(hb.profile_bytes)
        if p["zone"]!=hp["zone"] or p["hand_back_profile_digest"]!=_digest(hp,hb.algorithm):
            raise ValidationError("delivery policy differs from original installed hand-back policy/zone")
        if type(hb) is InstalledBootstrapHandBackVerifier and p["formula"]!="anchored-retry-and-escalation-v2":
            raise ValidationError("bootstrap delivery requires explicit v2 request-origin policy")

    def evaluate(self,hand_back_bytes,*,actual_operation,evaluated_at,clock_healthy,request_id=None,request_anchor=None):
        hb=self.hand_back_verifier;p=_profile(_parse_jcs_object(self.profile_bytes))
        bootstrap=type(hb) is InstalledBootstrapHandBackVerifier
        if bootstrap:
            original=hb.evaluate(hand_back_bytes,request_id=request_id,request_anchor=request_anchor,
                actual_operation=actual_operation,evaluated_at=evaluated_at,clock_healthy=clock_healthy)
        else:
            if request_id is not None or request_anchor is not None:raise ValidationError("registered hand-back delivery cannot select a request fallback")
            original=hb.evaluate(hand_back_bytes,actual_operation=actual_operation,evaluated_at=evaluated_at,clock_healthy=clock_healthy)
        if not original.valid:raise ValidationError("delivery lifecycle requires a separately valid original hand-back")
        op_bytes=canonical_demand_operation_bytes(actual_operation);op=_parse_jcs_object(op_bytes)
        wire=_parse_jcs_object(hand_back_bytes);message=_digest(wire,hb.algorithm);hs=_parse_jcs_object(original.authenticated_state_bytes)
        issued=_at(wire["issued_at"]);lease=hs["lease"];q=p["classes"][hs["consequence_class"]]
        origin_request_id=origin_request_anchor=None
        if bootstrap:
            recipient=hs["fallback"]["recipient"];request=hs["mint_request"]
            origin_at=request["requested_at"];origin_kind="mint-request";template_digest=lease_id=None
            origin_request_id=request["id"];origin_request_anchor=request["anchor"]
        else:
            recipient=hs["template"]["recipient"]
            if lease is None:
                if p["formula"]!="anchored-retry-and-escalation-v2":raise ValidationError("delivery without a granted lease requires explicit v2 origin policy")
                origin_at=hs["template"]["registered_at"];origin_kind="template-registration"
                template_digest=_digest(hs["template"],hb.algorithm);lease_id=None
            else:
                origin_at=lease["issued_at"];origin_kind="lease-grant";template_digest=lease["template_digest"];lease_id=lease["id"]
        source=self.context_source.resolve(deployment_profile_bytes=hb.deployment_profile_bytes,profile_bytes=self.profile_bytes,
            hand_back_bytes=hand_back_bytes,operation_bytes=op_bytes,evaluated_at=evaluated_at)
        if (type(source) is not AuthenticatedDeliveryContext or type(source.state_bytes) is not bytes or len(source.state_bytes)>262144
                or type(source.evidence_bytes) is not bytes or not source.evidence_bytes):raise ValidationError("complete authenticated original delivery lifecycle required")
        s=_parse_jcs_object(source.state_bytes)
        if (set(s)!={"deployment_digest","profile_digest","operation_digest","hand_back_digest","subject","zone","checked_at","expires_at",
                "queue_id","queue_anchor","history_start","ledger_head","declaration","capacity_binding","escrow","attempts","attempt_count",
                "escalations","escalation_count","capacity_records","receipt_bindings","acknowledgment","ledger_owner","append_protocol"}
                or s["deployment_digest"]!=hs["deployment_digest"] or s["profile_digest"]!=_digest(p,hb.algorithm)
                or s["operation_digest"]!=digest_demand_operation(op,algorithm=hb.algorithm) or s["hand_back_digest"]!=message
                or s["subject"]!=op["actor"] or s["zone"]!=p["zone"] or not _name(s["queue_id"]) or not is_digest(s["queue_anchor"])
                or s["ledger_owner"]!=p["ledger_owner"] or s["append_protocol"]!=p["append_protocol"]
                or not _time(s["checked_at"]) or s["checked_at"]!=evaluated_at or not _time(s["expires_at"]) or s["expires_at"]<=evaluated_at
                or _at(s["history_start"])>issued):raise ValidationError("delivery history differs from actual original hand-back/scope/complete coverage")
        head=s["ledger_head"]
        if type(head) is not dict or set(head)!={"anchor","sequence"} or not is_digest(head["anchor"]) or not _time(head["sequence"]):
            raise ValidationError("actual durable delivery ledger head required")
        d=s["declaration"];binding=s["capacity_binding"]
        declaration_fields={"anchor","profile_digest","declared_at","template_digest","lease_id","routes"}
        if p["formula"]=="anchored-retry-and-escalation-v2":declaration_fields|={"origin_kind","request_id","request_anchor"}
        if (type(d) is not dict or set(d)!=declaration_fields
                or not is_digest(d["anchor"]) or d["profile_digest"]!=s["profile_digest"] or not _time(d["declared_at"]) or d["declared_at"]>origin_at
                or d["template_digest"]!=template_digest or d["lease_id"]!=lease_id or type(d["routes"]) is not list or len(d["routes"])>4096
                or type(binding) is not dict or set(binding)!={"id","principal","declared_at","anchor"} or not _name(binding["id"])
                or binding["principal"]!=recipient["principal"] or not is_digest(binding["anchor"]) or not _time(binding["declared_at"])
                or binding["declared_at"]>origin_at):raise ValidationError("actual original origin-time delivery/capacity declaration required")
        if p["formula"]=="anchored-retry-and-escalation-v2" and (d["origin_kind"]!=origin_kind
                or d["request_id"]!=origin_request_id or d["request_anchor"]!=origin_request_anchor):
            raise ValidationError("delivery declaration substitutes original grant/template/request origin")
        routes={}
        for route in d["routes"]:
            if (type(route) is not dict or set(route)!={"ref","endpoint","principal","sealed_to","channel","registered_at","anchor"}
                    or not _name(route["ref"]) or route["ref"] in routes or not _name(route["channel"]) or not is_digest(route["anchor"])
                    or route["endpoint"]!=recipient["endpoint"] or route["principal"]!=recipient["principal"] or route["sealed_to"]!=recipient["key_id"]
                    or not _time(route["registered_at"]) or route["registered_at"]>origin_at):
                raise ValidationError("delivery cannot compose a new recipient, key or undeclared route at stop")
            routes[route["ref"]]=route
        if not {q["primary_route"],*q["escalation_routes"]}<=set(routes) or routes[q["primary_route"]]["channel"]!=recipient["channel"]:
            raise ValidationError("actual primary/escalation routes were not all declared at the original origin")
        attempts=s["attempts"];escalations=s["escalations"]
        if (type(attempts) is not list or type(escalations) is not list or not _time(s["attempt_count"]) or s["attempt_count"]!=len(attempts)
                or not _time(s["escalation_count"]) or s["escalation_count"]!=len(escalations)):
            raise ValidationError("complete actual delivery counters and attempt/escalation history required")
        escrow=s["escrow"];late_escrow=False
        if escrow is not None:
            if (type(escrow) is not dict or set(escrow)!={"anchor","stored_at","hand_back_digest","ciphertext_digest","sealed_to"}
                    or not is_digest(escrow["anchor"]) or not issued<=_at(escrow["stored_at"])<=evaluated_at
                    or escrow["hand_back_digest"]!=message or escrow["ciphertext_digest"]!=wire["context"]["ciphertext_digest"]
                    or escrow["sealed_to"]!=recipient["key_id"]):raise ValidationError("actual durable escrow must retain the original sealed hand-back/context")
            late_escrow=_at(escrow["stored_at"])>issued+q["tolerance_seconds"]
        ack=s["acknowledgment"]
        if ack is not None and (type(ack) is not dict or set(ack)!={"anchor","hand_back_digest","principal","acknowledged_at"}
                or not is_digest(ack["anchor"]) or ack["hand_back_digest"]!=message or ack["principal"]!=recipient["principal"]):
            raise ValidationError("actual original recipient acknowledgment required")
        projection=project_delivery_effort({k:q[k] for k in _TIMING},attempts,escalations,issued_at=issued,evaluated_at=evaluated_at,
            ledger_head_sequence=head["sequence"],escrow_present=escrow is not None,capacity_freshness_seconds=p["capacity_freshness_seconds"],
            ack_sla_seconds=recipient["ack_sla_seconds"],acknowledged_at=None if ack is None else ack["acknowledged_at"],
            hand_back_digest=message,capacity_binding=binding["id"])
        late_escrow=late_escrow and projection.escrow_needed
        original_delivery=hs["delivery"]
        if (s["attempt_count"]<original_delivery["attempts"] or original.delivery_state=="delivered" and (
                projection.delivery_state!="delivered" or not any(a["receipt"] is not None
                    and _at(a["receipt"]["accepted_at"])==original_delivery["accepted_at"] for a in attempts))):
            raise ValidationError("lifecycle history omits delivery facts already established by the original hand-back")
        records=s["capacity_records"];receipts=s["receipt_bindings"]
        if (type(records) is not dict or set(records)!={a["capacity_anchor"] for a in attempts} or type(receipts) is not dict
                or set(receipts)!={a["receipt"]["anchor"] for a in attempts if a["receipt"] is not None}):
            raise ValidationError("complete actual capacity snapshot/recipient receipt bindings required")
        for a in attempts:
            if a["route_ref"] not in routes:raise ValidationError("attempt used an undeclared original-recipient route")
            expected=dict(binding=binding["id"],principal=recipient["principal"],capacity=a["capacity"],observed_at=a["capacity_observed_at"])
            if records[a["capacity_anchor"]]!=expected:raise ValidationError("attempt substituted actual recipient capacity evidence")
            if a["receipt"] is not None:
                expected=dict(hand_back_digest=message,attempt_anchor=a["anchor"],endpoint=recipient["endpoint"],principal=recipient["principal"],
                    sealed_to=recipient["key_id"],ciphertext_digest=wire["context"]["ciphertext_digest"])
                if receipts[a["receipt"]["anchor"]]!=expected:raise ValidationError("receipt differs from actual original sealed message/recipient/attempt")
        if any(e["route_ref"]!=q["escalation_routes"][e["level"]-1] for e in escalations):raise ValidationError("escalation used a route outside its predeclared level")
        expiry=min(original.expires_at,s["expires_at"])
        if projection.next_change_at is not None:expiry=min(expiry,projection.next_change_at)
        result=object.__new__(HandBackDeliveryAssessment)
        for key,value in dict(hand_back=original,projection=projection,effort_current=projection.effort_current and not late_escrow,
                late_escrow_record_required=late_escrow,action_permitted=False,hand_back_digest=message,profile_bytes=self.profile_bytes,
                operation_bytes=op_bytes,evaluated_at=evaluated_at,expires_at=expiry,authenticated_state_bytes=source.state_bytes,
                source_evidence_bytes=source.evidence_bytes,capacity_pressure_record_required=bool(projection.capacity_exhaustion_anchors),
                capacity_pressure_hand_back_digest=message if projection.capacity_exhaustion_anchors else None).items():object.__setattr__(result,key,value)
        return result


__all__=("AuthenticatedDeliveryContext","HandBackDeliveryAssessment","InstalledHandBackDeliveryVerifier")
