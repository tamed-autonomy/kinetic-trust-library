"""Selected relationship-only reconciliation gate over persistent Source facts.

This private integer-second reference policy checks all relational adverse stops,
independently of bounded pricing history or penalty expungement. Source must
authenticate a complete inventory, durable barrier/epoch continuity, actual grant
position, current anchored records and live nonce state. No token is minted or
consumed, no human decision is inferred, and eligibility never permits action.
"""
from dataclasses import dataclass
from kinetic_trust_library.errors import ValidationError
from .installed_hysteresis import InstalledHandBackHysteresisVerifier
from .trust_proof_json import _parse_jcs_object
from .demand_supplier import _digest
from .demand_operation import canonical_demand_operation_bytes,digest_demand_operation
from .execution_observation import _name,_digest as is_digest
from .root_lifecycle import _time
from .reconciliation_record import ReconciliationRecordFacts,project_reconciliation_record


def _profile(p):
    if (set(p)!={"id","version","zone","formula","hysteresis_profile_digest","repair_ref","decline_clock_seconds"}
            or not _name(p["id"]) or not _name(p["zone"]) or not _time(p["version"]) or p["version"]==0
            or p["formula"]!="adverse-stop-relationship-record-v1" or not is_digest(p["hysteresis_profile_digest"])
            or not _name(p["repair_ref"]) or not _time(p["decline_clock_seconds"]) or p["decline_clock_seconds"]==0):
        raise ValidationError("invalid selected relational reissue policy")
    return p


@dataclass(frozen=True,slots=True)
class AuthenticatedRelationalReissueContext:
    state_bytes: bytes
    evidence_bytes: bytes


@dataclass(frozen=True,slots=True,init=False)
class RelationalReissueAssessment:
    eligible: bool
    reason: str
    action_permitted: bool
    lease_digest: str
    lease_id: str
    issued_at: int
    grant_sequence: int
    current_grant_epoch: int
    ledger_head_anchor: str
    ledger_head_sequence: int
    reconciliation_anchors: tuple
    latest_barrier_anchor: str | None
    repair_ref: str
    profile_bytes: bytes
    operation_bytes: bytes
    evaluated_at: int
    expires_at: int
    authenticated_state_bytes: bytes
    source_evidence_bytes: bytes

    def __init__(self,*args,**kwargs):raise TypeError("relational reissue requires installed authenticated persistent facts")


@dataclass(frozen=True,slots=True)
class InstalledRelationalReissueVerifier:
    hysteresis_verifier: InstalledHandBackHysteresisVerifier
    profile_bytes: bytes
    context_source: object

    def __post_init__(self):
        if (type(self.hysteresis_verifier) is not InstalledHandBackHysteresisVerifier or type(self.profile_bytes) is not bytes
                or not callable(getattr(self.context_source,"resolve",None))):raise ValidationError("invalid installed relational reissue verifier")
        hv=self.hysteresis_verifier;p=_profile(_parse_jcs_object(self.profile_bytes));hp=_parse_jcs_object(hv.profile_bytes)
        if p["hysteresis_profile_digest"]!=_digest(hp,hv.algorithm) or p["zone"]!=hp["zone"]:
            raise ValidationError("relational reissue differs from installed ledger policy/zone")

    def evaluate(self,lease_bytes,*,actual_operation,evaluated_at,clock_healthy):
        if type(lease_bytes) is not bytes or len(lease_bytes)>262144 or not _time(evaluated_at) or clock_healthy is not True:
            raise ValidationError("relational reissue requires immutable grant and healthy current time")
        hv=self.hysteresis_verifier;p=_profile(_parse_jcs_object(self.profile_bytes));hp=_parse_jcs_object(hv.profile_bytes)
        lease=_parse_jcs_object(lease_bytes);ld=_digest(lease,hv.algorithm)
        op_bytes=canonical_demand_operation_bytes(actual_operation);op=_parse_jcs_object(op_bytes)
        deployment=_digest(_parse_jcs_object(hv.deployment_profile_bytes),hv.algorithm)
        invocation=digest_demand_operation(op,algorithm=hv.algorithm)
        source=self.context_source.resolve(deployment_profile_bytes=hv.deployment_profile_bytes,profile_bytes=self.profile_bytes,
            lease_bytes=lease_bytes,operation_bytes=op_bytes,evaluated_at=evaluated_at)
        if (type(source) is not AuthenticatedRelationalReissueContext or type(source.state_bytes) is not bytes
                or len(source.state_bytes)>262144 or type(source.evidence_bytes) is not bytes or not source.evidence_bytes):
            raise ValidationError("relational Source must authenticate complete persistent barriers, records and live nonce")
        s=_parse_jcs_object(source.state_bytes)
        if (set(s)!={"deployment_digest","profile_digest","operation_digest","subject","zone","checked_at","expires_at",
                "ledger_owner","append_protocol","ledger_head","current_grant_epoch","latest_barrier","stops","nonce_state","grant","registered_route"}
                or s["deployment_digest"]!=deployment or s["profile_digest"]!=_digest(p,hv.algorithm)
                or s["operation_digest"]!=invocation or s["subject"]!=op["actor"] or s["zone"]!=p["zone"]
                or s["ledger_owner"]!=hp["ledger_owner"] or s["append_protocol"]!=hp["append_protocol"]
                or not _time(s["checked_at"]) or s["checked_at"]!=evaluated_at or not _time(s["expires_at"])
                or s["expires_at"]<=evaluated_at or not _time(s["current_grant_epoch"])):
            raise ValidationError("relational Source scope/profile/current time differs")
        head=s["ledger_head"];g=s["grant"];ns=s["nonce_state"]
        if (type(head) is not dict or set(head)!={"anchor","sequence"} or not is_digest(head["anchor"]) or not _time(head["sequence"])
                or type(g) is not dict or set(g)!={"lease_digest","id","subject","operation_digest","consequence_class","issued_at","grant_epoch","sequence","record_anchor"}
                or g["lease_digest"]!=ld or not is_digest(g["record_anchor"]) or not _name(g["id"])
                or g["subject"]!=op["actor"] or g["operation_digest"]!=invocation or g["consequence_class"]!="Relational"
                or any(lease.get(k)!=g[k] for k in ("id","subject","operation_digest","consequence_class","issued_at","grant_epoch"))
                or not _time(g["issued_at"]) or g["issued_at"]>evaluated_at or not _time(g["grant_epoch"])
                or not _time(g["sequence"]) or not 0<g["sequence"]<=head["sequence"]
                or lease.get("kind")!="single-use" or lease.get("expires_at") is not None or not _name(lease.get("nonce"))
                or type(ns) is not dict or set(ns)!={"nonce","consumed","revoked"} or ns["nonce"]!=lease["nonce"]
                or any(type(ns[k]) is not bool for k in ("consumed","revoked"))):
            raise ValidationError("relational reissue requires actual single-use grant/audit position/live nonce")
        stops=s["stops"];barrier=s["latest_barrier"]
        if type(stops) is not list or len(stops)>4096:raise ValidationError("complete relational stop inventory required")
        route=s["registered_route"]
        if (type(route) is not dict or set(route)!={"ref","registered_at","withdrawn_at","decline_clock_seconds","clock_origin","record_anchor"}
                or not _name(route["ref"]) or not _time(route["registered_at"]) or route["registered_at"]>evaluated_at
                or not _time(route["decline_clock_seconds"]) or route["decline_clock_seconds"]==0
                or route["clock_origin"]!="stop" or not is_digest(route["record_anchor"])
                or route["withdrawn_at"] is not None and (not _time(route["withdrawn_at"]) or not route["registered_at"]<=route["withdrawn_at"]<=evaluated_at)):
            raise ValidationError("actual registered relational route and clock required")
        unavailable=(route["ref"]!=p["repair_ref"] or route["decline_clock_seconds"]!=p["decline_clock_seconds"]
                     or route["withdrawn_at"] is not None or route["registered_at"]>g["issued_at"])
        positions={g["sequence"]:g["record_anchor"]};anchors={g["record_anchor"]};previous_epoch=-1;previous_time=-1;previous_sequence=0
        missing=False;early=False;record_anchors=[]
        for stop in stops:
            if (type(stop) is not dict or set(stop)!={"anchor","sequence","occurred_at","required_grant_epoch","accountable_terminator","required_parties","record"}
                    or not is_digest(stop["anchor"]) or stop["anchor"] in anchors or not _time(stop["sequence"])
                    or not previous_sequence<stop["sequence"]<=head["sequence"] or stop["sequence"] in positions
                    or not _time(stop["occurred_at"]) or not previous_time<=stop["occurred_at"]<=evaluated_at
                    or not _time(stop["required_grant_epoch"]) or not previous_epoch<stop["required_grant_epoch"]<=s["current_grant_epoch"]
                    or stop["required_grant_epoch"]==0 or not _name(stop["accountable_terminator"])
                    or type(stop["required_parties"]) is not list or not stop["required_parties"]
                    or any(not _name(x) for x in stop["required_parties"]) or len(set(stop["required_parties"]))!=len(stop["required_parties"])
                    or stop["accountable_terminator"] not in stop["required_parties"]):
                raise ValidationError("invalid complete ordered relational stop/barrier inventory")
            anchors.add(stop["anchor"]);positions[stop["sequence"]]=stop["anchor"]
            unavailable=unavailable or route["registered_at"]>stop["occurred_at"]
            previous_epoch=stop["required_grant_epoch"];previous_time=stop["occurred_at"];previous_sequence=stop["sequence"]
            early=early or g["sequence"]<=stop["sequence"] or g["issued_at"]<stop["occurred_at"]
            r=stop["record"]
            if r is None:missing=True;continue
            if (type(r) is not dict or set(r)!={"anchor","sequence","facts","repair_ref","disposition","route_started_at","route_completed_at"}
                    or not is_digest(r["anchor"]) or r["anchor"] in anchors or not _time(r["sequence"])
                    or not stop["sequence"]<r["sequence"]<=head["sequence"] or r["sequence"] in positions
                    or r["repair_ref"]!=p["repair_ref"] or r["disposition"] not in ("reconciled","open-to-declined")
                    or type(r["facts"]) is not dict or set(r["facts"])!=set(ReconciliationRecordFacts.__dataclass_fields__)):
                raise ValidationError("invalid anchored relational reconciliation record")
            positions[r["sequence"]]=r["anchor"];anchors.add(r["anchor"])
            f=dict(r["facts"])
            for key in ("required_parties","record_parties","independent_of","declined_parties","open_to"):
                if type(f[key]) is not list:raise ValidationError("relational record party arrays required")
                f[key]=tuple(f[key])
            record=project_reconciliation_record(ReconciliationRecordFacts(**f))
            if (f["cause_anchor"]!=stop["anchor"] or f["cause_at"]!=stop["occurred_at"]
                    or f["accountable_terminator"]!=stop["accountable_terminator"]
                    or set(f["required_parties"])!=set(stop["required_parties"])):
                raise ValidationError("reconciliation record substitutes the actual stop or accountability parties")
            if f["anchored_at"]>evaluated_at:raise ValidationError("relational record cannot be anchored in the future")
            declined=bool(f["declined_parties"])
            if declined:
                route_ok=(r["disposition"]=="open-to-declined" and _time(r["route_started_at"]) and _time(r["route_completed_at"])
                    and r["route_started_at"]==stop["occurred_at"]
                    and stop["occurred_at"]+p["decline_clock_seconds"]<=r["route_completed_at"]<=f["anchored_at"])
            else:
                route_ok=r["disposition"]=="reconciled" and r["route_started_at"] is None and r["route_completed_at"] is None
            missing=missing or not record.record_valid or not route_ok
            early=early or g["sequence"]<=r["sequence"] or g["issued_at"]<f["anchored_at"]
            record_anchors.append(r["anchor"])
        expected=None if not stops else {k:stops[-1][k] for k in ("anchor","sequence","occurred_at","required_grant_epoch")}
        if (barrier!=expected or barrier is not None and (type(barrier) is not dict or set(barrier)!=set(expected)
                or not is_digest(barrier["anchor"]) or any(not _time(barrier[k]) for k in ("sequence","occurred_at","required_grant_epoch")))):
            raise ValidationError("persistent latest relational barrier is missing or contradicts complete stops")
        reason=("RELATIONAL_NONCE_REVOKED" if ns["revoked"] else "RELATIONAL_GRANT_EPOCH" if g["grant_epoch"]!=s["current_grant_epoch"] else
                "RELATIONAL_NONCE_CONSUMED" if ns["consumed"] else "RELATIONAL_REPAIR_ROUTE_UNAVAILABLE" if unavailable else
                "RELATIONAL_GRANT_PRECEDES_REPAIR" if early else
                "RELATIONAL_RECONCILIATION_REQUIRED" if missing else "RELATIONAL_REISSUE_ELIGIBLE")
        result=object.__new__(RelationalReissueAssessment)
        for key,value in dict(eligible=reason=="RELATIONAL_REISSUE_ELIGIBLE",reason=reason,action_permitted=False,
                lease_digest=ld,lease_id=g["id"],issued_at=g["issued_at"],grant_sequence=g["sequence"],current_grant_epoch=s["current_grant_epoch"],
                ledger_head_anchor=head["anchor"],ledger_head_sequence=head["sequence"],reconciliation_anchors=tuple(record_anchors),
                latest_barrier_anchor=None if barrier is None else barrier["anchor"],repair_ref=p["repair_ref"],profile_bytes=self.profile_bytes,
                operation_bytes=op_bytes,evaluated_at=evaluated_at,expires_at=s["expires_at"],authenticated_state_bytes=source.state_bytes,
                source_evidence_bytes=source.evidence_bytes).items():object.__setattr__(result,key,value)
        return result


__all__=("AuthenticatedRelationalReissueContext","RelationalReissueAssessment","InstalledRelationalReissueVerifier")
