"""Installed grant reissue checks against historical governing ledger policies.

Source authenticates actual full signed grant/audit position, current protected
subject/class grant epoch, complete history and each stop's governing policy.
Library checks bounds; it never mints authority, repairs an early grant merely
because time passed, writes a ledger, or consumes a nonce.
"""
from dataclasses import dataclass
from kinetic_trust_library.errors import ValidationError
from .installed_hysteresis import InstalledHandBackHysteresisVerifier
from .hand_back_hysteresis import profile_terms as hysteresis_profile,project_hysteresis,_at
from .trust_proof_json import _parse_jcs_object
from .demand_supplier import _digest
from .demand_operation import canonical_demand_operation_bytes,digest_demand_operation
from .root_lifecycle import _time
from .execution_observation import _name,_digest as is_digest
from .relational_reissue import InstalledRelationalReissueVerifier


def _profile(p):
    keys={"id","version","zone","formula","hysteresis_profile_digest","relational_reissue"}
    selected=p.get("relational_reissue")=="relationship-record-v1"
    if (type(p) is not dict or set(p)!=(keys|({"relational_profile_digest"} if selected else set()))
            or not _name(p["id"]) or not _name(p["zone"]) or not _time(p["version"]) or p["version"]==0
            or p["formula"]!="historical-capped-bound-and-grant-epoch-v1" or not is_digest(p["hysteresis_profile_digest"])
            or p["relational_reissue"] not in ("unsupported","relationship-record-v1")
            or selected and not is_digest(p["relational_profile_digest"])):
        raise ValidationError("invalid selected reissue profile or unsupported relational claim")
    return p


@dataclass(frozen=True,slots=True)
class AuthenticatedReissueContext:
    state_bytes: bytes
    evidence_bytes: bytes


@dataclass(frozen=True,slots=True,init=False)
class HandBackReissueAssessment:
    eligible: bool
    reason: str
    lease_id: str
    lease_digest: str
    issued_at: int
    current_grant_epoch: int
    required_reissue_not_before: object
    bounds: tuple
    cap_satisfied: tuple
    ignored_expunged: tuple
    expungement_required: tuple
    revoker_accountability_required: tuple
    profile_bytes: bytes
    operation_bytes: bytes
    evaluated_at: int
    expires_at: int
    authenticated_state_bytes: bytes
    source_evidence_bytes: bytes
    relational: object

    def __init__(self,*args,**kwargs):raise TypeError("reissue assessments require installed complete current registry/ledger facts")


@dataclass(frozen=True,slots=True)
class InstalledHandBackReissueVerifier:
    hysteresis_verifier: InstalledHandBackHysteresisVerifier
    profile_bytes: bytes
    context_source: object
    relational_verifier: InstalledRelationalReissueVerifier | None = None

    def __post_init__(self):
        if (type(self.hysteresis_verifier) is not InstalledHandBackHysteresisVerifier or type(self.profile_bytes) is not bytes
                or not callable(getattr(self.context_source,"resolve",None))):raise ValidationError("invalid installed reissue verifier")
        hv=self.hysteresis_verifier;p=_profile(_parse_jcs_object(self.profile_bytes));hp=_parse_jcs_object(hv.profile_bytes)
        if p["hysteresis_profile_digest"]!=_digest(hp,hv.algorithm) or p["zone"]!=hp["zone"]:
            raise ValidationError("reissue policy differs from installed ledger policy/zone")
        selected=p["relational_reissue"]=="relationship-record-v1"
        rv=self.relational_verifier
        if (selected!=(rv is not None) or rv is not None and (type(rv) is not InstalledRelationalReissueVerifier
                or rv.hysteresis_verifier is not hv or p["relational_profile_digest"]!=_digest(_parse_jcs_object(rv.profile_bytes),hv.algorithm))):
            raise ValidationError("relational reissue selection requires the exact installed shared ledger policy")

    def evaluate(self,lease_bytes,*,actual_operation,evaluated_at,clock_healthy):
        if (type(lease_bytes) is not bytes or len(lease_bytes)>262144 or not _time(evaluated_at) or clock_healthy is not True):
            raise ValidationError("reissue requires complete immutable grant and healthy current time")
        hv=self.hysteresis_verifier;p=_profile(_parse_jcs_object(self.profile_bytes));hp=hysteresis_profile(_parse_jcs_object(hv.profile_bytes))
        lease=_parse_jcs_object(lease_bytes);ld=_digest(lease,hv.algorithm)
        op_bytes=canonical_demand_operation_bytes(actual_operation);op=_parse_jcs_object(op_bytes)
        deployment=_digest(_parse_jcs_object(hv.deployment_profile_bytes),hv.algorithm);invocation=digest_demand_operation(op,algorithm=hv.algorithm)
        source=self.context_source.resolve(deployment_profile_bytes=hv.deployment_profile_bytes,profile_bytes=self.profile_bytes,
            hysteresis_profile_bytes=hv.profile_bytes,lease_bytes=lease_bytes,operation_bytes=op_bytes,evaluated_at=evaluated_at)
        if (type(source) is not AuthenticatedReissueContext or type(source.state_bytes) is not bytes or len(source.state_bytes)>262144
                or type(source.evidence_bytes) is not bytes or not source.evidence_bytes):
            raise ValidationError("reissue Source must authenticate actual grant/epoch and complete historical policy inventory")
        s=_parse_jcs_object(source.state_bytes)
        if (set(s)!={"deployment_digest","profile_digest","operation_digest","subject","zone","checked_at","expires_at","ledger_owner","append_protocol",
                "retained_since","ledger_head","current_grant_epoch","history","pricing_profiles","profile_registry","grant"}
                or s["deployment_digest"]!=deployment or s["profile_digest"]!=_digest(p,hv.algorithm) or s["operation_digest"]!=invocation
                or s["subject"]!=op["actor"] or s["zone"]!=p["zone"] or s["ledger_owner"]!=hp["ledger_owner"] or s["append_protocol"]!=hp["append_protocol"]
                or not _time(s["checked_at"]) or s["checked_at"]!=evaluated_at or not _time(s["expires_at"]) or s["expires_at"]<=evaluated_at
                or not _time(s["current_grant_epoch"])):raise ValidationError("reissue scope differs from actual current registry/profile/time")
        head=s["ledger_head"];g=s["grant"]
        if (type(head) is not dict or set(head)!={"anchor","sequence"} or not is_digest(head["anchor"]) or not _time(head["sequence"])
                or type(g) is not dict or set(g)!={"lease_digest","id","subject","operation_digest","consequence_class","issued_at","grant_epoch","sequence","record_anchor"}
                or g["lease_digest"]!=ld or g["subject"]!=op["actor"] or g["operation_digest"]!=invocation or not is_digest(g["record_anchor"])
                or not _name(g["id"]) or type(g["consequence_class"]) is not str or g["consequence_class"] not in hp["classes"]
                or any(lease.get(k)!=g[k] for k in ("id","subject","operation_digest","consequence_class","issued_at","grant_epoch"))
                or not _time(g["issued_at"]) or g["issued_at"]>evaluated_at or not _time(g["grant_epoch"])
                or not _time(g["sequence"]) or not 0<g["sequence"]<=head["sequence"]):raise ValidationError("reissue requires the actual full grant and audit position")
        retained=_at(s["retained_since"])
        if retained>max(0,evaluated_at-hp["retention_seconds"]):raise ValidationError("incomplete retained audit history")
        if type(s["history"]) is not list or any(type(e) is not dict or e.get("sequence")==g["sequence"] for e in s["history"]):
            raise ValidationError("grant audit position cannot be reused by a stop")
        # The shared quote validates all timelines and supplies current ledger
        # correction/accountability diagnostics. This hypothetical price is not
        # emitted as an adverse event and imposes no additional delay.
        inventory=project_hysteresis(hp,s["history"],subject=op["actor"],consequence_class=g["consequence_class"],
            issued_at=g["issued_at"],current_sequence=g["sequence"],as_of=evaluated_at,ledger_head_sequence=head["sequence"])
        registry=s["profile_registry"];mapping=s["pricing_profiles"]
        if type(registry) is not dict or len(registry)>4096 or type(mapping) is not dict:
            raise ValidationError("complete historical governing policy registry required")
        for digest,body in registry.items():
            if digest!=_digest(body,hv.algorithm) or hysteresis_profile(body)["zone"]!=p["zone"]:
                raise ValidationError("historical governing profile digest/zone differs")
        if registry.get(p["hysteresis_profile_digest"])!=hp:
            raise ValidationError("current declared policy omitted or replaced")
        adverse={e["stop_anchor"] for e in s["history"] if e["variant"]!="Expired"}
        needed={e["stop_anchor"] for e in s["history"] if e["subject"]==op["actor"] and e["consequence_class"]==g["consequence_class"]
                and e["variant"]!="Expired" and e["false_attestation_finding"] is None and not any(a["outcome"]=="overturned" for a in e["adjudications"])}
        if not set(mapping)<=adverse or not needed<=set(mapping) or any(type(d) is not str or d not in registry for d in mapping.values()):
            raise ValidationError("surviving applicable stops require their historically governing profiles")
        bounds=[];capped=[];ignored=[];predates=False
        for e in s["history"]:
            if e["subject"]!=op["actor"] or e["consequence_class"]!=g["consequence_class"] or e["variant"]=="Expired":continue
            if e["false_attestation_finding"] is not None or any(a["outcome"]=="overturned" for a in e["adjudications"]):
                ignored.append(e["stop_anchor"]);continue
            old=registry[mapping[e["stop_anchor"]]];occurred=_at(e["occurred_at"])
            if e["sequence"]>=g["sequence"] or occurred>g["issued_at"]:predates=True
            if occurred+old["classes"][g["consequence_class"]]["cap_seconds"]<=g["issued_at"] and e["sequence"]<g["sequence"]:
                capped.append(e["stop_anchor"]);continue
            if retained>max(0,occurred-old["window_seconds"]):raise ValidationError("historical pricing window is incomplete")
            quote=project_hysteresis(old,s["history"],subject=op["actor"],consequence_class=e["consequence_class"],issued_at=occurred,
                current_sequence=e["sequence"],as_of=evaluated_at,ledger_head_sequence=head["sequence"])
            bounds.append((e["stop_anchor"],quote.reissue_not_before))
        required=max((bound for _,bound in bounds),default=None)
        relational=None
        if g["consequence_class"]=="Relational" and self.relational_verifier is not None:
            relational=self.relational_verifier.evaluate(lease_bytes,actual_operation=op,evaluated_at=evaluated_at,clock_healthy=clock_healthy)
            if (relational.current_grant_epoch!=s["current_grant_epoch"] or relational.lease_digest!=ld
                    or relational.grant_sequence!=g["sequence"] or relational.ledger_head_anchor!=head["anchor"]
                    or relational.ledger_head_sequence!=head["sequence"]):
                raise ValidationError("relational and historical reissue Sources disagree on actual grant/epoch/ledger head")
            rs=_parse_jcs_object(relational.authenticated_state_bytes)
            if rs["grant"]!=g:raise ValidationError("relational and historical grant audit records differ")
            retained_stops={e["stop_anchor"]:e for e in s["history"] if e["subject"]==op["actor"]
                and e["consequence_class"]=="Relational" and e["variant"]!="Expired"}
            persistent={e["anchor"]:e for e in rs["stops"]}
            if (not set(retained_stops)<=set(persistent) or any(e["occurred_at"]>=retained and e["anchor"] not in retained_stops for e in rs["stops"])
                    or any(persistent[a]["sequence"]!=e["sequence"] or persistent[a]["occurred_at"]!=_at(e["occurred_at"])
                           for a,e in retained_stops.items())):
                raise ValidationError("retained pricing history differs from persistent relational stop inventory")
        reason=("REISSUE_GRANT_EPOCH" if g["grant_epoch"]!=s["current_grant_epoch"] else
                "REISSUE_GRANT_PRECEDES_STOP" if predates else "REISSUE_TOO_EARLY" if required is not None and g["issued_at"]<required else
                "REISSUE_RELATIONAL_REPAIR_UNSUPPORTED" if g["consequence_class"]=="Relational" and relational is None else
                relational.reason if relational is not None and not relational.eligible else "REISSUE_ELIGIBLE")
        expiry=min(s["expires_at"],relational.expires_at) if relational is not None else s["expires_at"]
        for e in s["history"]:
            if e["variant"]=="Revoked" and any(a["outcome"]=="overturned" for a in e["adjudications"]):
                end=_at(e["occurred_at"])+hp["window_seconds"]
                if end>=evaluated_at:expiry=min(expiry,int(end)+1)
        result=object.__new__(HandBackReissueAssessment)
        for key,value in dict(eligible=reason=="REISSUE_ELIGIBLE",reason=reason,lease_id=g["id"],lease_digest=ld,issued_at=g["issued_at"],
                current_grant_epoch=s["current_grant_epoch"],required_reissue_not_before=required,bounds=tuple(sorted(bounds)),cap_satisfied=tuple(sorted(capped)),
                ignored_expunged=tuple(sorted(ignored)),expungement_required=inventory.expungement_required,revoker_accountability_required=inventory.revoker_accountability_required,
                profile_bytes=self.profile_bytes,operation_bytes=op_bytes,evaluated_at=evaluated_at,expires_at=expiry,
                authenticated_state_bytes=source.state_bytes,source_evidence_bytes=source.evidence_bytes,relational=relational).items():object.__setattr__(result,key,value)
        return result
