"""Revalidate an already accepted invocation; never reserve or reaccept replay.

The installed Source authenticates the current complete durable reservation,
issuer/JTI mapping, active-domain floor and restore continuity. SDK rechecks the
actual invocation, complete proof and carrier before checking that reservation.
RB_CURRENT is a continuing-use prerequisite only, not ordinary RB_BOUND or
permission to release effects. Ordinary verify() still rejects exact replay.
"""
from dataclasses import dataclass
from kinetic_trust_library.errors import ValidationError
from .request_association import InstalledRequestAssociationVerifier,RequestAssociationResult
from .trust_proof_json import _parse_jcs_object
from .root_lifecycle import _time
from .execution_observation import _name
from .demand_supplier import _digest


@dataclass(frozen=True,slots=True)
class AuthenticatedExistingAssociation:
    state_bytes: bytes
    evidence_bytes: bytes


@dataclass(frozen=True,slots=True)
class InstalledExistingAssociationVerifier:
    association_verifier: InstalledRequestAssociationVerifier
    profile_bytes: bytes
    context_source: object

    def __post_init__(self):
        if (type(self.association_verifier) is not InstalledRequestAssociationVerifier or type(self.profile_bytes) is not bytes
                or not callable(getattr(self.context_source,"resolve",None))):
            raise ValidationError("installed association policy and current protected reservation source required")
        p=_parse_jcs_object(self.profile_bytes)
        if (set(p)!={"id","version","zone","formula","registry","maximum_recheck_seconds"}
                or any(not _name(p[n]) for n in ("id","zone","registry")) or not _time(p["version"]) or p["version"]==0
                or p["formula"]!="reserved-invocation-current-use-v1" or not _time(p["maximum_recheck_seconds"]) or p["maximum_recheck_seconds"]==0
                or p["zone"]!=_parse_jcs_object(self.association_verifier.proof_verifier.expected_context_bytes)["zone"]):
            raise ValidationError("invalid installed current-reservation declaration")

    def verify(self,accepted,*,invocation_evidence,now,clock_healthy):
        if (type(accepted) is not RequestAssociationResult or accepted.verifier is not self.association_verifier
                or accepted.reason not in ("RB_BOUND","RB_CURRENT") or not _time(now) or clock_healthy is not True
                or not _time(accepted.checked_at) or accepted.checked_at>now):
            raise ValidationError("current-use checks require the actual previously accepted association and healthy current time")
        return self.association_verifier._verify(accepted.canonical_request_bytes,accepted.canonical_association_bytes,
            accepted.compact_proof,invocation_evidence=invocation_evidence,now=now,clock_healthy=clock_healthy,
            reservation_verifier=self,previous=accepted)

    def _current(self,scope,previous,now):
        import rfc8785
        p=_parse_jcs_object(self.profile_bytes);algorithm=self.association_verifier.algorithm
        source=self.context_source.resolve(profile_bytes=self.profile_bytes,association_scope_bytes=rfc8785.dumps(scope),evaluated_at=now)
        if (type(source) is not AuthenticatedExistingAssociation or type(source.state_bytes) is not bytes or len(source.state_bytes)>65536
                or type(source.evidence_bytes) is not bytes or not source.evidence_bytes):
            raise ValidationError("current complete authenticated reservation facts required")
        s=_parse_jcs_object(source.state_bytes)
        if (set(s)!=set(scope)|{"profile_digest","registry","registry_epoch","state_revision","reservation_anchor","accepted_at","checked_at","expires_at","status"}
                or any(s[n]!=v for n,v in scope.items()) or s["profile_digest"]!=_digest(p,algorithm) or s["registry"]!=p["registry"]
                or not _time(s["registry_epoch"]) or s["registry_epoch"]==0 or not _time(s["state_revision"]) or s["state_revision"]==0
                or not _name(s["reservation_anchor"]) or not _time(s["accepted_at"]) or s["accepted_at"]>previous.checked_at
                or not _time(s["checked_at"]) or s["checked_at"]!=now or not _time(s["expires_at"])
                or s["status"] not in ("active","revoked","retired","unavailable")):
            raise ValidationError("reservation differs from actual accepted invocation/current installed registry scope")
        if previous.reservation_state_bytes is not None:
            old=_parse_jcs_object(previous.reservation_state_bytes)
            if (old["profile_digest"]!=s["profile_digest"] or old["registry"]!=s["registry"]
                    or s["registry_epoch"]<old["registry_epoch"] or s["state_revision"]<old["state_revision"]
                    or s["reservation_anchor"]!=old["reservation_anchor"] or s["accepted_at"]!=old["accepted_at"]):
                raise ValidationError("current reservation cannot roll back or rewrite the original accepted record")
        expiry=min(s["expires_at"],now+p["maximum_recheck_seconds"])
        return ("RB_CURRENT" if s["status"]=="active" and now<expiry else "RB_RESERVATION_UNAVAILABLE",expiry,source.state_bytes,source.evidence_bytes)
