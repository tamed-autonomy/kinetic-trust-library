"""Native trajectory signatures, pairwise continuity and authenticated heads.

The resolver authenticates the accepted format/profile floor, current registry,
committed intent, unique selected head, accepted predecessor and any durable
migration activation. These checks compare that external evidence; they do not
implement consensus, persistence, migration consumption or transition authority.
"""
from dataclasses import dataclass
from datetime import datetime,timezone
from fractions import Fraction
import re
from kinetic_trust_library.errors import ValidationError,ProofFormatError
from .trust_proof_json import _parse_jcs_object
from .root_lifecycle import _time
from .sponsorship_repair import InstalledSponsorshipRepairVerifier,SponsorshipRepairAssessment
from .federated_sponsorship import InstalledFederatedSponsorshipVerifier,FederatedSponsorshipAssessment
from .demand_supplier import _digest


class TrajectoryStateUnavailable(Exception):
    pass


@dataclass(frozen=True, slots=True)
class AuthenticatedGenesisSponsorship:
    record_hash: str
    bond_bytes: bytes
    context_bytes: bytes


@dataclass(frozen=True, slots=True)
class AuthenticatedTrajectoryContext:
    state_bytes: bytes
    trusted_keys_bytes: bytes
    evidence_bytes: bytes
    genesis_sponsorship: AuthenticatedGenesisSponsorship | None = None


@dataclass(frozen=True, slots=True, init=False)
class TrajectoryVerificationResult:
    reason: str
    checked_at: int
    canonical_record_bytes: bytes | None
    record_hash: str | None
    commit_intent: str | None
    authenticated_state_bytes: bytes | None
    trusted_keys_bytes: bytes | None
    source_evidence_bytes: bytes | None
    genesis_sponsorship: SponsorshipRepairAssessment | None
    genesis_federated_sponsorship: FederatedSponsorshipAssessment | None

    def __init__(self,*args,**kwargs):
        raise TypeError("trajectory results are derived by an installed verifier")


def _expected(value):
    from . import _trajectory_reference as t
    required={"trusted_level","trusted_profile_digest","expected_agent","expected_zone","expected_chain","minimum_record_format"}
    if (type(value) is not dict or not required<=set(value) or set(value)-required-{"sponsorship_repair_profile_digest","federated_sponsorship_profile_digest"}
            or type(value["trusted_level"]) is not int or value["trusted_level"] not in (1,2,3)
            or value["minimum_record_format"]!=t.VERSION):
        raise ValidationError("installed native trajectory expectations are invalid")
    algorithm,count=("sha384",96) if value["trusted_level"]==3 else ("sha256",64)
    if type(value["trusted_profile_digest"]) is not str or not re.fullmatch(algorithm+r":[0-9a-f]{"+str(count)+"}",value["trusted_profile_digest"]):
        raise ValidationError("installed trajectory profile digest does not meet the trusted level")
    for field in ("expected_agent","expected_zone","expected_chain"):
        t.literal(value[field])
    return {k:v for k,v in value.items() if k not in ("minimum_record_format","sponsorship_repair_profile_digest","federated_sponsorship_profile_digest")}


def _seconds(text):
    from . import _trajectory_reference as t
    elapsed=t.instant(text)-datetime(1970,1,1,tzinfo=timezone.utc)
    return Fraction(elapsed.days*86400+elapsed.seconds)+Fraction(elapsed.microseconds,1000000)


def _integrity(record,expected,keys,now):
    from . import _trajectory_reference as t
    # Shared key loading contains no artifact-specific policy; the trajectory
    # reference separately verifies the exact signing purposes and strength.
    from ._jws_keys import load_key_binding as _binding
    agent,agent_key=_binding(keys,record["agent_signature"])
    oracle,oracle_key=_binding(keys,record["oracle_attestation"]["oracle_signature"])
    evidence=t.verify_record(record,agent,oracle,**_expected(expected))
    event,attested=_seconds(record["timestamp"]),_seconds(record["oracle_attestation"]["attestation_time"])
    if not event<=attested<=now:
        raise t.InvalidRecord("record or Oracle attestation is in the future")
    for key,instant in ((agent_key,event),(oracle_key,attested)):
        if not key["not_before"]<=instant<key["not_after"]:
            raise t.InvalidRecord("signature is outside its trusted key/role interval")
    return evidence


@dataclass(frozen=True, slots=True)
class InstalledTrajectoryVerifier:
    expected_context_bytes: bytes
    adapter: object
    sponsorship_repair_verifier: InstalledSponsorshipRepairVerifier | None = None
    federated_sponsorship_verifier: InstalledFederatedSponsorshipVerifier | None = None

    def __post_init__(self):
        if type(self.expected_context_bytes) is not bytes or not callable(getattr(self.adapter,"resolve",None)):
            raise ValidationError("installed trajectory verifier is invalid")
        expected=_parse_jcs_object(self.expected_context_bytes);_expected(expected)
        if "sponsorship_repair_profile_digest" in expected:
            verifier=self.sponsorship_repair_verifier
            algorithm="sha384" if expected["trusted_level"]==3 else "sha256"
            if (type(verifier) is not InstalledSponsorshipRepairVerifier or verifier.algorithm!=algorithm
                    or verifier.expected_zone!=expected["expected_zone"]
                    or _digest(_parse_jcs_object(verifier.profile_bytes),algorithm)!=expected["sponsorship_repair_profile_digest"]):
                raise ValidationError("selected trajectory sponsorship policy differs from installed profile/zone")
        elif self.sponsorship_repair_verifier is not None:
            raise ValidationError("trajectory sponsorship checks require an explicit profile binding")
        if "federated_sponsorship_profile_digest" in expected:
            policy=self.federated_sponsorship_verifier;algorithm="sha384" if expected["trusted_level"]==3 else "sha256"
            if (type(policy) is not InstalledFederatedSponsorshipVerifier or policy.algorithm!=algorithm
                    or _parse_jcs_object(policy.profile_bytes)["receiving_zone"]!=expected["expected_zone"]
                    or _digest(_parse_jcs_object(policy.profile_bytes),algorithm)!=expected["federated_sponsorship_profile_digest"]):
                raise ValidationError("selected trajectory cross-zone sponsorship differs from installed profile/zone")
        elif self.federated_sponsorship_verifier is not None:
            raise ValidationError("trajectory cross-zone sponsorship requires an explicit profile binding")

    def verify(self, record_bytes: bytes, *, now: int, clock_healthy: bool) -> TrajectoryVerificationResult:
        from . import _trajectory_reference as t
        from ._jws_keys import load_key_binding as _binding
        if type(record_bytes) is not bytes or not _time(now):
            raise ValidationError("trajectory verification requires immutable bytes and trusted time")
        values=dict(reason="TRAJECTORY_UNAVAILABLE",checked_at=now,canonical_record_bytes=None,record_hash=None,
            commit_intent=None,authenticated_state_bytes=None,trusted_keys_bytes=None,source_evidence_bytes=None,genesis_sponsorship=None,genesis_federated_sponsorship=None)
        def result():
            value=object.__new__(TrajectoryVerificationResult)
            for name,member in values.items():object.__setattr__(value,name,member)
            return value
        if clock_healthy is not True:return result()
        try:
            source=self.adapter.resolve(expected_context_bytes=self.expected_context_bytes,checked_at=now)
        except TrajectoryStateUnavailable:
            return result()
        if (type(source) is not AuthenticatedTrajectoryContext
                or any(type(raw) is not bytes for raw in (source.state_bytes,source.trusted_keys_bytes,source.evidence_bytes))
                or not source.evidence_bytes):
            raise ValidationError("trajectory resolver returned invalid authenticated context")
        in_sponsorship_provider=False
        try:
            state=_parse_jcs_object(source.state_bytes)
            expected=_parse_jcs_object(self.expected_context_bytes)
            if (set(state)!={"checked_at","context","head","predecessor","predecessor_context","migration"}
                    or not _time(state["checked_at"]) or state["checked_at"]!=now
                    or t.canonical(state["context"])!=self.expected_context_bytes):
                return result()
            if len(record_bytes)>262144:raise t.InvalidRecord("trajectory exceeds installed byte limit")
            record=_parse_jcs_object(record_bytes)
            keys=_parse_jcs_object(source.trusted_keys_bytes)
            evidence=_integrity(record,expected,keys,now)
            t.verify_head_binding(record,state["head"])
            previous=state["predecessor"]
            if record["sequence"]==0:
                if (previous is not None or state["predecessor_context"] is not None
                        or record["previous_hash"] is not None or record["previous_state"] is not None):
                    raise t.InvalidRecord("genesis has a predecessor")
            else:
                if type(previous) is not dict or type(state["predecessor_context"]) is not dict:
                    raise t.InvalidRecord("accepted predecessor is unavailable")
                prior_context=state["predecessor_context"]
                if any(prior_context[k]!=expected[k] for k in ("expected_agent","expected_zone","expected_chain")):
                    raise t.InvalidRecord("predecessor belongs to another identity or chain")
                _integrity(previous,prior_context,keys,now)
                if (record["sequence"]!=previous["sequence"]+1 or record["previous_hash"]!=previous["record_hash"]
                        or t.canonical(record["previous_state"])!=t.canonical(previous["current_state"])
                        or t.instant(record["timestamp"])<=t.instant(previous["timestamp"])):
                    raise t.InvalidRecord("trajectory continuity failed")
            birth=record if record["sequence"]==0 else previous if previous["sequence"]==0 else None
            sponsorship_selected=self.sponsorship_repair_verifier is not None or self.federated_sponsorship_verifier is not None
            if sponsorship_selected and birth is not None and birth["migration_checkpoint"] is None:
                binding=source.genesis_sponsorship
                if (type(binding) is not AuthenticatedGenesisSponsorship or binding.record_hash!=birth["record_hash"]
                        or type(binding.bond_bytes) is not bytes or type(binding.context_bytes) is not bytes):
                    raise t.InvalidRecord("authenticated genesis sponsorship binding is unavailable")
                birth_time=_seconds(birth["timestamp"])
                if self.sponsorship_repair_verifier is not None:
                    in_sponsorship_provider=True
                    sponsorship=self.sponsorship_repair_verifier.evaluate(binding.bond_bytes,context_bytes=binding.context_bytes,
                        evaluated_at=now,clock_healthy=clock_healthy)
                    in_sponsorship_provider=False
                    bond=_parse_jcs_object(sponsorship.authenticated_bond_body_bytes)
                    if (not sponsorship.eligible or sponsorship.subject!=birth["agent_id"] or sponsorship.zone_id!=birth["zone_id"]
                            or sponsorship.opened_at>birth_time or not bond["start_time"]<=birth_time<bond["end_time"]):
                        raise t.InvalidRecord("genesis bond was not eligible at the actor's birth")
                    values["genesis_sponsorship"]=sponsorship
                if self.federated_sponsorship_verifier is not None:
                    in_sponsorship_provider=True
                    cross=self.federated_sponsorship_verifier.evaluate(binding.bond_bytes,context_bytes=binding.context_bytes,
                        evaluated_at=now,clock_healthy=clock_healthy)
                    in_sponsorship_provider=False
                    bond=_parse_jcs_object(cross.authenticated_bond_body_bytes)
                    if (not cross.opening_valid or cross.subject!=birth["agent_id"] or cross.receiving_zone!=birth["zone_id"]
                            or cross.opened_at>birth_time or not bond["start_time"]<=birth_time<min(bond["end_time"],cross.ends_at)):
                        raise t.InvalidRecord("cross-zone genesis bond was not eligible at the actor's birth")
                    values["genesis_federated_sponsorship"]=cross
            elif not sponsorship_selected and source.genesis_sponsorship is not None:
                raise t.InvalidRecord("genesis sponsorship source cannot select an uninstalled policy")
            migration=state["migration"]
            if record["migration_checkpoint"] is not None or record["sequence"]==0 and migration is not None:
                if (type(migration) is not dict or set(migration)!={"token","checkpoint_digest","approved_state","activated_at"}):
                    raise t.InvalidRecord("authenticated migration activation is unavailable")
                token=migration["token"]
                checkpoint=_parse_jcs_object(t.unb64(token.split(".")[1]))
                authority,key=_binding(keys,token)
                t.verify_migration(checkpoint,token,authority,record,trusted_level=expected["trusted_level"],
                    trusted_checkpoint_digest=migration["checkpoint_digest"],trusted_revalidated_state=migration["approved_state"],
                    trusted_now=migration["activated_at"])
                activation=_seconds(migration["activated_at"])
                if not key["not_before"]<=_seconds(checkpoint["issued_at"])<=activation<key["not_after"] or activation>now:
                    raise t.InvalidRecord("migration activation key/time binding failed")
                if not (_seconds(checkpoint["issued_at"])<=_seconds(record["timestamp"])
                        <=_seconds(record["oracle_attestation"]["attestation_time"])<=activation):
                    raise t.InvalidRecord("migration activation predates its complete signed genesis")
        except (ValueError,ValidationError,ProofFormatError,KeyError,TypeError,IndexError,UnicodeError,RecursionError):
            if in_sponsorship_provider:raise
            values["reason"]="TRAJECTORY_INVALID"
            return result()
        values.update(reason="TRAJECTORY_VERIFIED",canonical_record_bytes=record_bytes,record_hash=evidence["record_hash"],
            commit_intent=evidence["commit_intent"],authenticated_state_bytes=source.state_bytes,trusted_keys_bytes=source.trusted_keys_bytes,
            source_evidence_bytes=source.evidence_bytes)
        return result()


__all__=["InstalledTrajectoryVerifier","AuthenticatedTrajectoryContext","AuthenticatedGenesisSponsorship","TrajectoryVerificationResult","TrajectoryStateUnavailable"]
