"""Fresh enclosure-measured egress claims, never edits to signed history.

The disclosure source authenticates the actual departure, current governance,
topology, recipient and approval of the complete new claim body. The Core claim
source independently derives the enclosure's current assertion. Nothing here
authorizes movement or implements gateway transport, audit export or logging.
"""
from dataclasses import dataclass

from kinetic_trust_library.errors import ValidationError
from .trust_proof_json import _parse_jcs_object
from .complete_proof_verifier import InstalledProofVerifier, ProofVerificationResult
from .core_claims import NativeCoreClaimsSource
from .core_projection import NativeCoreProjection
from .root_lifecycle import _time


@dataclass(frozen=True, slots=True)
class AuthenticatedEgressEvidence:
    state_bytes: bytes
    evidence_bytes: bytes


@dataclass(frozen=True, slots=True, init=False)
class EgressClaims:
    checked_at: int
    payload_bytes: bytes
    incoming_verification: ProofVerificationResult
    outward_core: NativeCoreProjection
    profile_bytes: bytes
    authenticated_state_bytes: bytes
    source_evidence_bytes: bytes
    expires_at: int

    def __init__(self, *args, **kwargs):
        raise TypeError("egress claims are derived by an installed projector")

    def produce(self, *, evaluated_at: int) -> bytes:
        if not _time(evaluated_at) or evaluated_at != self.checked_at:
            raise ValidationError("egress claims belong to another evaluation time")
        return self.payload_bytes


@dataclass(frozen=True, slots=True)
class InstalledEgressProjector:
    profile_bytes: bytes
    disclosure_source: object
    incoming_verifier: InstalledProofVerifier
    outward_claim_source: NativeCoreClaimsSource

    def __post_init__(self):
        if (type(self.profile_bytes) is not bytes or not callable(getattr(self.disclosure_source, "resolve", None))
                or type(self.incoming_verifier) is not InstalledProofVerifier
                or type(self.outward_claim_source) is not NativeCoreClaimsSource):
            raise ValidationError("installed egress projector is invalid")
        profile = _parse_jcs_object(self.profile_bytes)
        if (set(profile) != {"id", "version", "mode", "subject", "source_zone", "measurement_zone", "audience", "digest_algorithm"}
                or profile["mode"] != "fresh-enclosure-proof-v1" or not _time(profile["version"]) or profile["version"] == 0
                or profile["digest_algorithm"] not in ("sha256", "sha384")):
            raise ValidationError("installed egress disclosure profile is invalid")
        for name in ("id", "subject", "source_zone", "measurement_zone", "audience"):
            if type(profile[name]) is not str or not profile[name] or any(char.isspace() for char in profile[name]):
                raise ValidationError("invalid egress profile identifier")
        incoming = _parse_jcs_object(self.incoming_verifier.expected_context_bytes)
        receiving = incoming.get("receiving_zone", incoming["zone"])
        if incoming["subject"] != profile["subject"] or receiving != profile["source_zone"]:
            raise ValidationError("incoming proof policy differs from actual egress subject/source ring")

    def evaluate(self, incoming_compact: str, *, evaluated_at: int, clock_healthy: bool) -> EgressClaims:
        from .demand_supplier import _digest
        from ._readiness_crypto import digest_bytes
        if not _time(evaluated_at) or clock_healthy is not True:
            raise ValidationError("egress requires a healthy current clock")
        incoming = self.incoming_verifier.verify(incoming_compact, now=evaluated_at, clock_healthy=clock_healthy)
        if incoming.stage != 8:
            raise ValidationError("egress input failed current complete proof verification: "+incoming.reason)
        profile = _parse_jcs_object(self.profile_bytes)
        source = self.disclosure_source.resolve(profile_bytes=self.profile_bytes, evaluated_at=evaluated_at)
        if (type(source) is not AuthenticatedEgressEvidence or type(source.state_bytes) is not bytes
                or type(source.evidence_bytes) is not bytes or not source.evidence_bytes):
            raise ValidationError("egress source returned invalid authenticated disclosure evidence")
        state = _parse_jcs_object(source.state_bytes)
        level = 3 if profile["digest_algorithm"] == "sha384" else 2
        if (set(state) != {"profile_digest", "incoming_proof_digest", "outward_claims_digest", "checked_at", "topology_epoch", "ancestry", "expires_at"}
                or state["profile_digest"] != _digest(profile, profile["digest_algorithm"])
                or state["incoming_proof_digest"] != digest_bytes(incoming_compact.encode("ascii"), level)
                or not _time(state["checked_at"]) or state["checked_at"] != evaluated_at
                or not _time(state["topology_epoch"]) or not _time(state["expires_at"]) or state["expires_at"] <= evaluated_at):
            raise ValidationError("egress evidence differs from current input/profile/topology")
        ancestry = state["ancestry"]
        if (type(ancestry) is not list or not 1 <= len(ancestry) <= 6
                or any(type(zone) is not str or not zone for zone in ancestry) or len(set(ancestry)) != len(ancestry)
                or ancestry[-1] != profile["source_zone"]
                or profile["measurement_zone"] != (ancestry[-2] if len(ancestry) > 1 else ancestry[-1])):
            raise ValidationError("egress measurement is not the current direct enclosure/outermost ring")
        expected = _parse_jcs_object(self.incoming_verifier.expected_context_bytes)
        if expected["ring_depth"] != len(ancestry)-1:
            raise ValidationError("egress ancestry differs from incoming proof policy")
        ingress = incoming.ingress_verification
        if len(ancestry) > 1:
            if ingress is None or ingress.reason != "INGRESS_VERIFIED":
                raise ValidationError("nested egress requires current ingress evidence")
            topology = _parse_jcs_object(ingress.authenticated_state_bytes)["topology"]
            if topology["epoch"] != state["topology_epoch"] or [ring["zone_id"] for ring in topology["rings"]] != ancestry:
                raise ValidationError("egress topology differs from current ingress evidence")
        source_context = self.outward_claim_source.context
        if source_context.evaluated_at != evaluated_at:
            raise ValidationError("outward Core belongs to another evaluation time")
        payload_bytes = self.outward_claim_source.produce(evaluated_at=evaluated_at)
        payload = _parse_jcs_object(payload_bytes)
        original = _parse_jcs_object(incoming.authenticated_payload_bytes)
        support_expiry = min(original["exp"], state["expires_at"])
        if ingress is not None:
            support_expiry = min(support_expiry, ingress.expires_at)
        if (state["outward_claims_digest"] != digest_bytes(payload_bytes, level)
                or payload["sub"] != profile["subject"] or payload["aud"] != profile["audience"]
                or payload["ktp"]["zone"] != profile["measurement_zone"]
                or payload["iat"] != evaluated_at or payload["jti"] == original["jti"]
                or payload["exp"] > support_expiry):
            raise ValidationError("outward claims differ from approved recipient/measure/fresh assertion")
        if incoming.reason == "TP_VETO" and payload["ktp"]["gate_state"] != "veto":
            raise ValidationError("egress cannot clear a known input veto")
        # No original telemetry, extensions or receipt is copied. The strict
        # fresh Core producer currently omits these optional fields entirely.
        if "extensions" in payload or any(name in payload["ktp"] for name in ("de_dt", "sigma", "oracle_quorum", "resilience_hash")):
            raise ValidationError("outward payload contains telemetry outside this disclosure profile")
        visible = ancestry[:-1]
        path = payload["ktp"].get("ingress_path", [])
        if type(path) is not list or len(path) > len(visible) or any(receipt["zone_id"] != visible[index] for index, receipt in enumerate(path)):
            raise ValidationError("outward path discloses the departing ring or an inner ring")
        enclosure = self.outward_claim_source.core.enclosure_assessment
        measurement_depth = max(0, len(ancestry)-2)
        if measurement_depth > 0 and enclosure is None:
            raise ValidationError("nested outward enclosure requires its own enclosure assessment")
        if enclosure is not None:
            enclosing_state = _parse_jcs_object(enclosure.authenticated_body_bytes)
            if (enclosure.inputs.depth != measurement_depth or enclosing_state["topology_epoch"] != state["topology_epoch"]
                    or enclosing_state["enclosure_zone"] != (ancestry[-3] if measurement_depth > 0 else None)):
                raise ValidationError("outward Core and disclosure enclosure topology differ")
        result = object.__new__(EgressClaims)
        for name, value in dict(checked_at=evaluated_at, payload_bytes=payload_bytes, incoming_verification=incoming,
                                outward_core=self.outward_claim_source.core, profile_bytes=self.profile_bytes,
                                authenticated_state_bytes=source.state_bytes, source_evidence_bytes=source.evidence_bytes,
                                expires_at=payload["exp"]).items():
            object.__setattr__(result, name, value)
        return result


def minimize_confidential_exit_summary(summary_bytes: bytes) -> bytes:
    """Return a new minimal unsigned derivative, never edit an attestation.

    Deliberately omits all quantitative conditions, tiers, veto rates and
    unknown fields. Even these retained action counts require disclosure
    approval and a separately authenticated new attestation before external use.
    """
    from ._readiness_crypto import canonical
    summary = _parse_jcs_object(summary_bytes)
    retained = {}
    for name in ("actions_total", "actions_allowed", "actions_vetoed", "soul_vetoes", "attestations_earned"):
        if name in summary:
            if not _time(summary[name]):
                raise ValidationError("exit summary counts must be nonnegative safe integer tokens")
            retained[name] = summary[name]
    return canonical(retained)


__all__ = ("InstalledEgressProjector", "AuthenticatedEgressEvidence", "EgressClaims", "minimize_confidential_exit_summary")
