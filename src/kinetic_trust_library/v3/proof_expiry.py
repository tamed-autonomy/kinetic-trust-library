"""Authenticated ordinary-proof expiry metadata, never renewed authority."""
from dataclasses import dataclass

from kinetic_trust_library.errors import ValidationError, ProofFormatError
from .complete_proof_verifier import InstalledProofVerifier, NATIVE_PROOF_SCHEMA_ID
from .trust_proof_framing import parse_compact_framing
from .trust_proof_json import _parse_jcs_object, parse_proof_json_objects
from .trust_proof_time import _safe_time, trust_proof_time_valid
from .trust_proof_invariants import _invariants_hold


@dataclass(frozen=True, slots=True, init=False)
class ProofExpiryAssessment:
    expired: bool
    action_permitted: bool
    refresh_path: str | None
    proof_expires_at: int | None
    evaluated_at: int
    ordinary_verification: object
    profile_bytes: bytes
    compact_proof: str
    signed_payload_bytes: bytes | None

    def __init__(self, *args, **kwargs):
        raise TypeError("proof expiry is derived by an installed verifier")


@dataclass(frozen=True, slots=True)
class InstalledProofExpiryVerifier:
    proof_verifier: InstalledProofVerifier
    profile_bytes: bytes

    def __post_init__(self):
        if type(self.proof_verifier) is not InstalledProofVerifier or type(self.profile_bytes) is not bytes:
            raise ValidationError("installed proof expiry policy is invalid")
        p = _parse_jcs_object(self.profile_bytes)
        c = _parse_jcs_object(self.proof_verifier.expected_context_bytes)
        if (set(p) != {"id", "version", "zone", "formula", "refresh_path"}
                or any(type(p[k]) is not str or not p[k] for k in ("id", "zone", "refresh_path"))
                or type(p["version"]) is not int or p["version"] < 1
                or p["formula"] != "signed-ordinary-expiry-refresh-v1"
                or p["zone"] != c["zone"] or c.get("subject_kind") not in ("software_agent", "person")
                or self.proof_verifier.schema_bundle.root_id != NATIVE_PROOF_SCHEMA_ID):
            raise ValidationError("installed proof expiry profile is invalid")

    def evaluate(self, compact, *, actual_operation, evaluated_at, clock_healthy):
        verification = None
        expiry = None
        expired = False
        if clock_healthy is True and _safe_time(evaluated_at):
            try:
                framing = parse_compact_framing(compact)
                header, payload = parse_proof_json_objects(framing)
                # Do not enter the ordinary verifier's live Root path for a
                # currently valid proof, nor verify anything at a past time.
                if _safe_time(payload.get("exp")) and evaluated_at >= payload["exp"]:
                    verification = self.proof_verifier.verify(compact, now=evaluated_at, clock_healthy=True)
                    if verification.stage == 5 and verification.reason == "TP_TIME":
                        c = _parse_jcs_object(self.proof_verifier.expected_context_bytes)
                        key = _parse_jcs_object(self.proof_verifier.trusted_keys_bytes)[header["kid"]]
                        expired = (actual_operation.get("actor") == c["subject"]
                            and actual_operation.get("audience") == c["audience"]
                            and trust_proof_time_valid(payload, now=payload.get("iat"), clock_healthy=True,
                                key_not_before=key.get("not_before"), key_not_after=key.get("not_after"))
                            and self.proof_verifier.schema_bundle.valid(framing.payload_bytes)
                            and _invariants_hold(payload, expected_subject=c["subject"], expected_zone=c["zone"],
                                required_ceilings=c["required_ceilings"], expected_subject_kind=c["subject_kind"]))
                        # Critical extension semantics must be installed even
                        # for this restricted refresh classification.
                        handlers = dict(self.proof_verifier.extension_handlers)
                        import rfc8785
                        for namespace, extension in payload.get("extensions", {}).items():
                            handler = handlers.get(namespace)
                            if handler is None:
                                expired = expired and not extension["critical"]
                            elif handler(rfc8785.dumps(extension["value"])) is not True:
                                expired = False
                        if expired:
                            expiry = payload["exp"]
            except (ProofFormatError, ValidationError, KeyError, TypeError, ValueError, AttributeError):
                expired = False
        result = object.__new__(ProofExpiryAssessment)
        p = _parse_jcs_object(self.profile_bytes)
        for name, value in (("expired", bool(expired)), ("action_permitted", False),
                ("refresh_path", p["refresh_path"] if expired else None),
                ("proof_expires_at", expiry if expired else None), ("evaluated_at", evaluated_at),
                ("ordinary_verification", verification), ("profile_bytes", self.profile_bytes),
                ("compact_proof", compact), ("signed_payload_bytes", framing.payload_bytes if expired else None)):
            object.__setattr__(result, name, value)
        return result
