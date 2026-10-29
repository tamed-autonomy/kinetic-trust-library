"""Nested ingress bindings under an installed receipt cryptographic profile.

The topology source authenticates governance, current ancestry/roles and the
actual possession-verified admission session. The receipt adapter authenticates
every signed field and its complete-receipt link digest under the exact named
profile. This module does not invent a receipt wire encoding or run a gateway.
"""
from dataclasses import dataclass

from kinetic_trust_library.errors import ValidationError, ProofFormatError
from kinetic_trust_library._decimal import as_decimal
from .trust_proof_json import _parse_jcs_object
from .root_lifecycle import _time


class IngressUnavailable(Exception):
    pass


class IngressReceiptInvalid(Exception):
    pass


@dataclass(frozen=True, slots=True)
class AuthenticatedIngressContext:
    state_bytes: bytes
    evidence_bytes: bytes


@dataclass(frozen=True, slots=True)
class AuthenticatedIngressReceipt:
    receipt_bytes: bytes
    receipt_digest: str
    evidence_bytes: bytes


@dataclass(frozen=True, slots=True, init=False)
class IngressVerificationResult:
    reason: str
    checked_at: int
    payload_bytes: bytes
    depth: int | None
    expires_at: int | None
    authenticated_state_bytes: bytes | None
    source_evidence_bytes: bytes | None
    receipts: tuple[AuthenticatedIngressReceipt, ...]

    def __init__(self, *args, **kwargs):
        raise TypeError("ingress results are derived by an installed verifier")


_CLASSES = {"green": 0, "cyan": 1, "blue": 2, "deep_blue": 3}
_RECEIPT_FIELDS = {"zone_id", "oracle_kid", "sub", "cnf_jkt", "aud", "prev",
                   "topology_epoch", "iat", "exp", "admission_id", "sig"}


@dataclass(frozen=True, slots=True)
class InstalledIngressVerifier:
    context_bytes: bytes
    receipt_profile_bytes: bytes
    topology_source: object
    receipt_adapter: object

    def __post_init__(self):
        from . import _human_reference as h
        if (type(self.context_bytes) is not bytes or type(self.receipt_profile_bytes) is not bytes
                or not callable(getattr(self.topology_source, "resolve", None))
                or not callable(getattr(self.receipt_adapter, "verify", None))):
            raise ValidationError("installed ingress verifier is invalid")
        context = _parse_jcs_object(self.context_bytes)
        profile = _parse_jcs_object(self.receipt_profile_bytes)
        if (set(context) != {"subject", "receiving_zone", "receipt_profile_id", "receipt_profile_digest", "conformance_level"}
                or type(context["conformance_level"]) is not int or context["conformance_level"] not in (1, 2, 3)
                or profile.get("id") != context["receipt_profile_id"]
                or profile.get("link_digest_algorithm") not in ("sha256", "sha384")
                or context["conformance_level"] == 3 and profile.get("link_digest_algorithm") != "sha384"
                or not _time(profile.get("version")) or profile["version"] == 0
                or h.digest(profile, context["conformance_level"]) != context["receipt_profile_digest"]):
            raise ValidationError("installed ingress context/profile binding is invalid")
        for name in ("subject", "receiving_zone", "receipt_profile_id"):
            h.literal(context[name])

    def verify(self, payload_bytes: bytes, *, now: int, clock_healthy: bool) -> IngressVerificationResult:
        from . import _human_reference as h
        if type(payload_bytes) is not bytes or not _time(now):
            raise ValidationError("ingress requires exact authenticated payload bytes and trusted time")
        expected = _parse_jcs_object(self.context_bytes)
        values = dict(reason="INGRESS_UNAVAILABLE", checked_at=now, payload_bytes=payload_bytes, depth=None,
                      expires_at=None, authenticated_state_bytes=None, source_evidence_bytes=None, receipts=())

        def result():
            value = object.__new__(IngressVerificationResult)
            for name, member in values.items():
                object.__setattr__(value, name, member)
            return value

        if clock_healthy is not True:
            return result()
        try:
            source = self.topology_source.resolve(context_bytes=self.context_bytes, evaluated_at=now)
        except IngressUnavailable:
            return result()
        if (type(source) is not AuthenticatedIngressContext or type(source.state_bytes) is not bytes
                or type(source.evidence_bytes) is not bytes or not source.evidence_bytes):
            raise ValidationError("ingress source returned invalid authenticated state")
        try:
            state = _parse_jcs_object(source.state_bytes)
            if (set(state) != {"context", "checked_at", "topology", "session"}
                    or not _time(state["checked_at"]) or state["checked_at"] != now
                    or h.canonical(state["context"]) != self.context_bytes):
                return result()
            if len(payload_bytes) > 49152:
                raise h.InvalidRecord("ingress proof payload exceeds the native byte limit")
            payload = _parse_jcs_object(payload_bytes)
            if payload["sub"] != expected["subject"] or payload["ktp"]["zone"] != expected["receiving_zone"]:
                raise h.InvalidRecord("proof differs from installed subject/receiving ring")
            if not _time(payload["exp"]) or now >= payload["exp"]:
                raise h.InvalidRecord("supporting proof is not current")
            topology, session = state["topology"], state["session"]
            if (type(topology) is not dict or set(topology) != {"epoch", "rings"} or not _time(topology["epoch"])
                    or type(session) is not dict or set(session) != {"sub", "cnf_jkt", "admission_id", "expires_at"}
                    or session["sub"] != expected["subject"] or not _time(session["expires_at"]) or now >= session["expires_at"]):
                raise h.InvalidRecord("invalid current topology or possession-verified session")
            for name in ("sub", "cnf_jkt", "admission_id"):
                h.literal(session[name])
            rings = topology["rings"]
            if type(rings) is not list or not 1 <= len(rings) <= 6:
                raise h.InvalidRecord("ancestry must contain one through six rings")
            identifiers, previous_class = set(), -1
            for index, ring in enumerate(rings):
                if (type(ring) is not dict or set(ring) != {"zone_id", "enforcement_class", "enclosure_reach", "registry_enclosure_reach", "oracle_kids"}
                        or ring["enforcement_class"] not in _CLASSES):
                    raise h.InvalidRecord("invalid ring declaration")
                h.literal(ring["zone_id"])
                rank = _CLASSES[ring["enforcement_class"]]
                if ring["zone_id"] in identifiers or rank < previous_class:
                    raise h.InvalidRecord("repeating ancestry or decreasing enforcement class")
                identifiers.add(ring["zone_id"])
                previous_class = rank
                for field in ("enclosure_reach", "registry_enclosure_reach"):
                    reach = as_decimal(ring[field], name=field, minimum=0, maximum=1)
                    if (index == 0 and reach != 0) or (index > 0 and reach == 0):
                        raise h.InvalidRecord("enclosure reach must be disabled only at depth zero")
                keys = ring["oracle_kids"]
                if type(keys) is not list or not keys or any(type(kid) is not str for kid in keys) or len(set(keys)) != len(keys):
                    raise h.InvalidRecord("ring Oracle roles unavailable")
                for kid in keys:
                    h.literal(kid)
            if rings[-1]["zone_id"] != expected["receiving_zone"]:
                raise h.InvalidRecord("authenticated ancestry does not terminate at receiving ring")
            depth = len(rings)-1
            values["depth"] = depth
            path = payload["ktp"].get("ingress_path")
            if (depth == 0 and "ingress_path" in payload["ktp"]
                    or depth > 0 and (type(path) is not list or len(path) != depth)):
                raise h.InvalidRecord("path must exactly match authenticated ancestry depth")
            previous, verified = None, []
            expiry = min(payload["exp"], session["expires_at"])
            for index, receipt in enumerate(path or ()):
                if type(receipt) is not dict or set(receipt) != _RECEIPT_FIELDS:
                    raise h.InvalidRecord("invalid closed ingress receipt")
                for name in ("zone_id", "oracle_kid", "sub", "cnf_jkt", "aud", "admission_id"):
                    h.literal(receipt[name])
                if type(receipt["sig"]) is not str or not receipt["sig"]:
                    raise h.InvalidRecord("missing profile-encoded receipt signature")
                if (receipt["zone_id"] != rings[index]["zone_id"] or receipt["aud"] != rings[index+1]["zone_id"]
                        or receipt["oracle_kid"] not in rings[index]["oracle_kids"]
                        or any(receipt[name] != session[name] for name in ("sub", "cnf_jkt", "admission_id"))
                        or not _time(receipt["topology_epoch"]) or receipt["topology_epoch"] != topology["epoch"]
                        or receipt["prev"] != previous or not _time(receipt["iat"]) or not _time(receipt["exp"])
                        or not receipt["iat"] <= now < receipt["exp"]):
                    raise h.InvalidRecord("receipt ancestry/session/epoch/time/link binding mismatch")
                raw = h.canonical(receipt)
                assessed = self.receipt_adapter.verify(raw, context_bytes=self.context_bytes,
                    authenticated_state_bytes=source.state_bytes, receipt_profile_bytes=self.receipt_profile_bytes, evaluated_at=now)
                if (type(assessed) is not AuthenticatedIngressReceipt or assessed.receipt_bytes != raw
                        or type(assessed.receipt_bytes) is not bytes or type(assessed.evidence_bytes) is not bytes or not assessed.evidence_bytes):
                    raise h.InvalidRecord("receipt adapter did not authenticate exact signed fields")
                profile = _parse_jcs_object(self.receipt_profile_bytes)
                h.check_digest(assessed.receipt_digest, 3 if profile["link_digest_algorithm"] == "sha384" else 2)
                previous = assessed.receipt_digest
                expiry = min(expiry, receipt["exp"])
                verified.append(assessed)
        except IngressUnavailable:
            return result()
        except (IngressReceiptInvalid, ValueError, ValidationError, ProofFormatError, KeyError, TypeError, UnicodeError, RecursionError):
            values["reason"] = "INGRESS_INVALID"
            return result()
        values.update(reason="INGRESS_VERIFIED", expires_at=expiry, authenticated_state_bytes=source.state_bytes,
                      source_evidence_bytes=source.evidence_bytes, receipts=tuple(verified))
        return result()


__all__ = ("InstalledIngressVerifier", "IngressVerificationResult", "AuthenticatedIngressContext",
           "AuthenticatedIngressReceipt", "IngressUnavailable", "IngressReceiptInvalid")
