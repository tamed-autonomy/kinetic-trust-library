"""Purpose-separated Decision Geometry carrier verification at current use time.

DG_CARRIER_VALID authenticates a record, not permission or replay consumption.
Expected identities, profile, supporting proof and validity ceilings are installed
trusted context. Product adapters still own live source/profile/key state.
"""
from dataclasses import dataclass
from functools import lru_cache
from importlib.resources import files
import json
from kinetic_trust_library.errors import ValidationError, ProofFormatError
from kinetic_trust_library._jws_encoding import _decode_segment
from .trust_proof_json import _parse_jcs_object
from .trust_proof_framing import parse_compact_framing
from .trust_proof_signature import trust_proof_signature_valid
from .complete_proof_verifier import InstalledSchemaBundle
from .decision_geometry import digest_geometry_body
from .geometry_verifier import InstalledGeometryVerifier
from .request_binding import digest_canonical_request, digest_complete_proof
from .root_lifecycle import _time


@lru_cache(maxsize=1)
def _bundle():
    import rfc8785
    base=files("kinetic_trust_library.v3").joinpath("schemas")
    schemas=[json.loads(base.joinpath(n).read_text("utf-8")) for n in (
        "decision-geometry-carrier-v1.json","decision-geometry-v1.json",
        "request-binding-v1.json","request-proof-association-v1.json")]
    return InstalledSchemaBundle(tuple(rfc8785.dumps(s) for s in schemas),schemas[0]["$id"])


@dataclass(frozen=True,slots=True,init=False)
class GeometryCarrierResult:
    reason: str
    compact: str
    canonical_payload_bytes: bytes | None

    def __init__(self,*args,**kwargs):
        raise TypeError("GeometryCarrierResult is derived by an installed verifier")


@dataclass(frozen=True,slots=True)
class InstalledGeometryCarrierVerifier:
    trusted_keys_bytes: bytes
    expected_context_bytes: bytes
    geometry_verifier: InstalledGeometryVerifier
    installed_algorithms: tuple[str,...] = ("ES256",)

    def __post_init__(self):
        if (type(self.trusted_keys_bytes) is not bytes or type(self.expected_context_bytes) is not bytes
                or type(self.geometry_verifier) is not InstalledGeometryVerifier
                or type(self.installed_algorithms) is not tuple):
            raise ValidationError("installed geometry carrier policy is invalid")
        _parse_jcs_object(self.trusted_keys_bytes)
        _parse_jcs_object(self.expected_context_bytes)

    def verify(self,compact: str,*,now: int,clock_healthy: bool) -> GeometryCarrierResult:
        import rfc8785
        raw=None
        def result(reason):
            value=object.__new__(GeometryCarrierResult)
            for name,member in (("reason",reason),("compact",compact),("canonical_payload_bytes",raw)):
                object.__setattr__(value,name,member)
            return value
        try:
            if type(compact) is not str or len(compact.encode("ascii"))>524288:
                return result("DG_CARRIER_FORMAT")
            parts=compact.split(".")
            if len(parts)!=3 or any(not p for p in parts): return result("DG_CARRIER_FORMAT")
            header_bytes=_decode_segment(parts[0],name="carrier header")
            raw=_decode_segment(parts[1],name="carrier payload")
            _decode_segment(parts[2],name="carrier signature")
            if len(header_bytes)>1024 or len(raw)>393216: return result("DG_CARRIER_FORMAT")
            header=_parse_jcs_object(header_bytes)
            payload=_parse_jcs_object(raw)
        except (ValueError,TypeError,UnicodeError,ProofFormatError):
            return result("DG_CARRIER_FORMAT")
        if (set(header)!={"alg","kid","typ"} or any(type(v) is not str or not v for v in header.values())
                or header["typ"]!="ktp-decision-geometry-v1" or header["alg"] not in self.installed_algorithms
                or header["alg"] not in ("ES256","EdDSA")):
            return result("DG_CARRIER_FORMAT")
        context=_parse_jcs_object(self.expected_context_bytes)
        key=_parse_jcs_object(self.trusted_keys_bytes).get(header["kid"])
        if (type(key) is not dict or key.get("revoked") is not False
                or key.get("role")!="decision-geometry-evaluator" or key.get("alg")!=header["alg"]
                or key.get("issuer")!=context["identity"]["evaluator"] or key.get("audience")!=context["identity"]["audience"]
                or not _time(key.get("not_before")) or not _time(key.get("not_after"))):
            return result("DG_CARRIER_KEY")
        curve=key.get("curve")
        if (header["alg"]=="ES256" and curve!="P-256") or (header["alg"]=="EdDSA" and curve!="Ed25519"):
            return result("DG_CARRIER_KEY")
        signature_key={**key,"kty":"EC" if header["alg"]=="ES256" else "OKP","crv":curve}
        if not trust_proof_signature_valid(compact,algorithm=header["alg"],trusted_key=signature_key):
            return result("DG_CARRIER_SIGNATURE")
        if not _bundle().valid(raw): return result("DG_CARRIER_BINDING")
        body=payload["geometry"]
        try:
            algorithm=self.geometry_verifier.algorithm
            if payload["geometry_digest"]!=digest_geometry_body(body,algorithm=algorithm) or body["association"] is None:
                return result("DG_CARRIER_BINDING")
            framing=parse_compact_framing(context["proof"])
            proof=_parse_jcs_object(framing.payload_bytes)
            association=body["association"]
            actual=context["request"]
            if (association["proof_digest"]!=digest_complete_proof(context["proof"],algorithm=algorithm)
                    or association["request_digest"]!=digest_canonical_request(actual,algorithm=algorithm)
                    or association["proof_jti"]!=proof["jti"] or proof["sub"]!=actual["actor"] or proof["aud"]!=actual["audience"]):
                return result("DG_CARRIER_BINDING")
            verified=self.geometry_verifier.proof_verifier.verify(context["proof"],now=now,clock_healthy=clock_healthy)
            if verified.stage!=8 and verified.reason!="TP_TIME": return result("DG_CARRIER_BINDING")
        except (ValidationError,ProofFormatError,KeyError,TypeError,ValueError):
            return result("DG_CARRIER_BINDING")
        expiry=payload["expires_at"]
        limits=[proof.get("exp"),key["not_after"],context.get("profile_expires_at")]
        limits.extend(context.get("supporting_expiries",[]))
        if (type(clock_healthy) is not bool or not clock_healthy or not _time(now)
                or not _time(expiry) or not _time(body["evaluated_at"])
                or any(not _time(t) for t in limits) or expiry>min(limits)
                or not body["evaluated_at"]<=now<expiry
                or not key["not_before"]<=body["evaluated_at"]<key["not_after"]
                or verified.reason=="TP_TIME"):
            return result("DG_CARRIER_TIME")
        accepted=self.geometry_verifier.verify(rfc8785.dumps(body),evaluated_at=context["identity"]["evaluated_at"])
        return result("DG_CARRIER_VALID" if accepted.reason=="DG_VALID" else accepted.reason)


__all__=["InstalledGeometryCarrierVerifier","GeometryCarrierResult"]
