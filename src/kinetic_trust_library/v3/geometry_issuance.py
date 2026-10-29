"""Purpose-separated carrier issuance from independently verified records.

The installed producer owns the native record, the reproduction verifier checks
it independently, and the signing adapter owns private keys. Validity ends at
the earliest supporting expiry. A signed record is never execution permission.
"""
from dataclasses import dataclass
from kinetic_trust_library.errors import ValidationError
from .native_issuance import _segment
from .geometry_carrier import InstalledGeometryCarrierVerifier, GeometryCarrierResult, _bundle
from .trust_proof_json import _parse_jcs_object
from .trust_proof_framing import parse_compact_framing
from .decision_geometry import digest_geometry_body
from .root_lifecycle import _time


@dataclass(frozen=True, slots=True)
class IssuedGeometryCarrier:
    compact: str
    payload_bytes: bytes
    verification: GeometryCarrierResult


@dataclass(frozen=True, slots=True)
class InstalledGeometryCarrierIssuer:
    body_source: object
    signer: object
    verifier: InstalledGeometryCarrierVerifier
    algorithm: str
    kid: str

    def __post_init__(self):
        if (not callable(getattr(self.body_source,"produce",None))
                or not callable(getattr(self.signer,"sign",None))
                or type(self.verifier) is not InstalledGeometryCarrierVerifier
                or self.algorithm not in ("ES256","EdDSA")
                or self.algorithm not in self.verifier.installed_algorithms
                or type(self.kid) is not str or not self.kid):
            raise ValidationError("installed geometry issuance policy is invalid")

    def issue(self, *, now: int, clock_healthy: bool) -> IssuedGeometryCarrier:
        import rfc8785
        if not _time(now) or clock_healthy is not True:
            raise ValidationError("geometry issuance requires a healthy installed clock")
        context=_parse_jcs_object(self.verifier.expected_context_bytes)
        key=_parse_jcs_object(self.verifier.trusted_keys_bytes).get(self.kid)
        if (type(key) is not dict or key.get("kid")!=self.kid or key.get("revoked") is not False
                or key.get("role")!="decision-geometry-evaluator" or key.get("alg")!=self.algorithm
                or key.get("curve")!={"ES256":"P-256","EdDSA":"Ed25519"}[self.algorithm]
                or key.get("issuer")!=context["identity"]["evaluator"]
                or key.get("audience")!=context["identity"]["audience"]
                or not _time(key.get("not_before")) or not _time(key.get("not_after"))):
            raise ValidationError("geometry issuance key binding is invalid")
        evaluated_at=context["identity"]["evaluated_at"]
        proof_verifier=self.verifier.geometry_verifier.proof_verifier
        proof=proof_verifier.verify(context["proof"],now=now,clock_healthy=clock_healthy)
        if proof.stage!=8:
            raise ValidationError("geometry issuance supporting proof failed: "+proof.reason)
        claims=_parse_jcs_object(parse_compact_framing(context["proof"]).payload_bytes)
        limits=[claims["exp"],key["not_after"],context.get("profile_expires_at")]
        from .native_geometry import NativeGeometrySource
        if type(self.body_source) is NativeGeometrySource and self.body_source.supervision_rails is not None:
            limits.append(self.body_source.supervision_rails.expires_at)
        supporting=context.get("supporting_expiries",[])
        if type(supporting) is not list:
            raise ValidationError("installed geometry validity ceilings are invalid")
        limits.extend(supporting)
        if (not _time(evaluated_at) or any(not _time(t) for t in limits)
                or not key["not_before"]<=evaluated_at<=now<min(limits)):
            raise ValidationError("geometry issuance validity interval is invalid")
        raw=self.body_source.produce(evaluated_at=evaluated_at)
        if type(raw) is not bytes:
            raise ValidationError("geometry producer must return canonical immutable bytes")
        body=_parse_jcs_object(raw)
        verified_body=self.verifier.geometry_verifier.verify(raw,evaluated_at=evaluated_at)
        if verified_body.reason!="DG_VALID":
            raise ValidationError("geometry producer failed independent verification: "+verified_body.reason)
        payload=rfc8785.dumps(dict(carrier_version="decision-geometry-carrier-v1",geometry=body,
            geometry_digest=digest_geometry_body(body,algorithm=self.verifier.geometry_verifier.algorithm),expires_at=min(limits)))
        if not _bundle().valid(payload):
            raise ValidationError("geometry producer returned an invalid carrier payload")
        header=rfc8785.dumps(dict(alg=self.algorithm,kid=self.kid,typ="ktp-decision-geometry-v1"))
        signing_input=(_segment(header)+"."+_segment(payload)).encode("ascii")
        signature=self.signer.sign(signing_input,algorithm=self.algorithm,kid=self.kid)
        if type(signature) is not bytes:
            raise ValidationError("geometry signer must return raw signature bytes")
        compact=signing_input.decode("ascii")+"."+_segment(signature)
        verified=self.verifier.verify(compact,now=now,clock_healthy=clock_healthy)
        if verified.reason!="DG_CARRIER_VALID":
            raise ValidationError("issued geometry carrier failed verification: "+verified.reason)
        return IssuedGeometryCarrier(compact,payload,verified)


__all__=["InstalledGeometryCarrierIssuer","IssuedGeometryCarrier"]
