"""Ordered Decision Geometry verification against installed reproduction.

The reproduction adapter independently authenticates evaluation identity/time,
profile/release, actual invocation, source/evidence admissibility and reproduces
the complete evaluation under that profile. It never receives the candidate.
DG_VALID establishes record consistency, not permission or replay reservation.
"""
from dataclasses import dataclass
import json
from kinetic_trust_library.errors import ValidationError
from .decision_geometry import _geometry_validator
from .trust_proof_json import _reject_duplicate, _reject_constant, _check_tree, _parse_jcs_object
from .request_binding import canonical_request_bytes, digest_canonical_request, digest_complete_proof
from .complete_proof_verifier import InstalledProofVerifier
from .root_lifecycle import _time


@dataclass(frozen=True,slots=True)
class AuthenticatedGeometryReproduction:
    body_bytes: bytes
    actual_request_bytes: bytes
    compact_proof: str
    clock_healthy: bool


@dataclass(frozen=True,slots=True,init=False)
class GeometryVerificationResult:
    reason: str
    canonical_body_bytes: bytes | None
    reproduced_body_bytes: bytes | None

    def __init__(self,*args,**kwargs):
        raise TypeError("GeometryVerificationResult is derived by an installed verifier")


def _parse_body(raw):
    import rfc8785
    if type(raw) is not bytes or len(raw)>262144: raise ValueError("unbounded geometry")
    body=json.loads(raw.decode("utf-8"),object_pairs_hook=_reject_duplicate,parse_constant=_reject_constant)
    if type(body) is not dict: raise ValueError("geometry root must be an object")
    _check_tree(body,1)
    canonical=rfc8785.dumps(body)
    if len(canonical)>262144: raise ValueError("unbounded canonical geometry")
    return body,canonical


@dataclass(frozen=True,slots=True)
class InstalledGeometryVerifier:
    reproduction_adapter: object
    proof_verifier: InstalledProofVerifier
    algorithm: str

    def __post_init__(self):
        if (not callable(getattr(self.reproduction_adapter,"reproduce",None))
                or type(self.proof_verifier) is not InstalledProofVerifier or self.algorithm not in ("sha256","sha384")):
            raise ValidationError("installed geometry verifier is invalid")

    def verify(self,raw_body: bytes,*,evaluated_at: int) -> GeometryVerificationResult:
        import rfc8785
        if not _time(evaluated_at): raise ValidationError("trusted geometry evaluation time is invalid")
        canonical=reproduced=None
        def result(reason):
            value=object.__new__(GeometryVerificationResult)
            for name,member in (("reason",reason),("canonical_body_bytes",canonical),("reproduced_body_bytes",reproduced)):
                object.__setattr__(value,name,member)
            return value
        try:
            body,canonical=_parse_body(raw_body)
        except (ValueError,TypeError,UnicodeError,RecursionError):
            return result("DG_ENCODING")
        if (not _geometry_validator().is_valid(body) or type(body.get("evaluated_at")) is not int):
            return result("DG_SCHEMA")
        source=self.reproduction_adapter.reproduce(evaluated_at=evaluated_at)
        if (type(source) is not AuthenticatedGeometryReproduction or type(source.body_bytes) is not bytes
                or type(source.actual_request_bytes) is not bytes or type(source.compact_proof) is not str
                or type(source.clock_healthy) is not bool):
            raise ValidationError("geometry reproduction adapter returned invalid evidence")
        reproduced=source.body_bytes
        expected=_parse_jcs_object(reproduced)
        if not _geometry_validator().is_valid(expected) or expected["evaluated_at"]!=evaluated_at:
            raise ValidationError("installed geometry reproduction is invalid")
        def same(fields):
            return rfc8785.dumps({k:body[k] for k in fields if k in body}) == rfc8785.dumps({k:expected[k] for k in fields if k in expected})
        identity=("record_version","decision_id","evaluated_at","ktp_release","evaluation_profile","evaluator","subject","actor","audience")
        if not same(identity): return result("DG_CONTEXT")
        if not same(("association","embedded_request","embedded_proof")): return result("DG_BINDING")
        association=body["association"]
        if association is not None:
            actual=_parse_jcs_object(source.actual_request_bytes)
            verified=self.proof_verifier.verify(source.compact_proof,now=evaluated_at,clock_healthy=source.clock_healthy)
            if verified.stage!=8: return result("DG_BINDING")
            claims=_parse_jcs_object(verified.authenticated_payload_bytes)
            if (association["request_digest"]!=digest_canonical_request(actual,algorithm=self.algorithm)
                    or association["proof_digest"]!=digest_complete_proof(source.compact_proof,algorithm=self.algorithm)
                    or association["proof_jti"]!=claims["jti"] or claims["sub"]!=actual["actor"]
                    or claims["aud"]!=actual["audience"]):
                return result("DG_BINDING")
            if "embedded_request" in body and canonical_request_bytes(body["embedded_request"])!=source.actual_request_bytes:
                return result("DG_BINDING")
            if "embedded_proof" in body and body["embedded_proof"]!=source.compact_proof:
                return result("DG_BINDING")
        for item in body["inputs"]:
            if item["name"]=="soul" and "value" in item and (type(item["value"]) not in (int,float) or item["value"] not in (0,1)):
                return result("DG_INPUTS")
        if not same(("inputs","undefined_inputs")): return result("DG_INPUTS")
        if (not same(("gates","capacity","margin","reason_codes"))
                or body["result"]["supervision"]!=expected["result"]["supervision"]):
            return result("DG_ORDER")
        if not same(("result","consumer_result")): return result("DG_CONSTRAINTS")
        return result("DG_VALID")


__all__=["AuthenticatedGeometryReproduction","GeometryVerificationResult","InstalledGeometryVerifier"]
