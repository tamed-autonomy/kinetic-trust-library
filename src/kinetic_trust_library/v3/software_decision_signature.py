"""Independent classical signature stage for a software consumption sidecar.

Trusted issuer keys and profile are installed independently of the candidate.
Success proves only this signature/context/time stage, never current evidence,
ordinary authorization, epoch continuity, complete consumption or execution.
"""
from dataclasses import dataclass
from kinetic_trust_library.errors import ValidationError,ProofFormatError
from kinetic_trust_library._jws_encoding import _decode_segment
from .software_decision_shape import parse_software_decision
from .trust_proof_json import _parse_jcs_object
from .trust_proof_signature import trust_proof_signature_valid
from .root_lifecycle import _time
from .execution_observation import _name,_digest as is_digest


SOFTWARE_DECISION_PURPOSE="ktp-software-substrate-decision"


def _software_public_key_valid(key):
    from kinetic_trust_library._signature_shapes import (
        validate_ed25519_public_key,validate_es256_public_key,_PublicKeyShapeError)
    try:
        if key.get("alg")=="EdDSA" and (key.get("kty"),key.get("crv"))==("OKP","Ed25519"):
            validate_ed25519_public_key(_decode_segment(key["x"],name="software key x"))
        elif key.get("alg")=="ES256" and (key.get("kty"),key.get("crv"))==("EC","P-256"):
            x=_decode_segment(key["x"],name="software key x");y=_decode_segment(key["y"],name="software key y")
            if len(x)!=32 or len(y)!=32:return False
            validate_es256_public_key(b"\x04"+x+y)
            from cryptography.hazmat.primitives.asymmetric import ec
            ec.EllipticCurvePublicNumbers(int.from_bytes(x,"big"),int.from_bytes(y,"big"),ec.SECP256R1()).public_key()
        else:return False
    except (ProofFormatError,_PublicKeyShapeError,KeyError,TypeError,ValueError):return False
    return True


def _software_key_authorized(key,p,body,now):
    return (type(key) is dict and _name(key.get("kid")) and key.get("alg") in p["algorithms"] and _software_public_key_valid(key)
        and key.get("revoked") is False and key.get("purpose")==SOFTWARE_DECISION_PURPOSE
        and key.get("subject")==body["issuer_id"] and body["issuer_id"] in p["issuer_ids"] and key.get("zone_id")==p["zone"]
        and _time(key.get("not_before")) and _time(key.get("not_after"))
        and key["not_before"]<=body["evaluated_at"]<=now<body["expires_at"]<=key["not_after"]
        and body["request_binding"]["execution_profile_digest"]==p["execution_profile_digest"]
        and body["request_binding"]["policy_digest"]==p["policy_digest"])


@dataclass(frozen=True,slots=True,init=False)
class SoftwareSignatureAssessment:
    verified: bool
    reason: str
    decision_bytes: bytes | None
    checked_at: int | None
    expires_at: int | None
    signing_key_expires_at: int | None
    complete_consumption_verified: bool
    action_permitted: bool

    def __init__(self,*args,**kwargs):raise TypeError("software signature assessment requires an installed independent issuer policy")


@dataclass(frozen=True,slots=True)
class InstalledSoftwareDecisionSignatureVerifier:
    trusted_keys_bytes: bytes
    profile_bytes: bytes

    def __post_init__(self):
        if type(self.trusted_keys_bytes) is not bytes or type(self.profile_bytes) is not bytes:
            raise ValidationError("immutable installed software issuer keys/profile required")
        _parse_jcs_object(self.trusted_keys_bytes);p=_parse_jcs_object(self.profile_bytes)
        if (set(p)!={"id","version","zone","formula","execution_profile_digest","policy_digest","issuer_ids","algorithms"}
                or not _name(p["id"]) or not _name(p["zone"]) or not _time(p["version"]) or p["version"]==0
                or p["formula"]!="software-decision-es256-ed25519-v1"
                or not is_digest(p["execution_profile_digest"]) or not is_digest(p["policy_digest"])
                or type(p["issuer_ids"]) is not list or not p["issuer_ids"] or any(not _name(i) for i in p["issuer_ids"])
                or len(set(p["issuer_ids"]))!=len(p["issuer_ids"]) or type(p["algorithms"]) is not list or not p["algorithms"]
                or any(type(a) is not str or a not in ("ES256","EdDSA") for a in p["algorithms"])
                or len(set(p["algorithms"]))!=len(p["algorithms"])):
            raise ValidationError("invalid installed classical software signing profile")

    def verify(self,decision_bytes,*,now,clock_healthy):
        verified=False;expiry=key_expiry=None
        if clock_healthy is True and _time(now):
            try:
                body=parse_software_decision(decision_bytes);p=_parse_jcs_object(self.profile_bytes)
                pieces=body["signature"].split(".")
                if len(pieces)!=3:raise ValidationError("invalid software signature framing")
                header_raw=_decode_segment(pieces[0],name="software signature header")
                if len(header_raw)>1024:raise ValidationError("unbounded software signature header")
                header=_parse_jcs_object(header_raw)
                key=_parse_jcs_object(self.trusted_keys_bytes).get(header.get("kid"))
                if (not _software_key_authorized(key,p,body,now) or header.get("kid")!=key["kid"]
                        or header!={"alg":key["alg"],"kid":key["kid"],"typ":SOFTWARE_DECISION_PURPOSE}):
                    raise ValidationError("software signature differs from installed issuer/purpose/profile/time")
                import rfc8785
                payload=_decode_segment(pieces[1],name="software signature payload")
                if payload!=rfc8785.dumps({k:v for k,v in body.items() if k!="signature"}):
                    raise ValidationError("software signature payload does not match complete original decision")
                # Reuse only the strict raw ES256/Ed25519 JWS cryptographic
                # primitive, after independently checking this distinct purpose.
                verified=trust_proof_signature_valid(body["signature"],algorithm=key["alg"],trusted_key=key)
                if verified:expiry=body["expires_at"];key_expiry=key["not_after"]
            except (ValidationError,ProofFormatError,KeyError,ValueError,TypeError,UnicodeError):
                verified=False
        result=object.__new__(SoftwareSignatureAssessment)
        for k,v in dict(verified=verified,reason="SOFTWARE_SIGNATURE_VERIFIED" if verified else "SOFTWARE_SIGNATURE_INVALID",
                decision_bytes=decision_bytes if verified else None,checked_at=now if _time(now) else None,expires_at=expiry,
                signing_key_expires_at=key_expiry,complete_consumption_verified=False,action_permitted=False).items():object.__setattr__(result,k,v)
        return result
