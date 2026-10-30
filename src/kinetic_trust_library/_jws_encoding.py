"""Strict version-neutral compact-JWS base64url decoding."""
from base64 import b64decode,urlsafe_b64encode
from binascii import Error as Base64Error
import re
from kinetic_trust_library.errors import ProofFormatError

_BASE64URL=re.compile(r"^[A-Za-z0-9_-]+$")

def _decode_segment(segment: str, /, *, name: str) -> bytes:
    if _BASE64URL.fullmatch(segment) is None or len(segment) % 4 == 1:
        raise ProofFormatError(f"{name} segment is not strict base64url")
    encoded = segment.encode("ascii")
    try:
        decoded = b64decode(
            encoded + (b"=" * (-len(encoded) % 4)),
            altchars=b"-_",
            validate=True,
        )
    except (Base64Error, ValueError) as exc:
        raise ProofFormatError(f"{name} segment is not strict base64url") from exc
    if urlsafe_b64encode(decoded).rstrip(b"=") != encoded:
        raise ProofFormatError(f"{name} segment has nonzero base64url pad bits")
    return bytes(bytearray(decoded))
