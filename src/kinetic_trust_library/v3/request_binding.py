"""Provisional RFC PR #196 exact Trust Proof digest preimage.

This is a pure digest primitive. Call only with the complete, already verified
compact Trust Proof and an independently installed hash profile.
"""

from __future__ import annotations

import hashlib
from functools import lru_cache
from importlib.resources import files
import json
import re

from kinetic_trust_library.errors import ValidationError


_COMPACT = re.compile(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\Z")
_PREFIX = b"KTP/trust-proof-v3\x00"
_REQUEST_PREFIX = b"KTP/request-binding-v1\x00"


@lru_cache(maxsize=1)
def _request_validator():
    from .schema_formats import installed_format_checker
    from jsonschema import Draft202012Validator

    schema = json.loads(files("kinetic_trust_library.v3").joinpath(
        "schemas/request-binding-v1.json"
    ).read_text(encoding="utf-8"))
    return Draft202012Validator(schema, format_checker=installed_format_checker())


def canonical_request_bytes(request: dict[str, object]) -> bytes:
    """Validate and JCS-encode an already reconstructed actual request.

    This does not establish that the request matches an invocation, classifier,
    replay domain, delegation, or any other independently trusted context.
    """
    if type(request) is not dict:
        raise ValidationError("v3 request must be a closed object")
    try:
        import rfc8785
        from kinetic_trust_library.v3.trust_proof_json import _check_tree

        _check_tree(request, 1)
        if not _request_validator().is_valid(request):
            raise ValidationError("v3 request does not match its proposed schema")
        canonical = rfc8785.dumps(request)
        if len(canonical) > 65_536:
            raise ValidationError("canonical v3 request exceeds its byte limit")
        return canonical
    except ImportError as exc:
        raise ValidationError("v3 request canonicalization support is unavailable") from exc
    except (ValueError, TypeError, RecursionError, rfc8785.CanonicalizationError) as exc:
        raise ValidationError("v3 request cannot be canonicalized") from exc


def digest_canonical_request(request: dict[str, object], *, algorithm: str) -> str:
    """Digest the complete canonical request with the proposed domain prefix."""
    if algorithm not in ("sha256", "sha384"):
        raise ValidationError("v3 request digest algorithm is invalid")
    canonical = canonical_request_bytes(request)
    return f"{algorithm}:{hashlib.new(algorithm, _REQUEST_PREFIX + canonical).hexdigest()}"


def digest_complete_proof(proof: str, *, algorithm: str) -> str:
    """Digest exact compact proof bytes; never decode or re-encode them."""
    if (
        type(proof) is not str
        or len(proof) > 65_536
        or _COMPACT.fullmatch(proof) is None
        or algorithm not in ("sha256", "sha384")
    ):
        raise ValidationError("complete v3 proof or digest algorithm is invalid")
    encoded = proof.encode("ascii")
    return f"{algorithm}:{hashlib.new(algorithm, _PREFIX + encoded).hexdigest()}"


__all__ = [
    "canonical_request_bytes", "digest_canonical_request", "digest_complete_proof"
]
