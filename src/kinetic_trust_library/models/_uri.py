"""Legacy public validator location; shared version-neutral URI rules."""
from __future__ import annotations
from urllib.parse import urlsplit
from kinetic_trust_library._uri import _validate_absolute_uri

def validate_absolute_uri(value: object, *, name: str) -> str:
    """Return one exact absolute URI after strict RFC 3986 validation."""
    return _validate_absolute_uri(value,name=name,parser=urlsplit)
