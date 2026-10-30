"""Strict, value-preserving RFC 3986 absolute-URI validation."""

from __future__ import annotations

from ipaddress import AddressValueError, IPv4Address, IPv6Address
import re
from unicodedata import normalize
from urllib.parse import SplitResult, urlsplit

from kinetic_trust_library.errors import ValidationError


_URI_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*$")
_URI_SCHEME_PREFIX = re.compile(r"^([A-Za-z][A-Za-z0-9+.-]*):")
_URI_ASCII_CHARACTERS = re.compile(r"^[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+$")
_PCT_ENCODED = r"%[0-9A-Fa-f]{2}"
_UNRESERVED = r"[A-Za-z0-9._~-]"
_SUB_DELIMITER = r"[!$&'()*+,;=]"
_PCHAR = rf"(?:{_UNRESERVED}|{_PCT_ENCODED}|{_SUB_DELIMITER}|[:@])"
_URI_PATH = re.compile(rf"^(?:{_PCHAR}|/)*$")
_URI_QUERY_OR_FRAGMENT = re.compile(rf"^(?:{_PCHAR}|[/?])*$")
_URI_USERINFO = re.compile(rf"^(?:{_UNRESERVED}|{_PCT_ENCODED}|{_SUB_DELIMITER}|:)*$")
_URI_REG_NAME = re.compile(rf"^(?:{_UNRESERVED}|{_PCT_ENCODED}|{_SUB_DELIMITER})+$")
_URI_IPVFUTURE = re.compile(
    rf"^[vV][0-9A-Fa-f]+\.(?:{_UNRESERVED}|{_SUB_DELIMITER}|:)+$"
)
_INVALID_PERCENT_ESCAPE = re.compile(r"%(?![0-9A-Fa-f]{2})")
_MAX_ABSOLUTE_URI_LENGTH = 2048


def validate_absolute_uri(value: object, *, name: str) -> str:
    """Return the original exact absolute URI under shared RFC 3986 checks."""
    return _validate_absolute_uri(value,name=name,parser=urlsplit)


def _validate_absolute_uri(value: object, *, name: str, parser) -> str:
    """Return one exact absolute URI after strict RFC 3986 validation."""

    if type(value) is not str:
        raise ValidationError(f"{name} must be an exact string")
    if not value or len(value) > _MAX_ABSOLUTE_URI_LENGTH:
        raise ValidationError(
            f"{name} must contain 1 through {_MAX_ABSOLUTE_URI_LENGTH} characters"
        )
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValidationError(f"{name} contains invalid Unicode") from exc
    if normalize("NFC", value) != value:
        raise ValidationError(f"{name} must use NFC Unicode")
    if any(ord(character) < 0x21 or ord(character) > 0x7E for character in value):
        raise ValidationError(f"{name} must use encoded ASCII characters")
    if "\\" in value:
        raise ValidationError(f"{name} must not contain a backslash")
    if _URI_ASCII_CHARACTERS.fullmatch(value) is None:
        raise ValidationError(f"{name} contains a forbidden character")
    if _INVALID_PERCENT_ESCAPE.search(value):
        raise ValidationError(f"{name} has an invalid percent escape")
    scheme_match = _URI_SCHEME_PREFIX.match(value)
    if scheme_match is None:
        raise ValidationError(f"{name} must be an absolute URI")
    scheme = scheme_match.group(1)
    if not _URI_SCHEME.fullmatch(scheme):
        raise ValidationError(f"{name} must be an absolute URI")
    scheme_specific = value[scheme_match.end() :]
    hierarchical = scheme_specific.split("#", 1)[0].split("?", 1)[0]
    if not hierarchical:
        raise ValidationError(f"{name} needs a scheme-specific part")
    try:
        parsed = parser(_uri_parser_input(value, scheme_end=scheme_match.end()))
        parsed.port
    except Exception as exc:
        raise ValidationError(f"{name} must be an absolute URI") from exc
    if parsed.scheme.lower() != scheme.lower():
        raise ValidationError(f"{name} must be an absolute URI")
    if not _URI_PATH.fullmatch(parsed.path):
        raise ValidationError(f"{name} path is malformed")
    if not _URI_QUERY_OR_FRAGMENT.fullmatch(parsed.query):
        raise ValidationError(f"{name} query is malformed")
    if not _URI_QUERY_OR_FRAGMENT.fullmatch(parsed.fragment):
        raise ValidationError(f"{name} fragment is malformed")
    is_http = scheme.lower() in {"http", "https"}
    if is_http and not scheme_specific.startswith("//"):
        raise ValidationError(f"{name} HTTP form must use // and name a host")
    if scheme_specific.startswith("//"):
        _validate_network_authority(
            parsed,
            name=name,
            require_host=is_http,
            require_port_value=is_http,
        )
    return value


def _uri_parser_input(value: str, *, scheme_end: int) -> str:
    if not value.startswith("//", scheme_end):
        return value
    authority_start = scheme_end + 2
    authority_end = len(value)
    for delimiter in "/?#":
        position = value.find(delimiter, authority_start)
        if position >= 0:
            authority_end = min(authority_end, position)
    authority = value[authority_start:authority_end]
    host_and_port = authority.rsplit("@", 1)[-1]
    if not host_and_port.startswith("["):
        return value
    closing = host_and_port.find("]")
    if closing < 0:
        return value
    host = host_and_port[1:closing]
    if not host.startswith("V") or _URI_IPVFUTURE.fullmatch(host) is None:
        return value
    flag_index = authority_end - len(host_and_port) + 1
    return f"{value[:flag_index]}v{value[flag_index + 1 :]}"


def _validate_network_authority(
    parsed: SplitResult, *, name: str, require_host: bool, require_port_value: bool
) -> None:
    authority = parsed.netloc
    if authority.count("@") > 1:
        raise ValidationError(f"{name} authority is malformed")
    if not authority:
        if require_host:
            raise ValidationError(f"{name} HTTP form must name a host")
        return
    if "@" in authority:
        userinfo, host_and_port = authority.rsplit("@", 1)
        if not _URI_USERINFO.fullmatch(userinfo):
            raise ValidationError(f"{name} user information is malformed")
    else:
        host_and_port = authority
    if not host_and_port:
        if require_host:
            raise ValidationError(f"{name} HTTP form must name a host")
        return

    if host_and_port.startswith("["):
        closing = host_and_port.find("]")
        if closing < 0:
            raise ValidationError(f"{name} has a malformed IP literal")
        host = host_and_port[1:closing]
        remainder = host_and_port[closing + 1 :]
        if not host or (remainder and not remainder.startswith(":")):
            raise ValidationError(f"{name} has a malformed IP literal")
        if _URI_IPVFUTURE.fullmatch(host) is None:
            try:
                IPv6Address(host)
            except AddressValueError as exc:
                raise ValidationError(f"{name} has a malformed IPv6 host") from exc
        if remainder:
            _validate_uri_port(
                remainder[1:], name=name, require_value=require_port_value
            )
    else:
        if "[" in host_and_port or "]" in host_and_port:
            raise ValidationError(f"{name} has malformed host brackets")
        if host_and_port.count(":") > 1:
            raise ValidationError(f"{name} IPv6 hosts must use brackets")
        if ":" in host_and_port:
            host, port = host_and_port.rsplit(":", 1)
            _validate_uri_port(port, name=name, require_value=require_port_value)
        else:
            host = host_and_port
        if not host and require_host:
            raise ValidationError(f"{name} HTTP form must name a host")
        if host and all(character in "0123456789." for character in host):
            try:
                IPv4Address(host)
            except AddressValueError as exc:
                raise ValidationError(f"{name} has a malformed IPv4 host") from exc
        elif host and _URI_REG_NAME.fullmatch(host) is None:
            raise ValidationError(f"{name} has a malformed host")

    try:
        hostname = parsed.hostname
        parsed.port
    except Exception as exc:
        raise ValidationError(f"{name} has a malformed host or port") from exc
    if require_host and not hostname:
        raise ValidationError(f"{name} HTTP form must name a host")


def _validate_uri_port(value: str, *, name: str, require_value: bool) -> None:
    if not value:
        if require_value:
            raise ValidationError(f"{name} HTTP port must be numeric")
        return
    if not value.isascii() or not value.isdigit():
        raise ValidationError(f"{name} port must be numeric")
    if int(value) > 65535:
        raise ValidationError(f"{name} port is out of range")


__all__ = ["validate_absolute_uri"]
