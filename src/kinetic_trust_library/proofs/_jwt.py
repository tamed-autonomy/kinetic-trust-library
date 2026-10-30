"""Private compact Trust Proof framing."""

from base64 import urlsafe_b64encode
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
import json
import re
from unicodedata import category, normalize

from kinetic_trust_library.errors import (
    DisabledProofAlgorithmError,
    ProofFormatError,
    UnsupportedProofAlgorithmError,
    ValidationError,
)
from kinetic_trust_library.models._uri import validate_absolute_uri
from kinetic_trust_library.models.proof import ProofAlgorithm, TrustProofClaims
from kinetic_trust_library._jws_encoding import _decode_segment


_MAX_COMPACT_TOKEN_BYTES = 65_536
_MAX_HEADER_SEGMENT_BYTES = 2_048
_MAX_PAYLOAD_SEGMENT_BYTES = 60_000
_MAX_SIGNATURE_SEGMENT_BYTES = 128
_MAX_DECODED_HEADER_BYTES = 1_536
_MAX_DECODED_PAYLOAD_BYTES = 45_000
_MAX_SIGNING_INPUT_BYTES = 62_049
_MAX_JSON_DEPTH = 16
_MAX_OBJECT_MEMBERS = 128
_MAX_TOTAL_OBJECT_MEMBERS = 512
_MAX_ARRAY_ITEMS = 256
_MAX_TOTAL_COLLECTION_ITEMS = 1_024
_MAX_URI_STRING_BYTES = 2_048
_MAX_IDENTIFIER_STRING_BYTES = 256
_MAX_OTHER_STRING_BYTES = 4_096
_MAX_NUMERIC_LEXEME_BYTES = 128
_JSON_NUMBER = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?")
_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")
_HEADER_MEMBERS = frozenset({"alg", "kid", "typ"})


@dataclass(frozen=True, slots=True)
class _ParsedCompact:
    raw: str
    header_segment: str
    payload_segment: str
    signature_segment: str
    signing_input: bytes
    signature: bytes
    algorithm: ProofAlgorithm
    key_id: str
    untrusted_issuer: str
    payload_bytes: bytes


def _require_compact_token_width(raw: str, /) -> None:
    if len(raw) > _MAX_COMPACT_TOKEN_BYTES:
        raise ProofFormatError("compact proof exceeds its byte limit")


def _require_signing_input_width(signing_input: bytes, /) -> None:
    if len(signing_input) > _MAX_SIGNING_INPUT_BYTES:
        raise ProofFormatError("proof signing input exceeds its byte limit")


def _require_segment_width(segment: str, /, *, name: str, maximum: int) -> None:
    if len(segment) > maximum:
        raise ProofFormatError(f"{name} segment exceeds its byte limit")


def _require_header_segment_width(segment: str, /) -> None:
    _require_segment_width(
        segment,
        name="protected header",
        maximum=_MAX_HEADER_SEGMENT_BYTES,
    )


def _require_payload_segment_width(segment: str, /) -> None:
    _require_segment_width(segment, name="payload", maximum=_MAX_PAYLOAD_SEGMENT_BYTES)


def _require_signature_segment_width(segment: str, /) -> None:
    _require_segment_width(
        segment,
        name="signature",
        maximum=_MAX_SIGNATURE_SEGMENT_BYTES,
    )


def _require_decoded_header_width(header: bytes, /) -> None:
    if len(header) > _MAX_DECODED_HEADER_BYTES:
        raise ProofFormatError("decoded protected header exceeds its byte limit")


def _require_decoded_payload_width(payload: bytes, /) -> None:
    if len(payload) > _MAX_DECODED_PAYLOAD_BYTES:
        raise ProofFormatError("decoded proof payload exceeds its byte limit")


class _JSONScanner:
    def __init__(self, text: str, /) -> None:
        self._text = text
        self._index = 0
        self._depth = 0
        self._total_members = 0
        self._total_items = 0

    def scan(self) -> None:
        self._skip_whitespace()
        self._scan_value(member_name=None)
        self._skip_whitespace()
        if self._index != len(self._text):
            raise ProofFormatError("JSON contains trailing data")

    def _scan_value(self, *, member_name: str | None) -> None:
        if self._index >= len(self._text):
            raise ProofFormatError("JSON value is incomplete")
        character = self._text[self._index]
        if character == "{":
            self._scan_object()
        elif character == "[":
            self._scan_array()
        elif character == '"':
            self._scan_string(member_name=member_name)
        elif character in "-0123456789":
            self._scan_number()
        elif self._text.startswith("true", self._index):
            self._index += 4
        elif self._text.startswith("false", self._index):
            self._index += 5
        elif self._text.startswith("null", self._index):
            self._index += 4
        else:
            raise ProofFormatError("JSON contains an invalid value")

    def _scan_object(self) -> None:
        self._enter_container()
        self._index += 1
        self._skip_whitespace()
        if self._consume("}"):
            self._depth -= 1
            return
        members: set[str] = set()
        member_count = 0
        while True:
            if self._index >= len(self._text) or self._text[self._index] != '"':
                raise ProofFormatError("JSON object member name is malformed")
            member = self._scan_string(member_name=None)
            if member in members:
                raise ProofFormatError("JSON object contains a duplicate member")
            members.add(member)
            member_count += 1
            self._total_members += 1
            if member_count > _MAX_OBJECT_MEMBERS:
                raise ProofFormatError("JSON object has too many members")
            if self._total_members > _MAX_TOTAL_OBJECT_MEMBERS:
                raise ProofFormatError("JSON has too many total object members")
            self._skip_whitespace()
            if not self._consume(":"):
                raise ProofFormatError("JSON object member is missing a colon")
            self._skip_whitespace()
            self._scan_value(member_name=member)
            self._skip_whitespace()
            if self._consume("}"):
                self._depth -= 1
                return
            if not self._consume(","):
                raise ProofFormatError("JSON object members are malformed")
            self._skip_whitespace()

    def _scan_array(self) -> None:
        self._enter_container()
        self._index += 1
        self._skip_whitespace()
        if self._consume("]"):
            self._depth -= 1
            return
        item_count = 0
        while True:
            item_count += 1
            self._total_items += 1
            if item_count > _MAX_ARRAY_ITEMS:
                raise ProofFormatError("JSON array has too many items")
            if self._total_items > _MAX_TOTAL_COLLECTION_ITEMS:
                raise ProofFormatError("JSON has too many total collection items")
            self._scan_value(member_name=None)
            self._skip_whitespace()
            if self._consume("]"):
                self._depth -= 1
                return
            if not self._consume(","):
                raise ProofFormatError("JSON array items are malformed")
            self._skip_whitespace()

    def _scan_string(self, *, member_name: str | None) -> str:
        start = self._index
        self._index += 1
        while self._index < len(self._text):
            character = self._text[self._index]
            if character == '"':
                self._index += 1
                fragment = self._text[start : self._index]
                try:
                    value = json.loads(fragment)
                except json.JSONDecodeError as exc:
                    raise ProofFormatError("JSON string is malformed") from exc
                if type(value) is not str:
                    raise ProofFormatError("JSON string is malformed")
                try:
                    encoded = value.encode("utf-8")
                except UnicodeEncodeError as exc:
                    raise ProofFormatError(
                        "JSON string contains invalid Unicode"
                    ) from exc
                maximum = _MAX_OTHER_STRING_BYTES
                if member_name in {"iss", "sub"}:
                    maximum = _MAX_URI_STRING_BYTES
                elif member_name in {"kid", "jti"}:
                    maximum = _MAX_IDENTIFIER_STRING_BYTES
                if len(encoded) > maximum:
                    raise ProofFormatError("JSON string exceeds its UTF-8 limit")
                return value
            if character == "\\":
                self._index += 1
                if self._index >= len(self._text):
                    break
                escape = self._text[self._index]
                if escape == "u":
                    digits = self._text[self._index + 1 : self._index + 5]
                    if len(digits) != 4 or any(
                        digit not in _HEX_DIGITS for digit in digits
                    ):
                        raise ProofFormatError("JSON Unicode escape is malformed")
                    self._index += 5
                    continue
                if escape not in '"\\/bfnrt':
                    raise ProofFormatError("JSON string escape is malformed")
                self._index += 1
                continue
            if ord(character) < 0x20:
                raise ProofFormatError("JSON string contains an unescaped control")
            self._index += 1
        raise ProofFormatError("JSON string is unterminated")

    def _scan_number(self) -> None:
        match = _JSON_NUMBER.match(self._text, self._index)
        if match is None:
            raise ProofFormatError("JSON number is malformed")
        if match.end() - self._index > _MAX_NUMERIC_LEXEME_BYTES:
            raise ProofFormatError("JSON numeric lexeme exceeds its byte limit")
        self._index = match.end()

    def _enter_container(self) -> None:
        self._depth += 1
        if self._depth > _MAX_JSON_DEPTH:
            raise ProofFormatError("JSON nesting exceeds its depth limit")

    def _skip_whitespace(self) -> None:
        while self._index < len(self._text) and self._text[self._index] in " \t\r\n":
            self._index += 1

    def _consume(self, character: str, /) -> bool:
        if self._index < len(self._text) and self._text[self._index] == character:
            self._index += 1
            return True
        return False


def _reject_json_constant(value: str, /) -> object:
    raise ValueError(f"invalid JSON constant {value}")


def _parse_json_object(data: bytes, /) -> dict[str, object]:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ProofFormatError("JSON must be exact UTF-8") from exc
    _JSONScanner(text).scan()
    try:
        value = json.loads(
            text,
            parse_float=Decimal,
            parse_constant=_reject_json_constant,
        )
    except (InvalidOperation, json.JSONDecodeError, ValueError) as exc:
        raise ProofFormatError("JSON value is malformed") from exc
    if type(value) is not dict:
        raise ProofFormatError("JSON payload must be an object")
    if _canonical_json_bytes(value) != data:
        raise ProofFormatError("JSON must use canonical encoding")
    return dict(value)


def _canonical_json_bytes(value: object, /) -> bytes:
    return _encode_json(value).encode("utf-8")


def _encode_json(value: object, /) -> str:
    if value is None:
        return "null"
    if type(value) is bool:
        return "true" if value else "false"
    if type(value) is int:
        return str(value)
    if type(value) is Decimal:
        return _encode_decimal(value)
    if type(value) is str:
        try:
            value.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise ProofFormatError("JSON string contains invalid Unicode") from exc
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    if type(value) is list:
        return "[" + ",".join(_encode_json(item) for item in value) + "]"
    if type(value) is dict:
        if any(type(key) is not str for key in value):
            raise ProofFormatError("JSON object member names must be strings")
        return (
            "{"
            + ",".join(
                json.dumps(key, ensure_ascii=False, separators=(",", ":"))
                + ":"
                + _encode_json(value[key])
                for key in sorted(value)
            )
            + "}"
        )
    raise ProofFormatError("JSON contains an unsupported value")


def _encode_decimal(value: Decimal, /) -> str:
    if not value.is_finite():
        raise ProofFormatError("JSON numbers must be finite")
    if value.is_zero():
        return "0"
    sign, digits, exponent = value.as_tuple()
    coefficient = "".join(str(digit) for digit in digits)
    plain_length = _plain_decimal_length(coefficient, exponent, sign=bool(sign))
    if plain_length > 128:
        significant = coefficient.rstrip("0")
        mantissa = significant[0]
        if len(significant) > 1:
            mantissa += "." + significant[1:]
        adjusted = exponent + len(coefficient) - 1
        return ("-" if sign else "") + mantissa + "e" + str(adjusted)
    if exponent >= 0:
        integer, fractional = coefficient + ("0" * exponent), ""
    elif len(coefficient) > -exponent:
        split = len(coefficient) + exponent
        integer, fractional = coefficient[:split], coefficient[split:]
    else:
        integer = "0"
        fractional = ("0" * (-exponent - len(coefficient))) + coefficient
    fractional = fractional.rstrip("0")
    rendered = integer if not fractional else f"{integer}.{fractional}"
    return f"-{rendered}" if sign else rendered


def _plain_decimal_length(coefficient: str, exponent: int, *, sign: bool) -> int:
    prefix = 1 if sign else 0
    if exponent >= 0:
        return prefix + len(coefficient) + exponent
    if len(coefficient) > -exponent:
        return prefix + len(coefficient) + 1
    return prefix + 2 - exponent


def parse_payload(payload: bytes, /) -> dict[str, object]:
    if type(payload) is not bytes:
        raise ProofFormatError("proof payload must be exact immutable bytes")
    _require_decoded_payload_width(payload)
    return _parse_json_object(payload)


def _parse_header(header: dict[str, object], /) -> tuple[ProofAlgorithm, str]:
    if set(header) != _HEADER_MEMBERS:
        raise ProofFormatError("protected header must contain only alg, kid, and typ")
    algorithm_name = header["alg"]
    key_id = header["kid"]
    proof_type = header["typ"]
    if type(algorithm_name) is not str:
        raise ProofFormatError("protected header alg must be a string")
    if type(proof_type) is not str or proof_type != "ktp+jwt":
        raise ProofFormatError("protected header typ must be exactly ktp+jwt")
    if type(key_id) is not str:
        raise ProofFormatError("protected header kid must be a string")
    _require_key_id(key_id)
    try:
        algorithm = ProofAlgorithm(algorithm_name)
    except ValueError as exc:
        raise UnsupportedProofAlgorithmError(
            "protected header algorithm is unsupported"
        ) from exc
    return algorithm, key_id


def _require_key_id(key_id: str, /) -> None:
    try:
        encoded = key_id.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ProofFormatError("protected header kid contains invalid Unicode") from exc
    if not key_id or len(encoded) > 256:
        raise ProofFormatError("protected header kid exceeds its bounded policy")
    if normalize("NFC", key_id) != key_id:
        raise ProofFormatError("protected header kid must use NFC Unicode")
    if any(character.isspace() for character in key_id):
        raise ProofFormatError("protected header kid must not contain whitespace")
    if any(category(character) in {"Cc", "Cf"} for character in key_id):
        raise ProofFormatError("protected header kid must not contain controls")


def _require_enabled_algorithm(
    algorithm: ProofAlgorithm,
    enabled_algorithms: tuple[ProofAlgorithm, ...],
    /,
) -> None:
    if algorithm not in enabled_algorithms:
        raise DisabledProofAlgorithmError("proof algorithm is not enabled")


def _extract_untrusted_issuer(payload: dict[str, object], /) -> str:
    issuer = payload.get("iss")
    if type(issuer) is not str:
        raise ProofFormatError("proof payload requires a string issuer")
    try:
        validated = validate_absolute_uri(issuer, name="untrusted proof issuer")
    except ValidationError as exc:
        raise ProofFormatError(
            "proof payload issuer must be a bounded absolute URI"
        ) from exc
    if len(validated.encode("utf-8")) > 2_048:
        raise ProofFormatError("proof payload issuer exceeds its UTF-8 limit")
    return validated


def canonical_payload_bytes(claims: TrustProofClaims, /) -> bytes:
    if type(claims) is not TrustProofClaims:
        raise TypeError("proof claims must be a guarded TrustProofClaims value")
    context = {
        "evidence_density": claims.context.evidence_density,
        "trust_trend": claims.context.trust_trend,
        "adversarial_pressure": claims.context.adversarial_pressure,
        "update_resistance": claims.context.update_resistance,
        "attestation_coverage": claims.context.attestation_coverage,
        "moment_criticality": claims.context.moment_criticality,
    }
    soul: dict[str, object] = {"soul": claims.soul.soul}
    if claims.soul.constraint_type is not None:
        soul["constraint_type"] = claims.soul.constraint_type.value
    _include_optional(soul, "constraint_id", claims.soul.constraint_id)
    _include_optional(soul, "constraint_name", claims.soul.constraint_name)
    _include_optional(soul, "authority", claims.soul.authority)
    _include_optional(soul, "community", claims.soul.community)
    _include_optional(soul, "remediation", claims.soul.remediation)

    root: dict[str, object] = {"status": claims.root_instrument.status.value}
    if claims.root_instrument.end_time is not None:
        root["end_time"] = _unix_seconds(claims.root_instrument.end_time)
    _include_optional(
        root,
        "exposure_class",
        claims.root_instrument.exposure_class,
    )
    _include_optional(
        root,
        "declared_exposure",
        claims.root_instrument.declared_exposure,
    )
    _include_optional(
        root,
        "anchored_capacity",
        claims.root_instrument.anchored_capacity,
    )
    _include_optional(root, "terminator", claims.root_instrument.terminator)
    _include_optional(root, "chain_length", claims.root_instrument.chain_length)

    ktp: dict[str, object] = {
        "action": claims.action,
        "resource": claims.resource,
        "context_hash": claims.context_hash,
        "trajectory_id": claims.trajectory_id,
        "decision_id": claims.decision_id,
        "e_base": claims.base_trust,
        "e_trust": claims.effective_trust,
        "r": claims.risk,
        "context": context,
        "soul": soul,
        "lineage": claims.lineage.value,
        "generation": claims.generation,
        "resilience_hash": claims.resilience_hash,
        "peer_share": claims.peer_share,
        "applicable_ceilings": [
            {"ceiling": ceiling.ceiling, "value": ceiling.value}
            for ceiling in claims.applicable_ceilings
        ],
        "advancement_floor": claims.advancement_floor,
        "root_instrument": root,
    }
    _include_optional(ktp, "de_dt", claims.velocity)
    _include_optional(ktp, "sigma", claims.volatility)
    _include_optional(ktp, "sponsor", claims.sponsor)
    _include_optional(ktp, "zone", claims.zone)
    _include_optional(ktp, "oracle_quorum", claims.oracle_quorum)

    payload = {
        "iss": claims.issuer,
        "sub": claims.subject,
        "iat": _unix_seconds(claims.issued_at),
        "exp": _unix_seconds(claims.expires_at),
        "jti": claims.proof_id,
        "ktp": ktp,
    }
    encoded = _canonical_json_bytes(payload)
    _require_decoded_payload_width(encoded)
    _JSONScanner(encoded.decode("utf-8")).scan()
    return bytes(bytearray(encoded))


def _include_optional(
    target: dict[str, object],
    name: str,
    value: object | None,
) -> None:
    if value is None:
        return
    target[name] = value


def _unix_seconds(value: datetime, /) -> int:
    if type(value) is not datetime or value.tzinfo is not timezone.utc:
        raise TypeError("proof NumericDate source must be an exact UTC datetime")
    if value.microsecond != 0:
        raise TypeError("proof NumericDate source must use whole seconds")
    epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    delta = value - epoch
    return (delta.days * 86_400) + delta.seconds


def parse_compact(raw: str, /) -> _ParsedCompact:
    if type(raw) is not str:
        raise ProofFormatError("compact proof must be an exact string")
    _require_compact_token_width(raw)
    try:
        raw.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ProofFormatError("compact proof must contain only ASCII") from exc
    segments = raw.split(".")
    if len(segments) != 3 or any(not segment for segment in segments):
        raise ProofFormatError("compact proof must contain three nonempty segments")
    header_segment, payload_segment, signature_segment = segments
    _require_header_segment_width(header_segment)
    _require_payload_segment_width(payload_segment)
    _require_signature_segment_width(signature_segment)
    header_bytes = _decode_segment(header_segment, name="protected header")
    payload_bytes = _decode_segment(payload_segment, name="payload")
    signature = _decode_segment(signature_segment, name="signature")
    _require_decoded_header_width(header_bytes)
    _require_decoded_payload_width(payload_bytes)
    header = _parse_json_object(header_bytes)
    payload = parse_payload(payload_bytes)
    algorithm, key_id = _parse_header(header)
    untrusted_issuer = _extract_untrusted_issuer(payload)
    signing_input = f"{header_segment}.{payload_segment}".encode("ascii")
    _require_signing_input_width(signing_input)
    return _ParsedCompact(
        raw=raw,
        header_segment=header_segment,
        payload_segment=payload_segment,
        signature_segment=signature_segment,
        signing_input=signing_input,
        signature=signature,
        algorithm=algorithm,
        key_id=key_id,
        untrusted_issuer=untrusted_issuer,
        payload_bytes=payload_bytes,
    )
