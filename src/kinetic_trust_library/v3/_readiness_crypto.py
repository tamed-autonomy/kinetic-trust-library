# Adapted from nmcitra/ktp-rfc at 9612f7955d88e25d193dab2a17d51d0c9d9075d0.
# Copyright 2025-2026 Chris Perkins. Licensed under Apache-2.0.
# Modified for Library resource loading and isolated native readiness use.
"""Private readiness signature subset adapted from RFC trajectory primitives."""
from ._jws_keys import KeyBinding
import base64
import hashlib
import json
import math
import re
import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, utils
READINESS_TYPE = 'ktp-readiness-attestation-v1'
READINESS_DECISION_TYPE = 'ktp-readiness-decision-v1'
SIGNATURE_PURPOSES = (READINESS_TYPE,READINESS_DECISION_TYPE)


MAX_INTEGER = 2**53 - 1


ORDERS = {
    'ES256': int('ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551', 16),
    'ES384': int('ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973', 16),
}


class InvalidRecord(ValueError):
    """Malformed, mismatched, unsupported, or unauthenticated input."""


def json_value(value, active=None):
    """Reject Python-only values, unsafe integers, nonfinite values and cycles."""
    active = set() if active is None else active
    if value is None or type(value) is bool:
        return
    if type(value) is str:
        try:
            value.encode('utf-8', errors='strict')
        except UnicodeError as error:
            raise InvalidRecord('invalid Unicode scalar') from error
        return
    if type(value) is int:
        if abs(value) > MAX_INTEGER:
            raise InvalidRecord('integer exceeds exact interoperable range')
        return
    if type(value) is float:
        if not math.isfinite(value):
            raise InvalidRecord('nonfinite number')
        if value.is_integer() and abs(value) > MAX_INTEGER:
            raise InvalidRecord('integer-valued number exceeds exact interoperable range')
        return
    if type(value) not in (dict, list) or id(value) in active:
        raise InvalidRecord('non-JSON value or cycle')
    active.add(id(value))
    try:
        if type(value) is dict:
            for key, child in value.items():
                if type(key) is not str:
                    raise InvalidRecord('object names must be strings')
                json_value(key, active)
                json_value(child, active)
        else:
            for child in value:
                json_value(child, active)
    finally:
        active.remove(id(value))


def canonical(value):
    try:
        json_value(value)
        return rfc8785.dumps(value)
    except (rfc8785.CanonicalizationError, RecursionError) as error:
        raise InvalidRecord('cannot canonicalize JSON') from error


def strict_loads(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise InvalidRecord('duplicate object name')
            result[key] = value
        return result

    def nonfinite(_):
        raise InvalidRecord('nonfinite JSON constant')

    try:
        if isinstance(raw, bytes):
            raw = raw.decode('utf-8', errors='strict')
        value = json.loads(raw, object_pairs_hook=pairs, parse_constant=nonfinite)
        canonical(value)
        return value
    except (ValueError, TypeError, UnicodeError, RecursionError) as error:
        raise InvalidRecord(str(error)) from error


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def unb64(text):
    if type(text) is not str or not re.fullmatch(r'[A-Za-z0-9_-]+', text):
        raise InvalidRecord('invalid unpadded base64url')
    try:
        result = base64.urlsafe_b64decode(text + '=' * (-len(text) % 4))
    except ValueError as error:
        raise InvalidRecord('invalid base64url length') from error
    if b64(result) != text:
        raise InvalidRecord('noncanonical base64url')
    return result


def digest_bytes(data, level):
    if type(level) is not int or level not in (1, 2, 3):
        raise InvalidRecord('unsupported trusted conformance level')
    algorithm = 'sha384' if level == 3 else 'sha256'
    return algorithm + ':' + hashlib.new(algorithm, data).hexdigest()


def digest(value, level):
    return digest_bytes(canonical(value), level)




def literal(value):
    if type(value) is not str or not value or re.search(r'[\s*?\[\]{}]', value):
        raise InvalidRecord('expected nonempty literal identifier')


def check_key(key, algorithm, level):
    if hasattr(key, 'public_key'):
        key = key.public_key()
    if algorithm in ('ES256', 'ES384'):
        curve = ec.SECP256R1 if algorithm == 'ES256' else ec.SECP384R1
        valid = isinstance(key, ec.EllipticCurvePublicKey) and isinstance(key.curve, curve)
        if level == 3 and algorithm != 'ES384':
            valid = False
    elif algorithm == 'EdDSA':
        valid = isinstance(key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey))
        if level == 3 and not isinstance(key, ed448.Ed448PublicKey):
            valid = False
    else:
        valid = False
    if not valid:
        raise InvalidRecord('key, algorithm, or trusted strength mismatch')
    return key


def verify_jws(token, expected_payload, binding, *, level):
    digest_bytes(b'', level)
    literal(binding.key_id)
    literal(binding.subject)
    literal(binding.zone_id)
    if binding.purpose not in SIGNATURE_PURPOSES:
        raise InvalidRecord('unknown trusted signature purpose')
    if type(token) is not str:
        raise InvalidRecord('signature must be compact JWS')
    pieces = token.split('.')
    if len(pieces) != 3:
        raise InvalidRecord('signature must have three segments')
    header_raw, payload_raw, signature = map(unb64, pieces)
    header = strict_loads(header_raw)
    expected_header = {'alg': binding.algorithm, 'kid': binding.key_id, 'typ': binding.purpose}
    if header != expected_header or canonical(header) != header_raw:
        raise InvalidRecord('protected header does not match trusted binding')
    if canonical(expected_payload) != payload_raw:
        raise InvalidRecord('signed payload does not match complete canonical content')
    key = check_key(binding.public_key, binding.algorithm, level)
    message = (pieces[0] + '.' + pieces[1]).encode('ascii')
    try:
        if binding.algorithm in ORDERS:
            size = 32 if binding.algorithm == 'ES256' else 48
            if len(signature) != size * 2:
                raise InvalidRecord('invalid raw ECDSA signature length')
            r, s = int.from_bytes(signature[:size], 'big'), int.from_bytes(signature[size:], 'big')
            if not (0 < r < ORDERS[binding.algorithm] and 0 < s <= ORDERS[binding.algorithm] // 2):
                raise InvalidRecord('invalid or non-low-s ECDSA signature')
            hash_alg = hashes.SHA256() if binding.algorithm == 'ES256' else hashes.SHA384()
            key.verify(utils.encode_dss_signature(r, s), message, ec.ECDSA(hash_alg))
        else:
            key.verify(signature, message)
    except (InvalidSignature, ValueError) as error:
        raise InvalidRecord('signature verification failed') from error
