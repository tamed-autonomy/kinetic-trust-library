# Adapted from nmcitra/ktp-rfc scripts/privacy_evidence.py at
# 9612f7955d88e25d193dab2a17d51d0c9d9075d0.
# Copyright 2025-2026 Chris Perkins. Licensed under Apache-2.0.
# Modified: bundled schemas, mandatory formats, shared native crypto;
# raw-private-key signing helper removed.
#!/usr/bin/env python3
"""Encrypted evidence verification subset; not a key store or authorizer.

The RFC's raw-private-key seal helper is excluded here. Callers must establish
independent anchors, authorize decryption, enforce retention and implement
erasure. Outer integrity says nothing about the truth of inner evidence.
"""
import json
from dataclasses import dataclass
from importlib.resources import files

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from jsonschema import Draft202012Validator

from ._trajectory_reference import (
    InvalidRecord, PRIVACY_EVIDENCE_TYPE, b64, canonical, digest,
    unb64, verify_jws,
)

ROOT = files('kinetic_trust_library.v3')
SCHEMA = json.loads(ROOT.joinpath('schemas/privacy-evidence-envelope.json').read_text('utf-8'))
from .schema_formats import installed_format_checker
VALIDATOR = Draft202012Validator(SCHEMA, format_checker=installed_format_checker())
FORMAT = 'ktp-privacy-evidence-v1'


def body(envelope):
    return {k: v for k, v in envelope.items() if k not in ('signature', 'record_hash')}


def associated_data(envelope):
    header = {k: v for k, v in body(envelope).items() if k != 'encryption'}
    header['encryption'] = {k: v for k, v in envelope['encryption'].items()
                            if k != 'ciphertext'}
    return canonical(header)


def record_digest(envelope, level):
    return digest({k: v for k, v in envelope.items() if k != 'record_hash'}, level)


def validate_envelope(envelope):
    canonical(envelope)
    errors = list(VALIDATOR.iter_errors(envelope))
    if errors:
        raise InvalidRecord('privacy envelope schema: ' + errors[0].message)
    for name in ('sequence', 'conformance_level', 'created_at', 'delete_after'):
        if type(envelope[name]) is not int:
            raise InvalidRecord(name + ' must be an integer token')
    if envelope['created_at'] >= envelope['delete_after']:
        raise InvalidRecord('retention deadline must follow creation')
    if (envelope['sequence'] == 1) != (envelope['previous_hash'] is None):
        raise InvalidRecord('only genesis may have no predecessor')
    prefix = 'sha384:' if envelope['conformance_level'] == 3 else 'sha256:'
    for name in ('privacy_policy_digest', 'record_hash', 'previous_hash'):
        value = envelope[name]
        if value is not None and not value.startswith(prefix):
            raise InvalidRecord('digest strength differs from profile')
    if len(unb64(envelope['encryption']['nonce'])) != 12:
        raise InvalidRecord('AES-GCM nonce must have 96 bits')
    if len(unb64(envelope['encryption']['ciphertext'])) <= 16:
        raise InvalidRecord('ciphertext must include nonempty evidence and tag')


@dataclass(frozen=True)
class ExpectedEnvelope:
    """Independently authenticated archive anchor and installed policy context.

    Construction is not authentication. Policy validity and lawful retention
    must be established outside this helper, including justified holds.
    """
    zone_id: str
    chain_id: str
    sequence: int
    previous_hash: object
    record_hash: str
    purpose_id: str
    privacy_policy_digest: str
    issuer_id: str
    level: int
    key_valid_from: int
    key_valid_until: int


def verify_envelope(envelope, binding, expected, *, now):
    """Verify outer integrity and archive anchor without needing a data key.

    A valid result is deliberately 'outer_integrity_only'; neither decryption,
    original signatures, erasure, authority nor chain consensus is established.
    Historical verification may occur after deletion deadline; retaining the
    object beyond that deadline requires separate authority, never this result.
    """
    validate_envelope(envelope)
    for value in (now, expected.level, expected.sequence, expected.key_valid_from,
                  expected.key_valid_until):
        if type(value) is not int or value < 0 or value > 2**53 - 1:
            raise InvalidRecord('invalid trusted integer')
    for name in ('zone_id', 'chain_id', 'sequence', 'previous_hash', 'record_hash',
                 'purpose_id', 'privacy_policy_digest', 'issuer_id'):
        if envelope[name] != getattr(expected, name):
            raise InvalidRecord('envelope differs from independently anchored ' + name)
    if envelope['conformance_level'] != expected.level:
        raise InvalidRecord('trusted level mismatch')
    if (binding.purpose != PRIVACY_EVIDENCE_TYPE or binding.subject != expected.issuer_id
            or binding.zone_id != expected.zone_id):
        raise InvalidRecord('privacy evidence key role, issuer or zone mismatch')
    if not expected.key_valid_from <= envelope['created_at'] < expected.key_valid_until:
        raise InvalidRecord('signer not valid at envelope creation')
    if envelope['created_at'] > now:
        raise InvalidRecord('future envelope')
    verify_jws(envelope['signature'], body(envelope), binding, level=expected.level)
    if record_digest(envelope, expected.level) != expected.record_hash:
        raise InvalidRecord('completed envelope digest mismatch')
    return 'outer_integrity_only'


def open_evidence(envelope, data_key, binding, expected, *, now):
    """Verify the envelope then decrypt; caller must separately authorize access.

    Exact recovered bytes still require their original format/signature checks.
    This helper cannot grant access or verify destruction of other key copies.
    """
    verify_envelope(envelope, binding, expected, now=now)
    if type(data_key) is not bytes or len(data_key) != 32:
        raise InvalidRecord('256-bit data key required')
    if now >= envelope['delete_after']:
        raise InvalidRecord('expired evidence: do not decrypt without a new authorized retention record')
    try:
        return AESGCM(data_key).decrypt(unb64(envelope['encryption']['nonce']),
            unb64(envelope['encryption']['ciphertext']), associated_data(envelope))
    except InvalidTag as error:
        raise InvalidRecord('evidence key or ciphertext authentication failed') from error
