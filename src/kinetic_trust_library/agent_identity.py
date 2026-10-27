"""Provisional native v3 Agent URI syntax and sponsorship equality checks.

The caller supplies an already authenticated and applicable bond and proof.
These pure checks do not establish their signatures, status, or authority.
"""

from __future__ import annotations

import re

from kinetic_trust_library.errors import ValidationError


_UNRESERVED = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
)
_UPPER_HEX = frozenset("0123456789ABCDEF")
_GENERATION = re.compile(r"(?:0|[1-9][0-9]*)gen\Z")


def validate_agent_uri(value: object) -> str:
    """Return an exact canonical native v3 Agent URI or reject it."""
    if type(value) is not str or not value.isascii():
        raise ValidationError("Agent URI must be an ASCII string")
    parts = value.split(":")
    if len(parts) != 5 or parts[0] != "agent" or parts[1] not in {
        "sponsored", "independent", "guarantor"
    }:
        raise ValidationError("Agent URI has an invalid native v3 shape")
    for segment in parts[2:]:
        _validate_segment(segment)
    if parts[1] != "sponsored" and _GENERATION.fullmatch(parts[2]) is None:
        raise ValidationError("Agent URI generation is invalid")
    return value


def _validate_segment(segment: str) -> None:
    if not 1 <= len(segment) <= 255:
        raise ValidationError("Agent URI segment length is invalid")
    index = 0
    while index < len(segment):
        character = segment[index]
        if character in _UNRESERVED:
            index += 1
            continue
        if (
            character != "%"
            or index + 2 >= len(segment)
            or segment[index + 1] not in _UPPER_HEX
            or segment[index + 2] not in _UPPER_HEX
        ):
            raise ValidationError("Agent URI segment is not canonical")
        octet = int(segment[index + 1 : index + 3], 16)
        if not 0x20 <= octet <= 0x7E or chr(octet) in _UNRESERVED:
            raise ValidationError("Agent URI escape is not canonical")
        index += 3


def validate_sponsorship_binding(
    subject: object,
    bond_sponsored_id: object,
    bond_sponsor_id: object,
    proof_sub: object,
    proof_sponsor: object,
) -> None:
    """Check byte-exact v3 identifiers after bond and proof authentication."""
    evaluated_subject = validate_agent_uri(subject)
    sponsored = validate_agent_uri(bond_sponsored_id)
    sponsor = validate_agent_uri(bond_sponsor_id)
    proof_subject = validate_agent_uri(proof_sub)
    proof_sponsor_id = validate_agent_uri(proof_sponsor)
    if not evaluated_subject.startswith("agent:sponsored:"):
        raise ValidationError("subject must be a sponsored Agent")
    if evaluated_subject != sponsored or evaluated_subject != proof_subject:
        raise ValidationError("sponsored Agent binding does not match")
    if sponsor != proof_sponsor_id:
        raise ValidationError("sponsor Agent binding does not match")


__all__ = ["validate_agent_uri", "validate_sponsorship_binding"]
