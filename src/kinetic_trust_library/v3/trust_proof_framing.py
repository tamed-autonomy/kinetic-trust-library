"""Provisional compact-framing subset of RFC PR #195 stage 1.

This does not establish strict JSON/JCS or proof validity. All decoded bytes
remain untrusted until ordered verification completes.
"""

from __future__ import annotations

from dataclasses import dataclass

from kinetic_trust_library.errors import ProofFormatError
from kinetic_trust_library.proofs._jwt import _decode_segment


@dataclass(frozen=True, slots=True)
class CompactFraming:
    header_bytes: bytes
    payload_bytes: bytes
    signature: bytes
    signing_input: bytes


def parse_compact_framing(compact: str) -> CompactFraming:
    """Enforce v3 compact widths and canonical unpadded base64url framing."""
    if type(compact) is not str:
        raise ProofFormatError("compact proof must be text")
    try:
        wire = compact.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ProofFormatError("compact proof must be ASCII") from exc
    if len(wire) > 65_536:
        raise ProofFormatError("compact proof exceeds its byte limit")
    segments = compact.split(".")
    if len(segments) != 3 or any(not segment for segment in segments):
        raise ProofFormatError("compact proof needs three nonempty segments")
    header = _decode_segment(segments[0], name="protected header")
    payload = _decode_segment(segments[1], name="payload")
    signature = _decode_segment(segments[2], name="signature")
    if len(header) > 1_024 or len(payload) > 49_152:
        raise ProofFormatError("decoded proof segment exceeds its byte limit")
    try:
        header.decode("utf-8")
        payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ProofFormatError("proof JSON must be strict UTF-8") from exc
    return CompactFraming(
        header_bytes=header,
        payload_bytes=payload,
        signature=signature,
        signing_input=(segments[0] + "." + segments[1]).encode("ascii"),
    )


__all__ = ["CompactFraming", "parse_compact_framing"]
